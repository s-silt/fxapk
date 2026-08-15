"""apkscan.core.atomic — 主证据文件的原子写。

回灌层（pcap_ingest / probe_ingest）把带外线索合并进 report.json 时，若在 ``write_text``
中途（序列化后半程、磁盘满、进程被杀）失败，直接覆写会把主证据文件留成**半截坏 JSON**——
下一次读取即崩、取证链断裂。本模块提供 :func:`atomic_write_text`：同目录写临时文件
（带 pid+uuid 后缀，避免多进程互踩）→ ``os.replace`` 原子替换；以及
:func:`atomic_create_bytes`：完整临时文件 → 原子 no-replace 发布。写失败时抛出，让调用方
（回灌层已有 try/except + logging）能感知失败并保底 return 0；**关键不变式：无论成功或失败，
目标文件要么是旧内容完整、要么是新内容完整，绝不留半截。**

设计对齐 ``apkscan/dynamic/ledger.py`` 的原子落盘习惯。
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path
import time
from uuid import uuid4

logger = logging.getLogger(__name__)

_WINDOWS_REPLACE_RETRIES = 8
_CREATE_TEMP_ATTEMPTS = 16
_LINK_UNAVAILABLE_ERRNOS = frozenset(
    value
    for value in (
        errno.EACCES,
        errno.EINVAL,
        errno.ENOSYS,
        errno.EPERM,
        errno.EXDEV,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)
_LINK_UNAVAILABLE_WINERRORS = frozenset({1, 5, 17, 50})
_WINDOWS_DESTINATION_EXISTS = frozenset({80, 183})


class AtomicCreateUnsupportedError(OSError):
    """The filesystem has no safe atomic create-if-absent publication primitive."""


def _link_unavailable(exc: OSError) -> bool:
    return exc.errno in _LINK_UNAVAILABLE_ERRNOS or getattr(exc, "winerror", None) in (
        _LINK_UNAVAILABLE_WINERRORS
    )


def _destination_exists(exc: OSError) -> bool:
    return isinstance(exc, FileExistsError) or getattr(exc, "winerror", None) in (
        _WINDOWS_DESTINATION_EXISTS
    )


def _write_all_fsynced(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("atomic write made no progress")
        offset += written
    os.fsync(descriptor)


def atomic_create_bytes(path: str | os.PathLike[str], data: bytes) -> bool:
    """Atomically publish complete bytes only when ``path`` does not exist.

    The canonical target is never opened for streaming writes.  Bytes are
    first written and fsynced under a unique same-directory temporary name,
    then published with an atomic no-replace primitive.  A crash before
    publication can leave only that uniquely named temporary file; a crash
    afterwards leaves the complete canonical file.

    Hard-link creation supplies portable no-replace publication where the
    filesystem supports it.  Windows' ``os.rename`` is also no-replace (unlike
    POSIX rename), so it is a safe fallback for OneDrive/FAT/network volumes
    that reject links.  Other platforms fail closed when hard links are not
    available instead of streaming partial bytes into the final path.

    Returns:
        ``True`` when this call published the file, ``False`` when the target
        already existed or another creator won the publication race.

    Raises:
        AtomicCreateUnsupportedError: no safe publication primitive exists.
        OSError: temporary allocation/write/fsync or publication failed.
    """

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    descriptor: int | None = None
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        for _attempt in range(_CREATE_TEMP_ATTEMPTS):
            candidate = target.with_name(
                f".{target.name}.{os.getpid()}.{uuid4().hex}.tmp"
            )
            try:
                descriptor = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            temporary = candidate
            break
        if temporary is None or descriptor is None:
            raise OSError(f"cannot allocate unique atomic-create temporary file: {target}")

        try:
            _write_all_fsynced(descriptor, data)
        finally:
            owned_descriptor = descriptor
            descriptor = None
            os.close(owned_descriptor)

        try:
            os.link(temporary, target)
        except OSError as exc:
            if _destination_exists(exc):
                return False
            if not _link_unavailable(exc):
                raise
            if os.name != "nt":
                raise AtomicCreateUnsupportedError(
                    f"filesystem cannot atomically create without replacing: {target}"
                ) from exc
            try:
                # CPython maps os.rename to MoveFileExW without
                # MOVEFILE_REPLACE_EXISTING: the destination check and rename
                # are one filesystem operation, so concurrent creators cannot
                # overwrite one another.
                os.rename(temporary, target)
            except OSError as rename_exc:
                if _destination_exists(rename_exc):
                    return False
                raise
        published = True
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # Publication, when successful, already points at complete
                # fsynced bytes.  A stale unique temp must not turn success
                # into a false failure or remove another writer's scratch file.
                logger.debug(
                    "[atomic] 清理 create-only 临时文件失败：%s (published=%s)",
                    temporary,
                    published,
                    exc_info=True,
                )


def _replace_temp(tmp: Path, target: Path) -> None:
    """Replace ``target`` and tolerate Windows' transient sharing race.

    Two independent writers can finish their unique temporary files at the
    same instant.  POSIX serializes the two renames, while Windows may briefly
    return ``ERROR_ACCESS_DENIED`` for the loser even though neither file is
    held open.  Retrying only that Windows ``PermissionError`` preserves the
    atomic last-writer-wins contract without masking persistent permission
    failures.
    """
    for attempt in range(_WINDOWS_REPLACE_RETRIES):
        try:
            os.replace(tmp, target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == _WINDOWS_REPLACE_RETRIES - 1:
                raise
            time.sleep(0.01 * (attempt + 1))


def atomic_write_text(path: str | os.PathLike[str], data: str) -> None:
    """把 ``data`` 原子写入 ``path``（UTF-8）：同目录 tmp → ``os.replace`` 覆盖。

    临时名带 ``pid+uuid`` 后缀：多进程并发写同一文件时各写各的 ``.tmp``，再各自
    ``os.replace``（同目录、原子，最后一个胜出但永远是完整文件）。写 tmp 失败时清理残留的
    半截临时文件后重新抛出——目标文件此刻尚未被触碰，保持旧内容完整。

    Args:
        path: 目标文件路径。父目录不存在会先创建。
        data: 要写入的文本。

    Raises:
        OSError: 写临时文件或 ``os.replace`` 失败时抛出（清理 tmp 后原样上抛，不静默吞）。
    """
    target = Path(path)
    tmp = target.with_suffix(target.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # newline=""：禁用文本模式的换行翻译。否则 Windows 把 "\n" 写成 "\r\n"，落盘字节 ≠ 入参
        # 字节——破坏证据字节保真（corpus add 原样存证）、且让同一内容跨平台产生不同 sha（与 #105 抓
        # 的 frida JS CRLF 同类）。恒按 data 原样字节落盘，跨平台确定。
        tmp.write_text(data, encoding="utf-8", newline="")
        _replace_temp(tmp, target)  # 同目录原子替换，不留半截坏文件
    except OSError:
        # 目标文件在 os.replace 成功前从未被触碰，故此刻仍是旧内容完整。
        # 清理可能残留的半截临时文件后把异常上抛，交由调用方保底。
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            # 清理失败不掩盖原始写异常（tmp 残留无害，不覆盖主文件），但记一条便于排查磁盘态。
            logger.debug("[atomic] 清理临时文件失败：%s", tmp, exc_info=True)
        raise


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """把 ``data`` 原子写入 ``path``（二进制）：同目录 tmp → ``os.replace`` 覆盖。

    与 :func:`atomic_write_text` 同一"要么旧内容完整、要么新内容完整、绝不留半截"不变式，用于落盘取证
    制品的原始字节（如下载的远程配置对象）——字节原样保真（不经文本换行翻译，跨平台 sha 一致）。

    Args:
        path: 目标文件路径。父目录不存在会先创建。
        data: 要写入的原始字节。

    Raises:
        OSError: 写临时文件或 ``os.replace`` 失败时抛出（清理 tmp 后原样上抛，不静默吞）。
    """
    target = Path(path)
    tmp = target.with_suffix(target.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        _replace_temp(tmp, target)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            logger.debug("[atomic] 清理临时文件失败：%s", tmp, exc_info=True)
        raise
