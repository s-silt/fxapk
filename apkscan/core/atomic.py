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
from typing import BinaryIO, TextIO
from uuid import uuid4

logger = logging.getLogger(__name__)

_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700
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


def _ensure_private_directory(directory: Path) -> None:
    """Create every missing directory with a restrictive creation mode.

    On POSIX, each missing path component is created with mode ``0o700``.  The
    process umask may remove additional owner permissions, but can never add
    group or other permissions.  Existing directories are deliberately left
    unchanged: silently chmodding a shared case directory would be a separate
    and potentially disruptive policy change.

    ``Path.mkdir(parents=True, mode=...)`` is not used because CPython creates
    missing intermediate parents with its default mode rather than forwarding
    the requested mode to every parent.

    Windows ignores the POSIX mode argument for directory ACL construction.
    Consequently this call preserves the private-at-creation guarantee on
    POSIX only; it does not claim to isolate Windows directories from other
    accounts.  Enforcing that would require an explicit Windows security
    descriptor at creation time.
    """

    try:
        os.mkdir(directory, _PRIVATE_DIRECTORY_MODE)
    except FileNotFoundError:
        parent = directory.parent
        if parent == directory:
            raise
        _ensure_private_directory(parent)
        try:
            os.mkdir(directory, _PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            if not directory.is_dir():
                raise
    except FileExistsError:
        if not directory.is_dir():
            raise


def _allocate_private_temporary(target: Path) -> tuple[Path, int]:
    """Exclusively create a same-directory temporary file.

    On POSIX the mode applies when the inode is created, before any content is
    written or any other process can open the name with broader permissions.
    ``O_EXCL`` also prevents following an already existing temporary symlink.

    Windows does not map ``0o600`` to an owner-only ACL.  Exclusive creation
    and atomic publication still hold there, but access isolation is limited
    to whatever ACL the parent directory inherits.
    """

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _attempt in range(_CREATE_TEMP_ATTEMPTS):
        candidate = target.with_name(
            f".{target.name}.{os.getpid()}.{uuid4().hex}.tmp"
        )
        try:
            descriptor = os.open(candidate, flags, _PRIVATE_FILE_MODE)
        except FileExistsError:
            continue
        return candidate, descriptor

    raise OSError(
        errno.EEXIST,
        f"cannot allocate unique atomic temporary file: {target}",
        target,
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

    The canonical target is never opened for streaming writes. Bytes are first
    written and fsynced under a unique same-directory temporary name, then
    published with an atomic no-replace primitive. A crash before publication
    can leave only that uniquely named temporary file; a crash afterwards
    leaves the complete canonical file.

    On POSIX the temporary inode is created with mode ``0o600``. Hard-link
    publication adds the canonical name to that same inode, so the target has
    the same restricted mode. Windows does not provide equivalent ACL
    isolation through this mode argument.

    Hard-link creation supplies portable no-replace publication where the
    filesystem supports it. Windows' ``os.rename`` is also no-replace (unlike
    POSIX rename), so it is a safe fallback for OneDrive/FAT/network volumes
    that reject links. Other platforms fail closed when hard links are not
    available instead of streaming partial bytes into the final path.

    Returns:
        ``True`` when this call published the file, ``False`` when the target
        already existed or another creator won the publication race.

    Raises:
        AtomicCreateUnsupportedError: no safe publication primitive exists.
        OSError: temporary allocation/write/fsync or publication failed.
    """

    target = Path(path)
    _ensure_private_directory(target.parent)
    temporary: Path | None = None
    descriptor: int | None = None
    published = False
    try:
        temporary, descriptor = _allocate_private_temporary(target)

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
                # fsynced bytes. A stale unique temp must not turn success
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
    same instant. POSIX serializes the two renames, while Windows may briefly
    return ``ERROR_ACCESS_DENIED`` for the loser even though neither file is
    held open. Retrying only that Windows ``PermissionError`` preserves the
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


def _write_text_to_stream(stream: TextIO, data: str) -> None:
    """Write text to an already-open atomic temporary stream."""

    stream.write(data)


def _write_bytes_to_stream(stream: BinaryIO, data: bytes) -> None:
    """Write bytes to an already-open atomic temporary stream."""

    stream.write(data)


def atomic_write_text(path: str | os.PathLike[str], data: str) -> None:
    """把 ``data`` 原子写入 ``path``（UTF-8）：同目录 tmp → ``os.replace`` 覆盖。

    临时文件通过 ``O_CREAT|O_EXCL`` 以 ``0o600`` 创建，而不是先公开创建再 chmod。
    POSIX 的 rename/replace 替换的是目录项：成功后目标名称指向原临时文件 inode，该 inode
    的 mode 不变，因此最终目标也保持受限权限。Windows 的 mode 不等价于 ACL，无法据此
    声称实现账户隔离；Windows 仅保留独占创建和原子替换保证。

    多进程并发写同一文件时各写各的 ``.tmp``，再各自 ``os.replace``（同目录、原子，
    最后一个胜出但永远是完整文件）。写 tmp 失败时清理残留的半截临时文件后重新抛出——
    目标文件此刻尚未被触碰，保持旧内容完整。

    Args:
        path: 目标文件路径。缺失的父目录会以受限创建 mode 逐级创建。
        data: 要写入的文本。

    Raises:
        OSError: 写临时文件、同步数据或 ``os.replace`` 失败时抛出。
    """

    target = Path(path)
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        _ensure_private_directory(target.parent)
        temporary, descriptor = _allocate_private_temporary(target)

        stream = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="",
        )
        descriptor = None
        with stream:
            # newline="" 禁用文本模式换行翻译，否则 Windows 会把 "\n"
            # 写成 "\r\n"。原样编码可保证证据字节与跨平台 sha 一致。
            _write_text_to_stream(stream, data)
            stream.flush()
            os.fsync(stream.fileno())

        _replace_temp(temporary, target)
        temporary = None
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                logger.debug(
                    "[atomic] 关闭临时文件失败：%s",
                    temporary,
                    exc_info=True,
                )
            descriptor = None
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                logger.debug(
                    "[atomic] 清理临时文件失败：%s",
                    temporary,
                    exc_info=True,
                )
        raise


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """把 ``data`` 原子写入 ``path``（二进制）：同目录 tmp → ``os.replace`` 覆盖。

    临时文件通过 ``O_CREAT|O_EXCL`` 以 ``0o600`` 创建，而不是事后 chmod。POSIX
    ``os.replace`` 让目标名称指向临时文件原有 inode，因而会保留该 inode 的 ``0o600``
    权限。Windows 不会把这一 mode 转换成等价的 owner-only ACL，因此不声称 Windows
    账户隔离，只保证独占临时名和原子替换。

    与 :func:`atomic_write_text` 保持同一“要么旧内容完整、要么新内容完整、绝不留半截”
    不变式，用于落盘取证制品的原始字节。

    Args:
        path: 目标文件路径。缺失的父目录会以受限创建 mode 逐级创建。
        data: 要写入的原始字节。

    Raises:
        OSError: 写临时文件、同步数据或 ``os.replace`` 失败时抛出。
    """

    target = Path(path)
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        _ensure_private_directory(target.parent)
        temporary, descriptor = _allocate_private_temporary(target)

        stream = os.fdopen(descriptor, "wb")
        descriptor = None
        with stream:
            _write_bytes_to_stream(stream, data)
            stream.flush()
            os.fsync(stream.fileno())

        _replace_temp(temporary, target)
        temporary = None
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                logger.debug(
                    "[atomic] 关闭临时文件失败：%s",
                    temporary,
                    exc_info=True,
                )
            descriptor = None
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                logger.debug(
                    "[atomic] 清理临时文件失败：%s",
                    temporary,
                    exc_info=True,
                )
        raise
