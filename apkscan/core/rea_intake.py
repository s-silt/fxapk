"""可识别的未验证 REA 观察不得作为直接案件证据。

只读候选文件本身，以及祖先目录里固定的识别名（bundle 标记、
``observation.json``、``rea-original.json``、``cdp-trace-original.json``）。不枚举无关目录。词法祖先和
解析后的物理祖先都查，直到文件系统根；链长超过硬上限则拒绝，不截断后放行。
识别依据是契约字段，不是文件名本身：普通 ``observation.json`` 不会被拒绝。
保留名 ``fxapk-rea-bundle.json`` 只要存在就拒绝，内容损坏也一样。

复制裸脚本并去掉来源标记后，无法可靠识别，本模块不声称能防止故意剥离来源。
也不会把被拒绝的文件自动改判成 batch reference。
"""

from __future__ import annotations

import json
import os
import re
import stat
import zlib
from enum import Enum
from pathlib import Path
from typing import cast

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.redact import PublicDiagnosticError, register_public_diagnostic

MARKER_NAME = "fxapk-rea-bundle.json"
_RECOGNIZER_NAMES = (
    MARKER_NAME,
    "observation.json",
    "rea-original.json",
    "cdp-trace-original.json",
)
# 与可选插件 fxapk_rea.evidence.MAX_INPUT_BYTES 对齐。核心不导入该插件。
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_PREFIX_BYTES = 65536
_MAX_ANCESTORS = 256
# 识别读取自己的合计上限，默认与网页正文上限同为 96 MiB，但是独立开关。
# 注入识别预算不得改 MAX_TOTAL_BYTES，正文载入仍走原来的合计控制。
INTAKE_READ_BUDGET_BYTES = 96 * 1024 * 1024
_GZIP_CHUNK = 64 * 1024
_DIRECT_CASE_MESSAGE = "unverified REA observation cannot be admitted as direct case evidence"
_BUDGET_MESSAGE = "unverified REA recognition exceeded the intake read budget"


class ReaIntakeCode(str, Enum):
    """REA 直接证据入口的稳定错误码。"""

    DIRECT_CASE_REFUSED = "unverified_rea_direct_intake"
    RECOGNITION_BUDGET = "rea_recognition_budget_exhausted"


_MESSAGES: dict[ReaIntakeCode, str] = {
    ReaIntakeCode.DIRECT_CASE_REFUSED: _DIRECT_CASE_MESSAGE,
    ReaIntakeCode.RECOGNITION_BUDGET: _BUDGET_MESSAGE,
}


class ReaDirectIntakeError(ValueError, PublicDiagnosticError):
    """可识别的未验证 REA 材料被拒绝进入直接案件范围。"""

    def __init__(self, code: ReaIntakeCode = ReaIntakeCode.DIRECT_CASE_REFUSED) -> None:
        if type(code) is not ReaIntakeCode:
            raise TypeError(f"code 必须是 ReaIntakeCode，收到 {type(code).__name__}")
        self._code = code
        super().__init__(_MESSAGES[code])

    @property
    def code(self) -> ReaIntakeCode:
        return self._code

    @property
    def public_message(self) -> str:
        return _MESSAGES[self._code]

    @property
    def diagnostic_code(self) -> str:
        return self._code.value


register_public_diagnostic(
    ReaDirectIntakeError, lambda exc: cast(ReaDirectIntakeError, exc).public_message
)


def write_rea_bundle_marker(directory: Path) -> None:
    """在输出目录落本地 bundle 标记。调用方必须在任何原始/脚本/execution 产物之前调用。"""
    payload = {
        "kind": "unverified_external_observation_bundle",
        "producer": "rea",
        "schema_version": "fxapk-rea-bundle-marker/1",
    }
    raw = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")
    if not atomic_create_bytes(directory / MARKER_NAME, raw):
        raise FileExistsError("rea bundle marker exists")


class ReaIntakeBudget:
    """一次入口内的识别读取预算。多个候选共用同一个对象，不按文件重置。"""

    def __init__(self, limit: int) -> None:
        if type(limit) is not int or isinstance(limit, bool) or limit < 0:
            raise ValueError("intake read budget must be a non-negative integer")
        self.limit = limit
        self.used = 0

    def charge(self, count: int) -> None:
        if type(count) is not int or isinstance(count, bool) or count < 0:
            raise ReaDirectIntakeError(ReaIntakeCode.RECOGNITION_BUDGET)
        if count > self.limit - self.used:
            raise ReaDirectIntakeError(ReaIntakeCode.RECOGNITION_BUDGET)
        self.used += count


def refuse_unverified_rea_directory(
    directory: Path,
    *,
    cache: dict[str, bool] | None = None,
    budget: ReaIntakeBudget | None = None,
) -> None:
    """检查证据根自己的保留识别名，不依赖遍历是否发现了普通文件。"""
    remembered = cache if cache is not None else {}
    try:
        if _directory_refuses(directory, remembered, budget):
            raise ReaDirectIntakeError()
    except RecursionError as exc:
        raise ReaDirectIntakeError() from exc


def refuse_unverified_rea_direct_intake(
    path: Path,
    *,
    root: Path,
    cache: dict[str, bool] | None = None,
    budget: ReaIntakeBudget | None = None,
) -> None:
    """识别到 REA 来源时抛出 :class:`ReaDirectIntakeError`。

    ``root`` 是本次入口的证据根或包根。候选文件与该根的词法路径、以及两者
    解析后的物理路径，其祖先都会检查，直到文件系统根。这样 ``scripts/`` 入口、
    更深的嵌套目录、以及指向 bundle 的目录联接都仍能看见标记或旧回执。
    祖先层数超过 :data:`_MAX_ANCESTORS` 时拒绝，而不是截断后放行。
    """
    remembered = cache if cache is not None else {}
    try:
        for directory in _provenance_directories(path, root):
            if _directory_refuses(directory, remembered, budget):
                raise ReaDirectIntakeError()
        if _file_is_rea_document(path, budget):
            raise ReaDirectIntakeError()
    except RecursionError as exc:
        raise ReaDirectIntakeError() from exc


def _provenance_directories(path: Path, root: Path) -> list[Path]:
    """词法祖先加上物理祖先。解析失败不是“没有来源”，按拒绝处理。"""
    seeds: list[Path] = []
    seen_seeds: set[str] = set()

    def add_seed(candidate: Path) -> None:
        absolute = os.path.abspath(candidate)
        key = os.path.normcase(absolute)
        if key in seen_seeds:
            return
        seen_seeds.add(key)
        seeds.append(Path(absolute))

    add_seed(path)
    for origin in (path, root):
        try:
            add_seed(Path(origin).resolve())
        except OSError as exc:
            raise ReaDirectIntakeError() from exc
    directories: list[Path] = []
    seen_dirs: set[str] = set()
    for seed in seeds:
        for directory in _ancestor_directories(seed):
            key = os.path.normcase(str(directory))
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            directories.append(directory)
    return directories


def _ancestor_directories(path: Path) -> list[Path]:
    """从 ``path`` 的父目录走到文件系统根。超上限则拒绝，不返回截断链。"""
    current = Path(os.path.abspath(path)).parent
    chain: list[Path] = []
    for _ in range(_MAX_ANCESTORS):
        chain.append(current)
        parent = current.parent
        if parent == current:
            return chain
        current = parent
    raise ReaDirectIntakeError()


def _directory_refuses(
    directory: Path, cache: dict[str, bool], budget: ReaIntakeBudget | None
) -> bool:
    key = os.path.normcase(str(directory))
    remembered = cache.get(key)
    if remembered is not None:
        return remembered
    refused = any(
        _recognizer_refuses(directory / name, budget) for name in _RECOGNIZER_NAMES
    )
    cache[key] = refused
    return refused


def _is_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _recognizer_refuses(candidate: Path, budget: ReaIntakeBudget | None) -> bool:
    """固定识别名：不存在则放过；元数据失败、链接、非普通文件或契约命中则拒绝。

    ``FileNotFoundError`` 才是缺失。权限或其他 ``OSError`` 不是缺失。
    保留标记名只要作为普通文件存在就拒绝，不要求内容仍是合法标记。
    """
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    is_junction = getattr(candidate, "is_junction", None)
    try:
        if is_junction is not None and is_junction():
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if not stat.S_ISREG(info.st_mode):
        return True
    if os.path.normcase(candidate.name) == os.path.normcase(MARKER_NAME):
        return True
    try:
        with candidate.open("rb") as stream:
            data = stream.read(_MAX_DOCUMENT_BYTES + 1)
    except OSError:
        return True
    if budget is not None:
        budget.charge(len(data))
    return _matches_rea_contract(data, fail_closed=True, budget=budget)


def _confirmed_file_link(path: Path) -> bool:
    """只把明确的文件链接判为链接。元数据读失败留给后续打开处理。"""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return False


def _candidate_matches_rea_document(path: Path, budget: ReaIntakeBudget | None, *, link: bool) -> bool:
    try:
        with path.open("rb") as stream:
            buffered = _read_bounded_document(stream, budget)
    except OSError:
        return link
    if buffered is None:
        return False
    return _matches_rea_contract(buffered, fail_closed=False, budget=budget)


def _file_is_rea_document(path: Path, budget: ReaIntakeBudget | None = None) -> bool:
    """普通文件只看自身内容。文件链接同时看词法路径和解析目标，读失败则拒绝。"""
    linked = _confirmed_file_link(path)
    if _candidate_matches_rea_document(path, budget, link=linked):
        return True
    if not linked:
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return True
    if os.path.normcase(os.path.abspath(resolved)) == os.path.normcase(os.path.abspath(path)):
        return False
    return _candidate_matches_rea_document(resolved, budget, link=True)


def _read_bounded_document(stream: object, budget: ReaIntakeBudget | None = None) -> bytes | None:
    """在上限内读完整份候选。前导空白不构成“不是 JSON”。"""
    reader = getattr(stream, "read", None)
    if reader is None:
        return None
    buffered = bytearray()
    while len(buffered) <= _MAX_DOCUMENT_BYTES:
        decision = _document_prefix_decision(bytes(buffered)) if buffered else None
        if decision is False:
            return None
        if decision is True:
            break
        room = _MAX_DOCUMENT_BYTES + 1 - len(buffered)
        if room <= 0:
            return None
        block = reader(min(65536, room))
        if not isinstance(block, (bytes, bytearray)) or not block:
            return None
        if budget is not None:
            budget.charge(len(block))
        buffered.extend(block)
    else:
        return None
    room = _MAX_DOCUMENT_BYTES + 1 - len(buffered)
    if room > 0:
        extra = reader(room)
        if isinstance(extra, (bytes, bytearray)) and extra:
            if budget is not None:
                budget.charge(len(extra))
            buffered.extend(extra)
    return bytes(buffered)


_DOCUMENT_MAGICS = (b"\x1f\x8b", b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


def _document_prefix_decision(data: bytes) -> bool | None:
    """True 继续按文档解析，False 不是文档，None 还只有空白、需要再读。"""
    if data.startswith(_DOCUMENT_MAGICS):
        return True
    stripped = data.lstrip(b" \t\r\n\v\f")
    if not stripped:
        return None
    if stripped.startswith(b"{") or stripped.startswith(_DOCUMENT_MAGICS):
        return True
    return False


def _matches_rea_contract(
    data: bytes, *, fail_closed: bool, budget: ReaIntakeBudget | None = None
) -> bool:
    try:
        plain = _inflate(data)
    except _Oversize as oversize:
        if budget is not None and data.startswith(b"\x1f\x8b"):
            budget.charge(oversize.produced)
        return _prefix_matches(oversize.sample) or fail_closed
    except RecursionError:
        return True
    except ValueError as exc:
        produced = getattr(exc, "produced", 0)
        if (
            budget is not None
            and data.startswith(b"\x1f\x8b")
            and type(produced) is int
            and not isinstance(produced, bool)
            and produced > 0
        ):
            budget.charge(produced)
        return fail_closed
    if budget is not None and data.startswith(b"\x1f\x8b"):
        budget.charge(len(plain))
    if len(plain) > _MAX_DOCUMENT_BYTES:
        return _prefix_matches(plain[:_PREFIX_BYTES]) or fail_closed
    text = _decode_text(plain)
    if text is None:
        return fail_closed
    try:
        value = json.loads(text)
    except RecursionError:
        return True
    except ValueError:
        # 语法损坏不是契约命中。保留标记名在读到这里之前已经拒绝。
        return False
    return isinstance(value, dict) and _is_rea_object(value)


class _Oversize(Exception):
    def __init__(self, sample: bytes, produced: int = 0) -> None:
        super().__init__("rea recognition input exceeds bounded read")
        self.sample = sample
        self.produced = produced


class _GzipFailure(ValueError):
    """gzip 成员失败。

    ``produced`` 含已返回的字节，再加上失败那次调用的有界输出额度。
    zlib 丢掉的那一块实际长度不可知，额度本身已有上限，不另估无界输出。
    """

    def __init__(self, produced: int) -> None:
        super().__init__("gzip")
        self.produced = produced


def _inflate(data: bytes) -> bytes:
    if not data.startswith(b"\x1f\x8b"):
        if len(data) > _MAX_DOCUMENT_BYTES:
            raise _Oversize(data[:_PREFIX_BYTES], len(data))
        return data
    pending = data
    out = bytearray()
    while pending:
        if not pending.startswith(b"\x1f\x8b"):
            raise _GzipFailure(len(out))
        decompressor = zlib.decompressobj(wbits=31)
        source = pending
        while not decompressor.eof:
            room = _MAX_DOCUMENT_BYTES + 1 - len(out)
            if room <= 0:
                raise _Oversize(bytes(out[:_PREFIX_BYTES]), len(out))
            before = len(source)
            allowance = min(_GZIP_CHUNK, room)
            try:
                piece = decompressor.decompress(source, allowance)
            except zlib.error as exc:
                raise _GzipFailure(len(out) + allowance) from exc
            out.extend(piece)
            source = decompressor.unconsumed_tail
            if len(out) > _MAX_DOCUMENT_BYTES:
                raise _Oversize(bytes(out[:_PREFIX_BYTES]), len(out))
            if decompressor.eof:
                break
            if not piece and len(source) >= before:
                raise _GzipFailure(len(out) + allowance)
        pending = decompressor.unused_data
    return bytes(out)


def _decode_text(data: bytes) -> str | None:
    if data.startswith(b"\x00\x00\xfe\xff"):
        codec = "utf-32-be"
    elif data.startswith(b"\xff\xfe\x00\x00"):
        codec = "utf-32-le"
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        codec = "utf-16"
    else:
        codec = "utf-8-sig"
    try:
        text = data.decode(codec)
    except UnicodeError:
        return None
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def _prefix_matches(sample: bytes) -> bool:
    text = _decode_text(sample)
    if text is None or not text.lstrip().startswith("{"):
        return False
    compact = re.sub(r"\s+", "", text)
    if (
        '"schema_version":"fxapk-rea-bundle-marker/1"' in compact
        and '"producer":"rea"' in compact
        and '"kind":"unverified_external_observation_bundle"' in compact
    ):
        return True
    if '"schema_version":"rea-web-observation/' in compact and '"producer":"rea"' in compact:
        return True
    if '"producer":"fxapk-cdp-trace"' in compact and (
        '"schema_version":"fxapk-cdp-trace/1"' in compact
        or '"schema_version":"fxapk-cdp-trace-observation/1"' in compact
    ):
        return True
    return (
        '"operation":"inspect_web_page"' in compact
        and '"predicate_type":"rea.web-page-inspection"' in compact
        and '"id":"rea-cdp-browser"' in compact
    )


def _is_rea_object(value: dict[str, object]) -> bool:
    schema = value.get("schema_version")
    producer = value.get("producer")
    if schema == "fxapk-rea-bundle-marker/1" and producer == "rea":
        return value.get("kind") == "unverified_external_observation_bundle"
    if isinstance(schema, str) and schema.startswith("rea-web-observation/") and producer == "rea":
        return True
    if producer == "fxapk-cdp-trace" and schema in (
        "fxapk-cdp-trace/1",
        "fxapk-cdp-trace-observation/1",
    ):
        return True
    data = value.get("data")
    if not isinstance(data, dict):
        return False
    provider = data.get("provider")
    if not isinstance(provider, dict):
        return False
    return (
        data.get("operation") == "inspect_web_page"
        and data.get("predicate_type") == "rea.web-page-inspection"
        and provider.get("id") == "rea-cdp-browser"
    )
