"""JADX 持久化索引：契约与身份层（S1）+ 存储层（S2）。

S1：数据契约、DEX 输入复算校验、域分离 key 派生。
S2：受控 cache root、create-only 原子发布、fail-closed 加载校验链。
本模块不负责 JADX 调用、源码枚举与查询（S3）。
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from apkscan.core.atomic import AtomicCreateUnsupportedError, atomic_create_bytes
from apkscan.core.recognition_codec import canonical_json_v1, parse_json_v1


INDEX_SCHEMA_VERSION = "1.0"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# CacheMiss 的稳定 reason code。
REASON_ABSENT = "absent"
REASON_MALFORMED = "malformed"
REASON_SCHEMA_DRIFT = "schema_drift"
REASON_TOOL_DRIFT = "tool_drift"
REASON_KEY_MISMATCH = "key_mismatch"
REASON_SHARD_DIGEST_MISMATCH = "shard_digest_mismatch"
REASON_DUPLICATE_POSTING = "duplicate_posting"
REASON_PATH_ESCAPE = "path_escape"
REASON_NORMALIZATION_CONFLICT = "normalization_conflict"

# CacheUnavailable 的稳定 reason code。
REASON_PERMISSION_DENIED = "permission_denied"
REASON_ATOMIC_CREATE_UNSUPPORTED = "atomic_create_unsupported"
REASON_LOCK_CONTENDED = "lock_contended"
REASON_IO_ERROR = "io_error"

# 输入与身份校验的稳定 reason code。
REASON_INVALID_ROLE = "invalid_role"
REASON_INVALID_ORDINAL = "invalid_ordinal"
REASON_INVALID_SOURCE_LABEL = "invalid_source_label"
REASON_INVALID_RELATIVE_PATH = "invalid_relative_path"
REASON_INVALID_DIGEST = "invalid_digest"
REASON_DIGEST_MISMATCH = "digest_mismatch"
REASON_MAPPED_FILE_MISSING = "mapped_file_missing"
REASON_MAPPED_FILE_NOT_REGULAR = "mapped_file_not_regular"
REASON_DUPLICATE_LINEAGE = "duplicate_lineage"
REASON_INVALID_SOURCE_ROOT = "invalid_source_root"


class JadxIndexError(ValueError):
    """JADX 索引输入或身份不满足契约时抛出的结构化拒绝。"""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.field_path = path
        super().__init__(f"{code} at {path}")


def _fail(code: str, path: str = "$") -> NoReturn:
    raise JadxIndexError(code, path)


def _require_nfc_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(REASON_INVALID_SOURCE_LABEL, path)
    if unicodedata.normalize("NFC", value) != value:
        _fail("non_nfc_string", path)
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        _fail("forbidden_unicode_category", path)
    return value


def _validate_digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(REASON_INVALID_DIGEST, path)
    return value


def _normalize_safe_relative_path(value: object, path: str) -> str:
    """只接受无歧义的 POSIX 相对路径，不负责解析文件系统路径。"""
    if not isinstance(value, str) or not value:
        _fail(REASON_INVALID_RELATIVE_PATH, path)

    # 反斜杠在不同平台上含义不同，不能把它当作普通文件名字符。
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        _fail(REASON_INVALID_RELATIVE_PATH, path)

    # 驱动器路径、UNC 形式以及 drive-relative 形式均不属于安全相对路径。
    if re.match(r"^[A-Za-z]:", value) or value.startswith("//"):
        _fail(REASON_INVALID_RELATIVE_PATH, path)

    parts = value.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail(REASON_INVALID_RELATIVE_PATH, path)

    if unicodedata.normalize("NFC", value) != value:
        # 保留原始路径以便验证阶段报告 NFC 冲突；规范化编码由调用方
        # 在确认无冲突后自行产生。
        _fail("non_nfc_string", path)

    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        _fail("forbidden_unicode_category", path)

    return value


def _role_sort_value(role: DexRole) -> str:
    return role.value


class DexRole(StrEnum):
    APK_DEX = "apk_dex"
    EXTRA_DEX = "extra_dex"


@dataclass(frozen=True, slots=True)
class DexLineage:
    """已验证 DEX 的逻辑身份；不包含任何文件系统路径。"""

    role: DexRole
    ordinal: int
    source_label: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, DexRole):
            _fail(REASON_INVALID_ROLE, "$.role")
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 0:
            _fail(REASON_INVALID_ORDINAL, "$.ordinal")
        _require_nfc_string(self.source_label, "$.source_label")
        _validate_digest(self.digest, "$.digest")

    def to_record(self) -> dict[str, object]:
        """返回 canonical_json_v1 可编码、且不含路径的记录。"""
        return {
            "role": self.role.value,
            "ordinal": self.ordinal,
            "source_label": self.source_label,
            "digest": self.digest,
        }

    def sort_key(self) -> tuple[str, int, str, str]:
        return (
            _role_sort_value(self.role),
            self.ordinal,
            self.source_label,
            self.digest,
        )


@dataclass(frozen=True, slots=True)
class DexInput:
    """调用方提供的临时 DEX 映射及其待验证 digest 声明。"""

    role: DexRole
    ordinal: int
    source_label: str
    relative_path: str
    declared_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, DexRole):
            _fail(REASON_INVALID_ROLE, "$.role")
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 0:
            _fail(REASON_INVALID_ORDINAL, "$.ordinal")
        _require_nfc_string(self.source_label, "$.source_label")
        _normalize_safe_relative_path(self.relative_path, "$.relative_path")
        _validate_digest(self.declared_digest, "$.declared_digest")

    def lineage(self, verified_digest: str) -> DexLineage:
        return DexLineage(
            role=self.role,
            ordinal=self.ordinal,
            source_label=self.source_label,
            digest=_validate_digest(verified_digest, "$.digest"),
        )


@dataclass(frozen=True, slots=True)
class JadxIndexManifest:
    """索引清单的持久化契约；具体发布由后续切片实现。"""

    index_key: str
    key_material: Mapping[str, object]
    dex_lineage: tuple[DexLineage, ...]
    jadx_version: str
    # options_digest 必填：它是 key material 的一部分，绝不能有"看起来合法"的默认值
    # （sha256: 语法校验会拒掉任何占位默认，宁缺毋滥）。
    options_digest: str
    shard_refs: tuple[ShardRef, ...] = ()
    coverage: str = "complete"
    aggregate_digest: str = ""
    index_schema_version: str = INDEX_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.index_key, str) or not re.fullmatch(r"[0-9a-f]{64}", self.index_key):
            _fail(REASON_INVALID_DIGEST, "$.index_key")
        if not isinstance(self.key_material, Mapping):
            _fail("invalid_key_material", "$.key_material")
        if not isinstance(self.dex_lineage, tuple):
            _fail("lineage_must_be_tuple", "$.dex_lineage")
        if not isinstance(self.shard_refs, tuple) or any(
            not isinstance(ref, ShardRef) for ref in self.shard_refs
        ):
            _fail("shard_refs_must_be_tuple", "$.shard_refs")
        # coverage 是受控枚举，不是自由文本：任何拼写/大小写漂移都是篡改或 bug 信号。
        if self.coverage not in ("complete", "partial"):
            _fail("invalid_coverage", "$.coverage")
        if not isinstance(self.jadx_version, str) or not self.jadx_version:
            _fail("invalid_jadx_version", "$.jadx_version")
        _validate_digest(self.options_digest, "$.options_digest")
        if self.index_schema_version != INDEX_SCHEMA_VERSION:
            _fail(REASON_SCHEMA_DRIFT, "$.index_schema_version")


@dataclass(frozen=True, slots=True)
class ShardRef:
    """manifest 中对单个 shard 的引用：shard key 与其 canonical 字节的 sha256。"""

    shard_key: str
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.shard_key, str) or not re.fullmatch(r"[0-9a-f]{64}", self.shard_key):
            _fail(REASON_INVALID_DIGEST, "$.shard_key")
        if not isinstance(self.digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            _fail(REASON_INVALID_DIGEST, "$.digest")

    def to_record(self) -> dict[str, object]:
        return {"shard_key": self.shard_key, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class CacheMiss:
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CacheUnavailable:
    reason: str
    detail: str = ""


class IndexBuildState(StrEnum):
    BUILT = "built"
    REUSED = "reused"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class IndexBuildResult:
    state: IndexBuildState
    coverage: str
    manifest_locator: str | None = None
    shard_locators: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    manifest: JadxIndexManifest | None = None


@dataclass(frozen=True, slots=True)
class LoadedIndex:
    manifest: JadxIndexManifest
    shard_locators: tuple[str, ...] = ()
    coverage: str = "complete"
    #: 已验证 shard 的解析后 JSON 值（S3 查询层消费）；只含相对路径与 postings，无源码。
    shards: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class UsageHit:
    relative_path: str
    line: int
    column: int
    value_digest: str
    lineage: DexLineage
    class_context: str | None = None
    method_context: str | None = None
    ownership: str = "unknown"

    def __post_init__(self) -> None:
        _normalize_safe_relative_path(self.relative_path, "$.relative_path")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            _fail("invalid_line", "$.line")
        if isinstance(self.column, bool) or not isinstance(self.column, int) or self.column < 1:
            _fail("invalid_column", "$.column")
        _validate_digest(self.value_digest, "$.value_digest")
        if not isinstance(self.lineage, DexLineage):
            _fail("invalid_lineage", "$.lineage")
        if self.ownership != "unknown":
            _fail("invalid_ownership", "$.ownership")


def _resolve_source_root(source_root: str | os.PathLike[str]) -> Path:
    try:
        root = Path(source_root)
    except (TypeError, ValueError) as exc:
        raise JadxIndexError(REASON_INVALID_SOURCE_ROOT) from exc
    if not root.is_absolute():
        _fail(REASON_INVALID_SOURCE_ROOT, "$.source_root")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise JadxIndexError(REASON_INVALID_SOURCE_ROOT, "$.source_root") from exc
    if not resolved.is_dir():
        _fail(REASON_INVALID_SOURCE_ROOT, "$.source_root")
    return resolved


def _mapped_path(root: Path, relative_path: str, path: str) -> Path:
    _normalize_safe_relative_path(relative_path, path)
    candidate = root / Path(*relative_path.split("/"))
    # 文件不存在与路径逃逸是不同的拒绝语义：前者是输入缺失（可补），
    # 后者是安全违规（绝不放行）。
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise JadxIndexError(REASON_MAPPED_FILE_MISSING, path) from exc
    except (OSError, RuntimeError) as exc:
        raise JadxIndexError(REASON_PATH_ESCAPE, path) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise JadxIndexError(REASON_PATH_ESCAPE, path) from exc
    return resolved


def verify_dex_inputs(
    source_root: str | os.PathLike[str],
    inputs: Iterable[DexInput],
) -> tuple[DexLineage, ...]:
    """读取并复算所有映射 DEX，返回确定排序后的已验证 lineage。"""
    root = _resolve_source_root(source_root)
    items = tuple(inputs)
    seen_paths: dict[str, str] = {}
    lineages: list[DexLineage] = []
    seen_lineages: set[tuple[DexRole, int, str, str]] = set()

    for index, item in enumerate(items):
        if not isinstance(item, DexInput):
            _fail("invalid_dex_input", f"$.inputs[{index}]")

        normalized_key = unicodedata.normalize("NFC", item.relative_path).casefold()
        previous = seen_paths.get(normalized_key)
        if previous is not None:
            raise JadxIndexError(
                REASON_NORMALIZATION_CONFLICT,
                f"$.inputs[{index}].relative_path",
            )
        seen_paths[normalized_key] = item.relative_path

        mapped = _mapped_path(
            root,
            item.relative_path,
            f"$.inputs[{index}].relative_path",
        )
        if not mapped.is_file():
            _fail(
                REASON_MAPPED_FILE_NOT_REGULAR,
                f"$.inputs[{index}].relative_path",
            )

        try:
            actual = mapped.read_bytes()
        except OSError as exc:
            raise JadxIndexError(
                REASON_MAPPED_FILE_MISSING,
                f"$.inputs[{index}].relative_path",
            ) from exc

        actual_digest = "sha256:" + hashlib.sha256(actual).hexdigest()
        if actual_digest != item.declared_digest:
            _fail(
                REASON_DIGEST_MISMATCH,
                f"$.inputs[{index}].declared_digest",
            )

        lineage = item.lineage(actual_digest)
        identity = (
            lineage.role,
            lineage.ordinal,
            lineage.source_label,
            lineage.digest,
        )
        if identity in seen_lineages:
            _fail(REASON_DUPLICATE_LINEAGE, f"$.inputs[{index}]")
        seen_lineages.add(identity)
        lineages.append(lineage)

    return tuple(sorted(lineages, key=DexLineage.sort_key))


def _validate_identity_inputs(
    jadx_version: str,
    options_digest: str,
    index_schema_version: str,
) -> None:
    if not isinstance(jadx_version, str) or not jadx_version:
        _fail("invalid_jadx_version", "$.jadx_version")
    _require_nfc_string(jadx_version, "$.jadx_version")
    _validate_digest(options_digest, "$.options_digest")
    if index_schema_version != INDEX_SCHEMA_VERSION:
        _fail(REASON_SCHEMA_DRIFT, "$.index_schema_version")


def build_key_material(
    dex_lineage: Iterable[DexLineage],
    jadx_version: str,
    options_digest: str,
    index_schema_version: str = INDEX_SCHEMA_VERSION,
) -> dict[str, object]:
    """生成不依赖映射路径或字典插入顺序的 key material。"""
    _validate_identity_inputs(
        jadx_version,
        options_digest,
        index_schema_version,
    )
    lineage = tuple(dex_lineage)
    ordered = tuple(sorted(lineage, key=DexLineage.sort_key))
    identities = [
        (
            item.role,
            item.ordinal,
            item.source_label,
            item.digest,
        )
        for item in ordered
    ]
    if len(set(identities)) != len(identities):
        _fail(REASON_DUPLICATE_LINEAGE, "$.dex_lineage")

    return {
        "dex_lineage": [item.to_record() for item in ordered],
        "jadx_version": jadx_version,
        "options_digest": options_digest,
        "index_schema_version": index_schema_version,
    }


def derive_index_key(
    dex_lineage: Iterable[DexLineage],
    jadx_version: str,
    options_digest: str,
    index_schema_version: str = INDEX_SCHEMA_VERSION,
) -> str:
    material = build_key_material(
        dex_lineage,
        jadx_version,
        options_digest,
        index_schema_version,
    )
    encoded = canonical_json_v1(material)
    return hashlib.sha256(b"fxapk.jadx.index/key/v1\0" + encoded).hexdigest()


def derive_shard_key(
    lineage: DexLineage,
    jadx_version: str,
    options_digest: str,
    index_schema_version: str = INDEX_SCHEMA_VERSION,
) -> str:
    _validate_identity_inputs(
        jadx_version,
        options_digest,
        index_schema_version,
    )
    material = {
        "dex_lineage": lineage.to_record(),
        "jadx_version": jadx_version,
        "options_digest": options_digest,
        "index_schema_version": index_schema_version,
    }
    encoded = canonical_json_v1(material)
    return hashlib.sha256(b"fxapk.jadx.index/shard/v1\0" + encoded).hexdigest()


# ---------------------------------------------------------------------------
# S2：存储层 reason code
# ---------------------------------------------------------------------------

REASON_INVALID_CACHE_ROOT = "invalid_cache_root"
REASON_INVALID_PROTECTED_ROOT = "invalid_protected_root"
REASON_PROTECTED_ROOT_OVERLAP = "protected_root_overlap"
REASON_CACHE_CONFLICT = "cache_conflict"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class _StorageUnavailableError(Exception):
    """内部信使：环境层故障沿调用栈上抛，公共入口转 CacheUnavailable 值返回。

    CacheUnavailable 本身是数据类不是异常——把它 raise 出去是类型错误，
    也会破坏「公共 API 以返回值表达三态」的契约。
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _is_reparse_or_symlink(path: Path) -> bool:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return True
    return getattr(info, "st_reparse_tag", 0) != 0


def _components_contain(outer: tuple[str, ...], inner: tuple[str, ...]) -> bool:
    if len(inner) > len(outer):
        return False
    return outer[: len(inner)] == inner


def _resolve_root(value: str | os.PathLike[str], reason: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _fail(reason, "$")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw.strip():
        _fail(reason, "$")
    if raw.lower().startswith("file:"):
        _fail(reason, "$")
    path = Path(raw)
    if not path.is_absolute():
        _fail(reason, "$")
    # UNC / 网络路径一律拒绝：其解析语义与本地受控目录不同（凭据、延迟挂载、
    # 大小写规则均不可控），不属于安全 cache root。
    if raw.startswith(("\\\\", "//")):
        _fail(reason, "$")
    if os.name == "nt":
        drive, tail = os.path.splitdrive(raw)
        if drive and not tail.startswith(("\\", "/")):
            _fail(reason, "$")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        _fail(reason, "$")
    if not resolved.is_absolute():
        _fail(reason, "$")
    return resolved


def _contained_locator(cache_root: Path, locator: Path) -> Path:
    """校验 locator 解析后留在 cache_root 内，已存在组件无 symlink/junction/reparse 逃逸。"""
    try:
        relative = locator.relative_to(cache_root)
    except ValueError:
        _fail(REASON_PATH_ESCAPE, "$")
    current = cache_root
    for component in relative.parts:
        current = current / component
        if not current.exists():
            break
        if _is_reparse_or_symlink(current):
            _fail(REASON_PATH_ESCAPE, "$")
    try:
        if not locator.resolve(strict=False).is_relative_to(cache_root):
            _fail(REASON_PATH_ESCAPE, "$")
    except (OSError, RuntimeError):
        _fail(REASON_PATH_ESCAPE, "$")
    return locator


def _lineage_from_records(records: object) -> tuple[DexLineage, ...]:
    """从 manifest 的 key_material 记录重建 lineage；任何形状偏差抛 JadxIndexError。"""
    if not isinstance(records, list):
        _fail(REASON_MALFORMED, "$.key_material.dex_lineage")
    out: list[DexLineage] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or set(rec) != {"role", "ordinal", "source_label", "digest"}:
            _fail(REASON_MALFORMED, f"$.key_material.dex_lineage[{i}]")
        role_raw = rec["role"]
        if role_raw not in (DexRole.APK_DEX.value, DexRole.EXTRA_DEX.value):
            _fail(REASON_MALFORMED, f"$.key_material.dex_lineage[{i}].role")
        ordinal = rec["ordinal"]
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            _fail(REASON_MALFORMED, f"$.key_material.dex_lineage[{i}].ordinal")
        label = rec["source_label"]
        digest = rec["digest"]
        if not isinstance(label, str) or not isinstance(digest, str):
            _fail(REASON_MALFORMED, f"$.key_material.dex_lineage[{i}]")
        out.append(DexLineage(DexRole(role_raw), ordinal, label, digest))
    return tuple(out)


def _manifest_record(manifest: JadxIndexManifest) -> dict[str, object]:
    """canonical_json_v1 可编码的 manifest 记录（显式手写，不依赖 asdict 的隐式形态）。"""
    return {
        "index_key": manifest.index_key,
        "key_material": dict(manifest.key_material),
        "dex_lineage": [lin.to_record() for lin in manifest.dex_lineage],
        "jadx_version": manifest.jadx_version,
        "options_digest": manifest.options_digest,
        "shard_refs": [ref.to_record() for ref in manifest.shard_refs],
        "coverage": manifest.coverage,
        "aggregate_digest": manifest.aggregate_digest,
        "index_schema_version": manifest.index_schema_version,
    }


class JadxIndexStore:
    """受控 cache root 上的 create-only 索引存储。

    公共方法以返回值表达三态（LoadedIndex/IndexBuildResult | CacheMiss | CacheUnavailable）；
    构造期的配置错误（非法 root、保护根重叠）是调用方 bug，直接抛 JadxIndexError。
    """

    def __init__(
        self,
        cache_root: str | os.PathLike[str],
        *,
        protected_roots: Iterable[str | os.PathLike[str]] = (),
    ) -> None:
        self.cache_root = _resolve_root(cache_root, REASON_INVALID_CACHE_ROOT)
        resolved_protected = tuple(
            _resolve_root(root, REASON_INVALID_PROTECTED_ROOT) for root in protected_roots
        )
        cache_parts = tuple(part.casefold() for part in self.cache_root.parts)
        for protected in resolved_protected:
            protected_parts = tuple(part.casefold() for part in protected.parts)
            if _components_contain(cache_parts, protected_parts) or _components_contain(
                protected_parts, cache_parts
            ):
                _fail(REASON_PROTECTED_ROOT_OVERLAP, "$.cache_root")
        self.protected_roots = resolved_protected

    # -- 路径 --------------------------------------------------------------

    def _index_dir(self, index_key: str) -> Path:
        if not _HEX64_RE.fullmatch(index_key):
            _fail(REASON_MALFORMED, "$.index_key")
        return _contained_locator(self.cache_root, self.cache_root / index_key)

    def _manifest_path(self, index_key: str) -> Path:
        return _contained_locator(self.cache_root, self._index_dir(index_key) / "manifest.json")

    def _shard_path(self, index_key: str, shard_key: str) -> Path:
        if not _HEX64_RE.fullmatch(shard_key):
            _fail(REASON_MALFORMED, "$.shard_key")
        return _contained_locator(
            self.cache_root, self._index_dir(index_key) / "shards" / f"{shard_key}.json"
        )

    # -- 发布 --------------------------------------------------------------

    @staticmethod
    def _publish_bytes(path: Path, data: bytes) -> bool:
        """True=本次发布；False=已存在且内容逐字节相等（复用）；
        内容不等抛 cache_conflict；环境故障抛 _StorageUnavailableError。"""
        try:
            published = atomic_create_bytes(path, data)
        except AtomicCreateUnsupportedError as exc:
            raise _StorageUnavailableError(REASON_ATOMIC_CREATE_UNSUPPORTED) from exc
        except PermissionError as exc:
            raise _StorageUnavailableError(REASON_PERMISSION_DENIED) from exc
        except OSError as exc:
            raise _StorageUnavailableError(REASON_IO_ERROR) from exc
        if published:
            return True
        try:
            existing = path.read_bytes()
        except PermissionError as exc:
            raise _StorageUnavailableError(REASON_PERMISSION_DENIED) from exc
        except OSError as exc:
            raise _StorageUnavailableError(REASON_IO_ERROR) from exc
        if existing == data:
            return False
        _fail(REASON_CACHE_CONFLICT, "$")

    # -- 加载 --------------------------------------------------------------

    def load_index(self, index_key: str) -> LoadedIndex | CacheMiss | CacheUnavailable:
        if not isinstance(index_key, str) or not _HEX64_RE.fullmatch(index_key):
            return CacheMiss(REASON_MALFORMED, "index_key syntax")
        try:
            manifest_path = self._manifest_path(index_key)
        except JadxIndexError as exc:
            return CacheMiss(exc.code, exc.field_path)
        try:
            manifest_bytes = manifest_path.read_bytes()
        except FileNotFoundError:
            return CacheMiss(REASON_ABSENT)
        except PermissionError:
            return CacheUnavailable(REASON_PERMISSION_DENIED)
        except OSError:
            return CacheUnavailable(REASON_IO_ERROR)

        try:
            value = parse_json_v1(manifest_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return CacheMiss(REASON_MALFORMED, "manifest json")
        if not isinstance(value, dict):
            return CacheMiss(REASON_MALFORMED, "manifest not object")
        # canonical 字节自证：读回内容重编码必须逐字节一致，否则视为被篡改。
        if canonical_json_v1(value) != manifest_bytes:
            return CacheMiss(REASON_MALFORMED, "manifest not canonical")

        if value.get("index_schema_version") != INDEX_SCHEMA_VERSION:
            return CacheMiss(REASON_SCHEMA_DRIFT)
        if value.get("index_key") != index_key:
            return CacheMiss(REASON_KEY_MISMATCH, "manifest index_key")

        key_material = value.get("key_material")
        if not isinstance(key_material, dict):
            return CacheMiss(REASON_MALFORMED, "key_material")
        try:
            lineage = _lineage_from_records(key_material.get("dex_lineage"))
            jadx_version = key_material.get("jadx_version")
            options_digest = key_material.get("options_digest")
            schema_version = key_material.get("index_schema_version")
            if not isinstance(jadx_version, str) or not isinstance(options_digest, str):
                return CacheMiss(REASON_MALFORMED, "key_material identity")
            if schema_version != INDEX_SCHEMA_VERSION:
                return CacheMiss(REASON_SCHEMA_DRIFT, "key_material schema")
            derived = derive_index_key(lineage, jadx_version, options_digest)
        except JadxIndexError as exc:
            return CacheMiss(REASON_MALFORMED, exc.code)
        if derived != index_key:
            return CacheMiss(REASON_KEY_MISMATCH, "re-derived key differs")

        refs_raw = value.get("shard_refs")
        if not isinstance(refs_raw, list):
            return CacheMiss(REASON_MALFORMED, "shard_refs")
        shard_values: list[Mapping[str, object]] = []
        shard_locators: list[str] = []
        shard_refs: list[ShardRef] = []
        for i, ref in enumerate(refs_raw):
            if not isinstance(ref, dict) or set(ref) != {"shard_key", "digest"}:
                return CacheMiss(REASON_MALFORMED, f"shard_refs[{i}]")
            try:
                shard_ref = ShardRef(str(ref["shard_key"]), str(ref["digest"]))
                shard_path = self._shard_path(index_key, shard_ref.shard_key)
            except JadxIndexError as exc:
                return CacheMiss(exc.code, f"shard_refs[{i}]")
            try:
                shard_bytes = shard_path.read_bytes()
            except FileNotFoundError:
                return CacheMiss(REASON_ABSENT, f"shard {i}")
            except PermissionError:
                return CacheUnavailable(REASON_PERMISSION_DENIED)
            except OSError:
                return CacheUnavailable(REASON_IO_ERROR)
            if hashlib.sha256(shard_bytes).hexdigest() != shard_ref.digest:
                return CacheMiss(REASON_SHARD_DIGEST_MISMATCH, f"shard {i}")
            try:
                shard_value = parse_json_v1(shard_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                return CacheMiss(REASON_MALFORMED, f"shard {i} json")
            if not isinstance(shard_value, dict):
                return CacheMiss(REASON_MALFORMED, f"shard {i} not object")
            if canonical_json_v1(shard_value) != shard_bytes:
                return CacheMiss(REASON_MALFORMED, f"shard {i} not canonical")
            if shard_value.get("shard_key") != shard_ref.shard_key:
                return CacheMiss(REASON_KEY_MISMATCH, f"shard {i} key")

            files = shard_value.get("files")
            if not isinstance(files, list):
                return CacheMiss(REASON_MALFORMED, f"shard {i} files")
            seen_exact: set[str] = set()
            seen_folded: set[str] = set()
            for item in files:
                if not isinstance(item, str):
                    return CacheMiss(REASON_MALFORMED, f"shard {i} file entry")
                try:
                    _normalize_safe_relative_path(item, f"$.shards[{i}].files")
                except JadxIndexError:
                    return CacheMiss(REASON_PATH_ESCAPE, f"shard {i} file path")
                if item in seen_exact:
                    return CacheMiss(REASON_DUPLICATE_POSTING, f"shard {i}")
                folded = unicodedata.normalize("NFC", item).casefold()
                if folded in seen_folded:
                    return CacheMiss(REASON_NORMALIZATION_CONFLICT, f"shard {i}")
                seen_exact.add(item)
                seen_folded.add(folded)

            shard_values.append(shard_value)
            shard_locators.append(f"{index_key}/shards/{shard_ref.shard_key}.json")
            shard_refs.append(shard_ref)

        coverage = value.get("coverage")
        aggregate = value.get("aggregate_digest")
        if coverage not in ("complete", "partial") or not isinstance(aggregate, str):
            return CacheMiss(REASON_MALFORMED, "coverage/aggregate")
        # aggregate 复验：shard digest 集合的锚——shard_refs 列表级篡改在此揭穿。
        expected_aggregate = hashlib.sha256(
            "".join(sorted(ref.digest for ref in shard_refs)).encode("ascii")
        ).hexdigest()
        if aggregate != expected_aggregate:
            return CacheMiss(REASON_MALFORMED, "aggregate_digest mismatch")
        try:
            manifest_obj = JadxIndexManifest(
                index_key=index_key,
                key_material=key_material,
                dex_lineage=lineage,
                jadx_version=jadx_version,
                options_digest=options_digest,
                shard_refs=tuple(shard_refs),
                coverage=coverage,
                aggregate_digest=aggregate,
            )
        except JadxIndexError as exc:
            return CacheMiss(REASON_MALFORMED, exc.code)
        return LoadedIndex(
            manifest=manifest_obj,
            shard_locators=tuple(shard_locators),
            coverage=coverage,
            shards=tuple(shard_values),
        )

    # -- 构建（存储侧骨架；postings 由 S3 填充）-----------------------------

    def build_index(
        self,
        source_root: str | os.PathLike[str],
        manifest: JadxIndexManifest,
    ) -> IndexBuildResult | CacheUnavailable:
        index_key = manifest.index_key

        existing = self.load_index(index_key)
        if isinstance(existing, LoadedIndex):
            return IndexBuildResult(
                state=IndexBuildState.REUSED,
                coverage=existing.coverage,
                manifest_locator=f"{index_key}/manifest.json",
                shard_locators=existing.shard_locators,
                manifest=existing.manifest,
            )
        if isinstance(existing, CacheUnavailable):
            return existing

        try:
            shard_refs: list[ShardRef] = []
            shard_locators: list[str] = []
            for lineage in manifest.dex_lineage:
                shard_key = derive_shard_key(
                    lineage, manifest.jadx_version, manifest.options_digest
                )
                shard_record = {
                    "index_schema_version": manifest.index_schema_version,
                    "shard_key": shard_key,
                    "lineage": lineage.to_record(),
                    "files": [],
                    "postings": [],
                }
                shard_bytes = canonical_json_v1(shard_record)
                path = self._shard_path(index_key, shard_key)
                self._publish_bytes(path, shard_bytes)
                shard_refs.append(ShardRef(shard_key, hashlib.sha256(shard_bytes).hexdigest()))
                shard_locators.append(f"{index_key}/shards/{shard_key}.json")

            aggregate = hashlib.sha256(
                "".join(sorted(ref.digest for ref in shard_refs)).encode("ascii")
            ).hexdigest()
            final_manifest = replace(
                manifest, shard_refs=tuple(shard_refs), aggregate_digest=aggregate
            )
            manifest_bytes = canonical_json_v1(_manifest_record(final_manifest))
            self._publish_bytes(self._manifest_path(index_key), manifest_bytes)
            return IndexBuildResult(
                state=IndexBuildState.BUILT,
                coverage=final_manifest.coverage,
                manifest_locator=f"{index_key}/manifest.json",
                shard_locators=tuple(shard_locators),
                manifest=final_manifest,
            )
        except _StorageUnavailableError as exc:
            return CacheUnavailable(exc.reason)
        except JadxIndexError as exc:
            return IndexBuildResult(
                state=IndexBuildState.FAILED,
                coverage="failed",
                diagnostics=(f"{exc.code} at {exc.field_path}",),
            )
