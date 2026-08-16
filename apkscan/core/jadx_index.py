"""S1: JADX 持久化索引的契约、身份与 DEX 输入校验层。

本模块不负责文件发布、索引构建、加载、JADX 调用或查询。
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn


from apkscan.core.recognition_codec import canonical_json_v1


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
    shard_refs: tuple[str, ...] = ()
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
        if not isinstance(self.shard_refs, tuple):
            _fail("shard_refs_must_be_tuple", "$.shard_refs")
        if not isinstance(self.coverage, str) or not self.coverage:
            _fail("invalid_coverage", "$.coverage")
        if not isinstance(self.jadx_version, str) or not self.jadx_version:
            _fail("invalid_jadx_version", "$.jadx_version")
        _validate_digest(self.options_digest, "$.options_digest")
        if self.index_schema_version != INDEX_SCHEMA_VERSION:
            _fail(REASON_SCHEMA_DRIFT, "$.index_schema_version")


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
