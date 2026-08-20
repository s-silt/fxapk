"""JADX 持久化索引：契约与身份层（S1）+ 存储层（S2）+ 查询层（S3）。

S1：数据契约、DEX 输入复算校验、域分离 key 派生。
S2：受控 cache root、create-only 原子发布、fail-closed 加载校验链。
S3：确定性枚举、bounded postings、结构提取（P1-B）与 find_value_usage。
本模块不负责 JADX 调用；调用路径查询见 jadx_callpath。

结构段（版本见 ``INDEX_SCHEMA_VERSION``）是对反编译 Java 的**有界启发式**解析——反射、JNI、动态
分发与混淆构造均不可见；未识别的语法被跳过而非报错。结构的不完整是文档化的
启发式属性，绝不能被解释为「不存在」。
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
from apkscan.core.recognition_contract import CanonicalCodecError


# 1.2：结构段类身份从 name 改为 (name, path)——真实混淆样本（脱壳 dump）里
# 不同路径的同名类是常态，仅按 name 的唯一键会让索引整体不可建。schema 参与
# key material，bump 即让旧工件按既有漂移机制变为可重建的 CacheMiss，无迁移代码。
# 1.3：修正方法 arity 计数——泛型实参里的逗号此前被当成参数分隔符（`Map<String,
# String> m` 算成 2），令方法身份 `cls#name/arity` 错位，callpath 按真实 arity 查
# 假阴性、ownership 与 baseline 对不齐。字段集不变，只改既有 arity 的取值；仍须
# bump，否则同一 index_key 下的旧 shard 会继续返回错误 arity。
# 1.4：calls 记录扩为 {callee,line,qualifier,scope}，保存文本可确证的调用点上下文，
# 供后续切片消费；当前 resolution 不据此收窄候选。形状变化必须 bump，否则旧 shard
# 会在同一 index_key 下撞上 1.4 消费侧的 fail-closed 校验。
# 1.5：calls 字段集不变，但记录集剔除方法/构造器声明伪调用，并修正 switch rule
# 箭头的 scope。语义变化必须 bump，避免同一 index_key 继续复用旧 1.4 shard。
# 1.6：形状仍不变，但 calls 剔除注解名伪调用，classes 首次纳入 record 条目/方法，
# 并将 record 体调用从 method 纠正为 nested_type。内容语义变化必须 bump，避免
# 同一 index_key 静默复用含伪边、缺类或错 scope 的旧 1.5 shard。
INDEX_SCHEMA_VERSION = "1.6"
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
REASON_DUPLICATE_STRUCTURE = "duplicate_structure"

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
        # key_material 只允许四个受控键：未知键不参与 derive_index_key，却会随
        # canonical manifest 落盘——允许它们存在等于留一个不影响身份的自由载荷通道。
        # 物化、canonical 编码、键检查收在同一道归一化边界里：调用方 Mapping 的
        # 遍历异常（自定义容器）与循环引用的 RecursionError 都归一为结构化拒绝。
        # 承诺面是标准容器与这些常见病态形态；完全任意的毒对象异常不做保证。
        if not isinstance(self.key_material, Mapping):
            _fail("invalid_key_material", "$.key_material")
        try:
            declared_dict = dict(self.key_material)
            declared_material = canonical_json_v1(declared_dict)
        except (
            CanonicalCodecError,
            KeyError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            _fail("invalid_key_material", "$.key_material")
        if set(declared_dict) != {
            "dex_lineage",
            "jadx_version",
            "options_digest",
            "index_schema_version",
        }:
            _fail("invalid_key_material", "$.key_material")
        # 元素类型一并锁死：非 DexLineage 元素会让下方身份重算抛裸 AttributeError，
        # 拒绝就不再是结构化的 JadxIndexError。
        if not isinstance(self.dex_lineage, tuple) or any(
            not isinstance(item, DexLineage) for item in self.dex_lineage
        ):
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
        # key_material 是身份的持久化副本：内容必须与顶层身份字段的重算结果逐字节
        # 一致——「顶层旧身份 + material 新身份」的矛盾 manifest 一旦落盘，load 恒
        # CacheMiss，而 create-only 发布会让该 key 槽位被死件永久占住。比对通过后
        # 存重算份的快照：frozen 只是浅冻结，存调用方引用等于允许构造后改写绕过
        # 这里的全部校验。
        canonical_material = build_key_material(
            self.dex_lineage,
            self.jadx_version,
            self.options_digest,
            self.index_schema_version,
        )
        if canonical_json_v1(canonical_material) != declared_material:
            _fail("key_material_mismatch", "$.key_material")
        object.__setattr__(self, "key_material", canonical_material)
        # index_key 不是自由输入：必须恰为身份字段（lineage/version/digest/schema）
        # 的重算值——64-hex 语法校验挡不住编造的 key。放行「旧 key + 新
        # options_digest」的不一致 manifest，它就能凭旧 key 走 build_index 的
        # 复用分支，拿旧 structure 数据冒充新配置的产物；load 侧的重算比对只护
        # 磁盘读回，不护构造入口。
        derived = derive_index_key(
            self.dex_lineage,
            self.jadx_version,
            self.options_digest,
            self.index_schema_version,
        )
        if derived != self.index_key:
            _fail(REASON_KEY_MISMATCH, "$.index_key")


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
    """校验 locator 解析后留在 cache_root 内，已存在组件无 symlink/junction/reparse 逃逸。

    ★信任边界（spec 同步声明）：cache root 及其父路径必须由受信任主体独占管理。
    本检查防的是**错误/恶意输入**（locator、root、预置产物），不防「检查后、使用前」
    并发改写 cache 目录的攻击者（TOCTOU/并发 reparse 替换）——能写 cache root 的
    攻击者本就能伪造其中一切产物，该场景在威胁模型之外。
    """
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


_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")
_QUALIFIED_CLASS_RE = re.compile(r"[A-Za-z_$][\w$]*(?:[.$][A-Za-z_$][\w$]*)*")
#: 落盘标识符的硬上限：与 Limits.max_identifier_len 解耦——load 侧没有 Limits，
#: 这里只拦「自由载荷通道」级别的异常长度。
_MAX_PERSISTED_IDENTIFIER = 1024
_CALL_QUALIFIER_LITERALS = frozenset({"", "this", "super", "<expr>", "<unknown>"})
_CALL_SCOPES = frozenset({"method", "nested_type", "lambda", "unknown"})


def _valid_call_qualifier(value: object) -> bool:
    return isinstance(value, str) and (
        value in _CALL_QUALIFIER_LITERALS
        or (
            len(value) <= _MAX_PERSISTED_IDENTIFIER
            and _IDENTIFIER_RE.fullmatch(value) is not None
        )
    )


def _valid_call_scope(value: object) -> bool:
    return isinstance(value, str) and value in _CALL_SCOPES


def _validate_shard_structure(shard_value: Mapping[str, object], files: set[str]) -> None:
    """当前 schema（``INDEX_SCHEMA_VERSION``）structure 段的 fail-closed 校验；违规抛精确 reason code。

    形状违规 / 失序 / path 不在 files → malformed；完全重复的 (name, path) 类身份
    或 (name, arity, start_line) 方法三元组 → duplicate_structure。同名不同 path
    是混淆样本（脱壳 dump）的合法常态，不是违规。
    """
    raw = shard_value.get("structure")
    if not isinstance(raw, dict) or set(raw) != {"classes"}:
        _fail(REASON_MALFORMED, "$.structure")
    classes = raw["classes"]
    if not isinstance(classes, list):
        _fail(REASON_MALFORMED, "$.structure.classes")
    previous_identity: tuple[str, str] | None = None
    for ci, cls in enumerate(classes):
        prefix = f"$.structure.classes[{ci}]"
        if not isinstance(cls, dict) or set(cls) != {"name", "path", "methods"}:
            _fail(REASON_MALFORMED, prefix)
        name = cls["name"]
        if (
            not isinstance(name, str)
            or len(name) > _MAX_PERSISTED_IDENTIFIER
            or _QUALIFIED_CLASS_RE.fullmatch(name) is None
        ):
            _fail(REASON_MALFORMED, f"{prefix}.name")
        rel = cls["path"]
        if not isinstance(rel, str):
            _fail(REASON_MALFORMED, f"{prefix}.path")
        _normalize_safe_relative_path(rel, f"{prefix}.path")
        if rel not in files:
            _fail(REASON_MALFORMED, f"{prefix}.path")
        identity = (name, rel)
        if previous_identity is not None:
            if identity == previous_identity:
                _fail(REASON_DUPLICATE_STRUCTURE, f"{prefix}.path")
            if identity < previous_identity:
                _fail(REASON_MALFORMED, f"{prefix}.path")
        previous_identity = identity
        methods = cls["methods"]
        if not isinstance(methods, list):
            _fail(REASON_MALFORMED, f"{prefix}.methods")
        seen_triples: set[tuple[str, int, int]] = set()
        previous_order: tuple[int, str, int] | None = None
        for mi, method in enumerate(methods):
            m_prefix = f"{prefix}.methods[{mi}]"
            if not isinstance(method, dict) or set(method) != {
                "name",
                "arity",
                "start_line",
                "end_line",
                "body_digest",
                "calls",
            }:
                _fail(REASON_MALFORMED, m_prefix)
            mn = method["name"]
            if (
                not isinstance(mn, str)
                or len(mn) > _MAX_PERSISTED_IDENTIFIER
                or (mn != "<init>" and _IDENTIFIER_RE.fullmatch(mn) is None)
            ):
                _fail(REASON_MALFORMED, f"{m_prefix}.name")
            arity = method["arity"]
            if isinstance(arity, bool) or not isinstance(arity, int) or arity < 0:
                _fail(REASON_MALFORMED, f"{m_prefix}.arity")
            start = method["start_line"]
            end = method["end_line"]
            for field_name, field_value in (("start_line", start), ("end_line", end)):
                if (
                    isinstance(field_value, bool)
                    or not isinstance(field_value, int)
                    or field_value < 1
                ):
                    _fail(REASON_MALFORMED, f"{m_prefix}.{field_name}")
            assert isinstance(start, int) and isinstance(end, int)
            if end < start:
                _fail(REASON_MALFORMED, f"{m_prefix}.end_line")
            _validate_digest(method["body_digest"], f"{m_prefix}.body_digest")
            triple = (mn, arity, start)
            if triple in seen_triples:
                _fail(REASON_DUPLICATE_STRUCTURE, m_prefix)
            seen_triples.add(triple)
            order = (start, mn, arity)
            if previous_order is not None and order < previous_order:
                _fail(REASON_MALFORMED, f"{m_prefix}.start_line")
            previous_order = order
            calls = method["calls"]
            if not isinstance(calls, list):
                _fail(REASON_MALFORMED, f"{m_prefix}.calls")
            previous_call: tuple[int, str] | None = None
            for ki, call in enumerate(calls):
                c_prefix = f"{m_prefix}.calls[{ki}]"
                if not isinstance(call, dict) or set(call) != {
                    "callee",
                    "line",
                    "qualifier",
                    "scope",
                }:
                    _fail(REASON_MALFORMED, c_prefix)
                callee = call["callee"]
                if (
                    not isinstance(callee, str)
                    or len(callee) > _MAX_PERSISTED_IDENTIFIER
                    or _IDENTIFIER_RE.fullmatch(callee) is None
                ):
                    _fail(REASON_MALFORMED, f"{c_prefix}.callee")
                line = call["line"]
                if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                    _fail(REASON_MALFORMED, f"{c_prefix}.line")
                if not _valid_call_qualifier(call["qualifier"]):
                    _fail(REASON_MALFORMED, f"{c_prefix}.qualifier")
                if not _valid_call_scope(call["scope"]):
                    _fail(REASON_MALFORMED, f"{c_prefix}.scope")
                current_call = (line, callee)
                # 同行同名的多个调用点是合法重复；只有降序才是形状违规。
                if previous_call is not None and current_call < previous_call:
                    _fail(REASON_MALFORMED, f"{c_prefix}.line")
                previous_call = current_call


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
        if not isinstance(key_material, dict) or set(key_material) != {
            "dex_lineage",
            "jadx_version",
            "options_digest",
            "index_schema_version",
        }:
            return CacheMiss(REASON_MALFORMED, "key_material keys")
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

            try:
                _validate_shard_structure(shard_value, seen_exact)
            except JadxIndexError as exc:
                return CacheMiss(exc.code, f"shard {i} {exc.field_path}")

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
        *,
        scan: "ShardScanResult | Mapping[DexLineage, ShardScanResult] | None" = None,
    ) -> IndexBuildResult | CacheUnavailable:
        index_key = manifest.index_key

        # S3 扫描结果（可选）：无扫描输入时保持 S2 行为——空 files/postings、
        # coverage 取 manifest 值；有扫描输入时逐 lineage 落 postings，
        # manifest coverage 取最差值（partial 传染）。
        scans: dict[DexLineage, "ShardScanResult"]
        if scan is None:
            scans = {}
        elif isinstance(scan, ShardScanResult):
            scans = {scan.lineage: scan}
        elif isinstance(scan, Mapping):
            scans = dict(scan)
        else:
            _fail(REASON_MALFORMED, "$.scan")

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
            coverages: list[str] = []
            for lineage in manifest.dex_lineage:
                shard_key = derive_shard_key(
                    lineage, manifest.jadx_version, manifest.options_digest
                )
                current = scans.get(lineage)
                if current is None:
                    files: list[str] = []
                    postings: list[Mapping[str, object]] = []
                    structure_classes: list[dict[str, object]] = []
                    coverages.append(manifest.coverage)
                else:
                    files = list(current.files)
                    postings = [dict(p) for p in current.postings]
                    structure_classes = [dict(c) for c in current.structure]
                    coverages.append(current.coverage)
                # 发布闸门：完全相同的 (name, path) 类身份会让 shard 一落盘即
                # 不可加载——在发布前拒绝，绝不产出注定 CacheMiss 的半成品工件。
                # 同名不同 path（混淆样本常态）是合法形态，放行。
                class_identities = [
                    (str(c.get("name", "")), str(c.get("path", "")))
                    for c in structure_classes
                ]
                if len(set(class_identities)) != len(class_identities):
                    _fail(REASON_DUPLICATE_STRUCTURE, "$.scan.structure")
                shard_record = {
                    "index_schema_version": manifest.index_schema_version,
                    "shard_key": shard_key,
                    "lineage": lineage.to_record(),
                    "files": files,
                    "postings": postings,
                    "structure": {"classes": structure_classes},
                }
                shard_bytes = canonical_json_v1(shard_record)
                path = self._shard_path(index_key, shard_key)
                self._publish_bytes(path, shard_bytes)
                shard_refs.append(ShardRef(shard_key, hashlib.sha256(shard_bytes).hexdigest()))
                shard_locators.append(f"{index_key}/shards/{shard_key}.json")

            aggregate = hashlib.sha256(
                "".join(sorted(ref.digest for ref in shard_refs)).encode("ascii")
            ).hexdigest()
            final_coverage = (
                "partial" if any(c == "partial" for c in coverages) else manifest.coverage
            )
            final_manifest = replace(
                manifest,
                shard_refs=tuple(shard_refs),
                aggregate_digest=aggregate,
                coverage=final_coverage,
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


# ---------------------------------------------------------------------------
# S3：查询层——确定性枚举、bounded postings、find_value_usage
# ---------------------------------------------------------------------------

#: 查询值长度上限：Limits 默认与 find_value_usage 的独立防线共用同一常量。
_DEFAULT_MAX_VALUE_LEN = 4096


@dataclass(frozen=True, slots=True)
class Limits:
    max_files: int = 5000
    max_file_bytes: int = 4 * 1024 * 1024
    #: 全次扫描累计读取字节数上界。max_files × max_file_bytes 是单文件全部触顶时的
    #: 理论积（max_files 调到 12000 后约 47GiB）——聚合上界不能成为敌对样本可实际
    #: 兑现的读取量。撞文件数、单文件截断此前都有硬帽，唯独聚合量没有：大量各自
    #: 不超限的文件可以把总读取量堆起来。默认 512MiB 约为实测真实大样本的 6 倍余量。
    max_total_bytes: int = 512 * 1024 * 1024
    max_value_len: int = _DEFAULT_MAX_VALUE_LEN
    max_classes_per_file: int = 256
    max_methods_per_class: int = 512
    max_calls_per_method: int = 256
    max_identifier_len: int = 256

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_value_len",
            "max_classes_per_file",
            "max_methods_per_class",
            "max_calls_per_method",
            "max_identifier_len",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                _fail(REASON_MALFORMED, f"$.limits.{name}")


@dataclass(frozen=True, slots=True)
class ShardScanResult:
    lineage: DexLineage
    files: tuple[str, ...]
    postings: tuple[Mapping[str, object], ...]
    coverage: str
    files_total: int
    scanned: int
    read_failed: int
    truncated: int
    bytes_scanned: int
    scan_limit_hit: bool
    #: 结构段 classes 列表（JSON 形态的 dict，内层为 list——发布时直接 canonical 编码）。
    structure: tuple[Mapping[str, object], ...] = ()
    structure_limit_hit: bool = False


# -- 结构提取（P1-B）：有界启发式，只认 JADX 风格的良构输出 --------------------

#: class/interface/enum/record 声明须与 `{` 同行（JADX 输出形态）；允许
#: extends/implements/泛型子句。record 必须带「名字 + 形参括号」，避免误伤同名调用。
_CLASS_DECL_RE = re.compile(
    r"\b(?:class|interface|enum|record(?=\s+[A-Za-z_$][\w$]*[^{;=]*\())"
    r"\s+([A-Za-z_$][\w$]*)[^{;]*\{"
)
#: 成员方法：修饰符* 返回类型 名字(参数) [throws 子句] {——参数不允许嵌套括号。
#: ★已知边界：形参上带**参数的注解**（`void f(@IntRange(from=0) int x)`）会让整条声明
#: 匹配失败，于是该方法被静默漏掉，且不会置 limited、coverage 仍可能是 complete。
#: 要收敛它需要一条「疑似方法声明」的宽松探测正则，而宽松正则的误报会把大量样本
#: 打成 partial——收益与代价都要先量化，故留作已知边界而非静默假装不存在。
_METHOD_DECL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|strictfp)\s+)*"
    r"[\w$<>\[\], ?]+\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws[^{]*)?\{"
)
#: 构造器：无返回类型的 `Name(params) {`；是否真为构造器由「名字==类简单名」判定。
_CTOR_DECL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*"
    r"([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws[^{]*)?\{"
)
#: 形参个数上限。JVM 的硬限是 255 个 **slot**（long/double 各占 2），按个数计只能是
#: 宽松上界——这里要的正是宽松上界：超过它的声明必不是真实可编译方法，可直接不采信。
_MAX_DECLARED_ARITY = 255
_CALL_SITE_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
#: 语法关键字绝不是调用点；`new X(...)` 的构造器调用不是 P1-B 的边（文档化限制）。
_CALL_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "return", "new", "super", "this",
     "synchronized", "do", "else", "try"}
)
_CALL_AFTER_KEYWORDS = frozenset(
    {"return", "throw", "yield", "assert", "else", "do", "case", "instanceof"}
)
_PENDING_LOCAL_TYPE_RE = re.compile(
    r"(?:^|[^\w$.])"
    r"(?:class|interface|enum|record(?=\s+[A-Za-z_$][\w$]*[^{;=]*\())"
    r"\s+[A-Za-z_$][\w$]*[^{;]*$"
)


@dataclass(slots=True)
class _NewEntry:
    depth: int
    ctor_paren_seen: bool = False
    saw_bracket: bool = False
    angle_depth: int = 0


def _sanitize_java_source(text: str) -> list[str]:
    """把字符串/字符字面量内容与两种注释全部置空（保留行结构与逐行对齐）。

    ★注释与字面量里的括号绝不参与配平（JADX 输出满是 ``/* renamed from: */``）；
    块注释跨行由状态机跨行携带。返回行数恒等于 ``text.splitlines()``。
    """
    lines = text.splitlines()
    sanitized: list[str] = []
    state = "NORMAL"

    for source_line in lines:
        chars = list(source_line)
        index = 0
        while index < len(chars):
            current = chars[index]
            following = chars[index + 1] if index + 1 < len(chars) else ""

            if state == "NORMAL":
                if current == "/" and following == "/":
                    # 行注释：本行剩余全部置空，状态不跨行。
                    for j in range(index, len(chars)):
                        chars[j] = " "
                    break
                if current == "/" and following == "*":
                    chars[index] = " "
                    chars[index + 1] = " "
                    state = "BLOCK_COMMENT"
                    index += 2
                    continue
                if current == '"':
                    chars[index] = " "
                    state = "STRING"
                elif current == "'":
                    chars[index] = " "
                    state = "CHAR"
                index += 1
                continue

            if state == "BLOCK_COMMENT":
                if current == "*" and following == "/":
                    chars[index] = " "
                    chars[index + 1] = " "
                    state = "NORMAL"
                    index += 2
                else:
                    chars[index] = " "
                    index += 1
                continue

            # STRING / CHAR：全部置空；反斜杠转义连吞一个字符；闭引号回 NORMAL。
            closing = '"' if state == "STRING" else "'"
            chars[index] = " "
            if current == "\\":
                if index + 1 < len(chars):
                    chars[index + 1] = " "
                    index += 2
                else:
                    index += 1
            elif current == closing:
                state = "NORMAL"
                index += 1
            else:
                index += 1

        sanitized.append("".join(chars))

    return sanitized


def _declared_arity(params: str) -> int | None:
    """按尖括号深度 0 处的逗号计参数个数；**参数段畸形时返回 None**。

    只需跟踪尖括号：`_METHOD_DECL_RE` / `_CTOR_DECL_RE` 的参数捕获组是 `[^()]*`，
    圆括号（含带参注解）根本进不来；数组维度 `int[][]` 也不含逗号。

    ★畸形一律返回 None 交调用方丢弃该声明，绝不折叠成一个「看起来正常」的 arity：
    `f(,,,,)` 折叠后是 0、`f(x)` 折叠后是 1，都会与真实的 `f()` / `f(String x)` 撞成
    同一个 `cls#name/arity` 身份，而 :func:`~apkscan.core.jadx_callpath._index_methods`
    按同 id **合并出边**——等于让敌对样本把伪造的调用边挂到真实方法上。
    参数段是样本可控输入，不可判定就必须说不可判定。

    四类拒绝：尖括号不配对、存在空的顶层段、任一顶层段不含空白（合法形参必是
    ``类型 名字`` 两部分，``String... a`` / ``int[] a`` / ``@NonNull String x`` /
    ``final int a`` 都满足）、形参个数超上界。

    ★这是**有界启发式**，与本模块整体定位一致：它不做完整的 Java 形参语法验证，
    因此 ``int a int b``（漏写逗号）这类「平衡、非空、含空白但语法非法」的段仍会被
    当成一个形参。要根治须引入类型语法解析器，那是另一个量级的东西。
    """
    text = params.strip()
    if not text:
        return 0

    arity = 1
    angle_depth = 0
    segment_has_content = False
    segment_has_space = False
    for char in text:
        if char == "<":
            angle_depth += 1
        elif char == ">":
            if angle_depth == 0:
                return None
            angle_depth -= 1
        elif char == "," and angle_depth == 0:
            if not segment_has_content or not segment_has_space:
                return None
            segment_has_content = False
            segment_has_space = False
            arity += 1
            continue

        if char.isspace():
            # 只有已出现过实义字符的段才算「类型与名字之间的分隔空白」，
            # 否则 " , x" 的前导空白会冒充分隔。
            if segment_has_content:
                segment_has_space = True
        else:
            segment_has_content = True

    if angle_depth != 0 or not segment_has_content or not segment_has_space:
        return None
    if arity > _MAX_DECLARED_ARITY:
        return None
    return arity


def _method_body_digest(lines: list[str], start_line: int, end_line: int) -> str:
    """方法区域（含签名行与闭括号行）的规范化 digest：NFC + 逐行去首尾空白 + 删空行。"""
    region = [
        unicodedata.normalize("NFC", text).strip()
        for text in lines[start_line - 1 : end_line]
        if text.strip()
    ]
    return "sha256:" + hashlib.sha256("\n".join(region).encode("utf-8")).hexdigest()


def _method_end_line(clean_lines: list[str], start_line: int) -> int:
    """在已清理行上从签名行起做括号配平；找不到闭括号（截断文件）退回签名行。"""
    brace = 0
    for number in range(start_line, len(clean_lines) + 1):
        clean = clean_lines[number - 1]
        brace += clean.count("{") - clean.count("}")
        if brace <= 0:
            return number
    return start_line


def _method_calls(
    clean_lines: list[str], start_line: int, end_line: int, limits: Limits
) -> tuple[list[dict[str, object]], bool]:
    """已清理方法体内（不含签名行）的调用点；返回 (calls, 是否触界)。"""
    calls: list[dict[str, object]] = []
    limited = False
    paren_depth = 0
    rel_depth = 0
    scope_stack: list[tuple[str, int]] = []
    new_stack: list[_NewEntry] = []
    pending_arrow: tuple[int, str] | None = None
    expr_arrow_scopes: list[tuple[str, int]] = []
    pending_type_decl = False
    desync = False

    def is_identifier_char(char: str) -> bool:
        return char.isascii() and (char.isalnum() or char in "_$")

    def previous_nonspace(line_index: int, cursor: int) -> tuple[int, int] | None:
        lower_bound = start_line - 1
        while line_index >= lower_bound:
            clean = clean_lines[line_index]
            while cursor >= 0 and clean[cursor].isspace():
                cursor -= 1
            if cursor >= 0:
                return line_index, cursor
            line_index -= 1
            if line_index >= lower_bound:
                cursor = len(clean_lines[line_index]) - 1
        return None

    def next_nonspace(line_index: int, cursor: int) -> tuple[int, int] | None:
        upper_bound = end_line - 1
        while line_index <= upper_bound:
            clean = clean_lines[line_index]
            while cursor < len(clean) and clean[cursor].isspace():
                cursor += 1
            if cursor < len(clean):
                return line_index, cursor
            line_index += 1
            cursor = 0
        return None

    def declaration_on_left(line_index: int, start: int) -> bool:
        position = previous_nonspace(line_index, start - 1)
        if position is None:
            return False
        token_line, cursor = position
        clean = clean_lines[token_line]
        if not is_identifier_char(clean[cursor]):
            return False
        token_end = cursor + 1
        while cursor >= 0 and is_identifier_char(clean[cursor]):
            cursor -= 1
        token = clean[cursor + 1 : token_end]
        return (
            _IDENTIFIER_RE.fullmatch(token) is not None
            and token not in _CALL_AFTER_KEYWORDS
        )

    def declaration_on_right(line_index: int, open_paren: int) -> bool:
        depth = 0
        for scan_line in range(line_index, end_line):
            clean = clean_lines[scan_line]
            cursor = open_paren if scan_line == line_index else 0
            while cursor < len(clean):
                char = clean[cursor]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        following = next_nonspace(scan_line, cursor + 1)
                        return (
                            following is not None
                            and clean_lines[following[0]][following[1]] == "{"
                        )
                cursor += 1
        # 括号无法配平时 fail-open：保留现状调用记录，避免误删真实调用点。
        return False

    def is_declaration_site(line_index: int, start: int, open_paren: int) -> bool:
        return declaration_on_left(line_index, start) or declaration_on_right(
            line_index, open_paren
        )

    def is_annotation_site(line_index: int, start: int) -> bool:
        """沿点链回溯，链头左邻是 ``@`` 即判为注解位点（含限定名注解）。

        判据 sound 的前提是合法 Java 的 token 序：``@`` 不是表达式运算符、不能作调用
        接收者，故「``@`` + 点分标识符链 + ``(``」只可能是注解使用。真实的限定名调用
        （``util.log.d(1)`` / ``this.a.b.c(x)``）链头左邻不是 ``@``；``chain().next(y)``
        与 ``((Foo) x).bar()`` 回溯时撞上 ``)`` 即止。

        ★fail-open：点链中断、越界、遇非标识符成分一律返回 False（保留调用点记录）。
        错误方向只可能是漏剔，绝不误剔真实调用。
        """
        position = previous_nonspace(line_index, start - 1)
        while position is not None:
            row, column = position
            char = clean_lines[row][column]
            if char == "@":
                return True
            if char != ".":
                return False
            # 限定名点链：跳过 `.` 与其左侧一个完整标识符，继续看链头。
            identifier_end = previous_nonspace(row, column - 1)
            if identifier_end is None:
                return False
            identifier_row, identifier_column = identifier_end
            if not is_identifier_char(clean_lines[identifier_row][identifier_column]):
                return False
            cursor = identifier_column
            while cursor >= 0 and is_identifier_char(clean_lines[identifier_row][cursor]):
                cursor -= 1
            position = previous_nonspace(identifier_row, cursor)
        return False

    def arrow_kind(line_index: int, start: int) -> str:
        balance = 0
        lower_bound = start_line - 1
        for scan_line in range(line_index, lower_bound - 1, -1):
            clean = clean_lines[scan_line]
            cursor = start - 1 if scan_line == line_index else len(clean) - 1
            while cursor >= 0:
                char = clean[cursor]
                if char == ")":
                    balance += 1
                elif char == "(":
                    balance -= 1
                    if balance < 0:
                        return "lambda"
                elif balance == 0 and char in ";{}":
                    first = next_nonspace(scan_line, cursor + 1)
                    if first is None or first >= (line_index, start):
                        return "unknown"
                    token_line, token_start = first
                    token_clean = clean_lines[token_line]
                    token_end = token_start
                    while (
                        token_end < len(token_clean)
                        and is_identifier_char(token_clean[token_end])
                    ):
                        token_end += 1
                    token = token_clean[token_start:token_end]
                    return "switch" if token in ("case", "default") else "lambda"
                cursor -= 1
        return "unknown"

    def qualifier_at(line_index: int, start: int) -> str:
        position = previous_nonspace(line_index, start - 1)
        if position is None:
            return "<unknown>"
        token_line, cursor = position
        if clean_lines[token_line][cursor] != ".":
            return ""

        position = previous_nonspace(token_line, cursor - 1)
        if position is None:
            return "<unknown>"
        token_line, cursor = position
        clean = clean_lines[token_line]
        token_end = cursor + 1
        while cursor >= 0 and is_identifier_char(clean[cursor]):
            cursor -= 1
        token = clean[cursor + 1 : token_end]
        if not token:
            return "<expr>"
        if token in ("this", "super"):
            return token
        if token in _CALL_KEYWORDS:
            return "<expr>"
        before_token = previous_nonspace(token_line, cursor)
        if (
            before_token is not None
            and clean_lines[before_token[0]][before_token[1]] == "."
        ):
            return "<expr>"
        if len(token) > limits.max_identifier_len:
            return "<expr>"
        if _IDENTIFIER_RE.fullmatch(token) is None:
            return "<unknown>"
        return token

    def call_scope() -> str:
        if desync:
            return "unknown"
        if scope_stack:
            kind = scope_stack[-1][0]
            return "nested_type" if kind == "type" else kind
        if expr_arrow_scopes:
            return expr_arrow_scopes[-1][0]
        return "method"

    for line_no in range(start_line + 1, end_line + 1):
        clean = clean_lines[line_no - 1]
        call_matches = {match.start(): match for match in _CALL_SITE_RE.finditer(clean)}
        local_type_openings = {
            match.end() - 1 for match in _CLASS_DECL_RE.finditer(clean)
        }
        cursor = 0
        while cursor < len(clean):
            char = clean[cursor]
            if pending_arrow is not None and not char.isspace():
                arrow_depth, arrow_scope = pending_arrow
                if char == "{":
                    scope_stack.append((arrow_scope, rel_depth))
                    pending_arrow = None
                    rel_depth += 1
                    cursor += 1
                    continue
                expr_arrow_scopes.append((arrow_scope, arrow_depth))
                pending_arrow = None

            match = call_matches.get(cursor)
            if match is not None:
                callee = match.group(1)
                in_new_type = bool(
                    new_stack
                    and not new_stack[-1].ctor_paren_seen
                    and not new_stack[-1].saw_bracket
                    and paren_depth == new_stack[-1].depth
                )
                if (
                    callee not in _CALL_KEYWORDS
                    and len(callee) <= limits.max_identifier_len
                    and not in_new_type
                    and not is_annotation_site(line_no - 1, cursor)
                    and not is_declaration_site(
                        line_no - 1, cursor, match.end() - 1
                    )
                ):
                    if len(calls) >= limits.max_calls_per_method:
                        limited = True
                        break
                    calls.append({
                        "callee": callee,
                        "line": line_no,
                        "qualifier": qualifier_at(line_no - 1, cursor),
                        "scope": call_scope(),
                    })

            if (
                clean.startswith("new", cursor)
                and (cursor == 0 or not is_identifier_char(clean[cursor - 1]))
                and (
                    cursor + 3 == len(clean)
                    or not is_identifier_char(clean[cursor + 3])
                )
            ):
                new_stack.append(_NewEntry(paren_depth))

            if (
                clean.startswith("->", cursor)
                and (cursor == 0 or clean[cursor - 1] != "-")
            ):
                kind = arrow_kind(line_no - 1, cursor)
                if kind != "switch":
                    pending_arrow = (paren_depth, kind)
                cursor += 2
                continue

            if char == "(":
                if (
                    new_stack
                    and not new_stack[-1].ctor_paren_seen
                    and not new_stack[-1].saw_bracket
                    and paren_depth == new_stack[-1].depth
                    and new_stack[-1].angle_depth == 0
                ):
                    new_stack[-1].ctor_paren_seen = True
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
                if new_stack and paren_depth < new_stack[-1].depth:
                    new_stack.pop()
                if expr_arrow_scopes and paren_depth < expr_arrow_scopes[-1][1]:
                    expr_arrow_scopes.pop()
            elif char == "<" and new_stack:
                top = new_stack[-1]
                if not top.ctor_paren_seen and not top.saw_bracket:
                    top.angle_depth += 1
            elif char == ">" and new_stack:
                top = new_stack[-1]
                if not top.ctor_paren_seen and not top.saw_bracket:
                    top.angle_depth = max(0, top.angle_depth - 1)
            elif char == "[" and new_stack:
                top = new_stack[-1]
                if not top.ctor_paren_seen and paren_depth == top.depth:
                    top.saw_bracket = True
            elif char == ",":
                if (
                    new_stack
                    and paren_depth == new_stack[-1].depth
                    and new_stack[-1].angle_depth == 0
                ):
                    new_stack.pop()
                if expr_arrow_scopes and expr_arrow_scopes[-1][1] == paren_depth:
                    expr_arrow_scopes.pop()
            elif char == ";":
                while new_stack and new_stack[-1].depth >= paren_depth:
                    new_stack.pop()
                expr_arrow_scopes.clear()
                pending_type_decl = False
            elif char == "{" and (
                cursor in local_type_openings or pending_type_decl
            ):
                scope_stack.append(("type", rel_depth))
                pending_type_decl = False
                rel_depth += 1
            elif (
                char == "{"
                and new_stack
                and new_stack[-1].ctor_paren_seen
                and paren_depth == new_stack[-1].depth
                and not new_stack[-1].saw_bracket
            ):
                scope_stack.append(("type", rel_depth))
                new_stack.pop()
                rel_depth += 1
            elif (
                char == "{"
                and new_stack
                and new_stack[-1].saw_bracket
                and paren_depth == new_stack[-1].depth
            ):
                new_stack.pop()
                rel_depth += 1
            elif char == "{":
                rel_depth += 1
            elif char == "}":
                rel_depth -= 1
                if scope_stack and rel_depth == scope_stack[-1][1]:
                    scope_stack.pop()
                if rel_depth < 0:
                    desync = True
            cursor += 1
        if limited:
            break
        if _PENDING_LOCAL_TYPE_RE.search(clean) is not None:
            pending_type_decl = True
    calls.sort(
        key=lambda call: (
            call["line"],
            call["callee"],
            call["qualifier"],
            call["scope"],
        )
    )
    return calls, limited


def _extract_file_structure(
    relative: str, text: str, limits: Limits
) -> tuple[list[dict[str, object]], bool]:
    """单文件的类/方法/调用点提取；返回 (classes, 是否触界)。

    括号深度机：类声明推栈、深度回落弹栈；成员方法只在「类深度 + 1」识别，
    方法体语句（更深一层）与匿名类不会被误判为成员。
    """
    lines = text.splitlines()
    # ★匹配与配平全部走清理后的行；body_digest 仍然基于原始行（区域按打印形态摘要）。
    clean_lines = _sanitize_java_source(text)
    package = ""
    for line in clean_lines:
        match = re.match(r"\s*package\s+([\w.]+)\s*;", line)
        if match:
            package = match.group(1)
            break

    depth = 0
    classes: list[dict[str, object]] = []
    #: 栈元素：(简单名, 声明前深度, classes 下标)。限定名由简单名链拼出。
    stack: list[tuple[str, int, int]] = []
    limited = False

    for number, clean in enumerate(clean_lines, 1):
        class_match = _CLASS_DECL_RE.search(clean)
        if class_match:
            simple = class_match.group(1)
            chain = [entry[0] for entry in stack] + [simple]
            qualified = (f"{package}." if package else "") + "$".join(chain)
            if len(classes) >= limits.max_classes_per_file or (
                len(qualified) > limits.max_identifier_len
            ):
                limited = True
            else:
                classes.append({"name": qualified, "path": relative, "methods": []})
                stack.append((simple, depth, len(classes) - 1))
        elif stack:
            simple, class_depth, class_index = stack[-1]
            if depth == class_depth + 1:
                name: str | None = None
                params = ""
                # ★构造器判定必须先行：方法正则的"返回类型"字符类含空格（为泛型
                # `Map<String, String>` 服务），回溯时会把 `public` 当返回类型、
                # 构造器名当方法名吞掉。
                ctor_match = _CTOR_DECL_RE.match(clean)
                if ctor_match and ctor_match.group(1) == simple:
                    name, params = "<init>", ctor_match.group(2)
                else:
                    method_match = _METHOD_DECL_RE.match(clean)
                    if method_match:
                        name, params = method_match.group(1), method_match.group(2)
                if name is not None and len(name) <= limits.max_identifier_len:
                    arity = _declared_arity(params)
                    methods = classes[class_index]["methods"]
                    assert isinstance(methods, list)
                    if arity is None:
                        # 参数段不可判定 → 丢弃该声明，并按「不完整要说出来」标记。
                        # 绝不落一个会与真实重载撞身份的 arity（见 _declared_arity）。
                        # ★这里复用了 limited/structure_limit_hit 这个位，但语义上它是
                        # 「解析拒绝」而非「撞资源上限」——两者都该让 coverage 降级，
                        # 故安全效果正确；要区分二者需独立原因位，留待需要诊断时再拆。
                        limited = True
                    elif len(methods) >= limits.max_methods_per_class:
                        limited = True
                    else:
                        end = _method_end_line(clean_lines, number)
                        calls, calls_limited = _method_calls(clean_lines, number, end, limits)
                        limited = limited or calls_limited
                        methods.append(
                            {
                                "name": name,
                                "arity": arity,
                                "start_line": number,
                                "end_line": end,
                                "body_digest": _method_body_digest(lines, number, end),
                                "calls": calls,
                            }
                        )
        depth += clean.count("{") - clean.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()

    for item in classes:
        methods = item["methods"]
        assert isinstance(methods, list)
        methods.sort(key=lambda m: (m["start_line"], m["name"], m["arity"]))
    classes.sort(key=lambda c: (str(c["name"]), str(c["path"])))
    return classes, limited


def _scan_relative_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    return unicodedata.normalize("NFC", relative)


def scan_java_sources(
    jadx_output_root: str | os.PathLike[str],
    values: Iterable[str],
    *,
    lineage: DexLineage,
    limits: Limits,
) -> ShardScanResult:
    if not isinstance(lineage, DexLineage):
        _fail(REASON_MALFORMED, "$.lineage")
    if not isinstance(limits, Limits):
        _fail(REASON_MALFORMED, "$.limits")

    try:
        root = Path(jadx_output_root)
    except (TypeError, ValueError) as exc:
        raise JadxIndexError(REASON_INVALID_SOURCE_ROOT) from exc

    if not root.is_absolute():
        _fail(REASON_INVALID_SOURCE_ROOT, "$.jadx_output_root")
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise JadxIndexError(REASON_INVALID_SOURCE_ROOT, "$.jadx_output_root") from exc
    if not root.is_dir():
        _fail(REASON_INVALID_SOURCE_ROOT, "$.jadx_output_root")

    query_values: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        if not value or len(value) > limits.max_value_len:
            continue
        query_values.append(value)
    # 同一查询值只保留一次，避免重复 posting；排序保证结果确定。
    query_values = sorted(set(query_values))

    paths: list[tuple[str, Path]] = []
    try:
        candidates = tuple(item for item in root.rglob("*.java") if item.is_file())
    except (OSError, RuntimeError):
        candidates = ()

    seen_normalized: dict[str, str] = {}
    for path in candidates:
        try:
            relative = _scan_relative_path(root, path)
        except (ValueError, OSError):
            continue
        key = relative.casefold()
        previous = seen_normalized.get(key)
        if previous is not None and previous != relative:
            raise JadxIndexError(REASON_NORMALIZATION_CONFLICT, "$.jadx_output_root")
        seen_normalized[key] = relative
        paths.append((relative, path))

    # ★先全量排序、后截断：截断保留的文件集合才与枚举序无关（确定性契约）。
    paths.sort(key=lambda item: (item[0].casefold(), item[0]))
    files_total = len(paths)
    scan_limit_hit = files_total > limits.max_files
    selected = paths[: limits.max_files]

    postings: list[Mapping[str, object]] = []
    files: list[str] = []
    structures: list[dict[str, object]] = []
    structure_limit_hit = False
    byte_budget_hit = False
    read_failed = 0
    truncated = 0
    scanned = 0
    bytes_scanned = 0

    for relative, path in selected:
        if bytes_scanned >= limits.max_total_bytes:
            # ★聚合读取预算：触顶即停、剩余文件不扫，coverage 诚实降 partial
            # （scanned < files_total 且 read_failed/truncated/scan_limit_hit 皆无，
            # 可辨识）。检查在读之前，最后一个已读文件最多让累计超出预算
            # max_file_bytes，有界。
            byte_budget_hit = True
            break
        try:
            with path.open("rb") as stream:
                data = stream.read(limits.max_file_bytes + 1)
        except OSError:
            read_failed += 1
            continue

        if len(data) > limits.max_file_bytes:
            data = data[: limits.max_file_bytes]
            truncated += 1
        bytes_scanned += len(data)
        scanned += 1
        files.append(relative)

        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        for value in query_values:
            digest = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
            for line_number, line_text in enumerate(lines, start=1):
                start = 0
                while True:
                    column_zero = line_text.find(value, start)
                    if column_zero < 0:
                        break
                    postings.append(
                        {
                            "path": relative,
                            "line": line_number,
                            "column": column_zero + 1,
                            "value_digest": digest,
                        }
                    )
                    # 允许重叠子串命中。
                    start = column_zero + 1

        file_classes, file_limited = _extract_file_structure(relative, text, limits)
        structures.extend(file_classes)
        structure_limit_hit = structure_limit_hit or file_limited

    # 全 shard 的类按 (name, path) 升序——与 load 侧 canonical 校验同款序。
    structures.sort(key=lambda item: (str(item["name"]), str(item["path"])))
    coverage = (
        "complete"
        if not read_failed
        and not truncated
        and not scan_limit_hit
        and not structure_limit_hit
        and not byte_budget_hit
        else "partial"
    )
    return ShardScanResult(
        lineage=lineage,
        files=tuple(files),
        postings=tuple(postings),
        coverage=coverage,
        files_total=files_total,
        scanned=scanned,
        read_failed=read_failed,
        truncated=truncated,
        bytes_scanned=bytes_scanned,
        scan_limit_hit=scan_limit_hit,
        structure=tuple(structures),
        structure_limit_hit=structure_limit_hit,
    )


def _lineage_from_shard_record(record: Mapping[str, object], path: str) -> DexLineage:
    raw = record.get("lineage")
    if not isinstance(raw, Mapping):
        _fail(REASON_MALFORMED, f"{path}.lineage")
    if set(raw) != {"role", "ordinal", "source_label", "digest"}:
        _fail(REASON_MALFORMED, f"{path}.lineage")
    role = raw.get("role")
    ordinal = raw.get("ordinal")
    source_label = raw.get("source_label")
    digest = raw.get("digest")
    if role not in (DexRole.APK_DEX.value, DexRole.EXTRA_DEX.value):
        _fail(REASON_MALFORMED, f"{path}.lineage.role")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int):
        _fail(REASON_MALFORMED, f"{path}.lineage.ordinal")
    if not isinstance(source_label, str) or not isinstance(digest, str):
        _fail(REASON_MALFORMED, f"{path}.lineage")
    try:
        return DexLineage(
            role=DexRole(role), ordinal=ordinal, source_label=source_label, digest=digest
        )
    except JadxIndexError as exc:
        raise JadxIndexError(REASON_MALFORMED, f"{path}.lineage") from exc


#: 单一相对路径下参与归属反查的方法区间数上界。构建期由 ``Limits`` 约束，但 load 侧
#: 的结构校验没有对应计数上限，伪造 cache 可绕过；反查是逐命中线性扫描，无上界即
#: 可被放大成 CPU 面。正常文件远达不到此值。
_MAX_CONTEXT_RANGES_PER_PATH = 4096


def _build_usage_context_index(
    shard: Mapping[str, object],
) -> dict[str, tuple[tuple[str, str, int, int, int], ...]]:
    """按相对路径归组本 shard 的方法行号区间，供 usage 命中反查所属方法。

    ★这里**刻意宽松**：structure 段的严格校验属于 load 期（``_validate_shard_structure``），
    本函数只是给已找到的阳性命中补上下文。结构缺失或形状异常一律降级为「无法反查」
    （返回空索引），绝不因此让本来能返回的命中变成异常——那会把一个附加能力变成
    新的失败源。异常一律放弃**整个 shard** 的反查，不做逐条跳过：跳过某条坏 method
    会让剩余区间冒充「唯一归属」，把不确定伪装成确定。

    ★**信任边界（不是本函数能解决的，记录在此以免被误读）**：归属完全来自 shard 的
    structure 段，而 structure 只经形状/顺序/摘要校验，没有与真实 JADX 产物或 DEX 的
    语义绑定。能重写 cache 的攻击者可以连同摘要一并重算，从而让某个命中带上一个
    **形状合法、看起来很具体**的类/方法归属（`name/arity` 恰是 ``trace_callpath``
    的端点形态，可被继续追踪成内部自洽的伪链）。这与「能写 cache 者本就能伪造本阶段
    读取的一切工件」是同一条既有边界——posting 自身早已可伪造——本函数只是让伪造的
    命中看起来更具体，**不构成新的信任假设**。真要收敛必须在 cache 真实性层面解决。
    """
    structure = shard.get("structure")
    if not isinstance(structure, Mapping):
        return {}
    classes = structure.get("classes")
    if not isinstance(classes, list):
        return {}

    by_path: dict[str, list[tuple[str, str, int, int, int]]] = {}
    for cls in classes:
        if not isinstance(cls, Mapping):
            return {}
        class_name = cls.get("name")
        class_path = cls.get("path")
        methods = cls.get("methods")
        if (
            not isinstance(class_name, str)
            or not isinstance(class_path, str)
            or not isinstance(methods, list)
        ):
            return {}
        for method in methods:
            if not isinstance(method, Mapping):
                return {}
            name = method.get("name")
            arity = method.get("arity")
            start_line = method.get("start_line")
            end_line = method.get("end_line")
            if (
                not isinstance(name, str)
                or isinstance(arity, bool)
                or not isinstance(arity, int)
                or isinstance(start_line, bool)
                or not isinstance(start_line, int)
                or isinstance(end_line, bool)
                or not isinstance(end_line, int)
                or start_line > end_line
            ):
                # ★坏 method 必须放弃**整个** shard 的反查，不能只跳过它：被跳过的那条
                # 可能本来也覆盖某个命中行，剩下的区间就会冒充「唯一归属」——把
                # 「不确定」伪装成确定，正是本函数声称要避免的。粒度与 class 级一致。
                return {}
            by_path.setdefault(class_path, []).append(
                (class_name, name, arity, start_line, end_line)
            )
    # 单一路径下的区间数上界：正常文件远达不到；伪造 cache 可绕过构建期的 Limits，
    # 而反查是逐命中线性扫描，无上界即为可放大的 CPU 面（对齐本项目「未信任输入
    # 一律加硬帽」的既有做法）。超限即放弃该 shard 的反查，宁可无归属。
    if any(len(ranges) > _MAX_CONTEXT_RANGES_PER_PATH for ranges in by_path.values()):
        return {}
    return {path: tuple(ranges) for path, ranges in by_path.items()}


def find_value_usage(index: LoadedIndex, value: str) -> tuple[UsageHit, ...]:
    if (
        not isinstance(index, LoadedIndex)
        or not isinstance(value, str)
        or not value
        or len(value) > _DEFAULT_MAX_VALUE_LEN
    ):
        return ()

    value_digest = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    hits: list[UsageHit] = []

    for shard_index, shard in enumerate(index.shards):
        if not isinstance(shard, Mapping):
            _fail(REASON_MALFORMED, f"$.shards[{shard_index}]")
        lineage = _lineage_from_shard_record(shard, f"$.shards[{shard_index}]")
        postings = shard.get("postings")
        if not isinstance(postings, list):
            _fail(REASON_MALFORMED, f"$.shards[{shard_index}].postings")

        # 每个 shard 只建一次区间表；postings 与 structure 同 shard、同路径坐标系。
        context_index = _build_usage_context_index(shard)

        for posting_index, posting in enumerate(postings):
            path = f"$.shards[{shard_index}].postings[{posting_index}]"
            if not isinstance(posting, Mapping):
                _fail(REASON_MALFORMED, path)
            if set(posting) != {"path", "line", "column", "value_digest"}:
                _fail(REASON_MALFORMED, path)
            relative_path = posting.get("path")
            line = posting.get("line")
            column = posting.get("column")
            digest = posting.get("value_digest")
            if (
                not isinstance(relative_path, str)
                or isinstance(line, bool)
                or not isinstance(line, int)
                or isinstance(column, bool)
                or not isinstance(column, int)
                or not isinstance(digest, str)
            ):
                _fail(REASON_MALFORMED, path)
            # ★形状异常 fail-closed：即使不是本次查询的值，坏 posting 也必须当场揭穿，
            #   不许静默跳过（UsageHit 构造本身就是校验）。
            try:
                hit = UsageHit(
                    relative_path=relative_path,
                    line=line,
                    column=column,
                    value_digest=_validate_digest(digest, f"{path}.value_digest"),
                    lineage=lineage,
                )
            except JadxIndexError as exc:
                raise JadxIndexError(REASON_MALFORMED, path) from exc

            if digest != value_digest:
                continue

            # 归属反查 fail-closed：恰好一个方法区间包含该行才归属。0 个（字段初始化器 /
            # 静态块——class 段没有行号区间，无法单独定类）或 ≥2 个（区间重叠）一律留
            # None。命中集合不受影响：这里只给已找到的阳性命中补上下文，不增不减。
            spans = [
                span
                for span in context_index.get(relative_path, ())
                if span[3] <= line <= span[4]
            ]
            if len(spans) == 1:
                class_name, method_name, method_arity, _, _ = spans[0]
                hit = replace(
                    hit,
                    class_context=class_name,
                    method_context=f"{method_name}/{method_arity}",
                )
            hits.append(hit)

    hits.sort(key=lambda hit: (hit.lineage.sort_key(), hit.relative_path, hit.line, hit.column))
    return tuple(hits)
