"""jadx 深度反编译增强器：用 jadx CLI 反编译 APK，从 Java 字符串字面量补端点 / 密钥。

为什么需要：androguard 的 DEX 字符串池有时拿不全（被混淆 / 拆分 / 加固残留）；
jadx 反编译出可读 Java 后，真实接口与硬编码密钥往往在字符串字面量里更完整。

约束：
- ``requires=["jadx"]``：registry 探测到 PATH 有 jadx 才运行，否则 pipeline 自动 skipped。
- 用 ctx.apk_path 定位 APK；为空 → 优雅跳过（error 写明，不崩）。
- jadx 进程经 ``core.proctree.run_owned`` 执行：自身 300-1200s deadline + **整棵进程树**
  （Windows 上 ``.bat -> cmd -> java -> 后代``）的所有权与终止验证；临时目录 finally 走
  受检清理（失败进 receipt，不再 ``ignore_errors`` 无痕）。
- 每次 analyze 产出 ``meta['jadx_receipt']`` coverage receipt：逐次运行的进程结局 +
  确定性扫描统计（total/scanned/read_failed/truncated/bytes/scan_limit_hit）+ 清理状态；
  ``complete=True`` 是 visibility 给 java 通道定 complete 的唯一凭据。
- 只在 Java 字符串字面量（"..."）内抽取，并对裸域名用安全 TLD 白名单，降误报。
- 任何失败 → 记日志 + meta['jadx_status']，不抛、不静默吞错。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import stat
import struct
import tempfile
import time
import unicodedata
import zipfile
import zlib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, cast

from apkscan.config.string_graph import StringChain, scan_java_source
from apkscan.core.models import (
    FINDING_KIND_INFERENCE,
    AnalyzerResult,
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core import infra, proctree, tools
from apkscan.core.jadx_index import (
    CacheMiss,
    CacheUnavailable,
    DexInput,
    DexLineage,
    DexRole,
    IndexBuildState,
    JadxIndexError,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from apkscan.core.jadx_ownership import project_ownership
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.secrets import (
    SecretRules,
    is_sdk_constant,
    load_secret_rules,
    looks_like_secret_value,
)
from apkscan.core.textutil import is_noise_bare_ip as _is_noise_bare_ip

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# jadx 反编译大 APK 较慢，给足超时（秒）。这是**无额外 DEX**时的基础超时。
_TIMEOUT = 300.0
# 每个额外（脱壳 dump）DEX 追加的超时预算：加固样本的真实代码全在 dump DEX 里，成堆喂进
# jadx 反编译会显著变慢，固定 300s 必被撞穿——一撞穿就只反编译出壳桩、看着像「没代码」。
# 按 DEX 数量线性伸缩、封顶，让大 dump 有机会跑完，同时不至于无限拖住批处理。
_TIMEOUT_PER_EXTRA_DEX = 30.0
_TIMEOUT_MAX = 1200.0
_MAX_JAVA_FILES = 5000
_MAX_FILE_BYTES = 4 * 1024 * 1024
_SNIPPET_MAX = 200

# 裸域名安全 TLD 白名单（与 js_bundle / endpoints 同口径，剔除与代码撞车的伪 TLD）。
_SAFE_BARE_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "biz", "io", "co",
        "xyz", "vip", "club", "shop", "site", "app", "tech", "cloud",
        "fun", "ltd", "pro", "wang", "ren", "mobi", "asia", "icu",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
    }
)
_PACKAGE_ROOTS: frozenset[str] = frozenset(
    {"com", "cn", "org", "net", "io", "edu", "android", "androidx",
     "java", "javax", "kotlin", "kotlinx", "dalvik",
     # AOSP / JDK 内部包根：``Class.forName("libcore.icu.ICU")`` 末标签恰是真实 gTLD（.icu），
     # 不列进来就会被裸域名正则当域名端点收走。
     "libcore", "sun", "jdk"}
)
_CODE_WORDS: frozenset[str] = frozenset(
    {"this", "self", "length", "value", "name", "type", "style", "path",
     "data", "config", "prototype", "exports", "target", "state", "props"}
)

# Java 双引号字符串字面量（容忍转义）。
_STR_LIT_RE = re.compile(r'"([^"\\\n]*(?:\\.[^"\\\n]*)*)"')
_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"""(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\w.])""")
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w.-])"""
)
# 硬编码密钥键值：key = "value" / "key":"value"。
_SECRET_KV_RE = re.compile(
    r"""["']?(?P<key>[A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["'](?P<val>[^"'\n]{8,512})["']"""
)
_SECRET_HINTS: tuple[str, ...] = (
    "secret", "appkey", "app_key", "appsecret", "app_secret", "access_key",
    "accesskey", "api_key", "apikey", "private_key", "privatekey", "aes_key",
    "aeskey", "token", "client_secret", "mch_key", "sign_key", "signkey",
)
_SECRET_DENY: frozenset[str] = frozenset(
    {"token_type", "tokentype", "keyword", "keywords", "keycode", "keyboard"}
)
_PLACEHOLDER: frozenset[str] = frozenset(
    {"your_app_id", "yourappid", "your_app_key", "your_secret", "xxxxxxxx",
     "test", "demo", "none", "null", "undefined", "example"}
)

def _dex_checksum_ok(path: str) -> bool:
    """校验 .dex 文件的 Adler32 头校验和（DEX 头 offset 8 的 uint32，覆盖 offset 12 起的全部字节）。

    ★用途仅限「全军覆没后的降级重跑」筛坏 DEX，不做前置过滤：内存 dump 的 DEX 常见
    「结构完好但 checksum 过期」（dump 工具就地改字节没回填头），jadx 关掉校验后完全能
    反编译——这类不能拦。真正拖垮 jadx 的是「头与体不一致」的损坏 dump（实测：坏 DEX 的
    头整个复制自另一个 DEX，注解表偏移是垃圾值，jadx 载入期按垃圾长度分配直接 OOM 崩掉
    整个进程、一个 .java 都不产出）。checksum 不符恰是这类损坏的可静态判定超集。
    """
    try:
        data = Path(path).read_bytes()
    except Exception:
        logger.warning("[jadx] 读取额外 DEX 失败，按坏 DEX 处理：%s", path, exc_info=True)
        return False
    if len(data) < 16 or not data.startswith(b"dex\n"):
        return False
    (stored,) = struct.unpack_from("<I", data, 8)
    return stored == (zlib.adler32(data[12:]) & 0xFFFFFFFF)


#: 受检临时目录清理的重试次数与基础退避（秒）。Windows 上残余 java 进程刚被杀、句柄释放有
#: 毫秒级延迟，立即 rmtree 常撞 sharing violation；短退避重试即可覆盖，仍失败则如实进 receipt。
_CLEANUP_ATTEMPTS = 3
_CLEANUP_BACKOFF = 0.2


@dataclass(frozen=True)
class _JadxRun:
    """一次 jadx 进程执行的结局：状态 + 本次生效参数摘要 + 进程树结局（None=未启动）。"""

    status: str  # ok|partial|timeout|failed
    options_digest: str
    process: proctree.OwnedRun | None = None


@dataclass
class _ScanOutcome:
    """一次 Java 产物树扫描的全部产出 + 确定性覆盖统计（receipt 的 scan 块）。"""

    endpoints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    n_files: int = 0  # 旧口径：成功扫描的非空 .java 数（meta.jadx_java_files）
    decrypt_candidates: list = field(default_factory=list)
    suppressed: dict = field(default_factory=dict)
    truncated: bool = False  # 撞 _MAX_JAVA_FILES 上限（= scan_limit_hit）
    receipt: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 持久索引接线（opt-in：ctx.jadx_cache_root；一切失败 fail-open 到无索引路径）
# ---------------------------------------------------------------------------

#: jadx 版本参与持久索引身份。探测只占很短时间，不继承反编译的 300-1200s deadline。
_VERSION_PROBE_TIMEOUT = 30.0

#: 单个物化 DEX 的硬上限（解压前按 zip 声明大小挡一层，流式写入时再按实际字节复核）。
#: 必须在运行时经模块属性读取，部署策略与测试才能安全收紧。
_MAX_MATERIALIZE_DEX_BYTES = 256 * 1024 * 1024

#: 一次索引准备允许物化的全部 DEX 实际字节总量（防大量合法 classesN.dex 撑爆磁盘，
#: 磁盘耗尽会反噬「索引 fail-open 不影响主分析」的承诺）。运行时经模块属性读取。
_MAX_MATERIALIZE_TOTAL_BYTES = 1024 * 1024 * 1024

#: 一次索引准备允许接受的 APK + extra DEX 输入总数。运行时经模块属性读取。
_MAX_MATERIALIZE_DEX_COUNT = 200

#: receipt 只接受这个语法的稳定 reason code——其余一律折叠，防路径/异常文本外泄。
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

#: _run_jadx 的 resolved 参数 sentinel：区分「调用方未提供」（自行解析，既有行为）
#: 与「调用方明确提供 None」（已解析过、确实没有 jadx——绝不二次解析）。
_ResolvedJadx = tuple[list[str], dict[str, str]] | None
_RESOLVED_UNSET: object = object()

#: APK 顶层合法 DEX 名：classes.dex→ordinal 0、classes2.dex→1、classesN.dex→N-1。
#: classes1.dex / classes01.dex / 子目录中的 *.dex 都不属于 APK DEX lineage。
_APK_DEX_MEMBER_RE = re.compile(r"^classes(?:([2-9]|[1-9][0-9]+))?\.dex$")

#: jadx 输出是全部输入联合反编译的一棵树，.java 无法按 DEX 归属；扫描产物统一
#: 绑定排序后首个 lineage，其余 lineage 为空 shard。下游消费（结构 diff/ownership）
#: 是跨 shard 聚合，语义无损；此标记让读 receipt 的人知道 shard≠单 DEX 内容。
_INDEX_SCAN_ATTACHMENT = "joint_scan_first_lineage"

_INDEX_REASON_CACHE_NOT_CONFIGURED = "cache_root_not_configured"
_INDEX_REASON_NO_APK_PATH = "no_apk_path"
_INDEX_REASON_JADX_VERSION_UNAVAILABLE = "jadx_version_unavailable"
_INDEX_REASON_DEX_TOO_LARGE = "dex_too_large"
_INDEX_REASON_MATERIALIZE_BUDGET = "materialize_budget_exceeded"
_INDEX_REASON_DEX_MATERIALIZE_FAILED = "dex_materialize_failed"
_INDEX_REASON_NO_DEX_INPUTS = "no_dex_inputs"
_INDEX_REASON_DUPLICATE_APK_DEX = "duplicate_apk_dex_member"
_INDEX_REASON_INVALID_CACHE_STATE = "invalid_cache_state"
_INDEX_REASON_EMPTY_JADX_OUTPUT = "empty_jadx_output"
_INDEX_REASON_BUILD_FAILED = "index_build_failed"
_INDEX_REASON_INDEX_EXCEPTION = "index_exception"
_INDEX_REASON_EXCLUDED_DEX = "excluded_dex"
_INDEX_REASON_INVALID_BASELINE_KEY = "invalid_baseline_index_key"
_INDEX_REASON_BASELINE_UNAVAILABLE = "baseline_index_unavailable"
_INDEX_REASON_BASELINE_MANIFEST_UNAVAILABLE = "baseline_manifest_unavailable"
_INDEX_REASON_SUBJECT_UNAVAILABLE = "subject_index_unavailable"


@dataclass(frozen=True)
class _MaterializedDexInputs:
    """物化后的已验证 DEX 身份。``lineage`` 不含路径，可安全参与 index key 与 manifest。"""

    root: str
    lineage: tuple[DexLineage, ...]
    unrecognized_dex_members: int


class _DexMaterializeError(ValueError):
    """索引物化阶段的稳定拒绝；message 只进日志，code 才能进 receipt。"""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(message or code)


def _index_receipt(
    *,
    status: str = "disabled",
    reason_codes: Iterable[str] = (),
    unrecognized_dex_members: int = 0,
    key: str | None = None,
) -> dict:
    """创建不含文件系统路径的索引 receipt 子块。"""
    receipt: dict = {
        "status": status,
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "unrecognized_dex_members": int(unrecognized_dex_members),
        "scan_attachment": _INDEX_SCAN_ATTACHMENT,
    }
    if key is not None:
        receipt["key"] = key
    return receipt


def _append_index_reason(index_receipt: dict, code: str) -> None:
    """向 index.reason_codes 加稳定码并保持确定排序。

    receipt 只接受受限 ASCII reason code：P1 的三态对象（CacheUnavailable 等）自身
    不校验 reason，异常旁路可能把路径/异常文本带进来——不合语法的值折叠为
    ``invalid_cache_state``，原值仅进 warning 日志。
    """
    reasons: set[str] = set()
    raw_reasons = index_receipt.get("reason_codes") or []
    if isinstance(raw_reasons, str):
        existing_items: Iterable[object] = (raw_reasons,)
    elif isinstance(raw_reasons, (list, tuple, set, frozenset)):
        existing_items = raw_reasons
    else:
        logger.warning("[jadx-index] reason_codes 容器非法，已折叠：%r", raw_reasons)
        existing_items = ()
        reasons.add(_INDEX_REASON_INVALID_CACHE_STATE)
    for item in existing_items:
        if isinstance(item, str) and _REASON_CODE_RE.fullmatch(item) is not None:
            reasons.add(item)
        elif item:
            logger.warning("[jadx-index] 非法 reason code 已折叠：%r", item)
            reasons.add(_INDEX_REASON_INVALID_CACHE_STATE)
    if _REASON_CODE_RE.fullmatch(code) is not None:
        reasons.add(code)
    else:
        logger.warning("[jadx-index] 非法 reason code 已折叠：%r", code)
        reasons.add(_INDEX_REASON_INVALID_CACHE_STATE)
    index_receipt["reason_codes"] = sorted(reasons)


def _resolved_jadx_env(extra_env: dict[str, str]) -> dict[str, str] | None:
    """按反编译入口相同规则生成子进程环境（插件包 JRE 时注入 JAVA_HOME）。"""
    return {**os.environ, **extra_env} if extra_env else None


def _probe_jadx_version(
    resolved: tuple[list[str], dict[str, str]] | None,
) -> str | None:
    """探测本次解析出的 jadx 命令版本。

    不缓存成功或失败结果：每次启用持久索引的 analyze 都探测一次（相对反编译本体
    成本可忽略，且免去跨运行的缓存失效问题）。只有进程树受控、正常退出且 stdout
    首行经 NFC 规范化后非空，才允许版本进入 key material——版本参与索引身份，
    假版本会让不兼容索引共享身份。
    """
    if resolved is None:
        return None
    jadx_cmd, extra_env = resolved
    if not jadx_cmd:
        return None
    owned = proctree.run_owned(
        [*jadx_cmd, "--version"],
        timeout=_VERSION_PROBE_TIMEOUT,
        env=_resolved_jadx_env(extra_env),
    )
    if (
        owned.returncode != 0
        or owned.timed_out
        or not owned.ownership_complete
        or not owned.termination_complete
        or owned.forced_tree_kill
    ):
        return None
    lines = (owned.stdout or "").splitlines()
    if not lines:
        return None
    version = unicodedata.normalize("NFC", lines[0].strip())
    return version or None


def _copy_stream_limited(
    source: IO[bytes],
    destination: Path,
    *,
    total_remaining: int,
) -> tuple[str, int]:
    """把二进制流写入受控路径，返回 ``(复算 digest, 实际写入字节数)``。

    zip 声明大小可伪造（小压缩巨解压），实际写入必须独立计数：同时执行单 DEX 上限
    与本次物化剩余总预算；到达任一边界后额外读取至多一个字节探测越界，越界字节
    不落盘。
    """
    per_dex_limit = _MAX_MATERIALIZE_DEX_BYTES
    if per_dex_limit < 0:
        raise _DexMaterializeError(_INDEX_REASON_DEX_TOO_LARGE)
    if total_remaining < 0:
        raise _DexMaterializeError(_INDEX_REASON_MATERIALIZE_BUDGET)
    written = 0
    digest = hashlib.sha256()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while True:
            readable_without_overflow = min(
                per_dex_limit - written,
                total_remaining - written,
                1024 * 1024,
            )
            chunk = source.read(readable_without_overflow + 1)
            if not chunk:
                break
            next_written = written + len(chunk)
            if next_written > per_dex_limit:
                raise _DexMaterializeError(_INDEX_REASON_DEX_TOO_LARGE)
            if next_written > total_remaining:
                raise _DexMaterializeError(_INDEX_REASON_MATERIALIZE_BUDGET)
            output.write(chunk)
            digest.update(chunk)
            written = next_written
    return "sha256:" + digest.hexdigest(), written


def _apk_dex_ordinal(member_name: str, suffix: str | None) -> int:
    """把已匹配的 APK DEX 名转换成 role 内 ordinal（classes.dex=0、classesN=N-1）。"""
    if member_name == "classes.dex":
        return 0
    if suffix is None:
        raise _DexMaterializeError(
            _INDEX_REASON_DEX_MATERIALIZE_FAILED,
            f"合法 DEX 名缺少数字后缀：{member_name}",
        )
    return int(suffix) - 1


def _materialize_dex_inputs(
    apk_path: str,
    extra_dex_paths: Sequence[str],
) -> _MaterializedDexInputs:
    """把 APK 顶层 classes*.dex 与额外 DEX 物化到独立临时根并验证 lineage。

    verify_dex_inputs 只吃目录下的真实文件，而 APK 是 zip——必须先解出。物化路径
    用固定安全相对路径（apk/classes.dex、extra/000000.dex…），绝不把原绝对路径当
    relative_path。digest 为解出字节的复算值（declared=复算值；verify_dex_inputs
    再复算一遍是防物化后被改）。

    调用成功后 root 归调用方所有，必须立即并入 ``tmp_dirs`` 统一受检清理；失败时
    本函数尽力删除尚未交接的 root，清理失败只写日志。
    """
    root = tempfile.mkdtemp(prefix="apkscan_jadx_mat_")
    handed_off = False
    try:
        inputs: list[DexInput] = []
        unrecognized = 0
        total_written = 0
        total_budget = _MAX_MATERIALIZE_TOTAL_BYTES
        dex_count_limit = _MAX_MATERIALIZE_DEX_COUNT
        if total_budget < 0 or dex_count_limit < 0:
            raise _DexMaterializeError(_INDEX_REASON_MATERIALIZE_BUDGET)
        try:
            with zipfile.ZipFile(apk_path, "r") as archive:
                valid_members: list[tuple[int, zipfile.ZipInfo]] = []
                seen_ordinals: set[int] = set()
                for info in archive.infolist():
                    name = info.filename
                    match = _APK_DEX_MEMBER_RE.fullmatch(name)
                    if match is None:
                        # 非白名单形态的 .dex（子目录、非法编号）不静默：计数留痕。
                        if name.lower().endswith(".dex"):
                            unrecognized += 1
                        continue
                    ordinal = _apk_dex_ordinal(name, match.group(1))
                    if ordinal in seen_ordinals:
                        raise _DexMaterializeError(
                            _INDEX_REASON_DUPLICATE_APK_DEX,
                            f"APK 中出现重复 DEX ordinal：{ordinal}",
                        )
                    seen_ordinals.add(ordinal)
                    # 声明大小先挡单文件上限；总预算只按后续实际流读取字节累计。
                    if info.file_size > _MAX_MATERIALIZE_DEX_BYTES:
                        raise _DexMaterializeError(_INDEX_REASON_DEX_TOO_LARGE)
                    valid_members.append((ordinal, info))
                # 开始物化前先拒超量输入（extra 计入同一数量预算）：大量合法
                # classesN.dex 的磁盘占用会反噬 fail-open 承诺。
                if len(valid_members) + len(extra_dex_paths) > dex_count_limit:
                    raise _DexMaterializeError(_INDEX_REASON_MATERIALIZE_BUDGET)
                valid_members.sort(key=lambda item: item[0])
                for ordinal, info in valid_members:
                    relative = f"apk/{info.filename}"
                    destination = Path(root) / relative
                    with archive.open(info, "r") as source:
                        digest, written = _copy_stream_limited(
                            source, destination,
                            total_remaining=total_budget - total_written,
                        )
                    total_written += written
                    inputs.append(
                        DexInput(
                            role=DexRole.APK_DEX,
                            ordinal=ordinal,
                            source_label="apk",
                            relative_path=relative,
                            declared_digest=digest,
                        )
                    )
        except _DexMaterializeError:
            raise
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise _DexMaterializeError(
                _INDEX_REASON_DEX_MATERIALIZE_FAILED,
                f"读取 APK ZIP 失败：{exc}",
            ) from exc

        for ordinal, raw_path in enumerate(extra_dex_paths):
            source_path = Path(raw_path)
            relative = f"extra/{ordinal:06d}.dex"
            destination = Path(root) / relative
            try:
                if source_path.stat().st_size > _MAX_MATERIALIZE_DEX_BYTES:
                    raise _DexMaterializeError(_INDEX_REASON_DEX_TOO_LARGE)
                with source_path.open("rb") as source:
                    digest, written = _copy_stream_limited(
                        source, destination,
                        total_remaining=total_budget - total_written,
                    )
                total_written += written
            except _DexMaterializeError:
                raise
            except OSError as exc:
                raise _DexMaterializeError(
                    _INDEX_REASON_DEX_MATERIALIZE_FAILED,
                    f"读取额外 DEX 失败：{source_path}",
                ) from exc
            inputs.append(
                DexInput(
                    role=DexRole.EXTRA_DEX,
                    ordinal=ordinal,
                    source_label="extra",
                    relative_path=relative,
                    declared_digest=digest,
                )
            )

        if not inputs:
            raise _DexMaterializeError(_INDEX_REASON_NO_DEX_INPUTS)

        lineage = verify_dex_inputs(root, inputs)
        handed_off = True
        return _MaterializedDexInputs(
            root=root,
            lineage=lineage,
            unrecognized_dex_members=unrecognized,
        )
    finally:
        if not handed_off:
            cleanup = _remove_tree_checked(root)
            if not cleanup["complete"]:
                logger.warning("[jadx-index] 失败物化 root 未能清理：%s", root)


def _lineage_after_exclusions(
    lineage: tuple[DexLineage, ...],
    original_extra_paths: Sequence[str],
    excluded_paths: Sequence[str],
) -> tuple[DexLineage, ...]:
    """按原始 extra 输入序剔除降级重跑排除项；保留者 ordinal 不重排（身份稳定）。"""
    excluded = set(excluded_paths)
    excluded_ordinals = {
        ordinal
        for ordinal, path in enumerate(original_extra_paths)
        if path in excluded
    }
    return tuple(
        item
        for item in lineage
        if not (item.role is DexRole.EXTRA_DEX and item.ordinal in excluded_ordinals)
    )


def _index_values(outcome: "_ScanOutcome") -> list[str]:
    """构造 usage 索引关注值：端点值 + decrypt candidate 密文，稳定去重。

    这是「一次索引、多次廉价 usage 查询」的观察面；scan_java_sources 自会再做
    排序去重与长度上限。
    """
    values: set[str] = set()
    for endpoint in outcome.endpoints:
        value = getattr(endpoint, "value", None)
        if isinstance(value, str) and value:
            values.add(value)
    for candidate in outcome.decrypt_candidates:
        if not isinstance(candidate, dict):
            continue
        ciphertext = candidate.get("ciphertext")
        if isinstance(ciphertext, str) and ciphertext:
            values.add(ciphertext)
    return sorted(values)


def _index_status_from_build(state: IndexBuildState, coverage: str) -> str:
    """把 P1 build state 映射成 analyzer 对外状态（未知形态保守按 failed）。"""
    if state is IndexBuildState.REUSED:
        return "reused"
    if state is IndexBuildState.UNAVAILABLE:
        return "unavailable"
    if state is IndexBuildState.FAILED:
        return "failed"
    if state is IndexBuildState.PARTIAL or coverage == "partial":
        return "partial"
    if state is IndexBuildState.BUILT:
        return "built"
    return "failed"


def _stable_index_reason(value: object, fallback: str) -> str:
    """把外部/缓存状态压成 receipt/meta 可见的稳定 reason code。

    CacheMiss/CacheUnavailable 的 reason 字段数据类本身不校验——任何进入摘要
    或 receipt 的单值 reason 都必须过同一语法闸，不合法即折叠。
    """
    if isinstance(value, str) and _REASON_CODE_RE.fullmatch(value) is not None:
        return value
    return fallback


def _baseline_manifest_digest(cache_root: str, baseline_key: str) -> str | None:
    """读 cache 内 canonical manifest 的文件字节算摘要。

    cache 内 manifest.json 已由 P1 load 侧完成 canonical 自证——这里不得重新
    实现 canonicalization，直接对文件字节 sha256。读失败 → None（旁路 fail-open）。
    """
    try:
        manifest_path = Path(cache_root) / baseline_key / "manifest.json"
        data = manifest_path.read_bytes()
    except Exception:  # noqa: BLE001 - 摘要旁路 fail-open
        logger.warning("[jadx-ownership] baseline manifest 摘要不可得", exc_info=True)
        return None
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _unavailable_ownership_summary(reason: object) -> dict[str, object]:
    """构造不暴露路径/异常文本的 unavailable 摘要。"""
    return {
        "status": "unavailable",
        "reason": _stable_index_reason(reason, _INDEX_REASON_BASELINE_UNAVAILABLE),
    }


def _project_jadx_baseline(
    *,
    cache_root: str,
    subject_key: object,
    baseline_key: object,
) -> tuple[dict[str, object], dict[str, object]]:
    """加载 subject/baseline 索引并生成 ownership 摘要与 receipt baseline 块。

    返回 ``(summary, receipt_baseline)``。纯 baseline 旁路：任意异常只转
    unavailable，不向主分析传播。「official」身份由调用方断言、非鉴真——摘要
    只输出结构匹配计数与防误读字段，绝不输出 ownership 枚举值。
    """
    if not isinstance(baseline_key, str) or re.fullmatch(
        r"[0-9a-f]{64}", baseline_key
    ) is None:
        summary = _unavailable_ownership_summary(_INDEX_REASON_INVALID_BASELINE_KEY)
        return summary, {"status": "unavailable", "reason": summary["reason"]}
    if not isinstance(subject_key, str) or re.fullmatch(
        r"[0-9a-f]{64}", subject_key
    ) is None:
        summary = _unavailable_ownership_summary(_INDEX_REASON_SUBJECT_UNAVAILABLE)
        return summary, {"status": "unavailable", "reason": summary["reason"]}

    try:
        # subject 即使刚 built/reused 也必须从 store 再 load 一次：
        # build_index 的返回值不带 shards，投影要吃完整 LoadedIndex。
        store = JadxIndexStore(cache_root)
        subject_loaded = store.load_index(subject_key)
        if not isinstance(subject_loaded, LoadedIndex):
            summary = _unavailable_ownership_summary(_INDEX_REASON_SUBJECT_UNAVAILABLE)
            return summary, {"status": "unavailable", "reason": summary["reason"]}

        baseline_loaded = store.load_index(baseline_key)
        if not isinstance(baseline_loaded, LoadedIndex):
            reason = _stable_index_reason(
                getattr(baseline_loaded, "reason", None),
                _INDEX_REASON_BASELINE_UNAVAILABLE,
            )
            return (
                _unavailable_ownership_summary(reason),
                {"status": "unavailable", "reason": reason},
            )

        manifest_digest = _baseline_manifest_digest(cache_root, baseline_key)
        if manifest_digest is None:
            summary = _unavailable_ownership_summary(
                _INDEX_REASON_BASELINE_MANIFEST_UNAVAILABLE
            )
            return summary, {"status": "unavailable", "reason": summary["reason"]}

        projection = project_ownership(subject_loaded, baseline_loaded)
        counts = Counter(region.reason for region in projection.regions)
        matches = counts.get("matches_official_baseline", 0)
        modified = counts.get("modified_relative_to_baseline", 0)
        absent = counts.get("absent_from_baseline", 0)
        # 只有 P1-D 明确的三个 reason token 进主计数；其余（no_official_baseline、
        # baseline_coverage_partial）归入 unattributed，保证四桶之和 == region 总数。
        unattributed = len(projection.regions) - matches - modified - absent

        summary = {
            "status": "compared",
            "baseline_designation": "caller_asserted_official",
            "comparison_semantics": "structural_match_only",
            "authenticity_asserted": False,
            "verdict_effect": "none",
            "baseline_index_key": baseline_loaded.manifest.index_key,
            "subject_index_key": projection.subject_index_key,
            "baseline_manifest_digest": manifest_digest,
            "matches": matches,
            "modified": modified,
            "absent": absent,
            "unattributed": unattributed,
            "absence_claimable": bool(projection.absence_claimable),
            "subject_coverage": projection.subject_coverage,
            "baseline_coverage": projection.baseline_coverage,
        }
        return summary, {"status": "compared"}
    except Exception:  # noqa: BLE001 - ownership 旁路必须 fail-open
        logger.exception("[jadx-ownership] baseline 投影失败")
        summary = _unavailable_ownership_summary(_INDEX_REASON_BASELINE_UNAVAILABLE)
        return summary, {"status": "unavailable", "reason": summary["reason"]}


_FINDING_SECRET = "JADX-HARDCODED-SECRET"
#: config-chain 层②：方法内 密文→解密(→sink) 共现链（启发式、非数据流证明）。
_FINDING_STRING_CHAIN = "STRING-CHAIN-DECRYPT"


class JadxAnalyzer(BaseAnalyzer):
    """jadx 反编译后从 Java 字符串字面量补端点 / 密钥（requires=["jadx"]）。"""

    name: str = "jadx"
    meta_key_categories = {
        'decrypt_candidates': 'signal',
        'decrypt_candidates_suppressed': 'coverage',
        'jadx_bad_dex_excluded': 'coverage',
        'jadx_endpoint_count': 'record',
        'jadx_index_key': 'record',
        'jadx_index_status': 'coverage',
        'jadx_java_files': 'coverage',
        'jadx_ownership_summary': 'record',
        'jadx_receipt': 'coverage',
        'jadx_scan_truncated': 'coverage',
        'jadx_status': 'coverage',
    }
    meta_keys = frozenset(meta_key_categories)
    # 待定：它可能只是逆向候选清单，也可能应驱动后续解密动作；先按信号报警。
    meta_category_pending = frozenset({'decrypt_candidates'})
    requires: list[str] = ["jadx", "apk"]  # jadx 反编 DEX

    def __init__(self) -> None:
        # 每次 analyze 重新加载（见下）；这里给默认值供类型检查与兜底。
        self._secret_rules: SecretRules = SecretRules()
        self._noise_ips: frozenset[str] = frozenset()

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        apk_path = (getattr(ctx, "apk_path", "") or "").strip()
        # 持久索引 opt-in：不给 cache root = 现行为 + disabled，文件系统零持久化。
        cache_root = (getattr(ctx, "jadx_cache_root", "") or "").strip()
        # baseline 比较是索引之上的第二层 opt-in（须同时启用 cache root）。
        baseline_index = getattr(ctx, "jadx_baseline_index", None)
        baseline_requested = baseline_index is not None
        index_receipt = _index_receipt(
            status="disabled",
            reason_codes=(
                [_INDEX_REASON_CACHE_NOT_CONFIGURED] if not cache_root else []
            ),
        )
        result.meta["jadx_index_status"] = "disabled"

        if not apk_path:
            logger.info("[jadx] 无 apk_path，跳过 jadx 反编译")
            result.error = "无 apk_path，跳过 jadx 反编译"
            result.meta["jadx_status"] = "no_apk_path"
            _append_index_reason(index_receipt, _INDEX_REASON_NO_APK_PATH)
            # 早退也产 receipt（complete=False）：让「每次 analyze 都有 jadx_receipt」的
            # 契约无例外，visibility 的 receipt 通道能识别 no_apk_path → unavailable。
            result.meta["jadx_receipt"] = _build_jadx_receipt(
                status="no_apk_path", runs=[], scan=None,
                cleanup={"complete": True, "reason_codes": []}, analyzer_error=False,
                index=index_receipt,
            )
            return result

        # C2/C4 规则一次性加载（缺失走内置兜底，离线不崩）。
        self._secret_rules = load_secret_rules()
        self._noise_ips = _load_noise_ips()

        # 脱壳 dump 的额外 DEX 路径：加固样本的真实代码只在这些 DEX 里，必须一并喂给 jadx
        # 反编译，否则只反编译出壳桩（jadx_java_files 停在个位数）、真实代码仅以字符串池可见。
        # 存在性过滤：路径来自 ctx（多经 cli/unpack 预校验），但防御性剔除已不存在的条目，
        # 免得单个坏路径让 jadx 整体非零退出。
        extra_dex_paths = [
            p for p in (getattr(ctx, "extra_dex_paths", None) or []) if p and os.path.isfile(p)
        ]

        tmp = tempfile.mkdtemp(prefix="apkscan_jadx_")
        tmp_dirs = [tmp]  # 本次 analyze 创建过的全部输出目录（finally 逐个受检清理）
        runs: list[dict] = []
        scan_receipt: dict | None = None

        # 索引启用时只解析一次 jadx：版本探测与后续反编译共用同一份解析结果，
        # 版本身份与实际反编译命令绝不来自两次解析（解析出 None 也一样——绝不给
        # 二次解析留「换了台 jadx」的窗口）。未启用索引保持 sentinel，_run_jadx
        # 维持自行解析的既有行为。索引准备的任何失败只降级索引（fail-open）。
        resolved_jadx: _ResolvedJadx | object = _RESOLVED_UNSET
        materialized: _MaterializedDexInputs | None = None
        jadx_version: str | None = None
        if cache_root:
            try:
                resolved_for_index: _ResolvedJadx = tools.resolve_jadx()
                resolved_jadx = resolved_for_index
                jadx_version = _probe_jadx_version(resolved_for_index)
                if jadx_version is None:
                    _append_index_reason(
                        index_receipt, _INDEX_REASON_JADX_VERSION_UNAVAILABLE
                    )
                else:
                    materialized = _materialize_dex_inputs(apk_path, extra_dex_paths)
                    # 物化 root 创建成功后立刻交给统一 finally 管理（受检清理）。
                    tmp_dirs.append(materialized.root)
                    index_receipt["unrecognized_dex_members"] = (
                        materialized.unrecognized_dex_members
                    )
            except _DexMaterializeError as exc:
                logger.warning(
                    "[jadx-index] DEX 物化被拒绝：code=%s detail=%s", exc.code, exc
                )
                _append_index_reason(index_receipt, exc.code)
                materialized = None
            except JadxIndexError as exc:
                # 稳定协议值进 receipt；字段坐标只进日志。
                logger.warning(
                    "[jadx-index] lineage 输入被拒绝：code=%s field_path=%s",
                    exc.code, exc.field_path,
                )
                _append_index_reason(index_receipt, exc.code)
                materialized = None
            except OSError:
                logger.exception("[jadx-index] 版本探测或物化发生 OS 异常")
                _append_index_reason(
                    index_receipt, _INDEX_REASON_DEX_MATERIALIZE_FAILED
                )
                materialized = None
            except Exception:  # noqa: BLE001 - 索引旁路绝不影响主分析
                logger.exception("[jadx-index] 索引准备异常")
                _append_index_reason(index_receipt, _INDEX_REASON_INDEX_EXCEPTION)
                materialized = None

        try:
            run1 = self._run_jadx(apk_path, tmp, extra_dex_paths, resolved=resolved_jadx)
            final_run = run1
            runs.append(_run_receipt(run1))
            status = run1.status
            # 先落一次 status：_scan_java 若异常，报告里仍看得到 jadx 进程本身的结局
            # （降级重跑后下方会覆写为最终值）。
            result.meta["jadx_status"] = status
            # timeout/failed 仍尽量扫已生成产物（jadx 常非零退出但已产出部分源码）。
            outcome = self._scan_java(Path(tmp))
            excluded_paths: list[str] = []
            # ★全军覆没降级：损坏的 dump DEX（头体不一致，checksum 必不符）会让 jadx 在
            #   载入期 OOM 崩掉整个进程——不是拒载单个文件，而是 0 产出（实测比不喂 dump
            #   还差）。此时剔除 checksum 不符的 DEX 重跑一次，把好 DEX 的产出救回来。
            #   不做前置过滤的原因见 _dex_checksum_ok：checksum 过期但结构完好的 dump
            #   jadx 能正常反编译，先整体跑保住它们的信息，只在证实被拖垮后才降级。
            if outcome.n_files == 0 and status != "ok" and extra_dex_paths:
                bad = [p for p in extra_dex_paths if not _dex_checksum_ok(p)]
                if bad:
                    good = [p for p in extra_dex_paths if p not in bad]
                    logger.warning(
                        "[jadx] 首跑 0 产出（status=%s），剔除 %d 个坏 checksum DEX 降级重跑"
                        "（保留 %d 个）：%s",
                        status, len(bad), len(good),
                        ", ".join(os.path.basename(p) for p in bad),
                    )
                    # ★重跑写进**全新**目录：不复用首跑目录，杜绝「上一跑残留混进重跑
                    #   产物」的污染窗口（复用 + ignore_errors 清理失败时会发生）。
                    #   旧目录不在此刻删，统一由 finally 的受检清理收口并进 receipt。
                    tmp = tempfile.mkdtemp(prefix="apkscan_jadx_")
                    tmp_dirs.append(tmp)
                    retry = self._run_jadx(apk_path, tmp, good, resolved=resolved_jadx)
                    # 索引一律基于最终那次 run：最终输出树、最终 options_digest、
                    # 剔除坏 DEX 后的保留 lineage。
                    final_run = retry
                    # 重跑的输入集已剔除坏 DEX → options_digest 必与首跑不同：两次执行的
                    # 参数差异在 receipt 里可辨，不会被误当同一输入的重复执行。
                    runs.append({**_run_receipt(retry), "degraded_rerun": True})
                    outcome = self._scan_java(Path(tmp))
                    # 被剔除的 DEX 没被反编译，整体产出定义上就是「部分」——即使重跑本身
                    # 干净退出也不报 ok，避免把「部分丢失」读成「全部成功」。丢了哪些
                    # 落进 meta.jadx_bad_dex_excluded（basename，不带案件路径），报告可见。
                    status = retry.status if retry.status != "ok" else "partial"
                    excluded_paths = bad
                    result.meta["jadx_bad_dex_excluded"] = [
                        os.path.basename(p) for p in bad
                    ]
            result.meta["jadx_status"] = status
            if outcome.truncated:
                # 撞 _MAX_JAVA_FILES 上限截断扫描——与 jadx 进程本身的 partial/timeout 是
                # 两个正交维度，单独落键：jadx_java_files==5000 时读的人才能分清「恰好 5000」
                # 与「截断于 5000」。
                result.meta["jadx_scan_truncated"] = True
            result.endpoints = outcome.endpoints
            result.findings = outcome.findings
            result.meta["jadx_java_files"] = outcome.n_files
            result.meta["jadx_endpoint_count"] = len(outcome.endpoints)
            if outcome.decrypt_candidates:  # 机器可读「待 AI 解密」清单（疑似加密配置串 + 疑似解密 helper）
                result.meta["decrypt_candidates"] = outcome.decrypt_candidates
            if outcome.suppressed:  # 被降噪规则压制的候选数（按原因），供复核"压制是否吃掉了自有密文"
                result.meta["decrypt_candidates_suppressed"] = outcome.suppressed
            scan_receipt = outcome.receipt
            logger.info(
                "[jadx] status=%s java=%d 端点=%d 密钥Finding=%d",
                status, outcome.n_files, len(outcome.endpoints), len(outcome.findings),
            )

            # --------------------------------------------------------------
            # 持久索引旁路：build 时机在最终 _scan_java 之后、finally 清理之前
            # （jadx 输出目录与物化 root 都还活着）。任何异常只改索引 status/receipt，
            # 绝不污染 result.error 与既有产出。
            # --------------------------------------------------------------
            if cache_root and materialized is not None and jadx_version is not None:
                lineage = _lineage_after_exclusions(
                    materialized.lineage, extra_dex_paths, excluded_paths
                )
                if excluded_paths:
                    _append_index_reason(index_receipt, _INDEX_REASON_EXCLUDED_DEX)
                try:
                    if not lineage:
                        index_receipt["status"] = "disabled"
                        _append_index_reason(index_receipt, _INDEX_REASON_NO_DEX_INPUTS)
                    else:
                        options_digest = final_run.options_digest
                        key = derive_index_key(lineage, jadx_version, options_digest)
                        index_receipt["key"] = key
                        result.meta["jadx_index_key"] = key
                        # 保护根传 APK **文件**而非其目录：cache root 不许圈住样本文件，
                        # 但用户把 cache 放样本旁边是合法布局。tmp_dirs 已含全部输出目录
                        # 与物化 root。
                        try:
                            store = JadxIndexStore(
                                cache_root,
                                protected_roots=[apk_path, *tmp_dirs],
                            )
                        except JadxIndexError as exc:
                            logger.warning(
                                "[jadx-index] cache root 被拒绝：code=%s field_path=%s",
                                exc.code, exc.field_path,
                            )
                            index_receipt["status"] = "disabled"
                            _append_index_reason(index_receipt, exc.code)
                        else:
                            loaded = store.load_index(key)
                            if isinstance(loaded, LoadedIndex):
                                index_receipt["status"] = "reused"
                            elif isinstance(loaded, CacheUnavailable):
                                # CacheUnavailable 绝不当 miss：不重建、不覆盖、不绕道。
                                index_receipt["status"] = "unavailable"
                                if loaded.reason:
                                    _append_index_reason(index_receipt, loaded.reason)
                            elif isinstance(loaded, CacheMiss):
                                if outcome.n_files == 0:
                                    # jadx 0 产出（失败态）：绝不发布空索引冒充观察面。
                                    index_receipt["status"] = "failed"
                                    _append_index_reason(
                                        index_receipt, _INDEX_REASON_EMPTY_JADX_OUTPUT
                                    )
                                else:
                                    coverage = (
                                        "partial"
                                        if status in {"partial", "timeout"}
                                        or bool(excluded_paths)
                                        else "complete"
                                    )
                                    material = build_key_material(
                                        lineage, jadx_version, options_digest
                                    )
                                    manifest = JadxIndexManifest(
                                        index_key=key,
                                        key_material=material,
                                        dex_lineage=lineage,
                                        jadx_version=jadx_version,
                                        options_digest=options_digest,
                                        coverage=coverage,
                                    )
                                    scan = scan_java_sources(
                                        tmp,
                                        _index_values(outcome),
                                        lineage=lineage[0],
                                        limits=Limits(),
                                    )
                                    built = store.build_index(
                                        materialized.root, manifest, scan=scan
                                    )
                                    if isinstance(built, CacheUnavailable):
                                        index_receipt["status"] = "unavailable"
                                        if built.reason:
                                            _append_index_reason(
                                                index_receipt, built.reason
                                            )
                                    else:
                                        index_status = _index_status_from_build(
                                            built.state, built.coverage
                                        )
                                        index_receipt["status"] = index_status
                                        if index_status == "failed":
                                            _append_index_reason(
                                                index_receipt,
                                                _INDEX_REASON_BUILD_FAILED,
                                            )
                            else:
                                # 未知返回形态不能当 miss，更不能覆盖已有 cache。
                                index_receipt["status"] = "unavailable"
                                _append_index_reason(
                                    index_receipt, _INDEX_REASON_INVALID_CACHE_STATE
                                )
                except JadxIndexError as exc:
                    logger.warning(
                        "[jadx-index] 索引构建被拒绝：code=%s field_path=%s",
                        exc.code, exc.field_path,
                    )
                    index_receipt["status"] = "failed"
                    _append_index_reason(index_receipt, exc.code)
                except Exception:  # noqa: BLE001 - 索引旁路 fail-open
                    logger.exception("[jadx-index] 索引构建异常")
                    index_receipt["status"] = "failed"
                    _append_index_reason(index_receipt, _INDEX_REASON_INDEX_EXCEPTION)

                # disabled 是「未建未载」的承诺，不许留下 key 暗示索引存在。
                if index_receipt["status"] == "disabled":
                    index_receipt.pop("key", None)
                    result.meta.pop("jadx_index_key", None)
                result.meta["jadx_index_status"] = index_receipt["status"]

                # ----------------------------------------------------------
                # P2-C：baseline ownership 比较是索引之上的旁路——subject 索引
                # built/reused 才投影；否则摘要明确 unavailable。baseline 失败
                # 绝不牵连 subject 的 jadx_index_status / result.error / 任何
                # 既有产出（verdict 红线：摘要只新增键，不改任何值）。
                # ----------------------------------------------------------
                if cache_root and baseline_requested:
                    if index_receipt["status"] in {"built", "reused"}:
                        baseline_summary, baseline_receipt = _project_jadx_baseline(
                            cache_root=cache_root,
                            subject_key=result.meta.get("jadx_index_key"),
                            baseline_key=baseline_index,
                        )
                    else:
                        baseline_summary = _unavailable_ownership_summary(
                            _INDEX_REASON_SUBJECT_UNAVAILABLE
                        )
                        baseline_receipt = {
                            "status": "unavailable",
                            "reason": baseline_summary["reason"],
                        }
                    result.meta["jadx_ownership_summary"] = baseline_summary
                    index_receipt["baseline"] = baseline_receipt
        except Exception as exc:  # noqa: BLE001 - 任何异常转 error，不抛给 pipeline
            logger.exception("[jadx] 反编译/扫描异常")
            result.error = f"jadx 增强异常：{exc}"
            # 索引尚未获得终态时明确记 failed；不把主分析异常伪装成 cache unavailable。
            if cache_root and materialized is not None:
                index_receipt["status"] = "failed"
                _append_index_reason(index_receipt, _INDEX_REASON_INDEX_EXCEPTION)
                result.meta["jadx_index_status"] = "failed"
            # baseline 是摘要旁路：主分析异常时不再尝试投影，只给稳定 unavailable。
            if cache_root and baseline_requested:
                baseline_summary = _unavailable_ownership_summary(
                    _INDEX_REASON_SUBJECT_UNAVAILABLE
                )
                result.meta["jadx_ownership_summary"] = baseline_summary
                index_receipt["baseline"] = {
                    "status": "unavailable",
                    "reason": baseline_summary["reason"],
                }
        finally:
            # 受检清理：进程树已在 _run_jadx 内验证终止后才走到这里；失败不再无痕，
            # 进 receipt 的 cleanup 块并使 complete=False（Java 面不得算完整覆盖）。
            # 降级重跑时首跑目录也在 tmp_dirs 里，一并受检、结果合并。
            cleanups = [_remove_tree_checked(d) for d in tmp_dirs]
            cleanup = {
                "complete": all(c["complete"] for c in cleanups),
                "reason_codes": sorted({rc for c in cleanups for rc in c["reason_codes"]}),
            }
            # 物化 root 清理失败只进顶层 cleanup（挡 Java 面 complete），不回写已发布
            # manifest 的 coverage、也不改 jadx_index_status——索引内容的完整性由构建时
            # 的观察决定，与事后环境卫生无关。
            result.meta["jadx_receipt"] = _build_jadx_receipt(
                status=str(result.meta.get("jadx_status") or "failed"),
                runs=runs,
                scan=scan_receipt,
                cleanup=cleanup,
                analyzer_error=bool(result.error),
                index=index_receipt,
            )
        return result

    # ------------------------------------------------------------------

    def _run_jadx(
        self,
        apk_path: str,
        out_dir: str,
        extra_dex_paths: list[str] | None = None,
        *,
        resolved: _ResolvedJadx | object = _RESOLVED_UNSET,
    ) -> _JadxRun:
        """跑 jadx --no-res -d <out> <apk> [dump.dex...]。返回 :class:`_JadxRun`（不抛）。

        ``extra_dex_paths``：脱壳 dump 的额外 .dex 文件，作为**额外输入**与原 APK 一并反编译。
        jadx 接受多输入（.apk/.dex/...）；加固样本的真实代码全在 dump DEX 里，不喂进来只反编译
        出壳桩。超时按额外 DEX 数量线性伸缩（见 ``_jadx_timeout``）。

        ``resolved`` 非 sentinel 时直接消费该解析结果（含有意义的 None——调用方已经解析过、
        确实没有 jadx，绝不二次解析）：持久索引启用时 analyze 先用它探测 ``--version``，
        再把同一结果传进来——版本身份与实际反编译命令绝不来自两次解析。
        未启用索引时保持既有行为，本方法自行解析。

        进程经 ``proctree.run_owned`` 执行：本 analyzer 自己持有 300-1200s deadline（long lane
        调度器不加 worker 级超时），超时/正常退出后都验证 ``.bat -> java -> 后代`` 整树终止，
        结局落进返回值供 receipt 记录。串行与 long lane 都走本方法，无第二条执行路径。
        """
        # ★ 经 tools.resolve_jadx 解析：优先 PATH 上的 jadx，否则用独立插件包 jadx-addon/
        #   （自带 JRE → 注入 JAVA_HOME，无系统 Java 也能跑）。返回完整路径而非裸名：
        #   Windows 上 jadx 是 .bat，裸名经 subprocess 启动会 WinError 2。
        dex_inputs = list(extra_dex_paths or [])
        timeout = self._jadx_timeout(len(dex_inputs))
        digest = _options_digest(apk_path, dex_inputs, timeout)
        if resolved is _RESOLVED_UNSET:
            effective_resolved = tools.resolve_jadx()
        else:
            effective_resolved = cast(_ResolvedJadx, resolved)
        if effective_resolved is None:
            logger.warning("[jadx] 无可用 jadx（PATH 与插件包 jadx-addon 均无），跳过反编译")
            return _JadxRun(status="failed", options_digest=digest, process=None)
        jadx_cmd, extra_env = effective_resolved
        cmd = [*jadx_cmd, "--no-res"]
        if dex_inputs:
            # dump DEX 常从进程内存抓取，checksum/signature 与磁盘态不一致，jadx 默认
            # verify-checksum=yes 会拒载它们。关掉校验让脱壳 DEX 也能反编译（正规 APK 无副作用）。
            cmd.append("-Pdex-input.verify-checksum=no")
        cmd += ["-d", out_dir, apk_path, *dex_inputs]
        # 插件包自带 JRE 时把 JAVA_HOME 注入子进程环境（在系统环境基础上覆盖）。
        env = _resolved_jadx_env(extra_env)
        logger.info("[jadx] 执行（超时 %ss，额外 DEX %d 个）：%s", timeout, len(dex_inputs), " ".join(cmd))
        owned = proctree.run_owned(cmd, timeout=timeout, env=env)
        if not owned.ownership_complete:
            # fail closed：没拿到进程树所有权（Job assign/spawn 失败）就没放行 jadx，
            # 按 failed 定性；具体原因在 owned.reason_codes 里随 receipt 留痕。
            logger.warning(
                "[jadx] 进程树所有权建立失败（%s），本次未执行反编译",
                ", ".join(owned.reason_codes),
            )
            return _JadxRun(status="failed", options_digest=digest, process=owned)
        if owned.timed_out:
            # 超时不静默：返回 "timeout" 落进 meta.jadx_status，且调用方仍扫已生成的部分产物
            # （jadx_java_files 记录实际反编译出的文件数）。二者合看即可与「真·壳样本」区分——
            # 真壳样本是 status=ok + 个位数文件，超时是 status=timeout + 可能被腰斩的文件数。
            logger.warning(
                "[jadx] 反编译超时（%ss，额外 DEX %d 个），进程树已终止：%s",
                timeout, len(dex_inputs), apk_path,
            )
            return _JadxRun(status="timeout", options_digest=digest, process=owned)
        if owned.returncode != 0:
            # jadx 对部分类反编译失败时返回非零，但通常已产出大部分 .java。
            logger.warning(
                "[jadx] 非零退出（%s），按部分产物继续扫描。stderr 尾部：%s",
                owned.returncode,
                (owned.stderr or "")[-1000:],
            )
            return _JadxRun(status="partial", options_digest=digest, process=owned)
        if owned.forced_tree_kill or not owned.termination_complete:
            # 干净退出但留了后代被强杀 / 树终止未获确认：产物可能被仍在写的 java 腰斩，
            # 按 partial 定性，不许读成「全部成功」。
            logger.warning(
                "[jadx] 退出码 0 但进程树未干净收尾（%s），按 partial 计",
                ", ".join(owned.reason_codes),
            )
            return _JadxRun(status="partial", options_digest=digest, process=owned)
        return _JadxRun(status="ok", options_digest=digest, process=owned)

    @staticmethod
    def _jadx_timeout(n_extra_dex: int) -> float:
        """按额外 DEX 数量伸缩超时：基础 300s，每个 dump DEX +30s，封顶 1200s。

        无额外 DEX → 原基础超时（向后兼容，普通 APK 路径不变）。加固样本脱壳后常有 30+ 个
        dump DEX，固定 300s 必被撞穿；线性伸缩给大 dump 跑完的机会，封顶防无限拖住批处理。
        """
        if n_extra_dex <= 0:
            return _TIMEOUT
        return min(_TIMEOUT + _TIMEOUT_PER_EXTRA_DEX * n_extra_dex, _TIMEOUT_MAX)

    def _scan_java(self, root: Path) -> _ScanOutcome:
        """扫 root 下所有 .java，从字符串字面量抽端点、从键值抽密钥、产 config-chain 层② 共现链。

        ``decrypt_candidates`` 是机器可读的「待 AI 解密」清单（疑似加密配置串 + 疑似解密 helper +
        位置），供下游 AI/appcrypto 拾取尝试解密；``suppressed`` 是被 string_graph 降噪规则压制的
        候选数（按原因分组），只计数、不进 Finding；``truncated`` 表示 .java 文件数撞了
        ``_MAX_JAVA_FILES`` 上限、扫描被截断（落 meta 供报告区分「恰好 N 个」与「截断于 N 个」）。

        ★确定性截断：先**全量收集**规范化（NFC）相对路径、确定性排序，再取前 ``_MAX_JAVA_FILES``
        个。此前直接按 ``rglob`` 的文件系统枚举顺序取前 N 个——命中上限时被扫到的子集随枚举顺序
        漂移，同一产物树两次扫描可能覆盖不同文件。排序键取（casefold, 原串）二元组：同一棵树内
        完全确定，且 NTFS 线程竞争造成的目录大小写翻转（v/V）不改变选中集合。

        覆盖统计（receipt 的 scan 块）：total/selected/scanned/read_failed/truncated_files、
        bytes_total/bytes_scanned、scan_limit_hit、selected_paths_digest（选中集合的顺序敏感
        sha256，证明两次枚举选了同一子集而不必把最多 5000 条路径塞进报告）。
        """
        collector: dict[str, Endpoint] = {}
        secret_hits: dict[tuple[str, str], Finding] = {}
        chain_objs: dict[tuple[str, str], StringChain] = {}  # config-chain 层②：按 (文件, 密文) 去重（嵌套不重复）
        suppressed: Counter[str] = Counter()  # 压制原因 → 条数（同样按 (文件, 密文) 去重后计）

        candidates: list[tuple[Path, str]] = []  # (磁盘路径, NFC 规范化相对路径)
        discovery_failed = False
        try:
            for java in root.rglob("*.java"):
                rel_nfc = unicodedata.normalize("NFC", java.relative_to(root).as_posix())
                candidates.append((java, rel_nfc))
        except OSError:
            # 枚举中途失败 → 已收集的只是不完整子集，必须留痕并使 receipt 不 complete，
            # 不许把「枚举断在半路」静默当成「就这么多文件」。
            logger.exception("[jadx] 枚举 .java 产物树失败，覆盖不完整：%s", root)
            discovery_failed = True
        candidates.sort(key=lambda item: (item[1].casefold(), item[1]))

        files_total = len(candidates)
        scan_limit_hit = files_total > _MAX_JAVA_FILES
        if scan_limit_hit:
            logger.warning(
                "[jadx] .java 文件数 %d 超过上限 %d，确定性排序后截断扫描",
                files_total, _MAX_JAVA_FILES,
            )
        selected = candidates[:_MAX_JAVA_FILES]
        # NUL 分隔：路径里不可能出现 \0（任何文件系统），拼接无歧义；\n 在 POSIX 文件名里合法。
        paths_digest = hashlib.sha256(
            "\0".join(rel.lower() for _, rel in selected).encode("utf-8")
        ).hexdigest()

        n_files = 0
        files_scanned = 0
        read_failed = 0
        truncated_files = 0
        bytes_total = 0
        bytes_scanned = 0
        scan_exceptions = 0  # 单文件扫描内部异常数：吞掉不炸，但必须留痕挡 complete
        for java, rel_nfc in selected:
            try:
                data = java.read_bytes()
            except Exception:
                logger.exception("[jadx] 读取 .java 失败，跳过：%s", java)
                read_failed += 1
                continue
            files_scanned += 1
            bytes_total += len(data)
            if len(data) > _MAX_FILE_BYTES:
                truncated_files += 1
                data = data[:_MAX_FILE_BYTES]
            bytes_scanned += len(data)
            if not data:
                continue
            n_files += 1
            text = data.decode("utf-8", errors="ignore")
            # ★确定性：规范化相对路径为「正斜杠 + 全小写」再作 evidence.location。jadx 多线程反编译混淆
            # APK 时，仅大小写不同的包/类名（v/V）在 NTFS 大小写不敏感盘上的落地大小写由线程竞争决定，
            # 同一样本两次运行可产 sources\v\... 或 sources\V\...；location 直接吃磁盘大小写会让 evidence_id
            # 跨运行漂移（破坏 core/integrity.evidence_id 的「稳定坐标」承诺 + 串行==并行逐字节一致不变式）。
            # as_posix().lower() 使 location 跨运行、跨 OS 确定。代价：Linux 上仅大小写不同的孪生混淆类会
            # 并到同一 location（去重合并一条）——但二者是同端点/同凭据值的孪生，且 Windows 本就已坍缩，取证无损。
            rel = rel_nfc.lower()
            try:
                self._scan_text(text, rel, collector, secret_hits)
            except Exception:
                scan_exceptions += 1
                logger.exception("[jadx] 扫描 .java 失败，跳过：%s", rel)
            # config-chain 层②：方法作用域内 密文→解密/消费(→sink) 共现链（启发式、独立 try 不连累端点/密钥扫描）。
            try:
                for chain in scan_java_source(text, rel):
                    key = (chain.location, chain.secret[:64])
                    chain_objs.setdefault(key, chain)
            except Exception:
                scan_exceptions += 1
                logger.exception("[jadx] string_graph 扫描失败，跳过：%s", rel)
        # 压制链（第三方库路径 / 密码学参数表）只计数、不进 Finding 与待解密清单：它们是降噪规则的产物，
        # 但规则的 key 落在样本可控输入上，所以条数要留痕——压制量突然变大本身就是值得复核的信号。
        chains = []
        for chain in chain_objs.values():
            if chain.suppressed:
                suppressed[chain.suppressed] += 1
            else:
                chains.append(chain)
        findings = list(secret_hits.values()) + [_chain_finding(c) for c in chains]
        decrypt = [_chain_candidate(c) for c in chains]
        return _ScanOutcome(
            endpoints=list(collector.values()),
            findings=findings,
            n_files=n_files,
            decrypt_candidates=decrypt,
            suppressed=dict(suppressed),
            truncated=scan_limit_hit,
            receipt={
                "files_total": files_total,
                "files_selected": len(selected),
                "files_scanned": files_scanned,
                "read_failed": read_failed,
                "truncated_files": truncated_files,
                "bytes_total": bytes_total,
                "bytes_scanned": bytes_scanned,
                "scan_exceptions": scan_exceptions,
                "scan_limit_hit": scan_limit_hit,
                "discovery_failed": discovery_failed,
                "selected_paths_digest": f"sha256:{paths_digest}",
            },
        )

    def _scan_text(
        self,
        text: str,
        location: str,
        collector: dict[str, Endpoint],
        secret_hits: dict[tuple[str, str], Finding],
    ) -> None:
        # 1) 端点：只在字符串字面量内抽。
        for m in _STR_LIT_RE.finditer(text):
            lit = m.group(1)
            if not lit or len(lit) > 4096:
                continue
            self._scan_literal(lit, location, collector)
        # 2) 硬编码密钥（键值上下文，全文）。
        for m in _SECRET_KV_RE.finditer(text):
            self._consider_secret(m.group("key"), m.group("val"), location, secret_hits)

    def _scan_literal(
        self, lit: str, location: str, collector: dict[str, Endpoint]
    ) -> None:
        for m in _URL_RE.finditer(lit):
            url = _strip_tail(m.group())
            host = _host_from_url(url)
            if not url or not host:
                continue
            # B：XML 命名空间 / schema 声明（http://ns.adobe.com/xap/、xmlpull.org/v1/… 等）
            #   是反编译代码里的命名空间标识符、非网络端点，整条丢弃（含其 url 与 host）。
            if infra.is_xml_namespace_url(url):
                continue
            _add(collector, url, "url", location,
                 is_cleartext=url.lower().startswith("http://"))
            ip = _parse_ipv4(host)
            if ip is not None:
                # ★IP 同样标来源档：jadx 反编译源里的这次出现若在 app 包路径下标 app 档，
                #   pipeline 的 best_tier 合并才能把同值在 vendor bundle 里的降档救回来；
                #   反之在已知库包路径（*/com/squareup/* 等）下则降档。此前只有域名分支标。
                _add(collector, host, "ip", location, is_private=_ip_private(ip),
                     tier=infra.domain_source_tier(location, len(lit)))
            elif _safe_domain(host):
                _add(collector, host, "domain", location,
                     tier=infra.domain_source_tier(location, len(lit)))
        for m in _IPV4_RE.finditer(lit):
            ip_str = m.group(1)
            ip = _parse_ipv4(ip_str)
            if ip is None:
                continue
            # C4：裸 IP 去噪，与 endpoints/js_bundle 共享判定（bogon/保留段 +
            #   占位/版本号 denylist），消除三处不一致。URL 内 IP 走上面 host 通道不受限。
            if ip_str in self._noise_ips or _is_noise_bare_ip(ip_str):
                continue
            # 同上：裸 IP 也标来源档。
            _add(collector, ip_str, "ip", location, is_private=_ip_private(ip),
                 tier=infra.domain_source_tier(location, len(lit)))
        for m in _DOMAIN_RE.finditer(lit):
            dom = m.group(1).rstrip(".").lower()
            if _safe_domain(dom):
                _add(collector, dom, "domain", location,
                     tier=infra.domain_source_tier(location, len(lit)))

    def _consider_secret(
        self, key: str, val: str, location: str, hits: dict[tuple[str, str], Finding]
    ) -> None:
        low = key.lower()
        if low in _SECRET_DENY or not any(h in low for h in _SECRET_HINTS):
            return
        v = val.strip()
        if v.lower() in _PLACEHOLDER or len(set(v)) <= 2 or " " in v:
            return
        if v.startswith(("/", "http://", "https://", "./", "../")) or any(c in v for c in "{}$<>"):
            return
        # C2 三道闸（杀 SDK 常量名误报）：
        #  ① value==key / 已知 SDK 常量名/值 → drop（MIPUSH_APPKEY=MIPUSH_APPKEY、
        #     KEY_DEVICE_TOKEN=deviceToken、METHOD_CHECK_APPKEY=dc_checkappkey）。
        if is_sdk_constant(key, v, self._secret_rules):
            return
        #  ② value 不像凭据形态（无数字/非 hex/无 base64 字符）→ drop（deviceToken 类）。
        #     真凭据（Abc123Xyz789Def456 等）全 looks_keyish=True，不误杀。
        if not looks_like_secret_value(v, self._secret_rules):
            return
        dedup = (location, f"{low}:{v[:48]}")
        if dedup in hits:
            return
        hits[dedup] = Finding(
            id=_FINDING_SECRET,
            title="jadx 反编译发现硬编码密钥 / 凭证",
            severity=Severity.HIGH,
            category="secret",
            description=(
                f"jadx 反编译的 Java 中出现硬编码凭证：键 '{key}' 配置了明文常量。"
                "可被逆向直接读取并冒用访问后端 / 第三方服务。"
            ),
            recommendation="核实该凭证对应服务，向厂商调取调用记录与绑定主体；提示吊销。",
            evidences=[Evidence(source="jadx", location=location, snippet=_short(f"{key}={v}"))],
            references=["CWE-798"],
        )


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------


def _options_digest(apk_path: str, dex_inputs: list[str], timeout: float) -> str:
    """本次 jadx 执行的**语义参数**摘要（canonical JSON 的 sha256）。

    覆盖：jadx 语义 flags（含 checksum 校验开关）、APK 与额外 DEX 的逻辑身份
    （basename + 字节数，有序）、生效超时与扫描上限。**不含**解析出的 jadx 安装路径、
    输出目录、临时路径等环境量——同输入同参数跨机器/跨运行摘要一致。
    坏 checksum DEX 降级重跑时输入集缩小 → 摘要必然不同，两次执行策略在 receipt 里可辨。
    """
    def _identity(path: str) -> dict:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = -1
        return {"name": os.path.basename(path), "size": size}

    payload = {
        "jadx_args": ["--no-res"] + (["-Pdex-input.verify-checksum=no"] if dex_inputs else []),
        "apk": _identity(apk_path),
        "extra_dex": [_identity(p) for p in dex_inputs],
        "timeout": timeout,
        "max_java_files": _MAX_JAVA_FILES,
        "max_file_bytes": _MAX_FILE_BYTES,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _run_receipt(run: _JadxRun) -> dict:
    """把一次 :class:`_JadxRun` 压成 receipt 的 run 条目（确定性字段，不含 PID/耗时/路径）。"""
    p = run.process
    if p is None:  # 未启动（无可用 jadx）
        return {
            "status": run.status,
            "options_digest": run.options_digest,
            "timed_out": False,
            "ownership_complete": False,
            "termination_complete": True,
            "forced_tree_kill": False,
            "returncode": None,
            "reason_codes": ["jadx_unavailable"],
        }
    return {
        "status": run.status,
        "options_digest": run.options_digest,
        "timed_out": bool(p.timed_out),
        "ownership_complete": bool(p.ownership_complete),
        "termination_complete": bool(p.termination_complete),
        "forced_tree_kill": bool(p.forced_tree_kill),
        "returncode": p.returncode,
        "reason_codes": sorted(p.reason_codes),
    }


def _build_jadx_receipt(
    *, status: str, runs: list[dict], scan: dict | None, cleanup: dict,
    analyzer_error: bool, index: dict | None = None,
) -> dict:
    """组装 ``meta['jadx_receipt']``。``complete=True`` 是 Java 面「完整覆盖」的唯一凭据，
    要求全部成立：进程 ok 且**恰有一次**非降级执行、执行的进程树状态全程受验（含中间态）、
    枚举成功、未撞扫描上限、读失败 0、单文件截断 0、单文件扫描异常 0、清理完成、analyzer
    未抛异常。任一不成立即 ``complete=False`` 并在 ``reason_codes`` 留下稳定原因
    （阳性发现不受影响，只挡穷尽性）。builder 自身独立强制这些条件，不依赖调用方只在
    正确形态下调用（fail closed）。

    ``index`` 子块承载持久索引旁路的结局：只含稳定 status/reason code/计数/attachment/key，
    不含 field_path、异常字符串或文件系统路径。索引是旁路——其 disabled/failed/unavailable
    不进顶层 reason_codes、不挡 Java 面 ``complete``。
    """
    reasons: set[str] = set()
    if analyzer_error:
        reasons.add("analyzer_exception")
    if status == "timeout":
        reasons.add("producer_timeout")
    elif status == "failed":
        reasons.add("producer_failed")
    elif status == "partial":
        reasons.add("producer_partial")
    if not runs:
        # 没有任何执行记录却声称 ok 是自相矛盾：builder 独立兜住，不指望调用方形态正确。
        reasons.add("no_runs")
    for run in runs:
        if run.get("degraded_rerun"):
            reasons.add("degraded_rerun")
        if not run.get("ownership_complete"):
            reasons.add("ownership_incomplete")
        if not run.get("termination_complete"):
            reasons.add("termination_unverified")
        if run.get("forced_tree_kill"):
            reasons.add("descendants_after_root_exit")
        if "tree_state_unverified" in (run.get("reason_codes") or ()):
            # 根退出后的即时树状态查询失败过：最终 quiesce 即便成功，中间窗口无从复核，
            # 按覆盖不完整计（fail closed）。
            reasons.add("tree_state_unverified")
    if scan is None:
        reasons.add("scan_missing")
    else:
        if scan.get("scan_limit_hit"):
            reasons.add("scan_limit_hit")
        if int(scan.get("read_failed") or 0) > 0:
            reasons.add("read_failed")
        if int(scan.get("truncated_files") or 0) > 0:
            reasons.add("source_file_truncated")
        if int(scan.get("scan_exceptions") or 0) > 0:
            # 单文件扫描内部异常被吞掉继续（不炸整跑），但该文件的端点/密钥可能漏掉，
            # 穷尽性主张无资格。
            reasons.add("scan_exception")
        if scan.get("discovery_failed"):
            reasons.add("discovery_failed")
    if not cleanup.get("complete"):
        reasons.add("cleanup_incomplete")
    complete = status == "ok" and not reasons
    receipt: dict = {
        "schema": 1,
        "status": status,
        "options_digest": str(runs[-1]["options_digest"]) if runs else "",
        "runs": runs,
        "cleanup": cleanup,
        "complete": complete,
        "reason_codes": sorted(reasons),
        "index": (
            dict(index)
            if index is not None
            else _index_receipt(
                status="disabled",
                reason_codes=[_INDEX_REASON_CACHE_NOT_CONFIGURED],
            )
        ),
    }
    # 即使调用方传入未收敛列表，builder 仍自行收敛成确定形态（fail closed 同款纪律）。
    index_reasons = receipt["index"].get("reason_codes")
    receipt["index"]["reason_codes"] = sorted(
        {
            item
            for item in (index_reasons if isinstance(index_reasons, list) else [])
            if isinstance(item, str) and item
        }
    )
    # baseline 块（P2-C）独立收敛：只允许 compared，或 unavailable + 合法稳定 reason；
    # 非法/异常形态折叠——异常文本与路径绝不进 receipt。
    raw_baseline = receipt["index"].get("baseline")
    if raw_baseline is not None:
        if not isinstance(raw_baseline, dict):
            receipt["index"]["baseline"] = {
                "status": "unavailable",
                "reason": _INDEX_REASON_INVALID_CACHE_STATE,
            }
        elif raw_baseline.get("status") == "compared":
            receipt["index"]["baseline"] = {"status": "compared"}
        else:
            receipt["index"]["baseline"] = {
                "status": "unavailable",
                "reason": _stable_index_reason(
                    raw_baseline.get("reason"), _INDEX_REASON_INVALID_CACHE_STATE
                ),
            }
    if scan is not None:
        receipt["scan"] = scan
    return receipt


def _make_tree_writable(path: str) -> None:
    """尽力把整棵树改成可写（Windows 只读位会让 rmtree 失败）；单点失败继续。"""
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            try:
                os.chmod(os.path.join(dirpath, name), stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                continue


def _remove_tree_checked(path: str) -> dict:
    """受检删除临时目录：重试 + 只读位清理 + **存在性复核**。返回 cleanup receipt 块。

    此前是 ``shutil.rmtree(ignore_errors=True)``——Windows 上残余进程占着句柄时删除静默失败，
    临时目录无痕堆积且报告完全不知道。现在：删完以「目录已不存在」为准；仍在则重试（短退避，
    给句柄释放留时间）；最终失败如实进 receipt（``complete=False``），路径只进日志不进 receipt。
    """
    for attempt in range(_CLEANUP_ATTEMPTS):
        try:
            shutil.rmtree(path)
        except OSError:
            pass  # 以下方存在性复核为准
        if not os.path.lexists(path):
            return {"complete": True, "reason_codes": []}
        _make_tree_writable(path)
        time.sleep(_CLEANUP_BACKOFF * (attempt + 1))
    if not os.path.lexists(path):
        return {"complete": True, "reason_codes": []}
    logger.warning("[jadx] 临时目录清理失败（%d 次重试后仍存在）：%s", _CLEANUP_ATTEMPTS, path)
    return {"complete": False, "reason_codes": ["temp_tree_still_exists"]}


# 噪音 IP 兜底（C4：与 endpoints/js_bundle 同口径）。
_FALLBACK_NOISE_IPS: tuple[str, ...] = (
    "1.2.3.4", "0.0.0.0", "13.3.3.7", "2.1.5.1", "3.2.16.7",
)


def _load_noise_ips() -> frozenset[str]:
    """从 endpoints.yaml 读 noise_ips（C4 单一数据源；缺失走内置兜底）。"""
    try:
        from apkscan.core.registry import load_rules
        from apkscan.core.textutil import as_str_list

        data = load_rules("endpoints")
    except Exception:  # noqa: BLE001 — 规则读取失败不应炸掉 analyze
        logger.exception("[jadx] 读取 endpoints 规则（noise_ips）失败，用兜底")
        return frozenset(_FALLBACK_NOISE_IPS)
    if isinstance(data, dict):
        nips = as_str_list(data.get("noise_ips"))
        if nips:
            return frozenset(ip.strip() for ip in nips)
    return frozenset(_FALLBACK_NOISE_IPS)


def _add(
    collector: dict[str, Endpoint],
    value: str,
    kind: str,
    location: str,
    *,
    is_cleartext: bool = False,
    is_private: bool = False,
    tier: str | None = None,
) -> None:
    ep = collector.get(value)
    if ep is None:
        ep = Endpoint(
            value=value,
            kind=kind,
            evidences=[Evidence(source="jadx", location=location, snippet=_short(value))],
            is_cleartext=is_cleartext,
            is_private=is_private,
        )
        if tier is not None:
            ep.enrichment["tier"] = tier
        collector[value] = ep
        return
    ep.is_cleartext = ep.is_cleartext or is_cleartext
    ep.is_private = ep.is_private or is_private
    if tier is not None:
        # 来源可信度档（C1，域名与 IP 通用）：多来源取最可信档（app 优先）。
        current = ep.enrichment.get("tier")
        ep.enrichment["tier"] = infra.best_tier(current, tier) if current else tier
    if all(ev.location != location for ev in ep.evidences):
        ep.evidences.append(Evidence(source="jadx", location=location, snippet=_short(value)))


def _safe_domain(domain: str) -> bool:
    labels = domain.lower().split(".")
    if len(labels) < 2 or labels[-1] not in _SAFE_BARE_TLDS:
        return False
    sld = labels[-2]
    if len(sld) < 2 or sld in _CODE_WORDS or labels[0] in _PACKAGE_ROOTS:
        return False
    return True


def _parse_ipv4(s: str) -> ipaddress.IPv4Address | None:
    parts = s.split(".")
    if len(parts) != 4 or any((not p.isdigit() or len(p) > 3 or int(p) > 255) for p in parts):
        return None
    try:
        return ipaddress.IPv4Address(s)
    except ValueError:
        return None


def _ip_private(ip: ipaddress.IPv4Address) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved or ip.is_multicast)


def _host_from_url(url: str) -> str:
    try:
        after = url.split("://", 1)[1]
    except IndexError:
        return ""
    for sep in ("/", "?", "#"):
        idx = after.find(sep)
        if idx != -1:
            after = after[:idx]
    if "@" in after:
        after = after.rsplit("@", 1)[1]
    if ":" in after:
        after = after.split(":", 1)[0]
    return after.strip().rstrip(".").lower()


def _strip_tail(url: str) -> str:
    url = url.strip()
    while url and url[-1] in ".,;:'\")]}>":
        url = url[:-1]
    return url


def _chain_finding(chain: StringChain) -> Finding:
    """把方法内共现链转成一条 Finding（config-chain 层②）。★启发式共现、非数据流证明 → LOW + inference。

    两档：识别到**标准解密 API** → "密文→解密 共现链"；仅**被某函数消费**（疑似改名的解密 helper）→
    "疑似加密配置串（AI 辅助解密线索）"。两档都在 evidence.snippet 里带**完整密文**，供下游 AI/appcrypto 试解密。
    """
    sink_part = f"；下游 sink：{', '.join(chain.sinks)}" if chain.sinks else ""
    if chain.decrypt_calls:
        title = "jadx 反编译发现 密文→解密 方法内共现链（疑似运行时解密配置/后端地址）"
        description = (
            f"方法 {chain.method} 内共现硬编码密文候选串与解密调用（{', '.join(chain.decrypt_calls)}）{sink_part}。"
            "疑似运行时解密出配置 / 后端地址。★方法作用域内的**启发式共现**（非数据流证明），须人工复核。"
        )
        recommendation = (
            "AI 辅助解密：结合本 app crypto 证据（crypto_recipe / 硬编码 key）对证据里的完整密文尝试解密，"
            "看是否解出 URL / 域名 / 配置；解出则纳入 config-chain 归因。"
        )
    else:
        title = "jadx 反编译发现 疑似加密配置串（AI 辅助解密线索）"
        description = (
            f"方法 {chain.method} 内硬编码密文候选串被直接传入 {chain.consumer}()（疑似**改名的解密函数**——重度"
            f"混淆下认不出标准 crypto API，但『密文被传进某函数』是确定事实）{sink_part}。★方法级启发式（非证明）。"
        )
        recommendation = (
            f"AI 辅助解密：证据里是完整密文，{chain.consumer}() 疑似解密 helper；结合本 app crypto 证据尝试解密，"
            "看是否解出 URL / 域名 / 配置（如远程配置 OSS 地址）；解不出则判需动态/native 恢复。见 meta.decrypt_candidates。"
        )
    return Finding(
        id=_FINDING_STRING_CHAIN,
        title=title,
        severity=Severity.MEDIUM,
        category="config-chain",
        description=description,
        recommendation=recommendation,
        # ★带完整密文（不截断）：这是 AI/appcrypto 试解密的 actionable 载荷。
        evidences=[Evidence(source="jadx", location=chain.location, snippet=chain.secret)],
        references=["CWE-798"],
        confidence=Confidence.LOW,
        kind=FINDING_KIND_INFERENCE,
    )


def _chain_candidate(chain: StringChain) -> dict:
    """把共现链转成机器可读的「待 AI 解密」候选（供 meta.decrypt_candidates 供下游 AI/appcrypto 拾取）。"""
    return {
        "ciphertext": chain.secret,  # 完整密文
        "consumer": chain.consumer,  # 疑似解密 helper（改名）；None=识别到标准解密 API
        "method": chain.method,
        "location": chain.location,
        "standard_decrypt": list(chain.decrypt_calls),
        "sinks": list(chain.sinks),
    }


def _short(text: str, limit: int = _SNIPPET_MAX) -> str:
    return text if len(text) <= limit else text[:limit] + "…"
