"""Explainable, deterministic linkage candidates from corpus manifest rows.

The score produced here is a review priority, not a probability and never a
claim that two samples have the same operator.  Only positive observations
contribute; missing evidence is reported as a coverage gap rather than used as
negative evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import combinations
import ipaddress
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from apkscan.core.corpus import native_anchor_policy_snapshot, native_anchor_weakness


POLICY_ID = "fxapk-linkage-rules-v2"
MODEL_ID = POLICY_ID  # Backward-compatible public alias.
RESULT_SCHEMA_VERSION = "1.4"
SCHEMA_VERSION = RESULT_SCHEMA_VERSION  # Backward-compatible public alias.
FEATURE_SCHEMA_VERSION = "1.3"
NORMALIZATION_VERSION = "1.2"

_HEX = frozenset("0123456789abcdef")
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_FEATURE_FIELDS = (
    "sign_sha256",
    "native_lib_hashes",
    "remote_config_objects",
    "build_environments",
    "key_iocs",
    "visibility",
)
_FAMILY_ORDER = {"remote_config": 0, "native": 1, "signing": 2, "build": 3, "ioc": 4}
#: ★单个锚允许展开成两两候选的最大共享样本数：一个锚被 k 个样本共享要物化 C(k,2) 对
#: （k=200 → 19,900 对；k=1000 → 约 50 万对），而「几百个样本共享同一个值」的锚本身
#: 对「哪两个样本该优先并案」几乎没有区分力。超限的锚不展开，但按 weak-anchor 的
#: 「标注而非删除」哲学显式登记进输出的 ``truncated_anchors``，绝不静默丢弃。
_MAX_ANCHOR_CLUSTER_SAMPLES = 50
#: 全局候选对物化上限。单锚上限只能约束一个桶，许多中等大小桶仍可累积出无界 pair set。
#: 达到上限后停止继续展开并标记 partial；诊断只输出预算计数，不回显触发锚值。
_MAX_CANDIDATE_PAIRS = 250_000
#: 同一 native 内容须在至少三个不同真实样本与三个不同 basename 之间存在一对一匹配，
#: 才是组件被改名分发的形态指纹。单样本多 revision 的别名不计，synthetic 身份也不计。
#: 这不是“被多少样本共享”的频次阈值：同族自研库可以高频共享，但同一份字节持续换名时，
#: 文件名已不足以支持其主体归属。共享事实仍进入 ``excluded_evidence``，不会被删除。
_RENAMED_COMPONENT_MIN_BASENAMES = 3
#: repack_identity 分析器对「公知调试/测试证书」产的 finding id（已随 manifest 的
#: ``finding_ids`` 字段入库）。AOSP test-key 之类调试证书全球逐字节相同，共享它只说明
#: 「都用了公开调试签名」——与 dynamic/correlate 拒用 debug 证书归一匹配的口径一致。
_DEBUG_CERT_FINDING = "debug-certificate"
#: RFC 3986 的 scheme 词法：能匹配说明「URL 语法成立、只是本基线不支持该协议」。
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.\-]*\Z")
_REAL_SAMPLE_RE = re.compile(r"[0-9a-f]{64}\Z")
_SYNTHETIC_SAMPLE_RE = re.compile(r"nosha-[0-9a-f]{16}\Z")

_REMOTE_CONFIG_CONTENT_WEIGHT = 60
_REMOTE_CONFIG_URL_WEIGHT = 40
_NATIVE_BASE_WEIGHT = 50
_NATIVE_STEP_WEIGHT = 2
_NATIVE_MAX_WEIGHT = 56
_SIGNING_WEIGHT = 45
_BUILD_BASE_WEIGHT = 30
_BUILD_STEP_WEIGHT = 5
_BUILD_MAX_WEIGHT = 35
_IOC_WEIGHTS = {"url": 12, "domain": 8, "public_ip": 5, "other": 4}
_IOC_MAX_WEIGHT = 20
_NO_STRONG_SINGLE_CAP = 39
_NO_STRONG_MULTI_CAP = 59
_SINGLE_STRONG_CAP = 69
_SINGLE_STRONG_CORROBORATED_CAP = 89
# ★广域共享锚降档（复核优先级层，不是证据准入层）：同一 native/build 锚在语料里被
#   ≥N 个互不相关的样本群共享、且横跨 ≥N 个案件时，只靠这类锚支撑的候选对降入低优先档。
#   「互不相关」是结构性判定（簇内两两既不共享非调试签名证书、也不共享远程配置对象），
#   不是共享频次阈值——与 native_anchor_weakness 的「绝不用统计阈值」如何区分，
#   见 _broad_shared_anchors 的 docstring。
_BROAD_ANCHOR_MIN_UNRELATED_GROUPS = 4
_BROAD_ANCHOR_MIN_CASE_SPAN = 4
_BROAD_SHARED_ANCHOR_CAP = 49
_INVALID_FEATURE_CAP = 79
_SYNTHETIC_IDENTITY_CAP = 79
_OWNERSHIP_UNRESOLVED_CAP = 69
_NON_AUTHORITATIVE_INPUT_CAP = 69

_REPACK_SUSPECTED = "repack_suspected"
_REPACK_IDENTITY_VERDICTS = frozenset(
    {"self_built", _REPACK_SUSPECTED, "unknown"}
)
_RECORD_ACTIVE = "active"
_RECORD_QUARANTINED = "quarantined"
_RECORD_UNKNOWN = "unknown"
_COVERAGE_GAP_STATES = frozenset(
    {"unknown", "observed_with_invalid_siblings", "invalid_only"}
)
_PROVENANCE_FIELDS = (
    "tool_version",
    "ruleset_digest",
    "evidence_surface",
    "record_state",
    "report_bytes_sha256",
)

_POLICY_DESCRIPTOR = {
    "id": POLICY_ID,
    "candidate_generation": {
        "anchor_cluster_limit": _MAX_ANCHOR_CLUSTER_SAMPLES,
        "candidate_pair_budget": _MAX_CANDIDATE_PAIRS,
        "renamed_component_min_basenames": _RENAMED_COMPONENT_MIN_BASENAMES,
        "renamed_component_requires_distinct_real_sample_matching": True,
    },
    "weights": {
        "remote_config_content": _REMOTE_CONFIG_CONTENT_WEIGHT,
        "remote_config_url": _REMOTE_CONFIG_URL_WEIGHT,
        "native_base": _NATIVE_BASE_WEIGHT,
        "native_step": _NATIVE_STEP_WEIGHT,
        "native_max": _NATIVE_MAX_WEIGHT,
        "signing": _SIGNING_WEIGHT,
        "build_base": _BUILD_BASE_WEIGHT,
        "build_step": _BUILD_STEP_WEIGHT,
        "build_max": _BUILD_MAX_WEIGHT,
        "ioc": _IOC_WEIGHTS,
        "ioc_max": _IOC_MAX_WEIGHT,
    },
    "caps": {
        "no_strong_single": _NO_STRONG_SINGLE_CAP,
        "no_strong_multi": _NO_STRONG_MULTI_CAP,
        "single_strong": _SINGLE_STRONG_CAP,
        "single_strong_corroborated": _SINGLE_STRONG_CORROBORATED_CAP,
        "broad_shared_anchor_only": _BROAD_SHARED_ANCHOR_CAP,
        "invalid_feature": _INVALID_FEATURE_CAP,
        "synthetic_identity": _SYNTHETIC_IDENTITY_CAP,
        "repack_suspected": _OWNERSHIP_UNRESOLVED_CAP,
        "non_authoritative_input": _NON_AUTHORITATIVE_INPUT_CAP,
    },
    "broad_anchor_demotion": {
        "min_unrelated_groups": _BROAD_ANCHOR_MIN_UNRELATED_GROUPS,
        "min_case_span": _BROAD_ANCHOR_MIN_CASE_SPAN,
        "relatedness_anchor_families": ("signing", "remote_config"),
        "demotable_anchor_families": ("native", "build"),
    },
    "contracts": {
        "coverage_states": (
            "unknown",
            "assessed_empty",
            "observed",
            "observed_with_invalid_siblings",
            "invalid_only",
        ),
        "provenance_fields": _PROVENANCE_FIELDS,
        "non_authoritative_record_state": _RECORD_QUARANTINED,
        "repack_identity_field": "repack_identity_verdict",
    },
}
def _current_policy_metadata() -> tuple[str, str]:
    native_policy = native_anchor_policy_snapshot()
    descriptor = {**_POLICY_DESCRIPTOR, "native_anchor_weakness": native_policy}
    digest = hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    status = native_policy.get("status")
    normalized_status = (
        status
        if isinstance(status, str) and status in {"complete", "partial"}
        else "partial"
    )
    return digest, normalized_status


POLICY_DIGEST, POLICY_STATUS = _current_policy_metadata()


@dataclass(frozen=True, slots=True)
class RevisionProvenance:
    """Bounded coordinates for one immutable report revision."""

    tool_version: str | None
    ruleset_digest: str | None
    evidence_surface: str | None
    record_state: str
    report_bytes_sha256: str | None

    def summary(self) -> dict[str, str | None]:
        return {
            "tool_version": self.tool_version,
            "ruleset_digest": self.ruleset_digest,
            "evidence_surface": self.evidence_surface,
            "record_state": self.record_state,
            "report_bytes_sha256": self.report_bytes_sha256,
        }


@dataclass(frozen=True, slots=True)
class SampleFeatures:
    """Collapsed positive observations for one sample across corpus revisions."""

    sample_sha256: str
    synthetic_identity: bool
    case_ids: tuple[str, ...]
    revisions: tuple[RevisionProvenance, ...]
    evidence_surfaces: tuple[str, ...]
    ownership_unresolved: bool
    non_authoritative_input: bool
    #: 强签名锚（已剔除公知调试/测试证书）；被 debug-certificate finding 标记的进 weak_sign。
    sign_sha256: tuple[str, ...]
    #: 公知调试/测试证书指纹：全球逐字节相同，零分排除但仍展示（标注而非删除）。
    weak_sign: tuple[str, ...]
    native_sha256: tuple[str, ...]
    weak_native: tuple[tuple[str, str], ...]
    config_sha256: tuple[str, ...]
    config_urls: tuple[str, ...]
    build_environments: tuple[str, ...]
    key_iocs: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, str], ...]
    invalid_fields: tuple[str, ...]
    anchor_provenance: tuple[
        tuple[str, str, str, tuple[RevisionProvenance, ...]], ...
    ]

    def coverage_dict(self) -> dict[str, str]:
        return dict(self.coverage)

    def provenance_for(
        self, family: str, kind: str, value: str
    ) -> tuple[RevisionProvenance, ...]:
        for item_family, item_kind, item_value, revisions in self.anchor_provenance:
            if (item_family, item_kind, item_value) == (family, kind, value):
                return revisions
        return ()

    def summary(self) -> dict[str, Any]:
        return {
            "sample_sha256": self.sample_sha256,
            "synthetic_identity": self.synthetic_identity,
            "case_ids": list(self.case_ids),
            "revision_count": len(self.revisions),
            "revisions": [revision.summary() for revision in self.revisions],
            "evidence_surfaces": list(self.evidence_surfaces),
            "ownership_unresolved": self.ownership_unresolved,
            "non_authoritative_input": self.non_authoritative_input,
            "coverage": self.coverage_dict(),
        }


@dataclass(frozen=True, slots=True)
class LinkagePreprocessingContext:
    """Corpus-level preprocessing decisions that can be frozen across splits."""

    normalization_version: str
    renamed_native_sha256: frozenset[str]

    def __post_init__(self) -> None:
        if self.normalization_version != NORMALIZATION_VERSION:
            raise ValueError("preprocessing context normalization version is incompatible")
        if not isinstance(self.renamed_native_sha256, frozenset) or any(
            not isinstance(value, str) or _REAL_SAMPLE_RE.fullmatch(value) is None
            for value in self.renamed_native_sha256
        ):
            raise ValueError("preprocessing context contains an invalid native digest")


def _clean_text(value: object, *, max_length: int = 2048) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > max_length or any(ord(char) < 32 for char in text):
        return None
    return text


def _sha256(value: object) -> str | None:
    text = _clean_text(value, max_length=64)
    if text is None:
        return None
    lowered = text.lower()
    if len(lowered) != 64 or any(char not in _HEX for char in lowered):
        return None
    return lowered


def _entry_sample_identity(entry: object) -> str | None:
    """Return a validated real or explicitly synthetic sample identity."""
    if not isinstance(entry, dict):
        return None
    text = _clean_text(entry.get("sample_sha256"), max_length=64)
    if text is None:
        return None
    identity = text.lower()
    synthetic = entry.get("sample_sha256_synthetic") is True
    if synthetic:
        return identity if _SYNTHETIC_SAMPLE_RE.fullmatch(identity) else None
    return identity if _REAL_SAMPLE_RE.fullmatch(identity) else None


def _candidate_id(left_sample: str, right_sample: str) -> str:
    left, right = sorted((left_sample, right_sample))
    digest = hashlib.sha256(f"{left}\0{right}".encode("ascii")).hexdigest()
    return f"pair-{digest[:32]}"


def _native_basename(value: object) -> str | None:
    name = _clean_text(value, max_length=512)
    if name is None:
        return None
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base or None


def _normalize_url(value: object) -> str | None:
    text = _clean_text(value)
    if text is None:
        return None
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    # ★主机尾点归一：`config.example.` 与 `config.example` 是同一主机（FQDN 根点写法），
    #   不剥则同一底层观测在倒排索引里裂成两个锚；裸域名 IOC 分支早已 rstrip(".")，
    #   两处口径必须一致。必须在 IDNA 之前剥——Python 的 idna codec 会原样保留尾点。
    hostname = parsed.hostname.rstrip(".")
    if not hostname:
        return None
    try:
        host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    # ★空路径归一为 "/"：`https://host` 与 `https://host/` 按 RFC 3986 §6.2.3 等价，
    #   不归一则同一配置端点会被当成两个不同的锚。
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def _config_url(value: object) -> tuple[str | None, str]:
    """归一化配置对象 URL，三态区分「可匹配 / 不支持的 scheme / 畸形」。

    返回 ``(归一化 URL 或 None, 状态)``，状态 ∈ ``{"ok", "unsupported_scheme", "invalid"}``。
    ★``oss://`` 等私有协议 URL 是真实观测、只是本基线不参与匹配——把它记成 invalid 会触发
    ``invalid_feature_fields`` 封顶，误伤同一对里毫不相干的强锚。「未参与匹配」≠「数据畸形」。
    """
    text = _clean_text(value)
    if text is None:
        return None, "invalid"
    try:
        scheme = urlsplit(text).scheme.lower()
    except ValueError:
        return None, "invalid"
    if scheme not in {"http", "https"}:
        if _SCHEME_RE.fullmatch(scheme):
            return None, "unsupported_scheme"
        return None, "invalid"
    url = _normalize_url(text)
    if url is None:
        return None, "invalid"
    return url, "ok"


def _classify_ioc(value: object) -> tuple[str, str] | None:
    """Conservatively classify an IOC for corroboration-only scoring."""
    text = _clean_text(value)
    if text is None:
        return None
    url = _normalize_url(text)
    if url is not None:
        return ("url", url)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            return None
        return ("public_ip", address.compressed)
    lowered = text.rstrip(".").lower()
    if _DOMAIN_RE.fullmatch(lowered):
        return ("domain", lowered)
    return ("other", text)


def _revision_provenance(entry: dict[str, Any]) -> RevisionProvenance:
    raw_state = _clean_text(entry.get("record_state"), max_length=32)
    record_state = (
        raw_state
        if raw_state in {_RECORD_ACTIVE, _RECORD_QUARANTINED}
        else _RECORD_UNKNOWN
    )
    return RevisionProvenance(
        tool_version=_clean_text(entry.get("tool_version"), max_length=512),
        ruleset_digest=_clean_text(entry.get("ruleset_digest"), max_length=512),
        evidence_surface=_clean_text(entry.get("evidence_surface"), max_length=64),
        record_state=record_state,
        report_bytes_sha256=_sha256(entry.get("report_bytes_sha256")),
    )


def _provenance_sort_key(item: RevisionProvenance) -> tuple[str, ...]:
    return tuple((value or "") for value in (
        item.tool_version,
        item.ruleset_digest,
        item.evidence_surface,
        item.record_state,
        item.report_bytes_sha256,
    ))


def _coverage_status(state: dict[str, bool]) -> str:
    if state["observed"] and state["invalid"]:
        return "observed_with_invalid_siblings"
    if state["observed"]:
        return "observed"
    if state["invalid"]:
        return "invalid_only"
    if state["valid"]:
        return "assessed_empty"
    return "unknown"


def _has_distinct_native_name_matching(
    sample_names: dict[str, set[str]], *, minimum: int
) -> bool:
    """Return whether distinct real samples can be matched to distinct basenames."""
    matched_sample_by_name: dict[str, str] = {}

    def augment(sample: str, seen_names: set[str]) -> bool:
        for name in sorted(sample_names[sample]):
            if name in seen_names:
                continue
            seen_names.add(name)
            previous = matched_sample_by_name.get(name)
            if previous is None or augment(previous, seen_names):
                matched_sample_by_name[name] = sample
                return True
        return False

    matched = 0
    for sample in sorted(sample_names):
        if augment(sample, set()):
            matched += 1
            if matched >= minimum:
                return True
    return False


def fit_linkage_preprocessing_context(
    entries: Iterable[dict[str, Any]],
) -> LinkagePreprocessingContext:
    """Fit corpus-level native rename decisions without retaining raw names."""
    native_basenames: dict[str, dict[str, set[str]]] = {}
    for entry in entries:
        sample = _entry_sample_identity(entry)
        if sample is None or _REAL_SAMPLE_RE.fullmatch(sample) is None:
            continue
        raw_native = entry.get("native_lib_hashes")
        if not isinstance(raw_native, list):
            continue
        for item in raw_native:
            if not isinstance(item, dict):
                continue
            sha = _sha256(item.get("sha256"))
            base = _native_basename(item.get("name"))
            if sha is not None and base is not None:
                native_basenames.setdefault(sha, {}).setdefault(sample, set()).add(base)

    return LinkagePreprocessingContext(
        normalization_version=NORMALIZATION_VERSION,
        renamed_native_sha256=frozenset(
            sha
            for sha, sample_names in native_basenames.items()
            if _has_distinct_native_name_matching(
                sample_names, minimum=_RENAMED_COMPONENT_MIN_BASENAMES
            )
        ),
    )


def collapse_manifest_entries(
    entries: Iterable[dict[str, Any]],
    *,
    preprocessing_context: LinkagePreprocessingContext | None = None,
) -> tuple[SampleFeatures, ...]:
    """Collapse multiple revisions/surfaces into one positive-evidence sample view."""
    entry_list = list(entries)
    if preprocessing_context is None:
        preprocessing_context = fit_linkage_preprocessing_context(entry_list)
    elif not isinstance(preprocessing_context, LinkagePreprocessingContext):
        raise TypeError("preprocessing_context must be a LinkagePreprocessingContext")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entry_list:
        sample = _entry_sample_identity(entry)
        if sample is not None:
            grouped.setdefault(sample, []).append(entry)

    collapsed: list[SampleFeatures] = []
    for sample, rows in sorted(grouped.items()):
        cases: set[str] = set()
        revisions: set[RevisionProvenance] = set()
        surfaces: set[str] = set()
        signs: set[str] = set()
        debug_signs: set[str] = set()
        native_names: dict[str, set[str]] = {}
        config_shas: set[str] = set()
        config_urls: set[str] = set()
        builds: set[str] = set()
        iocs: set[tuple[str, str]] = set()
        anchor_sources: dict[
            tuple[str, str, str], set[RevisionProvenance]
        ] = {}
        synthetic = False
        ownership_unresolved = False
        non_authoritative_input = False
        states = {
            field: {"valid": False, "observed": False, "invalid": False}
            for field in _FEATURE_FIELDS
        }

        for row in rows:
            synthetic = synthetic or row.get("sample_sha256_synthetic") is True
            revision = _revision_provenance(row)
            revisions.add(revision)
            ownership_unresolved = (
                ownership_unresolved
                or row.get("repack_identity_verdict") == _REPACK_SUSPECTED
            )
            non_authoritative_input = (
                non_authoritative_input
                or revision.record_state == _RECORD_QUARANTINED
            )
            surface = _clean_text(row.get("evidence_surface"), max_length=64)
            if surface:
                surfaces.add(surface)

            raw_cases = row.get("case_ids")
            if isinstance(raw_cases, list):
                for case in raw_cases:
                    cleaned = _clean_text(case, max_length=512)
                    if cleaned:
                        cases.add(cleaned)
            elif raw_cases is None:
                legacy_case = _clean_text(row.get("case_id"), max_length=512)
                if legacy_case:
                    cases.add(legacy_case)

            # ★公知调试/测试证书识别：repack_identity 的 debug-certificate finding 已随
            #   manifest 的 finding_ids 入库——该行的签名证书是公开调试证书（如 AOSP
            #   test-key），全球逐字节相同，共享它不证任何主体关联。缺 finding_ids 不作
            #   反证（老行没跑过该规则），只有正向标记才降档，与「缺失不作反证」一致。
            raw_finding_ids = row.get("finding_ids")
            debug_cert_flagged = isinstance(raw_finding_ids, list) and any(
                isinstance(fid, str) and fid.strip() == _DEBUG_CERT_FINDING
                for fid in raw_finding_ids
            )

            raw_sign = row.get("sign_sha256")
            if raw_sign is not None:
                if isinstance(raw_sign, str):
                    states["sign_sha256"]["valid"] = True
                    normalized_sign = _sha256(raw_sign)
                    if normalized_sign:
                        signs.add(normalized_sign)
                        anchor_sources.setdefault(
                            ("signing", "certificate_sha256", normalized_sign), set()
                        ).add(revision)
                        if debug_cert_flagged:
                            debug_signs.add(normalized_sign)
                        states["sign_sha256"]["observed"] = True
                    elif _clean_text(raw_sign) is not None:
                        states["sign_sha256"]["invalid"] = True
                else:
                    states["sign_sha256"]["invalid"] = True

            raw_native = row.get("native_lib_hashes")
            if isinstance(raw_native, list):
                states["native_lib_hashes"]["valid"] = True
                for item in raw_native:
                    if not isinstance(item, dict):
                        states["native_lib_hashes"]["invalid"] = True
                        continue
                    sha = _sha256(item.get("sha256"))
                    if sha is None:
                        states["native_lib_hashes"]["invalid"] = True
                        continue
                    name = _clean_text(item.get("name"), max_length=512)
                    native_names.setdefault(sha, set())
                    if name:
                        native_names[sha].add(name)
                    anchor_sources.setdefault(("native", "sha256", sha), set()).add(
                        revision
                    )
                    states["native_lib_hashes"]["observed"] = True
            elif raw_native is not None:
                states["native_lib_hashes"]["invalid"] = True

            raw_builds = row.get("build_environments")
            if isinstance(raw_builds, list):
                states["build_environments"]["valid"] = True
                for item in raw_builds:
                    if not isinstance(item, dict):
                        states["build_environments"]["invalid"] = True
                        continue
                    identifier = _clean_text(item.get("identifier"), max_length=512)
                    if identifier:
                        builds.add(identifier)
                        anchor_sources.setdefault(
                            ("build", "environment_identifier", identifier), set()
                        ).add(revision)
                        states["build_environments"]["observed"] = True
                    elif item:
                        states["build_environments"]["invalid"] = True
            elif raw_builds is not None:
                states["build_environments"]["invalid"] = True

            scope_indexed = row.get("case_ioc_scope_indexed") is True
            raw_configs = row.get("remote_config_objects")
            raw_iocs = row.get("key_iocs")
            if scope_indexed:
                if isinstance(raw_configs, list):
                    states["remote_config_objects"]["valid"] = True
                    for item in raw_configs:
                        if not isinstance(item, dict):
                            states["remote_config_objects"]["invalid"] = True
                            continue
                        raw_url = item.get("url")
                        # ★三态：oss:// 等不支持的 scheme 是「观测到了、本基线不参与匹配」，
                        #   不是畸形数据——不得触发 invalid_feature_fields 封顶去误伤
                        #   同一对里无关的强锚。只有语法都不成立的才记 invalid。
                        url, url_status = _config_url(raw_url) if raw_url else (None, "absent")
                        sha = _sha256(item.get("sha256")) if item.get("sha256") else None
                        if url_status == "invalid":
                            states["remote_config_objects"]["invalid"] = True
                        if item.get("sha256") and sha is None:
                            states["remote_config_objects"]["invalid"] = True
                        if url:
                            config_urls.add(url)
                            anchor_sources.setdefault(
                                ("remote_config", "object_url", url), set()
                            ).add(revision)
                        if sha:
                            config_shas.add(sha)
                            anchor_sources.setdefault(
                                ("remote_config", "content_sha256", sha), set()
                            ).add(revision)
                        if url or sha or url_status == "unsupported_scheme":
                            states["remote_config_objects"]["observed"] = True
                        elif item:
                            states["remote_config_objects"]["invalid"] = True
                elif raw_configs is not None:
                    states["remote_config_objects"]["invalid"] = True

                if isinstance(raw_iocs, list):
                    states["key_iocs"]["valid"] = True
                    for value in raw_iocs:
                        if not isinstance(value, str):
                            if value is not None:
                                states["key_iocs"]["invalid"] = True
                            continue
                        classified = _classify_ioc(value)
                        if classified:
                            iocs.add(classified)
                            anchor_sources.setdefault(
                                ("ioc", classified[0], classified[1]), set()
                            ).add(revision)
                            states["key_iocs"]["observed"] = True
                elif raw_iocs is not None:
                    states["key_iocs"]["invalid"] = True

            raw_visibility = row.get("visibility")
            if isinstance(raw_visibility, dict):
                states["visibility"]["valid"] = True
                states["visibility"]["observed"] = True
            elif raw_visibility is not None:
                states["visibility"]["invalid"] = True

        strong_native: set[str] = set()
        weak_native: dict[str, str] = {}
        for sha, names in native_names.items():
            reasons = sorted(
                reason
                for name in names
                if (reason := native_anchor_weakness(name)) is not None
            )
            if sha in preprocessing_context.renamed_native_sha256:
                weak_native[sha] = "renamed-shared-component"
            elif reasons:
                weak_native[sha] = reasons[0]
            else:
                strong_native.add(sha)

        coverage = tuple((field, _coverage_status(states[field])) for field in _FEATURE_FIELDS)
        # ★visibility 不是关联特征：它记录的是证据可见性求值，形状畸形与「这两个样本是否
        #   相关」无关，不该触发 invalid_feature_fields 封顶。coverage / coverage_gaps 里
        #   仍如实标出 invalid sibling（不吞信息），只是不再压分。
        invalid = tuple(
            field
            for field, status in coverage
            if status in {"observed_with_invalid_siblings", "invalid_only"}
            and field != "visibility"
        )
        provenance = tuple(
            (
                family,
                kind,
                value,
                tuple(sorted(source_revisions, key=_provenance_sort_key)),
            )
            for (family, kind, value), source_revisions in sorted(anchor_sources.items())
        )
        collapsed.append(
            SampleFeatures(
                sample_sha256=sample,
                synthetic_identity=synthetic,
                case_ids=tuple(sorted(cases)),
                revisions=tuple(sorted(revisions, key=_provenance_sort_key)),
                evidence_surfaces=tuple(sorted(surfaces)),
                ownership_unresolved=ownership_unresolved,
                non_authoritative_input=non_authoritative_input,
                sign_sha256=tuple(sorted(signs - debug_signs)),
                weak_sign=tuple(sorted(debug_signs)),
                native_sha256=tuple(sorted(strong_native)),
                weak_native=tuple(sorted(weak_native.items())),
                config_sha256=tuple(sorted(config_shas)),
                config_urls=tuple(sorted(config_urls)),
                build_environments=tuple(sorted(builds)),
                key_iocs=tuple(sorted(iocs)),
                coverage=coverage,
                invalid_fields=invalid,
                anchor_provenance=provenance,
            )
        )
    return tuple(collapsed)


def _candidate_pairs(
    samples: tuple[SampleFeatures, ...],
) -> tuple[set[tuple[str, str]], list[dict[str, Any]], bool]:
    """Generate pairs from non-weak inverted indexes, avoiding O(n^2) scans.

    ★超大共享簇护栏：单个锚被超过 :data:`_MAX_ANCHOR_CLUSTER_SAMPLES` 个样本共享时不再
    展开成 C(k,2) 个两两候选（k=200 就是 19,900 对全量物化+打分）。被跳过的锚显式登记进
    第二个返回值（→ 输出的 ``truncated_anchors``），复核者可拿锚值直查语料库看簇成员——
    标注而非删除，绝不静默截断。所有桶累计的唯一 pair 另受全局预算约束；预算耗尽后返回
    第三个布尔值，由调用方标记 partial，且预算诊断不得携带触发锚值。
    """
    index: dict[tuple[str, str], set[str]] = {}
    for sample in samples:
        # 派生 nosha 身份不能证明两个物理 APK 不同，也不能稳定承载跨报告技术关联。
        # 它只允许进入 same_sample_case_links 的 possible_duplicate_report 提示；在拿到
        # 真实 APK SHA-256 前，绝不进入普通 pair 倒排或产生数值复核分数。
        if sample.synthetic_identity:
            continue
        anchors = (
            *(("config_sha256", value) for value in sample.config_sha256),
            *(("config_url", value) for value in sample.config_urls),
            *(("native_sha256", value) for value in sample.native_sha256),
            *(("sign_sha256", value) for value in sample.sign_sha256),
            *(("build_environment", value) for value in sample.build_environments),
        )
        for anchor in anchors:
            index.setdefault(anchor, set()).add(sample.sample_sha256)
    pairs: set[tuple[str, str]] = set()
    truncated: list[dict[str, Any]] = []
    pair_budget_exhausted = False
    for anchor, sample_ids in sorted(index.items()):
        if len(sample_ids) < 2:
            continue
        if len(sample_ids) > _MAX_ANCHOR_CLUSTER_SAMPLES:
            truncated.append(
                {
                    "kind": anchor[0],
                    "value": anchor[1],
                    "sample_count": len(sample_ids),
                    "reason": (
                        f"共享该锚的样本数超过 {_MAX_ANCHOR_CLUSTER_SAMPLES}，"
                        "未展开成两两候选；可用该锚值直查语料库列出簇成员"
                    ),
                }
            )
            continue
        if pair_budget_exhausted:
            continue
        for pair in combinations(sorted(sample_ids), 2):
            if pair in pairs:
                continue
            if len(pairs) >= _MAX_CANDIDATE_PAIRS:
                pair_budget_exhausted = True
                break
            pairs.add(pair)
    return pairs, truncated, pair_budget_exhausted


def _broad_shared_anchors(
    samples: tuple[SampleFeatures, ...],
) -> dict[tuple[str, str], dict[str, int]]:
    """找出「在互不相关样本群之间流转」的 native/build 锚 → ``{(family, value): 分布统计}``。

    ★与 :func:`apkscan.core.corpus.native_anchor_weakness` 的「绝不用统计阈值」**不冲突**，
    后来者别按那条注释把本函数删掉。那条禁令针对的是**证据准入层**的共享频次判据：
    「被很多样本共享」不能证明 .so 是第三方件，按频次把锚从证据里剔除会误杀同族核心
    业务库——同族样本共享自研库恰恰是最有价值的锚。本函数判定的是另一件结构性事实：
    该锚的共享簇**内部**是否存在任何主体性关联（成员两两共享非调试签名证书或远程配置
    对象）。同族核心库的簇至少有部分成员会被这两类主体锚连起来（→ 不判广域）；只有当
    ≥N 个成员群两两毫无其它主体证据、还横跨 ≥N 个案件——即「同一值在 N 份互不相关
    样本里同现」——才判为广域共享件。

    ★这也不是证据删除：广域锚照常计分、照常展示、家族计数不变，只对**仅靠**这类锚
    支撑的候选对加低优先 cap，且把分布事实（样本数/案件数/互不相关群数）随 cap 一并
    输出，复核者可拿锚值直查语料库反驳。已知盲区：全程加壳、证书轮换、又无共享配置的
    真家族，其核心库簇也会呈现「互不相关」形态而被降档——降的是复核顺序，不是结论；
    cap 注记保证这类边仍带着完整证据待在队列里。
    """
    index: dict[tuple[str, str], set[str]] = {}
    for sample in samples:
        # 与 _candidate_pairs 同口径：派生身份不能证明物理样本互异，不参与分布统计。
        if sample.synthetic_identity:
            continue
        for value in sample.native_sha256:
            index.setdefault(("native", value), set()).add(sample.sample_sha256)
        for value in sample.build_environments:
            index.setdefault(("build", value), set()).add(sample.sample_sha256)

    by_id = {sample.sample_sha256: sample for sample in samples}
    subject_keys: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for members in index.values():
        for sample_id in members:
            if sample_id not in subject_keys:
                sample = by_id[sample_id]
                subject_keys[sample_id] = (
                    frozenset(sample.sign_sha256),
                    frozenset(sample.config_sha256).union(sample.config_urls),
                )

    def _related(left_id: str, right_id: str) -> bool:
        left_keys = subject_keys[left_id]
        right_keys = subject_keys[right_id]
        return bool(left_keys[0] & right_keys[0]) or bool(left_keys[1] & right_keys[1])

    # 同一批样本常共享多枚锚（SDK 栈就是一组 .so 同进同出），按成员集缓存簇统计。
    stats_cache: dict[frozenset[str], tuple[int, int, int]] = {}

    def _cluster_stats(members: set[str]) -> tuple[int, int, int]:
        key = frozenset(members)
        cached = stats_cache.get(key)
        if cached is not None:
            return cached
        ordered = sorted(members)
        parent = {member: member for member in ordered}

        def _find(item: str) -> str:
            while parent[item] != item:
                parent[item] = parent[parent[item]]
                item = parent[item]
            return item

        for left_id, right_id in combinations(ordered, 2):
            if _related(left_id, right_id):
                left_root, right_root = _find(left_id), _find(right_id)
                if left_root != right_root:
                    parent[left_root] = right_root
        groups = len({_find(member) for member in ordered})
        cases: set[str] = set()
        for member in ordered:
            cases.update(by_id[member].case_ids)
        stats = (len(ordered), len(cases), groups)
        stats_cache[key] = stats
        return stats

    broad: dict[tuple[str, str], dict[str, int]] = {}
    for anchor, members in index.items():
        if len(members) < 2:
            continue
        sample_count, case_count, group_count = _cluster_stats(members)
        if (
            group_count >= _BROAD_ANCHOR_MIN_UNRELATED_GROUPS
            and case_count >= _BROAD_ANCHOR_MIN_CASE_SPAN
        ):
            broad[anchor] = {
                "sample_count": sample_count,
                "case_count": case_count,
                "unrelated_group_count": group_count,
            }
    return broad


def _intersection(left: tuple[str, ...], right: tuple[str, ...]) -> list[str]:
    return sorted(set(left).intersection(right))


def _render_provenance(
    revisions: Iterable[RevisionProvenance],
) -> list[dict[str, str | None]]:
    return [
        revision.summary()
        for revision in sorted(set(revisions), key=_provenance_sort_key)
    ]


def _support(
    *,
    family: str,
    strength: str,
    matches: list[tuple[str, str]],
    weight: int,
    left: SampleFeatures,
    right: SampleFeatures,
) -> dict[str, Any]:
    rendered_matches: list[dict[str, Any]] = []
    left_sources: set[RevisionProvenance] = set()
    right_sources: set[RevisionProvenance] = set()
    for kind, value in matches:
        left_match_sources = left.provenance_for(family, kind, value)
        right_match_sources = right.provenance_for(family, kind, value)
        left_sources.update(left_match_sources)
        right_sources.update(right_match_sources)
        rendered_matches.append(
            {
                "kind": kind,
                "value": value,
                "provenance": {
                    "left": _render_provenance(left_match_sources),
                    "right": _render_provenance(right_match_sources),
                },
            }
        )
    return {
        "family": family,
        "strength": strength,
        "weight": weight,
        "match_count": len(matches),
        "matches": rendered_matches,
        "provenance": {
            "left": _render_provenance(left_sources),
            "right": _render_provenance(right_sources),
        },
    }


def _score_pair(
    left: SampleFeatures,
    right: SampleFeatures,
    *,
    broad_anchors: Mapping[tuple[str, str], Mapping[str, int]] | None = None,
) -> dict[str, Any]:
    # broad_anchors 缺省为空映射＝没有任何锚被判广域（单测直调时的中性行为）；
    # 真入口 rank_link_candidates 恒传语料级 _broad_shared_anchors 结果。
    broad_anchors = broad_anchors or {}
    supports: list[dict[str, Any]] = []
    strong_families: set[str] = set()
    support_families: set[str] = set()
    raw_score = 0

    config_sha = _intersection(left.config_sha256, right.config_sha256)
    config_url = _intersection(left.config_urls, right.config_urls)
    if config_sha or config_url:
        matches = [("content_sha256", value) for value in config_sha]
        matches.extend(("object_url", value) for value in config_url)
        weight = _REMOTE_CONFIG_CONTENT_WEIGHT if config_sha else _REMOTE_CONFIG_URL_WEIGHT
        supports.append(
            _support(
                family="remote_config",
                strength="strong",
                matches=matches,
                weight=weight,
                left=left,
                right=right,
            )
        )
        strong_families.add("remote_config")
        support_families.add("remote_config")
        raw_score += weight

    native = _intersection(left.native_sha256, right.native_sha256)
    if native:
        weight = min(
            _NATIVE_MAX_WEIGHT,
            _NATIVE_BASE_WEIGHT + _NATIVE_STEP_WEIGHT * (len(native) - 1),
        )
        supports.append(
            _support(
                family="native",
                strength="strong",
                matches=[("sha256", value) for value in native],
                weight=weight,
                left=left,
                right=right,
            )
        )
        strong_families.add("native")
        support_families.add("native")
        raw_score += weight

    signs = _intersection(left.sign_sha256, right.sign_sha256)
    if signs:
        supports.append(
            _support(
                family="signing",
                strength="strong",
                matches=[("certificate_sha256", value) for value in signs],
                weight=_SIGNING_WEIGHT,
                left=left,
                right=right,
            )
        )
        strong_families.add("signing")
        support_families.add("signing")
        raw_score += _SIGNING_WEIGHT

    builds = _intersection(left.build_environments, right.build_environments)
    if builds:
        weight = min(
            _BUILD_MAX_WEIGHT,
            _BUILD_BASE_WEIGHT + _BUILD_STEP_WEIGHT * (len(builds) - 1),
        )
        supports.append(
            _support(
                family="build",
                strength="medium",
                matches=[("environment_identifier", value) for value in builds],
                weight=weight,
                left=left,
                right=right,
            )
        )
        support_families.add("build")
        raw_score += weight

    # ★同一份底层观测不得跨家族重复计分：key_iocs 常回声样本自己的配置 URL——该值已在
    #   本对的 remote_config 家族计过分时，再按 IOC 加分等于把一份观测数成两个独立家族
    #   （既 +12 又把 single_strong_family 封顶 69→89 解锁）。只剔除本对已计分的值：
    #   未被 config 家族命中的 IOC 照常参与（fail-closed 不吞正证据），剔除的登记进
    #   excluded_evidence（标注而非删除）。
    config_credited = set(config_sha).union(config_url)
    left_iocs = set(left.key_iocs)
    shared_iocs_all = sorted(left_iocs.intersection(right.key_iocs))
    echoed_iocs = [(kind, value) for kind, value in shared_iocs_all if value in config_credited]
    shared_iocs = [(kind, value) for kind, value in shared_iocs_all if value not in config_credited]
    if shared_iocs:
        weight = min(_IOC_MAX_WEIGHT, sum(_IOC_WEIGHTS[kind] for kind, _value in shared_iocs))
        supports.append(
            _support(
                family="ioc",
                strength="weak",
                matches=shared_iocs,
                weight=weight,
                left=left,
                right=right,
            )
        )
        support_families.add("ioc")
        raw_score += weight

    # ★广域共享锚判定（复核优先级层）：本对匹配的 native/build 锚是否全为
    #   「跨案在互不相关样本群间流转」的广域件（见 _broad_shared_anchors）。
    native_all_broad = bool(native) and all(
        ("native", value) in broad_anchors for value in native
    )
    build_all_broad = bool(builds) and all(
        ("build", value) in broad_anchors for value in builds
    )

    caps: list[dict[str, Any]] = []
    medium_families = support_families - strong_families
    if not strong_families:
        cap = _NO_STRONG_SINGLE_CAP if len(support_families) <= 1 else _NO_STRONG_MULTI_CAP
        caps.append(
            {
                "code": "no_strong_anchor",
                "cap": cap,
                "reason": "缺少配置内容、非公共 native 或签名等强锚",
            }
        )
    elif len(strong_families) == 1:
        # ★佐证必须自身不是广域件：build 匹配全为广域共享构建标识（如商用 SDK 内嵌
        #   构建路径）时，它与广域 native 锚同进同出，不构成独立佐证，不解锁 69→89。
        corroborating_medium = set(medium_families)
        if build_all_broad:
            corroborating_medium.discard("build")
        cap = _SINGLE_STRONG_CORROBORATED_CAP if corroborating_medium else _SINGLE_STRONG_CAP
        caps.append(
            {
                "code": "single_strong_family",
                "cap": cap,
                "reason": "只有一个独立强证据家族",
            }
        )
    # ★全部支撑锚皆广域 → 低优先档。只在「唯一强家族是 native 且其匹配全为广域件、
    #   无 IOC 佐证、build 佐证（若有）也全为广域件」时触发；任何一枚非广域锚
    #   （签名/配置强家族、非广域 .so、非广域构建标识、共享 IOC）都豁免本 cap。
    #   证据与权重不动（标注而非删除），分布事实随 cap 输出供复核者反驳。
    if (
        strong_families == {"native"}
        and native_all_broad
        and "ioc" not in support_families
        and (not builds or build_all_broad)
    ):
        broad_details = [
            {
                "family": "native",
                "kind": "sha256",
                "value": value,
                **broad_anchors[("native", value)],
            }
            for value in native
        ]
        broad_details.extend(
            {
                "family": "build",
                "kind": "environment_identifier",
                "value": value,
                **broad_anchors[("build", value)],
            }
            for value in builds
        )
        caps.append(
            {
                "code": "broad_shared_anchor_only",
                "cap": _BROAD_SHARED_ANCHOR_CAP,
                "reason": (
                    "全部支撑锚都在语料里跨案被多个互不相关样本群共享"
                    "（形态与公共组件一致），仅凭它们不进入高优先复核档"
                ),
                "anchors": broad_details,
            }
        )

    invalid = sorted(set(left.invalid_fields).union(right.invalid_fields))
    if invalid:
        caps.append(
            {
                "code": "invalid_feature_fields",
                "cap": _INVALID_FEATURE_CAP,
                "reason": f"关联字段形状异常：{', '.join(invalid)}",
            }
        )
    if left.synthetic_identity or right.synthetic_identity:
        caps.append(
            {
                "code": "synthetic_sample_identity",
                "cap": _SYNTHETIC_IDENTITY_CAP,
                "reason": "至少一侧缺少真实样本 SHA-256，使用的是派生身份",
            }
        )
    ownership_unresolved = left.ownership_unresolved or right.ownership_unresolved
    if ownership_unresolved:
        caps.append(
            {
                "code": "repack_suspected",
                "cap": _OWNERSHIP_UNRESOLVED_CAP,
                "reason": "至少一侧疑似正版重打包，官方同版本差分前资产归属未决",
            }
        )
    non_authoritative_input = (
        left.non_authoritative_input or right.non_authoritative_input
    )
    if non_authoritative_input:
        caps.append(
            {
                "code": "non_authoritative_input",
                "cap": _NON_AUTHORITATIVE_INPUT_CAP,
                "reason": "候选包含 catalog 已隔离 revision，仅供人工复核",
            }
        )

    final_score = min([100, raw_score, *(item["cap"] for item in caps)])
    if non_authoritative_input:
        level = "non_authoritative_review"
    elif ownership_unresolved:
        level = "ownership_unresolved_review"
    elif len(support_families) <= 1:
        level = "single_anchor_review"
    elif final_score >= 90:
        level = "multi_anchor_high_priority"
    elif final_score >= 75:
        level = "high_priority_family_candidate"
    elif final_score >= 50:
        level = "strong_technical_similarity"
    elif final_score >= 25:
        level = "review"
    else:
        level = "weak_hint"

    weak_left = dict(left.weak_native)
    weak_right = dict(right.weak_native)
    # ★「任一侧弱即弱」：sha 相同而一侧是弱名（libhermes.so）、另一侧被改成强名的共享 .so，
    #   既不能计分（.so 文件名是对手可控的，弱侧的降噪理由照样成立），也不能凭空消失——
    #   两侧 (strong∪weak) 的交集减去 strong∩strong 才是完整的「被排除的共享 .so」集合，
    #   只取 weak∩weak 会让「一侧弱名、一侧强名」的共享在输出里彻底不可见。
    left_all_native = set(left.native_sha256).union(weak_left)
    right_all_native = set(right.native_sha256).union(weak_right)
    excluded_native = sorted(left_all_native.intersection(right_all_native) - set(native))
    excluded = [
        {
            "family": "native",
            "kind": "sha256",
            "value": value,
            "weight": 0,
            "reason": weak_left.get(value) or weak_right.get(value) or "shared_component",
        }
        for value in excluded_native
    ]
    # ★公知调试/测试证书（同上「任一侧弱即弱」）：AOSP test-key 等公开调试证书全球逐字节
    #   相同，共享它只说明「都用了公开调试签名」——零分排除但保持可见，口径与
    #   dynamic/correlate 拒用 debug 证书归一匹配一致。
    left_all_signs = set(left.sign_sha256).union(left.weak_sign)
    right_all_signs = set(right.sign_sha256).union(right.weak_sign)
    excluded.extend(
        {
            "family": "signing",
            "kind": "certificate_sha256",
            "value": value,
            "weight": 0,
            "reason": _DEBUG_CERT_FINDING,
        }
        for value in sorted(left_all_signs.intersection(right_all_signs) - set(signs))
    )
    excluded.extend(
        {
            "family": "ioc",
            "kind": kind,
            "value": value,
            "weight": 0,
            "reason": "remote-config-echo",
        }
        for kind, value in echoed_iocs
    )
    excluded.sort(key=lambda row: (_FAMILY_ORDER[row["family"]], row["kind"], row["value"]))

    gaps: list[dict[str, str]] = []
    for sample in (left, right):
        for field, status in sample.coverage:
            if status in _COVERAGE_GAP_STATES:
                gaps.append(
                    {"sample_sha256": sample.sample_sha256, "field": field, "status": status}
                )

    supports.sort(key=lambda row: _FAMILY_ORDER[row["family"]])
    return {
        "left": left.summary(),
        "right": right.summary(),
        "candidate_id": _candidate_id(left.sample_sha256, right.sample_sha256),
        "review_priority_score": final_score,
        "uncapped_score": raw_score,
        # Compatibility aliases for schema 1.0 consumers. New code must use the
        # explicitly named fields above; these aliases will be removed in 2.0.
        "score": final_score,
        "raw_score": min(100, raw_score),
        "level": level,
        "ownership_unresolved": ownership_unresolved,
        "non_authoritative_input": non_authoritative_input,
        "strong_family_count": len(strong_families),
        "support_family_count": len(support_families),
        "supporting_evidence": supports,
        "score_caps": caps,
        "excluded_evidence": excluded,
        "coverage_gaps": gaps,
        "conclusion": "仅表示应优先人工复核的技术关联候选，不代表同一运营主体",
    }


def rank_link_candidates(
    entries: Iterable[dict[str, Any]],
    *,
    case_id: str = "",
    limit: int | None = 20,
    preprocessing_context: LinkagePreprocessingContext | None = None,
) -> dict[str, Any]:
    """Rank explainable sample pairs and direct same-sample cross-case links."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    # ★纯空白的 case_id 是输入错误，不是「不过滤」：静默退化成全量输出会让调用方以为
    #   看到的是过滤后的结果。空串（默认值）才表示不过滤。
    if case_id and not case_id.strip():
        raise ValueError("case_id must not be whitespace-only")
    wanted_case = case_id.strip()
    entry_list = list(entries)
    policy_digest, policy_status = _current_policy_metadata()
    invalid_identity_record_count = sum(
        1 for entry in entry_list if _entry_sample_identity(entry) is None
    )
    missing_repack_identity_record_count = sum(
        1
        for entry in entry_list
        if isinstance(entry, dict)
        and _entry_sample_identity(entry) is not None
        and "repack_identity_verdict" not in entry
    )
    invalid_repack_identity_record_count = sum(
        1
        for entry in entry_list
        if isinstance(entry, dict)
        and _entry_sample_identity(entry) is not None
        and "repack_identity_verdict" in entry
        and not (
            isinstance(entry.get("repack_identity_verdict"), str)
            and entry.get("repack_identity_verdict") in _REPACK_IDENTITY_VERDICTS
        )
    )
    samples = collapse_manifest_entries(
        entry_list, preprocessing_context=preprocessing_context
    )
    synthetic_sample_count = sum(sample.synthetic_identity for sample in samples)
    by_id = {sample.sample_sha256: sample for sample in samples}

    pairs, truncated_anchors, pair_budget_exhausted = _candidate_pairs(samples)
    broad_anchors = _broad_shared_anchors(samples)
    candidates: list[dict[str, Any]] = []
    for left_id, right_id in pairs:
        left = by_id[left_id]
        right = by_id[right_id]
        if wanted_case and wanted_case not in left.case_ids and wanted_case not in right.case_ids:
            continue
        candidates.append(_score_pair(left, right, broad_anchors=broad_anchors))
    candidates.sort(
        key=lambda row: (
            -row["review_priority_score"],
            -row["strong_family_count"],
            -row["support_family_count"],
            row["left"]["sample_sha256"],
            row["right"]["sample_sha256"],
        )
    )
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank

    direct_links: list[dict[str, Any]] = []
    for sample in samples:
        if len(sample.case_ids) < 2 or (wanted_case and wanted_case not in sample.case_ids):
            continue
        direct_links.append(
            {
                "sample_sha256": sample.sample_sha256,
                "case_ids": list(sample.case_ids),
                "relation": (
                    "possible_duplicate_report"
                    if sample.synthetic_identity
                    else "exact_artifact_identity"
                ),
                "synthetic_identity": sample.synthetic_identity,
                "ownership_unresolved": sample.ownership_unresolved,
                "non_authoritative_input": sample.non_authoritative_input,
                "conclusion": (
                    "同一派生报告身份跨案件出现，须先补真实样本 SHA-256"
                    if sample.synthetic_identity
                    else "同一 APK 样本 SHA-256 跨案件出现"
                ),
            }
        )

    total = len(candidates)
    generation_status = (
        "partial"
        if (
            truncated_anchors
            or pair_budget_exhausted
            or invalid_identity_record_count
            or missing_repack_identity_record_count
            or invalid_repack_identity_record_count
            or policy_status != "complete"
        )
        else "complete"
    )
    generation_notes: list[str] = []
    if truncated_anchors:
        generation_notes.append(
            "generated_pair_count excludes pairs reachable only through overbroad anchors"
        )
    if pair_budget_exhausted:
        generation_notes.append(
            "generated_pair_count is capped by the global candidate pair budget"
        )
    if missing_repack_identity_record_count:
        generation_notes.append(
            "manifest rows lack repack_identity_verdict; corpus reindex only rebuilds from "
            "existing reports and cannot backfill reports missing meta.repack_identity. "
            "re-analyze affected APKs with current fxapk (original APK required), then "
            "add/reindex before relying on ownership caps"
        )
    if invalid_repack_identity_record_count:
        generation_notes.append(
            "manifest rows contain invalid repack_identity_verdict; run corpus reindex, then "
            "re-analyze any rows that remain invalid before relying on ownership caps"
        )
    if policy_status != "complete":
        generation_notes.append(
            "native weak-anchor policy inputs did not load completely; ranking is partial"
        )
    selected = candidates if limit is None else candidates[:limit]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": generation_status,
        "model": {
            "id": MODEL_ID,
            "kind": "deterministic_rule_baseline",
            "score_semantics": "review_priority_not_probability",
            "result_schema_version": RESULT_SCHEMA_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "normalization_version": NORMALIZATION_VERSION,
            "policy_digest": policy_digest,
            "policy_status": policy_status,
            "deprecated_aliases": {
                "score": "review_priority_score",
                "raw_score": "min(100, uncapped_score)",
            },
        },
        "input": {
            "record_count": len(entry_list),
            "sample_count": len(samples),
            "real_sample_count": len(samples) - synthetic_sample_count,
            "synthetic_sample_count": synthetic_sample_count,
            "non_authoritative_sample_count": sum(
                sample.non_authoritative_input for sample in samples
            ),
            "ownership_unresolved_sample_count": sum(
                sample.ownership_unresolved for sample in samples
            ),
            "invalid_sample_identity_record_count": invalid_identity_record_count,
            "missing_repack_identity_record_count": (
                missing_repack_identity_record_count
            ),
            "invalid_repack_identity_record_count": (
                invalid_repack_identity_record_count
            ),
            # Compatibility alias: legacy rows are precisely rows missing the projection.
            "legacy_repack_identity_record_count": (
                missing_repack_identity_record_count
            ),
            "case_filter": wanted_case or None,
            "candidate_generation": "inverted_index_nonweak_anchors",
            "anchor_cluster_limit": _MAX_ANCHOR_CLUSTER_SAMPLES,
            "candidate_pair_budget": _MAX_CANDIDATE_PAIRS,
        },
        "candidate_generation": {
            "status": generation_status,
            "generated_pair_count": total,
            "overbroad_anchor_count": len(truncated_anchors),
            "pair_budget_exhausted": pair_budget_exhausted,
            "pair_budget_diagnostic": (
                {
                    "limit": _MAX_CANDIDATE_PAIRS,
                    "reason": "global candidate pair budget exhausted",
                }
                if pair_budget_exhausted
                else None
            ),
            "note": "; ".join(generation_notes) or None,
        },
        "migration": {
            "status": (
                "required"
                if (
                    missing_repack_identity_record_count
                    or invalid_repack_identity_record_count
                )
                else "current"
            ),
            "missing_manifest_fields": (
                ["repack_identity_verdict"]
                if missing_repack_identity_record_count
                else []
            ),
            "invalid_manifest_fields": (
                ["repack_identity_verdict"]
                if invalid_repack_identity_record_count
                else []
            ),
            "missing_record_count": missing_repack_identity_record_count,
            "invalid_record_count": invalid_repack_identity_record_count,
            "legacy_record_count": missing_repack_identity_record_count,
            # reindex 只会按现有 report 重算投影；缺 ``meta.repack_identity`` 的旧报告
            # 不会被单独 reindex 修复，必须先用当前版本重跑 analyze 生成新报告。
            "next_action": (
                "fxapk corpus reindex --corpus <corpus-root>; if rows remain missing, "
                "invalid, or unassessed because legacy reports do not contain "
                "meta.repack_identity, re-analyze affected APKs with current fxapk "
                "(original APK required) to regenerate reports, then add/reindex them"
                if (
                    missing_repack_identity_record_count
                    or invalid_repack_identity_record_count
                )
                else None
            ),
        },
        "count": len(selected),
        "total_before_limit": total,
        # ★共享样本数超限、未展开成两两候选的锚：显式可见，绝不静默截断。
        "truncated_anchors": truncated_anchors,
        "candidates": selected,
        "same_sample_case_links": direct_links,
        "disclaimer": "结果仅用于线索排序；必须回看原始证据，不得据此认定同一运营主体。",
    }
