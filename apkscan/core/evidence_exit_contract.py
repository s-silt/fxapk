"""证据单元到用户可见出口的显式契约。

本模块不做源码污点分析。契约只描述稳定的业务事实；测试用合成输入执行真正的
producer，并按 ``scenario`` 对声明的字段和分支作值级核验。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Sink(StrEnum):
    LEAD = "lead"
    FINDING = "finding"
    ENDPOINT = "endpoint"
    VISIBILITY = "visibility"
    CLOSURE = "closure"
    DIGEST = "digest"


class Coverage(StrEnum):
    ALL = "all"
    SUMMARY = "summary"
    CONDITIONAL = "conditional"
    NONE = "none"


class GapKind(StrEnum):
    COMPLETE = "complete"
    CONDITIONAL = "conditional"
    FIELD = "field"


@dataclass(frozen=True)
class Projection:
    """归档副本与必须抵达研判层的字段。"""

    archived: tuple[str, ...]
    required: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceExit:
    unit: str
    producer: tuple[str, ...]
    projection: Projection
    sinks: tuple[Sink, ...]
    coverage: Coverage
    scenario: str
    condition: str = ""
    gap: GapKind | None = None


def _ok(unit: str, producer: str, required: tuple[str, ...], sinks: tuple[Sink, ...],
        scenario: str, *, coverage: Coverage = Coverage.ALL, condition: str = "") -> EvidenceExit:
    return EvidenceExit(unit, (producer,), Projection((producer,), required), sinks,
                        coverage, scenario, condition)


def _gap(unit: str, producer: tuple[str, ...], required: tuple[str, ...], scenario: str,
         kind: GapKind, *, condition: str = "") -> EvidenceExit:
    return EvidenceExit(unit, producer, Projection(producer, required), (), Coverage.NONE,
                        scenario, condition, kind)


EVIDENCE_EXITS: tuple[EvidenceExit, ...] = (
    _gap("runtime_remote_control_unknown_packages",
         ("runtime_remote_control_unknown_packages",), ("package",),
         "runtime_unknown_package_meta_only", GapKind.CONDITIONAL,
         condition="未知包 accessibility 事件存在，且无 gesture/screencapture"),
    _gap("control_chains", ("control_chains",), ("config", "recipe", "backend", "attribution"),
         "control_chain_meta_only", GapKind.COMPLETE),
    _gap("firebase_unprojected_fields", ("firebase",),
         ("storage_bucket", "api_key", "sender_id", "project_number"),
         "firebase_field_gap", GapKind.FIELD),
    _gap("container_decoy_absolute_only", ("container_decoy_entries",),
         ("absolute_path_entries",), "container_decoy_conditional_gap", GapKind.CONDITIONAL,
         condition="存在绝对路径条目，但未冒充 APK 核心文件名"),

    _ok("runtime_antidetect", "runtime_antidetect", ("kind", "probe"),
        (Sink.FINDING,), "runtime_antidetect_finding"),
    # 原为 COMPLETE 缺口：写入点注释写着「供报告呈现」，实际没有任何出口呈现它。
    # 已补 RUNTIME-BRAND-HINTS observation Finding，缺口数字同步下调。
    _ok("runtime_brand_hints", "runtime_brand_hints", ("brand",),
        (Sink.FINDING,), "runtime_brand_hint_finding"),
    _ok("runtime_jsbridge", "runtime_jsbridge", ("interface",),
        (Sink.LEAD,), "runtime_jsbridge_lead"),
    _ok("runtime_sensitive_apis", "runtime_sensitive_apis", ("api",),
        (Sink.FINDING,), "runtime_sensitive_api_confirmation"),
    _ok("runtime_dead_drop_relations", "runtime_dead_drop_relations", ("command", "secondary"),
        (Sink.LEAD, Sink.ENDPOINT), "runtime_dead_drop_relation"),
    _ok("runtime_remote_control_targets", "runtime_remote_control_targets", ("package", "subject"),
        (Sink.LEAD,), "runtime_known_remote_target"),
    _ok("decrypt_candidates", "decrypt_candidates", ("ciphertext", "consumer"),
        (Sink.FINDING,), "decrypt_candidate_finding"),
    _ok("denial_bomb_entries", "denial_bomb_entries", ("path", "declared_size"),
        (Sink.FINDING,), "denial_bomb_finding"),
    _ok("dns_bypass", "dns_bypass", ("protocol",),
        (Sink.FINDING, Sink.VISIBILITY), "dns_bypass_finding"),
    _ok("manifest_anomaly", "manifest_anomaly", ("anomaly",),
        (Sink.FINDING, Sink.VISIBILITY), "manifest_anomaly_finding"),
    # 原为 COMPLETE 缺口：docstring 自称「研判标注」却零消费方，读报告的人看不到。
    # 已补 MANIFEST-SUSPICIOUS-VERSION-NAME（LOW observation）。
    EvidenceExit(
        "suspicious_version_keyword",
        ("suspicious_version_name", "suspicious_version_hits"),
        Projection(("suspicious_version_name",), ("version_name", "matched_keyword")),
        (Sink.FINDING,), Coverage.ALL, "suspicious_version_finding",
    ),
    _ok("re_toolkit", "re_toolkit", ("name", "capability"),
        (Sink.FINDING,), "re_toolkit_finding", coverage=Coverage.SUMMARY),
    _ok("web_redirect_chain", "web_redirect_chain", ("step", "target", "mechanism"),
        (Sink.FINDING, Sink.ENDPOINT), "web_redirect_chain_finding"),
    _ok("web_request_recipe", "web_request_recipe", ("decoded", "context"),
        (Sink.FINDING,), "web_request_recipe_finding"),
    _ok("webview_signals", "webview_signals", ("signal_id",),
        (Sink.FINDING,), "webview_signal_finding"),
)


# 审计范围是证据单元，不是每个 meta 键。新增单元必须同时加入契约；该集合故意
# 与 EVIDENCE_EXITS 分开，避免“只 append 一条对象”让准入检查恒真。
EVIDENCE_UNIT_INVENTORY = frozenset({
    "runtime_brand_hints", "runtime_remote_control_unknown_packages", "control_chains",
    "firebase_unprojected_fields", "suspicious_version_keyword", "container_decoy_absolute_only",
    "runtime_antidetect", "runtime_jsbridge", "runtime_sensitive_apis",
    "runtime_dead_drop_relations", "runtime_remote_control_targets", "decrypt_candidates",
    "denial_bomb_entries", "dns_bypass", "manifest_anomaly", "re_toolkit",
    "web_redirect_chain", "web_request_recipe", "webview_signals",
})


#: 已知缺口的 (证据单元数, producer 键数)。★数字下调只能因为**真的接上了出口**——
#: `runtime_brand_hints` 由 3/4 降为 2/3 是补了 RUNTIME-BRAND-HINTS Finding 的结果。
EXPECTED_GAPS = {GapKind.COMPLETE: (1, 1), GapKind.CONDITIONAL: (2, 2), GapKind.FIELD: (1, 1)}


def validate_evidence_exit_contract() -> list[str]:
    problems: list[str] = []
    units = [item.unit for item in EVIDENCE_EXITS]
    if len(units) != len(set(units)):
        problems.append("证据单元名称重复")
    missing = EVIDENCE_UNIT_INVENTORY - set(units)
    extra = set(units) - EVIDENCE_UNIT_INVENTORY
    if missing:
        problems.append(f"新增或未声明出口的证据单元：{sorted(missing)!r}")
    if extra:
        problems.append(f"契约含未纳入审计范围的证据单元：{sorted(extra)!r}")
    for item in EVIDENCE_EXITS:
        if not item.producer or not item.projection.required or not item.scenario:
            problems.append(f"{item.unit}: producer/projection/scenario 不完整")
        if item.gap is None and not item.sinks:
            problems.append(f"{item.unit}: 正向契约没有 sink")
        if item.gap is not None and (item.sinks or item.coverage is not Coverage.NONE):
            problems.append(f"{item.unit}: 缺口不得伪装成已有出口")
    actual: dict[GapKind, tuple[int, int]] = {}
    for kind in GapKind:
        rows = [item for item in EVIDENCE_EXITS if item.gap is kind]
        actual[kind] = (len(rows), sum(len(item.producer) for item in rows))
    if actual != EXPECTED_GAPS:
        problems.append(f"缺口数字漂移：expected={EXPECTED_GAPS!r}, actual={actual!r}")
    return problems
