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
    # 原为 CONDITIONAL 缺口：未知包只在有 gesture/screencapture 时才进 Finding，
    # 而 launch-only 抓包常抓不到手势 → 浅抓包样本整批静默。
    # 已补 RUNTIME-REMOTE-CONTROL-UNKNOWN-TARGET（LOW observation）覆盖无手势那一支。
    _ok("runtime_remote_control_unknown_packages", "runtime_remote_control_unknown_packages",
        ("package",), (Sink.FINDING,), "runtime_unknown_remote_target_finding"),
    _ok("decrypt_candidates", "decrypt_candidates", ("ciphertext", "consumer"),
        (Sink.FINDING,), "decrypt_candidate_finding"),
    _ok("denial_bomb_entries", "denial_bomb_entries", ("path", "declared_size"),
        (Sink.FINDING,), "denial_bomb_finding"),
    # 原为 CONDITIONAL 缺口：不冒充核心名那一支直接 return，分析员拿不到「别落盘解压」
    # 这条操作提示。已补 APK-ABSOLUTE-PATH-ENTRIES（LOW observation），两支都有出口。
    _ok("container_decoy_absolute_only", "container_decoy_entries", ("absolute_path_entries",),
        (Sink.FINDING,), "container_decoy_absolute_only_finding"),
    # 原为 FIELD 缺口：project_id 进 Lead、database_url 进 Endpoint，
    # 而 storage_bucket/api_key/sender_id/project_number 四字段只在 meta。
    # 已补：前三者作同一 GCP 项目的其它标识符并进那条 Lead 的证据；
    # storage_bucket 与 database_url 同口径产 domain Endpoint。
    _ok("firebase_unprojected_fields", "firebase",
        ("storage_bucket", "api_key", "sender_id", "project_number"),
        (Sink.LEAD, Sink.ENDPOINT), "firebase_field_exits"),
    # 原为 COMPLETE 缺口：build_control_chains 的存在理由就是「不再是孤立 IOC，而是可读的
    # 控制链」，可它只写 meta、无出口——组成节点各自可见 ≠ 这条关系可见。
    # 已补 digest 的 control_chains 段（逐链成条，链内保留归属，不拆成平铺列表）。
    _ok("control_chains", "control_chains", ("config", "recipe", "backend", "attribution"),
        (Sink.DIGEST,), "control_chain_digest_section"),
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


#: 已知缺口的 (证据单元数, producer 键数)。★数字下调只能因为**真的接上了出口**。
#:
#: 起点是 complete 3/4 + conditional 2/2 + field 1/1（**6 单元 / 7 键**），已全部接上：
#:   - runtime_brand_hints → RUNTIME-BRAND-HINTS Finding
#:   - suspicious_version_keyword → MANIFEST-SUSPICIOUS-VERSION-NAME Finding
#:   - control_chains → digest 的 control_chains 段
#:   - runtime_remote_control_unknown_packages → 无手势分支的 observation Finding
#:   - container_decoy_absolute_only → APK-ABSOLUTE-PATH-ENTRIES Finding
#:   - firebase_unprojected_fields → 三标识符并进 Lead 证据 + storage_bucket 产 Endpoint
#:
#: ★全零后**这张表更要留着**：它是「新增缺口即红」的判据。三类都写 (0, 0) 而不是删掉键——
#:   删掉读起来像「没查这一类」，写 0 才是「查过了，这一类没有」。
EXPECTED_GAPS = {
    GapKind.COMPLETE: (0, 0),
    GapKind.CONDITIONAL: (0, 0),
    GapKind.FIELD: (0, 0),
}


#: ★契约之外的 signal 类 meta 键——**冻住，新增即红**。
#:
#: 为什么需要它：`EVIDENCE_UNIT_INVENTORY` 是人工清单，`EXPECTED_GAPS` 全零只约束
#: 「已经被人列进契约的条目」。复审给的绕过构造是：分析器新增 `meta["new_signal"]`，
#: 同时在生产代码里加一个无用户价值的读取（例如只用于 debug 日志）——
#: 孤儿扫描因「有生产读取」判它非孤儿，证据契约因「不在人工清单里」看不见它，
#: 三类 gap 仍全零。**两道门都过，而那个信号其实没到任何人眼前。**
#:
#: 本表把当下 47 个 signal 键里未被证据单元覆盖的 35 个钉住。新增 signal 键必须二选一：
#: 要么建一个证据单元（说明它到达哪个出口），要么显式加进本表并说明为什么暂不建。
#: ★这不是「覆盖全部 signal 键」——证据契约的范围本就是已审过的那批；
#:   本表只保证**范围不会被无声扩大**。
SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT = frozenset({
    "allow_backup", "anti_frida", "api_surface", "contacts", "crypto_addresses",
    "crypto_recipe", "dangerous_matched", "debuggable", "deeplinks", "dex_string_pool",
    "firebase_project_id", "hardening_structural", "is_hardened", "native_config_channel",
    "native_obfuscation", "network_security_config", "package_name", "packed", "packer",
    "payment_keywords", "permissions", "repack_identity", "sdks", "sign_sha256",
    "sign_subject", "target_sdk", "telegram_bot_tokens", "uni_app_name", "uni_appid",
    "uni_encrypted", "uses_cleartext_traffic", "version_code", "version_name",
    "xposed_markers", "xposed_module",
})


#: ``scenario`` → 实现它的测试函数名。★没有这张表时 ``scenario`` 只是个自由字符串：
#: 验证器只查它非空，写错一个字母照样过，测试名里的 "executable scenario" 比实际保证强。
SCENARIO_TESTS: dict[str, str] = {
    "runtime_antidetect_finding": "test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks",
    "runtime_jsbridge_lead": "test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks",
    "runtime_sensitive_api_confirmation": (
        "test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks"
    ),
    "runtime_brand_hint_finding": "test_brand_hints_value_reaches_finding",
    "runtime_dead_drop_relation": "test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks",
    "runtime_known_remote_target": "test_unknown_remote_target_reaches_finding_without_gesture",
    "runtime_unknown_remote_target_finding": (
        "test_unknown_remote_target_reaches_finding_without_gesture"
    ),
    "decrypt_candidate_finding": "test_denial_bomb_value_reaches_finding",
    "denial_bomb_finding": "test_denial_bomb_value_reaches_finding",
    "container_decoy_absolute_only_finding": "test_both_container_branches_reach_a_finding",
    "firebase_field_exits": "test_firebase_every_field_reaches_an_exit",
    "control_chain_digest_section": "test_control_chain_relation_reaches_digest",
    "dns_bypass_finding": "test_dns_protocol_value_reaches_finding_and_visibility_wording",
    "manifest_anomaly_finding": "test_manifest_anomaly_value_reaches_finding",
    "suspicious_version_finding": "test_suspicious_version_value_reaches_finding",
    "re_toolkit_finding": "test_re_toolkit_name_and_capability_reach_finding",
    "web_redirect_chain_finding": "test_web_redirect_fields_reach_finding_and_endpoint",
    "web_request_recipe_finding": "test_web_request_decoded_value_and_context_reach_finding",
    "webview_signal_finding": "test_webview_signal_id_reaches_matching_finding",
}


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

    # ★scenario 必须指向一张明确的实现表——否则它只是个自由字符串，写错也照过。
    for item in EVIDENCE_EXITS:
        if item.gap is None and item.scenario not in SCENARIO_TESTS:
            problems.append(
                f"{item.unit}: scenario {item.scenario!r} 未登记实现它的测试（见 SCENARIO_TESTS）"
            )

    # ★signal 类 meta 键的范围不得被无声扩大：新增的要么建证据单元、要么显式进那张表。
    from apkscan.core.meta_contract import META_CATEGORY_SIGNAL, META_KEY_REGISTRY

    signal_keys = {
        key for key, contract in META_KEY_REGISTRY.items()
        if contract.category == META_CATEGORY_SIGNAL
    }
    covered = {producer for item in EVIDENCE_EXITS for producer in item.producer}
    unaccounted = signal_keys - covered - SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT
    stale = SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT - signal_keys
    if unaccounted:
        problems.append(
            f"新增 signal 键未交代出口：{sorted(unaccounted)!r}——"
            "要么建证据单元说明它到达哪个出口，要么显式加进 "
            "SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT 并说明为什么暂不建"
        )
    if stale:
        problems.append(
            f"SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT 有过期条目：{sorted(stale)!r}——"
            "它们已不是 signal 键（改类别或已删），请同步移除，别让表和现实脱节"
        )
    return problems
