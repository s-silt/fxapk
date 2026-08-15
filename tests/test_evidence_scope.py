from __future__ import annotations

from apkscan.core import infra
from apkscan.core import pipeline
from apkscan.core.closure import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    ClosureConfig,
    close_report,
)
from apkscan.core.closure.layers import _runtime_layer
from apkscan.core.closure.targets import _runtime_info, _select_targets_with_stats
from apkscan.core.leads import build_endpoint_leads
from apkscan.core.models import (
    DOWNGRADE_EVIDENCE_SCOPE,
    Confidence,
    Endpoint,
    Evidence,
    EvidenceScope,
    Lead,
    LeadCategory,
    Report,
    has_case_evidence,
)
from apkscan.dynamic.pcap_ingest import _merge_runtime_endpoint_dicts


def _report(endpoint: Endpoint) -> Report:
    lead = Lead(
        category=LeadCategory.DOMAIN,
        value=endpoint.value,
        confidence=Confidence.HIGH,
        source_refs=list(endpoint.evidences),
        advice=infra.ADVICE_INVESTIGATE,
        base_advice=infra.ADVICE_INVESTIGATE,
    )
    return Report(
        package_name="com.example.synthetic",
        meta={},
        leads=[lead],
        endpoints=[endpoint],
        findings=[],
        analyzer_status=[],
    )


def _endpoint(*scopes: EvidenceScope) -> Endpoint:
    return Endpoint(
        value="backend.example",
        kind="domain",
        evidences=[
            Evidence(source="runtime-pcap", location=f"capture-{index}.pcap", scope=scope)
            for index, scope in enumerate(scopes)
        ],
    )


def test_batch_reference_only_endpoint_cannot_become_closure_target() -> None:
    selected, stats = _select_targets_with_stats(
        _report(_endpoint(EvidenceScope.BATCH_REFERENCE)), 6
    )

    assert selected == []
    assert stats["scope_excluded"] == 1


def test_scope_exclusion_is_wired_into_close_report_entry_point() -> None:
    """★ 缺锁补回：闭环的作用域排除此前只在私有函数上验过。

    本文件原有的排除测试全部直调 ``_select_targets_with_stats`` / ``_runtime_info`` /
    ``_runtime_layer``，从未从 :func:`close_report` 这个真入口断言过。本仓纪律是
    「只调被测函数的单测永远测不到接线」——真入口哪天漏调了排除逻辑，那几条私有函数测试
    照样全绿，而对外产出的 ``meta.closure`` 已经把参考材料当成了本案闭环目标。
    """
    direct = close_report(
        _report(_endpoint(EvidenceScope.CASE_EVIDENCE)), ClosureConfig(online=False), enrichers=[]
    )
    assert len(direct["targets"]) == 1
    assert "scope_excluded" not in direct["target_selection"]

    for scope in (EvidenceScope.BATCH_REFERENCE, EvidenceScope.LEGACY_UNSPECIFIED):
        closure = close_report(
            _report(_endpoint(scope)), ClosureConfig(online=False), enrichers=[]
        )
        assert closure["targets"] == [], scope
        assert closure["target_selection"]["scope_excluded"] == 1, scope
        # 目标清单被排空后不得仍自称闭环完成。
        assert closure["status"] == CLOSURE_FAILED, scope


def test_legacy_unspecified_only_endpoint_cannot_become_closure_target() -> None:
    selected, stats = _select_targets_with_stats(
        _report(_endpoint(EvidenceScope.LEGACY_UNSPECIFIED)), 6
    )

    assert selected == []
    assert stats["scope_excluded"] == 1


def test_case_evidence_plus_batch_reference_remains_eligible() -> None:
    endpoint = _endpoint(EvidenceScope.CASE_EVIDENCE, EvidenceScope.BATCH_REFERENCE)

    selected, stats = _select_targets_with_stats(_report(endpoint), 6)

    assert selected == [endpoint]
    assert "scope_excluded" not in stats


def test_empty_evidence_list_is_not_certified_as_case_evidence() -> None:
    endpoint = _endpoint()

    selected, stats = _select_targets_with_stats(_report(endpoint), 6)

    assert selected == []
    assert stats["scope_excluded"] == 1


def test_lead_only_batch_reference_cannot_cover_empty_endpoint() -> None:
    endpoint = _endpoint()
    report = _report(endpoint)
    report.leads[0].source_refs = [
        Evidence(
            source="batch",
            location="batch.csv",
            scope=EvidenceScope.BATCH_REFERENCE,
        )
    ]

    selected, stats = _select_targets_with_stats(report, 6)

    assert selected == []
    assert stats["scope_excluded"] == 1


def test_direct_lead_reference_can_qualify_matching_endpoint_without_duplicate_ref() -> None:
    endpoint = _endpoint()
    report = _report(endpoint)
    report.leads[0].source_refs = [
        Evidence(source="runtime-pcap", location="capture.pcap")
    ]

    selected, _stats = _select_targets_with_stats(report, 6)

    assert selected == [endpoint]


def test_batch_only_endpoint_lead_is_downgraded_to_review() -> None:
    endpoint = _endpoint(EvidenceScope.BATCH_REFERENCE)

    lead = build_endpoint_leads([endpoint], online=False)[0]

    assert lead.advice == infra.ADVICE_REVIEW
    assert "evidence_scope" in lead.downgrades


def test_runtime_closure_facts_require_direct_case_runtime_evidence() -> None:
    for scope in (EvidenceScope.BATCH_REFERENCE, EvidenceScope.LEGACY_UNSPECIFIED):
        endpoint = _endpoint(scope)
        endpoint.enrichment["runtime"] = {
            "target_attributed": True,
            "has_payload": True,
        }

        runtime = _runtime_info(endpoint)
        layer = _runtime_layer(endpoint)

        assert runtime == {"observed": False}, scope
        assert layer["status"] == CLOSURE_FAILED
        assert layer["evidence"]["sources"] == []

    endpoint = _endpoint(EvidenceScope.CASE_EVIDENCE)
    endpoint.enrichment["runtime"] = {"target_attributed": True, "has_payload": True}
    assert _runtime_info(endpoint)["observed"] is True
    assert _runtime_layer(endpoint)["status"] == CLOSURE_COMPLETE


def test_endpoint_dedup_keeps_case_evidence_after_same_batch_signature() -> None:
    batch = Endpoint(
        value="backend.example",
        kind="domain",
        evidences=[
            Evidence(
                source="runtime-pcap",
                location="capture.pcap",
                snippet="same",
                scope=EvidenceScope.BATCH_REFERENCE,
            )
        ],
    )
    direct = Endpoint(
        value=batch.value,
        kind=batch.kind,
        evidences=[
            Evidence(
                source="runtime-pcap",
                location="capture.pcap",
                snippet="same",
                scope=EvidenceScope.CASE_EVIDENCE,
            )
        ],
    )

    merged = pipeline._dedup_endpoints([batch, direct])

    assert has_case_evidence(merged[0].evidences)
    assert {evidence.scope for evidence in merged[0].evidences} == {
        EvidenceScope.BATCH_REFERENCE,
        EvidenceScope.CASE_EVIDENCE,
    }


def test_runtime_endpoint_dict_merge_dedups_with_scope_in_signature() -> None:
    def endpoint(scope: str) -> dict:
        return {
            "value": "203.0.113.9",
            "kind": "ip",
            "evidences": [
                {
                    "source": "runtime-pcap",
                    "location": "pcap",
                    "snippet": "same",
                    "scope": scope,
                }
            ],
            "enrichment": {"runtime": {"remote_endpoints": ["203.0.113.9:443"]}},
        }

    payload = {"endpoints": [endpoint("batch_reference")]}

    _merge_runtime_endpoint_dicts(payload, [endpoint("case_evidence")])

    scopes = {evidence.get("scope") for evidence in payload["endpoints"][0]["evidences"]}
    assert scopes == {"batch_reference", "case_evidence"}


def _runtime_lead(scope: EvidenceScope, source: str = "runtime-pcap") -> Lead:
    return Lead(
        category=LeadCategory.DOMAIN,
        value="backend.example",
        confidence=Confidence.HIGH,
        source_refs=[Evidence(source=source, location="capture.pcap", scope=scope)],
    )


def test_runtime_seen_requires_case_evidence_scope() -> None:
    """★ 缺锁补回：``is_runtime_seen`` 的 scope 门此前无任何测试覆盖。

    实测过：把该属性里的 ``ev.scope is CASE_EVIDENCE`` 整条删掉（退回未分层的旧行为），
    全仓测试无一变红。这两个属性是报告徽标「运行时出现」/「确认 C2」的唯一判据，
    门一旦失守，跨批次参考材料就会被渲染成当前直接观测。
    """
    assert _runtime_lead(EvidenceScope.CASE_EVIDENCE).is_runtime_seen is True
    assert _runtime_lead(EvidenceScope.BATCH_REFERENCE).is_runtime_seen is False
    assert _runtime_lead(EvidenceScope.LEGACY_UNSPECIFIED).is_runtime_seen is False


def test_runtime_contact_requires_case_evidence_scope() -> None:
    """严一档的 observed-contact 同样只认当前案件直接证据。"""
    assert _runtime_lead(EvidenceScope.CASE_EVIDENCE).is_runtime_contact is True
    assert _runtime_lead(EvidenceScope.BATCH_REFERENCE).is_runtime_contact is False
    assert _runtime_lead(EvidenceScope.LEGACY_UNSPECIFIED).is_runtime_contact is False
    # 非 observed-contact 的 runtime* 来源即便 scope 合格也只到 seen，不算 contact。
    derived = _runtime_lead(EvidenceScope.CASE_EVIDENCE, source="runtime-derived")
    assert derived.is_runtime_seen is True
    assert derived.is_runtime_contact is False


def _scoped_endpoint(kind: str, value: str, scope: EvidenceScope) -> Endpoint:
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(source="dex", location="classes.dex", scope=scope)],
    )


def test_ip_lead_scope_downgrade_is_wired_in_real_entry_point() -> None:
    """★ 缺锁补回：IP 侧的作用域降档在真入口上此前无锁。

    实测过：把 ``leads.py`` 里 IP 分支那行 ``_apply_evidence_scope(lead, ep)`` 整行删掉，
    全仓 5118 条测试无一变红——domain 那一路有锁，IP 这一路没有。本仓纪律是
    「只调被测函数的单测永远测不到接线」，故这条走 :func:`build_endpoint_leads` 真入口。
    """
    [direct] = build_endpoint_leads(
        [_scoped_endpoint("ip", "100.64.10.20", EvidenceScope.CASE_EVIDENCE)], online=False
    )
    assert DOWNGRADE_EVIDENCE_SCOPE not in direct.downgrades

    for scope in (EvidenceScope.BATCH_REFERENCE, EvidenceScope.LEGACY_UNSPECIFIED):
        [lead] = build_endpoint_leads([_scoped_endpoint("ip", "100.64.10.20", scope)], online=False)
        assert DOWNGRADE_EVIDENCE_SCOPE in lead.downgrades, scope


def test_domain_lead_scope_downgrade_is_wired_in_real_entry_point() -> None:
    """domain 那一路同样从真入口锁一次，两个分支对称，避免只剩单侧有锁再次发生。"""
    [direct] = build_endpoint_leads(
        [_scoped_endpoint("domain", "backend.example", EvidenceScope.CASE_EVIDENCE)], online=False
    )
    assert DOWNGRADE_EVIDENCE_SCOPE not in direct.downgrades

    for scope in (EvidenceScope.BATCH_REFERENCE, EvidenceScope.LEGACY_UNSPECIFIED):
        [lead] = build_endpoint_leads(
            [_scoped_endpoint("domain", "backend.example", scope)], online=False
        )
        assert DOWNGRADE_EVIDENCE_SCOPE in lead.downgrades, scope
