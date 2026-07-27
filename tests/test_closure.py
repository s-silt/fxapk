from __future__ import annotations

from apkscan.core import closure as closure_module
from apkscan.core.closure import sources as closure_sources
from apkscan.core.closure import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    CLOSURE_PARTIAL,
    LAYER_NAMES,
    ClosureConfig,
    assemble_target_closure,
    close_report,
    evaluate_capture_quality,
    evaluate_closure,
    select_targets,
)
from apkscan.core.models import (
    Confidence,
    Endpoint,
    EnrichmentResult,
    Evidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.core.registry import BaseEnricher


def _endpoint(
    value: str,
    *,
    kind: str = "ip",
    runtime: bool = False,
    target: bool = False,
    payload: bool = False,
    sni: bool = False,
    enrichment: dict | None = None,
) -> Endpoint:
    source = "runtime" if runtime else "dex"
    merged_enrichment = dict(enrichment or {})
    if runtime:
        merged_enrichment["runtime"] = {
            "target_attributed": target,
            "has_payload": payload,
            "sni": "api.example.test" if sni else None,
        }
    return Endpoint(
        value=value,
        kind=kind,
        evidences=[Evidence(source=source, location="synthetic", snippet=value)],
        is_suspicious=True,
        enrichment=merged_enrichment,
    )


def _report(*endpoints: Endpoint) -> Report:
    leads = [
        Lead(
            category=LeadCategory.IP if ep.kind == "ip" else LeadCategory.DOMAIN,
            value=ep.value,
            confidence=Confidence.HIGH,
            source_refs=list(ep.evidences),
            advice="建议调证",
        )
        for ep in endpoints
    ]
    return Report(
        package_name="com.example.synthetic",
        meta={},
        leads=leads,
        endpoints=list(endpoints),
        findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )


def _complete_endpoint() -> Endpoint:
    return _endpoint(
        "198.51.100.10",
        runtime=True,
        target=True,
        payload=True,
        enrichment={
            "ip_rdap": {
                "netname": "EXAMPLE-NET",
                "org": "Example Registry Ltd",
                "country": "US",
                "handle": "NET-198-51-100-0-1",
                "cidr": "198.51.100.0/24",
            },
            "ripestat_bgp": {
                "origin_asn": 64500,
                "asn_holder": "Example Network Ltd",
                "prefix": "198.51.100.0/24",
                "upstreams": [64501],
            },
            "asn": {
                "asn": "AS64500",
                "org": "Example Hosting Ltd",
                "isp": "Example Hosting Ltd",
                "country": "US",
            },
            "shodan": {
                "org": "Example Hosting Ltd",
                "ports": [443],
                "services": [{"port": 443, "product": "nginx"}],
            },
            "source_status": {
                "ip_rdap": {"status": "hit"},
                "ripestat_bgp": {"status": "hit"},
                "shodan": {"status": "hit"},
                "urlscan": {"status": "no_record"},
            },
        },
    )


def _complete_ip_endpoint(value: str) -> Endpoint:
    """A five-layer-complete IP endpoint at ``value`` (fresh enrichment tree per call)."""
    template = _complete_endpoint()
    return _endpoint(value, runtime=True, target=True, payload=True, enrichment=template.enrichment)


def test_select_targets_with_stats_reports_truncation() -> None:
    report = _report(*[_complete_ip_endpoint(f"198.51.100.1{n}") for n in range(7)])

    selected, stats = closure_module._select_targets_with_stats(report, 6)

    assert [ep.value for ep in selected] == [f"198.51.100.1{n}" for n in range(6)]
    assert stats == {
        "candidate_total": 7,
        "selected": 6,
        "limit": 6,
        "truncated": 1,
        "dropped": ["198.51.100.16"],
    }


def test_close_report_truncated_targets_yield_partial_with_gap() -> None:
    report = _report(*[_complete_ip_endpoint(f"198.51.100.1{n}") for n in range(7)])

    closure = close_report(report, ClosureConfig(online=False, require_dynamic=False), enrichers=[])

    assert closure["status"] == CLOSURE_PARTIAL
    assert len(closure["targets"]) == 6
    assert closure["target_selection"] == {
        "candidate_total": 7,
        "selected": 6,
        "limit": 6,
        "truncated": 1,
        "dropped": ["198.51.100.16"],
    }
    assert any("198.51.100.16" in str(gap) for gap in closure["gaps"])


def test_close_report_untruncated_targets_stay_complete() -> None:
    report = _report(_complete_ip_endpoint("198.51.100.10"), _complete_ip_endpoint("198.51.100.11"))

    closure = close_report(report, ClosureConfig(online=False, require_dynamic=False), enrichers=[])

    assert closure["status"] == CLOSURE_COMPLETE
    assert closure["gaps"] == []
    assert closure["target_selection"]["truncated"] == 0
    assert closure["target_selection"]["candidate_total"] == closure["target_selection"]["selected"] == 2


def test_select_targets_prioritizes_target_attributed_runtime_endpoint() -> None:
    report = _report(
        _endpoint("198.51.100.30", runtime=False),
        _endpoint("198.51.100.20", runtime=True, target=True),
        _endpoint("198.51.100.10", runtime=True, payload=True, sni=True),
    )

    selected = select_targets(report, max_targets=2)

    assert [ep.value for ep in selected] == ["198.51.100.20", "198.51.100.10"]


def test_select_targets_is_stable_and_deduplicates_domain_case() -> None:
    upper = _endpoint("API.EXAMPLE.TEST", kind="domain", runtime=True)
    lower = _endpoint("api.example.test", kind="domain", runtime=True)
    report = _report(upper, lower, _endpoint("198.51.100.10", runtime=True))

    first = [ep.value for ep in select_targets(report, max_targets=6)]
    second = [ep.value for ep in select_targets(report, max_targets=6)]

    assert first == second
    assert len([value for value in first if value.lower() == "api.example.test"]) == 1


def test_capture_channel_without_packets_is_failed() -> None:
    quality = evaluate_capture_quality(
        {"channel_ready": True, "pcap_valid": False, "packet_count": 0}
    )

    assert quality["dynamic_status"] == CLOSURE_FAILED


def test_capture_business_candidate_without_target_attribution_is_partial() -> None:
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 0,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL


def test_capture_quality_distinguishes_floor_parse_failure_from_zero_traffic() -> None:
    """★回归（codex 复核 P1）：floor pcap 解析失败要在动态质量里与真实零业务流量区分（reason + floor_parse_status），
    否则 case-close/操作员无法区分「要重抓」与「真无业务流量」。"""
    failed = evaluate_capture_quality(
        {"channel_ready": True, "packet_count": 0, "business_candidate_count": 0, "floor_parse_status": "parse_error"}
    )
    assert failed["dynamic_status"] == CLOSURE_FAILED
    assert "parse failed" in str(failed["reason"]) and failed["floor_parse_status"] == "parse_error"
    zero = evaluate_capture_quality(
        {"channel_ready": True, "packet_count": 0, "business_candidate_count": 0, "floor_parse_status": "ok"}
    )
    assert zero["dynamic_status"] == CLOSURE_FAILED and "parse failed" not in str(zero["reason"])


def test_capture_target_attributed_candidate_is_complete() -> None:
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
            "bidirectional_business_count": 1,
            # 双向载荷就落在那个已归因到目标 App 的端点上——这才是闭环。
            "bidirectional_target_count": 1,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_COMPLETE


def test_capture_bidirectional_on_a_different_endpoint_is_not_complete() -> None:
    """★有双向载荷、也有归因端点，但两者不是同一个 → 不算闭环。

    代理是整机级的，所以「有往返」可能来自别的 App。分别判断两个汇总值 > 0 时，
    目标 App 的单向端点 + 无关端点的往返会拼出一个假 complete。
    """
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
            "bidirectional_business_count": 1,   # 有往返
            "bidirectional_target_count": 0,     # 但不在归因端点上
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL
    assert "same endpoint" in str(quality["reason"])


def test_capture_missing_target_bidirectional_field_fails_closed() -> None:
    """★两个可信字段都缺时按 0 处理，降 partial 而非放行。

    延续本模块既有纪律：宁可把已闭环说成未闭环（多跑一次采集），
    不可把未闭环说成已闭环（据以结案）。这也堵住了"手编三个旧汇总字段即 complete"的口子——
    bidirectional_business_count 含未归因的 mitm 端点，**不能**用作回退依据。
    """
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
            "bidirectional_business_count": 1,
            # 既无 bidirectional_target_count，也无 bidirectional_floor_count
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL


def test_capture_legacy_floor_count_still_completes() -> None:
    """兼容早于新字段的 runtime_report：floor 侧计数口径与新字段一致，可安全回退。

    floor_bidirectional 本就是「归因到目标 **且** 双向有载荷」，即同一端点上两条件都成立。
    不做这层回退，存量运行时报告会被整体误降为未闭环，逼人重跑本已成功的采集。
    """
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
            "bidirectional_business_count": 1,
            "bidirectional_floor_count": 1,   # 旧字段，语义等价
        }
    )

    assert quality["dynamic_status"] == CLOSURE_COMPLETE


def test_capture_one_way_traffic_is_not_complete() -> None:
    """★真样本回归：目标 UID 只向公共解析器发过 DNS query（出站 ~6KB、入站 0B），
    两案都被判 complete —— 人工结论是动态未闭环。归因到目标 ≠ 与后端通信过。
    """
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 42,
            "business_candidate_count": 3,
            "target_attributed_count": 3,
            "bidirectional_business_count": 0,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL
    assert "bidirectional" in str(quality["reason"])


def test_capture_quality_missing_bidirectional_field_fails_closed() -> None:
    """字段缺失（老 runtime_report）不得当成"有双向证据"——宁可降级 partial 也不误判闭环。"""
    quality = evaluate_capture_quality(
        {
            "channel_ready": True,
            "pcap_valid": True,
            "packet_count": 12,
            "business_candidate_count": 2,
            "target_attributed_count": 1,
        }
    )

    assert quality["dynamic_status"] == CLOSURE_PARTIAL


def test_assemble_target_closure_builds_all_investigation_layers() -> None:
    target = assemble_target_closure(_complete_endpoint())

    assert set(target["layers"]) == set(LAYER_NAMES)
    assert all(layer["status"] == CLOSURE_COMPLETE for layer in target["layers"].values())
    assert target["layers"]["resource_registration"]["evidence"]["cidr"] == "198.51.100.0/24"
    assert target["layers"]["request_target"]["evidence"]["provider"] == "Example Hosting Ltd"
    assert target["status"] == CLOSURE_COMPLETE


def test_registration_without_country_or_handle_stays_partial() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["ip_rdap"].pop("country")
    endpoint.enrichment["ip_rdap"].pop("handle")

    target = assemble_target_closure(endpoint)

    assert target["layers"]["resource_registration"]["status"] == CLOSURE_PARTIAL
    assert target["status"] == CLOSURE_PARTIAL


def test_registration_does_not_treat_bare_start_address_as_cidr() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["ip_rdap"]["cidr"] = "198.51.100.0"

    target = assemble_target_closure(endpoint)

    assert target["layers"]["resource_registration"]["status"] == CLOSURE_PARTIAL
    assert target["status"] == CLOSURE_PARTIAL


def test_bgp_without_upstream_evidence_stays_partial() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["ripestat_bgp"].pop("upstreams")

    target = assemble_target_closure(endpoint)

    assert target["layers"]["bgp_announcement"]["status"] == CLOSURE_PARTIAL
    assert target["status"] == CLOSURE_PARTIAL


def test_parent_asn_and_bare_port_cannot_complete_hosting_or_request_layers() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["shodan"] = {
        "org": "Example Hosting Ltd",
        "ports": [443],
        "services": [{"port": 443}],
    }
    endpoint.enrichment["attribution"] = {
        "hosting_provider": {
            "name": "Example Hosting Ltd",
            "matched_signals": ["origin_asn_category"],
        }
    }

    target = assemble_target_closure(endpoint)

    assert target["layers"]["hosting_delivery"]["status"] == CLOSURE_PARTIAL
    assert target["layers"]["request_target"]["status"] == CLOSURE_PARTIAL
    assert target["status"] == CLOSURE_PARTIAL


def test_fofa_product_evidence_can_complete_hosting_without_shodan() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment.pop("shodan")
    endpoint.enrichment["fofa"] = {
        "records": [
            [
                "https://api.example.test",
                "198.51.100.10",
                443,
                "https",
                "Example API",
                "nginx",
                "US",
                "California",
                "Los Angeles",
                64500,
                "FOFA Hosting Ltd",
            ]
        ],
        "count": 1,
        "source": "fofa",
    }

    target = assemble_target_closure(endpoint)

    hosting = target["layers"]["hosting_delivery"]
    assert hosting["status"] == CLOSURE_COMPLETE
    assert hosting["evidence"]["provider"] == "FOFA Hosting Ltd"
    assert hosting["evidence"]["services"][0]["server"] == "nginx"
    assert target["layers"]["request_target"]["status"] == CLOSURE_COMPLETE
    assert target["status"] == CLOSURE_COMPLETE


def test_fofa_fields_match_enricher_query_no_drift() -> None:
    """★codex #3 漂移守卫：closure 的 FOFA 字段序必须与富化器查询串逐字段一致，否则命名解析会错位。"""
    from apkscan.core import closure as _closure
    from apkscan.enrichers.multisource import FOFA_QUERY_FIELDS

    assert ",".join(_closure._FOFA_FIELDS) == FOFA_QUERY_FIELDS


def test_fofa_malformed_row_skipped_not_misparsed() -> None:
    """★FOFA 行字段数与预期不符（改列/查询漂移）→ 跳过该行，不按错位下标取值污染归属。"""
    from apkscan.core.closure import _parse_fofa_row

    assert _parse_fofa_row(["only", "three", "fields"]) is None      # 太短
    assert _parse_fofa_row(list(range(20))) is None                   # 太长
    assert _parse_fofa_row("not a list") is None
    ok = _parse_fofa_row([
        "h", "1.2.3.4", 443, "https", "t", "nginx", "US", "CA", "LA", 64500, "Org Ltd",
    ])
    assert ok is not None
    assert ok["as_organization"] == "Org Ltd" and ok["port"] == 443 and ok["server"] == "nginx"


def test_fofa_malformed_row_does_not_pollute_closure() -> None:
    """畸形 FOFA 行不得让归属层拿到错位的 provider/port。"""
    endpoint = _complete_endpoint()
    endpoint.enrichment.pop("shodan")
    endpoint.enrichment["fofa"] = {"records": [["h", "1.2.3.4", 443]], "count": 1}  # 只有 3 字段
    target = assemble_target_closure(endpoint)
    # 畸形行被跳过 → hosting 不会拿到错位 provider（回到无 fofa 证据的状态）
    hosting = target["layers"]["hosting_delivery"]
    assert hosting["evidence"].get("provider") != 443  # 绝不把 port 当 provider


def test_unconfirmed_origin_candidate_cannot_satisfy_cdn_origin_gate() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["attribution"] = {
        "edge_provider": {"name": "Example Edge"},
        "hosting_provider": {
            "name": "Example Hosting Ltd",
            "matched_signals": ["shodan_org"],
        },
    }
    endpoint.enrichment["origin_candidates"] = ["203.0.113.20"]

    target = assemble_target_closure(endpoint)

    assert target["origin"]["status"] == "missing"
    assert target["layers"]["request_target"]["evidence"]["provider"] == "Example Edge"
    assert "origin configuration" in target["layers"]["request_target"]["evidence"][
        "evidence_fields"
    ]
    assert "origin" in target["gaps"]
    assert target["status"] == CLOSURE_PARTIAL


def test_confirmed_origin_without_origin_provider_keeps_request_partial() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["attribution"] = {
        "edge_provider": {"name": "Example Edge"},
        "hosting_provider": {
            "name": "Example Hosting Ltd",
            "matched_signals": ["shodan_org"],
        },
    }
    endpoint.enrichment["origin"] = {
        "ip": "203.0.113.20",
        "confirmed": True,
        "source": "passive_dns",
    }

    target = assemble_target_closure(endpoint)

    assert target["origin"]["status"] == CLOSURE_COMPLETE
    assert target["layers"]["request_target"]["status"] == CLOSURE_PARTIAL
    assert target["status"] == CLOSURE_PARTIAL


def test_confirmed_origin_uses_origin_provider_as_request_target() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["attribution"] = {
        "edge_provider": {"name": "Example Edge"},
        "hosting_provider": {
            "name": "Example Hosting Ltd",
            "matched_signals": ["shodan_org"],
        },
    }
    endpoint.enrichment["origin"] = {
        "ip": "203.0.113.20",
        "confirmed": True,
        "source": "passive_dns",
        "provider": "Origin Host Ltd",
    }

    target = assemble_target_closure(endpoint)

    request = target["layers"]["request_target"]
    assert request["status"] == CLOSURE_COMPLETE
    assert request["evidence"]["provider"] == "Origin Host Ltd"
    assert request["evidence"]["origin_ip"] == "203.0.113.20"
    assert target["status"] == CLOSURE_COMPLETE


def test_cdn_without_origin_cannot_be_complete() -> None:
    report = _report(_complete_endpoint())
    target = assemble_target_closure(report.endpoints[0])
    target["origin"] = {"required": True, "status": "missing"}

    closure = evaluate_closure(report, [target], require_dynamic=False)

    assert closure["status"] == CLOSURE_PARTIAL
    assert "origin" in " ".join(closure["gaps"]).lower()


def test_static_critical_failure_makes_closure_failed() -> None:
    report = _report(_complete_endpoint())
    report.analysis_status = "partial"
    report.critical_failures = ["manifest"]

    closure = evaluate_closure(
        report,
        [assemble_target_closure(report.endpoints[0])],
        require_dynamic=False,
    )

    assert closure["status"] == CLOSURE_FAILED
    assert closure["checks"][0]["id"] == "static_health"
    assert closure["checks"][0]["status"] == "fail"


def test_passive_mode_blocked_active_source_does_not_prevent_completion() -> None:
    report = _report(_complete_endpoint())
    target = assemble_target_closure(report.endpoints[0])
    target["source_status"]["active_fake"] = {
        "status": "skipped",
        "reason": "active_mode_blocked",
    }

    closure = evaluate_closure(report, [target], require_dynamic=False)

    assert closure["status"] == CLOSURE_COMPLETE


def _blind_assessment() -> dict:
    """壳桩样本的可见性求值（DEX 只看得到壳桩 → 端点穷尽性无资格下）。"""
    from apkscan.core import visibility

    return visibility.assess({"meta": {"is_hardened": True}})


def test_static_only_targets_blocked_when_dex_invisible() -> None:
    """★目标靠静态提取、而静态输入不可见 → 目标集合可能压根不全，说"闭环完成"站不住。

    真 C2 可能就藏在看不见的 DEX 里，此时选出的目标只是"看得见的那部分"。
    """
    report = _report(_complete_endpoint())
    report.meta["visibility"] = _blind_assessment()

    closure = evaluate_closure(
        report, [assemble_target_closure(report.endpoints[0])], require_dynamic=False
    )

    assert closure["status"] == CLOSURE_PARTIAL
    assert any("target set may be incomplete" in g for g in closure["gaps"])
    vis_check = next(c for c in closure["checks"] if c["id"] == "evidence_visibility")
    assert vis_check["status"] == "warn"


def test_runtime_attributed_targets_not_downgraded_by_static_blindness() -> None:
    """★★不为一个穷尽性疑问，把已坐实的动态证据降级。

    目标由运行时唯一归因确认（pcap 实测连接 + socket/UID 归到本 app）时，DEX 看不看得见
    都不影响这个目标本身。全局一刀切封顶会把真实、可办案的动态证据一起拖下水——
    这正是"按主张相关性消费"要防的。
    """
    report = _report(_complete_endpoint())
    report.meta["visibility"] = _blind_assessment()
    target = assemble_target_closure(report.endpoints[0])
    target["runtime"] = {"status": CLOSURE_COMPLETE, "evidence": {"target_attributed": True}}

    closure = evaluate_closure(report, [target], require_dynamic=False)

    assert closure["status"] == CLOSURE_COMPLETE, "运行时已坐实的目标被静态盲区误伤了"
    assert not any("target set may be incomplete" in g for g in closure["gaps"])
    vis_check = next(c for c in closure["checks"] if c["id"] == "evidence_visibility")
    assert vis_check["status"] == "warn"           # 仍如实告知盲区
    assert "runtime-attributed" in vis_check["reason"]


def test_visible_report_passes_visibility_check() -> None:
    from apkscan.core import visibility

    report = _report(_complete_endpoint())
    report.meta["visibility"] = visibility.assess({"meta": {"dex_available": True}})

    closure = evaluate_closure(
        report, [assemble_target_closure(report.endpoints[0])], require_dynamic=False
    )

    assert closure["status"] == CLOSURE_COMPLETE
    vis_check = next(c for c in closure["checks"] if c["id"] == "evidence_visibility")
    assert vis_check["status"] == "pass"


def test_old_report_without_visibility_is_not_applicable() -> None:
    """旧报告没有该字段 → not_applicable，不得凭空降级（也不得凭空放行成 pass）。"""
    report = _report(_complete_endpoint())
    closure = evaluate_closure(
        report, [assemble_target_closure(report.endpoints[0])], require_dynamic=False
    )
    vis_check = next(c for c in closure["checks"] if c["id"] == "evidence_visibility")
    assert vis_check["status"] == "not_applicable"
    assert closure["status"] == CLOSURE_COMPLETE


def test_monkeypatch_target_differs_by_caller() -> None:
    """★拆包后 monkeypatch 打哪里分两类、方向相反，打错一边会**静默失效**（测试仍绿却不测了）。

    判据是「谁调用它」：被 __init__ 的 close_report 直调的，调用时按 __init__ 的模块命名空间
    解析，必须 patch 包；只在子模块内部互调的，必须 patch 定义它的子模块。
    本测试把这个分界钉住——注释被改坏或函数被挪到另一类时，这里会红。
    """
    from apkscan.core import closure as pkg
    from apkscan.core.closure import gates, layers, sources, targets

    def _global_names(code: object) -> set[str]:
        """收集 code 对象及其**嵌套** code 对象引用的全局名。

        ★必须递归：Python 3.12 起（PEP 709）把推导式内联进外层函数，其引用的名字会出现在外层
        co_names 里；3.11 仍为推导式建独立 code object，同一份代码两版结果不同。只读顶层
        co_names 会让本测试的判据跟解释器版本走——本地 3.12 绿、CI 的 3.11 红。
        """
        names = set(getattr(code, "co_names", ()))
        for const in getattr(code, "co_consts", ()):
            if hasattr(const, "co_names"):
                names |= _global_names(const)
        return names

    # 名字出现在 close_report（含其推导式）引用的全局名里 = 经 __init__ 命名空间解析 → 须 patch 包
    called_by_close_report = _global_names(pkg.close_report.__code__)

    patch_package = {
        "_select_targets_with_stats", "assemble_target_closure",
        "_ensure_source_status_coverage", "_enrich_resolved_ips",
        "_set_attribution", "evaluate_closure",
    }
    patch_submodule = {
        "_normalized_public_ip", "_resolved_ips", "_is_known_intercept_ip",
        "_normalize_source_status", "_runtime_info", "evaluate_capture_quality",
    }

    for name in patch_package:
        assert name in called_by_close_report, (
            f"{name} 已不再被 close_report 直调；它的 patch 方式变了，"
            f"__init__.py 顶部的指引注释与本测试都要同步更新"
        )
    for name in patch_submodule:
        assert name not in called_by_close_report, (
            f"{name} 现在被 close_report 直调了 → patch 子模块会失效，须改 patch 包"
        )

    # 两类名字都必须仍能从包导入（re-export 面不得回退）
    for name in patch_package | patch_submodule:
        assert hasattr(pkg, name), f"包的属性面丢了 {name}，既有测试的 patch 会 AttributeError"
    for mod in (sources, layers, targets, gates):
        assert mod.__name__.startswith("apkscan.core.closure.")


def test_incidentally_imported_names_stay_off_the_package_surface() -> None:
    """★原模块"顺带导入"的名字不再从包可见——这是**有意的**，别当遗漏补回来。

    拆分前 `from apkscan.core.closure import os` 之类能用，纯属旧单文件模块的 import 副作用。
    从别人模块借 import 是坏习惯，re-export 回来等于把它固化成契约。实测全仓零处这样用。
    """
    from apkscan.core import closure as pkg

    for name in ("os", "ipaddress", "Counter", "dataclass", "Any", "Endpoint",
                 "ANALYSIS_MODES", "ANALYSIS_MODE_PASSIVE",
                 "ANALYSIS_STATUS_COMPLETE", "ANALYSIS_STATUS_FAILED"):
        assert not hasattr(pkg, name), (
            f"{name} 又出现在包的属性面上了——它不是 closure 的 API，"
            f"若确需使用请从其定义处导入"
        )


def test_closure_config_rejects_non_positive_target_limit() -> None:
    try:
        ClosureConfig(max_targets=0)
    except ValueError as exc:
        assert "max_targets" in str(exc)
    else:
        raise AssertionError("ClosureConfig accepted max_targets=0")


class _FakeEnricher(BaseEnricher):
    def __init__(self, name: str, applies_to: list[str], data: dict) -> None:
        self.name = name
        self.applies_to = applies_to
        self.data = data
        self.calls: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls.append(ep.value)
        return EnrichmentResult(provider=self.name, ok=True, data=dict(self.data))


def _full_ip_enrichers() -> list[_FakeEnricher]:
    return [
        _FakeEnricher(
            "ip_rdap",
            ["ip"],
            {
                "netname": "EXAMPLE-NET",
                "org": "Example Registry Ltd",
                "country": "US",
                "handle": "NET-198-51-100-0-1",
                "cidr": "198.51.100.0/24",
            },
        ),
        _FakeEnricher(
            "ripestat_bgp",
            ["ip"],
            {
                "origin_asn": 64500,
                "asn_holder": "Example Network Ltd",
                "prefix": "198.51.100.0/24",
                "upstreams": [64501],
            },
        ),
        _FakeEnricher(
            "asn",
            ["ip"],
            {
                "asn": "AS64500",
                "org": "Example Hosting Ltd",
                "country": "US",
            },
        ),
        _FakeEnricher(
            "shodan",
            ["ip"],
            {
                "org": "Example Hosting Ltd",
                "ports": [443],
                "services": [{"port": 443, "product": "nginx"}],
            },
        ),
    ]


def test_close_report_reenriches_runtime_ip_and_writes_closure() -> None:
    endpoint = _endpoint(
        "198.51.100.10",
        runtime=True,
        target=True,
        payload=True,
    )
    report = _report(endpoint)
    enrichers = _full_ip_enrichers()

    closure = close_report(
        report,
        ClosureConfig(online=True, require_dynamic=False),
        enrichers=enrichers,
    )

    assert closure["status"] == CLOSURE_COMPLETE
    assert report.meta["closure"] is closure
    assert endpoint.enrichment["ip_rdap"]["netname"] == "EXAMPLE-NET"
    assert endpoint.enrichment["ripestat_bgp"]["origin_asn"] == 64500
    assert all(enricher.calls == ["198.51.100.10"] for enricher in enrichers)
    assert report.leads[0].where_to_request == "Example Hosting Ltd"
    assert "tenant identity" in report.leads[0].evidence_to_obtain


def test_close_report_is_idempotent_and_preserves_analyst_notes() -> None:
    endpoint = _complete_endpoint()
    report = _report(endpoint)
    report.leads[0].notes = "Analyst note must remain unchanged."

    first = close_report(
        report,
        ClosureConfig(online=False, require_dynamic=False),
        enrichers=[],
    )
    first_notes = report.leads[0].notes
    first_evidence = list(report.leads[0].evidence_to_obtain)
    second = close_report(
        report,
        ClosureConfig(online=False, require_dynamic=False),
        enrichers=[],
    )

    assert second == first
    assert report.leads[0].notes == first_notes
    assert report.leads[0].notes.startswith("Analyst note must remain unchanged.")
    assert report.leads[0].evidence_to_obtain == first_evidence


def test_domain_target_enriches_each_resolved_ip(monkeypatch) -> None:  # noqa: ANN001
    # patch 定义 _normalized_public_ip 的子模块（closure.sources）——patch 包属性改不到实际调用点；
    # 不带 raising=False：函数若再被挪走，这里立刻 AttributeError 变红，而非静默失效。
    monkeypatch.setattr(
        closure_sources,
        "_normalized_public_ip",
        lambda value: str(value).strip(),
    )
    domain = _endpoint(
        "api.example.test",
        kind="domain",
        runtime=True,
        target=True,
        payload=True,
    )
    report = _report(domain)
    dns = _FakeEnricher("dns", ["domain"], {"ips": ["198.51.100.10"], "cname": []})
    ip_enrichers = _full_ip_enrichers()

    closure = close_report(
        report,
        ClosureConfig(online=True, require_dynamic=False),
        enrichers=[dns, *ip_enrichers],
    )

    resolved = domain.enrichment["resolved_ip_enrichment"]["198.51.100.10"]
    assert resolved["ip_rdap"]["netname"] == "EXAMPLE-NET"
    assert resolved["ripestat_bgp"]["origin_asn"] == 64500
    assert closure["targets"][0]["resolved_ips"] == ["198.51.100.10"]
    assert closure["targets"][0]["layers"]["resource_registration"]["status"] == CLOSURE_COMPLETE
    assert all(enricher.calls == ["198.51.100.10"] for enricher in ip_enrichers)


def test_close_report_top_level_attribution_absorbs_resolved_evidence(monkeypatch) -> None:  # noqa: ANN001
    """close_report 后顶层 enrichment.attribution 吸收逐 IP 富化的 resource_holder（P1-3：顶层归因在
    _enrich_resolved_ips 之后重建，且 build_endpoint_attribution 域名分支读 resolved_ip_enrichment，
    否则闭环后拿到的 RDAP/BGP 证据只留在嵌套结构，文书/摘要读顶层 attribution 恒 unknown）。"""
    monkeypatch.setattr(
        closure_sources, "_normalized_public_ip", lambda value: str(value).strip()
    )
    domain = _endpoint("api.example.test", kind="domain", runtime=True, target=True, payload=True)
    report = _report(domain)
    dns = _FakeEnricher("dns", ["domain"], {"ips": ["198.51.100.10"], "cname": []})
    ip_enrichers = _full_ip_enrichers()

    close_report(report, ClosureConfig(online=True, require_dynamic=False), enrichers=[dns, *ip_enrichers])

    ip_layer = domain.enrichment["attribution"]["ips"][0]
    assert ip_layer["resource_holder"]["name"] == "EXAMPLE-NET"  # 来自 resolved 的 ip_rdap，吸收进顶层
    assert ip_layer["resource_holder"]["confidence"] == "high"
    assert ip_layer["origin_network"]["asn"] == 64500  # origin/hosting 层未退化


def test_domain_resolved_ip_enrichment_is_bounded(monkeypatch) -> None:  # noqa: ANN001
    # patch 定义 _normalized_public_ip 的子模块（closure.sources）——patch 包属性改不到实际调用点；
    # 不带 raising=False：函数若再被挪走，这里立刻 AttributeError 变红，而非静默失效。
    monkeypatch.setattr(
        closure_sources,
        "_normalized_public_ip",
        lambda value: str(value).strip(),
    )
    domain = _endpoint(
        "api.example.test",
        kind="domain",
        runtime=True,
        target=True,
        payload=True,
    )
    report = _report(domain)
    addresses = [f"198.51.100.{value}" for value in range(1, 13)]
    dns = _FakeEnricher("dns", ["domain"], {"ips": addresses, "cname": []})
    ip_enricher = _FakeEnricher("ip_rdap", ["ip"], {"netname": "EXAMPLE-NET"})

    closure = close_report(
        report,
        ClosureConfig(online=True, require_dynamic=False),
        enrichers=[dns, ip_enricher],
    )

    assert len(ip_enricher.calls) == 8
    assert len(closure["targets"][0]["resolved_ips"]) == 8
    assert closure["targets"][0]["resolved_ip_selection"]["truncated"] == 4
    assert "resolved_ip_limit" in closure["targets"][0]["gaps"]
    assert closure["status"] == CLOSURE_PARTIAL


def test_domain_resolution_excludes_nonpublic_and_invalid_addresses() -> None:
    domain = _endpoint(
        "api.example.test",
        kind="domain",
        runtime=True,
        target=True,
        payload=True,
        enrichment={"dns": {"ips": ["10.0.0.2", "not-an-ip"]}},
    )
    report = _report(domain)
    enricher = _FakeEnricher("ip_rdap", ["ip"], {"netname": "MUST-NOT-RUN"})

    close_report(
        report,
        ClosureConfig(online=True, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == []
    assert domain.enrichment["resolved_ip_selection"]["excluded_nonpublic"] == 2


def test_domain_resolution_excludes_known_intercept_address(monkeypatch) -> None:  # noqa: ANN001
    # patch 定义 _normalized_public_ip 的子模块（closure.sources）——patch 包属性改不到实际调用点；
    # 不带 raising=False：函数若再被挪走，这里立刻 AttributeError 变红，而非静默失效。
    monkeypatch.setattr(
        closure_sources,
        "_normalized_public_ip",
        lambda value: str(value).strip(),
    )
    monkeypatch.setattr(
        closure_sources,
        "_is_known_intercept_ip",
        lambda value: value == "198.51.100.20",
    )
    domain = _endpoint(
        "api.example.test",
        kind="domain",
        runtime=True,
        target=True,
        payload=True,
        enrichment={"dns": {"ips": ["198.51.100.10", "198.51.100.20"]}},
    )
    report = _report(domain)
    enricher = _FakeEnricher("ip_rdap", ["ip"], {"netname": "EXAMPLE-NET"})

    close_report(
        report,
        ClosureConfig(online=True, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == ["198.51.100.10"]
    assert domain.enrichment["resolved_ip_selection"]["excluded_intercept"] == 1


def test_close_report_reuses_completed_source_outcomes_without_refresh() -> None:
    endpoint = _complete_endpoint()
    report = _report(endpoint)
    enricher = _FakeEnricher("shodan", ["ip"], {"org": "Changed Provider"})

    close_report(
        report,
        ClosureConfig(online=True, refresh=False, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == []
    assert endpoint.enrichment["shodan"]["org"] == "Example Hosting Ltd"


def test_close_report_refreshes_completed_source_when_requested() -> None:
    endpoint = _complete_endpoint()
    report = _report(endpoint)
    enricher = _FakeEnricher("shodan", ["ip"], {"org": "Refreshed Provider"})

    close_report(
        report,
        ClosureConfig(online=True, refresh=True, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == ["198.51.100.10"]
    assert endpoint.enrichment["shodan"]["org"] == "Refreshed Provider"


def test_close_report_retries_only_nonterminal_sources_without_refresh() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["source_status"]["retry_fake"] = {
        "status": "failed",
        "error_type": "timeout",
    }
    report = _report(endpoint)
    completed = _FakeEnricher("shodan", ["ip"], {"org": "MUST-NOT-REPLACE"})
    retry = _FakeEnricher("retry_fake", ["ip"], {"record": "found"})

    close_report(
        report,
        ClosureConfig(online=True, refresh=False, require_dynamic=False),
        enrichers=[completed, retry],
    )

    assert completed.calls == []
    assert retry.calls == ["198.51.100.10"]
    assert endpoint.enrichment["shodan"]["org"] == "Example Hosting Ltd"
    assert endpoint.enrichment["source_status"]["retry_fake"]["status"] == "hit"


def test_close_report_retries_disabled_source_after_credential_is_configured(
    monkeypatch,
) -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["source_status"] = {
        "configured_fake": {"status": "disabled", "reason": "credential_not_configured"}
    }
    report = _report(endpoint)
    enricher = _FakeEnricher("configured_fake", ["ip"], {"record": "found"})
    enricher.required_env = ("FXAPK_SYNTHETIC_CASE_KEY",)
    monkeypatch.setenv("FXAPK_SYNTHETIC_CASE_KEY", "configured-for-test")

    close_report(
        report,
        ClosureConfig(online=True, refresh=False, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == ["198.51.100.10"]
    assert endpoint.enrichment["source_status"]["configured_fake"]["status"] == "hit"


def test_close_report_retries_source_that_was_skipped_offline() -> None:
    endpoint = _complete_endpoint()
    endpoint.enrichment["source_status"] = {
        "configured_fake": {"status": "skipped", "reason": "offline"}
    }
    report = _report(endpoint)
    enricher = _FakeEnricher("configured_fake", ["ip"], {"record": "found"})

    close_report(
        report,
        ClosureConfig(online=True, refresh=False, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == ["198.51.100.10"]
    assert endpoint.enrichment["source_status"]["configured_fake"]["status"] == "hit"


def test_offline_close_does_not_enrich_previously_resolved_ip() -> None:
    domain = _endpoint(
        "api.example.test",
        kind="domain",
        runtime=True,
        target=True,
        payload=True,
        enrichment={"dns": {"ips": ["198.51.100.10"]}},
    )
    report = _report(domain)
    enricher = _FakeEnricher("ip_rdap", ["ip"], {"netname": "MUST-NOT-RUN"})

    close_report(
        report,
        ClosureConfig(online=False, require_dynamic=False),
        enrichers=[enricher],
    )

    assert enricher.calls == []


def test_offline_close_marks_configured_source_without_cache_as_incomplete() -> None:
    endpoint = _complete_endpoint()
    report = _report(endpoint)
    enricher = _FakeEnricher("configured_missing", ["ip"], {"record": "MUST-NOT-RUN"})

    closure = close_report(
        report,
        ClosureConfig(online=False, require_dynamic=False),
        enrichers=[enricher],
    )

    source = closure["targets"][0]["source_status"]["configured_missing"]
    assert enricher.calls == []
    assert source == {"status": "skipped", "reason": "offline"}
    assert closure["status"] == CLOSURE_PARTIAL


def test_unconfigured_source_is_disabled_without_blocking_offline_closure(
    monkeypatch,
) -> None:
    endpoint = _complete_endpoint()
    report = _report(endpoint)
    enricher = _FakeEnricher("unconfigured_optional", ["ip"], {"record": "MUST-NOT-RUN"})
    enricher.required_env = ("FXAPK_SYNTHETIC_OPTIONAL_KEY",)
    monkeypatch.delenv("FXAPK_SYNTHETIC_OPTIONAL_KEY", raising=False)

    closure = close_report(
        report,
        ClosureConfig(online=False, require_dynamic=False),
        enrichers=[enricher],
    )

    source = closure["targets"][0]["source_status"]["unconfigured_optional"]
    assert enricher.calls == []
    assert source == {"status": "disabled", "reason": "credential_not_configured"}
    assert closure["status"] == CLOSURE_COMPLETE


def test_populate_network_attribution_failure_preserves_existing_view(monkeypatch) -> None:
    """★回归（codex 审计 P2）：close 期 network_attribution 组装失败不覆盖 analyze 期已有的有效视图，只附 close_error。"""
    def _boom(*_a, **_k):
        raise RuntimeError("assemble failed")

    monkeypatch.setattr("apkscan.attribution.assemble.build_network_attribution", _boom)
    report = _report(_complete_endpoint())
    report.meta["network_attribution"] = {"phase": "analyze", "roles": ["x"]}  # analyze 期已有有效视图
    closure_module._populate_network_attribution(report)
    view = report.meta["network_attribution"]
    assert view["phase"] == "analyze" and view["roles"] == ["x"]  # 旧视图保留
    assert view["close_error"] == "RuntimeError"  # 只附错误标记


def test_populate_network_attribution_failure_marks_when_no_prior_view(monkeypatch) -> None:
    """无 analyze 期视图时，组装失败仍写纯错误标记（保持既有行为）。"""
    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("apkscan.attribution.assemble.build_network_attribution", _boom)
    report = _report(_complete_endpoint())
    closure_module._populate_network_attribution(report)
    assert report.meta["network_attribution"] == {"phase": "close", "error": "RuntimeError"}


def test_close_report_refreshes_fronting_cluster(monkeypatch) -> None:
    """★回归（codex 审计"已知边界"）：close 后重跑 fronting-cluster——单端点 _set_attribution 重建冲掉的
    cluster_id 被全报告重聚类恢复，不再停留在 analyze 期/丢失。"""
    # patch 定义模块（closure.sources），不带 raising=False——函数被挪走时立刻红，不再静默失效。
    monkeypatch.setattr(closure_sources, "_normalized_public_ip", lambda value: str(value).strip())
    # patch 生效自证：真实现会把 TEST-NET 文档段 IP 判非公网（is_global=False）剔除；经 patch 后原样
    # 保留 → 证明 patch 命中了 _resolved_ips 的实际调用点。将来再拆分若 patch 失效，这里立刻红。
    probe = _endpoint("probe.example.test", kind="domain", enrichment={"dns": {"ips": ["198.51.100.77"]}})
    assert closure_sources._resolved_ips(probe) == ["198.51.100.77"]
    e1 = _endpoint("1.1.1.1", runtime=True, target=True, enrichment={"tls": {"spki_sha256": "sharedspki"}})
    e2 = _endpoint("2.2.2.2", runtime=True, target=True, enrichment={"tls": {"spki_sha256": "sharedspki"}})
    report = _report(e1, e2)
    close_report(report, ClosureConfig(online=False, require_dynamic=False), enrichers=[])
    edge1 = e1.enrichment["attribution"]["ips"][0]["edge_provider"]
    edge2 = e2.enrichment["attribution"]["ips"][0]["edge_provider"]
    assert edge1["cluster_id"] == edge2["cluster_id"] == "fronting-cluster-0001"  # close 后重聚类恢复编号


def test_close_report_clears_stale_case_close_marker_on_unselected_lead() -> None:
    """★回归（codex 审计 P1-1 B 面）：上一轮更大 max_targets 给现已未选/被截断的 lead 写的旧 [case-close] 注记，
    本轮 close 须清掉，不残留与本轮 closure 不一致的陈旧状态。"""
    report = _report(_complete_endpoint())  # 198.51.100.10 会被选中
    stale = Lead(
        category=LeadCategory.IP, value="203.0.113.99", confidence=Confidence.HIGH,
        source_refs=[], advice="建议调证",
    )
    stale.notes = "[case-close] status=complete; gaps=none"  # 模拟上一轮它曾是 target 的陈旧注记
    report.leads.append(stale)  # 无对应端点 → 本轮不被选为 target
    close_report(report, ClosureConfig(online=False, require_dynamic=False), enrichers=[])
    assert "[case-close]" not in stale.notes  # 未选中 lead 的旧 marker 被清
