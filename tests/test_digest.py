"""紧凑调证摘要（Codex 友好）测试：build_digest 优先级排序 / 压缩字段 / 计数 + CLI stdout JSON。"""

from __future__ import annotations

import json
from types import SimpleNamespace

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.report.digest import build_digest

runner = CliRunner()


def test_build_digest_sorts_and_summarizes() -> None:
    report = {
        "meta": {"package_name": "com.x", "sample_sha256": "AB12", "comm_sessions": [{}, {}]},
        "leads": [
            {"category": "DOMAIN", "value": "infra.com", "advice": "无需调证", "confidence": "LOW"},
            {"category": "WALLET_SECRET", "value": "seed", "advice": "建议调证", "confidence": "HIGH",
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
            {"category": "ADMIN_PANEL", "value": "a.com", "advice": "待核", "confidence": "MEDIUM"},
        ],
    }
    d = build_digest(report)
    assert d["package"] == "com.x"
    assert d["sha256"] == "AB12"
    assert d["summary"]["total_leads"] == 3
    assert d["summary"]["comm_sessions"] == 2
    # 优先级排序：建议调证 > 待核 > 无需调证
    assert [lead["advice"] for lead in d["leads"]] == ["建议调证", "待核", "无需调证"]
    assert d["leads"][0]["category"] == "WALLET_SECRET"
    # 压缩：去掉 source_refs 等冗长内部结构
    assert "source_refs" not in d["leads"][0]
    assert d["summary"]["by_advice"]["建议调证"] == 1


def test_digest_recomputes_runtime_flags_from_case_scoped_evidence() -> None:
    def report(scope: str) -> dict:
        return {
            "leads": [
                {
                    "category": "IP",
                    "value": "203.0.113.9",
                    "advice": "建议调证",
                    "confidence": "HIGH",
                    "is_runtime_seen": True,
                    "is_runtime_contact": True,
                    "source_refs": [
                        {
                            "source": "runtime-pcap",
                            "location": "capture.pcap",
                            "scope": scope,
                        }
                    ],
                }
            ]
        }

    for scope in ("batch_reference", "legacy_unspecified"):
        lead = build_digest(report(scope))["leads"][0]
        assert lead["is_runtime_seen"] is False, scope
        assert lead["is_runtime_contact"] is False, scope

    lead = build_digest(report("case_evidence"))["leads"][0]
    assert lead["is_runtime_seen"] is True
    assert lead["is_runtime_contact"] is True


def test_build_digest_redacts_remote_control_value() -> None:
    """★回归（codex 全库审计 P1）：REMOTE_CONTROL 被动态侧标为高敏（含被害人关联），`digest --redact` 须脱敏
    其 value（与脱敏表同步）；非高敏类（IP）仍明文。"""
    report = {
        "leads": [
            {"category": "REMOTE_CONTROL", "value": "com.icbc.bank 被害人账户 6222abcd", "advice": "建议调证", "confidence": "HIGH"},
            {"category": "IP", "value": "1.2.3.4", "advice": "建议调证", "confidence": "HIGH"},
        ],
    }
    d = build_digest(report, redact=True)
    by_cat = {lead["category"]: lead["value"] for lead in d["leads"]}
    assert "6222" not in by_cat["REMOTE_CONTROL"] and "已脱敏" in by_cat["REMOTE_CONTROL"]
    assert by_cat["IP"] == "1.2.3.4"  # 非高敏类不脱敏


def test_redact_scrubs_pii_from_freetext_fields() -> None:
    """★codex C1：redact 时 subject/notes/where_to_request/evidence_to_obtain 自由文本里的结构化 PII
    （手机号/证件号/邮箱/卡号）被抹除，不再绕过脱敏进云端摘要；并置 redaction_warning 告警。"""
    report = {
        "leads": [{
            "category": "VICTIM_DATA",
            "value": "受害人物证",
            "subject": "受害人 张三 手机 13800138000",
            "notes": "身份证 11010119900307391X，邮箱 victim@example.com",
            "where_to_request": "向 6222021234567890123 开户行调证",
            "evidence_to_obtain": ["联系电话 13900139000 的通话记录"],
            "advice": "建议调证", "confidence": "HIGH",
        }],
    }
    d = build_digest(report, redact=True)
    lead = d["leads"][0]
    blob = f"{lead['subject']} {lead['notes']} {lead['where_to_request']} {lead['evidence_to_obtain']}"
    assert "13800138000" not in blob and "13900139000" not in blob  # 手机号
    assert "11010119900307391X" not in blob                          # 身份证
    assert "victim@example.com" not in blob                          # 邮箱
    assert "6222021234567890123" not in blob                         # 卡号
    assert "PII已脱敏" in blob                                        # 有替换标记
    assert "张三" in lead["subject"]  # 非结构化姓名保留（如实局限）：仅证明结构化 PII 被抹
    assert d.get("redaction_warning")  # 告警不静默


def test_no_redact_keeps_freetext_plaintext() -> None:
    """显式关掉脱敏（``redact=False``）时自由文本原样，无告警。

    ★这里必须**显式**传 ``redact=False``：默认值已翻转成脱敏，不传参数拿到的是脱敏结果。
    """
    report = {"leads": [{"category": "VICTIM_DATA", "value": "x",
                         "notes": "手机 13800138000", "advice": "待核", "confidence": "LOW"}]}
    d = build_digest(report, redact=False)
    assert d["leads"][0]["notes"] == "手机 13800138000"
    assert "redaction_warning" not in d


def test_integrity_flags_low_completeness_and_enrichment() -> None:
    """分析完整度/富化成功终态率低 + 关键分析器失败 → integrity.reliable=False + warnings。"""
    report = {
        "leads": [],
        "analysis_status": "partial",
        "completeness": 0.5,
        "critical_failures": ["endpoints"],
        "enricher_status": [
            {"provider": "asn", "attempted": 10, "ok": 2, "failed": 8},
            {"provider": "rdap", "attempted": 4, "ok": 1, "failed": 3},
        ],
    }
    d = build_digest(report)
    integ = d["integrity"]
    assert integ["reliable"] is False
    assert integ["enrichment_ok_rate"] == round(3 / 14, 4)
    assert any("完整度" in w for w in integ["warnings"])
    assert any("关键分析器失败" in w for w in integ["warnings"])
    assert any("富化成功终态率" in w for w in integ["warnings"])


def test_integrity_reliable_when_healthy() -> None:
    """完整度高 + 富化命中率高 + 无关键失败 → reliable=True、无 warnings。"""
    report = {
        "leads": [], "analysis_status": "complete", "completeness": 1.0,
        "critical_failures": [],
        "enricher_status": [{"provider": "asn", "attempted": 10, "ok": 9, "failed": 1}],
    }
    integ = build_digest(report)["integrity"]
    assert integ["reliable"] is True
    assert integ["warnings"] == []


def test_integrity_dirty_counts_never_throw() -> None:
    """★codex P0：脏 enricher_status（attempted="bad"/列表/负数）→ 不抛，跳过并降可靠性告警。"""
    report = {
        "leads": [], "analysis_status": "partial", "completeness": 1.0, "critical_failures": [],
        "enricher_status": [
            {"provider": "asn", "attempted": "bad", "ok": 1},        # 脏字符串
            {"provider": "rdap", "attempted": [1, 2], "ok": 0},       # 脏列表
            {"provider": "x", "attempted": 3, "ok": 5},               # ok>attempted
            {"provider": "y", "attempted": 10, "ok": 9},              # 正常
        ],
    }
    d = build_digest(report)  # 绝不抛
    integ = d["integrity"]
    assert integ["enrichment_ok_rate"] == round(9 / 10, 4)  # 仅正常条目
    assert any("异常条目" in w for w in integ["warnings"])


def test_integrity_nan_completeness_not_reliable() -> None:
    """★codex P1：NaN/越界 completeness 不得绕过阈值伪装 reliable=True。"""
    d1 = build_digest({"leads": [], "completeness": float("nan"), "enricher_status": []})
    assert d1["integrity"]["reliable"] is False
    d2 = build_digest({"leads": [], "completeness": 1.5, "enricher_status": []})
    assert d2["integrity"]["reliable"] is False
    d3 = build_digest({"leads": [], "completeness": -0.1, "enricher_status": []})
    assert d3["integrity"]["reliable"] is False


def test_partial_status_makes_integrity_unreliable() -> None:
    """★D1-a：analysis_status=partial（即使 completeness=1.0、无 critical_failures，如仅
    pipeline 阶段崩溃降档）→ reliable=False，warning 同时点名 status 与失败阶段。

    夹具用**存盘形状**：stage_status 由 pipeline 写在 meta 下（pipeline.run →
    ``state.meta["stage_status"]``），不是根级——根级形状比真实流程干净，会把缺陷盖住。
    """
    report = {
        "leads": [],
        "analysis_status": "partial",
        "completeness": 1.0,
        "critical_failures": [],
        "enricher_status": [],
        "meta": {"stage_status": [{"name": "enrich", "status": "error"}]},
    }
    integ = build_digest(report)["integrity"]
    assert integ["reliable"] is False
    assert any("partial" in w and "enrich" in w for w in integ["warnings"])


def test_integrity_no_enrichment_attempts_not_flagged() -> None:
    """零富化尝试（离线/无端点）→ enrichment_ok_rate=None，不因此告警（不是失败）。"""
    report = {"leads": [], "analysis_status": "complete", "completeness": 1.0,
              "critical_failures": [], "enricher_status": []}
    integ = build_digest(report)["integrity"]
    assert integ["enrichment_ok_rate"] is None
    assert integ["reliable"] is True


def _run_enrichment_stage(monkeypatch, endpoints, enrichers, **config_overrides):  # noqa: ANN001
    state = SimpleNamespace(
        config=AnalysisConfig(online=True, **config_overrides),
        meta={},
        endpoints=endpoints,
        enricher_status=[],
    )
    monkeypatch.setattr(pipeline, "_enrichment_targets", lambda _endpoints: endpoints)
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: enrichers)
    pipeline._stage_enrich(state)
    return state


def _digest_from_pipeline_state(state) -> dict:  # noqa: ANN001
    return build_digest(
        {
            "meta": state.meta,
            "leads": [],
            "analysis_status": "complete",
            "completeness": 1.0,
            "critical_failures": [],
            "enricher_status": state.enricher_status,
        }
    )


def test_pipeline_digest_exposes_consistent_high_cardinality_deferral(monkeypatch) -> None:
    class _Rdap(BaseEnricher):
        name = "rdap"
        applies_to = ["domain"]

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            raise AssertionError(f"熔断后不得查询 {ep.kind}")

    class _MissingKey(BaseEnricher):
        name = "icp"
        applies_to = ["domain"]
        required_env = ("FXAPK_SYNTHETIC_MISSING_DIGEST_KEY",)

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            raise AssertionError(f"缺凭据不得查询 {ep.kind}")

    monkeypatch.delenv("FXAPK_SYNTHETIC_MISSING_DIGEST_KEY", raising=False)
    endpoints = [Endpoint(value=f"node-{index}.example.test", kind="domain") for index in range(33)]
    state = _run_enrichment_stage(
        monkeypatch,
        endpoints,
        [_Rdap(), _MissingKey()],
        enrich_max_targets=32,
    )
    report_plan = state.meta["enrichment_plan"]
    report_execution = state.meta["enrichment_execution"]

    digest = _digest_from_pipeline_state(state)

    assert report_plan["provider_plan"]["rdap"] == {
        "applicable": 33,
        "selected": 0,
        "deferred": 33,
        "disabled": 0,
        "skipped": 0,
        "configured": True,
        "mode_allowed": True,
        "status": "deferred",
        "reason": "target_cap",
    }
    assert report_plan["provider_plan"]["icp"] == {
        "applicable": 33,
        "selected": 0,
        "deferred": 0,
        "disabled": 33,
        "skipped": 0,
        "configured": False,
        "mode_allowed": True,
        "status": "disabled",
        "reason": "credential_not_configured",
    }
    assert report_plan["estimated_provider_invocations"] == {"rdap": 0, "icp": 0}
    assert report_execution["status"] == "not_run"
    assert report_execution["attempted_total"] == 0
    assert endpoints[0].enrichment["source_status"] == {
        "rdap": {"status": "skipped", "reason": "target_cap"},
        "icp": {"status": "disabled", "reason": "credential_not_configured"},
    }
    assert digest["enrichment"]["status"] == "deferred_high_cardinality"
    assert digest["enrichment"]["candidate_total"] == 33
    assert digest["enrichment"]["provider_plan"] == report_plan["provider_plan"]
    assert digest["enrichment"]["estimated_provider_invocations"] == {"rdap": 0, "icp": 0}
    assert digest["integrity"]["reliable"] is False
    assert any("联网富化整轮未执行" in item for item in digest["integrity"]["warnings"])


def test_pipeline_digest_treats_no_record_as_successful_terminal_outcome(monkeypatch) -> None:
    class _NoRecord(BaseEnricher):
        name = "rdap"
        applies_to = ["domain"]

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"_source_status": "no_record"},
            )

    endpoint = Endpoint(value="empty.example.test", kind="domain")
    state = _run_enrichment_stage(monkeypatch, [endpoint], [_NoRecord()])

    digest = _digest_from_pipeline_state(state)

    assert endpoint.enrichment["source_status"]["rdap"] == {"status": "no_record"}
    assert state.enricher_status == [
        {
            "provider": "rdap",
            "attempted": 1,
            "ok": 0,
            "no_record": 1,
            "failed": 0,
            "typical_error": None,
        }
    ]
    assert state.meta["enrichment_execution"]["status"] == "completed"
    assert state.meta["enrichment_execution"]["failed_total"] == 0
    assert digest["enrichment"]["execution_status"] == "completed"
    assert digest["enrichment"]["attempted_total"] == 1
    assert digest["integrity"]["enrichment_ok_rate"] == 1.0
    assert digest["integrity"]["reliable"] is True


def test_build_digest_bad_input_never_throws() -> None:
    assert build_digest(["not a dict"])["leads"] == []
    assert build_digest(None)["leads"] == []
    assert build_digest({})["leads"] == []


def test_build_digest_exposes_compact_closure_without_raw_targets() -> None:
    report = {
        "meta": {
            "closure": {
                "status": "partial",
                "targets": [{"value": "198.51.100.10", "raw": {"large": "payload"}}],
                "gaps": ["Origin is missing"],
                "next_actions": ["request edge origin logs"],
                "source_summary": {"hit": 3, "failed": 1},
            }
        },
        "leads": [],
    }

    digest = build_digest(report)

    assert digest["closure"]["status"] == "partial"
    assert digest["closure"]["target_count"] == 1
    assert digest["closure"]["gaps"] == ["Origin is missing"]
    assert "targets" not in digest["closure"]
    assert "large" not in str(digest["closure"])


def test_findings_reach_the_digest() -> None:
    """★Finding 必须进 digest —— 它承载 leads 不表达的判断。

    实测一个真实样本产 31 条 Finding，而 digest 此前完全不透 findings：那些结论对 AI
    消费方等于不存在。丢的包括「疑似正版重打包，接口不能直接作线索」这种防误伤的警示，
    以及 HIGH 级的通讯录窃取接口。这正是"提取出来却在最后一环沉默"。
    """
    report = {
        "meta": {"package_name": "com.x"},
        "leads": [],
        "findings": [
            {"id": "API-SEMANTIC-CONTACT-THEFT", "severity": "HIGH", "title": "通讯录窃取接口"},
            {"id": "REPACK-IDENTITY-SUSPECTED", "severity": "MEDIUM", "title": "疑似正版重打包"},
            {"id": "BUILD-PROVENANCE-PATHS", "severity": "INFO", "title": "构建来源"},
        ],
    }
    d = build_digest(report)
    ids = {f["id"] for f in d["findings"]["items"]}
    assert "API-SEMANTIC-CONTACT-THEFT" in ids
    assert "REPACK-IDENTITY-SUSPECTED" in ids
    # findings 排在 leads 之前：研判次序是「哪里没看见 → 看见了什么 → 向谁调证」
    keys = list(d)
    assert keys.index("visibility") < keys.index("findings") < keys.index("leads")


def test_omitted_findings_are_counted_not_silently_dropped() -> None:
    """★省略必须说出来：只列 CRITICAL/HIGH/MEDIUM，但省了几条、什么分布要写清楚。

    静默丢弃会被读成"只有这些"——与本项目反复要防的"缺失被当不存在"是同一个错。
    """
    report = {
        "meta": {},
        "leads": [],
        "findings": [
            {"id": "A", "severity": "HIGH", "title": "x"},
            {"id": "B", "severity": "INFO", "title": "y"},
            {"id": "C", "severity": "LOW", "title": "z"},
        ],
    }
    c = build_digest(report)["findings"]["counts"]
    assert c["total"] == 3 and c["shown"] == 1 and c["omitted"] == 2
    assert c["by_severity"] == {"HIGH": 1, "INFO": 1, "LOW": 1}


def test_severity_survives_enum_serialization() -> None:
    """★严重度经 JSON 往返会变成 dict（Enum 的 __dict__），不能只 str()。

    直接 str 会得到一大坨对象文本，既污染 digest 又让严重度筛选整个失效——
    结果是 HIGH 级结论被当成未知级别丢掉。
    """
    report = {
        "meta": {},
        "leads": [],
        "findings": [
            {"id": "X", "severity": {"_name_": "HIGH", "_value_": "HIGH"}, "title": "枚举序列化形态"},
            {"id": "Y", "severity": None, "title": "缺失"},
        ],
    }
    d = build_digest(report)
    items = {f["id"]: f["severity"] for f in d["findings"]["items"]}
    assert items.get("X") == "HIGH", "枚举序列化后的严重度没认出来，HIGH 结论会被丢掉"
    assert "Y" not in items  # severity 缺失 → UNKNOWN → 不进（但计数里有）
    assert d["findings"]["counts"]["by_severity"].get("UNKNOWN") == 1


def test_findings_absent_or_malformed_never_throws() -> None:
    for bad in ({"meta": {}, "leads": []},
                {"meta": {}, "leads": [], "findings": "x"},
                {"meta": {}, "leads": [], "findings": [None, 7, {"id": "ok", "severity": "HIGH"}]}):
        d = build_digest(bad)
        assert isinstance(d["findings"]["items"], list)


def test_cli_digest_emits_json_stdout(tmp_path) -> None:
    rep = tmp_path / "report.json"
    rep.write_text(
        json.dumps(
            {
                "meta": {"package_name": "com.evil"},
                "leads": [
                    {"category": "DOMAIN", "value": "c2.evil.com", "advice": "建议调证",
                     "confidence": "HIGH", "is_c2": True, "evidence_to_obtain": ["x"]}
                ],
            }
        ),
        encoding="utf-8",
    )
    res = runner.invoke(cli.app, ["digest", str(rep)])
    assert res.exit_code == 0
    assert '"c2.evil.com"' in res.output
    assert '"leads"' in res.output


def test_cli_digest_warns_on_stderr_without_corrupting_json_stdout(tmp_path) -> None:
    rep = tmp_path / "old-report.json"
    rep.write_text(
        json.dumps({"meta": {"tool_version": "0.0.0-old"}, "leads": []}),
        encoding="utf-8",
    )

    res = runner.invoke(cli.app, ["digest", str(rep)])

    assert res.exit_code == 0
    assert isinstance(json.loads(res.stdout), dict)
    assert "分析修订与当前 fxapk 不一致" in res.stderr


def test_cli_digest_bad_path_exits_1() -> None:
    res = runner.invoke(cli.app, ["digest", "/no/such/report.json"])
    assert res.exit_code == 1


def test_build_digest_carries_downgrade_ledger() -> None:
    """★抑制账本必须进 digest：降档原因不再拼 notes，digest 的主要读者是 AI，
    它要判断「这条为什么被压着、能不能放回」全靠这个字段——漏了它，压档就成了无来由的档位。"""
    from apkscan.core import infra

    report = {
        "leads": [
            {"category": "DOMAIN", "value": "pressed.example.com",
             "advice": infra.ADVICE_REVIEW, "confidence": "HIGH",
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}],
             "downgrades": {"sni_masquerade": "只在非标准 TLS 端口作 SNI 出现"}},
            {"category": "DOMAIN", "value": "clean.example.com",
             "advice": infra.ADVICE_INVESTIGATE, "confidence": "HIGH",
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
        ],
    }
    d = build_digest(report)
    by_val = {lead["value"]: lead for lead in d["leads"]}
    assert by_val["pressed.example.com"]["downgrades"] == {
        "sni_masquerade": "只在非标准 TLS 端口作 SNI 出现"
    }
    assert by_val["clean.example.com"]["downgrades"] == {}, "无抑制的也要有该键（空 dict），消费方不必判缺"


def test_build_digest_redact_keeps_ledger_usable() -> None:
    """redact 路径：账本的值过脱敏兜底后仍是字符串、键不丢——账本值是判据产生的固定文案，
    脱敏是防御性的（防上游把 PII 写进说明），不该把整个字段抹没。"""
    from apkscan.core import infra

    report = {
        "leads": [
                {"category": "DOMAIN", "value": "pressed.example.com",
                 "advice": infra.ADVICE_REVIEW, "confidence": "HIGH",
                 "downgrades": {"repack_identity": "按疑似正版资产隔离"},
                 "source_refs": [{
                     "source": "dex",
                     "location": "classes.dex",
                     "scope": "case_evidence",
                 }]},
        ],
    }
    d = build_digest(report, redact=True)
    dg = d["leads"][0]["downgrades"]
    assert set(dg.keys()) == {"repack_identity"}
    assert isinstance(dg["repack_identity"], str) and dg["repack_identity"], "脱敏后值仍须可读"


def test_build_digest_flags_manually_restored_leads() -> None:
    """★人工放行必须在 digest 上可见：AI 要能分清「判据说它干净」与「人把它放回来了」。

    手改 advice 会被 closure 的一致性守卫挡下，手塞一条墓碑不会——不呈现就等于给绕过守卫留了
    一条更安静的路。墓碑不做真伪校验，可见性是唯一站得住的保证。
    """
    from apkscan.core import infra
    from apkscan.core.restore import MANUAL_RESTORES_KEY

    report = {
        "meta": {MANUAL_RESTORES_KEY: [
            {"category": "DOMAIN", "value": "restored.example.com",
             "source": "repack_identity", "note": "已差分核实"},
        ]},
        "leads": [
            {"category": "DOMAIN", "value": "restored.example.com",
             "advice": infra.ADVICE_INVESTIGATE, "confidence": "HIGH",
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
            {"category": "DOMAIN", "value": "clean.example.com",
             "advice": infra.ADVICE_INVESTIGATE, "confidence": "HIGH",
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
        ],
    }
    d = build_digest(report)
    by_val = {lead["value"]: lead for lead in d["leads"]}
    assert by_val["restored.example.com"]["manually_restored"] == ["repack_identity"]
    assert by_val["clean.example.com"]["manually_restored"] == [], "判据说它干净的不该被标成人工放行"


def test_digest_surfaces_jadx_index_status() -> None:
    """P2-A 消费面锁：meta 带 jadx_index_status → digest 顶层出现 jadx_index 段。

    删掉 build_digest 里的透出线（消费面接线）本测试必须变红。
    """
    key = "a1" * 32
    report = {"meta": {"jadx_index_status": "built", "jadx_index_key": key}, "leads": []}
    d = build_digest(report)
    assert d["jadx_index"] == {"status": "built", "key": key}

    # disabled（无 key）→ 只出 status；key 非 hex64 语法（如被塞了路径）绝不透出。
    forged = {
        "meta": {"jadx_index_status": "disabled", "jadx_index_key": "C:/evil/path"},
        "leads": [],
    }
    d2 = build_digest(forged)
    assert d2["jadx_index"] == {"status": "disabled"}

    # 旧报告（无该键）：整段省略，不出现空壳。
    d3 = build_digest({"meta": {}, "leads": []})
    assert "jadx_index" not in d3
