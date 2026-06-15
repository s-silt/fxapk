"""pipeline.run 的契约测试：跑通、错误被记录而非抛出、端点 → Lead。

通过 monkeypatch 注入 fake 分析器/富化器，不依赖真实的 analyzers/enrichers 包内容。
"""

from __future__ import annotations


from apkscan.core import infra, pipeline
from apkscan.core.models import (
    AnalysisConfig,
    AnalyzerResult,
    Confidence,
    EnrichmentResult,
    Endpoint,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, BaseEnricher


# --- fake 分析器 / 富化器 --------------------------------------------------


class _GoodAnalyzer(BaseAnalyzer):
    name = "good"
    requires: list[str] = []

    def analyze(self, ctx) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            endpoints=[
                Endpoint(
                    value="pay.example.com",
                    kind="domain",
                    evidences=[Evidence(source="dex", location="X;->y", snippet="pay.example.com")],
                ),
                Endpoint(value="1.2.3.4", kind="ip"),
                Endpoint(value="https://pay.example.com/notify", kind="url"),
            ],
            findings=[
                Finding(
                    id="F1",
                    title="测试发现",
                    severity=Severity.LOW,
                    category="test",
                    description="desc",
                )
            ],
            leads=[Lead(category=LeadCategory.SDK_SERVICE, value="极光 JPush")],
            meta={"packer": "none"},
        )


class _CrashingAnalyzer(BaseAnalyzer):
    name = "crashing"
    requires: list[str] = []

    def analyze(self, ctx) -> AnalyzerResult:
        raise RuntimeError("boom")


class _SkippedAnalyzer(BaseAnalyzer):
    name = "needs_adb"
    requires = ["adb"]

    def analyze(self, ctx) -> AnalyzerResult:  # pragma: no cover - 应被跳过
        raise AssertionError("requires 未满足却被执行")


class _DomainEnricher(BaseEnricher):
    name = "icp"
    applies_to = ["domain"]

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name,
            ok=True,
            data={"subject": "示例科技有限公司", "license_no": "京ICP备12345678号"},
        )


class _CrashingEnricher(BaseEnricher):
    name = "asn"
    applies_to = ["ip"]

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        raise RuntimeError("network down")


# --- 测试 ------------------------------------------------------------------


def test_pipeline_runs_and_records_errors(monkeypatch, fake_ctx):
    monkeypatch.setattr(
        pipeline,
        "discover_analyzers",
        lambda: [_GoodAnalyzer(), _CrashingAnalyzer(), _SkippedAnalyzer()],
    )
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    # 能力集只给 online，不给 adb → _SkippedAnalyzer 应被跳过
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    config = AnalysisConfig(online=False)
    report = pipeline.run(fake_ctx, config)

    # 跑通，不抛异常
    assert report.package_name == "com.test.app"
    assert report.meta.get("packer") == "none"

    # 聚合结果
    assert len(report.endpoints) == 3
    assert len(report.findings) == 1

    # 状态：good=ran, crashing=error（被记录而非抛出）, needs_adb=skipped
    status = {s["name"]: s for s in report.analyzer_status}
    assert status["good"]["status"] == "ran"
    assert status["crashing"]["status"] == "error"
    assert "boom" in status["crashing"]["reason"]
    assert status["needs_adb"]["status"] == "skipped"
    assert "adb" in status["needs_adb"]["reason"]


def test_endpoint_leads_built_from_domains_and_ips(monkeypatch, fake_ctx):
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_GoodAnalyzer()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))

    categories = [lead.category for lead in report.leads]
    # 分析器自带的 SDK_SERVICE lead 保留
    assert LeadCategory.SDK_SERVICE in categories
    # 端点产出的 DOMAIN / IP lead（URL 不产）
    assert categories.count(LeadCategory.DOMAIN) == 1
    assert categories.count(LeadCategory.IP) == 1

    domain_lead = next(l for l in report.leads if l.category == LeadCategory.DOMAIN)
    assert domain_lead.value == "pay.example.com"
    # 源证据从端点透传
    assert domain_lead.source_refs and domain_lead.source_refs[0].source == "dex"


def test_online_enrichment_applied_and_failures_recorded(monkeypatch, fake_ctx):
    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_GoodAnalyzer()])
    monkeypatch.setattr(
        pipeline, "discover_enrichers", lambda: [_DomainEnricher(), _CrashingEnricher()]
    )
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: {"online"})

    report = pipeline.run(fake_ctx, AnalysisConfig(online=True))

    domain_ep = next(e for e in report.endpoints if e.kind == "domain")
    ip_ep = next(e for e in report.endpoints if e.kind == "ip")

    # 富化结果写入 endpoint.enrichment[provider]
    assert domain_ep.enrichment["icp"]["subject"] == "示例科技有限公司"
    # 富化器异常被记录而非抛出
    assert ip_ep.enrichment["asn"]["ok"] is False

    # domain lead 用 icp 结果填 subject / where_to_request，置信度升 HIGH
    domain_lead = next(l for l in report.leads if l.category == LeadCategory.DOMAIN)
    assert domain_lead.subject == "示例科技有限公司"
    assert domain_lead.confidence == Confidence.HIGH
    assert "ICP" in (domain_lead.where_to_request or "")


def test_offline_skips_enrichers(monkeypatch, fake_ctx):
    called = {"n": 0}

    class _CountingEnricher(BaseEnricher):
        name = "whois"
        applies_to = ["domain"]

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            called["n"] += 1
            return EnrichmentResult(provider=self.name, ok=True, data={})

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_GoodAnalyzer()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [_CountingEnricher()])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    pipeline.run(fake_ctx, AnalysisConfig(online=False))
    assert called["n"] == 0


def test_enrichment_targets_only_suspicious():
    """联网富化只对"高度可疑"端点（建议调证）：infra 域名 / 私网·回环 IP 一律不查。"""
    eps = [
        Endpoint(value="gw.hxhcapi.vip", kind="domain", evidences=[]),  # 疑似 C2 → 查
        Endpoint(value="maps.googleapis.com", kind="domain", evidences=[]),  # 已知 infra → 跳
        Endpoint(value="connectivitycheck.gstatic.com", kind="domain", evidences=[]),  # infra → 跳
        Endpoint(value="45.76.1.1", kind="ip", evidences=[]),  # 真公网 IP → 查
        Endpoint(value="127.0.0.1", kind="ip", evidences=[]),  # 回环 → 待核 → 跳
        Endpoint(value="192.168.1.1", kind="ip", evidences=[]),  # 私网 → 跳
        Endpoint(value="https://gw.hxhcapi.vip/x", kind="url", evidences=[]),  # url 不富化
    ]
    targets = {e.value for e in pipeline._enrichment_targets(eps)}
    assert targets == {"gw.hxhcapi.vip", "45.76.1.1"}


def test_online_skips_infra_domain_enrichment(monkeypatch, fake_ctx):
    """端到端：online=True 下，已知 infra 域名不被富化器查询（只查建议调证的）。"""
    queried: list[str] = []

    class _Spy(BaseEnricher):
        name = "whois"
        applies_to = ["domain"]

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            queried.append(ep.value)
            return EnrichmentResult(provider=self.name, ok=True, data={"registrar": "x"})

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_GoodAnalyzer()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [_Spy()])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: {"online"})

    pipeline.run(fake_ctx, AnalysisConfig(online=True))
    # 被查的域名都必须是"建议调证"（绝不含 infra/已知第三方）
    for d in queried:
        advice, _ = infra.classify_domain(d)
        assert advice == infra.ADVICE_INVESTIGATE, f"不该查 {d}（{advice}）"


def test_domain_tier_downgrades_advice_to_review():
    # C1：library-file / bulk-string tier 的非 infra 域名 → advice 降"待核" + notes 标库内置。
    eps = [
        Endpoint(value="amazon-mirror-cdn.com", kind="domain", enrichment={"tier": "library-file"}),
    ]
    leads = pipeline.build_endpoint_leads(eps, online=False)
    domain_lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert domain_lead.advice == "待核"
    assert domain_lead.confidence == Confidence.LOW
    assert "库内置" in domain_lead.notes


def test_app_tier_real_c2_not_downgraded():
    # ★ C1 回归锁：app tier（或无 tier）的真 C2（hxhcapi.vip）→ 建议调证，不被降档。
    eps = [
        Endpoint(value="api.hxhcapi.vip", kind="domain", enrichment={"tier": "app"}),
        Endpoint(value="pay.hcrsex.com", kind="domain"),  # 无 tier
    ]
    leads = pipeline.build_endpoint_leads(eps, online=False)
    by_val = {l.value: l for l in leads}
    assert by_val["api.hxhcapi.vip"].advice == "建议调证"
    assert by_val["pay.hcrsex.com"].advice == "建议调证"


def test_infra_domain_with_library_tier_stays_skip():
    # 已知 infra 域名即便 tier=library-file，仍"无需调证"（不被降到"待核"）。
    eps = [Endpoint(value="sdk.getui.com", kind="domain", enrichment={"tier": "library-file"})]
    leads = pipeline.build_endpoint_leads(eps, online=False)
    assert leads[0].advice == "无需调证"


def test_dedup_endpoints_tier_takes_best():
    # C1：同域名既来自 app 文件又来自 library 文件 → tier 取最可信（app）。
    eps = [
        Endpoint(value="x.fraud.cn", kind="domain", enrichment={"tier": "library-file"}),
        Endpoint(value="x.fraud.cn", kind="domain", enrichment={"tier": "app"}),
    ]
    merged = pipeline._dedup_endpoints(eps)
    assert len(merged) == 1
    assert merged[0].enrichment["tier"] == "app"


def test_build_endpoint_leads_directly():
    eps = [
        Endpoint(value="a.com", kind="domain", enrichment={"whois": {"registrar": "GoDaddy"}}),
        Endpoint(value="9.9.9.9", kind="ip", enrichment={"asn": {"org": "Aliyun"}}),
        Endpoint(value="http://a.com/x", kind="url"),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    assert {l.category for l in leads} == {LeadCategory.DOMAIN, LeadCategory.IP}

    domain_lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert "GoDaddy" in (domain_lead.where_to_request or "")

    ip_lead = next(l for l in leads if l.category == LeadCategory.IP)
    assert ip_lead.subject == "Aliyun"


def test_advice_assigned_by_infra_and_category(monkeypatch, fake_ctx):
    """每条 Lead 都应带 advice：DOMAIN/IP 按 infra 分级，其它类别按兜底默认。"""

    class _AdviceAnalyzer(BaseAnalyzer):
        name = "advice_src"
        requires: list[str] = []

        def analyze(self, ctx) -> AnalyzerResult:
            return AnalyzerResult(
                analyzer=self.name,
                endpoints=[
                    # 已知第三方基础设施 → 无需调证
                    Endpoint(value="sdk.getui.com", kind="domain"),
                    # 疑似 App 自有服务 → 建议调证
                    Endpoint(value="pay.evil-app.com", kind="domain"),
                    # 公网 IP → 建议调证
                    Endpoint(value="8.8.8.8", kind="ip"),
                    # 内网 IP（端点标 is_private）→ 无需调证
                    Endpoint(value="192.168.0.1", kind="ip", is_private=True),
                ],
                leads=[
                    # 分析器自带 advice 的，pipeline 兜底不得覆盖。
                    Lead(category=LeadCategory.SDK_SERVICE, value="个推", advice="无需调证"),
                    # 未带 advice 的 SIGNING → 兜底"待核"。
                    Lead(category=LeadCategory.SIGNING, value="CN=Dev"),
                    # 未带 advice 的 CONFIG_KEY → 兜底"建议调证"。
                    Lead(category=LeadCategory.CONFIG_KEY, value="GETUI_APPID=DVRqp"),
                ],
            )

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [_AdviceAnalyzer()])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    monkeypatch.setattr(pipeline, "detect_capabilities", lambda online=True: set())

    report = pipeline.run(fake_ctx, AnalysisConfig(online=False))
    by_value = {(l.category, l.value): l.advice for l in report.leads}

    # DOMAIN：infra 分级
    assert by_value[(LeadCategory.DOMAIN, "sdk.getui.com")] == "无需调证"
    assert by_value[(LeadCategory.DOMAIN, "pay.evil-app.com")] == "建议调证"
    # IP：公网 vs 内网
    assert by_value[(LeadCategory.IP, "8.8.8.8")] == "建议调证"
    assert by_value[(LeadCategory.IP, "192.168.0.1")] == "无需调证"
    # 类别兜底，且不覆盖分析器自带值
    assert by_value[(LeadCategory.SDK_SERVICE, "个推")] == "无需调证"
    assert by_value[(LeadCategory.SIGNING, "CN=Dev")] == "待核"
    assert by_value[(LeadCategory.CONFIG_KEY, "GETUI_APPID=DVRqp")] == "建议调证"

    # 每条 Lead 都应被研判（无空 advice）。
    assert all(l.advice for l in report.leads)


# --------------------------- 归属优先级 icp → rdap → whois ---------------------


def test_domain_lead_subject_priority_icp_first():
    """归属优先级：icp.subject > rdap.registrant > whois.registrant。"""
    eps = [
        Endpoint(
            value="a.fraud.com",
            kind="domain",
            enrichment={
                "icp": {"subject": "ICP 主体公司", "license_no": "京ICP备1号"},
                "rdap": {"registrant": "RDAP 注册人", "registrar": "GoDaddy", "source": "rdap"},
                "whois": {"registrant": "WHOIS 注册人", "registrar": "OldReg"},
            },
        ),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert lead.subject == "ICP 主体公司"
    assert "ICP" in (lead.where_to_request or "")


def test_domain_lead_rdap_when_no_icp():
    """无 icp 时用 rdap 的 registrar / registrant 填归属（rdap 优先于 whois）。"""
    eps = [
        Endpoint(
            value="b.fraud.com",
            kind="domain",
            enrichment={
                "rdap": {
                    "registrar": "RDAP Registrar Inc",
                    "registrant": "RDAP Registrant Co",
                    "source": "rdap",
                },
                "whois": {"registrar": "Whois Reg", "registrant": "Whois Co"},
            },
        ),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert lead.subject == "RDAP Registrant Co"
    assert "RDAP Registrar Inc" in (lead.where_to_request or "")
    # 用了 rdap 的注册商，而非 whois 的。
    assert "Whois Reg" not in (lead.where_to_request or "")


def test_domain_lead_whois_fallback_when_no_icp_no_rdap():
    """无 icp、无 rdap 时回退 whois。"""
    eps = [
        Endpoint(
            value="c.fraud.com",
            kind="domain",
            enrichment={"whois": {"registrar": "Whois Only Reg", "registrant": "Whois Co"}},
        ),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert lead.subject == "Whois Co"
    assert "Whois Only Reg" in (lead.where_to_request or "")


def test_domain_lead_rdap_whois_fallback_source_used():
    """rdap 内部 whois 兜底（source=whois-fallback）的字段同样可用于归属。"""
    eps = [
        Endpoint(
            value="d.fraud.com",
            kind="domain",
            enrichment={
                "rdap": {
                    "registrar": "Fallback Reg",
                    "registrant": "Fallback Co",
                    "source": "whois-fallback",
                }
            },
        ),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    assert lead.subject == "Fallback Co"
    assert "Fallback Reg" in (lead.where_to_request or "")


def test_domain_lead_dns_hosting_in_evidence_and_notes():
    """dns 富化的托管 IP / ASN 体现在 evidence_to_obtain 或 notes。"""
    eps = [
        Endpoint(
            value="e.fraud.com",
            kind="domain",
            enrichment={
                "rdap": {"registrar": "R", "source": "rdap"},
                "dns": {
                    "ips": ["45.76.1.1", "45.76.1.2"],
                    "hosting": [
                        {"ip": "45.76.1.1", "asn": "AS20473 Vultr", "org": "Vultr", "country": "US"},
                        {"ip": "45.76.1.2", "asn": "AS20473 Vultr", "org": "Vultr", "country": "US"},
                    ],
                },
            },
        ),
    ]
    leads = pipeline.build_endpoint_leads(eps)
    lead = next(l for l in leads if l.category == LeadCategory.DOMAIN)
    blob = " ".join(lead.evidence_to_obtain) + " " + (lead.notes or "")
    assert "45.76.1.1" in blob
    assert "Vultr" in blob


def test_whois_enricher_not_routed_by_pipeline():
    """避免 whois 双查：独立 WhoisEnricher 的 applies_to 应为空，pipeline 不再路由它。"""
    from apkscan.enrichers.whois import WhoisEnricher

    assert WhoisEnricher().applies_to == []

    queried: list[str] = []

    class _SpyWhois(BaseEnricher):
        name = "whois"
        applies_to = WhoisEnricher().applies_to  # 即 []

        def enrich(self, ep: Endpoint) -> EnrichmentResult:  # pragma: no cover
            queried.append(ep.value)
            return EnrichmentResult(provider=self.name, ok=True, data={})

    eps = [Endpoint(value="pay.evil-app.com", kind="domain")]
    pipeline._enrich_endpoints(eps, [_SpyWhois()])
    assert queried == []  # applies_to=[] → 不被路由


# --------------------------- 资源审计（exe-ready）---------------------------


def test_load_rules_via_importlib_resources_reads_yaml():
    """registry.load_rules 经 importlib.resources 读 rules/*.yaml（非 Path(__file__) 相对）。

    锚顶层包 'apkscan'，读真实存在的规则文件，断言返回非空 dict/list；并确认
    模块不再保留 __file__ 相对的 _rules_dir 帮助器（exe-ready 改造已落地）。
    """
    from apkscan.core import registry

    # __file__ 相对定位帮助器已移除。
    assert not hasattr(registry, "_rules_dir")

    data = registry.load_rules("sdks")
    assert isinstance(data, (dict, list))
    assert data  # sdks.yaml 非空

    # 带 .yaml 后缀亦可。
    data2 = registry.load_rules("sdks.yaml")
    assert isinstance(data2, (dict, list))
    assert data2

    # 不存在的规则 → 空 dict（不抛）。
    assert registry.load_rules("__nope__") == {}
