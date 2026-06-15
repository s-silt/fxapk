"""report.json.dump / report.html.render 单测。

手工构造含若干 Lead / Endpoint / Finding 的 Report（不依赖 androguard / 网络），
断言：
- json.dump 产出合法 JSON、Enum 已转为字符串值、含关键线索值。
- html.render 产出含关键中文小节标题与线索值的 HTML 文件。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core.models import (
    Confidence,
    Endpoint,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Report,
    Severity,
)
from apkscan.report import html as report_html
from apkscan.report import json as report_json
from apkscan.report.html import (
    group_leads_by_category,
    network_leads_by_advice,
    sort_leads_by_confidence,
)


@pytest.fixture
def sample_report() -> Report:
    """含配置键值/支付/SDK/域名/IP/联系方式线索 + 端点 + 发现的样例 Report。"""
    leads = [
        Lead(
            category=LeadCategory.CONFIG_KEY,
            value="GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3",
            subject="每日互动股份有限公司（个推）",
            where_to_request="个推（GeTui）厂商",
            evidence_to_obtain=["AppID 对应注册主体", "推送 / 设备日志"],
            confidence=Confidence.HIGH,
            advice="建议调证",
            source_refs=[Evidence(source="manifest", location="AndroidManifest.xml#meta-data", snippet="GETUI_APPID")],
            notes="个推推送 AppID（manifest meta-data）",
        ),
        Lead(
            category=LeadCategory.PAYMENT,
            value="pay.fraud-example.com",
            subject="某聚合支付公司",
            where_to_request="聚合支付平台 / 收单机构",
            evidence_to_obtain=["商户号绑定主体", "结算银行账户"],
            confidence=Confidence.HIGH,
            advice="建议调证",
            source_refs=[Evidence(source="dex", location="com/app/Pay.java", snippet="pay.fraud-example.com/notify")],
            notes="支付回调域名",
        ),
        Lead(
            category=LeadCategory.SDK_SERVICE,
            value="极光推送 JPush",
            subject="深圳市和讯华谷信息技术有限公司",
            where_to_request="极光（JPush）厂商",
            evidence_to_obtain=["AppKey 对应注册主体", "推送日志"],
            confidence=Confidence.MEDIUM,
            advice="建议调证",
            source_refs=[Evidence(source="dex", location="cn.jpush.android.api.JPushInterface")],
        ),
        Lead(
            category=LeadCategory.DOMAIN,
            value="ctrl.fraud-example.com",
            subject="某科技有限公司",
            where_to_request="域名注册商 / ICP 备案主体",
            confidence=Confidence.HIGH,
            advice="建议调证",
            notes="疑似主控域名",
        ),
        Lead(
            category=LeadCategory.DOMAIN,
            value="cdn.aliyuncs.com",
            subject="阿里云",
            where_to_request="域名注册商 / ICP 备案主体",
            confidence=Confidence.LOW,
            advice="无需调证",
            notes="公共 CDN",
        ),
        Lead(
            category=LeadCategory.IP,
            value="1.2.3.4",
            where_to_request="IP 归属 ASN / IDC",
            confidence=Confidence.MEDIUM,
            advice="无需调证",
        ),
        Lead(
            category=LeadCategory.CONTACT,
            value="kefu_fraud_2024",
            subject="客服微信",
            confidence=Confidence.MEDIUM,
            advice="建议调证",
            source_refs=[Evidence(source="resource", location="res/values/strings.xml")],
            notes="微信号",
        ),
    ]
    endpoints = [
        Endpoint(
            value="ctrl.fraud-example.com",
            kind="domain",
            evidences=[Evidence(source="dex", location="com/app/Net.java")],
            is_cleartext=False,
            enrichment={
                "whois": {"registrar": "Alibaba Cloud", "registrant": "隐藏"},
                "icp": {"subject": "某科技有限公司", "license_no": "粤ICP备12345678号"},
            },
        ),
        Endpoint(
            value="1.2.3.4",
            kind="ip",
            evidences=[Evidence(source="dex", location="com/app/Net.java")],
            is_cleartext=True,
            is_private=False,
            enrichment={"asn": {"asn": "AS37963", "org": "Alibaba", "country": "CN"}},
        ),
        Endpoint(
            value="http://10.0.0.1/internal",
            kind="url",
            is_cleartext=True,
            is_private=True,
        ),
    ]
    findings = [
        Finding(
            id="CRYPTO-001",
            title="使用 MD5 弱哈希",
            severity=Severity.MEDIUM,
            category="crypto",
            description="检测到 MessageDigest.getInstance(\"MD5\")。",
            recommendation="改用 SHA-256。",
            evidences=[Evidence(source="dex", location="com/app/Crypto.java")],
        ),
    ]
    meta = {
        "version_name": "3.2.1",
        "version_code": 321,
        "min_sdk": 21,
        "target_sdk": 33,
        "sign_subject": "CN=Fraud Dev",
        "sign_sha256": "ab" * 32,
        "packer": "梆梆加固",
        "is_hardened": True,
        "uni_app": "__UNI__F7A0431",
        "uni_encrypted": True,
        "permissions": ["android.permission.INTERNET", "android.permission.READ_SMS"],
        "components": [
            {"name": "com.app.MainActivity", "kind": "activity", "exported": True},
        ],
        "certificates": [
            {
                "subject": "CN=Fraud Dev",
                "issuer": "CN=Fraud Dev",
                "serial": "0x1a2b3c",
                "sha256": "ab" * 32,
                "not_before": "2023-01-01",
                "not_after": "2048-01-01",
                "is_debug": False,
                "schemes": ["v1", "v2"],
            }
        ],
    }
    analyzer_status = [
        {"name": "manifest", "status": "ran", "reason": ""},
        {"name": "packing", "status": "ran", "reason": ""},
        {"name": "runtime_capture", "status": "skipped", "reason": "缺少 adb 能力"},
        {"name": "broken_one", "status": "error", "reason": "ValueError: boom"},
    ]
    return Report(
        package_name="com.fraud.example",
        meta=meta,
        leads=leads,
        endpoints=endpoints,
        findings=findings,
        analyzer_status=analyzer_status,
    )


# --------------------------- JSON ---------------------------


def test_json_dump_writes_valid_json(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report_json.dump(sample_report, str(path))

    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))  # 合法 JSON

    assert data["package_name"] == "com.fraud.example"
    assert len(data["leads"]) == 7
    assert len(data["endpoints"]) == 3
    assert len(data["findings"]) == 1
    assert len(data["analyzer_status"]) == 4


def test_json_enums_serialized_as_values(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report_json.dump(sample_report, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))

    # LeadCategory / Confidence / Severity 都应是字符串值，而非枚举 repr。
    cats = {lead["category"] for lead in data["leads"]}
    assert cats == {"CONFIG_KEY", "PAYMENT", "SDK_SERVICE", "DOMAIN", "IP", "CONTACT"}
    confs = {lead["confidence"] for lead in data["leads"]}
    assert confs <= {"LOW", "MEDIUM", "HIGH"}
    assert data["findings"][0]["severity"] == "MEDIUM"


def test_json_contains_lead_values_and_enrichment(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report_json.dump(sample_report, str(path))
    raw = path.read_text(encoding="utf-8")

    assert "pay.fraud-example.com" in raw
    assert "极光推送 JPush" in raw  # ensure_ascii=False 保留中文
    assert "粤ICP备12345678号" in raw  # 富化结果保留
    assert "GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3" in raw  # 具体配置键值
    # nested Evidence 被序列化为 dict
    data = json.loads(raw)
    pay = next(lead for lead in data["leads"] if lead["category"] == "PAYMENT")
    assert pay["source_refs"][0]["location"] == "com/app/Pay.java"


def test_json_contains_advice_field(sample_report: Report, tmp_path: Path) -> None:
    """advice 随 dataclass 自动序列化，且按线索保留正确取值。"""
    path = tmp_path / "report.json"
    report_json.dump(sample_report, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))

    # 每条 lead 都带 advice 字段
    assert all("advice" in lead for lead in data["leads"])
    config = next(lead for lead in data["leads"] if lead["category"] == "CONFIG_KEY")
    assert config["advice"] == "建议调证"
    cdn = next(lead for lead in data["leads"] if lead["value"] == "cdn.aliyuncs.com")
    assert cdn["advice"] == "无需调证"


def test_json_is_utf8_no_ascii_escape(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report_json.dump(sample_report, str(path))
    raw = path.read_text(encoding="utf-8")
    assert "\\u" not in raw  # ensure_ascii=False


def test_json_creates_parent_dirs(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "nested" / "deep" / "report.json"
    report_json.dump(sample_report, str(path))
    assert path.exists()


# --------------------------- helpers ---------------------------


def test_sort_leads_by_confidence_high_first() -> None:
    leads = [
        Lead(category=LeadCategory.DOMAIN, value="a", confidence=Confidence.LOW),
        Lead(category=LeadCategory.DOMAIN, value="b", confidence=Confidence.HIGH),
        Lead(category=LeadCategory.DOMAIN, value="c", confidence=Confidence.MEDIUM),
    ]
    ordered = sort_leads_by_confidence(leads)
    assert [lead.value for lead in ordered] == ["b", "c", "a"]


def test_group_leads_by_category(sample_report: Report) -> None:
    groups = group_leads_by_category(sample_report.leads)
    cats = [g["category"] for g in groups]
    # CONFIG_KEY 置于最前（最高优先）
    assert cats[0] == LeadCategory.CONFIG_KEY
    # 仅含非空分组；PAYMENT/SDK_SERVICE/CONTACT 应排在 DOMAIN/IP 之前
    assert LeadCategory.PAYMENT in cats
    assert cats.index(LeadCategory.PAYMENT) < cats.index(LeadCategory.DOMAIN)
    assert cats.index(LeadCategory.SDK_SERVICE) < cats.index(LeadCategory.IP)
    # 每组都带中文 label 且非空
    assert all(g["label"] and g["leads"] for g in groups)


def test_network_leads_by_advice_splits(sample_report: Report) -> None:
    buckets = network_leads_by_advice(sample_report.leads)
    need_values = {lead.value for lead in buckets["need"]}
    skip_values = {lead.value for lead in buckets["skip"]}
    # 建议调证的主控域名进 need；无需调证的 CDN/IP 进 skip
    assert "ctrl.fraud-example.com" in need_values
    assert "cdn.aliyuncs.com" in skip_values
    assert "1.2.3.4" in skip_values
    # 仅含 DOMAIN/IP，不含 PAYMENT/CONFIG_KEY
    assert "pay.fraud-example.com" not in (need_values | skip_values)
    assert "GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3" not in (need_values | skip_values)


# --------------------------- HTML ---------------------------


def test_html_render_writes_file(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    assert path.exists()
    html = path.read_text(encoding="utf-8")
    assert html.lstrip().lower().startswith("<!doctype html")


def test_html_contains_section_titles(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    for title in [
        "概览",
        "调用插件 / 配置键值",  # ② ★ CONFIG_KEY
        "主控域名",  # ③ 建议调证
        "通联域名 / IP",  # ④ 无需调证
        "SDK",  # ⑤ 第三方 SDK → 厂商
        "支付",
        "联系方式",
        "签名证书",  # ⑦
        "技术附录",  # ⑧
        "分析器",  # ⑨ 分析器 + 富化器运行状态
    ]:
        assert title in html, f"缺少小节标题: {title}"


def test_html_config_key_section_shows_key_and_advice(sample_report: Report, tmp_path: Path) -> None:
    """★ 调用插件/配置键值小节：含具体 key 值（mono 显著）与 advice 标记。"""
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "调用插件 / 配置键值" in html  # 小节标题
    assert "GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3" in html  # 具体 key 值
    assert "mono-strong" in html  # 具体值用显著 mono 样式
    assert "每日互动股份有限公司（个推）" in html  # 所属公司
    # advice 标记同时出现「建议调证」与「无需调证」两种
    assert "建议调证" in html
    assert "无需调证" in html
    # advice 上色类
    assert "advice-need" in html
    assert "advice-skip" in html


def test_html_crypto_recipe_section_renders(tmp_path: Path) -> None:
    """C5a：CRYPTO_RECIPE 线索渲染为专属小节（配方摘要 + advice），不缺标题。"""
    report = Report(
        package_name="com.test",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.CRYPTO_RECIPE,
                value="AES-CFB/Pkcs7 key(utf8,32B)=55f0…3467 iv=md5(key+ts)[:16]",
                confidence=Confidence.HIGH,
                advice="建议调证",
                notes="自 JS 逆出的应用层加密配方",
                source_refs=[Evidence(source="js", location="app-service.js", snippet="AES.encrypt")],
            )
        ],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    path = tmp_path / "report.html"
    report_html.render(report, str(path))
    html = path.read_text(encoding="utf-8")

    assert 'id="crypto-recipe"' in html
    assert "应用层加密配方" in html
    assert "AES-CFB/Pkcs7 key(utf8,32B)" in html
    assert "建议调证" in html


def test_html_escapes_attacker_controlled_strings(tmp_path: Path) -> None:
    """报告嵌入的包名/线索值是涉诈样本里攻击者可控的串：必须被 HTML 转义，绝不原样注入。

    报告常在浏览器打开给执法/调证人员看，若模板某处不慎用 |safe 或关 autoescape，样本里的
    <script> 就会 XSS。此用例钉住转义状态（之前 19 个 HTML 用例全是正向存在性，无转义断言）。
    """
    report = Report(
        package_name="<script>alert(1)</script>",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.CONFIG_KEY,
                value="<img src=x onerror=alert(2)>",
                confidence=Confidence.HIGH,
                advice="建议调证",
                notes='a&b"c',
                source_refs=[Evidence(source="dex", location="X.java", snippet="<b>x</b>")],
            )
        ],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    path = tmp_path / "report.html"
    report_html.render(report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html  # 原始恶意标签绝不出现
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # 转义形态出现
    assert "<img src=x onerror=alert(2)>" not in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


def test_html_template_has_no_unsafe_filter() -> None:
    """模板不得使用 |safe（会绕过 autoescape 引入 XSS）——防有人将来误加。"""
    import importlib.resources

    tmpl = (
        importlib.resources.files("apkscan") / "report" / "templates" / "report.html.j2"
    ).read_text(encoding="utf-8")
    assert "|safe" not in tmpl
    assert "| safe" not in tmpl


def test_html_no_crypto_recipe_section_when_absent(sample_report: Report, tmp_path: Path) -> None:
    """无 CRYPTO_RECIPE 线索时不渲染该小节（避免空小节噪音）。"""
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")
    assert 'id="crypto-recipe"' not in html


def test_html_network_split_by_advice(sample_report: Report, tmp_path: Path) -> None:
    """主控域名（建议调证）与通联域名/IP（无需调证）分区展示。"""
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "ctrl.fraud-example.com" in html  # 主控域名（建议调证）
    assert "cdn.aliyuncs.com" in html  # 通联域名（无需调证）
    # uni-app 代码加密提示
    assert "__UNI__F7A0431" in html
    assert "plus.confusion" in html


def test_html_contains_lead_values(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "pay.fraud-example.com" in html
    assert "极光推送 JPush" in html
    assert "某聚合支付公司" in html
    assert "kefu_fraud_2024" in html


def test_html_shows_hardening_and_enrichment(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "梆梆加固" in html  # 加固状态
    assert "粤ICP备12345678号" in html  # icp 富化（主控域名行）
    assert "AS37963" in html  # asn 富化（通联 IP 行）


def test_html_renders_rdap_and_dns_enrichment(tmp_path: Path) -> None:
    """归属富化迁移回归：enrichment 改用 rdap（注册归属）+ dns（托管）后，富化单元格须渲染二者。

    旧模板只读 whois/icp/asn 三个 provider；WhoisEnricher.applies_to 置空后 pipeline 不再产
    whois 键，注册归属迁到 enrichment["rdap"]，并新增 enrichment["dns"] 托管。本用例钉住：
    - 仅有 rdap（无 icp/asn）的域名不再误判「未富化」；
    - rdap 注册商/注册人与 dns 托管 IP/ASN/org 都渲染得出来。
    """
    report = Report(
        package_name="com.x",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value="c2.fraud-gw.cn",
                subject="某科技有限公司",
                where_to_request="域名注册商",
                confidence=Confidence.HIGH,
                advice="建议调证",
            )
        ],
        endpoints=[
            Endpoint(
                value="c2.fraud-gw.cn",
                kind="domain",
                enrichment={
                    "rdap": {
                        "registrar": "GoDaddy.com, LLC",
                        "registrant": "Zhang Fraud",
                        "created": "2024-01-02T00:00:00Z",
                        "status": ["client transfer prohibited"],
                        "nameservers": ["ns1.dnspod.net"],
                        "source": "rdap",
                    },
                    "dns": {
                        "ips": ["203.0.113.9"],
                        "hosting": [
                            {
                                "ip": "203.0.113.9",
                                "asn": "AS37963",
                                "org": "Hangzhou Alibaba",
                                "country": "CN",
                                "isp": "Aliyun",
                            }
                        ],
                    },
                },
            )
        ],
        findings=[],
        analyzer_status=[],
    )
    path = tmp_path / "report.html"
    report_html.render(report, str(path))
    html = path.read_text(encoding="utf-8")

    # rdap-only 端点不得命中「未富化」分支。
    assert "未富化" not in html
    # RDAP 注册归属渲染得出来。
    assert "GoDaddy.com, LLC" in html  # 注册商
    assert "Zhang Fraud" in html  # 注册人
    # DNS 托管渲染得出来（IP / ASN / org）。
    assert "203.0.113.9" in html
    assert "AS37963" in html
    assert "Hangzhou Alibaba" in html


def test_html_shows_analyzer_status(sample_report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")

    assert "缺少 adb 能力" in html  # skipped 原因
    assert "ValueError: boom" in html  # error 原因
    assert "已跳过" in html
    assert "异常" in html


def test_html_render_empty_report(tmp_path: Path) -> None:
    """空 Report 不应崩溃，并给出空提示。"""
    empty = Report(
        package_name="com.empty.app",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    path = tmp_path / "report.html"
    report_html.render(empty, str(path))
    html = path.read_text(encoding="utf-8")
    assert "com.empty.app" in html
    # 各空线索区给出空提示，不崩溃
    assert "未抠取到配置键值" in html
    assert "未识别到「建议调证」的主控域名" in html


# --------------------------- 资源审计（exe-ready）---------------------------


def test_template_loaded_via_importlib_resources(sample_report: Report, tmp_path: Path) -> None:
    """html 模板经 importlib.resources 定位而非 Path(__file__) 相对路径，仍能正常渲染。

    锚顶层包 'apkscan'，并断言模板加载链不再引用模块级 __file__ 相对目录常量
    （exe-ready：PyInstaller onefile 下资源不是真实目录，靠 importlib.resources + as_file）。
    """
    # 模块不再保留 __file__ 相对的模板目录常量。
    assert not hasattr(report_html, "_TEMPLATE_DIR")
    # render_to_string 走 importlib.resources，渲染产物与现状一致。
    out = report_html.render_to_string(sample_report)
    assert out.lstrip().lower().startswith("<!doctype html")
    assert "ctrl.fraud-example.com" in out


# ---------------------------------------------------------------------------
# C2 标注：Lead.is_c2 / is_runtime_seen + 报告渲染
# ---------------------------------------------------------------------------


def test_lead_is_c2_only_network_and_investigate() -> None:
    from apkscan.core.models import Lead, LeadCategory

    assert Lead(category=LeadCategory.DOMAIN, value="c2.fraud.cn", advice="建议调证").is_c2 is True
    assert Lead(category=LeadCategory.IP, value="203.0.113.9", advice="建议调证").is_c2 is True
    # 无需调证（CDN/公共服务）→ 非 C2
    assert Lead(category=LeadCategory.DOMAIN, value="maps.googleapis.com", advice="无需调证").is_c2 is False
    # 非网络端点（配置键）即使建议调证也非 C2 服务器
    assert Lead(category=LeadCategory.CONFIG_KEY, value="K=V", advice="建议调证").is_c2 is False


def test_lead_is_runtime_seen() -> None:
    from apkscan.core.models import Evidence, Lead, LeadCategory

    runtime = Lead(
        category=LeadCategory.DOMAIN, value="c2.fraud.cn", advice="建议调证",
        source_refs=[Evidence(source="runtime-decrypted", location="flows", snippet="y")],
    )
    static = Lead(
        category=LeadCategory.DOMAIN, value="c2.fraud.cn", advice="建议调证",
        source_refs=[Evidence(source="dex", location="classes.dex", snippet="y")],
    )
    assert runtime.is_runtime_seen is True
    assert static.is_runtime_seen is False


def test_json_includes_c2_flags(sample_report: Report, tmp_path: Path) -> None:
    import json as _json

    from apkscan.report import json as report_json

    p = tmp_path / "r.json"
    report_json.dump(sample_report, str(p))
    data = _json.loads(p.read_text(encoding="utf-8"))
    for lead in data["leads"]:
        assert "is_c2" in lead
        assert "is_runtime_seen" in lead


def test_html_marks_c2_servers(tmp_path: Path) -> None:
    from apkscan.core.models import Evidence, Lead, LeadCategory, Report
    from apkscan.report import html as report_html

    rpt = Report(
        package_name="com.x",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.DOMAIN, value="c2.fraud-gw.cn", advice="建议调证",
                source_refs=[Evidence(source="runtime", location="flows", snippet="x")],
            ),
            Lead(category=LeadCategory.DOMAIN, value="maps.googleapis.com", advice="无需调证"),
        ],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    out = tmp_path / "r.html"
    report_html.render(rpt, str(out))
    text = out.read_text(encoding="utf-8")
    assert "C2" in text  # C2 标注出现
    assert "c2.fraud-gw.cn" in text


# ---------------------------------------------------------------------------
# 取证完整性：Evidence 注入 evidence_id（可回溯锚点）
# ---------------------------------------------------------------------------


def test_json_injects_evidence_id_on_every_evidence(sample_report: Report, tmp_path: Path) -> None:
    """每条 Evidence（line 在 lead.source_refs / endpoint.evidences / finding.evidences）
    序列化后都带 evidence_id，且与 integrity.evidence_id(source, location) 一致。"""
    import json as _json

    from apkscan.core.integrity import evidence_id
    from apkscan.report import json as report_json

    p = tmp_path / "r.json"
    report_json.dump(sample_report, str(p))
    data = _json.loads(p.read_text(encoding="utf-8"))

    seen = 0
    for lead in data["leads"]:
        for ev in lead.get("source_refs", []):
            assert "evidence_id" in ev
            assert ev["evidence_id"] == evidence_id(ev["source"], ev["location"])
            seen += 1
    for ep in data["endpoints"]:
        for ev in ep.get("evidences", []):
            assert "evidence_id" in ev
            assert ev["evidence_id"] == evidence_id(ev["source"], ev["location"])
            seen += 1
    for f in data["findings"]:
        for ev in f.get("evidences", []):
            assert "evidence_id" in ev
            assert ev["evidence_id"] == evidence_id(ev["source"], ev["location"])
            seen += 1
    assert seen > 0  # sample_report 里确有若干 Evidence，确保真的断言到了


def test_json_evidence_id_ignores_snippet(tmp_path: Path) -> None:
    """同 source|location、snippet 不同的两条证据，evidence_id 相同（id 不随 snippet 漂移）。"""
    import json as _json

    from apkscan.report import json as report_json

    rpt = Report(
        package_name="com.x",
        meta={},
        leads=[
            Lead(
                category=LeadCategory.DOMAIN,
                value="c2.example.cn",
                source_refs=[
                    Evidence(source="runtime", location="flows#0", snippet="ts=111"),
                    Evidence(source="runtime", location="flows#0", snippet="ts=999"),
                ],
            ),
        ],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    p = tmp_path / "r.json"
    report_json.dump(rpt, str(p))
    data = _json.loads(p.read_text(encoding="utf-8"))
    refs = data["leads"][0]["source_refs"]
    assert refs[0]["evidence_id"] == refs[1]["evidence_id"]


def test_html_renders_evidence_integrity_section(tmp_path: Path) -> None:
    """meta 带 evidence_manifest 时，HTML 渲染「证据完整性」小节，列检材 sha256/大小/时间/版本，
    且含克制的法律措辞（分析时间≠采集时间、md5/sha1 仅兼容冗余、不替代司法鉴定）。"""
    rpt = Report(
        package_name="com.x",
        meta={
            "evidence_manifest": {
                "sha256": "ab" * 32,
                "sha1": "cd" * 20,
                "md5": "ef" * 16,
                "size": 123456,
                "analyzed_at": "2026-06-12T00:00:00+00:00",
                "tool_version": "0.5.4",
                "platform": "Windows-11",
            },
            "sample_sha256": "ab" * 32,
        },
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    out = tmp_path / "r.html"
    report_html.render(rpt, str(out))
    html = out.read_text(encoding="utf-8")

    assert "证据完整性" in html  # 小节标题
    assert "ab" * 32 in html  # 检材 sha256
    assert "0.5.4" in html  # 工具版本
    # 法律措辞：克制、不夸大
    assert "分析时间" in html and "采集时间" in html  # 显式区分
    assert "SHA-256 为准" in html  # md5/sha1 仅兼容冗余，完整性以 sha256 为准
    assert "司法鉴定" in html  # 不替代证据保全
    # 不出现打包票措辞
    assert "法律可采性" not in html


def test_html_no_integrity_section_when_manifest_absent(sample_report: Report, tmp_path: Path) -> None:
    """meta 无 evidence_manifest 时不渲染该小节（避免空小节噪音；现有报告不受影响）。"""
    path = tmp_path / "r.html"
    report_html.render(sample_report, str(path))
    html = path.read_text(encoding="utf-8")
    assert "证据完整性" not in html
