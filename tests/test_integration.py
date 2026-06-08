"""端到端集成测试：用真实的全部分析器跑 pipeline.run（不 monkeypatch 发现），
离线模式（不触网），断言各类调证线索都产出，且 HTML / JSON 报告能落盘。

这是对"自动发现 + 全分析器 + 端点→Lead + 报告渲染"的真实链路覆盖，
无需 androguard、无需网络（FakeContext + online=False）。
"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, CertInfo, Component, ComponentSet, LeadCategory
from apkscan.report import html as html_report
from apkscan.report import json as json_report

from tests.conftest import FakeContext


def _rich_ctx() -> FakeContext:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.fraud.app" android:versionName="2.3.1" android:versionCode="231">'
        '<uses-permission android:name="android.permission.READ_SMS"/>'
        '<application android:debuggable="true">'
        '<activity android:name=".Main" android:exported="true"/>'
        '</application></manifest>'
    )
    cert = CertInfo(
        subject="CN=Fraud Dev, O=Shadow Co",
        issuer="CN=Fraud Dev, O=Shadow Co",
        sha256="d" * 64,
        not_before="2024-01-01T00:00:00",
        not_after="2025-01-01T00:00:00",
        schemes=["v1", "v2"],
    )
    return FakeContext(
        package_name="com.fraud.app",
        manifest_xml=manifest,
        permissions=["android.permission.READ_SMS", "android.permission.INTERNET"],
        files={
            "AndroidManifest.xml": manifest.encode("utf-8"),
            "assets/config.json": b'{"notify_url":"https://pay.fraud.cn/cb","mail":"boss@fraud.cn"}',
            "lib/arm64-v8a/libjiagu.so": b"\x7fELF",
        },
        dex_strings=[
            "https://pay.fraud.cn/notify",
            "http://1.2.3.4:8080/api",
            "cn.jpush.android.api.JPushInterface",
            "com.alipay.sdk.app.PayTask",
            '{"mch_id":"1900000109"}',
            "加QQ:123456 咨询",
            "客服微信：abc_def123",
            "充值 USDT TRC20",
        ],
        native_libs=["lib/arm64-v8a/libjiagu.so"],
        certificates=[cert],
        components=ComponentSet(
            activities=[Component(name="com.fraud.app.Main", exported=True, kind="activity")],
        ),
        online=False,
    )


def test_full_pipeline_produces_all_lead_categories():
    report = pipeline.run(_rich_ctx(), AnalysisConfig(online=False))

    cats = {lead.category for lead in report.leads}
    # 涉诈调证核心几类线索都应产出
    for expected in (
        LeadCategory.PAYMENT,
        LeadCategory.CONTACT,
        LeadCategory.SDK_SERVICE,
        LeadCategory.DOMAIN,
        LeadCategory.IP,
        LeadCategory.PACKER,
        LeadCategory.SIGNING,
    ):
        assert expected in cats, f"缺少线索类别：{expected}"

    # 加固命中 360（libjiagu.so），meta 键供报告概览消费
    assert report.meta.get("is_hardened") is True
    assert "360" in (report.meta.get("packer") or "")

    # 证书 meta 对接报告概览/附录
    assert report.meta.get("sign_subject")
    assert isinstance(report.meta.get("certificates"), list) and report.meta["certificates"]

    # 离线标记：归属未查询而非查无结果
    assert report.meta.get("enrichment_skipped_offline") is True

    # 分析器状态全覆盖（10 个分析器，全部 ran/有记录）
    names = {s["name"] for s in report.analyzer_status}
    assert {"payment", "contacts", "sdk_fingerprint", "packing"} <= names


def test_full_pipeline_offline_domain_lead_marked():
    report = pipeline.run(_rich_ctx(), AnalysisConfig(online=False))
    domain_leads = [l for l in report.leads if l.category == LeadCategory.DOMAIN]
    assert domain_leads
    # 离线时域名归属应标注"未查询"
    assert any("离线扫描" in (l.notes or "") for l in domain_leads)


def test_reports_render_to_files(tmp_path: Path):
    report = pipeline.run(_rich_ctx(), AnalysisConfig(online=False))

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    json_report.dump(report, str(json_path))
    html_report.render(report, str(html_path))

    assert json_path.is_file() and html_path.is_file()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["package_name"] == "com.fraud.app"
    assert data["leads"]  # 非空
    assert "enricher_status" in data  # 新字段已序列化

    html = html_path.read_text(encoding="utf-8")
    assert "调证线索清单" in html
    assert "支付宝" in html or "Alipay" in html  # 支付 SDK 线索进入报告
    assert "离线模式" in html  # 离线说明 banner
