"""证据出口契约：声明形状、缺口基线与关键值级执行锁。"""

from __future__ import annotations

import json
import base64

from apkscan.analyzers.dns_bypass import DnsBypassAnalyzer
from apkscan.analyzers.firebase import FirebaseAnalyzer
from apkscan.analyzers.manifest import ManifestAnalyzer
from apkscan.analyzers.packing import PackingAnalyzer
from apkscan.analyzers.re_toolkit import ReToolkitAnalyzer
from apkscan.analyzers.web_evidence import WebRedirectChainAnalyzer, WebRequestRecipeAnalyzer
from apkscan.analyzers.webview_jsbridge import WebViewJsBridgeAnalyzer
from apkscan.config.chain import build_control_chains
from apkscan.core.evidence_exit_contract import (
    EVIDENCE_EXITS, EVIDENCE_UNIT_INVENTORY, EXPECTED_GAPS, GapKind,
    validate_evidence_exit_contract,
)
from apkscan.core.models import Finding, Report, Severity
from apkscan.dynamic import merge
from tests.conftest import FakeContext


def test_contract_is_complete_and_gap_numbers_are_honest() -> None:
    """缺口的实际条目必须与 ``EXPECTED_GAPS`` 声明的 (单元数, 键数) 逐类对上。

    ★不再另写一份「总数 == 6」的魔数：那样同一个事实存在两处，
      接好一个出口就要记得改两个地方，忘一个就是契约自己漂移——
      正是这套机制要治的毛病，不该在它自己的测试里复现。
    """
    assert validate_evidence_exit_contract() == []
    gaps = [item for item in EVIDENCE_EXITS if item.gap is not None]
    actual: dict[GapKind, tuple[int, int]] = {}
    for item in gaps:
        units, keys = actual.get(item.gap, (0, 0))
        actual[item.gap] = (units + 1, keys + len(item.producer))
    assert actual == EXPECTED_GAPS, "缺口条目与 EXPECTED_GAPS 声明不符"


def test_every_positive_lock_names_a_real_sink_and_executable_scenario() -> None:
    """正向单元 = 清单里除去已知缺口的那些；每个都必须有 sink、场景与必达字段。"""
    positives = [item for item in EVIDENCE_EXITS if item.gap is None]
    gap_units = {item.unit for item in EVIDENCE_EXITS if item.gap is not None}
    assert {item.unit for item in positives} == EVIDENCE_UNIT_INVENTORY - gap_units
    assert all(item.sinks and item.scenario and item.projection.required for item in positives)


def test_firebase_field_gap_runs_analyzer_and_checks_each_missing_field() -> None:
    xml = ("<resources><string name='project_id'>demo-project</string>"
           "<string name='google_storage_bucket'>demo-project.appspot.com</string>"
           "<string name='google_api_key'>FAKE-API-KEY</string>"
           "<string name='gcm_defaultSenderId'>123456789012</string></resources>")
    result = FirebaseAnalyzer().analyze(FakeContext(files={"res/values/strings.xml": xml.encode()}))
    assert result.meta["firebase"] == {
        "project_id": "demo-project", "api_key": "FAKE-API-KEY",
        "sender_id": "123456789012", "storage_bucket": "demo-project.appspot.com",
    }
    rendered = "\n".join(
        [lead.value for lead in result.leads]
        + [ep.value for ep in result.endpoints]
        + [f.description for f in result.findings]
    )
    for value in ("demo-project.appspot.com", "FAKE-API-KEY", "123456789012"):
        assert value not in rendered


def test_both_container_branches_reach_a_finding() -> None:
    """★两支都要有出口：冒充核心名 → MEDIUM；仅绝对路径 → LOW（操作提示）。

    原实现在「有绝对路径但不冒充核心名」这一支直接 return，只写 meta——
    可 recommendation 里那条「别用会落盘解压的工具展开」的操作风险，
    对**所有**绝对路径条目都成立。意图不明是不下定性结论的理由，不是不告诉人的理由。
    """
    gap = PackingAnalyzer().analyze(FakeContext(files={"/tmp/note.txt": b"x"}))
    assert gap.meta["container_decoy_entries"]["absolute_path_entries"] == 1
    assert not any(f.id == "APK-CORE-NAME-DECOY-ENTRIES" for f in gap.findings)
    weak = next(f for f in gap.findings if f.id == "APK-ABSOLUTE-PATH-ENTRIES")
    assert weak.severity is Severity.LOW, "意图不明的一支不得与冒充核心名同级"
    assert "落盘解压" in weak.recommendation, "操作风险提示必须到达分析员"
    assert "/tmp/note.txt" in " ".join(ev.snippet for ev in weak.evidences)

    positive = PackingAnalyzer().analyze(
        FakeContext(files={"/classes2.dex/picture.png": b"x"})
    )
    finding = next(f for f in positive.findings if f.id == "APK-CORE-NAME-DECOY-ENTRIES")
    assert "classes2.dex" in finding.description


def test_brand_hints_value_reaches_finding(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """★行为锁：品牌词必须**带着值**进 Finding，而不只是写进 meta。

    这个出口原本不存在——写入点注释写着「供报告呈现」，但没有任何东西呈现它，
    读报告的人看不到。

    ★必须走真入口 ``decrypt_runtime_messages``，不能直接调 ``_add_brand_hint_finding``：
      本仓实证过「只调被测函数的单测永远测不到接线」——删掉调用点，那种测试照样全绿。
      我写这条时先犯了一次，突变（把调用行换成 pass）没变红才发现。
    """
    import base64
    import json

    plaintext = json.dumps({"webName": "某某证券", "note": "某某银行股份"}, ensure_ascii=False)
    runtime_report = tmp_path / "runtime_report.json"
    runtime_report.write_text(
        json.dumps({"crypto_events": [
            {"plaintext_b64": base64.b64encode(plaintext.encode()).decode()},
        ]}),
        encoding="utf-8",
    )
    report = Report(
        package_name="com.test.app", meta={}, leads=[], endpoints=[],
        findings=[], analyzer_status=[],
    )
    merge.decrypt_runtime_messages(report, str(runtime_report))

    assert "某某证券" in report.meta["runtime_brand_hints"], "夹具没触发 brand hints 抽取"
    finding = next(f for f in report.findings if f.id == "RUNTIME-BRAND-HINTS")
    assert "某某证券" in finding.description
    assert "某某证券" in " ".join(ev.snippet for ev in finding.evidences)
    # 措辞不得替人下「冒充了 X」的结论——同名可能来自第三方 SDK 文案或行业通用词。
    assert "冒充" not in finding.title
    assert "同名不等于冒充" in finding.recommendation
    # ★合规提示必须在：词条截自解密明文、判据是「命中行业词」，可能连带受害人信息片段。
    #   挂在「品牌/行业词」这个看着无害的标签下而不标敏感，比放原文更危险
    #   （凭据 Lead 走的是 RUNTIME_CREDENTIAL + 合规提示，本条须对齐）。
    assert "合规提示" in finding.description
    assert "受害人个人信息" in finding.description
    # ★分类字段不得替人断言「冒充」：它进统计与筛选，比正文更容易被当成结论。
    assert "impersonation" not in finding.category

    # ★幂等：重复合并（重跑动态 / 重渲染）不得堆出同 ID 的多条 Finding。
    merge.decrypt_runtime_messages(report, str(runtime_report))
    assert len([f for f in report.findings if f.id == "RUNTIME-BRAND-HINTS"]) == 1


def test_suspicious_version_value_reaches_finding() -> None:
    """★行为锁：命中的关键词与 versionName 必须带值进 Finding。

    原实现只写 meta 并在 docstring 里自称「研判标注」——可它谁也没告诉。
    走真入口 ``ManifestAnalyzer().analyze``，不直接调 ``_annotate_suspicious``。
    """
    xml = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.demo.app" android:versionName="1.0-马甲-debug">'
        "<application/></manifest>"
    )
    result = ManifestAnalyzer().analyze(FakeContext(manifest_xml=xml))

    assert result.meta["suspicious_version_hits"], "夹具没命中关键词"
    finding = next(f for f in result.findings if f.id == "MANIFEST-SUSPICIOUS-VERSION-NAME")
    assert "1.0-马甲-debug" in finding.description
    assert "马甲" in finding.description
    # 弱信号：份量必须压住，且不得替人定性。
    assert finding.severity is Severity.LOW
    assert "需另有证据" in finding.recommendation


def test_denial_bomb_value_reaches_finding() -> None:
    path = "assets/oversized.bin"
    result = PackingAnalyzer().analyze(FakeContext(files={path: b"x"}, declared_sizes={path: 600_000_000}))
    finding = next(f for f in result.findings if f.id == "APK-DENIAL-OF-ANALYSIS-BOMB")
    assert path in " ".join(ev.location + ev.snippet for ev in finding.evidences)


def test_dns_protocol_value_reaches_finding_and_visibility_wording() -> None:
    marker = "application/dns-message"
    result = DnsBypassAnalyzer().analyze(FakeContext(dex_strings=[marker]))
    finding = next(f for f in result.findings if f.id == "APP-MANAGED-DNS-RESOLUTION")
    assert marker in " ".join(ev.snippet for ev in finding.evidences)
    assert "SNI" in finding.recommendation


def test_manifest_anomaly_value_reaches_finding() -> None:
    anomaly = "合成清单包名交叉校验不一致"
    xml = "<manifest package='com.example.synthetic'><application/></manifest>"
    result = ManifestAnalyzer().analyze(FakeContext(manifest_xml=xml, manifest_anomaly=anomaly))
    finding = next(f for f in result.findings if f.id == "MANIFEST-PARSE-ANOMALY")
    assert anomaly in finding.description


def test_control_chain_relationship_is_archived_without_dedicated_sink() -> None:
    chains = build_control_chains(
        [{"source_url": "https://config.example.test/a", "decoded": True,
          "decode_chain": ["aes", "json"], "domains": ["api.example.test"], "ips": []}],
        {"algo": "AES", "key_encoding": "resource"}, [],
    )
    assert chains
    assert "config.example.test" in json.dumps(chains, ensure_ascii=False)
    assert "api.example.test" in json.dumps(chains, ensure_ascii=False)


def _report() -> Report:
    return Report(package_name="com.example.synthetic", meta={}, leads=[], endpoints=[],
                  findings=[], analyzer_status=[])


def test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks(monkeypatch) -> None:
    report = _report()
    static = Finding(id="SAPI-IMEI", title="读取设备标识", severity=Severity.HIGH,
                     category="sensitive_api", description="调用 getDeviceId")
    report.findings.append(static)
    events = {
        "antidetect_events": [{"kind": "root", "probe": "synthetic-root-probe"}],
        "jsbridge_events": [{"event": "register", "iface": "SyntheticBridge", "methods": "pay"}],
        "sensitive_api_events": [{"api": "TelephonyManager.getDeviceId"}],
    }
    monkeypatch.setattr(merge, "_load_events_field", lambda _path, field: events[field])
    merge.merge_runtime_traces(report, "synthetic-runtime-report.json")
    anti = next(f for f in report.findings if f.category == "anti_analysis")
    assert "root" in anti.description and "synthetic-root-probe" in " ".join(e.snippet for e in anti.evidences)
    assert any(lead.value == "JSBridge:SyntheticBridge" for lead in report.leads)
    assert any(e.source == "runtime" and "getDeviceId" in e.snippet for e in static.evidences)


def test_re_toolkit_name_and_capability_reach_finding() -> None:
    result = ReToolkitAnalyzer().analyze(
        FakeContext(native_libs=["lib/arm64-v8a/libshadowhook.so"])
    )
    tool = result.meta["re_toolkit"][0]
    finding = next(f for f in result.findings if f.id == "RE-TOOLKIT-DETECTED")
    assert tool["name"] in finding.description
    assert tool["capability"] in finding.description


def test_web_redirect_fields_reach_finding_and_endpoint() -> None:
    first = "https://first.example.test/landing"
    second = "https://second.example.test/app"
    html = (f'<meta http-equiv="refresh" content="0;url={first}">'
            f'<script>location.replace("{second}")</script>').encode()
    result = WebRedirectChainAnalyzer().analyze(FakeContext(files={"web/a.html": html}))
    hops = result.meta["web_redirect_chain"][0]["hops"]
    finding = next(f for f in result.findings if f.id == "WEB-REDIRECT-CHAIN")
    assert [(h["step"], h["target"], h["mechanism"]) for h in hops] == [
        (1, first, "meta-refresh"), (2, second, "location-call"),
    ]
    assert finding.description.index(first) < finding.description.index(second)
    assert {ep.value for ep in result.endpoints} >= {first, second}


def test_web_request_decoded_value_and_context_reach_finding() -> None:
    decoded = "X-Synthetic-Header: placeholder"
    token = base64.b64encode(decoded.encode()).decode()
    js = f'xhr.setRequestHeader(atob("{token}"));'.encode()
    result = WebRequestRecipeAnalyzer().analyze(FakeContext(files={"web/app.js": js}))
    recipe = result.meta["web_request_recipe"][0]
    finding = next(f for f in result.findings if f.id == "WEB-REQUEST-RECIPE")
    assert recipe["decoded"] == decoded
    assert recipe["context"] in finding.description.lower()
    assert decoded in finding.description


def test_webview_signal_id_reaches_matching_finding() -> None:
    result = WebViewJsBridgeAnalyzer().analyze(
        FakeContext(dex_strings=["addJavascriptInterface", "Landroid/webkit/WebView;"])
    )
    assert "WV-ADD-JS-INTERFACE" in result.meta["webview_signals"]
    finding = next(f for f in result.findings if f.id == "WV-ADD-JS-INTERFACE")
    assert any("addJavascriptInterface" in ev.snippet for ev in finding.evidences)
