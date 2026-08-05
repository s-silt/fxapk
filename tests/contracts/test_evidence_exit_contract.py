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
    EVIDENCE_EXITS, EXPECTED_GAPS, GapKind, validate_evidence_exit_contract,
)
from apkscan.core.models import Finding, Report, Severity
from apkscan.dynamic import merge
from tests.conftest import FakeContext


def test_contract_is_complete_and_gap_numbers_are_honest() -> None:
    assert validate_evidence_exit_contract() == []
    gaps = [item for item in EVIDENCE_EXITS if item.gap is not None]
    assert len(gaps) == 6
    assert sum(len(item.producer) for item in gaps) == 7
    assert EXPECTED_GAPS == {
        GapKind.COMPLETE: (3, 4), GapKind.CONDITIONAL: (2, 2), GapKind.FIELD: (1, 1),
    }


def test_every_positive_lock_names_a_real_sink_and_executable_scenario() -> None:
    positives = [item for item in EVIDENCE_EXITS if item.gap is None]
    assert len(positives) == 13
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


def test_conditional_container_gap_and_positive_decoy_branch() -> None:
    gap = PackingAnalyzer().analyze(FakeContext(files={"/tmp/note.txt": b"x"}))
    assert gap.meta["container_decoy_entries"]["absolute_path_entries"] == 1
    assert not any(f.id == "APK-CORE-NAME-DECOY-ENTRIES" for f in gap.findings)

    positive = PackingAnalyzer().analyze(
        FakeContext(files={"/classes2.dex/picture.png": b"x"})
    )
    finding = next(f for f in positive.findings if f.id == "APK-CORE-NAME-DECOY-ENTRIES")
    assert "classes2.dex" in finding.description


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


def test_suspicious_version_two_key_unit_is_meta_only() -> None:
    manifest = ("<manifest xmlns:android='http://schemas.android.com/apk/res/android' "
                "android:versionName='1.0-test'><application/></manifest>")
    result = ManifestAnalyzer().analyze(FakeContext(manifest_xml=manifest))
    assert result.meta["suspicious_version_name"] is True
    assert "test" in result.meta["suspicious_version_hits"]
    assert not any("versionName" in f.description and "test" in f.description for f in result.findings)


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
