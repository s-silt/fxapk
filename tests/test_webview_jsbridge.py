"""webview_jsbridge 分析器单测：FakeContext 喂合成 DEX/资源，断言 Finding / 桥接 Lead。"""

from __future__ import annotations

from apkscan.analyzers import webview_jsbridge
from apkscan.analyzers.webview_jsbridge import (
    WebViewJsBridgeAnalyzer,
    _is_h5_resource,
)
from apkscan.core.models import Confidence, LeadCategory, Severity
from tests.conftest import FakeContext


def _run(dex_strings=None, files=None):
    return WebViewJsBridgeAnalyzer().analyze(
        FakeContext(dex_strings=dex_strings or [], files=files or {})
    )


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def _sev(result, fid: str) -> Severity:
    return next(f.severity for f in result.findings if f.id == fid)


# ---------------------------------------------------------------------------
# dex 信号
# ---------------------------------------------------------------------------


def test_addjsinterface_dex_token_yields_high_finding() -> None:
    r = _run(dex_strings=["addJavascriptInterface", "Landroid/webkit/WebView;"])
    assert "WV-ADD-JS-INTERFACE" in _ids(r)
    assert _sev(r, "WV-ADD-JS-INTERFACE") == Severity.HIGH
    f = next(f for f in r.findings if f.id == "WV-ADD-JS-INTERFACE")
    assert f.category == "webview"
    assert f.evidences[0].source == "dex"


def test_dangerous_websettings_combo_requires_all_tokens() -> None:
    # 仅一个 token → 不触发组合信号
    r1 = _run(dex_strings=["setJavaScriptEnabled"])
    assert "WV-DANGEROUS-WEBSETTINGS" not in _ids(r1)
    # 两个 token 共现 → HIGH
    r2 = _run(dex_strings=["setJavaScriptEnabled", "setAllowFileAccessFromFileURLs"])
    assert "WV-DANGEROUS-WEBSETTINGS" in _ids(r2)
    assert _sev(r2, "WV-DANGEROUS-WEBSETTINGS") == Severity.HIGH


def test_universal_access_single_token_high() -> None:
    r = _run(dex_strings=["setAllowUniversalAccessFromFileURLs"])
    assert "WV-UNIVERSAL-ACCESS" in _ids(r)


def test_evaluate_javascript_is_medium() -> None:
    r = _run(dex_strings=["evaluateJavascript"])
    assert "WV-EVALUATE-JS" in _ids(r)
    assert _sev(r, "WV-EVALUATE-JS") == Severity.MEDIUM


def test_evaluate_js_via_resource_token() -> None:
    """WV-EVALUATE-JS 也能由 H5 资源里的 javascript: 触发（resource 路径）。"""
    r = _run(files={"assets/www/a.js": b'location.href="javascript:alert(1)"'})
    assert "WV-EVALUATE-JS" in _ids(r)
    f = next(f for f in r.findings if f.id == "WV-EVALUATE-JS")
    assert any(ev.source == "resource" for ev in f.evidences)


def test_save_password_signal() -> None:
    r = _run(dex_strings=["setSavePassword"])
    assert "WV-SAVE-PASSWORD" in _ids(r)
    assert _sev(r, "WV-SAVE-PASSWORD") == Severity.MEDIUM


def test_dex_match_is_substring_not_word_boundary() -> None:
    """webview dex 用子串匹配（要匹配框架包前缀），与 sensitive_api 的词边界不同。"""
    # com.tencent.smtt 作为前缀子串命中完整类名
    r = _run(dex_strings=["com.tencent.smtt.sdk.WebView"])
    assert any(l.value == "JSBridge:com.tencent.smtt" for l in r.leads)


# ---------------------------------------------------------------------------
# 资源（H5）信号
# ---------------------------------------------------------------------------


def test_h5_window_bridge_in_assets_js() -> None:
    r = _run(
        files={
            "assets/apps/__UNI__X/www/app-service.js": b"foo(); window.webkit.messageHandlers.bridge.postMessage(1);"
        }
    )
    assert "WV-H5-BRIDGE-CALL" in _ids(r)
    f = next(f for f in r.findings if f.id == "WV-H5-BRIDGE-CALL")
    assert any(ev.source == "resource" for ev in f.evidences)


def test_non_h5_path_js_ignored() -> None:
    """不在 assets/www 下的 .js 不参与资源扫描。"""
    r = _run(files={"res/raw/x.js": b"window.webkit.messageHandlers.foo.postMessage(1)"})
    assert "WV-H5-BRIDGE-CALL" not in _ids(r)


# ---------------------------------------------------------------------------
# 桥接框架 → CONFIG_KEY Lead
# ---------------------------------------------------------------------------


def test_known_bridge_framework_yields_configkey_lead() -> None:
    r = _run(dex_strings=["com.tencent.smtt.sdk.WebView", "addJavascriptInterface"])
    bridge_leads = [l for l in r.leads if l.category == LeadCategory.CONFIG_KEY]
    assert bridge_leads
    lead = bridge_leads[0]
    assert lead.value.startswith("JSBridge:")
    assert "com.tencent.smtt" in lead.value
    assert lead.subject  # 厂商
    assert lead.confidence == Confidence.HIGH


def test_dcloud_uniapp_bridge_hint() -> None:
    r = _run(dex_strings=["io.dcloud.feature.weex"])
    assert any(l.value == "JSBridge:io.dcloud" for l in r.leads)


def test_multiple_bridge_frameworks_yield_distinct_leads() -> None:
    """同一 APK 命中多个不同框架 → 多条不同 Lead；同框架 token 去重。"""
    r = _run(dex_strings=["com.tencent.smtt.sdk.WebView", "io.dcloud.feature.weex", "io.dcloud.x"])
    values = sorted(l.value for l in r.leads if l.category == LeadCategory.CONFIG_KEY)
    assert values == ["JSBridge:com.tencent.smtt", "JSBridge:io.dcloud"]  # io.dcloud 去重为 1


# ---------------------------------------------------------------------------
# _is_h5_resource 路径形态
# ---------------------------------------------------------------------------


def test_is_h5_resource_path_forms() -> None:
    assert _is_h5_resource("assets/apps/__UNI__X/www/app.js") is True
    assert _is_h5_resource("app/www/x.html") is True  # /www/ 非 assets 前缀也算
    assert _is_h5_resource("assets\\www\\a.js") is True  # 反斜杠归一化
    assert _is_h5_resource("assets/dist/index.js") is True  # assets 下 .js
    assert _is_h5_resource("assets/a.htm") is True
    assert _is_h5_resource("assets/config.json") is False  # 非 .js/.html
    assert _is_h5_resource("res/raw/x.js") is False  # 非 assets/非 www


# ---------------------------------------------------------------------------
# 空 / 鲁棒性
# ---------------------------------------------------------------------------


def test_no_webview_no_findings() -> None:
    r = _run(dex_strings=["java.lang.String", "onCreate"])
    assert r.findings == []
    assert r.leads == []
    assert r.meta["webview_signals"] == []
    assert r.meta["webview_signal_count"] == 0
    assert r.error is None


def test_dex_iteration_error_does_not_crash() -> None:
    class _BoomCtx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("dex boom")

    r = WebViewJsBridgeAnalyzer().analyze(_BoomCtx())
    assert r.meta["dex_scanned"] is False
    assert isinstance(r.findings, list)  # 不抛


def test_read_file_error_does_not_crash() -> None:
    class _BoomReadCtx(FakeContext):
        def read_file(self, path: str):  # type: ignore[override]
            raise RuntimeError("read boom")

    ctx = _BoomReadCtx(files={"assets/www/app.js": b"window.webkit.messageHandlers"})
    r = WebViewJsBridgeAnalyzer().analyze(ctx)
    # 单文件读取异常被吞，不影响整体（不抛）
    assert isinstance(r.findings, list)


def test_rules_missing_uses_no_findings(monkeypatch) -> None:
    monkeypatch.setattr(webview_jsbridge, "load_rules", lambda name: {})
    r = _run(dex_strings=["addJavascriptInterface"])
    assert r.findings == []
    assert r.leads == []


def test_bad_signal_entries_skipped(monkeypatch) -> None:
    monkeypatch.setattr(
        webview_jsbridge,
        "load_rules",
        lambda name: {
            "signals": [
                "not-a-dict",
                {"title": "缺 id"},
                {"id": "NOTOK"},  # 无任何 token
                {"id": "OK", "dex_tokens": ["addJavascriptInterface"], "severity": "HIGH"},
            ],
            "bridge_object_hints": "not-a-dict",  # 容错
        },
    )
    r = _run(dex_strings=["addJavascriptInterface"])
    assert _ids(r) == {"OK"}
    assert r.leads == []  # bridge_object_hints 非 dict，安全跳过


def test_resource_none_and_empty_bytes_skipped() -> None:
    """read_file 返回 None / 空 bytes 的资源被安全跳过，不崩。"""
    files = {
        "assets/www/empty.js": b"",  # 空
        "assets/www/real.js": b"window.webkit.messageHandlers.x.postMessage(1)",
    }
    r = WebViewJsBridgeAnalyzer().analyze(FakeContext(files=files))
    assert "WV-H5-BRIDGE-CALL" in _ids(r)  # 真文件命中，空文件不影响


def test_bridge_hint_empty_vendor_subject_none(monkeypatch) -> None:
    """桥接 hint 厂商为空 → Lead.subject=None，不崩。"""
    monkeypatch.setattr(
        webview_jsbridge,
        "load_rules",
        lambda name: {"signals": [], "bridge_object_hints": {"my.custom.bridge": ""}},
    )
    r = _run(dex_strings=["my.custom.bridge.Foo"])
    leads = [l for l in r.leads if l.value == "JSBridge:my.custom.bridge"]
    assert leads
    assert leads[0].subject is None
