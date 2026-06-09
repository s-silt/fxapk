"""deeplink_surface 分析器单测：FakeContext 喂合成 manifest，断言 deeplink 枚举 / Finding。"""

from __future__ import annotations

from apkscan.analyzers.deeplink_surface import DeeplinkSurfaceAnalyzer
from apkscan.core.models import Severity
from tests.conftest import FakeContext

_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def _manifest(body: str) -> str:
    return f'<?xml version="1.0"?><manifest {_NS} package="com.test.app"><application>{body}</application></manifest>'


def _run(body: str):
    return DeeplinkSurfaceAnalyzer().analyze(FakeContext(manifest_xml=_manifest(body)))


def _activity(name: str, *, exported: str | None, filter_body: str) -> str:
    exp = f' android:exported="{exported}"' if exported is not None else ""
    return f'<activity android:name="{name}"{exp}><intent-filter>{filter_body}</intent-filter></activity>'


_BROWSABLE = '<action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/>'


# ---------------------------------------------------------------------------
# deeplink 枚举 + Finding
# ---------------------------------------------------------------------------


def test_browsable_deeplink_yields_finding() -> None:
    body = _activity("com.x.JumpActivity", exported="true", filter_body=_BROWSABLE + '<data android:scheme="myapp" android:host="open"/>')
    r = _run(body)
    f = next(iter(r.findings))
    assert f.category == "attack_surface"
    assert "myapp" in f.description
    assert r.meta["deeplinks"][0]["uri"] == "myapp://open"
    assert r.meta["browsable_deeplink_count"] == 1


def test_high_risk_component_name_is_high() -> None:
    body = _activity("com.x.WebViewActivity", exported="true", filter_body=_BROWSABLE + '<data android:scheme="myapp"/>')
    r = _run(body)
    f = next(iter(r.findings))
    assert f.severity == Severity.HIGH  # 名字含 webview


def test_ordinary_component_is_medium() -> None:
    body = _activity("com.x.LandingActivity", exported="true", filter_body=_BROWSABLE + '<data android:scheme="appx"/>')
    r = _run(body)
    f = next(iter(r.findings))
    assert f.severity == Severity.MEDIUM


def test_launcher_without_scheme_no_deeplink() -> None:
    body = _activity(
        "com.x.MainActivity",
        exported="true",
        filter_body='<action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/>',
    )
    r = _run(body)
    assert r.findings == []
    assert r.meta["deeplinks"] == []


def test_explicit_exported_false_skipped() -> None:
    body = _activity("com.x.Internal", exported="false", filter_body=_BROWSABLE + '<data android:scheme="myapp"/>')
    r = _run(body)
    assert r.findings == []


def test_implicit_exported_with_filter_included() -> None:
    """未声明 exported + 有 intent-filter → 隐式导出（保守按可外部触发处理）。"""
    body = _activity("com.x.Implicit", exported=None, filter_body=_BROWSABLE + '<data android:scheme="myapp"/>')
    r = _run(body)
    assert "myapp" in next(iter(r.findings)).description


def test_http_scheme_without_host_skipped() -> None:
    """纯 http/https 无 host 是 App Links，不计入自定义 scheme deeplink 攻击面。"""
    body = _activity("com.x.A", exported="true", filter_body=_BROWSABLE + '<data android:scheme="https"/>')
    r = _run(body)
    assert r.meta["deeplinks"] == []


def test_browsable_required() -> None:
    """无 BROWSABLE category 的 scheme filter 不产 Finding（非外部网页可达）。"""
    body = _activity(
        "com.x.A",
        exported="true",
        filter_body='<action android:name="android.intent.action.VIEW"/><data android:scheme="myapp"/>',
    )
    r = _run(body)
    assert r.findings == []
    # 但仍枚举进 meta（scheme 存在）
    assert r.meta["deeplinks"] and r.meta["deeplinks"][0]["browsable"] is False


def test_multiple_schemes_each_enumerated() -> None:
    body = _activity(
        "com.x.Multi",
        exported="true",
        filter_body=_BROWSABLE + '<data android:scheme="aaa"/><data android:scheme="bbb"/>',
    )
    r = _run(body)
    schemes = {d["uri"].split(":")[0] for d in r.meta["deeplinks"]}
    assert schemes == {"aaa", "bbb"}


# ---------------------------------------------------------------------------
# 鲁棒性
# ---------------------------------------------------------------------------


def test_empty_manifest_no_findings() -> None:
    r = DeeplinkSurfaceAnalyzer().analyze(FakeContext(manifest_xml=""))
    assert r.findings == []
    assert r.meta["deeplinks"] == []


def test_no_application_no_crash() -> None:
    r = DeeplinkSurfaceAnalyzer().analyze(
        FakeContext(manifest_xml=f'<manifest {_NS} package="com.x"></manifest>')
    )
    assert r.findings == []


def test_bad_xml_sets_error_no_crash() -> None:
    r = DeeplinkSurfaceAnalyzer().analyze(FakeContext(manifest_xml="<manifest <<<broken"))
    assert r.error is not None
    assert r.findings == []


def test_xxe_manifest_rejected() -> None:
    xxe = (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "x">]>'
        f'<manifest {_NS} package="com.x"><application></application></manifest>'
    )
    r = DeeplinkSurfaceAnalyzer().analyze(FakeContext(manifest_xml=xxe))
    assert r.error is not None  # 含 DTD/实体 → 拒绝
    assert r.findings == []
