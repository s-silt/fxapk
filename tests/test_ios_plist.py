"""ios_plist 分析器单测：FakeContext 喂 Info.plist（binary plist），断言各类线索。"""

from __future__ import annotations

import plistlib

from apkscan.analyzers.ios_plist import IosPlistAnalyzer
from apkscan.core.models import Severity
from tests.conftest import FakeContext

_PLIST_PATH = "Payload/Demo.app/Info.plist"


def _run(plist: dict):
    raw = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY)
    ctx = FakeContext(files={_PLIST_PATH: raw}, platform="ios")
    return IosPlistAnalyzer().analyze(ctx)


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def test_url_scheme_attack_surface():
    r = _run({"CFBundleIdentifier": "com.x", "CFBundleURLTypes": [{"CFBundleURLSchemes": ["evilpay", "demoapp"]}]})
    assert "IOS-URL-SCHEME" in _ids(r)
    f = next(f for f in r.findings if f.id == "IOS-URL-SCHEME")
    assert f.category == "attack_surface"
    assert "evilpay" in f.description
    assert r.meta["ios_url_schemes"] == ["evilpay", "demoapp"]


def test_ats_arbitrary_loads_high():
    r = _run({"CFBundleIdentifier": "com.x", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})
    assert "IOS-ATS-CLEARTEXT" in _ids(r)
    f = next(f for f in r.findings if f.id == "IOS-ATS-CLEARTEXT")
    assert f.severity == Severity.HIGH
    assert f.category == "security"


def test_ats_exception_domains_medium():
    r = _run({"CFBundleIdentifier": "com.x", "NSAppTransportSecurity": {"NSExceptionDomains": {"evil.com": {}}}})
    f = next(f for f in r.findings if f.id == "IOS-ATS-CLEARTEXT")
    assert f.severity == Severity.MEDIUM
    assert "evil.com" in f.description


def test_ats_clean_no_finding():
    r = _run({"CFBundleIdentifier": "com.x", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}})
    assert "IOS-ATS-CLEARTEXT" not in _ids(r)


def test_query_pay_apps():
    r = _run({"CFBundleIdentifier": "com.x", "LSApplicationQueriesSchemes": ["alipay", "weixin", "http"]})
    assert "IOS-QUERY-PAYAPP" in _ids(r)
    assert set(r.meta["ios_finance_queries"]) == {"alipay", "weixin"}  # http 不算


def test_sensitive_usage_descriptions():
    r = _run({
        "CFBundleIdentifier": "com.x",
        "NSContactsUsageDescription": "需要通讯录",
        "NSCameraUsageDescription": "需要相机",
    })
    assert "IOS-USAGE-DESC" in _ids(r)
    f = next(f for f in r.findings if f.id == "IOS-USAGE-DESC")
    assert f.category == "permission"
    assert "通讯录" in f.description and "相机" in f.description


def test_impersonated_brand_lead():
    r = _run({"CFBundleIdentifier": "com.evil.demo", "CFBundleDisplayName": "示例证券"})
    leads = [l for l in r.leads if l.value.startswith("iOS:")]
    assert leads
    assert leads[0].subject == "示例证券"
    assert r.meta["ios_bundle_id"] == "com.evil.demo"
    assert r.meta["ios_display_name"] == "示例证券"


def test_no_info_plist_no_crash():
    ctx = FakeContext(files={"Payload/Demo.app/www/app.js": b"x"}, platform="ios")
    r = IosPlistAnalyzer().analyze(ctx)
    assert r.findings == []
    assert r.error is None


def test_benign_plist_no_noise():
    r = _run({"CFBundleIdentifier": "com.x", "CFBundleVersion": "1.0"})
    assert r.findings == []  # 没有 URL scheme/ATS/敏感权限 → 无 Finding（只产品牌 Lead）
