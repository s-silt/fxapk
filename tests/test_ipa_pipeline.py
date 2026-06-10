"""IPA 端到端门控测试：合成 IPA → load_ipa → pipeline.run，断言平台门控 + H5 线索。"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

from apkscan.core import pipeline
from apkscan.core.loader import load_app
from apkscan.core.models import AnalysisConfig

# IPA 上预期跑/跳的 analyzer（与设计一致）。
_IPA_SKIPPED = {
    "permissions", "components", "manifest", "deeplink_surface",
    "certificate", "sdk_fingerprint", "sensitive_api", "packing", "jadx",
}
_IPA_RAN = {
    "js_bundle", "crypto_recipe", "endpoints", "config_keys",
    "contacts", "payment", "webview_jsbridge", "crypto", "ios_plist",
}


def _make_ipa(tmp_path: Path) -> str:
    p = tmp_path / "fraud.ipa"
    root = "Payload/Fraud.app/"
    plist = {
        "CFBundleIdentifier": "com.evil.fraud",
        "CFBundleDisplayName": "示例证券",
        "CFBundleExecutable": "Fraud",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["fraudpay"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    # 真样本形态 H5：C2 端点 + 变量 key 的 AES 配方。
    js = (
        b'var api="https://c2.evil-fraud.vip/api/login";'
        b'var wl="55f0e4afd83cf8dcae7a4d3daf663467";'
        b'CryptoJS.AES.encrypt(yu(d),CryptoJS.enc.Utf8.parse(wl),'
        b'{mode:CryptoJS.mode.CFB,padding:CryptoJS.pad.Pkcs7});'
        b'var iv=CryptoJS.MD5(wl+ts).toString().substring(0,16);'
    )
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(root + "Info.plist", plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
        zf.writestr(root + "www/app-service.js", js)
        zf.writestr(root + "Fraud", b"some readable string " * 10)
    return str(p)


def test_ipa_pipeline_gating_and_h5_intel(tmp_path):
    ctx = load_app(_make_ipa(tmp_path), AnalysisConfig(online=False))
    report = pipeline.run(ctx, AnalysisConfig(online=False))

    status = {s["name"]: s["status"] for s in report.analyzer_status}
    # 9 个 Android 专属全 skipped，reason 含 apk
    for name in _IPA_SKIPPED:
        assert status.get(name) == "skipped", f"{name} 应 skipped，实际 {status.get(name)}"
    for s in report.analyzer_status:
        if s["name"] in _IPA_SKIPPED:
            assert "apk" in s["reason"]
    # 字符串型 + ios_plist 全 ran
    for name in _IPA_RAN:
        assert status.get(name) == "ran", f"{name} 应 ran，实际 {status.get(name)}"

    # 平台标志 + 不当加固告警
    assert report.meta["platform"] == "ios"
    assert report.meta.get("dex_parse_failed") is False

    # H5 核心调证链：C2 端点 + 加密配方 + 冒充品牌
    values = {e.value for e in report.endpoints}
    assert any("c2.evil-fraud.vip" in v for v in values)
    recipe = report.meta.get("crypto_recipe")
    assert isinstance(recipe, dict) and recipe.get("key") == "55f0e4afd83cf8dcae7a4d3daf663467"
    # ios_plist 线索
    fids = {f.id for f in report.findings}
    assert {"IOS-URL-SCHEME", "IOS-ATS-CLEARTEXT"} <= fids
