"""load_app 分流单测：APK/IPA 路由 + extra_dex 仅对 APK 生效（过去只被 IPA 侧间接覆盖）。"""

from __future__ import annotations

import logging
import plistlib
import zipfile
from pathlib import Path

from apkscan.core import apk as apk_mod
from apkscan.core.loader import load_app
from apkscan.core.models import AnalysisConfig


def _make_ipa(tmp_path: Path) -> str:
    p = tmp_path / "demo.ipa"
    root = "Payload/Demo.app/"
    plist = {"CFBundleIdentifier": "com.evil.demo", "CFBundleExecutable": "Demo"}
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr(root + "Info.plist", plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
    return str(p)


def test_load_app_routes_ipa_to_ipacontext(tmp_path: Path) -> None:
    ctx = load_app(_make_ipa(tmp_path), AnalysisConfig(online=False))
    assert getattr(ctx, "platform", "android") == "ios"
    assert ctx.package_name == "com.evil.demo"
    getattr(ctx, "close", lambda: None)()


def test_load_app_routes_non_ipa_to_load_apk(tmp_path: Path, monkeypatch) -> None:
    """非 IPA → 走 load_apk，且 extra_dex 透传（不需要 androguard：打桩 load_apk）。"""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 64)  # 像 APK（非 IPA：无 Payload/）
    captured: dict[str, object] = {}

    def _fake_load_apk(path: str, config: AnalysisConfig, extra_dex=None):  # noqa: ANN001
        captured["path"] = path
        captured["extra_dex"] = extra_dex
        return "APKCTX"

    monkeypatch.setattr(apk_mod, "load_apk", _fake_load_apk)
    result = load_app(str(apk), AnalysisConfig(online=False), extra_dex=["/x/a.dex"])
    assert result == "APKCTX"
    assert captured["path"] == str(apk)
    assert captured["extra_dex"] == ["/x/a.dex"]  # extra_dex 透传给 APK


def test_load_app_ipa_ignores_extra_dex(tmp_path: Path, caplog) -> None:  # noqa: ANN001
    """IPA + extra_dex → 忽略 extra_dex 且记日志（IPA 无 DEX）。"""
    with caplog.at_level(logging.INFO):
        ctx = load_app(_make_ipa(tmp_path), AnalysisConfig(online=False), extra_dex=["/x/a.dex"])
    assert getattr(ctx, "platform", "android") == "ios"
    assert any("忽略 extra_dex" in r.message for r in caplog.records)
    getattr(ctx, "close", lambda: None)()
