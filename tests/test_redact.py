"""高敏值脱敏（隐私安全）测试 + digest 可选脱敏验证（默认明文，--redact 才脱敏）。"""

from __future__ import annotations

from apkscan.core.redact import mask, redact_value
from apkscan.report.digest import build_digest


def test_mask_short_and_long() -> None:
    assert mask("abc") == "***（已脱敏）"
    assert mask("") == ""
    masked = mask("abandon abandon about ...long mnemonic...")
    assert masked.startswith("aba") and "已脱敏" in masked and "abandon abandon" not in masked


def test_redact_value_only_sensitive() -> None:
    assert "已脱敏" in str(redact_value("WALLET_SECRET", "abandon abandon about end here"))
    assert "已脱敏" in str(redact_value("BACKEND_CREDENTIAL", "Basic admin:s3cretpass"))
    # 非高敏类别原样返回。
    assert redact_value("DOMAIN", "evil.com") == "evil.com"
    assert redact_value("ADMIN_PANEL", "admin.evil.com") == "admin.evil.com"


def test_digest_redact_is_opt_in() -> None:
    report = {
        "meta": {"package_name": "com.x"},
        "leads": [
            {"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
             "advice": "建议调证", "confidence": "HIGH"},
            {"category": "DOMAIN", "value": "c2.evil.com", "advice": "建议调证", "confidence": "HIGH"},
        ],
    }
    # 默认明文（取证查看需要看到实际值）。
    d_raw = build_digest(report)
    wallet_raw = next(lead for lead in d_raw["leads"] if lead["category"] == "WALLET_SECRET")
    assert wallet_raw["value"] == "abandon abandon about real mnemonic here"
    # --redact / redact=True 时才脱敏（喂云端 agent）。
    d_red = build_digest(report, redact=True)
    wallet_red = next(lead for lead in d_red["leads"] if lead["category"] == "WALLET_SECRET")
    domain = next(lead for lead in d_red["leads"] if lead["category"] == "DOMAIN")
    assert "已脱敏" in wallet_red["value"] and "real mnemonic" not in wallet_red["value"]
    assert domain["value"] == "c2.evil.com"  # 非高敏不脱敏
