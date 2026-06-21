"""高敏值脱敏（隐私安全）测试 + digest 默认脱敏验证。"""

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


def test_digest_redacts_sensitive_by_default() -> None:
    report = {
        "meta": {"package_name": "com.x"},
        "leads": [
            {"category": "WALLET_SECRET", "value": "abandon abandon about real mnemonic here",
             "advice": "建议调证", "confidence": "HIGH"},
            {"category": "DOMAIN", "value": "c2.evil.com", "advice": "建议调证", "confidence": "HIGH"},
        ],
    }
    d = build_digest(report)  # 默认脱敏
    wallet = next(lead for lead in d["leads"] if lead["category"] == "WALLET_SECRET")
    domain = next(lead for lead in d["leads"] if lead["category"] == "DOMAIN")
    assert "已脱敏" in wallet["value"] and "real mnemonic" not in wallet["value"]
    assert domain["value"] == "c2.evil.com"  # 非高敏不脱敏


def test_digest_raw_keeps_plaintext() -> None:
    report = {"leads": [{"category": "WALLET_SECRET", "value": "secret mnemonic words here all",
                         "advice": "建议调证", "confidence": "HIGH"}]}
    d = build_digest(report, redact=False)
    assert d["leads"][0]["value"] == "secret mnemonic words here all"
