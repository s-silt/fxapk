"""PaymentAnalyzer 测试：支付 SDK 指纹 + 资金关键字 → PAYMENT 线索。

用 FakeContext 喂合成数据，配真实 apkscan/rules/payment.yaml 规则验证命中/不命中。
"""

from __future__ import annotations

from apkscan.analyzers.payment import PaymentAnalyzer
from apkscan.core.models import Confidence, LeadCategory

from tests.conftest import FakeContext


def _pay_leads(result):
    return [l for l in result.leads if l.category == LeadCategory.PAYMENT]


def test_alipay_sdk_hit_via_dex_prefix():
    ctx = FakeContext(dex_strings=["com.alipay.sdk.app.PayTask", "随便一条无关字符串"])
    result = PaymentAnalyzer().analyze(ctx)

    leads = _pay_leads(result)
    assert leads, "应识别到支付宝 SDK"
    lead = next(l for l in leads if "支付宝" in l.value or "Alipay" in l.value)
    assert "支付宝" in (lead.subject or "")
    assert lead.evidence_to_obtain  # 有可调取证据
    assert lead.source_refs and lead.source_refs[0].source == "dex"
    assert "支付宝 (Alipay SDK)" in result.meta["payment_sdks"]


def test_sdk_so_hit_is_high_confidence():
    ctx = FakeContext(
        native_libs=["lib/arm64-v8a/libalipayssl.so"],
        files={"lib/arm64-v8a/libalipayssl.so": b"\x7fELF"},
    )
    result = PaymentAnalyzer().analyze(ctx)
    leads = _pay_leads(result)
    assert leads
    # 命中 .so（强特征）→ HIGH
    assert any(l.confidence == Confidence.HIGH for l in leads)


def test_merchant_id_keyword_is_strong_high():
    ctx = FakeContext(dex_strings=['{"mch_id":"1900000109","body":"x"}'])
    result = PaymentAnalyzer().analyze(ctx)
    leads = _pay_leads(result)
    assert leads
    mch = next(l for l in leads if "商户号" in l.value)
    assert mch.confidence == Confidence.HIGH  # strong=true
    assert "商户号 (mch_id / merchant id)" in result.meta["payment_keywords"]


def test_usdt_keyword_hit():
    ctx = FakeContext(dex_strings=["充值 USDT TRC20 到账"])
    result = PaymentAnalyzer().analyze(ctx)
    leads = _pay_leads(result)
    assert any("USDT" in l.value or "虚拟货币" in l.value for l in leads)


def test_tron_wallet_address_regex_hit():
    # 合法格式 TRON 地址（T + 33 位 base58）。
    addr = "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"
    ctx = FakeContext(dex_strings=[f"收款地址 {addr}"])
    result = PaymentAnalyzer().analyze(ctx)
    leads = _pay_leads(result)
    assert any("钱包地址" in l.value for l in leads), "应命中加密货币钱包地址规则"


def test_keyword_hit_in_text_resource():
    ctx = FakeContext(
        files={"assets/config.json": b'{"notify_url":"https://evil.example/cb"}'}
    )
    result = PaymentAnalyzer().analyze(ctx)
    leads = _pay_leads(result)
    assert any("notify_url" in l.value or "回调" in l.value for l in leads)
    # 证据来源应为 resource
    hit = next(l for l in leads if l.source_refs)
    assert any(ev.source == "resource" for ev in hit.source_refs)


def test_no_payment_signal_yields_no_leads():
    ctx = FakeContext(
        dex_strings=["android.app.Activity", "java.lang.String", "hello world"],
    )
    result = PaymentAnalyzer().analyze(ctx)
    assert _pay_leads(result) == []
    assert result.meta["payment_sdks"] == []
    assert result.meta["payment_keywords"] == []
    assert result.error is None


def test_robust_against_empty_context():
    result = PaymentAnalyzer().analyze(FakeContext())
    assert result.error is None
    assert _pay_leads(result) == []
