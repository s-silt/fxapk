"""ContactsAnalyzer 测试：QQ/微信/Telegram/邮箱/手机号 → CONTACT 线索 + 去误报。

用 FakeContext 喂合成数据，配真实 apkscan/rules/contacts.yaml 规则。
"""

from __future__ import annotations

from apkscan.analyzers.contacts import ContactsAnalyzer
from apkscan.core.models import Confidence, LeadCategory

from tests.conftest import FakeContext


def _contact_values(result) -> list[str]:
    return [l.value for l in result.leads if l.category == LeadCategory.CONTACT]


def test_email_hit_and_resource_blacklist():
    ctx = FakeContext(
        dex_strings=["联系邮箱 scammer@gmail.com 谢谢"],
        files={"res/values/strings.xml": b'<string name="x">@drawable/icon</string>'},
    )
    result = ContactsAnalyzer().analyze(ctx)
    values = _contact_values(result)
    assert any("scammer@gmail.com" in v for v in values)
    # @drawable 等资源引用不应被当成邮箱
    assert not any("drawable" in v for v in values)


def test_phone_hit_with_boundary():
    # 真实形态号码（13912345678，无长重复-run）应命中，前后非数字边界生效。
    ctx = FakeContext(dex_strings=["客服热线13912345678随时在线"])
    result = ContactsAnalyzer().analyze(ctx)
    assert any("13912345678" in v for v in _contact_values(result))


def test_placeholder_phone_filtered():
    # C3：占位/测试号 13800138000（显式 denylist）+ 13888888801（denylist & run≥6）
    # 不应产 phone lead；真号 13912345678 / 18612349999(run4) 保留。
    ctx = FakeContext(
        dex_strings=[
            "测试号13800138000占位",
            "客服13888888801引流",
            "真号13912345678",
            "另一真号18612349999",
        ]
    )
    result = ContactsAnalyzer().analyze(ctx)
    phones = [v for v in _contact_values(result) if v.startswith("手机号")]
    joined = " ".join(phones)
    assert "13800138000" not in joined
    assert "13888888801" not in joined
    assert "13912345678" in joined
    assert "18612349999" in joined


def test_repeat_run_phone_demoted_not_dropped():
    # C3 评审 no-false-kill：最长连续相同数字 ≥6 的号（13666666666 run=9、13700000000
    # run=8）疑似 vanity/占位，但杀猪盘靓号客服号不可一票误杀 → 保留但降 LOW，不 drop。
    ctx = FakeContext(dex_strings=["13666666666", "13700000000"])
    result = ContactsAnalyzer().analyze(ctx)
    phone_leads = [
        l
        for l in result.leads
        if l.category == LeadCategory.CONTACT and l.value.startswith("手机号")
    ]
    values = " ".join(l.value for l in phone_leads)
    assert "13666666666" in values
    assert "13700000000" in values
    # 全部降为 LOW 可信，且带"疑似 vanity/占位"提示。
    assert all(l.confidence == Confidence.LOW for l in phone_leads)
    assert all("vanity" in (l.notes or "") for l in phone_leads)


def test_vanity_phone_kept_low_confidence():
    # 杀猪盘客服靓号（18888888888 run=10、13966666660 run=7）属真线索形态，必须保留。
    ctx = FakeContext(dex_strings=["客服18888888888", "引流13966666660"])
    result = ContactsAnalyzer().analyze(ctx)
    phone_leads = [
        l
        for l in result.leads
        if l.category == LeadCategory.CONTACT and l.value.startswith("手机号")
    ]
    values = " ".join(l.value for l in phone_leads)
    assert "18888888888" in values
    assert "13966666660" in values
    assert all(l.confidence == Confidence.LOW for l in phone_leads)


def test_oss_author_emails_filtered():
    # C3：OSS 库作者邮箱（GSAP / JS 库作者）不应被当 App 联系方式；真线索保留。
    ctx = FakeContext(
        dex_strings=[
            "GSAP by jack@greensock.com",
            "lib author jhruby.web@gmail.com",
            "联系骗子 scammer@gmail.com",
        ]
    )
    result = ContactsAnalyzer().analyze(ctx)
    values = " ".join(_contact_values(result))
    assert "jack@greensock.com" not in values
    assert "jhruby.web@gmail.com" not in values
    # 真线索（gmail 个人邮箱）仍保留。
    assert "scammer@gmail.com" in values


def test_long_digit_run_is_not_a_phone():
    # 14 位连续数字不应被当成手机号（前后数字边界）。
    ctx = FakeContext(dex_strings=["12345678901234"])
    result = ContactsAnalyzer().analyze(ctx)
    assert not any(v.startswith("手机号") for v in _contact_values(result))


def test_qq_via_context_and_email_form():
    ctx = FakeContext(
        dex_strings=["加QQ:123456 咨询", "客服QQ 987654321", "联系 10001@qq.com"],
    )
    result = ContactsAnalyzer().analyze(ctx)
    values = " ".join(_contact_values(result))
    assert "123456" in values
    assert "987654321" in values
    assert "10001" in values  # 来自 @qq.com 形式


def test_wechat_context_and_wxid():
    ctx = FakeContext(dex_strings=["加微信：abc_123xyz", "wxid_a1b2c3d4e5"])
    result = ContactsAnalyzer().analyze(ctx)
    values = " ".join(v for v in _contact_values(result) if v.startswith("微信"))
    assert "abc_123xyz" in values
    assert "wxid_a1b2c3d4e5" in values


def test_telegram_link_is_low_confidence():
    ctx = FakeContext(dex_strings=["飞机群 t.me/scamchannel 进群"])
    result = ContactsAnalyzer().analyze(ctx)
    tg = [l for l in result.leads if l.category == LeadCategory.CONTACT and l.value.startswith("Telegram")]
    assert tg
    assert "scamchannel" in tg[0].value
    assert tg[0].confidence == Confidence.LOW


def test_dedup_same_value_across_sources():
    # 用真实形态号（13912345678，非占位）验证跨源去重。
    ctx = FakeContext(
        dex_strings=["13912345678", "13912345678"],
        files={"assets/a.txt": b"13912345678"},
    )
    result = ContactsAnalyzer().analyze(ctx)
    phones = [v for v in _contact_values(result) if v.startswith("手机号")]
    # 同一号码只产一条 Lead（证据可多条）
    assert len(phones) == 1


def test_no_contacts_yields_empty():
    ctx = FakeContext(dex_strings=["android.app.Activity", "java.lang.Object"])
    result = ContactsAnalyzer().analyze(ctx)
    assert _contact_values(result) == []
    assert result.error is None


def test_meta_counts_present():
    ctx = FakeContext(dex_strings=["邮箱 a@b.com", "电话13912345678"])
    result = ContactsAnalyzer().analyze(ctx)
    assert isinstance(result.meta.get("contacts"), dict)
    assert result.meta["contacts"].get("email", 0) >= 1
    assert result.meta["contacts"].get("phone", 0) >= 1
