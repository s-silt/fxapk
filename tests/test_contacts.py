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
    ctx = FakeContext(dex_strings=["客服热线13800138000随时在线"])
    result = ContactsAnalyzer().analyze(ctx)
    assert any("13800138000" in v for v in _contact_values(result))


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
    ctx = FakeContext(
        dex_strings=["13800138000", "13800138000"],
        files={"assets/a.txt": b"13800138000"},
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
