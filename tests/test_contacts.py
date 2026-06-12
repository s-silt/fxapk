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


# ===========================================================================
# IM 回传通道：Telegram bot token / chat_id + 企微钉钉飞书 webhook → CHANNEL
# ===========================================================================

# 合法 bot token：冒号前 10 位纯数字，冒号后正好 35 位 [A-Za-z0-9_-]。
_VALID_BOT_TOKEN = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789"


def _channel_leads(result):
    return [l for l in result.leads if l.category == LeadCategory.CHANNEL]


def test_telegram_bot_token_yields_channel_lead():
    ctx = FakeContext(dex_strings=[f"botToken={_VALID_BOT_TOKEN} 上传短信"])
    result = ContactsAnalyzer().analyze(ctx)
    channel = _channel_leads(result)
    tg = [l for l in channel if "Telegram" in (l.subject or "")]
    assert tg, "应产出 Telegram bot token 的 CHANNEL Lead"
    lead = tg[0]
    # value 是裸 token（不带类型前缀），主体含 Telegram，HIGH 置信。
    assert lead.value == _VALID_BOT_TOKEN
    assert "Telegram" in (lead.subject or "")
    assert lead.confidence == Confidence.HIGH
    assert lead.where_to_request
    assert lead.evidence_to_obtain


def test_bot_token_form_gate_rejects_malformed():
    # 冒号后非 35 位（34 位）/ 冒号前非纯数字 → 不应命中。
    too_short = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz12345678"   # 34 位
    too_long = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz1234567890"  # 36 位
    non_digit_prefix = "12ab567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789"
    ctx = FakeContext(
        dex_strings=[
            f"token={too_short}",
            f"token={too_long}",
            f"token={non_digit_prefix}",
        ]
    )
    result = ContactsAnalyzer().analyze(ctx)
    vals = " ".join(l.value for l in _channel_leads(result))
    assert too_short not in vals
    assert too_long not in vals
    assert non_digit_prefix not in vals


def _webhook_lead_for(result, domain: str):
    cands = [l for l in _channel_leads(result) if domain in l.value]
    return cands[0] if cands else None


def test_dingtalk_webhook_attributes_to_alibaba():
    url = "https://oapi.dingtalk.com/robot/send?access_token=abc123def456"
    ctx = FakeContext(dex_strings=[f"webhook {url}"])
    result = ContactsAnalyzer().analyze(ctx)
    lead = _webhook_lead_for(result, "oapi.dingtalk.com")
    assert lead is not None, "钉钉 webhook 应产 CHANNEL Lead"
    assert "oapi.dingtalk.com/robot/send" in lead.value
    assert "阿里" in (lead.subject or "")
    assert lead.confidence == Confidence.HIGH


def test_wecom_webhook_attributes_to_tencent():
    url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxx"
    ctx = FakeContext(dex_strings=[f"上报 {url}"])
    result = ContactsAnalyzer().analyze(ctx)
    lead = _webhook_lead_for(result, "qyapi.weixin.qq.com")
    assert lead is not None, "企微 webhook 应产 CHANNEL Lead"
    assert "腾讯" in (lead.subject or "")


def test_feishu_webhook_attributes_to_bytedance():
    url = "https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxx"
    ctx = FakeContext(dex_strings=[f"外传 {url}"])
    result = ContactsAnalyzer().analyze(ctx)
    lead = _webhook_lead_for(result, "open.feishu.cn")
    assert lead is not None, "飞书 webhook 应产 CHANNEL Lead"
    assert "字节" in (lead.subject or "")


def test_meta_has_telegram_bot_tokens():
    ctx = FakeContext(dex_strings=[f"botToken={_VALID_BOT_TOKEN}"])
    result = ContactsAnalyzer().analyze(ctx)
    tokens = result.meta.get("telegram_bot_tokens")
    assert isinstance(tokens, list)
    assert _VALID_BOT_TOKEN in tokens


def test_getme_default_off_offline():
    # 默认离线（FakeContext online=False）：不联网、不抛，仍保留静态 token 线索，
    # notes 带离线告警。
    ctx = FakeContext(dex_strings=[f"botToken={_VALID_BOT_TOKEN}"], online=False)
    result = ContactsAnalyzer().analyze(ctx)
    assert result.error is None
    tg = [l for l in _channel_leads(result) if "Telegram" in (l.subject or "")]
    assert tg, "离线下静态 token 线索必须保留"
    # 未发 getMe（无 bot username），notes 含离线/未验证提示。
    notes = tg[0].notes or ""
    assert "getMe" in notes or "未验证" in notes or "离线" in notes


def test_channel_leads_do_not_disturb_contacts():
    # 同一语料里既有真号又有 webhook：CONTACT 与 CHANNEL 各自独立产出，互不污染。
    url = "https://oapi.dingtalk.com/robot/send?access_token=zzz"
    ctx = FakeContext(dex_strings=[f"客服13912345678 上报 {url}"])
    result = ContactsAnalyzer().analyze(ctx)
    assert any("13912345678" in v for v in _contact_values(result))
    assert any("oapi.dingtalk.com" in l.value for l in _channel_leads(result))
