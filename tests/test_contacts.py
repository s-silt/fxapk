"""ContactsAnalyzer 测试：QQ/微信/Telegram/邮箱/手机号 → CONTACT 线索 + 去误报。

用 FakeContext 喂合成数据，配真实 apkscan/rules/contacts.yaml 规则。
"""

from __future__ import annotations

import time

from apkscan.analyzers.contacts import ContactsAnalyzer
from apkscan.core.models import Confidence, LeadCategory

from tests.conftest import FakeContext


def _contact_values(result) -> list[str]:
    return [l.value for l in result.leads if l.category == LeadCategory.CONTACT]


def test_email_regex_no_redos_on_pathological_input():
    """回归：email 正则曾对长字母/点串灾难性回溯（O(n²)）。

    真机上一个 512KB 二进制字体（MaterialIcons-Regular.otf）解码后内容让 contacts
    单独卡 4.6 分钟。界定量词（local≤64 / label≤63 / TLD 2–24）修复后必须线性、秒级完成。
    30KB 病态输入：旧正则 ~9s，修复后 <0.1s。
    """
    pathological = "a." * 15000  # 30KB，无 @、纯 [A-Za-z.] 长串 → 旧前缀扫描 O(n²)
    ctx = FakeContext(dex_strings=[pathological])
    start = time.perf_counter()
    result = ContactsAnalyzer().analyze(ctx)
    elapsed = time.perf_counter() - start
    assert result.error is None
    assert elapsed < 3.0, f"contacts 在病态输入上耗时 {elapsed:.1f}s，疑似 email 正则回溯未修复"


def test_binary_resources_not_scanned_for_contacts():
    """回归：assets/ 前缀曾把整棵资源树（含 .otf 字体 / .png 图片 / .so）当文本资源。

    把二进制解码成 utf-8 去跑联系方式正则既错（字体里"找邮箱"）又慢。二进制资源必须排除；
    合法文本资源（.json）仍须照常扫描。
    """
    payload = b"......scammer@gmail.com......"
    binary = FakeContext(
        files={
            "assets/flutter_assets/fonts/MaterialIcons-Regular.otf": payload,
            "assets/flutter_assets/assets/images/splash.png": payload,
            "assets/payload.so": payload,
        }
    )
    assert not any(
        "scammer@gmail.com" in v for v in _contact_values(ContactsAnalyzer().analyze(binary))
    ), "字体/图片/.so 等二进制资源不应被当文本扫描出联系方式"

    text = FakeContext(files={"assets/config.json": payload})
    assert any(
        "scammer@gmail.com" in v for v in _contact_values(ContactsAnalyzer().analyze(text))
    ), "合法文本资源(.json)仍应被扫描"


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
    # 长数字串不产手机号线索（phone 类型已整类移除；本例另守「长数字串不被其它类型误收」）。
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
    # 跨源去重（原用手机号做载体，phone 类型已移除 → 改用邮箱）。
    ctx = FakeContext(
        dex_strings=["联系 kefu@fanzha-test.cn", "kefu@fanzha-test.cn"],
        files={"assets/a.txt": b"kefu@fanzha-test.cn"},
    )
    result = ContactsAnalyzer().analyze(ctx)
    emails = [v for v in _contact_values(result) if v.startswith("邮箱")]
    # 同一值只产一条 Lead（证据可多条）
    assert len(emails) == 1


def test_no_contacts_yields_empty():
    ctx = FakeContext(dex_strings=["android.app.Activity", "java.lang.Object"])
    result = ContactsAnalyzer().analyze(ctx)
    assert _contact_values(result) == []
    assert result.error is None


def test_meta_counts_present():
    ctx = FakeContext(dex_strings=["邮箱 a@b.com", "客服QQ：800820820"])
    result = ContactsAnalyzer().analyze(ctx)
    assert isinstance(result.meta.get("contacts"), dict)
    assert result.meta["contacts"].get("email", 0) >= 1
    assert result.meta["contacts"].get("qq", 0) >= 1
    # phone 类型已整类移除，不应再出现在计数里
    assert "phone" not in result.meta["contacts"]


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
    # 同一语料里既有联系方式又有 webhook：CONTACT 与 CHANNEL 各自独立产出，互不污染。
    # （原用手机号做 CONTACT 载体，phone 类型已整类移除 → 改用 QQ。）
    url = "https://oapi.dingtalk.com/robot/send?access_token=zzz"
    ctx = FakeContext(dex_strings=[f"客服QQ：800820820 上报 {url}"])
    result = ContactsAnalyzer().analyze(ctx)
    assert any("800820820" in v for v in _contact_values(result))
    assert any("oapi.dingtalk.com" in l.value for l in _channel_leads(result))


# ===========================================================================
# 手机号整类移除的回归守卫（2026-07-24）
# ===========================================================================


def test_phone_type_removed_no_bare_number_extraction():
    """裸手机号不再被提取为联系方式线索。

    移除依据（实证）：语料库 多个样本提取出的 12 个「手机号」逐条回原始 snippet 核验，
    **12/12 全为误报**，来源包括矢量图 path 坐标、Lottie 动画数值与颜色分量、数学常量 π、
    SHA 初始常量、以太坊合约字节码、货币配置上限。11 位数字窗口在浮点/十六进制串里无处不在，
    靠正则边界修不干净；而该类型产出 advice=建议调证 + subject=电信运营商，
    等于建议办案人拿假号去运营商调机主实名。

    业务判断：嫌疑人不会把自己手机号编进 APK，真实联系方式走 QQ/微信/Telegram。
    """
    ctx = FakeContext(
        dex_strings=[
            "13912345678",                                  # 形态完全合法的真号
            "客服热线13912345678随时在线",                    # 带中文上下文
            "l 0.0,2.15845447942 c 0.0,0.0",                # 矢量图坐标（曾误报）
            "const float PI = 3.14159265358;",              # π（曾误报）
            "16a09e667f3bcc908b2fb1366ea957d3e3adec17512775099da2f590b0667322a",  # SHA 常量（曾误报）
        ],
    )
    result = ContactsAnalyzer().analyze(ctx)
    phones = [v for v in _contact_values(result) if v.startswith("手机号")]
    assert phones == [], f"phone 类型应已整类移除，却仍提取到：{phones}"
    assert "phone" not in (result.meta.get("contacts") or {})


def test_phone_removal_does_not_break_other_contact_types():
    """移除 phone 后，QQ / 微信 / Telegram / 邮箱 四类仍正常提取（防误删波及）。"""
    ctx = FakeContext(
        dex_strings=[
            "客服QQ：800820820",
            "加微信 wxid_abc123def",
            "Telegram @scam_support",
            "邮箱 kefu@fanzha-test.cn",
        ],
    )
    result = ContactsAnalyzer().analyze(ctx)
    joined = " ".join(_contact_values(result))
    assert "800820820" in joined
    assert "kefu@fanzha-test.cn" in joined
