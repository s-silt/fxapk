"""sms_forwarding 分析器测试：识别短信 / 验证码转发服务 → SMS_FORWARDING 调证线索。

零真机、零联网：用轻量 stub ctx 喂 dex 字符串 / 文本资源。webhook host 研判走真实
infra.classify_domain（离线纯函数）。覆盖：强档（关键词 / 接收+转发组合 / Telegram webhook /
转发目标手机号）、弱档待核（单关键词 / 仅接收）、FP 排除（正规短信发送 SDK）、去重、可套打。
"""

from __future__ import annotations

from apkscan.analyzers.sms_forwarding import SmsForwardingAnalyzer
from apkscan.core import infra
from apkscan.core.models import Confidence, LeadCategory
from apkscan.report.letters import build_letters


class _Ctx:
    """最小 AnalysisContext 替身：仅实现 sms_forwarding 用到的三个接口。"""

    def __init__(
        self,
        dex: list[str] | None = None,
        files: list[str] | None = None,
        contents: dict[str, bytes] | None = None,
    ) -> None:
        self._dex = dex or []
        self._files = files or []
        self._contents = contents or {}

    def dex_strings(self):
        return list(self._dex)

    def list_files(self):
        return list(self._files)

    def read_file(self, path: str):
        return self._contents.get(path)


def _leads(ctx: _Ctx):
    return SmsForwardingAnalyzer().analyze(ctx).leads


def test_chinese_forward_keyword_high() -> None:
    leads = _leads(_Ctx(dex=["将短信转发到指定服务器"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.SMS_FORWARDING
    assert lead.value == "短信 / 验证码转发服务"
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == infra.ADVICE_INVESTIGATE


def test_recv_plus_forward_combo_high() -> None:
    # SMS_RECEIVED 接收 + Telegram sendMessage 上报共现 → 强证据。
    leads = _leads(
        _Ctx(
            dex=[
                "android.provider.Telephony.SMS_RECEIVED",
                "Landroid/telephony/SmsMessage;->createFromPdu",
                "->getMessageBody()Ljava/lang/String;",
                "->sendMessage(token, chatId)",
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_telegram_webhook_high() -> None:
    leads = _leads(_Ctx(dex=["https://api.telegram.org/bot123456:ABCDEF/sendMessage?chat_id=1"]))
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_forward_phone_target_high() -> None:
    # 转发关键词 + 转发目标手机号共现 → 强证据。
    leads = _leads(_Ctx(dex=["短信转发到 13800138000"]))
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH


def test_single_weak_keyword_is_review() -> None:
    leads = _leads(_Ctx(dex=["读取短信内容用于自动填充"]))
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_receive_only_is_review() -> None:
    # 仅命中短信接收方法、无上传/转发 → 弱档待核（不轻易建议调证）。
    leads = _leads(
        _Ctx(dex=["android.provider.Telephony.SMS_RECEIVED", "->getMessageBody()"])
    )
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_receive_plus_generic_http_not_high() -> None:
    # 对抗 FP：接收短信(如验证码自动填充) + 通用网络库(okhttp3) → 绝不升 HIGH。
    # 通用 HTTP token 已从 forward_tokens 移除，故 forward 不命中，最多到 MEDIUM·待核。
    leads = _leads(
        _Ctx(
            dex=[
                "android.provider.Telephony.SMS_RECEIVED",
                "->getMessageBody()Ljava/lang/String;",
                "okhttp3",
                "HttpURLConnection",
            ]
        )
    )
    # 不得出 HIGH（建议调证）：要么待核，要么不出。
    for lead in leads:
        assert lead.confidence is not Confidence.HIGH
        assert lead.advice != infra.ADVICE_INVESTIGATE


def test_receive_plus_telegram_forward_high() -> None:
    # 接收短信 + 真转发落点(api.telegram.org/bot...) 共现 → 强证据，建议调证。
    leads = _leads(
        _Ctx(
            dex=[
                "android.provider.Telephony.SMS_RECEIVED",
                "->getMessageBody()Ljava/lang/String;",
                "https://api.telegram.org/bot123:ABC/sendMessage",
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_receive_plus_forward_webhook_high() -> None:
    # 接收短信 + 转发 webhook 配置(forward_webhook) 共现 → 强证据，建议调证。
    leads = _leads(
        _Ctx(
            dex=[
                "android.provider.Telephony.SMS_RECEIVED",
                "->getMessageBody()Ljava/lang/String;",
                'cfg = {"forward_webhook": "https://evil.example.com/recv"}',
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_skip_legit_sms_sender_sdk() -> None:
    # 仅命中正规短信发送 SDK（阿里云 dysms），无任何转发/接收信号 → 不出线索。
    leads = _leads(_Ctx(dex=["https://dysmsapi.aliyuncs.com/?Action=SendSms"]))
    assert leads == []


def test_no_signal_no_lead() -> None:
    leads = _leads(_Ctx(dex=["just a normal string with no sms signal"]))
    assert leads == []


def test_telegram_webhook_word_boundary_no_false_match() -> None:
    # getMessageBodyExtra 不应被 getMessageBody token 词边界误命中（仅接收 token 时无强证据）。
    leads = _leads(_Ctx(dex=["->getMessageBodyExtra()", "okhttp3"]))
    assert leads == []


def test_dedup_single_lead_per_sample() -> None:
    # 同一样本多处强证据 → 仅一条线索（按样本聚合），强档优先。
    leads = _leads(
        _Ctx(
            dex=[
                "读取短信内容",  # 弱关键词
                "验证码转发",  # 强关键词
                "https://api.telegram.org/bot999:XYZ/sendMessage",  # 强 webhook
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH


def test_resource_scan_detects_forward_config() -> None:
    ctx = _Ctx(
        files=["assets/www/config.js", "res/raw/foo.png"],
        contents={
            "assets/www/config.js": b'var cfg={"forward_url":"https://api.telegram.org/bot1:A/sendMessage"};',
            "res/raw/foo.png": b"\x89PNG not-text",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].source_refs[0].source == "resource"


def test_lead_is_letter_ready() -> None:
    # SMS_FORWARDING 强档线索须可直接套打：where_to_request 为真实受文机关 + evidence_to_obtain 非空。
    leads = _leads(_Ctx(dex=["验证码转发到接收端"]))
    lead = leads[0]
    assert lead.evidence_to_obtain  # 非空
    report = {
        "leads": [
            {
                "category": lead.category.value,
                "value": lead.value,
                "where_to_request": lead.where_to_request,
                "evidence_to_obtain": lead.evidence_to_obtain,
                "advice": lead.advice,
                "subject": lead.subject,
            }
        ]
    }
    drafts = build_letters(report)
    assert len(drafts) == 1
    assert drafts[0]["category"] == "SMS_FORWARDING"
