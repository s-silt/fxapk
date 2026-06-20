"""self_hosted_im 分析器测试：识别自建 IM / C2 控制信道 → SELF_HOSTED_IM 调证线索。

零真机、零联网：用轻量 stub ctx 喂 dex 字符串 / 文本资源。host 研判走真实
infra.classify_domain（离线纯函数）：evilbroker.* → 建议调证、公共 MQTT/推送基础设施
（firebase / mqtt.eclipseprojects.io / getui 等）→ 无需调证（不产强线索）。
"""

from __future__ import annotations

from apkscan.analyzers.self_hosted_im import SelfHostedImAnalyzer
from apkscan.core import infra
from apkscan.core.models import Confidence, LeadCategory
from apkscan.report.letters import build_letters


class _Ctx:
    """最小 AnalysisContext 替身：仅实现用到的三个接口。"""

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
    return SelfHostedImAnalyzer().analyze(ctx).leads


# ---------------------------------------------------------------------------
# 强证据：硬编码非白名单控制信道地址
# ---------------------------------------------------------------------------


def test_hardcoded_wss_channel_high() -> None:
    leads = _leads(_Ctx(dex=['url="wss://im.evilbroker.com/socket"']))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.SELF_HOSTED_IM
    assert lead.value == "im.evilbroker.com"
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == infra.ADVICE_INVESTIGATE


def test_hardcoded_mqtt_channel_high() -> None:
    leads = _leads(_Ctx(dex=["mqtt://broker.evilbroker.com:1883"]))
    assert len(leads) == 1
    assert leads[0].value == "broker.evilbroker.com"
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_hardcoded_tcp_socket_channel_high() -> None:
    leads = _leads(_Ctx(dex=["tcp://gate.evilbroker.com:9000"]))
    assert len(leads) == 1
    assert leads[0].value == "gate.evilbroker.com"
    assert leads[0].confidence is Confidence.HIGH


# ---------------------------------------------------------------------------
# 弱证据：仅库指纹（无硬编码非白名单地址）→ 待核
# ---------------------------------------------------------------------------


def test_library_fingerprint_only_is_review() -> None:
    leads = _leads(_Ctx(dex=["Lorg/eclipse/paho/client/mqttv3/MqttClient;"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.SELF_HOSTED_IM
    assert lead.confidence is Confidence.MEDIUM
    assert lead.advice == infra.ADVICE_REVIEW


def test_smack_xmpp_fingerprint_is_review() -> None:
    leads = _leads(_Ctx(dex=["org.jivesoftware.smack.tcp.XMPPTCPConnection"]))
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_fingerprint_token_word_boundary() -> None:
    # io.netty.channel 不应被 io.netty.channelextra 之类同名前缀误命中（词边界）。
    leads = _leads(_Ctx(dex=["io.netty.channelextrastuff.Foo"]))
    assert leads == []


# ---------------------------------------------------------------------------
# FP 收敛：公共 IM / 推送 / MQTT 基础设施、私网 → 不产强线索
# ---------------------------------------------------------------------------


def test_skip_public_push_firebase() -> None:
    # firebase（google.com）是公共推送/实时数据库基础设施 → infra 判无需调证 → 不产强线索。
    leads = _leads(_Ctx(dex=["wss://test.firebaseio.google.com/im"]))
    assert leads == []


def test_skip_public_push_getui() -> None:
    # 个推（getui）是公共推送基础设施 → infra 判无需调证 → 不产强线索。
    leads = _leads(_Ctx(dex=["mqtt://mqtt.getui.com:1883"]))
    assert leads == []


def test_skip_private_host_channel() -> None:
    leads = _leads(_Ctx(dex=["ws://192.168.1.10:8080/socket"]))
    assert leads == []


def test_no_channel_no_fingerprint_no_lead() -> None:
    leads = _leads(_Ctx(dex=["https://evilbroker.com/home/index", "just a string"]))
    assert leads == []


# ---------------------------------------------------------------------------
# 去重 + 强弱共存优先级
# ---------------------------------------------------------------------------


def test_dedup_per_host() -> None:
    # 同一 host 多个信道 URL → 仅一条线索（按 host 去重）。
    leads = _leads(
        _Ctx(
            dex=[
                "wss://im.evilbroker.com/a",
                "wss://im.evilbroker.com/b",
                "mqtt://im.evilbroker.com:1883",
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].value == "im.evilbroker.com"


def test_hardcoded_address_suppresses_fingerprint_lead() -> None:
    # 既有硬编码非白名单地址、又命中库指纹时：只出地址强线索，不再单独出库指纹弱线索。
    leads = _leads(
        _Ctx(
            dex=[
                "wss://im.evilbroker.com/socket",
                "Lorg/eclipse/paho/client/mqttv3/MqttClient;",
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].value == "im.evilbroker.com"
    assert leads[0].confidence is Confidence.HIGH


# ---------------------------------------------------------------------------
# 资源扫描
# ---------------------------------------------------------------------------


def test_resource_scan_detects_h5_channel() -> None:
    ctx = _Ctx(
        files=["assets/www/app-service.js", "res/raw/foo.png"],
        contents={
            "assets/www/app-service.js": b'var ws="wss://chat.evilbroker.com/ws";',
            "res/raw/foo.png": b"\x89PNG not-text",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].value == "chat.evilbroker.com"
    assert leads[0].source_refs[0].source == "resource"
    assert "app-service.js" in leads[0].source_refs[0].location


# ---------------------------------------------------------------------------
# 可套打调证函
# ---------------------------------------------------------------------------


def test_lead_is_letter_ready() -> None:
    # 强证据 SELF_HOSTED_IM 线索须可直接套打：where_to_request 为真实受文机关 + evidence 非空。
    leads = _leads(_Ctx(dex=["wss://im.evilbroker.com/socket"]))
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
    assert drafts[0]["category"] == "SELF_HOSTED_IM"
