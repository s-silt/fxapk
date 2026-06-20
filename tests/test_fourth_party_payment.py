"""fourth_party_payment 分析器测试：识别四方支付 / 跑分平台 → FOURTH_PARTY_PAYMENT 线索。

零真机、零联网：用轻量 stub ctx 喂 dex 字符串 / 文本资源。host 研判走真实
infra.classify_domain（离线纯函数）：自有灰产网关 → 建议调证、已知基础设施 / 私网 → 排除。

判定回顾：
  - 强档 = 同段文本既有支付网关 URL 又有跑分 / 代收代付中文关键词，且 host 建议调证 → HIGH·建议调证。
  - 弱档 = 仅端点或仅关键词 → MEDIUM·待核。
  - FP 排除 = 正规支付 SDK / 网关（alipay/wechat/unionpay/stripe…）、已知基础设施、私网。
"""

from __future__ import annotations

from apkscan.analyzers.fourth_party_payment import FourthPartyPaymentAnalyzer
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
    return FourthPartyPaymentAnalyzer().analyze(ctx).leads


def test_endpoint_plus_keyword_is_high() -> None:
    # 网关 URL + 跑分黑话共现，host 建议调证 → 强档 HIGH·建议调证。
    leads = _leads(
        _Ctx(dex=["跑分平台下单 https://pay.evilgw.com/api/pay/notify?mch_id=8801"])
    )
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.FOURTH_PARTY_PAYMENT
    assert lead.value == "pay.evilgw.com"
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == infra.ADVICE_INVESTIGATE


def test_daifu_subdomain_endpoint_high() -> None:
    # host 以 daifu. 开头本身命中 FPP-HOST 支付网关子域名（= 端点特征），
    # 同行又有「代收代付」关键词，host 建议调证 → 强档 HIGH·建议调证。
    leads = _leads(_Ctx(dex=["代收代付通道 https://daifu.evilgw.com/home/index"]))
    assert len(leads) == 1
    assert leads[0].value == "daifu.evilgw.com"
    assert leads[0].confidence is Confidence.HIGH  # daifu. 子域名命中端点 + 关键词 → 强档
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_keyword_only_no_endpoint_is_review() -> None:
    # 仅中文关键词、URL host/path 都不含支付端点特征 → MEDIUM·待核。
    leads = _leads(_Ctx(dex=["聚合支付平台 https://cdn.evilgw.com/static/app.js"]))
    assert len(leads) == 1
    assert leads[0].value == "cdn.evilgw.com"
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_endpoint_only_is_review() -> None:
    # 仅支付端点、无中文跑分黑话 → MEDIUM·待核（FP 风险高，不轻易建议调证）。
    leads = _leads(_Ctx(dex=["https://pay.evilgw.com/api/pay/notify?mch_id=8801"]))
    assert len(leads) == 1
    assert leads[0].value == "pay.evilgw.com"
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_skip_legit_alipay() -> None:
    # 支付宝是合规三方支付，非四方 / 跑分 → 不产线索（即便带支付端点 + 关键词）。
    leads = _leads(
        _Ctx(dex=["聚合支付 https://openapi.alipay.com/gateway.do?mch_id=1&pay_key=x"])
    )
    assert leads == []


def test_skip_legit_wechat_and_unionpay() -> None:
    leads = _leads(
        _Ctx(
            dex=[
                "代收代付 https://api.mch.weixin.qq.com/pay/notify?mch_id=1",
                "跑分 https://gateway.95516.com/api/pay/create?merchant_no=2",
            ]
        )
    )
    assert leads == []


def test_skip_known_infra() -> None:
    # 已知第三方基础设施（云厂商对象存储等）由 infra 排除。
    leads = _leads(
        _Ctx(dex=["聚合支付 https://pay.example.myqcloud.com/api/pay/notify?mch_id=1"])
    )
    assert leads == []


def test_skip_private_host() -> None:
    leads = _leads(_Ctx(dex=["跑分平台 http://192.168.1.10/api/pay/notify?mch_id=1"]))
    assert leads == []


def test_no_signal_no_lead() -> None:
    # 无支付端点、无中文关键词 → 不产线索。
    leads = _leads(_Ctx(dex=["https://evilgw.com/home/index"]))
    assert leads == []


def test_dedup_per_host() -> None:
    # 同一 host 多条命中 → 仅一条线索（按 host 去重），端点 + 关键词共现升 HIGH。
    leads = _leads(
        _Ctx(
            dex=[
                "聚合支付平台 https://gw.evilgw.com/static/x.js",  # 仅关键词
                "https://gw.evilgw.com/api/pay/notify?mch_id=9",  # 端点
                "跑分系统 https://gw.evilgw.com/api/order/create",  # 端点 + 关键词
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].value == "gw.evilgw.com"
    assert leads[0].confidence is Confidence.HIGH


def test_resource_scan_detects_h5_gateway() -> None:
    ctx = _Ctx(
        files=["assets/www/pay-service.js", "res/raw/logo.png"],
        contents={
            "assets/www/pay-service.js": (
                "跑分平台 var api='https://pay.evilgw.com/gateway/pay?merchant_no=7';".encode(
                    "utf-8"
                )
            ),
            "res/raw/logo.png": b"\x89PNG not-text",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].value == "pay.evilgw.com"
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].source_refs[0].source == "resource"
    assert "pay-service.js" in leads[0].source_refs[0].location


def test_h5_far_apart_keyword_and_endpoint_no_false_high() -> None:
    # FP 回归：H5 单文件里「跑分」关键词与支付端点 URL 分属两个无关 host，且相隔很远
    # （远超就近窗口）→ 不得仅凭文件级存在关键词把端点 host 误升 HIGH。
    far = "x" * 1000  # 把关键词与端点 URL 拉开到就近窗口之外
    js = (
        "跑分平台运营后台 var a='https://cdn.unrelated-host.com/static/app.js';"
        + far
        + "var pay='https://pay.evilgw.com/api/pay/notify?merchant_no=7';"
    )
    ctx = _Ctx(
        files=["assets/www/bundle.js"],
        contents={"assets/www/bundle.js": js.encode("utf-8")},
    )
    leads = _leads(ctx)
    # 端点 host 仅有端点、无就近关键词 → 至多 MEDIUM·待核，绝不可 HIGH。
    by_host = {ld.value: ld for ld in leads}
    pay_lead = by_host.get("pay.evilgw.com")
    assert pay_lead is not None  # 端点本身仍记为弱档线索
    assert pay_lead.confidence is Confidence.MEDIUM
    assert pay_lead.advice == infra.ADVICE_REVIEW
    # 无 host 应被升为 HIGH（关键词与端点未就近共现）。
    assert all(ld.confidence is not Confidence.HIGH for ld in leads)


def test_h5_near_keyword_and_endpoint_same_host_high() -> None:
    # 对照：同一 host 的端点 URL 与「跑分」关键词就近（同处）共现 → 仍正常升 HIGH。
    js = "跑分平台 var pay='https://pay.evilgw.com/api/pay/notify?merchant_no=7';"
    ctx = _Ctx(
        files=["assets/www/near.js"],
        contents={"assets/www/near.js": js.encode("utf-8")},
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].value == "pay.evilgw.com"
    assert leads[0].confidence is Confidence.HIGH


def test_strong_lead_is_letter_ready() -> None:
    # 强档线索须可直接套打调证函：where_to_request 为真实受文机关 + evidence_to_obtain 非空 + 建议调证。
    leads = _leads(
        _Ctx(dex=["代收代付 https://pay.evilgw.com/api/pay/notify?mch_id=8801"])
    )
    lead = leads[0]
    assert lead.advice == infra.ADVICE_INVESTIGATE
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
    assert drafts[0]["category"] == "FOURTH_PARTY_PAYMENT"
