"""低段位裸 IP 的托管佐证豁免：判据接线与调证出口。

低段位降级（四段全 ≤32 且样本里未当地址用 → 待核）压掉的是版本号/序号被 IP 正则吃掉的假线索，
代价是真实公网后端里凑得出这种形态的那一批（AWS 3./23. 段）也一并被降。裸字面自己提不出
端口/URL 上下文来自证，只能靠外部佐证捞回。

本文件断言落在**接线与出口**（build_endpoint_leads 有没有真把佐证算出来传进去、升级后的
线索能不能进闭环目标），而不是只测 infra.classify_ip 的参数——参数加了但没人传，就是又一个
"提取出信号 ≠ 做完了"。
"""

from __future__ import annotations

import pytest

from apkscan.core import corpus
from apkscan.core.attribution import classify_network
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.infra import ADVICE_INVESTIGATE, ADVICE_REVIEW
from apkscan.core.leads import _is_tenant_hosting_asn, build_endpoint_leads
from apkscan.core.models import Confidence, Endpoint, Evidence, Report
from apkscan.network.categories import CAT_CLOUD, CAT_TELECOM
from apkscan.report.json import _to_jsonable
from apkscan.report.letters import build_letters

#: 裸字面证据：值本身出现在字符串表里，既无端口也无 URL 语境——降级判据的触发前提。
_BARE = "23.21.5.12"  # leak-scan: allow 低段位降级判据的形态夹具：本测试测的就是「四段≤32、与版本号同形」，换文档段即失去被测形态

_CLOUD_ASN = {"asn": "AS14618", "org": "Amazon.com, Inc."}
_TELECOM_ASN = {"asn": "AS4134", "org": "CHINANET-BACKBONE"}


def _ip_ep(value: str, asn: dict | None = None) -> Endpoint:
    ep = Endpoint(
        kind="ip",
        value=value,
        evidences=[Evidence(source="strings", location="classes.dex", snippet=value)],
    )
    if asn is not None:
        ep.enrichment["asn"] = asn
    return ep


def test_provider_keywords_still_classify_as_expected() -> None:
    """★fixture 前提：providers.yaml 关键字漂移会让本文件其余测试静默失效。

    豁免只在 ASN org 被判为云/IDC/托管转售时成立；关键字改了而这条不响，下面的测试会
    从"锁住行为"退化成"锁住一个不再触发的分支"。
    """
    assert classify_network("Amazon.com, Inc.", "AS14618") == CAT_CLOUD
    assert classify_network("CHINANET-BACKBONE", "AS4134") == CAT_TELECOM


def test_hosting_asn_helper_excludes_cdn_and_telecom() -> None:
    """佐证只认租户可查的托管段。CDN 边缘不是源站，运营商段不是租户段。"""
    assert _is_tenant_hosting_asn(_CLOUD_ASN) is True
    assert _is_tenant_hosting_asn(_TELECOM_ASN) is False
    assert _is_tenant_hosting_asn({"org": "Cloudflare, Inc."}) is False
    assert _is_tenant_hosting_asn({}) is False
    assert _is_tenant_hosting_asn(None) is False  # type: ignore[arg-type]


def test_wired_lone_low_octet_on_cloud_asn_is_promoted() -> None:
    """★核心接线锁：build_endpoint_leads 必须自己算出佐证并传给 classify_ip。

    只退 leads 侧接线（infra 的参数留着）时，单元层测试仍全绿而本测试必红——这正是
    "参数是死代码"的形态。
    """
    leads = build_endpoint_leads([_ip_ep(_BARE, _CLOUD_ASN)])

    assert len(leads) == 1
    assert leads[0].advice == ADVICE_INVESTIGATE
    assert "形态存疑" in leads[0].notes, "升级须带保留意见，发函前人看得到"


def test_wired_sequence_cluster_stays_demoted() -> None:
    """★兄弟池接线锁：同形态成簇即编号序列，纵然每个都挂着云 ASN 也不升。

    退回 build_endpoint_leads 里的兄弟池计算（siblings 恒 0）→ 三条全被升级，本测试即红。
    """
    eps = [_ip_ep(v, _CLOUD_ASN) for v in ("1.3.1.1", "1.3.1.6", "1.4.1.14")]  # leak-scan: allow 低段位降级判据的形态夹具：本测试测的就是「四段≤32、与版本号同形」，换文档段即失去被测形态
    leads = build_endpoint_leads(eps)

    assert len(leads) == 3
    assert all(x.advice == ADVICE_REVIEW for x in leads), [
        (x.value, x.advice) for x in leads
    ]


def test_wired_sibling_pool_excludes_self() -> None:
    """兄弟池要减掉自己：两个低段位值时各自只有 1 个兄弟，未达成簇阈值 → 都升。

    不减自己就会让"孤值 + 自己"凑够 2 个，把定向豁免整条废掉。
    """
    eps = [_ip_ep(v, _CLOUD_ASN) for v in ("23.21.5.12", "3.15.20.4")]  # leak-scan: allow 低段位降级判据的形态夹具：本测试测的就是「四段≤32、与版本号同形」，换文档段即失去被测形态
    leads = build_endpoint_leads(eps)

    assert [x.advice for x in leads] == [ADVICE_INVESTIGATE, ADVICE_INVESTIGATE]


@pytest.mark.parametrize(
    "asn, why",
    [
        (_TELECOM_ASN, "运营商段不是租户可查的托管段"),
        ({"org": "Cloudflare, Inc."}, "CDN 边缘不当源站进调证函"),
        (None, "离线/无富化：行为与加这条豁免之前逐字一致"),
    ],
)
def test_wired_without_hosting_evidence_stays_demoted(asn: dict | None, why: str) -> None:
    """★错误方向守卫：佐证不成立就不升。

    绝不能把佐证放松成"有 asn 数据"——几乎每个全球 IP 都有 ASN，那等于无差别取消判据。
    """
    leads = build_endpoint_leads([_ip_ep(_BARE, asn)])
    assert leads[0].advice == ADVICE_REVIEW, why


def test_promoted_lead_reaches_closure_targets() -> None:
    """★出口锁：升级必须真的把这个端点送回闭环目标，而不是只改了个字段。

    finding 的实际危害面就在这里——被降的真后端会被 targets 的「建议调证」过滤剔掉，
    连带调证函与 IOC 导出一起丢。
    """
    ep = _ip_ep(_BARE, _CLOUD_ASN)
    leads = build_endpoint_leads([ep])
    rep = Report(
        package_name="com.example.app",
        meta={},
        leads=leads,
        endpoints=[ep],
        findings=[],
        analyzer_status=[],
    )

    selected, _stats = _select_targets_with_stats(rep, max_targets=6)

    assert [e.value for e in selected] == [_BARE]


# ---------------------------------------------------------------------------
# 保留意见必须走完全程：升上来的值不得以"干净的 HIGH 条目"示人
#
# 这一节是一次教训的回归锁。判据原本只把保留意见拼进 Lead.notes，并在提交说明里声称
# "办案人发函前看得到"——而 letters 全文不读 notes。发出去的是一封干净的、HIGH 置信度、
# 指名某云厂商的调证函，没有半点存疑提示。信号必须自己走到出口。
# ---------------------------------------------------------------------------


def test_promotion_is_marked_structurally_not_only_in_prose() -> None:
    """★保留意见是结构化字段，不是 notes 里的一句话——散文没有下游能消费。"""
    lead = build_endpoint_leads([_ip_ep(_BARE, _CLOUD_ASN)])[0]
    assert lead.shape_uncertain is True
    assert "形态存疑" in lead.notes, "人读通道也留着，但它不是唯一通道"


def test_promotion_never_presents_as_high_confidence() -> None:
    """★HIGH 是"这确实是个地址"的断言，而此处恰恰不确定。

    ASN org 非空只说明"这串数字解释成 IP 后落在谁的网段"，不是地址性证据，不该驱动 HIGH。
    """
    lead = build_endpoint_leads([_ip_ep(_BARE, _CLOUD_ASN)])[0]
    assert lead.subject, "前提：ASN 富化给了 subject，未修复时正是它把置信抬到 HIGH"
    assert lead.confidence is Confidence.MEDIUM


def test_letter_draft_carries_the_reservation() -> None:
    """★出口锁（本条最重）：套打出来的调证函正文必须带着存疑警示。

    退回 letters 的渲染，这里即红——而那正是"承诺写在 notes、出口不读 notes"的形态：
    一封指名真实云厂商、要求提供租户实名的函，标的却可能只是个版本号字面。
    """
    lead = build_endpoint_leads([_ip_ep(_BARE, _CLOUD_ASN)])[0]
    letters = build_letters({"leads": [_to_jsonable(lead)]})

    assert len(letters) == 1, "仍应套打（值可能是真后端），但必须带警示"
    body = letters[0]["body_md"]
    assert "标的形态存疑" in body
    assert "发函前请人工确认" in body
    assert letters[0]["shape_uncertain"] is True
    # 警示要排在受文机关**字段**之前——决定这封函发不发的，正是它
    # （不能拿"受文机关"三字比：顶部免责声明里也有这三个字，会撞上）
    assert body.index("标的形态存疑") < body.index("**受文机关（候选）：**")


def test_normal_lead_letter_has_no_spurious_warning() -> None:
    """反向护栏：正常线索的函不得平白多出存疑警示（否则警示贬值成噪声）。"""
    ep = _ip_ep("103.36.167.109", _CLOUD_ASN)  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    ep.evidences[0].snippet = "https://103.36.167.109:8443/api"  # 当地址用，走正常路径  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    lead = build_endpoint_leads([ep])[0]

    assert lead.shape_uncertain is False
    body = build_letters({"leads": [_to_jsonable(lead)]})[0]["body_md"]
    assert "标的形态存疑" not in body


def test_shape_uncertain_does_not_crowd_out_solid_targets() -> None:
    """★Top-N 名额有限：可能是版本号的字面不得挤掉确凿的后端地址。

    两个候选刻意做成**其余排序维度全部打平**：同为 MEDIUM（存疑值被封顶、对照值无 ASN 富化）、
    同无运行时观测，且存疑值的字面还排在字典序前面——只有形态存疑这一个排序键能把顺序扳过来。
    不打平的话，这条测试会被置信度或字典序"顺便"通过，排序键删掉也不红。
    """
    suspect = _ip_ep("18.20.31.2", _CLOUD_ASN)          # 低段位 + 云 ASN + 裸字面 → 存疑  # leak-scan: allow 低段位降级判据的形态夹具：本测试测的就是「四段≤32、与版本号同形」，换文档段即失去被测形态
    solid = _ip_ep("185.60.216.35")                      # 无 ASN 富化 → 同为 MEDIUM  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    solid.evidences[0].snippet = "https://185.60.216.35:8443/api"   # 当地址用 → 不存疑  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    assert "18.20.31.2" < "185.60.216.35", "前提：存疑值字典序在前，否则排序键不是唯一变量"  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效

    eps = [suspect, solid]
    leads = build_endpoint_leads(eps)
    assert {ld.confidence for ld in leads} == {Confidence.MEDIUM}, "前提：置信度打平"
    rep = Report(
        package_name="com.example.app", meta={},
        leads=leads, endpoints=eps, findings=[], analyzer_status=[],
    )

    selected, _stats = _select_targets_with_stats(rep, max_targets=1)

    assert [e.value for e in selected] == ["185.60.216.35"], "存疑候选应排在正常候选之后"  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效


def test_reservation_survives_report_round_trip() -> None:
    """★往返锁：`case close` / `letters` 都从磁盘上的 report.json 走。

    读侧不还原这个字段，保留意见就在落盘那一刻蒸发——分析时标了、发函时没了，
    与"写进 notes 但出口不读 notes"是同一种断裂，只是断在另一处。
    """
    from apkscan.core.report_io import report_from_dict
    from apkscan.report.json import to_dict

    ep = _ip_ep(_BARE, _CLOUD_ASN)
    rep = Report(
        package_name="com.example.app", meta={},
        leads=build_endpoint_leads([ep]), endpoints=[ep], findings=[], analyzer_status=[],
    )
    assert rep.leads[0].shape_uncertain is True

    payload = to_dict(rep)
    assert payload["leads"][0]["shape_uncertain"] is True, "写侧丢字段"

    reloaded = report_from_dict(payload)
    assert reloaded.leads[0].shape_uncertain is True, "读侧丢字段：落盘一趟保留意见就没了"
    # 出口仍然带警示（而不是只有内存里那份带）
    assert "标的形态存疑" in build_letters(payload)[0]["body_md"]


def test_shape_uncertain_value_stays_out_of_cross_case_iocs() -> None:
    """★串案出口：两个无关样本恰好含同一个版本号，不得被呈现成「共享基础设施」。"""
    lead = build_endpoint_leads([_ip_ep(_BARE, _CLOUD_ASN)])[0]
    assert corpus._key_iocs({"leads": [_to_jsonable(lead)]}) == []

    solid = _ip_ep("103.36.167.109", _CLOUD_ASN)  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    solid.evidences[0].snippet = "https://103.36.167.109:8443/api"  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
    ok = build_endpoint_leads([solid])[0]
    assert corpus._key_iocs({"leads": [_to_jsonable(ok)]}) == ["103.36.167.109"]  # leak-scan: allow 低段位测试的对照组：需 is_global 为真才能走正常（不降级）路径，文档保留段被判私网会使对照失效
