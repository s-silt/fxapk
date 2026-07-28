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

from apkscan.core.attribution import classify_network
from apkscan.core.closure.targets import _select_targets_with_stats
from apkscan.core.infra import ADVICE_INVESTIGATE, ADVICE_REVIEW
from apkscan.core.leads import _is_tenant_hosting_asn, build_endpoint_leads
from apkscan.core.models import Endpoint, Evidence, Report
from apkscan.network.categories import CAT_CLOUD, CAT_TELECOM

#: 裸字面证据：值本身出现在字符串表里，既无端口也无 URL 语境——降级判据的触发前提。
_BARE = "23.21.5.12"

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
    eps = [_ip_ep(v, _CLOUD_ASN) for v in ("1.3.1.1", "1.3.1.6", "1.4.1.14")]
    leads = build_endpoint_leads(eps)

    assert len(leads) == 3
    assert all(x.advice == ADVICE_REVIEW for x in leads), [
        (x.value, x.advice) for x in leads
    ]


def test_wired_sibling_pool_excludes_self() -> None:
    """兄弟池要减掉自己：两个低段位值时各自只有 1 个兄弟，未达成簇阈值 → 都升。

    不减自己就会让"孤值 + 自己"凑够 2 个，把定向豁免整条废掉。
    """
    eps = [_ip_ep(v, _CLOUD_ASN) for v in ("23.21.5.12", "3.15.20.4")]
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
