"""Official product fingerprints: recall, false positives and attribution boundaries."""
from __future__ import annotations

import json

import pytest

from apkscan.core.attribution import build_ip_attribution, score_edge_provider


@pytest.mark.parametrize(("suffix", "provider"), [
    ("cdn.dnsv1.com", "cdn.tencent"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：cdn.dnsv1.com
    ("dsa.dnsv1.com", "cdn.tencent"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：dsa.dnsv1.com
    ("c.cdnhwc1.com", "cdn.huawei"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：c.cdnhwc1.com
    ("cdn.bcebos.com", "cdn.baidu_bos"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：cdn.bcebos.com
    ("qiniudns.com", "cdn.qiniu"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：qiniudns.com
    ("b0.aicdn.com", "cdn.upyun"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：b0.aicdn.com
    ("ksyuncdn.com", "cdn.kingsoft"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：ksyuncdn.com
    ("vip1.huaweicloudwaf.com", "waf.huawei"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：vip1.huaweicloudwaf.com
    ("qcloudwzgj.com", "waf.tencent"),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：qcloudwzgj.com
])
def test_official_cname_and_spoof_boundary(suffix: str, provider: str) -> None:
    edge = score_edge_provider({"cname_chain": [f"fixture.{suffix.upper()}."]})
    assert edge and edge["id"] == provider and edge["tier"] == "probable"
    assert edge["provenance"]["source"] == "public_docs"
    for forged in (f"fixture.{suffix}.attacker.test", f"not{suffix}"):
        assert score_edge_provider({"cname_chain": [forged]}) is None


@pytest.mark.parametrize(("headers", "provider", "tier"), [
    ({"EO-Cache-Status": "RefreshHit", "EO-LOG-UUID": "fixture"}, "cdn.tencent_edgeone", "probable"),
    ({"X-NWS-LOG-UUID": "fixture"}, "cdn.tencent", "possible"),
    ({"X-HCS-Proxy-Type": "1"}, "cdn.huawei", "possible"),
    ({"X-Bdcdn-Logid": "fixture", "X-Bdcdn-Cache-Status": "TCP_HIT"}, "cdn.volcengine", "probable"),
])
def test_http_headers_stay_one_evidence_surface(headers: dict[str, str], provider: str, tier: str) -> None:
    edge = score_edge_provider({"response_headers": headers})
    assert edge and edge["id"] == provider and edge["tier"] == tier
    assert score_edge_provider({"response_headers": dict.fromkeys(headers, " ")}) is None


@pytest.mark.parametrize("headers", [
    {"Server": "nginx", "X-Cache": "HIT", "Age": "1", "X-Cache-Lookup": "Cache Hit"},
    {"Server": "openresty"},
    {"Server": "TencentEdgeOneInjected"},
    {"EO-Cache-Status": "not-a-status"},
    {"X-HCS-Proxy-Type": "10"},
    {"X-Bce-Request-Id": "fixture"},
    {"X-Tt-Trace-Tag": "fixture"},
    {"Server": "AliyunOSS", "X-Oss-Request-Id": "fixture"},
    {"Server": "tencent-cos", "X-Cos-Request-Id": "fixture"},
    {"Server": "OBS", "X-Obs-Request-Id": "fixture"},
])
def test_generic_or_storage_headers_do_not_establish_edge(headers: dict[str, str]) -> None:
    assert score_edge_provider({"response_headers": headers}) is None


@pytest.mark.parametrize("cname", ["fixture.volces.com", "fixture.bcebos.com", "fixture.s1.aicdn.com"])  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：fixture.bcebos.com, fixture.s1.aicdn.com, fixture.volces.com
def test_product_root_does_not_imply_cdn(cname: str) -> None:
    assert score_edge_provider({"cname_chain": [cname]}) is None


def test_independent_dns_and_http_identify_product_not_customer_or_origin() -> None:
    view = build_ip_attribution("192.0.2.10", {
        "cname_chain": ["fixture.c.cdnhwc1.com"], "response_headers": {"X-HCS-Proxy-Type": "0"},  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：fixture.c.cdnhwc1.com
    })
    assert view["edge_provider"]["id"] == "cdn.huawei"
    assert view["edge_provider"]["tier"] == "confirmed"
    assert view["hosting_provider"]["name"] is None
    assert view["service_operator"]["name"] is None


def test_multiple_layers_survive_scoring_without_inventing_topology() -> None:
    view = build_ip_attribution("192.0.2.10", {
        "cname_chain": ["fixture.vip1.huaweicloudwaf.com", "fixture.cdn.dnsv1.com"],  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：fixture.cdn.dnsv1.com, fixture.vip1.huaweicloudwaf.com
        "response_headers": {"X-NWS-LOG-UUID": "fixture"},
    })
    edge = view["edge_provider"]
    assert edge["id"] == "cdn.tencent" and edge["tier"] == "confirmed"
    assert [row["id"] for row in edge["other_candidates"]] == ["waf.huawei"]
    assert edge["other_candidates"][0]["tier"] == "probable"
    assert edge["selection_scope"] == "ranked_fingerprints_not_exclusive_or_topology"
    assert "other_candidates" not in edge["other_candidates"][0]
    assert json.loads(json.dumps(view)) == view  # no self-reference in preserved candidates
    assert view["service_operator"]["name"] is None


def test_edgeone_with_storage_origin_header_retains_edge_identity() -> None:
    edge = score_edge_provider({"response_headers": {
        "Server": "tencent-cos", "X-Cos-Request-Id": "fixture-origin",
        "EO-LOG-UUID": "fixture-edge", "EO-Cache-Status": "MISS",
    }})
    assert edge and edge["id"] == "cdn.tencent_edgeone" and edge["tier"] == "probable"
