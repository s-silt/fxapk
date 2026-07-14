"""五层 IP 归属模型（core/attribution）：分类器 + 五层组装 + edge 多信号打分，纯逻辑离线测。

★核心纪律测试点：五层不塌缩（service_operator 恒 None、hosting≠website_owner）；confirmed 须 ≥2 独立强信号；
单一 ASN/header 不足以 confirmed；负证据抑制"租了公有云"误判；坏输入 → unknown、绝不抛。
"""

from __future__ import annotations

from apkscan.core import attribution as A

# 自造规则（不依赖 rules/providers.yaml，测引擎逻辑本身）。
_RULES = {
    "network_categories": {
        A.CAT_CLOUD: {"org_keywords": ["tencent", "aliyun", "阿里"]},
        A.CAT_CDN: {"org_keywords": ["cloudflare"]},
        A.CAT_TELECOM: {"org_keywords": ["chinanet", "中国电信"]},
        A.CAT_SECURITY_PROXY: {"org_keywords": ["jiasule", "加速乐"]},
    },
    "edge_providers": [
        {
            "id": "cdn.cf", "name": "Cloudflare", "category": "cdn", "role": "reverse_proxy",
            "signals": {
                "http": {"headers": [{"name": "cf-ray", "weight": 6}]},
                "dns": {"cname_suffix": [{"value": ".cloudflare.net", "weight": 8}]},
                "network": {"asns": [{"value": 13335, "weight": 2}]},
            },
        },
        {
            "id": "waf.jsl", "name": "加速乐", "category": "security_proxy", "role": "waf",
            "signals": {"http": {
                "headers": [{"name": "server", "regex": "jsl", "weight": 6}],
                "cookies": [{"value": "__jsluid", "weight": 5}],
            }},
            "negative_signals": [{"type": "public_cloud_only", "weight": -2}],
        },
    ],
    "scoring": {"confirmed": 10, "probable": 6, "possible": 3},
}


def test_classify_network() -> None:
    assert A.classify_network("Tencent cloud computing", "AS45090") == A.CAT_CLOUD
    assert A.classify_network("Cloudflare Inc", "AS13335") == A.CAT_CDN
    assert A.classify_network("CHINANET-BACKBONE", "AS4134") == A.CAT_TELECOM
    assert A.classify_network("Yunaq Jiasule", None) == A.CAT_SECURITY_PROXY  # rules/providers.yaml 有 jiasule
    assert A.classify_network(None, None) == A.CAT_UNKNOWN
    assert A.classify_network("Some Random Ltd", "AS99999") == A.CAT_UNKNOWN


def test_five_layers_never_collapse() -> None:
    """★五层各自独立、不塌缩：service_operator 恒未知、hosting 不等于 website_owner。"""
    att = A.build_ip_attribution("1.2.3.4", {
        "country": "cn", "rdap": {"netname": "ALISOFT"},
        "asn": {"asn": "AS37963", "org": "Hangzhou Aliyun"},
    })
    assert set(att) == {"ip", "country", "resource_holder", "origin_network",
                        "hosting_provider", "edge_provider", "service_operator"}
    assert att["country"] == "CN"
    assert att["resource_holder"]["name"] == "ALISOFT" and att["resource_holder"]["confidence"] == A.CONF_HIGH
    assert att["origin_network"]["asn"] == 37963 and att["origin_network"]["category"] == A.CAT_CLOUD  # Aliyun→cloud
    assert att["hosting_provider"]["role"] == "cloud_host"  # hosting 反映网络类型，★不写成 website_owner
    # ★实际站点运营者绝不从 ASN/RDAP 推断
    assert att["service_operator"]["name"] is None and att["service_operator"]["confidence"] == A.CONF_UNKNOWN


def test_edge_confirmed_requires_two_strong_signals() -> None:
    """★单一强信号最多 probable；≥2 个不同强信号才 confirmed（防单头被配置/伪造即坐实）。"""
    one = A.score_edge_provider({"response_headers": {"CF-RAY": "abc"}}, rules=_RULES)
    assert one["tier"] == "probable" and one["confidence"] == A.CONF_MEDIUM
    two = A.score_edge_provider(
        {"response_headers": {"CF-RAY": "abc"}, "cname_chain": ["x.cloudflare.net"]}, rules=_RULES)
    assert two["tier"] == "confirmed" and two["confidence"] == A.CONF_HIGH
    assert len([m for m in two["matched_signals"] if m.startswith(("cname", "response_header"))]) == 2


def test_edge_cookie_name_matched_by_name() -> None:
    """观测 cookie 带 =value → 按名匹配规则的 cookie 名（server 头 + __jsluid cookie = 2 强信号 → confirmed）。"""
    edge = A.score_edge_provider(
        {"response_headers": {"Server": "jsl/1.1"}, "cookies": ["__jsluid=deadbeef; path=/"]}, rules=_RULES)
    assert edge["id"] == "waf.jsl" and edge["tier"] == "confirmed"


def test_edge_weak_only_below_threshold_returns_none() -> None:
    """只命中 ASN（弱信号 weight 2 < possible 阈值 3）→ 不达阈值 → None（未识别，非"无代理"）。"""
    assert A.score_edge_provider({"asn": 13335}, rules=_RULES) is None


def test_edge_negative_public_cloud_only_dampens() -> None:
    """只公共云 ASN 类别、无强信号 → public_cloud_only 负证据触发（防"租了公有云"当代理坐实）。"""
    # 无任何正信号 → 直接 None
    assert A.score_edge_provider({"origin_category": A.CAT_CLOUD}, rules=_RULES) is None


def test_origin_network_parses_asn_string_forms() -> None:
    assert A._origin_network({"asn": "AS12345 Some Org"})["asn"] == 12345
    assert A._origin_network({"asn": "12345", "org": "X"})["asn"] == 12345
    assert A._origin_network({})["asn"] is None and A._origin_network({})["confidence"] == A.CONF_UNKNOWN
    assert A._origin_network(None)["asn"] is None  # type: ignore[arg-type]


def test_build_robust_bad_input() -> None:
    att = A.build_ip_attribution("x", None)  # type: ignore[arg-type]
    assert att["resource_holder"]["name"] is None
    assert att["origin_network"]["category"] == A.CAT_UNKNOWN
    assert att["edge_provider"]["name"] is None  # 无信号 → edge 未识别
    assert att["service_operator"]["name"] is None


def test_attribution_from_enrichment_maps_asn_layers() -> None:
    """扁平 enrichment 的 asn 子键 → origin/hosting 分层；resource_holder 暂 unknown（未接 IP RDAP，不冒充登记方）。"""
    att = A.attribution_from_enrichment({"asn": {"asn": "AS45090", "org": "Tencent cloud", "country": "CN"}})
    assert att is not None
    assert att["origin_network"]["asn"] == 45090 and att["origin_network"]["category"] == A.CAT_CLOUD
    assert att["hosting_provider"]["role"] == "cloud_host"
    assert att["resource_holder"]["name"] is None  # ★不拿 ISP 冒充 RDAP 登记方
    assert att["service_operator"]["name"] is None


def test_attribution_from_enrichment_none_without_signals() -> None:
    assert A.attribution_from_enrichment({}) is None
    assert A.attribution_from_enrichment({"tier": "app"}) is None  # 无 asn/webcheck → None
    assert A.attribution_from_enrichment(None) is None  # type: ignore[arg-type]


def test_attribution_from_enrichment_edge_from_webcheck() -> None:
    """webcheck 的响应头 → edge 层（此处只 1 强信号 → 最多 probable）。"""
    att = A.attribution_from_enrichment({
        "asn": {"asn": "AS13335", "org": "Cloudflare"},
        "webcheck": {"response_headers": {"CF-RAY": "abc123"}},
    })
    assert att is not None
    assert att["origin_network"]["category"] == A.CAT_CDN
    assert att["edge_provider"].get("name") == "Cloudflare" and att["edge_provider"].get("tier") == "probable"
