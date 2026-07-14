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
                "tls": {"spki_sha256": [{"value": "deadbeef", "weight": 4}]},  # 中信号（非强），供负证据测试
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
    """★负证据**精确扣 2**（非随意扣分）：验证扣分前后分数差正好 2、且带 neg 标签、跨阈值时降档。"""
    # 仅命中 TLS 中信号（weight 4，非强）→ 4 ≥ possible(3) → possible。
    hit = A.score_edge_provider({"tls_spki": "deadbeef"}, rules=_RULES)
    assert hit is not None and hit["tier"] == "possible" and hit["score"] == 4.0
    # 叠加 origin 在公共云类别且无强信号 → public_cloud_only 扣 2 → 2 < possible(3) → 被抑制为 None。
    damp = A.score_edge_provider({"tls_spki": "deadbeef", "origin_category": A.CAT_CLOUD}, rules=_RULES)
    assert damp is None
    # ★精确性：TLS(4)+ASN(2)=6 probable，叠负证据 → 正好 4.0（差恰为 2，不是 3、不是 100）→ possible，且带 neg 标签。
    exact = A.score_edge_provider({"tls_spki": "deadbeef", "asn": 13335, "origin_category": A.CAT_CLOUD}, rules=_RULES)
    assert exact is not None and exact["score"] == 4.0 and exact["tier"] == "possible"
    assert "neg:public_cloud_only" in exact["weak_signals"]
    # 反向对照：非公共云类别 → 负证据不触发 → 6.0 probable（证明确是该负证据在起作用）。
    keep = A.score_edge_provider({"tls_spki": "deadbeef", "asn": 13335, "origin_category": A.CAT_TELECOM}, rules=_RULES)
    assert keep is not None and keep["score"] == 6.0 and keep["tier"] == "probable"


def test_edge_reranks_by_tier_not_raw_score() -> None:
    """★负证据后重排：原始分更高但只到 probable 的弱候选，不得压过分数略低却 confirmed（≥2 强信号）的候选。"""
    rules = {"edge_providers": [
        {"id": "A", "name": "ProvA", "category": "cdn",
         "signals": {"tls": {"spki_sha256": [{"value": "aa", "weight": 15}]}}},   # 原始分 15、0 强信号 → 顶 probable
        {"id": "B", "name": "ProvB", "category": "cdn", "signals": {              # 6+8=14、2 强信号 → confirmed
            "http": {"headers": [{"name": "x-b", "weight": 6}]},
            "dns": {"cname_suffix": [{"value": ".provb.net", "weight": 8}]}}},
    ], "scoring": {"confirmed": 10, "probable": 6, "possible": 3}}
    obs = {"tls_spki": "aa", "response_headers": {"x-b": "1"}, "cname_chain": ["e.provb.net"],
           "origin_category": A.CAT_CLOUD}
    best = A.score_edge_provider(obs, rules=rules)
    assert best is not None and best["name"] == "ProvB" and best["tier"] == "confirmed"


def test_edge_negative_x_cache_and_nginx_only_dampen() -> None:
    """x_cache_only / nginx_only 两类通用中间件负证据也真扣分。"""
    base = {"tls_spki": "deadbeef"}
    assert A.score_edge_provider({**base, "x_cache_only": True}, rules=_RULES) is None   # 4-2=2 → None
    assert A.score_edge_provider({**base, "server_nginx_only": True}, rules=_RULES) is None  # 4-3=1 → None


def test_edge_forged_suffix_not_confirmed() -> None:
    """★P0：伪造域名把品牌根塞进**中间**（x.cloudflare.net.attacker.example）不得命中——标签级匹配。"""
    forged = A.score_edge_provider(
        {"response_headers": {"CF-RAY": "forged"}, "cname_chain": ["x.cloudflare.net.attacker.example"]}, rules=_RULES)
    # CNAME 不命中 → 只剩单 header 强信号 → 最多 probable，绝不 confirmed。
    assert forged is not None and forged["tier"] == "probable"
    assert not any(m.startswith("cname") for m in forged["matched_signals"])
    # 真·子域仍 confirmed（header + cname = 2 强信号）。
    genuine = A.score_edge_provider(
        {"response_headers": {"CF-RAY": "ok"}, "cname_chain": ["edge.cloudflare.net"]}, rules=_RULES)
    assert genuine is not None and genuine["tier"] == "confirmed"


def test_host_suffix_match_boundaries() -> None:
    """★标签级后缀匹配的边界：精确/子域/大小写/末点 命中；中间根/空标签/父域 不命中。"""
    S = A._host_hits_suffix
    assert S(["cloudflare.net"], ".cloudflare.net")            # 精确
    assert S(["edge.cloudflare.net"], "cloudflare.net")        # 子域（后缀前导点可省）
    assert S(["EDGE.CloudFlare.NET"], ".cloudflare.net")       # 大小写不敏感
    assert S(["edge.cloudflare.net."], ".cloudflare.net")      # 末点归一
    assert not S(["x.cloudflare.net.evil.com"], ".cloudflare.net")   # 根在中间
    assert not S(["x..cloudflare.net"], ".cloudflare.net")     # 空标签畸形
    assert not S(["notcloudflare.net"], ".cloudflare.net")     # 非标签边界（子串但非后缀标签）
    assert not S(["net"], ".cloudflare.net")                   # 父域（比根短）
    assert not S([], ".cloudflare.net") and not S(["a.b"], "")  # 空输入/空规则


def test_origin_network_rejects_malformed_asn() -> None:
    """★P0：畸形 ASN（负号/小数/前缀垃圾/越界/保留值/bool）不得抠出数字冒充高置信 BGP 归属 → 一律 unknown。"""
    bad_values: list[object] = [
        "-123 Tencent", "1.5 Tencent", "garbage123 Tencent", "AS4294967296 Tencent",
        "AS0", "AS4294967295",  # 0（RFC7607）与 0xFFFFFFFF（RFC7300）保留值
        "", True, False,        # bool 是 int 子类，须显式排除，不得被当作 AS1/AS0
    ]
    for bad in bad_values:
        o = A._origin_network({"asn": bad})
        assert o["asn"] is None and o["confidence"] == A.CONF_UNKNOWN, f"bad asn {bad!r} 未被拒"
        assert o["source"] is None
    # 合法边界仍解析：可路由上界 4294967294、裸数字、AS 前缀带 org 尾。
    for ok_val, want in [("AS45090", 45090), ("AS4294967294", 4294967294), (45090, 45090), ("AS12345 Org", 12345)]:
        o = A._origin_network({"asn": ok_val})
        assert o["asn"] == want and o["confidence"] == A.CONF_HIGH and o["source"] == "BGP/ASN", f"{ok_val!r} 应解析"


def test_never_raises_on_bad_input() -> None:
    """★核心 invariant「绝不抛」：各类坏输入（None/错类型/畸形规则）都返回结构或 None，绝不异常。"""
    assert A.score_edge_provider(None) is None                       # observed=None
    assert A.score_edge_provider({}, rules=[]) is None               # rules 非 dict
    assert A.score_edge_provider({}, rules={"edge_providers": "x"}) is None  # edges 非 list
    # 列表字段被喂标量 → 不迭代崩溃。
    for bad_field in ({"cname_chain": 123}, {"nameservers": 5}, {"cookies": "a=b"}, {"response_headers": [1, 2]}):
        A.build_ip_attribution("1.2.3.4", bad_field)  # 不抛即通过
    # 畸形 scoring/weights 不参与比较时崩溃（None/字符串阈值与权重都被 _num 清洗回默认）。
    r = A.score_edge_provider(
        {"response_headers": {"cf-ray": "x"}, "cname_chain": ["a.cdn.cloudflare.net"]},
        rules={"edge_providers": [{"id": "c", "name": "CF", "signals": {
            "http": {"headers": [{"name": "cf-ray", "weight": 6}]},
            "dns": {"cname_suffix": [{"value": ".cdn.cloudflare.net", "weight": 8}]}}}],
            "scoring": {"probable": None, "confirmed": "x"},
            "weights": {"response_header": "bad", "cname_suffix": None}})   # 脏正权重不得 0.0+str 抛
    assert r is not None  # 阈值/权重被 _num 清洗回默认，仍能定档
    # 观测 ASN 为无穷/极端浮点 → int() 转换 OverflowError 须被吞（绝不抛）。
    assert A.score_edge_provider(
        {"asn": float("inf")},
        rules={"edge_providers": [{"id": "c", "name": "C", "signals": {
            "network": {"asns": [{"value": 13335, "weight": 2}]}}}]}) is None


def test_every_layer_has_source_field() -> None:
    """★invariant：五层都带 source 键（未知即 None，已识别写明来源）。"""
    att = A.build_ip_attribution("1.2.3.4", {"rdap": {"netname": "X"}, "asn": {"asn": "AS45090", "org": "Tencent"}})
    for layer in ("resource_holder", "origin_network", "hosting_provider", "edge_provider", "service_operator"):
        assert "source" in att[layer], f"{layer} 缺 source 键"
    assert att["origin_network"]["source"] == "BGP/ASN"
    assert att["hosting_provider"]["source"] == "origin_asn_category"


def test_real_providers_yaml_confirmed_needs_two_signals() -> None:
    """契约测试：用**真实 rules/providers.yaml**，Cloudflare 单头 probable、header+cname 才 confirmed。"""
    one = A.score_edge_provider({"response_headers": {"CF-RAY": "abc"}})  # rules=None → 加载真实库
    assert one is not None and one["tier"] == "probable"
    two = A.score_edge_provider(
        {"response_headers": {"CF-RAY": "abc"}, "cname_chain": ["e.cdn.cloudflare.net"]})
    assert two is not None and two["tier"] == "confirmed" and two["name"] == "Cloudflare"


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


def test_attribution_from_enrichment_reads_dns_cname() -> None:
    """★P1-2：映射器须读 DnsEnricher 真实输出位置 enrichment['dns']['cname']（而非只看 webcheck）。

    dns.cname（专属后缀，强信号）+ webcheck 响应头 CF-RAY（强信号）= 2 强信号 → confirmed。
    """
    att = A.attribution_from_enrichment({
        "asn": {"asn": "AS13335", "org": "Cloudflare"},
        "dns": {"cname": ["a.cdn.cloudflare.net"]},
        "webcheck": {"response_headers": {"CF-RAY": "z"}},
    })
    assert att is not None
    assert att["edge_provider"].get("name") == "Cloudflare"
    assert att["edge_provider"].get("tier") == "confirmed"  # 若只读 webcheck、漏 dns.cname，则只会 probable


def test_attribution_from_enrichment_none_on_dns_only_no_signal() -> None:
    """只有 dns 但无 cname/asn 可用信号 → 仍返回结构（dns 子键存在即触发），edge 未识别。"""
    att = A.attribution_from_enrichment({"dns": {"ips": ["1.2.3.4"]}})
    assert att is not None and att["edge_provider"]["name"] is None
