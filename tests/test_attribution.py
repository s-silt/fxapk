"""五层 IP 归属模型（core/attribution）：分类器 + 五层组装 + edge 多信号打分，纯逻辑离线测。

★核心纪律测试点：五层不塌缩（service_operator 恒 None、hosting≠website_owner）；confirmed 须 ≥2 独立强信号；
单一 ASN/header 不足以 confirmed；负证据抑制"租了公有云"误判；坏输入 → unknown、绝不抛。
"""

from __future__ import annotations

import math

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
    # 超大整数权重（float() OverflowError）与 inf 权重（非有限）→ _num 兜默认、不抛、不泄漏 inf 分。
    huge = A.score_edge_provider(
        {"response_headers": {"cf-ray": "x"}},
        rules={"edge_providers": [{"id": "c", "name": "C", "signals": {"http": {"headers": [{"name": "cf-ray"}]}}}],
               "weights": {"response_header": 10 ** 10000}})
    assert huge is not None and huge["score"] == 6.0  # 脏权重回落默认 6
    inf_w = A.score_edge_provider(
        {"response_headers": {"cf-ray": "x"}, "cname_chain": ["a.cf.net"]},
        rules={"edge_providers": [{"id": "c", "name": "C", "signals": {
            "http": {"headers": [{"name": "cf-ray", "weight": float("inf")}]},
            "dns": {"cname_suffix": [{"value": ".cf.net", "weight": 8}]}}}]})
    assert inf_w is not None and math.isfinite(inf_w["score"]) and inf_w["score"] == 14.0


def test_edge_asn_signal_rejects_reserved_and_out_of_range() -> None:
    """★ASN 弱信号匹配前须过 range 校验：保留值/越界观测 ASN 不得被规则采纳为证据（与 _parse_asn 同纪律）。"""
    def _rule(asn_val: int) -> dict:
        return {"edge_providers": [{"id": "c", "name": "C", "signals": {
            "network": {"asns": [{"value": asn_val, "weight": 3}]}}}],
            "scoring": {"confirmed": 10, "probable": 6, "possible": 3}}
    # 保留值 4294967295 / 0：即便规则恰好列了它，观测到也不采纳 → None。
    assert A.score_edge_provider({"asn": 4294967295}, rules=_rule(4294967295)) is None
    assert A.score_edge_provider({"asn": 0}, rules=_rule(0)) is None
    # 合法可路由 ASN 仍正常匹配 → possible。
    ok = A.score_edge_provider({"asn": 13335}, rules=_rule(13335))
    assert ok is not None and ok["tier"] == "possible" and ok["score"] == 3.0
    # 非整数 float ASN（13335.9）不得被截断采纳；规则侧超长数字串不得抛。
    assert A.score_edge_provider({"asn": 13335.9}, rules=_rule(13335)) is None
    assert A.score_edge_provider({"asn": 13335}, rules=_rule("9" * 10000)) is None  # type: ignore[arg-type]


def test_parse_asn_oversized_digit_string_no_raise() -> None:
    """★超长数字串（>10 位）在 int() 触达 CPython 4300 位限制前即判非法 → (None, None)，绝不抛。"""
    assert A._parse_asn("9" * 10000) == (None, None)
    assert A._parse_asn("AS" + "1" * 5000) == (None, None)
    assert A._parse_asn("13335.9") == (None, None)  # 非整数字符串
    assert A._parse_asn(13335.9) == (None, None)    # 非整数 float


def test_edge_score_always_finite() -> None:
    """★分数有限总闸：即便规则权重是有限大数（1e308）累加溢出成 inf，也不得泄漏非有限分 → 候选作废。"""
    r = A.score_edge_provider(
        {"response_headers": {"cf-ray": "x"}, "cname_chain": ["a.cf.net"]},
        rules={"edge_providers": [{"id": "c", "name": "C", "signals": {
            "http": {"headers": [{"name": "cf-ray", "weight": 1e308}]},
            "dns": {"cname_suffix": [{"value": ".cf.net", "weight": 1e308}]}}}]})
    assert r is None  # inf 分被 isfinite 闸拦下
    # 合法权重仍产出有限分。
    ok = A.score_edge_provider({"response_headers": {"cf-ray": "x"}}, rules=_RULES)
    assert ok is not None and math.isfinite(ok["score"])


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
    """只有 dns.ips 但无 cname/asn 可用信号 → 无归因价值 → None（不产全 unknown 空壳）。"""
    assert A.attribution_from_enrichment({"dns": {"ips": ["1.2.3.4"]}}) is None
    # 但有 CNAME（可识别 edge）就该产出。
    att = A.attribution_from_enrichment({"dns": {"cname": ["a.cdn.cloudflare.net"]}})
    assert att is not None and att["edge_provider"]["name"] == "Cloudflare"


def test_build_endpoint_attribution_ip() -> None:
    """IP 端点：用 enrichment['asn'] → 单条五层归因。"""
    att = A.build_endpoint_attribution("ip", "1.2.3.4", {"asn": {"asn": "AS45090", "org": "Tencent cloud"}})
    assert att is not None and att["kind"] == "ip" and att["endpoint"] == "1.2.3.4"
    assert len(att["ips"]) == 1
    assert att["ips"][0]["origin_network"]["category"] == A.CAT_CLOUD
    assert att["ips"][0]["resource_holder"]["name"] is None  # 未接 IP-RDAP，不冒充登记方


def test_build_endpoint_attribution_domain_per_ip_never_collapses() -> None:
    """★域名解析到多 IP（异构 ASN）→ 逐 IP 五层、绝不合并；域名级 CNAME 喂每个 IP 的 edge。"""
    att = A.build_endpoint_attribution("domain", "pay.example.com", {
        "dns": {
            "ips": ["1.1.1.1", "2.2.2.2"],
            "hosting": [
                {"ip": "1.1.1.1", "asn": "AS13335", "org": "Cloudflare", "country": "US"},
                {"ip": "2.2.2.2", "asn": "AS45090", "org": "Tencent", "country": "CN"},
            ],
            "cname": ["pay.example.com.cdn.cloudflare.net"],
        },
    })
    assert att is not None and att["kind"] == "domain" and len(att["ips"]) == 2
    by_ip = {layer["ip"]: layer for layer in att["ips"]}
    # ★两个 IP 的 origin 各不相同（不塌缩）：一个 cdn、一个 cloud。
    assert by_ip["1.1.1.1"]["origin_network"]["category"] == A.CAT_CDN
    assert by_ip["2.2.2.2"]["origin_network"]["category"] == A.CAT_CLOUD
    # 域名级 CNAME 共享给每个 IP 的 edge（单强信号 → probable）。
    assert by_ip["1.1.1.1"]["edge_provider"]["name"] == "Cloudflare"
    assert by_ip["2.2.2.2"]["edge_provider"]["name"] == "Cloudflare"


def test_build_endpoint_attribution_domain_hosting_missing_degrades() -> None:
    """域名 hosting 缺（限速）但有 ips+cname → 退化：origin unknown，但 CNAME 仍识别 edge。"""
    att = A.build_endpoint_attribution("domain", "x.com", {
        "dns": {"ips": ["3.3.3.3"], "cname": ["x.com.cdn.cloudflare.net"]}})
    assert att is not None and len(att["ips"]) == 1
    assert att["ips"][0]["origin_network"]["category"] == A.CAT_UNKNOWN
    assert att["ips"][0]["edge_provider"]["name"] == "Cloudflare"


def test_build_endpoint_attribution_partial_hosting_keeps_all_ips() -> None:
    """★P0 回归（不塌缩）：hosting 常少于 ips（部分 IP 托管查询限速被跳过）——每个解析 IP 都须产一条，
    只在 ips 里、hosting 缺的 IP 用 unknown ASN，绝不因只遍历 hosting 而丢失。"""
    att = A.build_endpoint_attribution("domain", "pay.x.com", {
        "dns": {
            "ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],  # 解析到 3 个
            "hosting": [{"ip": "1.1.1.1", "asn": "AS13335", "org": "Cloudflare"}],  # 仅 1 个查到托管
        },
    })
    assert att is not None
    by_ip = {layer["ip"]: layer for layer in att["ips"]}
    assert set(by_ip) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}, "只在 ips 里的 IP 被丢失 = per-IP 塌缩"
    assert by_ip["1.1.1.1"]["origin_network"]["asn"] == 13335  # hosting 命中 → 有 ASN
    assert by_ip["2.2.2.2"]["origin_network"]["asn"] is None   # hosting 缺 → unknown ASN，但 IP 保留
    assert by_ip["3.3.3.3"]["origin_network"]["asn"] is None


def test_build_endpoint_attribution_hosting_ip_not_in_ips_kept() -> None:
    """hosting 里出现 ips 未列的 IP（数据不一致）→ 也纳入，一个不丢（ips ∪ hosting.ip）。"""
    att = A.build_endpoint_attribution("domain", "y.com", {
        "dns": {"ips": ["1.1.1.1"], "hosting": [{"ip": "9.9.9.9", "asn": "AS45090", "org": "Tencent"}]}})
    assert att is not None
    assert {layer["ip"] for layer in att["ips"]} == {"1.1.1.1", "9.9.9.9"}


def test_build_endpoint_attribution_no_empty_shell() -> None:
    """★P2：非空但字段全 None 的子键不得产全 unknown 空壳 → None（IP 端点空 asn / 域名空 hosting 元素）。"""
    assert A.build_endpoint_attribution("ip", "1.2.3.4", {"asn": {"asn": None, "org": None, "isp": None}}) is None
    assert A.build_endpoint_attribution("ip", "1.2.3.4", {"asn": {"unexpected": "v"}}) is None
    assert A.build_endpoint_attribution("ip", "1.2.3.4", {"webcheck": {"unrelated": True}}) is None
    assert A.build_endpoint_attribution("domain", "z.com", {"dns": {"hosting": [{}]}}) is None  # 无有效 IP
    assert A.build_endpoint_attribution("domain", "z.com", {"dns": {"ips": [""]}}) is None       # 空 IP 串


def test_build_endpoint_attribution_none_and_robust() -> None:
    """无归属信号 → None；坏输入/未知 kind → None，绝不抛。"""
    assert A.build_endpoint_attribution("domain", "y.com", {}) is None
    assert A.build_endpoint_attribution("ip", "5.5.5.5", {"tier": "app"}) is None
    assert A.build_endpoint_attribution("ip", "x", None) is None  # type: ignore[arg-type]
    assert A.build_endpoint_attribution("weird", "x", {"asn": {"asn": "AS1"}}) is None  # 未知 kind → 无 per-IP
    # 域名 hosting 列表里混入坏元素不抛。
    att = A.build_endpoint_attribution("domain", "z.com", {"dns": {"hosting": [None, {"ip": "9.9.9.9", "asn": "AS45090"}]}})
    assert att is not None and len(att["ips"]) == 1 and att["ips"][0]["ip"] == "9.9.9.9"
    # ★退化分支 ips 非 list：int 不得抛（不可迭代）、str 不得被逐字符迭代成垃圾 per-IP → 一律 None。
    for bad_ips in (123, "1.2.3.4", None, {"a": 1}):
        assert A.build_endpoint_attribution("domain", "x", {"dns": {"ips": bad_ips}}) is None, f"ips={bad_ips!r} 未安全归空"
    # dns 子键本身非 dict 也不抛。
    assert A.build_endpoint_attribution("domain", "x", {"dns": []}) is None
    assert A.build_endpoint_attribution("domain", "x", {"dns": "garbage"}) is None


def test_ip_rdap_fills_resource_holder() -> None:
    """★slice-1c：IP-RDAP 子键（资源登记方）→ resource_holder 层不再恒 unknown。"""
    ip_rdap = {"netname": "VULTR-AS20473", "org": "Vultr Holdings", "country": "US", "source": "rdap-ip"}
    att = A.build_endpoint_attribution("ip", "45.76.1.1", {"asn": {"asn": "AS20473", "org": "Vultr"}, "ip_rdap": ip_rdap})
    rh = att["ips"][0]["resource_holder"]
    assert rh["name"] == "VULTR-AS20473" and rh["confidence"] == A.CONF_HIGH and rh["source"] == "rdap-ip"


def test_ip_rdap_only_is_valid_signal() -> None:
    """仅有 ip_rdap（无 asn/dns）也算有效信号 → 产出（resource_holder 有值，其余层 unknown）。"""
    att = A.build_endpoint_attribution("ip", "1.2.3.4", {"ip_rdap": {"netname": "SOME-NET", "source": "rdap-ip"}})
    assert att is not None
    assert att["ips"][0]["resource_holder"]["name"] == "SOME-NET"
    assert att["ips"][0]["origin_network"]["category"] == A.CAT_UNKNOWN  # 无 ASN → origin 仍 unknown（不塌缩）


def test_ip_rdap_empty_not_signal() -> None:
    """ip_rdap 存在但无 netname/org（全空登记）→ 不算有效信号、不冒充 resource_holder。"""
    assert A.build_endpoint_attribution("ip", "x", {"ip_rdap": {"source": "rdap-ip"}}) is None
    # country 补全：ip_rdap 有 country 但无 netname/org 时不设 rdap，但 country 仍不足以单独成信号。
    assert A.build_endpoint_attribution("ip", "x", {"ip_rdap": {"country": "US"}}) is None
