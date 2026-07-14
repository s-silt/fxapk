"""五层 IP/域名基础设施归属模型 —— 把"IP 归属"从扁平"所属公司"升级为不塌缩的归因链。

    resource_holder（IP 资源登记方）
      → origin_network（BGP Origin ASN / 网络运营方）
        → hosting_provider（云厂商 / IDC）
          → edge_provider（CDN / WAF / 防红代理，多信号指纹）
            → service_operator（实际站点运营者，通常未知）

★核心纪律（用户明确要求）：**五层绝不塌缩成一个"所属公司"字段**。IP 在腾讯 ASN ≠ 涉诈 App 由腾讯运营。
每层带 ``name/role/source/confidence``（edge 另带 ``matched_signals``/``weak_signals``/``score``）；查不到就
标 ``unknown``、绝不为了填满而猜。edge_provider（防红/CDN/WAF）靠**可解释多信号加权**——单一 ASN/CIDR
不足以 confirmed（代理商会换服务器商、云 IP 大量无关租户共用）。

纯函数、离线可测、绝不抛：坏输入 → 该层 unknown。规则来自 ``rules/providers.yaml``（缺失 → 内置兜底）。
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# 置信度档。
CONF_HIGH = "high"
CONF_MEDIUM = "medium"
CONF_LOW = "low"
CONF_UNKNOWN = "unknown"

# 网络类型分类（origin_network / hosting_provider 用）。
CAT_TELECOM = "telecom"
CAT_CLOUD = "cloud"
CAT_IDC = "idc"
CAT_CDN = "cdn"
CAT_SECURITY_PROXY = "security_proxy"
CAT_HOSTING_RESELLER = "hosting_reseller"
CAT_ENTERPRISE = "enterprise_network"
CAT_UNKNOWN = "unknown"

#: 云/CDN 类别（这些类别下的 ASN 不足以独立坐实 edge——共享租户多，见 _score_edge 负证据）。
_SHARED_INFRA_CATEGORIES = frozenset({CAT_CLOUD, CAT_CDN, CAT_IDC, CAT_HOSTING_RESELLER})

#: edge 打分默认权重（rules 的每条 signal 可带 weight 覆盖）。可解释：越"专属"越高分，公共基础设施特征扣分。
#: 强信号=cname_suffix/response_header/error_page_hash/nameserver/cookie；中=tls/ip_pool；弱=asn/cidr/geo。
_EDGE_WEIGHTS = {
    "cname_suffix": 8,       # 专属接入域名后缀——最有辨识力
    "response_header": 6,    # 官方文档可验证的独特响应头（CF-Ray / Server:TencentEdgeOne 等）
    "error_page_hash": 6,    # 默认错误页精确哈希（body_sha256 / favicon mmh3）
    "nameserver": 5,         # 专属 NS 后缀
    "cookie": 5,             # 专属 Cookie 名
    "tls_fingerprint": 4,    # TLS SPKI / JA4S 服务端指纹
    "ip_pool": 3,            # 命中高重合 IP 池
    "asn_cidr": 2,           # 专属 CIDR 命中
    "asn": 1,                # 普通云厂商 ASN（最弱——大量共用）
    "geo": 0.5,
}
#: 负证据（公共基础设施特征——防止把"租了公有云/通用 nginx"当"代理商坐实"）。
_EDGE_NEG_WEIGHTS = {
    "public_cloud_only": -2,   # 只命中公共云 ASN
    "x_cache_only": -2,        # 只命中通用 X-Cache（多家 CDN 共用）
    "nginx_only": -3,          # 只命中 Server: nginx
    "time_span_wide": -2,      # 证据时间跨度过大
    "cname_changed_no_history": -2,
    "generic_nginx_page": -2,
    "shared_le_cert": -1,
}
#: edge 判定阈值（rules 的 scoring 可覆盖）。confirmed 另要求 ≥2 独立强信号（见 _edge_tier）。
_EDGE_THRESHOLDS = {"confirmed": 10, "probable": 6, "possible": 3}
_EDGE_CONF = {"confirmed": CONF_HIGH, "probable": CONF_MEDIUM, "possible": CONF_LOW, "clustered": CONF_HIGH}
#: 强信号种类（confirmed 需 ≥2 个不同强信号命中——单一强信号最多 probable）。
_STRONG_SIGNAL_KINDS = frozenset({"cname_suffix", "response_header", "error_page_hash", "nameserver", "cookie"})

_PROVIDERS_CACHE: dict[str, Any] | None = None


def _providers_rules() -> dict[str, Any]:
    """加载 rules/providers.yaml（网络类别关键字 + edge 指纹库）。缺失/异常 → 内置兜底。绝不抛。"""
    global _PROVIDERS_CACHE
    if _PROVIDERS_CACHE is not None:
        return _PROVIDERS_CACHE
    data: Any = None
    try:
        from apkscan.core.registry import load_rules

        data = load_rules("providers")
    except Exception:
        logger.debug("[attribution] providers.yaml 加载失败，用内置兜底", exc_info=True)
    # load_rules 对缺失文件返回 {}（非 None）——故须查关键字段：无 network_categories 即视为未提供、用兜底。
    _PROVIDERS_CACHE = data if (isinstance(data, dict) and data.get("network_categories")) else _FALLBACK_PROVIDERS
    return _PROVIDERS_CACHE


#: 内置兜底（规则缺失时最小可用）：五大云 + 主流 CDN/电信的 org 关键字。
_FALLBACK_PROVIDERS: dict[str, Any] = {
    "network_categories": {
        CAT_CLOUD: {
            "org_keywords": [
                "tencent", "qcloud", "腾讯", "alibaba", "aliyun", "阿里", "huawei cloud",
                "huaweicloud", "华为云", "volcengine", "火山引擎", "ucloud", "amazon", "aws",
                "google cloud", "microsoft azure", "azure", "baidu", "百度智能云",
            ]
        },
        CAT_CDN: {"org_keywords": ["cloudflare", "akamai", "fastly", "cloudfront", "edgeone", "stackpath"]},
        CAT_TELECOM: {
            "org_keywords": [
                "chinanet", "china telecom", "中国电信", "china unicom", "中国联通",
                "china mobile", "中国移动", "cnc group", "chinatelecom",
            ]
        },
    },
    "edge_providers": [],
    "scoring": _EDGE_THRESHOLDS,
}


def _s(value: Any) -> str:
    """任意值 → 去空白小写字符串（None/非串 → ""）。用于关键字匹配，绝不抛。"""
    if value is None:
        return ""
    try:
        return str(value).strip().lower()
    except Exception:
        return ""


def classify_network(org: str | None, asn: str | None = None) -> str:
    """按 org/ASN 名称关键字判网络类型（cloud/cdn/telecom/idc/security_proxy/...）。命不中 → unknown。绝不抛。"""
    blob = f"{_s(org)} {_s(asn)}"
    if not blob.strip():
        return CAT_UNKNOWN
    cats = _providers_rules().get("network_categories")
    if not isinstance(cats, dict):
        return CAT_UNKNOWN
    for category, spec in cats.items():
        if not isinstance(spec, dict):
            continue
        for kw in spec.get("org_keywords") or []:
            if _s(kw) and _s(kw) in blob:
                return str(category)
    return CAT_UNKNOWN


def _layer(**kw: Any) -> dict[str, Any]:
    """构造一层（统一带 confidence，缺则 unknown）。"""
    kw.setdefault("confidence", CONF_UNKNOWN)
    return kw


def _resource_holder(rdap: dict[str, Any] | None) -> dict[str, Any]:
    """第 1 层：IP 资源登记方（RDAP/WHOIS 的 netname/org/descr）。★输出叫 resource_holder，不叫 website_owner。"""
    if not isinstance(rdap, dict):
        return _layer(name=None, source=None)
    name = rdap.get("netname") or rdap.get("org") or rdap.get("organization") or rdap.get("descr")
    return _layer(
        name=_s(name).upper() if name else None,
        source=rdap.get("source") or "RDAP/WHOIS",
        confidence=CONF_HIGH if name else CONF_UNKNOWN,  # 登记方最可靠（但粒度粗、不等于运营者）
    )


def _origin_network(asn_info: dict[str, Any] | None) -> dict[str, Any]:
    """第 2 层：BGP Origin ASN + 组织。``asn`` 形如 'AS12345 Some Org' 或 {asn, org}。"""
    if not isinstance(asn_info, dict):
        return _layer(asn=None, organization=None, category=CAT_UNKNOWN)
    raw_as = asn_info.get("asn") or asn_info.get("as")
    org = asn_info.get("org") or asn_info.get("organization") or asn_info.get("isp")
    asn_num = None
    if raw_as is not None:
        m = re.search(r"(?:AS)?\s*(\d+)", str(raw_as), re.IGNORECASE)  # 'AS12345' / 'as12345' / 裸 '12345'
        if m:
            asn_num = int(m.group(1))
        if not org:  # 'AS12345 Org Name' → 取号后的组织名
            org = re.sub(r"^\s*(?:AS)?\s*\d+\s*", "", str(raw_as), flags=re.IGNORECASE).strip() or None
    return _layer(
        asn=asn_num,
        organization=str(org) if org else None,
        category=classify_network(org, str(raw_as) if raw_as else None),
        confidence=CONF_HIGH if asn_num is not None else CONF_UNKNOWN,
    )


def _hosting_provider(origin: dict[str, Any], ptr: str | None) -> dict[str, Any]:
    """第 3 层：云厂商/IDC。综合 Origin ASN 分类 + org 名 + PTR。★role 反映网络类型，name 不写成"网站所有者"。"""
    category = origin.get("category", CAT_UNKNOWN)
    org = origin.get("organization")
    if category in (CAT_CLOUD, CAT_IDC, CAT_CDN, CAT_HOSTING_RESELLER, CAT_SECURITY_PROXY):
        # 云/IDC 类：hosting 就是该 org；置信度中（ASN org 可靠，但具体租户/机房未定）。
        role = {CAT_CLOUD: "cloud_host", CAT_IDC: "idc_host", CAT_CDN: "cdn",
                CAT_SECURITY_PROXY: "security_proxy", CAT_HOSTING_RESELLER: "hosting_reseller"}.get(category, "host")
        matched = ["origin_asn_category"]
        if ptr:
            matched.append("ptr")
        return _layer(name=org, role=role, category=category, matched_signals=matched, confidence=CONF_MEDIUM)
    return _layer(name=None, role=None, category=category, matched_signals=[], confidence=CONF_UNKNOWN)


def score_edge_provider(observed: dict[str, Any], *, rules: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """第 4 层引擎：多信号加权识别 CDN/WAF/防红代理。达阈值 → edge dict；不达/无匹配 → None（未识别，非"无代理"）。

    ``observed``（从 PCAP/tshark/证书/DNS 被动抽的信号，扁平）常见键：``cname_chain``[list] / ``nameservers``[list]
    / ``response_headers``{name→value} / ``cookies``[list of name] / ``body_sha256`` / ``favicon_mmh3`` /
    ``tls_spki`` / ``tls_ja4s`` / ``asn``(int) / ``ip`` / ``origin_category`` / ``x_cache_only``(bool) / ``server_nginx_only``(bool)。
    对 rules['edge_providers'] 每条累加命中权重，取最高分者；★confirmed 另要求 **≥2 个不同强信号**（单一强信号最多
    probable——防单条被配置/伪造的头就坐实）；负证据（公共云 only / 通用 X-Cache / nginx）扣分。规则的 FingerprintHub
    风格嵌套 schema：``signals.dns.{cname_suffix,ns_suffix}`` / ``signals.http.{headers,cookies,body_hashes,favicon}`` /
    ``signals.tls.{spki_sha256,ja4s}`` / ``signals.network.{asns,cidrs}`` + ``negative_signals[]`` + ``provenance{}``。
    """
    rules = rules if rules is not None else _providers_rules()
    edges = rules.get("edge_providers")
    if not isinstance(edges, list) or not edges:
        return None
    w_over = rules.get("weights")
    weights: dict[str, float] = {**_EDGE_WEIGHTS, **(w_over if isinstance(w_over, dict) else {})}
    s_over = rules.get("scoring")
    thresholds = {**_EDGE_THRESHOLDS, **(s_over if isinstance(s_over, dict) else {})}

    best: dict[str, Any] | None = None
    for prov in edges:
        if not isinstance(prov, dict):
            continue
        score, strong, matched, weak = _score_one_edge(prov, observed, weights)
        if score <= 0:
            continue
        if best is None or score > best["_score"]:
            best = {
                "name": prov.get("name") or prov.get("id"),
                "id": prov.get("id"),
                "role": prov.get("role") or "reverse_proxy",
                "category": prov.get("category") or CAT_SECURITY_PROXY,
                "_score": score, "_strong": strong,
                "matched_signals": matched, "weak_signals": weak,
                "provenance": prov.get("provenance") if isinstance(prov.get("provenance"), dict) else None,
            }
    if best is None:
        return None
    tier = _edge_tier(best["_score"], len(best["_strong"]), thresholds)
    if tier is None:
        return None
    best["confidence"] = _EDGE_CONF[tier]
    best["tier"] = tier
    best["score"] = round(best.pop("_score"), 1)
    best.pop("_strong", None)
    return best


def _edge_tier(score: float, strong_count: int, thresholds: dict[str, float]) -> str | None:
    """由分数 + 独立强信号数定档：confirmed 须 score≥阈值 **且** ≥2 个不同强信号；否则按分 probable/possible。"""
    if score >= thresholds["confirmed"] and strong_count >= 2:
        return "confirmed"
    if score >= thresholds["probable"]:
        return "probable"
    if score >= thresholds["possible"]:
        return "possible"
    return None


def _entries(sig: dict[str, Any], *path: str) -> list[tuple[str, Any, dict]]:
    """从嵌套规则 signals 取某类条目 → [(value, weight|None, raw_entry)]。缺/坏 → []。绝不抛。"""
    cur: Any = sig
    for k in path:
        cur = cur.get(k) if isinstance(cur, dict) else None
    out: list[tuple[str, Any, dict]] = []
    if isinstance(cur, list):
        for it in cur:
            if isinstance(it, dict):
                out.append((_s(it.get("value") or it.get("name")), it.get("weight"), it))
            else:
                out.append((_s(it), None, {}))
    return out


def _score_one_edge(
    prov: dict[str, Any], obs: dict[str, Any], weights: dict[str, float]
) -> tuple[float, set[str], list[str], list[str]]:
    """对单个 edge_provider 规则累加命中权重 → (score, strong_kinds, matched_signals, weak_signals)。绝不抛。"""
    score = 0.0
    strong: set[str] = set()
    matched: list[str] = []
    weak: list[str] = []
    sig_raw = prov.get("signals")
    sig: dict[str, Any] = sig_raw if isinstance(sig_raw, dict) else {}

    def _add(kind: str, weight_key: str, label: str, entry_w: Any, *, strong_kind: bool) -> None:
        w = float(entry_w) if isinstance(entry_w, (int, float)) else weights.get(weight_key, 0)
        score_add[0] = score_add[0] + w
        matched.append(label)
        if strong_kind:
            strong.add(kind)

    score_add = [score]  # 闭包可变累加器

    # 强信号 —— DNS 专属 CNAME 后缀 / NS 后缀。
    cname_blob = " ".join(_s(c) for c in (obs.get("cname_chain") or []))
    for val, w, _e in _entries(sig, "dns", "cname_suffix"):
        if val and val in cname_blob:
            _add("cname_suffix", "cname_suffix", f"cname_suffix:{val}", w, strong_kind=True)
            break
    ns_blob = " ".join(_s(n) for n in (obs.get("nameservers") or []))
    for val, w, _e in _entries(sig, "dns", "ns_suffix"):
        if val and val in ns_blob:
            _add("nameserver", "nameserver", f"nameserver:{val}", w, strong_kind=True)
            break
    # 强信号 —— HTTP 响应头（可带 regex）/ Cookie / body 哈希 / favicon mmh3。
    hdr_raw = obs.get("response_headers")
    headers = {_s(k): _s(v) for k, v in (hdr_raw.items() if isinstance(hdr_raw, dict) else [])}
    for val, w, e in _entries(sig, "http", "headers"):
        if val and val in headers:
            rx = e.get("regex")
            try:
                if rx and not re.search(str(rx), headers[val]):
                    continue
            except re.error:
                continue
            _add("response_header", "response_header", f"response_header:{val}", w, strong_kind=True)
    # 观测 cookie 归一到**名**（剥 =value / 属性），与规则的 cookie 名精确比。
    obs_cookies = {_s(c).split("=", 1)[0].strip() for c in (obs.get("cookies") or [])}
    for val, w, _e in _entries(sig, "http", "cookies"):
        if val and val in obs_cookies:
            _add("cookie", "cookie", f"cookie:{val}", w, strong_kind=True)
    for val, w, e in _entries(sig, "http", "body_hashes"):
        if val and val == _s(obs.get("body_sha256")):
            _add("error_page_hash", "error_page_hash", f"body_hash:{e.get('page_type') or 'page'}", w, strong_kind=True)
            break
    fav = _s(obs.get("favicon_mmh3"))
    for val, w, _e in _entries(sig, "http", "favicon", "mmh3"):
        if val and val == fav:
            _add("error_page_hash", "error_page_hash", "favicon_mmh3", w, strong_kind=True)
            break
    # 中信号 —— TLS SPKI / JA4S。
    for path_, key in ((("tls", "spki_sha256"), "tls_spki"), (("tls", "ja4s"), "tls_ja4s")):
        for val, w, _e in _entries(sig, *path_):
            if val and val == _s(obs.get(key)):
                _add("tls", "tls_fingerprint", f"tls:{path_[1]}", w, strong_kind=False)
                break
    # 弱信号 —— ASN / CIDR。
    asn_obs = obs.get("asn")
    if asn_obs is not None:
        for val, w, _e in _entries(sig, "network", "asns"):
            try:
                if int(val) == int(asn_obs):
                    _add("asn", "asn", f"asn:{asn_obs}", w, strong_kind=False)
                    weak.append(f"asn:{asn_obs}")
                    break
            except (ValueError, TypeError):
                continue

    # 负证据（防"租了公有云/通用 nginx"当代理坐实）。
    for neg in prov.get("negative_signals") or []:
        if not isinstance(neg, dict):
            continue
        ntype = _s(neg.get("type"))
        fired = (
            (ntype == "public_cloud_only" and obs.get("origin_category") in _SHARED_INFRA_CATEGORIES and not strong)
            or (ntype == "x_cache_only" and obs.get("x_cache_only"))
            or (ntype == "nginx_only" and obs.get("server_nginx_only"))
        )
        if fired:
            nw = neg.get("weight")
            score_add[0] += float(nw) if isinstance(nw, (int, float)) else _EDGE_NEG_WEIGHTS.get(ntype, 0)
            weak.append(f"neg:{ntype}")
    return score_add[0], strong, matched, weak


def build_ip_attribution(ip: str, signals: dict[str, Any]) -> dict[str, Any]:
    """把一个 IP 的多源信号组装成五层归因（不塌缩）。``signals`` 见各层 + score_edge_provider。绝不抛。

    ``signals`` 常见键：``country`` / ``rdap``(dict) / ``asn``(dict 或含 isp/org/as) / ``ptr`` /
    以及 edge 用的 ``cname_chain`` / ``response_headers`` / ``tls_*`` / ``error_page_sha256`` 等。
    """
    if not isinstance(signals, dict):
        signals = {}
    origin = _origin_network(signals.get("asn") if isinstance(signals.get("asn"), dict) else signals)
    edge_signals = {**signals, "origin_category": origin.get("category"),
                    "asn": origin.get("asn") if origin.get("asn") is not None else signals.get("asn")}
    edge = score_edge_provider(edge_signals)
    return {
        "ip": ip,
        "country": _s(signals.get("country")).upper() or None,
        "resource_holder": _resource_holder(signals.get("rdap")),
        "origin_network": origin,
        "hosting_provider": _hosting_provider(origin, signals.get("ptr")),
        "edge_provider": edge if edge is not None else _layer(name=None, role=None, matched_signals=[]),
        # ★第 5 层：实际站点运营者——绝不从 ASN/RDAP 推断（那只是基础设施持有方，不是运营者）。
        "service_operator": _layer(name=None),
    }


def attribution_from_enrichment(enrichment: dict[str, Any], ip: str = "") -> dict[str, Any] | None:
    """把端点既有扁平 ``enrichment``（asn/webcheck 等子键）映射到五层归因。无可用 IP 归属信号 → None。绝不抛。

    映射（诚实、不塞满）：``asn`` 子键 {asn,org,isp,country} → origin_network + hosting_provider；
    ``webcheck`` 子键的响应头/CNAME → edge_provider。★resource_holder 暂留 unknown——现有 asn 走 ip-api（ISP，
    非 RDAP 登记方），不冒充权威登记方；接入 IP RDAP 富化器后再填（slice-1b）。origin/hosting 已比扁平"org"精确。
    """
    if not isinstance(enrichment, dict):
        return None
    asn_e = enrichment.get("asn")
    asn_e = asn_e if isinstance(asn_e, dict) else {}
    wc = enrichment.get("webcheck")
    wc = wc if isinstance(wc, dict) else {}
    if not asn_e and not wc:
        return None
    signals: dict[str, Any] = {
        "country": asn_e.get("country"),
        "asn": {"asn": asn_e.get("asn"), "org": asn_e.get("org") or asn_e.get("isp")},
    }
    headers = wc.get("response_headers") or wc.get("headers")
    if isinstance(headers, dict):
        signals["response_headers"] = headers
    cname = wc.get("cname") or wc.get("cnames") or wc.get("cname_chain")
    if isinstance(cname, list):
        signals["cname_chain"] = cname
    return build_ip_attribution(ip, signals)
