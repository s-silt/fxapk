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

import ipaddress
import logging
import math
import re
from typing import Any

from apkscan.network.categories import (  # 网络类别规范取值（与角色层同一份）
    CAT_CDN,
    CAT_CLOUD,
    CAT_HOSTING_RESELLER,
    CAT_IDC,
    CAT_SECURITY_PROXY,
    CAT_TELECOM,
    CAT_UNKNOWN,
)
from apkscan.network.fingerprints import parse_asn as _parse_asn  # 共享 ASN 解析契约（与角色层同一份）

logger = logging.getLogger(__name__)

# 置信度档。
CONF_HIGH = "high"
CONF_MEDIUM = "medium"
CONF_LOW = "low"
CONF_UNKNOWN = "unknown"

# 网络类型分类（origin_network / hosting_provider 用）——规范取值 import 自 network.categories（与角色层同一份）。
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
#: 负证据（公共基础设施特征——防止把"租了公有云/通用 nginx"当"代理商坐实"）。★仅列**已实现、会自动生效**的三类
#: （见 _negative_adjustment，对最佳候选全局评估、不依赖 provider 配 negative_signals）；不声明未接线的能力。
_EDGE_NEG_WEIGHTS = {
    "public_cloud_only": -2,   # 命中公共云/IDC 类别但无任何强信号（只是租户共用基础设施）
    "x_cache_only": -2,        # 只命中通用 X-Cache（多家 CDN 共用，非专属）
    "nginx_only": -3,          # 只命中 Server: nginx（通用中间件，无辨识力）
}
#: edge 判定阈值（rules 的 scoring 可覆盖）。confirmed 另要求 ≥2 独立强信号（见 _edge_tier）。
_EDGE_THRESHOLDS = {"confirmed": 10, "probable": 6, "possible": 3}
_EDGE_CONF = {"confirmed": CONF_HIGH, "probable": CONF_MEDIUM, "possible": CONF_LOW, "clustered": CONF_HIGH}
#: 档位优先级（选最佳候选时先比 tier 再比分——防高原始分但低档候选压过高档候选）。
_TIER_RANK = {"confirmed": 3, "probable": 2, "possible": 1, "clustered": 2}
#: 强信号种类（confirmed 需 ≥2 个不同强信号命中——单一强信号最多 probable）。
_STRONG_SIGNAL_KINDS = frozenset({"cname_suffix", "response_header", "error_page_hash", "nameserver", "cookie"})

_PROVIDERS_CACHE: dict[str, Any] | None = None


def _providers_rules() -> dict[str, Any]:
    """加载 provider 归属规则：主 rules/providers.yaml + 分目录 rules/providers/{cloud,idc,cdn,waf,carrier}.yaml
    合并（B1 国内专库）。缺失/异常 → 内置兜底。绝不抛。"""
    global _PROVIDERS_CACHE
    if _PROVIDERS_CACHE is not None:
        return _PROVIDERS_CACHE
    merged: dict[str, Any] = {}
    try:
        from apkscan.core.registry import load_rules, load_rules_dir

        base = load_rules("providers")
        # 分目录（cloud/idc/cdn/waf/carrier）+ fxapk 自有共享前置/分发指纹（investigative，在线库认不出的国内防红类前端）。
        parts = load_rules_dir("providers") + load_rules_dir("providers/investigative")
        merged = _merge_provider_rules(base if isinstance(base, dict) else {}, parts)
    except Exception:
        logger.debug("[attribution] providers 规则加载失败，用内置兜底", exc_info=True)
    # 合并后无 network_categories（主文件缺失 + 分目录空）→ 内置兜底（五大云/CDN/电信关键字最小可用）。
    _PROVIDERS_CACHE = merged if merged.get("network_categories") else _FALLBACK_PROVIDERS
    return _PROVIDERS_CACHE


def _merge_provider_rules(base: dict[str, Any], parts: list[dict[str, Any]]) -> dict[str, Any]:
    """合并主 providers.yaml 与分目录各文件（B1）：network_categories 按类别并 org_keywords（去重保序）、
    edge_providers 按 id 去重拼接（先出现者优先、主文件在前）、scoring/weights/negative_weights 以主文件为准。绝不抛。"""
    cats: dict[str, dict[str, list[Any]]] = {}
    edge_by_id: dict[str, dict[str, Any]] = {}
    edge_order: list[str] = []
    for src in [base, *parts]:
        if not isinstance(src, dict):
            continue
        nc = src.get("network_categories")
        if isinstance(nc, dict):
            for cat, body in nc.items():
                kws = body.get("org_keywords") if isinstance(body, dict) else None
                if not isinstance(kws, list):
                    continue
                bucket = cats.setdefault(str(cat), {"org_keywords": []})["org_keywords"]
                for kw in kws:
                    if kw not in bucket:
                        bucket.append(kw)
        eps = src.get("edge_providers")
        if isinstance(eps, list):
            for ep in eps:
                if isinstance(ep, dict) and ep.get("id") and ep["id"] not in edge_by_id:
                    edge_by_id[str(ep["id"])] = ep
                    edge_order.append(str(ep["id"]))
    merged: dict[str, Any] = {
        "network_categories": cats,
        "edge_providers": [edge_by_id[i] for i in edge_order],
    }
    for key in ("scoring", "weights", "negative_weights"):
        if isinstance(base.get(key), dict):
            merged[key] = base[key]
    # 分目录文件里的 scoring/weights/negative_weights 被忽略（只认主文件）——静默失效易踩坑，记一条 debug。
    for part in parts:
        if isinstance(part, dict) and any(k in part for k in ("scoring", "weights", "negative_weights")):
            logger.debug("[attribution] 分目录 provider 文件的 scoring/weights 被忽略（仅主 providers.yaml 生效）")
            break
    return merged


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


def _as_list(value: Any) -> list[Any]:
    """任意值 → list（list/tuple/set 原样成列，其余 → []）。防对整数/字符串等误迭代抛异常。"""
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return []


def _num(value: Any, default: float) -> float:
    """任意值 → **有限** float（bool/None/非数/超大整数/inf/nan → default）。清洗外部 weights/thresholds，绝不抛、不泄漏非有限分。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        f = float(value)   # 超大 int（如 10**10000）→ OverflowError
    except (OverflowError, ValueError):
        return default
    return f if math.isfinite(f) else default   # inf/nan → default，防非有限分泄漏进证据链


def _host_hits_suffix(hosts: list[Any], suffix_val: str) -> bool:
    """★标签级后缀匹配（防子串误判 + 拒空标签）：host 的**尾部标签序列**须完全等于规则根的标签序列。

    ``suffix_val`` 形如 '.cdn.cloudflare.net'（前导点可有可无）。'x.cdn.cloudflare.net' 命中；伪造的
    'x.cdn.cloudflare.net.attacker.example'（根在中间）不命中；畸形空标签 'x..cloudflare.net' 也不命中。
    """
    root_labels = _s(suffix_val).strip(".").split(".")
    if not root_labels or any(not lbl for lbl in root_labels):  # 规则后缀空/含空标签 → 无效
        return False
    n = len(root_labels)
    for h in hosts:
        labels = _s(h).strip(".").split(".")
        if any(not lbl for lbl in labels):   # 观测 host 含空标签（畸形）→ 跳过，不蒙混命中
            continue
        if len(labels) >= n and labels[-n:] == root_labels:
            return True
    return False


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
    """构造一层（统一带 confidence + source，缺则 unknown/None）。★invariant：每层都有 source，未知即 None。"""
    kw.setdefault("confidence", CONF_UNKNOWN)
    kw.setdefault("source", None)
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


#: 合法可路由 ASN 范围。0（RFC 7607）与 4294967295=0xFFFFFFFF（RFC 7300 保留）均排除；落域外/畸形 → unknown。
def _origin_network(asn_info: dict[str, Any] | None) -> dict[str, Any]:
    """第 2 层：BGP Origin ASN + 组织。``asn`` 形如 'AS12345 Some Org' / 12345 / {asn, org}。畸形 ASN → unknown。"""
    if not isinstance(asn_info, dict):
        return _layer(asn=None, organization=None, category=CAT_UNKNOWN)
    raw_as = asn_info.get("asn") or asn_info.get("as")
    asn_num, org_tail = _parse_asn(raw_as)
    org = asn_info.get("org") or asn_info.get("organization") or asn_info.get("isp") or org_tail
    # ★仅在 ASN 解析成功时才把原始串喂给分类器——畸形串（如 '-123 Tencent'）不得反向驱动网络类别。
    asn_hint = str(raw_as) if asn_num is not None else None
    return _layer(
        asn=asn_num,
        organization=str(org) if org else None,
        category=classify_network(org, asn_hint),
        confidence=CONF_HIGH if asn_num is not None else CONF_UNKNOWN,
        source="BGP/ASN" if asn_num is not None else None,
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
        return _layer(name=org, role=role, category=category, matched_signals=matched,
                      confidence=CONF_MEDIUM, source="origin_asn_category")
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
    observed = observed if isinstance(observed, dict) else {}   # ★绝不抛：坏 observed → 空信号
    if rules is None:
        rules = _providers_rules()
    if not isinstance(rules, dict):                             # ★绝不抛：坏 rules → 未识别
        return None
    edges = rules.get("edge_providers")
    if not isinstance(edges, list) or not edges:
        return None
    # 清洗权重/阈值/负权重：外部规则可能给 None/非数/字符串，逐键 _num 兜默认，防相加/比较时抛异常。
    w_raw = rules.get("weights")
    w_over = w_raw if isinstance(w_raw, dict) else {}
    weights = {k: _num(w_over.get(k), v) for k, v in _EDGE_WEIGHTS.items()}
    s_raw = rules.get("scoring")
    s_over = s_raw if isinstance(s_raw, dict) else {}
    thresholds = {k: _num(s_over.get(k), v) for k, v in _EDGE_THRESHOLDS.items()}
    n_raw = rules.get("negative_weights")
    n_over = n_raw if isinstance(n_raw, dict) else {}
    neg_weights = {k: _num(n_over.get(k), v) for k, v in _EDGE_NEG_WEIGHTS.items()}

    # ★每个候选**先扣负证据、再定档**，最后按 (tier 优先级, 最终分) 排序——避免"原始分更高但只到 probable
    # 的弱候选"压过"分数略低却有 ≥2 强信号、应 confirmed 的候选"（负证据在选定后才扣会漏这个重排）。
    best: dict[str, Any] | None = None
    best_key: tuple[int, float] | None = None
    for prov in edges:
        if not isinstance(prov, dict):
            continue
        score, strong, matched, weak = _score_one_edge(prov, observed, weights)
        if score <= 0:
            continue
        neg_adj, neg_fired = _negative_adjustment(observed, strong, neg_weights)
        final = score + neg_adj
        if not math.isfinite(final):   # ★分数有限总闸：坏规则权重累加成 inf/-inf/nan → 候选作废，不泄漏非有限分
            continue
        tier = _edge_tier(final, len(strong), thresholds)
        if tier is None:
            continue
        key = (_TIER_RANK[tier], final)
        if best_key is None or key > best_key:
            best_key = key
            best = {
                "name": prov.get("name") or prov.get("id"),
                "id": prov.get("id"),
                "role": prov.get("role") or "reverse_proxy",
                "category": prov.get("category") or CAT_SECURITY_PROXY,
                "source": prov.get("id") or "edge_fingerprint",
                "provenance": prov.get("provenance") if isinstance(prov.get("provenance"), dict) else None,
                "matched_signals": matched,
                "weak_signals": list(weak) + neg_fired,
                "confidence": _EDGE_CONF[tier],
                "tier": tier,
                "score": round(final, 1),
            }
    return best


def _negative_adjustment(
    observed: dict[str, Any], strong: set[str], neg_weights: dict[str, float]
) -> tuple[float, list[str]]:
    """全局负证据：对最佳候选评估三类公共基础设施特征，返回 (扣分, 触发标签)。绝不抛。

    - public_cloud_only：origin 在云/CDN/IDC 类别却**无任何强信号**（只是共用租户，别当代理坐实）。
    - x_cache_only / nginx_only：只命中多家共用的通用 X-Cache / Server:nginx（无专属辨识力）。
    """
    adj, fired = 0.0, []
    if not strong and observed.get("origin_category") in _SHARED_INFRA_CATEGORIES:
        adj += neg_weights["public_cloud_only"]
        fired.append("neg:public_cloud_only")
    if observed.get("x_cache_only"):
        adj += neg_weights["x_cache_only"]
        fired.append("neg:x_cache_only")
    if observed.get("server_nginx_only"):
        adj += neg_weights["nginx_only"]
        fired.append("neg:nginx_only")
    return adj, fired


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


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """被观测 IP 是否落在规则 CIDR 内（供 network.cidrs / ip_pool 弱信号匹配）。坏 IP/CIDR → False，绝不抛。"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


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
        w = _num(entry_w, weights.get(weight_key, 0.0))  # 条目权重非数（含外部规则脏值）→ 兜该类默认，绝不抛
        score_add[0] = score_add[0] + w
        matched.append(label)
        if strong_kind:
            strong.add(kind)

    score_add = [score]  # 闭包可变累加器

    # 强信号 —— DNS 专属 CNAME 后缀 / NS 后缀。★标签边界匹配（_host_hits_suffix）防伪造域名把根塞进中间蒙混。
    cname_hosts = _as_list(obs.get("cname_chain"))
    for val, w, _e in _entries(sig, "dns", "cname_suffix"):
        if val and _host_hits_suffix(cname_hosts, val):
            _add("cname_suffix", "cname_suffix", f"cname_suffix:{val}", w, strong_kind=True)
            break
    ns_hosts = _as_list(obs.get("nameservers"))
    for val, w, _e in _entries(sig, "dns", "ns_suffix"):
        if val and _host_hits_suffix(ns_hosts, val):
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
    obs_cookies = {_s(c).split("=", 1)[0].strip() for c in _as_list(obs.get("cookies"))}
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
    # 弱信号 —— ASN。★观测与规则两侧**都过 _parse_asn**（统一纪律：非整数 float/保留值/越界/超长数字串一律不采纳，
    # 且 _parse_asn 绝不抛）——避免手写 int() 在 13335.9 被截断、或 '9'*10000 抛 ValueError。
    obs_asn, _ = _parse_asn(obs.get("asn"))
    if obs_asn is not None:
        for val, w, _e in _entries(sig, "network", "asns"):
            rule_asn, _ = _parse_asn(val)
            if rule_asn is not None and rule_asn == obs_asn:
                _add("asn", "asn", f"asn:{obs_asn}", w, strong_kind=False)
                weak.append(f"asn:{obs_asn}")
                break
    # 弱信号 —— IP 池 / 专属 CIDR。观测 IP 落在规则 network.cidrs 内 → ip_pool（弱信号：IP 段常运营商/云共享、仅佐证）。
    obs_ip = _s(obs.get("ip"))
    if obs_ip:
        for val, w, _e in _entries(sig, "network", "cidrs"):
            if val and _ip_in_cidr(obs_ip, val):
                _add("ip_pool", "ip_pool", f"ip_pool:{val}", w, strong_kind=False)
                weak.append(f"ip_pool:{val}")
                break

    # 负证据不在此处按 provider 评估——统一在 score_edge_provider 对最佳候选全局评估（见 _negative_adjustment）。
    return score_add[0], strong, matched, weak


#: 高区分度「前置指纹」观测键 → 标签前缀。TLS SPKI / JA4S / 默认页 body 哈希 / favicon mmh3 都是天然唯一
#: 的服务端指纹——即便 score_edge_provider 认不出是哪家 CDN/防红，跨端点共享同一枚即证同一（未命名）前置。
#: 仅取哈希/指纹类（不取可通用的 header/cookie/asn/cidr，那些多家共用、单独不足以证同一前置）。
_FRONTING_SIGNAL_KEYS: tuple[tuple[str, str], ...] = (
    ("tls_spki", "spki"),
    ("tls_ja4s", "ja4s"),
    ("body_sha256", "body_hash"),
    ("favicon_mmh3", "favicon"),
)


def _fronting_fingerprint(observed: dict[str, Any]) -> list[str]:
    """从观测信号抽高区分度前置指纹（见 _FRONTING_SIGNAL_KEYS），排序去重。缺/坏 → []。绝不抛。"""
    if not isinstance(observed, dict):
        return []
    fp = [f"{prefix}:{v}" for key, prefix in _FRONTING_SIGNAL_KEYS if (v := _s(observed.get(key)))]
    return sorted(set(fp))


def _fronting_candidate(observed: dict[str, Any]) -> dict[str, Any]:
    """edge 认不出名时的兜底：有高区分度前置指纹 → clustered 候选（保留证据，cluster_id 待
    cluster_fronting 跨端点编号）；无 → 空 edge 层。★解决「有信号叫不出名」与「无信号」不可区分。"""
    fp = _fronting_fingerprint(observed)
    if not fp:
        return _layer(name=None, role=None, matched_signals=[])
    return _layer(name=None, id=None, role="reverse_proxy", category=CAT_SECURITY_PROXY,
                  source="fronting_fingerprint", matched_signals=fp, weak_signals=[],
                  tier="clustered", cluster_id=None, confidence=CONF_LOW)


def build_ip_attribution(ip: str, signals: dict[str, Any]) -> dict[str, Any]:
    """把一个 IP 的多源信号组装成五层归因（不塌缩）。``signals`` 见各层 + score_edge_provider。绝不抛。

    ``signals`` 常见键：``country`` / ``rdap``(dict) / ``asn``(dict 或含 isp/org/as) / ``ptr`` /
    以及 edge 用的 ``cname_chain`` / ``response_headers`` / ``tls_*`` / ``error_page_sha256`` 等。
    """
    if not isinstance(signals, dict):
        signals = {}
    origin = _origin_network(signals.get("asn") if isinstance(signals.get("asn"), dict) else signals)
    # ★被观测 IP 用入参 ip（权威）注入 edge 信号——否则 score_edge_provider 的 network.cidrs / ip_pool
    # 弱信号在生产路径（IP 端点、域名 per-IP、直接调用都经此）永远拿不到 obs.ip、静默漏 CIDR 命中。
    edge_signals = {**signals, "ip": ip, "origin_category": origin.get("category"),
                    "asn": origin.get("asn") if origin.get("asn") is not None else signals.get("asn")}
    edge = score_edge_provider(edge_signals)
    return {
        "ip": ip,
        "country": _s(signals.get("country")).upper() or None,
        "resource_holder": _resource_holder(signals.get("rdap")),
        "origin_network": origin,
        "hosting_provider": _hosting_provider(origin, signals.get("ptr")),
        # 命名 edge → 用之；认不出名但有前置指纹 → clustered 候选保留证据；都没有 → 空 edge 层。
        "edge_provider": edge if edge is not None else _fronting_candidate(edge_signals),
        # ★第 5 层：实际站点运营者——绝不从 ASN/RDAP 推断（那只是基础设施持有方，不是运营者）。
        "service_operator": _layer(name=None),
    }


def cluster_fronting(ip_views: list[dict[str, Any]]) -> int:
    """跨端点把**认不出名但带同一高区分度前置指纹**的 IP 归因聚成 ``fronting-cluster-NNNN``（成员≥2）。

    只作用于 ``edge_provider.tier=='clustered'`` 且未编号（``cluster_id is None``）的候选——即
    build_ip_attribution 对 score_edge_provider 认不出、但存在前置指纹的 IP 产的标记。按共享指纹用并查集
    连边，连通分量成员≥2 者编号 ``fronting-cluster-NNNN``（从 1、确定性），就地写回各成员 edge_provider 的
    ``cluster_id`` / ``name`` / ``confidence`` / ``cluster_shared``。孤点保留证据但不编号。绝不抛，返回簇数。
    命名先例见 dynamic/correlate.py（cluster_id 从 1）；此处是**单份报告内跨端点**视角。
    """
    cand: list[tuple[str, dict[str, Any], frozenset[str]]] = []
    for view in ip_views if isinstance(ip_views, list) else []:
        if not isinstance(view, dict):
            continue
        edge = view.get("edge_provider")
        if not isinstance(edge, dict) or edge.get("tier") != "clustered" or edge.get("cluster_id"):
            continue
        fps = frozenset(s for s in (edge.get("matched_signals") or []) if isinstance(s, str) and s)
        if fps:
            cand.append((_s(view.get("ip")), edge, fps))
    if len(cand) < 2:
        return 0
    cand.sort(key=lambda t: (t[0], sorted(t[2])))          # 确定性：先按 ip、再按指纹排序 → NNNN 稳定

    index: dict[str, list[int]] = {}                        # 倒排：指纹 → [候选下标]
    for i, (_ip, _edge, fps) in enumerate(cand):
        for fp in fps:
            index.setdefault(fp, []).append(i)

    parent = list(range(len(cand)))                         # 并查集（root=分量内最小下标 → 确定性编号）
    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for idxs in index.values():
        for other in idxs[1:]:
            ra, rb = _find(idxs[0]), _find(other)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

    groups: dict[int, list[int]] = {}
    for i in range(len(cand)):
        groups.setdefault(_find(i), []).append(i)

    n = 0
    for root in sorted(groups):
        members = groups[root]
        if len(members) < 2:
            continue                                        # 孤点：指纹已保留在 edge，不编号
        n += 1
        cid = f"fronting-cluster-{n:04d}"
        member_fps = [cand[i][2] for i in members]
        shared = sorted(fp for fp in frozenset().union(*member_fps)
                        if sum(fp in fps for fps in member_fps) >= 2)   # 只列真正共享（≥2 成员）的指纹
        for i in members:
            edge = cand[i][1]
            edge["cluster_id"] = cid
            edge["name"] = cid
            edge["confidence"] = _EDGE_CONF["clustered"]
            edge["cluster_shared"] = shared
    return n


#: case-close 富化源（multisource 被动查询，均 case_close_only）里承载 AS 组织名的子键，按优先级。
_ONLINE_ASORG_SOURCES = ("fofa", "hunter", "quake", "virustotal", "shodan", "ripestat_bgp")
#: 从资产记录里取"网络运营方"的字段——★只取 as_org 类，绝不取 company（Hunter 的 ICP 备案主体=服务运营方，
#: service_operator 恒 unknown，不得从数据推断）。
_ONLINE_ASORG_FIELDS = ("as_organization", "as_org")


def _online_as_org(enrichment: dict[str, Any]) -> str | None:
    """ip-api 未给 org 时，从 case-close 在线源（FOFA/Hunter/Shodan/Quake…）的资产记录回落取 AS 组织名，
    补 origin_network 的网络运营方。只在结案路径（这些源为 case_close_only）有数据；绝不取 company/ICP 主体。"""
    for src in _ONLINE_ASORG_SOURCES:
        node = enrichment.get(src)
        if not isinstance(node, dict):
            continue
        records = node.get("records")
        recs = records if isinstance(records, list) else [node]  # 有的源（如 shodan）字段在顶层
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            for key in _ONLINE_ASORG_FIELDS:
                val = rec.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return None


def attribution_from_enrichment(enrichment: dict[str, Any], ip: str = "") -> dict[str, Any] | None:
    """把端点既有扁平 ``enrichment``（asn/dns/ip_rdap 等子键）映射到五层归因。无可用 IP 归属信号 → None。绝不抛。

    映射（诚实、按各富化器**真实 schema**）：``asn`` 子键 {asn,org,isp,country} → origin_network + hosting_provider；
    ``dns`` 子键的 ``cname``（DnsEnricher 实际输出位置）→ edge 的 CNAME 强信号。响应头信号保留在
    ``signals["response_headers"]`` 契约里（PCAP-first 下响应头来自被动抓包），当前无富化器写入即为空。
    ★resource_holder **仅**由 ``ip_rdap`` 子键（IpRdapEnricher，IP 资源登记方）填——绝不用域名 rdap
    （applies_to=['domain']，域名注册方）或 asn 的 ip-api ISP（网络运营方）冒充 IP 资源持有方。
    """
    if not isinstance(enrichment, dict):
        return None
    asn_e = enrichment.get("asn")
    asn_e = asn_e if isinstance(asn_e, dict) else {}
    dns_e = enrichment.get("dns")
    dns_e = dns_e if isinstance(dns_e, dict) else {}
    ip_rdap = enrichment.get("ip_rdap")
    ip_rdap = ip_rdap if isinstance(ip_rdap, dict) else {}
    tls_e = enrichment.get("tls")
    tls_e = tls_e if isinstance(tls_e, dict) else {}
    # ip-api org/isp 优先；均空时回落 case-close 在线源（FOFA/Hunter/Shodan…）的 as_org 补网络运营方。
    # 提前算并纳入早期返回判据——否则只有 fofa/hunter（无 asn/dns/ip_rdap）时会在提取 as_org 前误返回 None。
    online_org = _online_as_org(enrichment)
    if not asn_e and not dns_e and not ip_rdap and not online_org and not tls_e:
        return None
    signals: dict[str, Any] = {
        "country": asn_e.get("country"),
        "asn": {"asn": asn_e.get("asn"), "org": asn_e.get("org") or asn_e.get("isp") or online_org},
    }
    # ★IP-RDAP（IpRdapEnricher，applies_to=['ip']）是 IP **资源登记方** → resource_holder（第 1 层）。
    # 区别于域名 rdap（注册方）与 asn 的 ISP，故用它、不用那两者冒充 IP 资源持有方。
    if ip_rdap.get("netname") or ip_rdap.get("org"):
        signals["rdap"] = ip_rdap
        if not signals["country"]:
            signals["country"] = ip_rdap.get("country")
    # DnsEnricher 把 CNAME 链写在 enrichment['dns']['cname']（去了末点，便于后缀匹配）——edge 最可靠的强信号。
    cname = dns_e.get("cname")
    if isinstance(cname, list):
        signals["cname_chain"] = cname
    # ★前置指纹接线（B2-b）：TLS SPKI/JA4S（tls 子键）——高区分度服务端指纹，
    # 认不出名的前置靠它跨端点聚 fronting-cluster。当前无生产富化器写入即为空、纯前向兼容（数据源见 C 阶段网络流引擎）。
    for skey, sval in (("tls_spki", tls_e.get("spki_sha256") or tls_e.get("spki")),
                       ("tls_ja4s", tls_e.get("ja4s") or tls_e.get("ja4s_hash")),
                       ):
        if _s(sval):
            signals[skey] = _s(sval)
    # ★有效信号判据（不塞空壳）：子键非空但字段全 None（如 {"asn":{"asn":None}}）时，至少要有一个可解析
    # ASN / 资源登记方 / 国家 / CNAME / 响应头 / 前置指纹，否则五层全 unknown 无归因价值 → 返回 None。
    asn_num, _ = _parse_asn(signals["asn"].get("asn"))
    if not (asn_num is not None or signals.get("rdap") or _s(signals.get("country"))
            or signals.get("cname_chain") or signals.get("response_headers")
            or _fronting_fingerprint(signals)          # 高区分度前置指纹单独也算有效（可聚 fronting-cluster）
            or _s(signals["asn"].get("org"))):  # ★仅在线 as_org（无 asn 数值）也算有效——能把 org 归类定 origin_network
        return None
    return build_ip_attribution(ip, signals)


def build_endpoint_attribution(kind: str, value: str, enrichment: dict[str, Any]) -> dict[str, Any] | None:
    """端点级归因入口（pipeline 用）：把一个端点的 enrichment 映射成 **per-IP** 五层归因。无信号 → None。绝不抛。

    ★不塌缩：域名常解析到多个 IP、各自 ASN/edge 可能不同，故按 IP 逐个产五层（``ips`` 列表），不合并成一份。
    - IP 端点：``enrichment['asn']``（AsnEnricher applies_to=['ip']）→ 单条五层；``enrichment['ip_rdap']``
      （IpRdapEnricher）→ resource_holder。
    - 域名端点：``enrichment['dns']['hosting']``（每解析 IP 一条 {ip,asn,org,isp}）→ 每 IP 一条五层；
      ``dns['cname']`` 是**域名级共享** edge 信号，喂给每个 IP 的 edge 层。hosting 缺时退化用 ``dns['ips']``
      （ASN 未知，但 CNAME 仍可识别 edge）。
    ★域名端点的 per-IP resource_holder 仍 unknown——IP-RDAP 只对 IP 端点跑，域名解析 IP 未单独富化（后续增强）。
    """
    if not isinstance(enrichment, dict):
        return None
    kind_s = _s(kind)
    ips: list[dict[str, Any]] = []

    if kind_s == "ip":
        att = attribution_from_enrichment(enrichment, ip=str(value or ""))
        if att is not None:
            ips.append(att)
    elif kind_s == "domain":
        dns_e = enrichment.get("dns")
        dns_e = dns_e if isinstance(dns_e, dict) else {}
        cname_raw = dns_e.get("cname")
        cname = cname_raw if isinstance(cname_raw, list) else None
        # hosting 建 ip→info 映射（每 IP 的 asn/org/isp）。★hosting **常少于** ips——部分 IP 的托管查询限速/失败
        # 被跳过（见 DnsEnricher._hosting），但 IP 仍留在 dns.ips。故不能只遍历 hosting，否则丢失只在 ips 里的 IP
        # （per-IP 塌缩）。_as_list 兜坏容器（非 list 归空，绝不抛、不逐字符迭代成垃圾）。
        host_by_ip: dict[str, dict[str, Any]] = {}
        for h in _as_list(dns_e.get("hosting")):
            if isinstance(h, dict):
                hk = _s(h.get("ip"))
                if hk:
                    host_by_ip.setdefault(hk, h)
        # 主列表 = dns.ips ∪ hosting 里的 IP（去重保序）——每个解析到的 IP 都产一条五层，一个不丢。
        ordered: list[str] = []
        seen_ip: set[str] = set()
        for ip in list(_as_list(dns_e.get("ips"))) + list(host_by_ip):
            k = _s(ip)
            if k and k not in seen_ip:
                seen_ip.add(k)
                ordered.append(k)
        # case close 会对每个解析 IP 单独富化（ip_rdap 资源登记方 / asn / 在线源 as_org），落在
        # enrichment['resolved_ip_enrichment'][ip]。顶层域名归因吸收它，否则这些证据只留在嵌套结构，
        # 顶层五层的 resource_holder 恒 unknown，文书/摘要（只读顶层 attribution）漏掉闭环后的 RDAP/BGP 证据（P1-3）。
        resolved_all = enrichment.get("resolved_ip_enrichment")
        resolved_all = resolved_all if isinstance(resolved_all, dict) else {}
        for ip in ordered:
            h = host_by_ip.get(ip, {})
            resolved_ip = resolved_all.get(ip)
            if isinstance(resolved_ip, dict):
                merged = dict(resolved_ip)
                # 域名级 CNAME 字段级注入：resolved 无 dns.cname 时补（含 resolved 有 dns dict 但缺 cname 的情形）。
                merged_dns = merged.get("dns")
                if cname and not (isinstance(merged_dns, dict) and merged_dns.get("cname")):
                    merged["dns"] = {**merged_dns, "cname": cname} if isinstance(merged_dns, dict) else {"cname": cname}
                # hosting 兜底按**有效字段**判（非键存在）：resolved 的 asn 缺失或只有 error/note 等控制字段
                # （如富化失败写的 {"error": "..."}）时，用 dns.hosting 的 ASN 补，防 origin/hosting 层退化丢证据。
                merged_asn = merged.get("asn")
                asn_has_value = isinstance(merged_asn, dict) and (
                    merged_asn.get("asn") or merged_asn.get("org") or merged_asn.get("isp")
                )
                if not asn_has_value and (h.get("asn") or h.get("org") or h.get("isp")):
                    merged["asn"] = {
                        "asn": h.get("asn"),
                        "org": h.get("org") or h.get("isp"),
                        "country": h.get("country"),
                    }
                att = attribution_from_enrichment(merged, ip=ip)
                if att is not None:
                    ips.append(att)
                    continue
            signals: dict[str, Any] = {
                "country": h.get("country"),
                "asn": {"asn": h.get("asn"), "org": h.get("org") or h.get("isp")},
            }
            if cname:
                signals["cname_chain"] = cname
            ips.append(build_ip_attribution(ip, signals))

    if not ips:
        return None
    return {"endpoint": str(value or ""), "kind": kind_s or "unknown", "ips": ips}
