"""PR9: assemble ``report.meta["network_attribution"]`` from existing report facts.

A pure, PASSIVE, deterministic assembler that surfaces the PR7 infrastructure
graph + PR3/4/8 role candidates as an additive report view. It reads ONLY facts
already on the ``Report`` (``endpoint.enrichment`` / ``endpoint.evidences``) — no
network, no enricher / ``build_endpoint_attribution`` re-run, no file I/O, and no
import of ``apkscan.core.enrichment`` / intel providers / ``requests`` / ``socket``.

The bridge is a fact-to-signal COMPILER, not an inference engine: every emitted
``AttributionEvidence`` / ``RoleFeature`` is licensed by one already-collected
fact, one fact licenses at most one signal, and a signal with no observed fact
stays absent. A cloud / ASN / CDN membership is a RESOURCE fact — never an
operator/actor claim; ``service_operator`` is never surfaced.

Determinism: fact-only ``stable_digest`` ids (excluding confidence/timestamp),
a CONSTANT confidence per (source, type) with ``timestamp=None`` (so re-runs over
the same report are byte-identical and never trip the same-id/different-payload
guard), and fully sorted output.
"""

from __future__ import annotations

import logging
import math
from types import MappingProxyType
from typing import Any, Sequence

from apkscan.attribution.graph import build_infrastructure_graph
from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    RoleClassifier,
    RoleFeature,
    RoleSignal,
    _ROLE_DEFINITIONS,
)
from apkscan.attribution.scorer import EvidenceScorer
from apkscan.core.models import OBSERVED_CONTACT_SOURCES
from apkscan.network import NetworkEntity, NetworkEntityType
from apkscan.network.categories import CAT_CDN, CAT_CLOUD, CAT_IDC, CAT_TELECOM  # 网络类别规范取值（与五层同一份）
from apkscan.network.fingerprints import (
    is_known_intercept_ip,
    normalize_domain,
    normalize_ip,
    parse_asn,
    stable_digest,
)

logger = logging.getLogger(__name__)

__all__ = ["build_network_attribution"]

_NS = "apkscan.attribution/report-bridge"

_DISCLAIMER = (
    "A cloud / ASN / CDN membership is a resource fact, not an operator claim; "
    "roles are multi-evidence forensic candidates, never accusations."
)

#: CONSTANT confidence per (source, evidence_type) — never context-dependent, so
#: the fact-only id and the to_dict payload stay a pure function of the fact.
_CONFIDENCE: MappingProxyType[tuple[str, str], float] = MappingProxyType(
    {
        ("dns", "resolved_ip"): 0.8,
        ("dns", "dns_alias"): 0.8,
        ("dns", "asn"): 0.6,
        ("asn", "asn"): 0.6,
        ("shodan", "asn"): 0.6,
        ("attribution", "asn"): 0.6,
        ("certs", "related_hostname"): 0.7,
        ("shodan", "related_hostname"): 0.6,
        # runtime-observed edges (PCAP/mitm) — the strongest signal: the app
        # actually spoke to this IP / sent this SNI to this IP at capture time.
        ("runtime", "tls_sni"): 0.95,
        ("runtime", "network_flow"): 0.95,
    }
)
#: CONSTANT confidence per role signal for the (provenance-only) licensing evidence.
_SIGNAL_CONFIDENCE: MappingProxyType[RoleSignal, float] = MappingProxyType(
    {
        RoleSignal.DIRECT_CONNECTION: 0.9,
        RoleSignal.DOMESTIC_NETWORK: 0.7,
        RoleSignal.PUBLIC_CDN: 0.8,
        RoleSignal.NON_PUBLIC_CDN: 0.5,
        # 运行时行为信号（P0）：接触该境内 IP 后随后又连境外——中继候选，correlational（非 relay 铁证）。
        RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION: 0.7,
        # 运行时行为信号（P0-2）：该 IP 被观测服务业务/登录 API 路径——origin_candidate 证据（像真后端源站）。
        RoleSignal.BUSINESS_API: 0.75,
        RoleSignal.LOGIN_ENDPOINT: 0.7,
        # 运行时行为信号（P0-3）：跨 host 重定向 / 挑战 cookie 下发——edge_candidate / cloaking_edge_node 证据。
        RoleSignal.REDIRECT: 0.7,
        RoleSignal.COOKIE_CHALLENGE: 0.75,
    }
)

_CDN_CATEGORIES = frozenset({CAT_CDN})
_NON_PUBLIC_CDN_HOSTING = frozenset({CAT_CLOUD, CAT_IDC})
_CONFIRMED_EDGE_TIERS = frozenset({"confirmed", "probable"})


# --------------------------------------------------------------------------- #
# Small pure helpers                                                          #
# --------------------------------------------------------------------------- #
def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_asn(value: object) -> int | None:
    """角色层只要 ASN 数值——复用共享 ``fingerprints.parse_asn`` 契约（与五层同一份、绝不抛），取其 asn_num。
    ★统一后顺带修旧实现的潜在 bug：旧 ``int(head)`` 对超长数字串会触达 CPython 4300 位限制抛异常。"""
    return parse_asn(value)[0]


def _ip_entity(value: object) -> NetworkEntity | None:
    if not isinstance(value, str):
        return None
    try:
        return NetworkEntity(NetworkEntityType.IP, normalize_ip(value.strip()), ())
    except (ValueError, TypeError):
        return None


def _domain_entity(value: object) -> NetworkEntity | None:
    if not isinstance(value, str):
        return None
    try:
        return NetworkEntity(NetworkEntityType.DOMAIN, normalize_domain(value.strip()), ())
    except (ValueError, TypeError):
        return None


def _evidence(
    *, source: str, etype: str, target: NetworkEntity, value: Any, raw_reference: str,
    confidence: float,
) -> AttributionEvidence:
    """A bridged evidence with a fact-only stable id (confidence/timestamp excluded)."""
    evidence_id = stable_digest(
        _NS,
        {
            "source": source,
            "type": etype,
            "target_type": target.kind.value,
            "target_value": target.value,
            "value": value,
        },
    )
    return AttributionEvidence(
        id=evidence_id, source=source, type=etype, target=target, value=value,
        confidence=confidence, timestamp=None, raw_reference=raw_reference,
    )


#: runtime evidence sub-sources that OBSERVED the actual network peer of an IP endpoint:
#: pcap parses the real TCP/UDP dst_ip; mitm records the actual upstream server IP it
#: connected to. Every OTHER runtime sub-source derives the IP endpoint's value from an
#: HTTP Host / :authority header (``runtime-tshark``), a decrypted request/body
#: (``*-decrypted``), a synthetic / non-runtime* fallback (``runtime-derived``), or a
#: tool-initiated probe — none of which prove the app contacted THAT IP — so they license
#: no observed-contact edge/signal. Allowlist, not denylist: a new content-derived source
#: is excluded by default (the safe direction for the no-over-inference contract).
#: Single source of truth lives in ``core.models.OBSERVED_CONTACT_SOURCES`` so the
#: machine-facing role gate here and the case-officer-facing ``Lead.is_runtime_contact``
#: "confirmed C2" badge stay one口径 (never drift apart).
_OBSERVED_CONTACT_SOURCES = OBSERVED_CONTACT_SOURCES


def _runtime_contact_observed(endpoint: Any) -> bool:
    """Whether a runtime source OBSERVED a network flow to this endpoint's own peer IP
    (pcap ``dst_ip`` / mitm upstream), as opposed to deriving the value from a Host /
    :authority header, a decrypted body, or a tool probe — none of which prove a contact."""
    return any(
        str(getattr(ev, "source", "")) in _OBSERVED_CONTACT_SOURCES
        for ev in getattr(endpoint, "evidences", []) or []
    )


def _ip_from_hostport(value: object) -> str | None:
    """The IP half of an ``ip:port`` runtime ``remote_endpoints`` entry (the capture
    writer always emits ``f"{ip}:{port}"``). IPv6-safe: split on the LAST colon and
    require a valid decimal port suffix. Best-effort on malformed input: an entry whose
    stripped head is not a valid address is skipped, but a hand-edited *port-less* IPv6
    whose last group is decimal (e.g. ``2001:db8::aaaa:443``) is inherently ambiguous with
    the ``ip:port`` form and may still be mis-split — real capture data always carries a
    genuine port, and brackets would be needed to disambiguate hand-edited input."""
    if not isinstance(value, str) or ":" not in value:
        return None
    head, _, port = value.rpartition(":")
    if not head or not port.isdecimal() or not (1 <= int(port) <= 65535):
        return None
    return head


def _domain_in_observed_sni(domain: NetworkEntity, runtime: dict[str, Any]) -> bool:
    """The endpoint's own domain is among the runtime-observed SNI names, so its
    ``remote_endpoints`` really are IPs THIS domain's TLS was sent to — a guard
    against a hand-edited report pairing a domain with unrelated remote IPs."""
    return any(
        (host := _domain_entity(raw)) is not None and host.value == domain.value
        for raw in _as_list(runtime.get("sni"))
    )


# --------------------------------------------------------------------------- #
# The fact -> AttributionEvidence bridge (edges) + the fact -> signal compiler #
# --------------------------------------------------------------------------- #
def _bridge_endpoint(endpoint: Any) -> tuple[list[AttributionEvidence], list[dict[str, Any]]]:
    """Edge-worthy AttributionEvidence + per-IP resource-context snapshots for one
    domain/ip endpoint. Never raises for a single malformed field (skip it)."""
    kind = getattr(endpoint, "kind", None)
    value = getattr(endpoint, "value", None)
    enrichment = _as_dict(getattr(endpoint, "enrichment", None))
    edges: list[AttributionEvidence] = []
    contexts: list[dict[str, Any]] = []

    domain = _domain_entity(value) if kind == "domain" else None
    ref = f"endpoints[{value}].enrichment"

    dns = _as_dict(enrichment.get("dns"))
    hosting = [_as_dict(h) for h in _as_list(dns.get("hosting"))]
    if domain is not None:
        resolved: list[str] = []
        for raw in list(_as_list(dns.get("ips"))) + [h.get("ip") for h in hosting]:
            ip = _ip_entity(raw)
            if ip is not None and ip.value not in resolved:
                resolved.append(ip.value)
                edges.append(_evidence(
                    source="dns", etype="resolved_ip", target=domain, value=ip.value,
                    raw_reference=f"{ref}.dns", confidence=_CONFIDENCE[("dns", "resolved_ip")]))
        for raw in _as_list(dns.get("cname")):
            hop = _domain_entity(raw)
            if hop is not None and hop.value != domain.value:
                edges.append(_evidence(
                    source="dns", etype="dns_alias", target=domain, value=hop.value,
                    raw_reference=f"{ref}.dns.cname", confidence=_CONFIDENCE[("dns", "dns_alias")]))
        for source_key in ("certs", "shodan"):
            block = _as_dict(enrichment.get(source_key))
            for raw in _as_list(block.get("related_hostnames")) + _as_list(block.get("hostnames")):
                host = _domain_entity(raw)
                if host is not None and host.value != domain.value:
                    edges.append(_evidence(
                        source=source_key, etype="related_hostname", target=domain,
                        value=host.value, raw_reference=f"{ref}.{source_key}",
                        confidence=_CONFIDENCE[(source_key, "related_hostname")]))

    # asn evidence (IP -> ASN) from every source that carries a per-IP ASN.
    for host in hosting:
        ip = _ip_entity(host.get("ip"))
        asn = _parse_asn(host.get("asn"))
        if ip is not None and asn is not None:
            edges.append(_evidence(
                source="dns", etype="asn", target=ip, value=asn,
                raw_reference=f"{ref}.dns.hosting", confidence=_CONFIDENCE[("dns", "asn")]))
    if kind == "ip":
        ip = _ip_entity(value)
        for source_key in ("asn", "shodan"):
            asn = _parse_asn(_as_dict(enrichment.get(source_key)).get("asn"))
            if ip is not None and asn is not None:
                edges.append(_evidence(
                    source=source_key, etype="asn", target=ip, value=asn,
                    raw_reference=f"{ref}.{source_key}", confidence=_CONFIDENCE[(source_key, "asn")]))

    # per-IP attribution: asn edge + resource-context snapshot (five-layer, referenced).
    attribution = _as_dict(enrichment.get("attribution"))
    for entry in _as_list(attribution.get("ips")):
        entry = _as_dict(entry)
        ip = _ip_entity(entry.get("ip"))
        if ip is None:
            continue
        origin = _as_dict(entry.get("origin_network"))
        asn = _parse_asn(origin.get("asn"))
        if asn is not None:
            edges.append(_evidence(
                source="attribution", etype="asn", target=ip, value=asn,
                raw_reference=f"{ref}.attribution", confidence=_CONFIDENCE[("attribution", "asn")]))
        hosting_layer = _as_dict(entry.get("hosting_provider"))
        edge_layer = _as_dict(entry.get("edge_provider"))
        contexts.append({
            "ip": ip.value,
            "resource_context": {
                "origin_asn": asn,
                "origin_category": origin.get("category"),
                "hosting_category": hosting_layer.get("category"),
                "edge_provider": edge_layer.get("name"),
                "edge_tier": edge_layer.get("tier"),
            },
            "_entry": entry,  # internal, stripped before serialization
        })

    # runtime-observed edges (the strongest signal — dynamic ground truth). Reads
    # ONLY the structured runtime pairing (capture._annotate_runtime_endpoints); the
    # free-text evidence snippet is never parsed. graph.py already routes these two
    # evidence types (tls_sni -> DOMAIN served_at IP + APK contacted DOMAIN;
    # network_flow -> APK contacted IP), so no frozen-module change is needed. Known
    # anti-fraud interception nodes are excluded — an intercept page is never a
    # domain's serving IP nor a business contact (parity with the pcap ingest drop).
    runtime = _as_dict(enrichment.get("runtime"))
    if domain is not None and _domain_in_observed_sni(domain, runtime):
        seen_ips: set[str] = set()
        for raw in _as_list(runtime.get("remote_endpoints")):
            ip = _ip_entity(_ip_from_hostport(raw))
            if ip is not None and ip.value not in seen_ips and not is_known_intercept_ip(ip.value):
                seen_ips.add(ip.value)
                edges.append(_evidence(
                    source="runtime", etype="tls_sni", target=domain, value=ip.value,
                    raw_reference=f"{ref}.runtime", confidence=_CONFIDENCE[("runtime", "tls_sni")]))
    if kind == "ip" and _runtime_contact_observed(endpoint):
        ip = _ip_entity(value)
        if ip is not None and not is_known_intercept_ip(ip.value):
            edges.append(_evidence(
                source="runtime", etype="network_flow", target=ip, value=True,
                raw_reference=f"endpoints[{value}].evidences[runtime]",
                confidence=_CONFIDENCE[("runtime", "network_flow")]))

    return edges, contexts


def _ip_signal_features(
    ip: NetworkEntity, entry: dict[str, Any], *, endpoint: Any, max_overseas_ts: float | None = None
) -> list[RoleFeature]:
    """The conservative fact->RoleSignal compiler for one IP (one fact -> one signal).

    ``max_overseas_ts``: latest runtime contact time to any OVERSEAS IP endpoint in the
    report (pre-scanned across all endpoints) — licenses SUBSEQUENT_OVERSEAS_CONNECTION on a
    domestic relay-candidate IP when the app contacted overseas AFTER contacting this IP.
    """
    origin = _as_dict(entry.get("origin_network"))
    hosting = _as_dict(entry.get("hosting_provider"))
    edge = _as_dict(entry.get("edge_provider"))
    country = entry.get("country")
    ref = f"endpoints[{getattr(endpoint, 'value', '')}].enrichment.attribution"
    features: list[RoleFeature] = []

    def add(signal: RoleSignal, source: str, value: Any, raw_reference: str) -> None:
        features.append(RoleFeature(
            signal=signal,
            evidence=_evidence(source=source, etype=signal.value, target=ip, value=value,
                               raw_reference=raw_reference, confidence=_SIGNAL_CONFIDENCE[signal]),
        ))

    is_ip_endpoint = getattr(endpoint, "kind", None) == "ip" and _ip_entity(getattr(endpoint, "value", None))
    # ★已知反诈拦截节点的"被接触"是反诈拦截事实、非业务/中继接触——绝不授权任何运行时行为信号
    #   （与 _bridge_endpoint 对 tls_sni/network_flow 边的 is_known_intercept_ip 排除一致；DOMESTIC_NETWORK
    #   是纯资源事实可留、且单独不足以 eligible）。防拦截页被升格为中继候选进线索输出。
    runtime_signal_ok = not is_known_intercept_ip(ip.value)
    if (
        is_ip_endpoint is not None
        and getattr(is_ip_endpoint, "value", None) == ip.value
        and _runtime_contact_observed(endpoint)
        and runtime_signal_ok
    ):
        add(RoleSignal.DIRECT_CONNECTION, "runtime", True, f"endpoints[{ip.value}].evidences[runtime]")

    # domestic_network is a PER-IP jurisdiction fact: the IP's own attribution
    # country / telecom category, or an IP endpoint's own ASN country. A domain's
    # ICP filing is a domain-registration fact — it does NOT make a resolved edge
    # IP (e.g. a US Cloudflare node) domestic, so it licenses no per-IP signal.
    # The endpoint-level asn.country belongs to the endpoint's OWN IP, so (like
    # direct_connection above) it may only license a signal when this attribution
    # entry IS that endpoint IP — never a different IP listed in its attribution.
    ip_asn_country = _as_dict(_as_dict(getattr(endpoint, "enrichment", None)).get("asn")).get("country")
    endpoint_is_this_ip = (
        is_ip_endpoint is not None and getattr(is_ip_endpoint, "value", None) == ip.value
    )
    if country == "CN" or (origin.get("category") == CAT_TELECOM and country == "CN"):
        add(RoleSignal.DOMESTIC_NETWORK, "attribution", "CN", f"{ref}.country")
    elif endpoint_is_this_ip and ip_asn_country == "CN":
        add(RoleSignal.DOMESTIC_NETWORK, "asn", "CN",
            f"endpoints[{getattr(endpoint, 'value', '')}].enrichment.asn.country")

    # SUBSEQUENT_OVERSEAS_CONNECTION（运行时行为信号，P0）：接触该境内 IP 后随后又连境外 = 中继候选行为。
    #   时序判据：本端点最早接触时刻 t_dom < 报告内任一境外 IP 接触时刻（预扫 max_overseas_ts）。仅对**境内
    #   IP 端点自身**、且该 IP 有运行时接触时成立。correlational（同会话先后，非 relay 铁证）→ 支撑 *_candidate。
    is_domestic = country == "CN" or (endpoint_is_this_ip and ip_asn_country == "CN")
    if (
        endpoint_is_this_ip
        and is_domestic
        and max_overseas_ts is not None
        and _runtime_contact_observed(endpoint)
        and runtime_signal_ok  # 拦截节点不产该运行时行为信号（见上）
    ):
        t_dom = _runtime_first_contact_ts(endpoint)
        if t_dom is not None and max_overseas_ts > t_dom:
            add(RoleSignal.SUBSEQUENT_OVERSEAS_CONNECTION, "runtime", True,
                f"endpoints[{ip.value}].enrichment.runtime.first_contact_ts<overseas_contact")

    # BUSINESS_API / LOGIN_ENDPOINT（运行时行为信号，P0-2）：该 IP 在运行时被观测服务业务/登录 API 路径
    #   （capture 从 mitm 请求路径 per-IP 累积）→ origin_candidate 证据（app 直连该 IP 打 /api、/login=像真后端
    #   源站）。须真运行时接触（守不变量：手注 path 字典无 runtime 证据不授信）+ 非拦截节点。
    #   ★有任何 edge 指纹（clustered/possible/probable/confirmed=像前置/CDN/防红共享前端）→ 不当源站、不产
    #   origin 信号：confirmed/probable 另有 PUBLIC_CDN 阻断，此处兜住 possible/clustered 的负证据缺口
    #   （防红前置带高区分度指纹产 fronting-cluster=clustered，穿透它的业务/登录流量必落其上，绝不能升为源站）。
    if endpoint_is_this_ip and runtime_signal_ok and not edge.get("tier") and _runtime_contact_observed(endpoint):
        rt = _as_dict(_as_dict(getattr(endpoint, "enrichment", None)).get("runtime"))
        biz_paths = {p for p in _as_list(rt.get("business_api_paths")) if isinstance(p, str) and p}
        login_paths = {p for p in _as_list(rt.get("login_paths")) if isinstance(p, str) and p}
        # ★BUSINESS_API 须有**非登录类**业务路径——防单条 /api/user/login 同授两信号、把"BUSINESS_API+独立佐证"
        #   塌缩成一条请求（origin 第二要件须来自不同事实）。
        if biz_paths - login_paths:
            add(RoleSignal.BUSINESS_API, "runtime", True,
                f"endpoints[{ip.value}].enrichment.runtime.business_api_paths")
        if login_paths:
            add(RoleSignal.LOGIN_ENDPOINT, "runtime", True,
                f"endpoints[{ip.value}].enrichment.runtime.login_paths")

    # REDIRECT / COOKIE_CHALLENGE（运行时行为信号，P0-3）：该 IP 响应观测到跨 host 重定向 / 挑战 cookie 下发
    #   = edge_candidate / cloaking_edge_node 证据（前置/隐匿边缘的主动行为）。须真运行时接触 + 非拦截节点；
    #   ★不加 edge.tier 门——边缘行为信号与"该 IP 是前置/CDN"一致（edge 角色 PUBLIC_CDN 只作 context 不阻断）。
    if endpoint_is_this_ip and runtime_signal_ok and _runtime_contact_observed(endpoint):
        rt2 = _as_dict(_as_dict(getattr(endpoint, "enrichment", None)).get("runtime"))
        edge_hosts = _as_dict(rt2.get("edge_hosts"))
        # ★同 host 共现才发这对信号：某单个请求 host 同时被重定向 + 挑战 = 该前置对该 host 的 cloaking 行为。
        #   共享边缘上不同租户各出一个信号（A 重定向 / B 挑战）绝不凑成 cloaking（复审 P1：跨租户混淆）。
        #   两信号成对发出——edge_candidate 需 ≥2 edge 信号、cloaking_edge_node 需 ≥2 强行为，均由这对满足。
        if any(isinstance(h, dict) and h.get("r") and h.get("c") for h in edge_hosts.values()):
            add(RoleSignal.REDIRECT, "runtime", True,
                f"endpoints[{ip.value}].enrichment.runtime.edge_hosts")
            add(RoleSignal.COOKIE_CHALLENGE, "runtime", True,
                f"endpoints[{ip.value}].enrichment.runtime.edge_hosts")

    tier = edge.get("tier")
    if (
        tier in _CONFIRMED_EDGE_TIERS
        or hosting.get("category") in _CDN_CATEGORIES
        or origin.get("category") in _CDN_CATEGORIES
    ):
        add(RoleSignal.PUBLIC_CDN, "attribution", str(edge.get("name") or hosting.get("category") or CAT_CDN),
            f"{ref}.edge_provider")
    elif hosting.get("category") in _NON_PUBLIC_CDN_HOSTING and tier is None:
        add(RoleSignal.NON_PUBLIC_CDN, "attribution", str(hosting.get("category")),
            f"{ref}.hosting_provider")

    return features


def _score_ip_roles(ip: NetworkEntity, features: list[RoleFeature]) -> tuple[list[dict[str, Any]], list[Any]]:
    """Assess + score an IP; return (compact role summaries incl. ineligible, eligible RoleScores)."""
    if not features:
        return [], []
    present = {feature.signal for feature in features}
    assessments = RoleClassifier().assess(ip, features)
    scorer = EvidenceScorer()
    summaries: list[dict[str, Any]] = []
    eligible_scores: list[Any] = []
    for definition, assessment in zip(_ROLE_DEFINITIONS, assessments):
        universe = definition.supporting | definition.context | definition.blockers
        if not (present & universe):
            continue  # every signal for this role is merely 'missing' — do not emit
        score = scorer.score(assessment)
        evidence_ids = sorted({
            feature.evidence.id
            for feature in (
                assessment.matched_features + assessment.context_features + assessment.negative_features
            )
        })
        summaries.append({
            "role": assessment.role.value,
            "eligible": assessment.eligible,
            "score": score.score,
            "confidence": score.confidence,
            "matched_signals": [s.value for s in assessment.matched_signals],
            "context_signals": [s.value for s in assessment.context_signals],
            "negative_signals": [s.value for s in assessment.negative_signals],
            "missing_signals": sorted(s.value for s in assessment.missing_evidence),
            "evidence": evidence_ids,
        })
        if assessment.eligible:
            eligible_scores.append(score)
    summaries.sort(key=lambda item: item["role"])
    return summaries, eligible_scores


def _ip_endpoint_country(ep: Any) -> str | None:
    """IP 端点自身的归因国家：attribution 里 ip==端点值（**双侧 _ip_entity 归一化**，与编译器 endpoint_is_this_ip
    对齐）的条目 country——命中但缺/坏 → None（不回落）；无命中条目 → 回落 asn.country。仅采信非空字符串
    （坏值如 True/dict/list → None，别把垃圾当境外）。端点值不可归一化 → None。绝不抛。"""
    enr = _as_dict(getattr(ep, "enrichment", None))
    self_ip = _ip_entity(getattr(ep, "value", None))
    if self_ip is None:
        return None
    for entry in _as_list(_as_dict(enr.get("attribution")).get("ips")):
        e = _as_dict(entry)
        entry_ip = _ip_entity(e.get("ip"))
        if entry_ip is not None and entry_ip.value == self_ip.value:
            c = e.get("country")
            return c if isinstance(c, str) and c else None
    c = _as_dict(enr.get("asn")).get("country")
    return c if isinstance(c, str) and c else None


def _endpoint_asn_country(ep: Any) -> str | None:
    """端点自身 asn 富化里的国家（仅采信非空字符串）。绝不抛。"""
    c = _as_dict(_as_dict(getattr(ep, "enrichment", None)).get("asn")).get("country")
    return c if isinstance(c, str) and c else None


def _runtime_first_contact_ts(ep: Any) -> float | None:
    """端点被运行时最早接触的时刻（capture 写的 runtime.first_contact_ts）。缺/坏/非有限(NaN/±inf)/≤0/bool
    → None（NaN 会让 max() 顺序敏感、inf 会让垃圾值恒产信号，故一并拒）。绝不抛。"""
    ts = _as_dict(_as_dict(getattr(ep, "enrichment", None)).get("runtime")).get("first_contact_ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
        return None
    return float(ts)


def _overseas_contact_timestamps(endpoints: Sequence[Any]) -> list[float]:
    """被运行时接触过的**明确境外** IP 端点的接触时刻列表（供 SUBSEQUENT_OVERSEAS 跨端点时序关联）。
    仅取：IP 端点 + 有运行时接触 + 非已知反诈拦截节点 + first_contact_ts 可用 + 归因国家已知且非 CN
    + **端点自身 asn 口径非 CN**。★后一条使本池与 is_domestic **互斥**：任一口径判境内（含 asn 回落路径）
    即排除，防国别冲突 IP（如电信出海段 attribution=US 但 asn=CN）同时充当"境内主体"与"境外接触"自我授信。绝不抛。"""
    out: list[float] = []
    for ep in endpoints:
        try:
            if getattr(ep, "kind", None) != "ip" or not _runtime_contact_observed(ep):
                continue
            if is_known_intercept_ip(str(getattr(ep, "value", ""))):
                continue  # 反诈拦截节点不是业务接触、绝不入时序池
            ts = _runtime_first_contact_ts(ep)
            country = _ip_endpoint_country(ep)
            if ts is not None and country and country != "CN" and _endpoint_asn_country(ep) != "CN":
                out.append(ts)
        except Exception:  # noqa: BLE001 - 一个坏端点不得沉掉时序预扫
            continue
    return out


# --------------------------------------------------------------------------- #
# The public assembler                                                        #
# --------------------------------------------------------------------------- #
def build_network_attribution(
    endpoints: Sequence[Any], *, artifact_id: str, phase: str
) -> dict[str, Any] | None:
    """Assemble the additive network_attribution view, or None when there is
    nothing to attribute. Pure, passive, deterministic; never raises."""
    edge_evidence: dict[str, AttributionEvidence] = {}
    role_scores: list[Any] = []
    endpoint_views: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    # 预扫：报告内被运行时接触过的境外 IP 端点的最晚接触时刻——供境内 IP 的 SUBSEQUENT_OVERSEAS 时序判据。
    _overseas_ts = _overseas_contact_timestamps(endpoints)
    max_overseas_ts = max(_overseas_ts) if _overseas_ts else None

    for endpoint in endpoints:
        if getattr(endpoint, "kind", None) not in ("domain", "ip"):
            continue
        try:
            edges, contexts = _bridge_endpoint(endpoint)
            for evidence in edges:
                # Permutation-invariant dedup of the same fact discovered via two
                # endpoints: the fact-only id fixes source/type/target/value and
                # confidence/timestamp are constant, so raw_reference is the only
                # order-sensitive field — keep the lexicographically-smallest one
                # so the serialized evidence list is independent of endpoint order.
                existing = edge_evidence.get(evidence.id)
                if existing is None or (evidence.raw_reference or "") < (existing.raw_reference or ""):
                    edge_evidence[evidence.id] = evidence
            ip_views: list[dict[str, Any]] = []
            for context in contexts:
                ip = _ip_entity(context["ip"])
                if ip is None:
                    continue
                features = _ip_signal_features(ip, context["_entry"], endpoint=endpoint,
                                               max_overseas_ts=max_overseas_ts)
                roles, eligible = _score_ip_roles(ip, features)
                role_scores.extend(eligible)
                ip_views.append({
                    "ip": ip.value,
                    "resource_context": context["resource_context"],
                    "roles": roles,
                })
            if edges or any(view["roles"] for view in ip_views):
                endpoint_views.append({
                    "endpoint": str(getattr(endpoint, "value", "")),
                    "kind": getattr(endpoint, "kind"),
                    "ips": sorted(ip_views, key=lambda item: item["ip"]),
                })
        except Exception as exc:  # noqa: BLE001 - one bad endpoint never sinks the view
            logger.debug("network_attribution: skip endpoint %r", getattr(endpoint, "value", None), exc_info=True)
            skipped.append({"endpoint": str(getattr(endpoint, "value", "")), "error": type(exc).__name__})

    if not edge_evidence and not endpoint_views:
        return None

    try:
        graph = build_infrastructure_graph(
            artifact_id=artifact_id,
            extra_evidence=list(edge_evidence.values()),
            role_scores=role_scores,
        )
        graph_dict = graph.to_dict()
    except Exception as exc:  # noqa: BLE001 - degrade to an explainable marker, never raise
        logger.debug("network_attribution: graph build failed", exc_info=True)
        graph_dict = {"error": type(exc).__name__}

    return {
        "version": 1,
        "phase": phase,
        "artifact_id": artifact_id,
        "disclaimer": _DISCLAIMER,
        "graph": graph_dict,
        "evidence": [e.to_dict() for e in sorted(edge_evidence.values(), key=lambda e: e.id)],
        "endpoints": sorted(endpoint_views, key=lambda item: (item["kind"], item["endpoint"])),
        "skipped": sorted(skipped, key=lambda item: item["endpoint"]),
    }
