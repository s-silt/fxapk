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
from apkscan.network import NetworkEntity, NetworkEntityType
from apkscan.network.fingerprints import (
    is_known_intercept_ip,
    normalize_domain,
    normalize_ip,
    stable_digest,
)

logger = logging.getLogger(__name__)

__all__ = ["build_network_attribution"]

_NS = "apkscan.attribution/report-bridge"
_MAX_ASN = 4_294_967_294

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
    }
)

_CDN_CATEGORIES = frozenset({"cdn"})
_NON_PUBLIC_CDN_HOSTING = frozenset({"cloud", "idc"})
_CONFIRMED_EDGE_TIERS = frozenset({"confirmed", "probable"})


# --------------------------------------------------------------------------- #
# Small pure helpers                                                          #
# --------------------------------------------------------------------------- #
def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_asn(value: object) -> int | None:
    """Strict full-match parse of an ASN: an int, or an ``AS<int>`` / ``AS<int> Org``
    string. Never extracts digits from the middle of a malformed string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        head = value.strip().split(" ", 1)[0]
        if head[:2].upper() == "AS":
            head = head[2:]
        if not head.isdecimal():
            return None
        number = int(head)
    else:
        return None
    return number if 1 <= number <= _MAX_ASN else None


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
#: (``*-decrypted``), or a tool-initiated probe — none of which prove the app contacted
#: THAT IP — so they license no observed-contact edge/signal. Allowlist, not denylist: a
#: new content-derived source is excluded by default (the safe direction for the
#: no-over-inference contract).
_OBSERVED_CONTACT_SOURCES = frozenset({"runtime", "runtime-pcap"})


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
    ip: NetworkEntity, entry: dict[str, Any], *, endpoint: Any
) -> list[RoleFeature]:
    """The conservative fact->RoleSignal compiler for one IP (one fact -> one signal)."""
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
    if (
        is_ip_endpoint is not None
        and getattr(is_ip_endpoint, "value", None) == ip.value
        and _runtime_contact_observed(endpoint)
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
    if country == "CN" or (origin.get("category") == "telecom" and country == "CN"):
        add(RoleSignal.DOMESTIC_NETWORK, "attribution", "CN", f"{ref}.country")
    elif endpoint_is_this_ip and ip_asn_country == "CN":
        add(RoleSignal.DOMESTIC_NETWORK, "asn", "CN",
            f"endpoints[{getattr(endpoint, 'value', '')}].enrichment.asn.country")

    tier = edge.get("tier")
    if (
        tier in _CONFIRMED_EDGE_TIERS
        or hosting.get("category") in _CDN_CATEGORIES
        or origin.get("category") in _CDN_CATEGORIES
    ):
        add(RoleSignal.PUBLIC_CDN, "attribution", str(edge.get("name") or hosting.get("category") or "cdn"),
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
                features = _ip_signal_features(ip, context["_entry"], endpoint=endpoint)
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
