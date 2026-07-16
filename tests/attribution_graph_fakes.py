"""Shared fixtures for the PR7 infrastructure attribution graph tests."""

from __future__ import annotations

from apkscan.attribution import (
    AttributionEvidence,
    EvidenceScorer,
    InfrastructureRole,
    RoleClassifier,
    RoleFeature,
    RoleScore,
    RoleSignal,
)
from apkscan.network import NetworkEntity, NetworkEntityType


def ip(value: str = "1.2.3.4", sources: tuple[str, ...] = ("pcap",)) -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources)


def domain(value: str = "example.com", sources: tuple[str, ...] = ("pcap",)) -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.DOMAIN, value, sources)


def cert(fingerprint: str = "a" * 64, sources: tuple[str, ...] = ("censys",)) -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.CERTIFICATE, f"sha256:{fingerprint}", sources)


def host(value: str = "example.com:8443", sources: tuple[str, ...] = ("mitmproxy",)) -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.HOST, value, sources)


def evidence(
    *,
    id: str,
    type: str,
    target: NetworkEntity,
    value: object,
    source: str = "pcap",
    confidence: float = 1.0,
) -> AttributionEvidence:
    return AttributionEvidence(
        id=id, source=source, type=type, target=target, value=value, confidence=confidence
    )


def domestic_relay_score_for(target: NetworkEntity) -> RoleScore:
    """A real, eligible domestic_relay_candidate RoleScore for any target entity,
    built through the classifier + scorer so it is self-consistent."""

    def _ev(signal: str, index: int) -> AttributionEvidence:
        return AttributionEvidence(
            id=f"role-{target.kind.value}-{target.value}-{signal}-{index}",
            source="pcap",
            type=signal,
            target=target,
            value=True,
            confidence=1.0,
        )

    features = [
        RoleFeature(signal=RoleSignal.DIRECT_CONNECTION, evidence=_ev("direct_connection", 1)),
        RoleFeature(signal=RoleSignal.DOMESTIC_NETWORK, evidence=_ev("domestic_network", 2)),
        RoleFeature(signal=RoleSignal.REDIRECT, evidence=_ev("redirect", 3)),
    ]
    for assessment in RoleClassifier().assess(target, features):
        if assessment.role is InfrastructureRole.DOMESTIC_RELAY_CANDIDATE:
            return EvidenceScorer().score(assessment)
    raise RuntimeError("expected a domestic_relay_candidate assessment")


def domestic_relay_score(ip_value: str = "1.2.3.4") -> RoleScore:
    return domestic_relay_score_for(ip(ip_value))


def edge_tuples(graph) -> set[tuple[str, str, str, str, str]]:
    return {
        (
            edge.relation.value,
            edge.source_type.value,
            edge.source_value,
            edge.target_type.value,
            edge.target_value,
        )
        for edge in graph.edges
    }


def node_keys(graph) -> set[tuple[str, str]]:
    return {(node.node_type.value, node.value) for node in graph.nodes}
