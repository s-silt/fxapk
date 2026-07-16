"""PR7 builder determinism: permutation invariance, fact-only ids, conflicts."""

from __future__ import annotations

import json
import random

import pytest

from apkscan.attribution.graph import build_infrastructure_graph
from tests.attribution_graph_fakes import cert, domain, domestic_relay_score, evidence, ip


def _diverse_evidence():
    return [
        evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.example.com", confidence=0.4),
        # e1b corroborates the same edge with a higher confidence -> merge=max must be order-free
        evidence(id="e1b", type="resolved_ip", target=domain("a.example.com"), value="1.2.3.4", source="shodan", confidence=0.9),
        evidence(id="e2", type="tls_sni", target=domain("a.example.com"), value="1.2.3.4"),
        evidence(id="e3", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),
        evidence(id="e4", type="network_flow", target=ip("5.6.7.8"), value="tcp/80"),
        evidence(id="e5", type="cert_san_dns", target=cert(), value="a.example.com", source="censys"),
        evidence(id="e6", type="related_ip", target=domain("a.example.com"), value="9.9.9.9", source="fofa"),
        evidence(id="e7", type="service_org", target=ip("1.2.3.4"), value="Acme", source="shodan"),
    ]


def _canonical(graph) -> str:
    return json.dumps(graph.to_dict(), sort_keys=True, ensure_ascii=False)


def test_permutation_invariance() -> None:
    evs = _diverse_evidence()
    roles = [domestic_relay_score("1.2.3.4"), domestic_relay_score("5.6.7.8")]
    baseline = _canonical(
        build_infrastructure_graph(artifact_id="s", extra_evidence=evs, role_scores=roles)
    )
    for seed in range(6):
        rng = random.Random(seed)
        shuffled_ev = list(evs)
        rng.shuffle(shuffled_ev)
        shuffled_roles = list(roles)
        rng.shuffle(shuffled_roles)
        other = build_infrastructure_graph(
            artifact_id="s", extra_evidence=shuffled_ev, role_scores=shuffled_roles
        )
        assert _canonical(other) == baseline


def test_confidence_merges_as_max() -> None:
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="lo", type="dns_resolution", target=ip("1.2.3.4"), value="a.com", confidence=0.4),
            evidence(id="hi", type="resolved_ip", target=domain("a.com"), value="1.2.3.4", source="shodan", confidence=0.9),
        ],
    )
    edge = next(e for e in g.edges if e.relation.value == "resolves_to")
    assert edge.confidence == 0.9


def test_identical_build_twice_is_equal() -> None:
    evs = _diverse_evidence()
    a = build_infrastructure_graph(artifact_id="s", extra_evidence=evs)
    b = build_infrastructure_graph(artifact_id="s", extra_evidence=evs)
    assert a == b
    assert _canonical(a) == _canonical(b)


def test_edge_id_stable_when_unrelated_facts_added() -> None:
    base = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.com")],
    )
    edge_id = next(e.id for e in base.edges if e.relation.value == "resolves_to")
    grown = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.com"),
            evidence(id="e2", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),
            evidence(id="e3", type="service_org", target=ip("1.2.3.4"), value="Acme", source="shodan"),
        ],
    )
    grown_id = next(e.id for e in grown.edges if e.relation.value == "resolves_to")
    assert grown_id == edge_id  # provenance/corroboration does not change the edge id


def test_same_resolution_two_observations_is_one_edge_two_provenance() -> None:
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="obs-early", type="dns_resolution", target=ip("1.2.3.4"), value="a.com"),
            evidence(id="obs-late", type="dns_resolution", target=ip("1.2.3.4"), value="a.com"),
        ],
    )
    resolves = [e for e in g.edges if e.relation.value == "resolves_to"]
    assert len(resolves) == 1
    assert set(resolves[0].provenance) == {"obs-early", "obs-late"}


def test_conflicting_id_raises() -> None:
    with pytest.raises(ValueError):
        build_infrastructure_graph(
            artifact_id="s",
            extra_evidence=[
                evidence(id="dup", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),
                evidence(id="dup", type="asn", target=ip("1.2.3.4"), value=20940, source="shodan"),
            ],
        )


def test_semantic_conflict_keeps_parallel_edges() -> None:
    # one IP asserted in two different ASNs (distinct evidence ids) -> two edges
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="e1", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),
            evidence(id="e2", type="asn", target=ip("1.2.3.4"), value=20940, source="censys"),
        ],
    )
    asn_edges = {e.target_value for e in g.edges if e.relation.value == "in_asn"}
    assert asn_edges == {"AS13335", "AS20940"}


def test_duplicate_evidence_absorbed() -> None:
    ev = evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.com")
    once = build_infrastructure_graph(artifact_id="s", extra_evidence=[ev])
    twice = build_infrastructure_graph(artifact_id="s", extra_evidence=[ev, ev])
    assert _canonical(once) == _canonical(twice)


def test_to_dict_is_not_aliased() -> None:
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[evidence(id="e1", type="dns_resolution", target=ip("1.2.3.4"), value="a.com")],
    )
    first = g.to_dict()
    first["edges"].append("mutated")
    assert "mutated" not in g.to_dict()["edges"]
