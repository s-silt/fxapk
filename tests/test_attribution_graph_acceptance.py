"""PR7 acceptance scenarios + anti-over-inference negatives."""

from __future__ import annotations

import json

from apkscan.attribution.graph import build_infrastructure_graph
from tests.attribution_graph_fakes import (
    cert,
    domain,
    domestic_relay_score,
    edge_tuples,
    evidence,
    ip,
    node_keys,
)


def test_apk_to_domestic_to_overseas_chain() -> None:
    domestic = "203.0.113.9"
    overseas = "198.51.100.7"
    g = build_infrastructure_graph(
        artifact_id="sample-A",
        extra_evidence=[
            evidence(id="f1", type="network_flow", target=ip(domestic), value="tcp/443"),
            evidence(id="f2", type="network_flow", target=ip(overseas), value="tcp/443"),
            # the domestic relay redirects the app onward to the overseas host
            evidence(id="r1", type="http_redirect", target=ip(domestic), value=f"https://{overseas}/x"),
            evidence(id="a1", type="asn", target=ip(overseas), value=13335, source="shodan"),
        ],
        role_scores=[domestic_relay_score(domestic)],
    )
    tuples = edge_tuples(g)
    assert ("contacted", "APK", "sample-A", "IP", domestic) in tuples
    assert ("contacted", "APK", "sample-A", "IP", overseas) in tuples
    assert ("redirects_to", "IP", domestic, "IP", overseas) in tuples
    assert ("in_asn", "IP", overseas, "ASN", "AS13335") in tuples

    domestic_node = next(n for n in g.nodes if (n.node_type.value, n.value) == ("IP", domestic))
    assert [r.role.value for r in domestic_node.roles] == ["domestic_relay_candidate"]
    overseas_node = next(n for n in g.nodes if (n.node_type.value, n.value) == ("IP", overseas))
    assert overseas_node.roles == ()  # no role invented for the overseas host


def test_shared_cert_is_a_linear_star_not_pairwise() -> None:
    sans = [f"host{i}.example.com" for i in range(5)]
    evs = [
        evidence(id=f"san-{i}", type="cert_san_dns", target=cert(), value=san, source="censys")
        for i, san in enumerate(sans)
    ]
    g = build_infrastructure_graph(artifact_id="s", extra_evidence=evs)
    certifies = [e for e in g.edges if e.relation.value == "certifies"]
    assert len(certifies) == len(sans)  # linear, one edge per SAN — never O(N^2) pairwise
    assert len({(e.source_type.value, e.source_value) for e in certifies}) == 1  # one cert node
    # no DOMAIN<->DOMAIN edge between co-certified hosts
    assert not any(
        e.source_type.value == "DOMAIN" and e.target_type.value == "DOMAIN" for e in g.edges
    )


def test_ordinary_site_gets_no_origin_role_without_a_rolescore() -> None:
    # resolve facts exist, but roles are only ever consumed (never re-derived), so
    # absent a RoleScore no origin_candidate annotation appears.
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="e1", type="resolved_ip", target=domain("www.example.com"), value="104.16.0.1", source="shodan"),
            evidence(id="e2", type="asn", target=ip("104.16.0.1"), value=13335, source="shodan"),
        ],
    )
    assert all(node.roles == () for node in g.nodes)
    assert not any("origin" in json.dumps(node.to_dict()) for node in g.nodes)


def test_same_asn_alone_makes_no_cross_edge_or_cluster() -> None:
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="a1", type="asn", target=ip("203.0.113.1"), value=4837, source="shodan"),
            evidence(id="a2", type="asn", target=ip("203.0.113.2"), value=4837, source="censys"),
        ],
    )
    # one ASN node, two IN_ASN edges, and NOTHING linking the two IPs
    assert ("ASN", "AS4837") in node_keys(g)
    in_asn = [e for e in g.edges if e.relation.value == "in_asn"]
    assert len(in_asn) == 2
    assert not any(
        e.source_type.value == "IP" and e.target_type.value == "IP" for e in g.edges
    )
    # no cluster/member vocabulary exists at all
    serialized = json.dumps(g.to_dict())
    assert "cluster" not in serialized.lower()
    assert "member_of" not in serialized.lower()


def test_serialized_graph_has_no_operator_or_actor_field() -> None:
    g = build_infrastructure_graph(
        artifact_id="s",
        extra_evidence=[
            evidence(id="e1", type="asn", target=ip("1.2.3.4"), value=13335, source="shodan"),
            evidence(id="e2", type="service_org", target=ip("1.2.3.4"), value="AMAZON-02", source="shodan"),
        ],
    )
    blob = json.dumps(g.to_dict()).lower()
    for forbidden in ("operator", "actor", "owned_by", "operated_by"):
        assert forbidden not in blob


def test_every_provenance_id_resolves_to_an_input_fact() -> None:
    role = domestic_relay_score("203.0.113.9")
    extra = [
        evidence(id="f1", type="network_flow", target=ip("203.0.113.9"), value="tcp/443"),
        evidence(id="d1", type="dns_resolution", target=ip("203.0.113.9"), value="relay.example.com"),
    ]
    g = build_infrastructure_graph(artifact_id="s", extra_evidence=extra, role_scores=[role])

    valid_ids = {e.id for e in extra}
    for contribution in role.contributions:
        for feature in contribution.features:
            valid_ids.add(feature.evidence.id)

    for node in g.nodes:
        assert set(node.provenance) <= valid_ids, node.to_dict()
    for edge in g.edges:
        assert set(edge.provenance) <= valid_ids, edge.to_dict()
