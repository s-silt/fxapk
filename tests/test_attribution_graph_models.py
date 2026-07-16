"""PR7 graph value objects: enums, node/edge/issue/container invariants."""

from __future__ import annotations

import json

import pytest

from apkscan.attribution.graph import (
    GraphEdge,
    GraphIssue,
    GraphNode,
    GraphNodeType,
    GraphRelation,
    InfrastructureGraph,
)
from apkscan.network import NetworkEntityType
from apkscan.network.fingerprints import stable_digest as _stable_digest
from tests.attribution_graph_fakes import domestic_relay_score


def _node(node_type=GraphNodeType.IP, value="1.2.3.4", provenance=("obs-1",), **kw):
    return GraphNode(node_type=node_type, value=value, provenance=provenance, **kw)


def test_node_and_relation_enum_members() -> None:
    assert {t.value for t in GraphNodeType} == {"APK", "DOMAIN", "IP", "CERTIFICATE", "ASN"}
    assert {r.value for r in GraphRelation} == {
        "contacted", "resolves_to", "alias_of", "served_at",
        "redirects_to", "intel_related", "in_asn", "certifies",
    }
    # PR1's NetworkEntityType must stay frozen at its 8 members.
    assert {t.value for t in NetworkEntityType} == {
        "DOMAIN", "IP", "CERTIFICATE", "ASN", "URL", "HOST", "PROVIDER", "NETWORK_CLUSTER",
    }


def test_node_normalizes_value_per_kind() -> None:
    assert _node(GraphNodeType.IP, "2001:0db8::1").value == "2001:db8::1"
    assert _node(GraphNodeType.DOMAIN, "Example.COM").value == "example.com"
    assert _node(GraphNodeType.ASN, "13335").value == "AS13335"
    assert _node(GraphNodeType.ASN, "AS13335").value == "AS13335"
    assert _node(GraphNodeType.CERTIFICATE, "sha256:" + "a" * 64).value == "sha256:" + "a" * 64
    assert _node(GraphNodeType.APK, "  sample-A  ").value == "sample-A"


def test_node_is_frozen_and_sorts_sources() -> None:
    node = _node(sources=("b", "a", "a"))
    assert node.sources == ("a", "b")
    with pytest.raises(Exception):
        node.value = "x"  # type: ignore[misc]


def test_node_provenance_must_be_non_empty() -> None:
    with pytest.raises(ValueError):
        _node(provenance=())


def test_node_bad_value_raises() -> None:
    with pytest.raises(ValueError):
        _node(GraphNodeType.IP, "not-an-ip")
    with pytest.raises(ValueError):
        _node(GraphNodeType.CERTIFICATE, "sha256:AA")
    with pytest.raises(ValueError):
        _node(GraphNodeType.ASN, "AS0")


def test_node_roles_annotation_and_conflict() -> None:
    score = domestic_relay_score("1.2.3.4")
    node = GraphNode(node_type=GraphNodeType.IP, value="1.2.3.4", provenance=("p",), roles=(score,))
    assert node.roles[0].role.value == "domestic_relay_candidate"
    # a role whose target does not match the node is rejected
    with pytest.raises(ValueError):
        GraphNode(node_type=GraphNodeType.IP, value="9.9.9.9", provenance=("p",), roles=(score,))
    # APK nodes cannot carry roles
    with pytest.raises(ValueError):
        GraphNode(node_type=GraphNodeType.APK, value="sample-A", provenance=("p",), roles=(score,))


def _edge(rel=GraphRelation.RESOLVES_TO, st=GraphNodeType.DOMAIN, sv="example.com",
          tt=GraphNodeType.IP, tv="1.2.3.4", provenance=("ev-1",), **kw):
    return GraphEdge(source_type=st, source_value=sv, relation=rel,
                     target_type=tt, target_value=tv, provenance=provenance, **kw)


def test_edge_id_is_fact_only_stable_digest() -> None:
    edge = _edge()
    expected = _stable_digest("apkscan.attribution/graph-edge", {
        "relation": "resolves_to", "source_type": "DOMAIN", "source_value": "example.com",
        "target_type": "IP", "target_value": "1.2.3.4",
    })
    assert edge.id == expected
    # provenance / confidence do not change the id
    other = _edge(provenance=("ev-1", "ev-2"), confidence=0.5)
    assert other.id == edge.id


def test_edge_rejects_wrong_endpoint_kinds() -> None:
    with pytest.raises(ValueError):
        _edge(GraphRelation.RESOLVES_TO, GraphNodeType.IP, "1.2.3.4", GraphNodeType.DOMAIN, "example.com")
    with pytest.raises(ValueError):
        _edge(GraphRelation.IN_ASN, GraphNodeType.DOMAIN, "example.com", GraphNodeType.ASN, "AS1")


def test_edge_rejects_self_loop() -> None:
    with pytest.raises(ValueError):
        _edge(GraphRelation.ALIAS_OF, GraphNodeType.DOMAIN, "a.com", GraphNodeType.DOMAIN, "a.com")


def test_edge_provenance_non_empty_and_confidence_bounds() -> None:
    with pytest.raises(ValueError):
        _edge(provenance=())
    with pytest.raises(ValueError):
        _edge(confidence=1.5)
    assert _edge(confidence=None).confidence is None


def test_issue_shape() -> None:
    issue = GraphIssue(stage="asn", reference="ev-9", reason="invalid ASN value")
    assert issue.to_dict() == {"stage": "asn", "reference": "ev-9", "reason": "invalid ASN value"}
    with pytest.raises(ValueError):
        GraphIssue(stage="", reference="x", reason="y")


def test_graph_container_dedup_sort_and_referential_integrity() -> None:
    n_apk = GraphNode(node_type=GraphNodeType.APK, value="sample-A", provenance=("ev-1",))
    n_dom = _node(GraphNodeType.DOMAIN, "example.com", provenance=("ev-1",))
    n_ip = _node(GraphNodeType.IP, "1.2.3.4", provenance=("ev-1",))
    edge = _edge()
    graph = InfrastructureGraph(artifact_id="sample-A", nodes=(n_ip, n_dom, n_apk), edges=(edge,))
    # sorted by (type, value)
    assert [(n.node_type.value, n.value) for n in graph.nodes] == [
        ("APK", "sample-A"), ("DOMAIN", "example.com"), ("IP", "1.2.3.4"),
    ]
    # a dangling edge endpoint raises
    with pytest.raises(ValueError):
        InfrastructureGraph(artifact_id="sample-A", nodes=(n_dom,), edges=(edge,))
    # duplicate node key raises
    with pytest.raises(ValueError):
        InfrastructureGraph(artifact_id="sample-A", nodes=(n_ip, _node(GraphNodeType.IP, "1.2.3.4", provenance=("ev-2",))))
    # duplicate edge identity key raises (merging is the builder's job)
    with pytest.raises(ValueError):
        InfrastructureGraph(
            artifact_id="sample-A", nodes=(n_dom, n_ip),
            edges=(_edge(provenance=("ev-1",)), _edge(provenance=("ev-2",))),
        )


def test_empty_graph_is_valid_and_json_round_trips() -> None:
    graph = InfrastructureGraph(artifact_id="sample-A")
    assert graph.to_dict() == {"artifact_id": "sample-A", "nodes": [], "edges": [], "issues": []}
    n_dom = _node(GraphNodeType.DOMAIN, "example.com", provenance=("ev-1",))
    n_ip = _node(GraphNodeType.IP, "1.2.3.4", provenance=("ev-1",))
    full = InfrastructureGraph(artifact_id="sample-A", nodes=(n_dom, n_ip), edges=(_edge(),),
                               issues=(GraphIssue(stage="asn", reference="e", reason="bad"),))
    assert json.loads(json.dumps(full.to_dict())) == full.to_dict()
