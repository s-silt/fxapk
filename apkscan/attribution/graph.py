"""In-memory explainable infrastructure attribution graph (PR7).

A per-run **value model** assembled from facts PR1-PR6 already produce
(``Observation``/``AttributionEvidence`` inside a ``ConversionResult``,
``RoleScore``). It is NOT a store and is unrelated to the frozen Kuzu
``apkscan.graph`` product: no persistence, no DB, no ``kuzu``/``sqlite3``, and no
``Entity``/``OBSERVED`` vocabulary.

Every node and edge carries non-empty ``provenance`` (the ids of the supporting
observations/evidence), so the graph answers "why is this here?" for each
element. Edges come from a single **closed evidence registry** (``_EDGE_HANDLERS``):
the converters emit a single-target evidence for every edge-worthy fact, so
deriving from evidence — rather than also parsing the parallel ``Observation`` —
avoids double-counting. Observations only fold their ids into the provenance of
nodes already admitted by evidence, which is exactly what drops the analysis
device's source IP. A fact type outside the registry contributes provenance to
its target node only (never an edge, never an issue), so future evidence types
fail safe.

Determinism mirrors ``converters._make_result``: fact-only ``stable_digest`` ids
(identity excludes provenance/confidence/timestamp), every collection
``set -> tuple(sorted(...))``, and a JSON-safe deterministic ``to_dict()``.
Conflicting ids raise (the PR3/PR4/PR5 iron law); semantic conflicts (one IP in
two ASNs) are kept as parallel edges, never merged by preference. No operator/
actor is ever a node or an inference; clusters are deferred.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlsplit

from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.scorer import RoleScore
from apkscan.network import NetworkEntity, NetworkEntityType, Observation
from apkscan.network.fingerprints import (
    normalize_authority,
    normalize_domain,
    normalize_ip,
    stable_digest,
)

if TYPE_CHECKING:
    # Imported lazily inside build_infrastructure_graph at runtime: a module-level
    # import would form a cycle (converters -> attribution.models -> attribution
    # package __init__ -> graph -> converters), crashing any consumer whose first
    # apkscan import is apkscan.network.converters.
    from apkscan.network.converters import ConversionResult

__all__ = [
    "GraphEdge",
    "GraphIssue",
    "GraphNode",
    "GraphNodeType",
    "GraphRelation",
    "InfrastructureGraph",
    "build_infrastructure_graph",
]

_CERT_VALUE_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_ASN = 4_294_967_294


# --------------------------------------------------------------------------- #
# Enums                                                                        #
# --------------------------------------------------------------------------- #
class GraphNodeType(str, Enum):
    """Graph-local node vocabulary. DOMAIN/IP/CERTIFICATE/ASN mirror
    ``NetworkEntityType`` 1:1; APK is the analyzed sample (value = artifact id),
    which has no ``NetworkEntityType`` counterpart — keeping that enum frozen."""

    APK = "APK"
    DOMAIN = "DOMAIN"
    IP = "IP"
    CERTIFICATE = "CERTIFICATE"
    ASN = "ASN"


class GraphRelation(str, Enum):
    """Closed v1 relation vocabulary (never the legacy ``OBSERVED``)."""

    CONTACTED = "contacted"
    RESOLVES_TO = "resolves_to"
    ALIAS_OF = "alias_of"
    SERVED_AT = "served_at"
    REDIRECTS_TO = "redirects_to"
    INTEL_RELATED = "intel_related"
    IN_ASN = "in_asn"
    CERTIFIES = "certifies"


#: NetworkEntityType -> graph node kind for the four network kinds.
_NETWORK_KIND_TO_NODE: MappingProxyType[NetworkEntityType, GraphNodeType] = MappingProxyType(
    {
        NetworkEntityType.DOMAIN: GraphNodeType.DOMAIN,
        NetworkEntityType.IP: GraphNodeType.IP,
        NetworkEntityType.CERTIFICATE: GraphNodeType.CERTIFICATE,
        NetworkEntityType.ASN: GraphNodeType.ASN,
    }
)
#: graph node kind -> the NetworkEntityType a RoleScore target must carry.
_NODE_TO_NETWORK_KIND: MappingProxyType[GraphNodeType, NetworkEntityType] = MappingProxyType(
    {node: kind for kind, node in _NETWORK_KIND_TO_NODE.items()}
)

#: allowed (source_kinds, target_kinds) per relation.
_RELATION_ENDPOINTS: MappingProxyType[
    GraphRelation, tuple[frozenset[GraphNodeType], frozenset[GraphNodeType]]
] = MappingProxyType(
    {
        GraphRelation.CONTACTED: (
            frozenset({GraphNodeType.APK}),
            frozenset({GraphNodeType.DOMAIN, GraphNodeType.IP}),
        ),
        GraphRelation.RESOLVES_TO: (
            frozenset({GraphNodeType.DOMAIN}),
            frozenset({GraphNodeType.IP}),
        ),
        GraphRelation.ALIAS_OF: (
            frozenset({GraphNodeType.DOMAIN}),
            frozenset({GraphNodeType.DOMAIN}),
        ),
        GraphRelation.SERVED_AT: (
            frozenset({GraphNodeType.DOMAIN}),
            frozenset({GraphNodeType.IP}),
        ),
        GraphRelation.REDIRECTS_TO: (
            frozenset({GraphNodeType.DOMAIN, GraphNodeType.IP}),
            frozenset({GraphNodeType.DOMAIN, GraphNodeType.IP}),
        ),
        GraphRelation.INTEL_RELATED: (
            frozenset({GraphNodeType.DOMAIN, GraphNodeType.IP}),
            frozenset({GraphNodeType.DOMAIN, GraphNodeType.IP}),
        ),
        GraphRelation.IN_ASN: (
            frozenset({GraphNodeType.IP}),
            frozenset({GraphNodeType.ASN}),
        ),
        GraphRelation.CERTIFIES: (
            frozenset({GraphNodeType.CERTIFICATE}),
            frozenset({GraphNodeType.DOMAIN}),
        ),
    }
)


# --------------------------------------------------------------------------- #
# Value normalization / coercion                                              #
# --------------------------------------------------------------------------- #
def _clean_identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{name} must not be blank")
    return stripped


def _coerce_node_type(value: object) -> GraphNodeType:
    if isinstance(value, GraphNodeType):
        return value
    if isinstance(value, str):
        try:
            return GraphNodeType(value)
        except ValueError as exc:
            raise ValueError(f"invalid graph node type: {value!r}") from exc
    raise TypeError(f"node type must be GraphNodeType or str, got {type(value).__name__}")


def _coerce_relation(value: object) -> GraphRelation:
    if isinstance(value, GraphRelation):
        return value
    if isinstance(value, str):
        try:
            return GraphRelation(value)
        except ValueError as exc:
            raise ValueError(f"invalid graph relation: {value!r}") from exc
    raise TypeError(f"relation must be GraphRelation or str, got {type(value).__name__}")


def _normalize_asn_value(value: str) -> str:
    text = value.strip()
    if text[:2].upper() == "AS":
        text = text[2:]
    if not text.isdecimal():
        raise ValueError(f"invalid ASN value: {value!r}")
    number = int(text)
    if not 1 <= number <= _MAX_ASN:
        raise ValueError(f"ASN out of range: {number}")
    return f"AS{number}"


def _normalize_node_value(node_type: GraphNodeType, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"node value must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError("node value must not be blank")
    if node_type is GraphNodeType.APK:
        return text
    if node_type is GraphNodeType.IP:
        return normalize_ip(text)
    if node_type is GraphNodeType.DOMAIN:
        return normalize_domain(text)
    if node_type is GraphNodeType.CERTIFICATE:
        if not _CERT_VALUE_RE.fullmatch(text):
            raise ValueError(f"non-canonical certificate value: {text!r}")
        return text
    return _normalize_asn_value(text)


def _clean_sources(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("sources must be an iterable of str")
    cleaned: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"sources must contain str, got {type(item).__name__}")
        stripped = item.strip()
        if stripped:
            cleaned.add(stripped)
    return tuple(sorted(cleaned))


def _clean_provenance(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("provenance must be an iterable of str")
    cleaned: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"provenance must contain str, got {type(item).__name__}")
        stripped = item.strip()
        if stripped:
            cleaned.add(stripped)
    if not cleaned:
        raise ValueError("provenance must be non-empty")
    return tuple(sorted(cleaned))


def _validate_optional_confidence(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("confidence must be an int, float, or None")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("confidence must be finite")
    if not 0.0 <= result <= 1.0:
        raise ValueError("confidence must be within [0, 1]")
    return result


# --------------------------------------------------------------------------- #
# Value objects                                                               #
# --------------------------------------------------------------------------- #
def _normalize_roles(
    value: object, node_type: GraphNodeType, node_value: str
) -> tuple[RoleScore, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError("roles must be an iterable of RoleScore")
    scores = tuple(value)
    if not scores:
        return ()
    expected_kind = _NODE_TO_NETWORK_KIND.get(node_type)
    if expected_kind is None:
        raise ValueError(f"{node_type.value} nodes cannot carry roles")
    by_role: dict[str, RoleScore] = {}
    payloads: dict[str, dict[str, Any]] = {}
    for score in scores:
        if not isinstance(score, RoleScore):
            raise TypeError(f"roles must contain RoleScore, got {type(score).__name__}")
        target = score.target
        if target.kind is not expected_kind or _normalize_node_value(
            node_type, target.value
        ) != node_value:
            raise ValueError("role score target must match the node entity")
        key = score.role.value
        payload = score.to_dict()
        existing = payloads.get(key)
        if existing is None:
            payloads[key] = payload
        elif existing != payload:
            raise ValueError(f"conflicting role score for {key!r}")
        by_role.setdefault(key, score)
    return tuple(by_role[key] for key in sorted(by_role))


@dataclass(frozen=True, kw_only=True)
class GraphNode:
    """A graph node: an entity (or the APK) with merged sources, role
    annotations, and non-empty provenance."""

    node_type: GraphNodeType
    value: str
    provenance: tuple[str, ...]
    sources: tuple[str, ...] = ()
    roles: tuple[RoleScore, ...] = ()

    def __post_init__(self) -> None:
        node_type = _coerce_node_type(self.node_type)
        object.__setattr__(self, "node_type", node_type)
        object.__setattr__(self, "value", _normalize_node_value(node_type, self.value))
        object.__setattr__(self, "sources", _clean_sources(self.sources))
        object.__setattr__(self, "roles", _normalize_roles(self.roles, node_type, self.value))
        object.__setattr__(self, "provenance", _clean_provenance(self.provenance))

    @property
    def key(self) -> tuple[GraphNodeType, str]:
        return (self.node_type, self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.node_type.value,
            "value": self.value,
            "sources": list(self.sources),
            "roles": [role.to_dict() for role in self.roles],
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True, kw_only=True)
class GraphEdge:
    """A directed, typed, provenance-bearing edge. Identity (and id) is
    fact-only: provenance/confidence are excluded so the id is stable as
    corroboration accumulates."""

    source_type: GraphNodeType
    source_value: str
    relation: GraphRelation
    target_type: GraphNodeType
    target_value: str
    provenance: tuple[str, ...]
    confidence: float | None = None

    def __post_init__(self) -> None:
        source_type = _coerce_node_type(self.source_type)
        target_type = _coerce_node_type(self.target_type)
        relation = _coerce_relation(self.relation)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "target_type", target_type)
        object.__setattr__(self, "relation", relation)
        object.__setattr__(self, "source_value", _normalize_node_value(source_type, self.source_value))
        object.__setattr__(self, "target_value", _normalize_node_value(target_type, self.target_value))
        allowed_sources, allowed_targets = _RELATION_ENDPOINTS[relation]
        if source_type not in allowed_sources or target_type not in allowed_targets:
            raise ValueError(
                f"relation {relation.value} does not allow "
                f"{source_type.value}->{target_type.value}"
            )
        if (self.source_type, self.source_value) == (self.target_type, self.target_value):
            raise ValueError("graph edge must not be a self-loop")
        object.__setattr__(self, "provenance", _clean_provenance(self.provenance))
        object.__setattr__(self, "confidence", _validate_optional_confidence(self.confidence))

    @property
    def id(self) -> str:
        return stable_digest(
            "apkscan.attribution/graph-edge",
            {
                "relation": self.relation.value,
                "source_type": self.source_type.value,
                "source_value": self.source_value,
                "target_type": self.target_type.value,
                "target_value": self.target_value,
            },
        )

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.relation.value,
            self.source_type.value,
            self.source_value,
            self.target_type.value,
            self.target_value,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "relation": self.relation.value,
            "source": {"type": self.source_type.value, "value": self.source_value},
            "target": {"type": self.target_type.value, "value": self.target_value},
            "provenance": list(self.provenance),
            "confidence": self.confidence,
        }


@dataclass(frozen=True, kw_only=True)
class GraphIssue:
    """A quarantined fact, referenced by its fact id (never a positional index)."""

    stage: str
    reference: str
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", _clean_identifier("stage", self.stage))
        object.__setattr__(self, "reference", _clean_identifier("reference", self.reference))
        object.__setattr__(self, "reason", _clean_identifier("reason", self.reason))

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.stage, self.reference, self.reason)

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "reference": self.reference, "reason": self.reason}


def _as_object_tuple(name: str, value: object, cls: type) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{name} must be a non-string iterable of {cls.__name__}")
    items = tuple(value)
    for item in items:
        if not isinstance(item, cls):
            raise TypeError(f"{name} must contain {cls.__name__}, got {type(item).__name__}")
    return items


@dataclass(frozen=True, kw_only=True)
class InfrastructureGraph:
    """A deterministic, referentially-closed per-artifact attribution graph."""

    artifact_id: str
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    issues: tuple[GraphIssue, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _clean_identifier("artifact_id", self.artifact_id))

        nodes = _as_object_tuple("nodes", self.nodes, GraphNode)
        node_by_key: dict[tuple[GraphNodeType, str], GraphNode] = {}
        for node in nodes:
            if node.key in node_by_key:
                raise ValueError(
                    f"duplicate node for {node.key[0].value} {node.key[1]!r}"
                )
            node_by_key[node.key] = node
        object.__setattr__(
            self,
            "nodes",
            tuple(sorted(node_by_key.values(), key=lambda n: (n.node_type.value, n.value))),
        )

        edges = _as_object_tuple("edges", self.edges, GraphEdge)
        edge_by_key: dict[tuple[str, str, str, str, str], GraphEdge] = {}
        for edge in edges:
            if edge.key in edge_by_key:
                raise ValueError(f"duplicate edge for {edge.key}")
            edge_by_key[edge.key] = edge
        object.__setattr__(
            self, "edges", tuple(sorted(edge_by_key.values(), key=lambda e: e.key))
        )

        issues = _as_object_tuple("issues", self.issues, GraphIssue)
        object.__setattr__(
            self, "issues", tuple(sorted({i.key: i for i in issues}.values(), key=lambda i: i.key))
        )

        node_keys = set(node_by_key)
        for edge in self.edges:
            if (edge.source_type, edge.source_value) not in node_keys:
                raise ValueError(
                    f"edge source has no node: {edge.source_type.value} {edge.source_value!r}"
                )
            if (edge.target_type, edge.target_value) not in node_keys:
                raise ValueError(
                    f"edge target has no node: {edge.target_type.value} {edge.target_value!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "issues": [issue.to_dict() for issue in self.issues],
        }


# --------------------------------------------------------------------------- #
# Builder                                                                      #
# --------------------------------------------------------------------------- #
_NodeRef = tuple[GraphNodeType, str]
_EdgeKey = tuple[str, str, str, str, str]


@dataclass
class _NodeData:
    ref: _NodeRef
    sources: set[str] = field(default_factory=set)
    provenance: set[str] = field(default_factory=set)
    roles: list[RoleScore] = field(default_factory=list)


@dataclass
class _EdgeData:
    source: _NodeRef
    relation: GraphRelation
    target: _NodeRef
    provenance: set[str] = field(default_factory=set)
    confidences: list[float] = field(default_factory=list)


class _Accumulator:
    """Deterministic key-based accumulator; sorted only at ``build()`` time."""

    def __init__(self, artifact_id: str) -> None:
        self.artifact_id = artifact_id
        self.nodes: dict[_NodeRef, _NodeData] = {}
        self.edges: dict[_EdgeKey, _EdgeData] = {}
        self.issues: set[tuple[str, str, str]] = set()

    def add_node(self, ref: _NodeRef, sources: Iterable[str], provenance: str) -> _NodeData:
        data = self.nodes.get(ref)
        if data is None:
            data = _NodeData(ref)
            self.nodes[ref] = data
        for source in sources:
            if source:
                data.sources.add(source)
        if provenance:
            data.provenance.add(provenance)
        return data

    def add_edge(
        self, source: _NodeRef, relation: GraphRelation, target: _NodeRef, evidence: AttributionEvidence
    ) -> None:
        key = (relation.value, source[0].value, source[1], target[0].value, target[1])
        data = self.edges.get(key)
        if data is None:
            data = _EdgeData(source, relation, target)
            self.edges[key] = data
        data.provenance.add(evidence.id)
        data.confidences.append(evidence.confidence)

    def add_issue(self, stage: str, reference: str, reason: str) -> None:
        self.issues.add((stage, reference, reason))

    def add_contacted(self, target: _NodeRef, evidence: AttributionEvidence) -> None:
        apk_ref = (GraphNodeType.APK, self.artifact_id)
        self.add_node(apk_ref, (), evidence.id)
        self.add_edge(apk_ref, GraphRelation.CONTACTED, target, evidence)

    def build(self) -> InfrastructureGraph:
        nodes = tuple(
            GraphNode(
                node_type=ref[0],
                value=ref[1],
                sources=tuple(sorted(data.sources)),
                roles=tuple(data.roles),
                provenance=tuple(sorted(data.provenance)),
            )
            for ref, data in self.nodes.items()
        )
        edges = tuple(
            GraphEdge(
                source_type=data.source[0],
                source_value=data.source[1],
                relation=data.relation,
                target_type=data.target[0],
                target_value=data.target[1],
                provenance=tuple(sorted(data.provenance)),
                confidence=max(data.confidences) if data.confidences else None,
            )
            for data in self.edges.values()
            if data.source in self.nodes and data.target in self.nodes
        )
        issues = tuple(
            GraphIssue(stage=stage, reference=reference, reason=reason)
            for stage, reference, reason in self.issues
        )
        return InfrastructureGraph(
            artifact_id=self.artifact_id, nodes=nodes, edges=edges, issues=issues
        )


def _fold_host(value: str) -> _NodeRef:
    _authority, host, _port, is_ip = normalize_authority(value)
    return (GraphNodeType.IP, host) if is_ip else (GraphNodeType.DOMAIN, host)


def _entity_ref(entity: NetworkEntity) -> _NodeRef | None:
    """A node ref for an entity, folding HOST onto DOMAIN/IP; None for kinds that
    are not v1 graph nodes (URL/PROVIDER/NETWORK_CLUSTER) or a value that fails
    normalization."""
    node_type = _NETWORK_KIND_TO_NODE.get(entity.kind)
    try:
        if node_type is not None:
            return (node_type, _normalize_node_value(node_type, entity.value))
        if entity.kind is NetworkEntityType.HOST:
            return _fold_host(entity.value)
    except (ValueError, TypeError):
        return None
    return None


def _far_node(
    acc: _Accumulator, evidence: AttributionEvidence, node_type: GraphNodeType, raw: object
) -> _NodeRef | None:
    """Normalize a far-endpoint value into an admitted node, or quarantine it."""
    if not isinstance(raw, str):
        acc.add_issue(evidence.type, evidence.id, f"non-string {node_type.value} value")
        return None
    try:
        value = _normalize_node_value(node_type, raw)
    except (ValueError, TypeError):
        acc.add_issue(evidence.type, evidence.id, f"invalid {node_type.value} value")
        return None
    ref = (node_type, value)
    acc.add_node(ref, (evidence.source,), evidence.id)
    return ref


def _far_host_from_url(acc: _Accumulator, evidence: AttributionEvidence, raw: object) -> _NodeRef | None:
    if isinstance(raw, str):
        try:
            # urlsplit itself raises ValueError on a bracket-malformed netloc
            # (e.g. 'http://[::1'), so it must be inside the guard too.
            parsed = urlsplit(raw)
            ref = _fold_host(parsed.netloc) if parsed.netloc else None
        except ValueError:
            ref = None
        if ref is not None:
            acc.add_node(ref, (evidence.source,), evidence.id)
            return ref
    acc.add_issue(evidence.type, evidence.id, "invalid redirect location")
    return None


def _h_contacted(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] in (GraphNodeType.DOMAIN, GraphNodeType.IP):
        acc.add_contacted(target, ev)


def _h_tls_sni(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.DOMAIN:
        return
    acc.add_contacted(target, ev)
    far = _far_node(acc, ev, GraphNodeType.IP, ev.value)
    if far is not None:
        acc.add_edge(target, GraphRelation.SERVED_AT, far, ev)


def _h_http_redirect(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] not in (GraphNodeType.DOMAIN, GraphNodeType.IP):
        return
    acc.add_contacted(target, ev)
    far = _far_host_from_url(acc, ev, ev.value)
    if far is not None and far != target:
        acc.add_edge(target, GraphRelation.REDIRECTS_TO, far, ev)


def _h_dns_resolution(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    # inverted: evidence target = answer IP, value = qname -> DOMAIN(value) RESOLVES_TO IP(target)
    if target[0] is not GraphNodeType.IP:
        return
    far = _far_node(acc, ev, GraphNodeType.DOMAIN, ev.value)
    if far is not None:
        acc.add_edge(far, GraphRelation.RESOLVES_TO, target, ev)


def _h_dns_alias(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.DOMAIN:
        return
    far = _far_node(acc, ev, GraphNodeType.DOMAIN, ev.value)
    if far is not None and far != target:
        acc.add_edge(target, GraphRelation.ALIAS_OF, far, ev)


def _h_resolved_ip(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.DOMAIN:
        return
    far = _far_node(acc, ev, GraphNodeType.IP, ev.value)
    if far is not None:
        acc.add_edge(target, GraphRelation.RESOLVES_TO, far, ev)


def _h_related_ip(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.DOMAIN:
        return
    far = _far_node(acc, ev, GraphNodeType.IP, ev.value)
    if far is not None:
        acc.add_edge(target, GraphRelation.INTEL_RELATED, far, ev)


def _h_related_hostname(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] not in (GraphNodeType.DOMAIN, GraphNodeType.IP):
        return
    far = _far_node(acc, ev, GraphNodeType.DOMAIN, ev.value)
    if far is not None and far != target:
        acc.add_edge(target, GraphRelation.INTEL_RELATED, far, ev)


def _h_asn(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.IP:
        return
    far = _far_node(acc, ev, GraphNodeType.ASN, _asn_str(ev.value))
    if far is not None:
        acc.add_edge(target, GraphRelation.IN_ASN, far, ev)


def _h_cert_san(acc: _Accumulator, ev: AttributionEvidence, target: _NodeRef) -> None:
    if target[0] is not GraphNodeType.CERTIFICATE:
        return
    far = _far_node(acc, ev, GraphNodeType.DOMAIN, ev.value)
    if far is not None:
        acc.add_edge(target, GraphRelation.CERTIFIES, far, ev)


def _asn_str(value: object) -> object:
    # ASN evidence value is an int; _normalize_asn_value needs a str. bool is
    # rejected (bool is an int subclass); leave non-int/str values to be quarantined.
    if isinstance(value, bool):
        return value  # non-str -> _far_node records an issue
    if isinstance(value, int):
        return str(value)
    return value


#: The single closed edge registry. A type NOT here is provenance-only (never an
#: edge, never an issue). Covered by an exact-equality policy test.
_EDGE_HANDLERS: MappingProxyType[
    str, Callable[[_Accumulator, AttributionEvidence, _NodeRef], None]
] = MappingProxyType(
    {
        "network_flow": _h_contacted,
        "http_request": _h_contacted,
        "http_response": _h_contacted,
        "http_redirect": _h_http_redirect,
        "tls_sni": _h_tls_sni,
        "dns_resolution": _h_dns_resolution,
        "dns_alias": _h_dns_alias,
        "resolved_ip": _h_resolved_ip,
        "related_ip": _h_related_ip,
        "related_hostname": _h_related_hostname,
        "asn": _h_asn,
        "cert_san_dns": _h_cert_san,
    }
)


def _as_input_tuple(name: str, value: object, cls: type) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{name} must be a non-string iterable of {cls.__name__}")
    items = tuple(value)
    for item in items:
        if not isinstance(item, cls):
            raise TypeError(f"{name} must contain {cls.__name__}, got {type(item).__name__}")
    return items


def _evidence_pool(*groups: Iterable[AttributionEvidence]) -> dict[str, AttributionEvidence]:
    pool: dict[str, AttributionEvidence] = {}
    payloads: dict[str, dict[str, Any]] = {}
    for group in groups:
        for evidence in group:
            payload = evidence.to_dict()
            existing = payloads.get(evidence.id)
            if existing is None:
                payloads[evidence.id] = payload
                pool[evidence.id] = evidence
            elif existing != payload:
                raise ValueError(f"conflicting evidence for id {evidence.id!r}")
    return pool


def _role_evidence(role_scores: Iterable[RoleScore]) -> list[AttributionEvidence]:
    collected: list[AttributionEvidence] = []
    for score in role_scores:
        for contribution in score.contributions:
            for feature in contribution.features:
                collected.append(feature.evidence)
    return collected


def build_infrastructure_graph(
    *,
    artifact_id: str,
    conversions: Iterable[ConversionResult] = (),
    role_scores: Iterable[RoleScore] = (),
    extra_evidence: Iterable[AttributionEvidence] = (),
) -> InfrastructureGraph:
    """Assemble the infrastructure attribution graph for one analyzed artifact.

    Pure and deterministic: the same inputs (in any order) yield a byte-identical
    ``to_dict()``. Intel evidence reaches the graph via ``extra_evidence`` — this
    module imports nothing from the intel package (importing it would pull the
    provider adapters and ``requests`` into every consumer). ``RoleScore`` is
    consumed verbatim as a node annotation; roles are never re-derived.
    """
    # Lazy import breaks the converters<->attribution package import cycle.
    from apkscan.network.converters import ConversionResult, merge_conversion_results

    artifact = _clean_identifier("artifact_id", artifact_id)
    conversion_list = _as_input_tuple("conversions", conversions, ConversionResult)
    role_list = _as_input_tuple("role_scores", role_scores, RoleScore)
    extra_list = _as_input_tuple("extra_evidence", extra_evidence, AttributionEvidence)

    # Observations come from the merged result (deterministic, provenance-only), but
    # the evidence pool is built from the RAW per-conversion evidence: merge's
    # first-seen-wins would silently resolve a same-id/different-payload conflict by
    # input order, so pooling the raw facts makes the conflict raise regardless of
    # order (permutation-invariant), matching the iron law.
    merged = merge_conversion_results(*conversion_list) if conversion_list else None
    observations: tuple[Observation, ...] = merged.observations if merged is not None else ()

    pool = _evidence_pool(
        *(result.evidence for result in conversion_list),
        extra_list,
        _role_evidence(role_list),
    )

    acc = _Accumulator(artifact)

    # 1. Lift every pooled evidence: admit its target node, then apply the edge rule.
    for evidence in pool.values():
        target = _entity_ref(evidence.target)
        if target is not None:
            acc.add_node(target, evidence.target.sources, evidence.id)
            handler = _EDGE_HANDLERS.get(evidence.type)
            if handler is not None:
                handler(acc, evidence, target)

    # 2. Attach role annotations to already-admitted nodes (contribution evidence
    #    was pooled above, so a role's target node is admitted with its provenance).
    #    Only attach when the role target's kind is exactly the node's network kind:
    #    a HOST-kind target folds onto a DOMAIN/IP node whose kind would not match,
    #    so GraphNode._normalize_roles would reject it — quarantine instead of crash.
    for score in role_list:
        ref = _entity_ref(score.target)
        if ref is None or ref not in acc.nodes or ref[0] is GraphNodeType.APK:
            continue
        if _NODE_TO_NETWORK_KIND.get(ref[0]) is not score.target.kind:
            acc.add_issue(
                "role",
                f"{score.role.value}@{ref[0].value}:{ref[1]}",
                "role target kind is not the folded node kind",
            )
            continue
        acc.nodes[ref].roles.append(score)

    # 3. Fold observation ids into the provenance of nodes already admitted by
    #    evidence — never creating a node (which drops the device src IP).
    for observation in observations:
        for entity in observation.entities:
            ref = _entity_ref(entity)
            if ref is not None and ref in acc.nodes:
                node = acc.nodes[ref]
                node.provenance.add(observation.id)
                for source in entity.sources:
                    if source:
                        node.sources.add(source)

    return acc.build()
