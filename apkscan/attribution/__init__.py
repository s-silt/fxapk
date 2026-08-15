"""Network infrastructure attribution models and explainable role inference."""

from apkscan.attribution.graph import (
    GraphEdge,
    GraphIssue,
    GraphNode,
    GraphNodeType,
    GraphRelation,
    InfrastructureGraph,
    build_infrastructure_graph,
)
from apkscan.attribution.models import AttributionEvidence
from apkscan.attribution.roles import (
    InfrastructureRole,
    RoleAssessment,
    RoleClassifier,
    RoleFeature,
    RoleSignal,
)
from apkscan.attribution.scorer import (
    EvidenceScorer,
    MissingScoreEvidence,
    RoleScore,
    ScoreContribution,
)

__all__ = [
    "AttributionEvidence",
    "EvidenceScorer",
    "GraphEdge",
    "GraphIssue",
    "GraphNode",
    "GraphNodeType",
    "GraphRelation",
    "InfrastructureGraph",
    "InfrastructureRole",
    "MissingScoreEvidence",
    "RoleAssessment",
    "RoleClassifier",
    "RoleFeature",
    "RoleScore",
    "RoleSignal",
    "ScoreContribution",
    "build_infrastructure_graph",
]
