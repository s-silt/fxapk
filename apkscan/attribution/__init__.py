"""Network infrastructure attribution models and explainable role inference."""

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
    "InfrastructureRole",
    "MissingScoreEvidence",
    "RoleAssessment",
    "RoleClassifier",
    "RoleFeature",
    "RoleScore",
    "RoleSignal",
    "ScoreContribution",
]
