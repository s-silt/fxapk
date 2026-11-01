"""Occurrence identity is provenance, not a claim of business relevance."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from apkscan.core.integrity import sha256_canonical_json


@dataclass(frozen=True)
class DexStringRecord:
    value: str
    provenance: dict = field(default_factory=dict)
    locator: dict = field(default_factory=dict)


def occurrence_id(evidence: object) -> str | None:
    """Do not manufacture coordinates for old or unlocated observations."""
    def get(name: str, default: object = None) -> object:
        return evidence.get(name, default) if isinstance(evidence, Mapping) else getattr(
            evidence, name, default
        )

    locator = get("locator")
    provenance = get("provenance")
    if (
        not isinstance(locator, Mapping)
        or not locator
        or not isinstance(provenance, Mapping)
        or not provenance
    ):
        return None
    return "occ-v1-" + sha256_canonical_json({
        "source": get("source", ""),
        "location": get("location", ""),
        "provenance": provenance,
        "locator": locator,
        "observed_at": get("observed_at"),
    })


def evidence_identity(evidence: object) -> tuple[object, ...]:
    """Dedup exact observations only; neither weak nor strong copies overwrite facts."""
    def get(name: str, default: object = None) -> object:
        return evidence.get(name, default) if isinstance(evidence, Mapping) else getattr(evidence, name, default)

    scope = get("scope", "legacy_unspecified")
    return (
        get("source", ""), get("location", ""), get("snippet", ""),
        getattr(scope, "value", scope), get("observed_at"),
        json.dumps({
            "provenance": get("provenance", {}),
            "locator": get("locator", {}),
            "structure_status": get("structure_status", "unknown"),
            "reference_status": get("reference_status", "unknown"),
            "reachability": get("reachability", "unknown"),
            "suspicions": get("suspicions", []),
        }, sort_keys=True, ensure_ascii=True, separators=(",", ":")),
    )
