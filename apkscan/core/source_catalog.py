"""Dated, read-only source product catalog; never an entitlement or live quota.

Keep commercial descriptions out of transport adapters and evidence verdicts.
This catalog informs selection; only the existing execution gates run queries.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml

_CATEGORIES = ("all", "free", "registered", "paid")


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    # Both loaders are safe constructors; use libyaml when available to avoid
    # a large one-time pure-Python parse on the first pre-report projection.
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    payload = yaml.load(files("apkscan").joinpath("rules/source_access.yaml").read_text(encoding="utf-8"), Loader=loader)
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        raise ValueError("invalid_source_catalog")
    seen = set()
    for row in payload["sources"]:
        if (not isinstance(row, dict) or not isinstance(row.get("provider_key"), str)
                or row["provider_key"] in seen or not isinstance(row.get("access_tiers"), list)):
            raise ValueError("invalid_source_catalog_entry")
        seen.add(row["provider_key"])
    return payload


@lru_cache(maxsize=1)
def _providers() -> dict[str, dict[str, Any]]:
    return {row["provider_key"]: row for row in _catalog()["sources"]}


def _category(tier: str) -> str:
    if tier.startswith("free_no_registration"):
        return "free"
    if tier.startswith(("registered", "commercial_trial")):
        return "registered"
    return "paid" if tier.startswith("paid") else "unknown"


def source_catalog(*, category: str = "all") -> dict[str, Any]:
    if category not in _CATEGORIES:
        raise ValueError("invalid_source_category")
    result = deepcopy(_catalog())
    rows = []
    for row in result["sources"]:
        for tier in row["access_tiers"]:
            tier["category"] = _category(tier["tier"])
        if category == "all" or any(t["category"] == category for t in row["access_tiers"]):
            rows.append(row)
    result["sources"] = rows
    result.update(category=category, network_requests=0, automatic_purchase=False,
                  account_entitlements_verified=False, product_catalog_not_execution_policy=True)
    return result


def source_access_summary(provider: str) -> dict[str, Any]:
    """Small advisory attached to a worklist, without copying account or secret data."""
    # Unknown adapters are explicit gaps, never presumed free or usable.
    row = _providers().get(provider)
    if row is None:
        return {"status": "not_catalogued", "account_entitlements_verified": False}
    return {"status": "review_product_and_usage_terms",
            "catalog_verified_on": row["verified_on"],
            "access_categories": sorted({_category(t["tier"]) for t in row["access_tiers"]}),
            "api_access_caveat": row["api_access_caveat"],
            "institutional_use_status": row["institutional_use_status"],
            "account_entitlements_verified": False}
