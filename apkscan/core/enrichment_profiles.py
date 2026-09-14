"""Explicit enrichment stages; configuration inventory never reveals values."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

BASELINE = frozenset({"rdap", "ip_rdap", "asn", "certs", "ripestat_bgp", "dns_records", "cymru", "internetdb"})
OPTIONAL = frozenset({"threatbook", "whoisxml"})
# Version invalidation is deliberately narrow: old trustworthy sources remain resumable.
CONTRACTS = {"censys": 2, "zoomeye": 2, "shodan": 2, "quake": 2}


def configuration_issues(enrichers: Sequence[Any], env: Mapping[str, str]) -> list[dict[str, str]]:
    issues = []
    for e in enrichers:
        if e.name not in {"fofa", "quake", "zoomeye"}:
            continue
        name = f"FXAPK_{e.name.upper()}_URL"
        value = env.get(name, "").strip()
        if not value:
            continue
        try:
            url = urlsplit(value)
            valid = url.scheme == "https" and bool(url.hostname) and not (url.username or url.password or url.query or url.fragment)
        except ValueError:
            valid = False
        if not valid:
            issues.append({"provider": e.name, "variable": name, "error": "expected_https_base_or_endpoint_without_credentials_or_query"})
    return issues


def select_enrichers(enrichers: Sequence[Any], stage: str, providers: str = "") -> list[Any]:
    if stage not in {"all", "baseline", "api"}:
        raise ValueError("stage must be all, baseline or api")
    requested = {p.strip() for p in providers.split(",") if p.strip()}
    available = {e.name for e in enrichers}
    if requested - available:
        raise ValueError("unknown providers: " + ", ".join(sorted(requested - available)))
    selected = []
    for e in enrichers:
        baseline = e.name in BASELINE
        if (stage == "baseline" and not baseline) or (stage == "api" and baseline):
            continue
        # The richer DNS view replaces the old resolver only within this batch entrypoint.
        if e.name == "dns" and "dns_records" in available and e.name not in requested:
            continue
        if requested and e.name not in requested:
            continue
        if e.name in OPTIONAL:
            e.explicitly_selected = e.name in requested
        selected.append(e)
    if requested - {e.name for e in selected}:
        raise ValueError("requested provider is outside selected stage")
    return sorted(selected, key=lambda e: (e.name not in BASELINE, e.name))


def api_inventory(enrichers: Sequence[Any], env: Mapping[str, str]) -> dict[str, object]:
    services = []
    referenced = set()
    for e in sorted(enrichers, key=lambda x: x.name):
        keys = tuple(getattr(e, "required_env", ()))
        # These legacy adapters discover keys internally.
        if e.name == "shodan":
            keys = ("FXAPK_SHODAN_KEY", "SHODAN_API_KEY")
        if e.name == "icp":
            keys = ("FXAPK_ICP_HAPI_KEY",)
        if e.name == "urlscan":
            keys = ("FXAPK_URLSCAN_KEY", "URLSCAN_API_KEY")
        referenced.update(keys)
        services.append({"provider": e.name, "stage": "baseline" if e.name in BASELINE else "api",
                         "credentials": [{"name": k, "configured": bool(env.get(k, "").strip())} for k in keys],
                         "implemented": True, "requires_product_check": e.name in OPTIONAL,
                         "live_health": "not_checked", "applies_to": list(e.applies_to)})
    unknown = [k for k in env if k == "NGHIMMO_API_KEY" and k not in referenced and env[k]]
    return {"services": services, "configured_without_adapter": unknown,
            "note": "Configuration presence is not proof of permissions, quota, successful queries or attribution."}
