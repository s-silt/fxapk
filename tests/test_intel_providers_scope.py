"""PR6 scope / backward-compatibility conformance.

Proves the adapters are inert: exported deterministically, unwired from
auto-discovery, credential-compatible with the legacy enrichers, passive, and
touching no runtime code or network at import time.
"""

from __future__ import annotations

import importlib
import pathlib
import re
import socket

import pytest

import apkscan.intel
import apkscan.intel.providers as providers
from apkscan.core.registry import BaseEnricher, discover_enrichers
from apkscan.enrichers.multisource import (
    CensysPassiveEnricher,
    FofaPassiveEnricher,
    HunterPassiveEnricher,
    configured_case_close_enrichers,
)
from apkscan.enrichers.shodan import ShodanEnricher
from apkscan.intel import IntelCapability
from apkscan.intel.providers._http import _HttpIntelProvider
from apkscan.intel.providers.censys import CensysIntelProvider
from apkscan.intel.providers.fofa import FofaIntelProvider
from apkscan.intel.providers.hunter import HunterIntelProvider
from apkscan.intel.providers.shodan import ShodanIntelProvider

_ADAPTERS = [FofaIntelProvider, HunterIntelProvider, ShodanIntelProvider, CensysIntelProvider]


def test_providers_all_sorted_and_extended() -> None:
    assert providers.__all__ == sorted(providers.__all__)
    assert set(providers.__all__) == {
        "CensysIntelProvider",
        "FofaIntelProvider",
        "HunterIntelProvider",
        "IntelProvider",
        "ProviderContractError",
        "ShodanIntelProvider",
    }


def test_top_level_intel_all_unchanged() -> None:
    assert apkscan.intel.__all__ == [
        "CAPABILITY_ENTITY_KIND",
        "IntelCapability",
        "IntelProvider",
        "IntelResult",
        "IntelStatus",
        "ProviderContractError",
        "validate_certificate_value",
    ]


def test_adapters_not_auto_discovered() -> None:
    discovered = discover_enrichers()
    assert not any(type(inst).__module__.startswith("apkscan.intel") for inst in discovered)
    for cls in _ADAPTERS:
        assert not issubclass(cls, BaseEnricher)


def test_case_close_enricher_set_unchanged() -> None:
    names = {enricher.name for enricher in configured_case_close_enrichers()}
    assert names == {
        "ripestat_bgp", "fofa", "quake", "hunter", "zoomeye",
        "censys", "virustotal", "otx", "urlscan",
    }


def test_env_alias_parity_with_legacy_enrichers() -> None:
    assert FofaIntelProvider.required_env == FofaPassiveEnricher.required_env == ("FXAPK_FOFA_KEY",)
    assert HunterIntelProvider.required_env == HunterPassiveEnricher.required_env == ("FXAPK_HUNTER_KEY",)
    assert ShodanIntelProvider.required_env == ShodanEnricher.required_env == (
        "FXAPK_SHODAN_KEY", "SHODAN_API_KEY",
    )
    assert CensysIntelProvider.required_env == CensysPassiveEnricher.required_env == (
        "FXAPK_CENSYS_TOKEN", "CENSYS_API_TOKEN",
    )


def test_active_is_exactly_false_declared() -> None:
    for cls in _ADAPTERS:
        assert cls.active is False
        assert "active" in cls.__dict__


def test_capability_sets_exact() -> None:
    ip_domain = frozenset({IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_DOMAIN})
    assert FofaIntelProvider.capabilities == ip_domain
    assert HunterIntelProvider.capabilities == ip_domain
    assert ShodanIntelProvider.capabilities == ip_domain
    assert CensysIntelProvider.capabilities == frozenset(
        {IntelCapability.LOOKUP_IP, IntelCapability.LOOKUP_CERT}
    )
    assert IntelCapability.LOOKUP_CERT not in FofaIntelProvider.capabilities


# Absolute dotted, relative (from .intel / from ..intel), `import intel`, and any
# constructed 'intel.providers' string (importlib) — all the natural wiring spellings.
_INTEL_REF = re.compile(r"apkscan\.intel|from\s+\.+intel|import\s+intel\b|intel\.providers")


def test_no_runtime_module_references_intel() -> None:
    root = pathlib.Path(apkscan.__file__).parent
    intel_dir = root / "intel"
    offenders = []
    for path in root.rglob("*.py"):
        if intel_dir in path.parents or path == intel_dir:
            continue
        if _INTEL_REF.search(path.read_text(encoding="utf-8")):
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == [], f"runtime modules must not reference apkscan.intel: {offenders}"


def test_concrete_adapter_requires_api_authority() -> None:
    # A concrete leaf (implemented _fetch) with no _API_AUTHORITY must fail at
    # class-definition time, not defer to a per-lookup InvalidURL.
    with pytest.raises(ValueError):

        class _NoAuth(_HttpIntelProvider):
            name = "noauth"
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = ()
            active = False

            def _request_spec(self, capability, query):  # pragma: no cover - never reached
                raise AssertionError

            def _interpret(self, capability, query, payload):  # pragma: no cover
                raise AssertionError

            def _fetch(self, capability, query):  # pragma: no cover
                return self._fetch_via_http(capability, query)


def test_adapter_import_touches_no_network(monkeypatch) -> None:
    def _no_socket(*_a: object, **_k: object) -> None:
        raise AssertionError("no network at import time")

    monkeypatch.setattr(socket, "socket", _no_socket)
    for name in (
        "apkscan.intel.providers._http",
        "apkscan.intel.providers.fofa",
        "apkscan.intel.providers.hunter",
        "apkscan.intel.providers.shodan",
        "apkscan.intel.providers.censys",
    ):
        importlib.reload(importlib.import_module(name))


@pytest.mark.parametrize("cls", _ADAPTERS, ids=[c.name for c in _ADAPTERS])
def test_construct_without_env_or_session_is_pure(cls) -> None:
    # No env, no injected session: construction must not read a key or touch the
    # network (a Session is built lazily, credentials read only in _request_spec).
    provider = cls()
    assert provider.name == cls.name
