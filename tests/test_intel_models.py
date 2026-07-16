"""PR5 intel value-object tests: enums, capability map, cert validator, IntelResult."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest

from apkscan.attribution import AttributionEvidence
from apkscan.attribution import models as attribution_models
from apkscan.intel import models as intel_models
from apkscan.intel.models import (
    CAPABILITY_ENTITY_KIND,
    IntelCapability,
    IntelResult,
    IntelStatus,
    ProviderContractError,
    validate_certificate_value,
)
from apkscan.network import NetworkEntity, NetworkEntityType

_HEX64 = "a" * 64
_CANONICAL_CERT = f"sha256:{_HEX64}"


def _ip_entity(value: str = "1.2.3.4", *, sources: tuple[str, ...] = ("pcap",)) -> NetworkEntity:
    return NetworkEntity(NetworkEntityType.IP, value, sources)


def _evidence(
    *,
    id_: str = "ev-1",
    source: str = "example",
    target: NetworkEntity | None = None,
) -> AttributionEvidence:
    return AttributionEvidence(
        id=id_,
        source=source,
        type="geo",
        target=target or _ip_entity(),
        value="US",
        confidence=0.5,
    )


# ---- Task 1: enums, capability map, cert validator ----


def test_capability_members_and_values() -> None:
    assert IntelCapability.LOOKUP_IP.value == "lookup_ip"
    assert IntelCapability.LOOKUP_DOMAIN.value == "lookup_domain"
    assert IntelCapability.LOOKUP_CERT.value == "lookup_cert"
    assert isinstance(IntelCapability.LOOKUP_IP, str)


def test_status_members_and_values() -> None:
    assert {s.value for s in IntelStatus} == {
        "success",
        "empty",
        "unsupported",
        "unavailable",
        "failure",
    }
    assert isinstance(IntelStatus.SUCCESS, str)


def test_enums_are_json_safe() -> None:
    assert json.dumps(IntelCapability.LOOKUP_IP) == '"lookup_ip"'
    assert json.dumps(IntelStatus.FAILURE) == '"failure"'


def test_capability_entity_kind_map_is_readonly_and_total() -> None:
    assert isinstance(CAPABILITY_ENTITY_KIND, MappingProxyType)
    assert CAPABILITY_ENTITY_KIND[IntelCapability.LOOKUP_IP] is NetworkEntityType.IP
    assert CAPABILITY_ENTITY_KIND[IntelCapability.LOOKUP_DOMAIN] is NetworkEntityType.DOMAIN
    assert CAPABILITY_ENTITY_KIND[IntelCapability.LOOKUP_CERT] is NetworkEntityType.CERTIFICATE
    assert set(CAPABILITY_ENTITY_KIND) == set(IntelCapability)
    with pytest.raises(TypeError):
        CAPABILITY_ENTITY_KIND[IntelCapability.LOOKUP_IP] = NetworkEntityType.DOMAIN  # type: ignore[index]


def test_validate_certificate_value_accepts_canonical() -> None:
    """v1 canonical = SHA-256 leaf-certificate DER fingerprint; SPKI/serial/PEM deferred."""
    assert validate_certificate_value(_CANONICAL_CERT) == _CANONICAL_CERT


@pytest.mark.parametrize(
    "bad",
    [
        f"sha256:{'A' * 64}",  # uppercase hex
        f"sha256:{'a' * 63}",  # too short
        f"sha256:{'a' * 65}",  # too long
        "sha256:" + ":".join(["ab"] * 32),  # colon-pair separators
        f"sha1:{'a' * 40}",  # other algorithm
        f"0x{'a' * 64}",  # 0x prefix
        _HEX64,  # missing prefix
        f"SHA256:{_HEX64}",  # uppercase prefix
        f"sha256:{'g' * 64}",  # non-hex
        f"{_CANONICAL_CERT}\n",  # trailing LF (re.match with $ would accept)
        f"\n{_CANONICAL_CERT}",  # leading LF
        f"{_CANONICAL_CERT}\r\n",  # trailing CRLF
        f"{_CANONICAL_CERT}\r",  # trailing CR
        f"{_CANONICAL_CERT}\nsha256:{'b' * 64}",  # multiline injection
    ],
)
def test_validate_certificate_value_rejects_noncanonical(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_certificate_value(bad)


def test_cert_validator_uses_fullmatch_not_match() -> None:
    """`$` in re.match accepts a final newline; canonical values must reject it."""
    with pytest.raises(ValueError):
        validate_certificate_value(f"{_CANONICAL_CERT}\n")


def test_models_imports_attribution_evidence_directly() -> None:
    """models must import from apkscan.attribution.models, not the package facade."""
    assert intel_models.AttributionEvidence is attribution_models.AttributionEvidence


def test_validate_certificate_value_rejects_non_str() -> None:
    with pytest.raises(TypeError):
        validate_certificate_value(123)  # type: ignore[arg-type]


# ---- Task 2: IntelResult invariants ----


def test_success_result_valid() -> None:
    ev = _evidence()
    result = IntelResult(
        provider="example",
        capability=IntelCapability.LOOKUP_IP,
        query=_ip_entity(),
        status=IntelStatus.SUCCESS,
        evidence=(ev,),
        reason=None,
    )
    assert result.status is IntelStatus.SUCCESS
    assert result.evidence == (ev,)


def test_result_is_frozen() -> None:
    result = IntelResult.empty("example", IntelCapability.LOOKUP_IP, _ip_entity())
    with pytest.raises(FrozenInstanceError):
        result.status = IntelStatus.SUCCESS  # type: ignore[misc]


def test_result_requires_keyword_only() -> None:
    with pytest.raises(TypeError):
        IntelResult("example", IntelCapability.LOOKUP_IP, _ip_entity())  # type: ignore[misc]


@pytest.mark.parametrize("bad", ["Example", "ex ample", "ex-ample", "1example", "", "ex\t"])
def test_result_rejects_bad_provider(bad: str) -> None:
    with pytest.raises((ValueError, TypeError)):
        IntelResult.empty(bad, IntelCapability.LOOKUP_IP, _ip_entity())


def test_result_query_must_be_network_entity() -> None:
    with pytest.raises(TypeError):
        IntelResult.empty("example", IntelCapability.LOOKUP_IP, "1.2.3.4")  # type: ignore[arg-type]


def test_evidence_source_must_equal_provider() -> None:
    with pytest.raises(ValueError):
        IntelResult(
            provider="example",
            capability=IntelCapability.LOOKUP_IP,
            query=_ip_entity(),
            status=IntelStatus.SUCCESS,
            evidence=(_evidence(source="other"),),
            reason=None,
        )


def test_evidence_deduplicated_and_sorted() -> None:
    ev_a = _evidence(id_="a")
    ev_b = _evidence(id_="b")
    result = IntelResult(
        provider="example",
        capability=IntelCapability.LOOKUP_IP,
        query=_ip_entity(),
        status=IntelStatus.SUCCESS,
        evidence=(ev_b, ev_a, ev_b),
        reason=None,
    )
    assert [e.id for e in result.evidence] == ["a", "b"]


def test_conflicting_evidence_id_rejected() -> None:
    ev_a = _evidence(id_="dup", target=_ip_entity("1.1.1.1"))
    ev_b = _evidence(id_="dup", target=_ip_entity("2.2.2.2"))
    with pytest.raises(ValueError):
        IntelResult(
            provider="example",
            capability=IntelCapability.LOOKUP_IP,
            query=_ip_entity(),
            status=IntelStatus.SUCCESS,
            evidence=(ev_a, ev_b),
            reason=None,
        )


@pytest.mark.parametrize("status", list(IntelStatus))
def test_closed_per_status_invariants(status: IntelStatus) -> None:
    ev = _evidence()
    q = _ip_entity()
    base = {"provider": "example", "capability": IntelCapability.LOOKUP_IP, "query": q}

    if status is IntelStatus.SUCCESS:
        # valid
        IntelResult(**base, status=status, evidence=(ev,), reason=None)
        # invalid: empty evidence
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(), reason=None)
        # invalid: reason not None
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(ev,), reason="x")
    elif status is IntelStatus.EMPTY:
        IntelResult(**base, status=status, evidence=(), reason="no_records")
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(ev,), reason="no_records")
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(), reason="other")
    elif status is IntelStatus.UNSUPPORTED:
        IntelResult(**base, status=status, evidence=(), reason="capability_not_supported")
        IntelResult(**base, status=status, evidence=(), reason="entity_kind_mismatch")
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(), reason="bogus")
    elif status is IntelStatus.UNAVAILABLE:
        IntelResult(
            **base,
            status=status,
            evidence=(),
            reason="credentials_unavailable",
            missing_env=("FXAPK_X",),
        )
        with pytest.raises(ValueError):
            IntelResult(
                **base,
                status=status,
                evidence=(),
                reason="credentials_unavailable",
                missing_env=(),
            )
        with pytest.raises(ValueError):
            IntelResult(
                **base,
                status=status,
                evidence=(),
                reason="other",
                missing_env=("FXAPK_X",),
            )
    else:  # FAILURE
        IntelResult(**base, status=status, evidence=(), reason="ValueError")
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(), reason=None)
        with pytest.raises(ValueError):
            IntelResult(**base, status=status, evidence=(), reason="not an identifier")


def test_missing_env_only_for_unavailable() -> None:
    # EMPTY with a non-empty missing_env is contradictory.
    with pytest.raises(ValueError):
        IntelResult(
            provider="example",
            capability=IntelCapability.LOOKUP_IP,
            query=_ip_entity(),
            status=IntelStatus.EMPTY,
            evidence=(),
            reason="no_records",
            missing_env=("FXAPK_X",),
        )


def test_missing_env_grammar_and_sorting() -> None:
    result = IntelResult.unavailable(
        "example",
        IntelCapability.LOOKUP_IP,
        _ip_entity(),
        ("FXAPK_B", "FXAPK_A", "FXAPK_A"),
    )
    assert result.missing_env == ("FXAPK_A", "FXAPK_B")


def test_missing_env_rejects_bad_grammar() -> None:
    with pytest.raises(ValueError):
        IntelResult.unavailable(
            "example", IntelCapability.LOOKUP_IP, _ip_entity(), ("bad name",)
        )


def test_to_dict_is_json_safe_and_deterministic() -> None:
    ev = _evidence()
    result = IntelResult(
        provider="example",
        capability=IntelCapability.LOOKUP_IP,
        query=_ip_entity(),
        status=IntelStatus.SUCCESS,
        evidence=(ev,),
        reason=None,
    )
    payload = result.to_dict()
    round_tripped = json.loads(json.dumps(payload))
    assert round_tripped == payload
    assert payload["provider"] == "example"
    assert payload["capability"] == "lookup_ip"
    assert payload["status"] == "success"
    assert payload["query"] == {"type": "IP", "value": "1.2.3.4", "sources": ["pcap"]}
    assert payload["reason"] is None
    assert payload["missing_env"] == []
    assert payload["evidence"] == [ev.to_dict()]


# ---- Task 3: factories ----


def test_success_factory_requires_evidence() -> None:
    ev = _evidence()
    result = IntelResult.success("example", IntelCapability.LOOKUP_IP, _ip_entity(), (ev,))
    assert result.status is IntelStatus.SUCCESS
    assert result.reason is None
    with pytest.raises(ValueError):
        IntelResult.success("example", IntelCapability.LOOKUP_IP, _ip_entity(), ())


def test_empty_factory() -> None:
    result = IntelResult.empty("example", IntelCapability.LOOKUP_IP, _ip_entity())
    assert result.status is IntelStatus.EMPTY
    assert result.reason == "no_records"


def test_unsupported_factory_closed_reasons() -> None:
    result = IntelResult.unsupported(
        "example", IntelCapability.LOOKUP_IP, _ip_entity(), "entity_kind_mismatch"
    )
    assert result.status is IntelStatus.UNSUPPORTED
    with pytest.raises(ValueError):
        IntelResult.unsupported("example", IntelCapability.LOOKUP_IP, _ip_entity(), "nope")


def test_unavailable_factory() -> None:
    result = IntelResult.unavailable(
        "example", IntelCapability.LOOKUP_IP, _ip_entity(), ("FXAPK_X",)
    )
    assert result.status is IntelStatus.UNAVAILABLE
    assert result.reason == "credentials_unavailable"
    assert result.missing_env == ("FXAPK_X",)
    with pytest.raises(ValueError):
        IntelResult.unavailable("example", IntelCapability.LOOKUP_IP, _ip_entity(), ())


def test_failure_factory_rejects_non_identifier() -> None:
    result = IntelResult.failure(
        "example", IntelCapability.LOOKUP_IP, _ip_entity(), "ValueError"
    )
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ValueError"
    with pytest.raises(ValueError):
        IntelResult.failure("example", IntelCapability.LOOKUP_IP, _ip_entity(), "not ok")


def test_provider_contract_error_is_exception() -> None:
    assert issubclass(ProviderContractError, Exception)


def test_package_all_is_exact() -> None:
    import apkscan.intel as intel_pkg

    assert intel_pkg.__all__ == [
        "CAPABILITY_ENTITY_KIND",
        "IntelCapability",
        "IntelProvider",
        "IntelResult",
        "IntelStatus",
        "ProviderContractError",
        "validate_certificate_value",
    ]
