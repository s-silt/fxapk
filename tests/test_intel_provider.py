"""PR5 IntelProvider tests: subclass validation, dispatch guards, credential
matrix, post-fetch contract, secret-safe failure/logging, public exports.

IntelProvider is a plain stateless ABC (see apkscan/intel/providers/base.py):
__init_subclass__ fail-fast validates the four declarations, but subclasses are
free to carry a custom __init__ (dependency injection), private helpers,
constants, __slots__, and to inherit indirectly or via mixins. The fakes here
exercise that real usability.

All tests use in-memory fakes; no network I/O.
"""

from __future__ import annotations

import json
import logging

import pytest

from apkscan.attribution import AttributionEvidence
from apkscan.intel import (
    CAPABILITY_ENTITY_KIND,
    IntelCapability,
    IntelResult,
    IntelStatus,
    ProviderContractError,
    validate_certificate_value,
)
from apkscan.intel.providers import IntelProvider
from apkscan.intel.providers import ProviderContractError as ProviderContractErrorReexport
from apkscan.network import NetworkEntity, NetworkEntityType

_HEX64 = "a" * 64
_CANONICAL_CERT = f"sha256:{_HEX64}"


def _entity(kind: NetworkEntityType, value: str, sources: tuple[str, ...] = ("pcap",)) -> NetworkEntity:
    return NetworkEntity(kind, value, sources)


def _evidence(provider: str, target: NetworkEntity) -> AttributionEvidence:
    return AttributionEvidence(
        id="ev-1",
        source=provider,
        type="geo",
        target=target,
        value="US",
        confidence=0.5,
    )


class FakeProvider(IntelProvider):
    """In-memory provider carrying real per-instance state via __init__.

    Demonstrates the ABC allows a custom __init__ (dependency injection), a
    private helper, and instance recording of _fetch calls.
    """

    name = "fake"
    capabilities = frozenset(IntelCapability)
    required_env = ()
    active = False

    def __init__(self, result_factory=None) -> None:
        self.calls: list[tuple[IntelCapability, str]] = []
        self._result_factory = result_factory

    def _fetch(self, capability: IntelCapability, query: NetworkEntity) -> IntelResult:
        self.calls.append((capability, query.value))
        if self._result_factory is not None:
            return self._result_factory(self, capability, query)
        return IntelResult.empty(type(self).name, capability, query)


# ===========================================================================
# Subclass validation (fail-fast at class-definition time)
# ===========================================================================


def test_intel_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        IntelProvider()  # type: ignore[abstract]


def test_valid_subclass_accepted() -> None:
    provider = FakeProvider()
    assert provider.name == "fake"


def test_subclass_must_implement_fetch() -> None:
    """A subclass without _fetch stays abstract and cannot be instantiated."""

    class NoFetch(IntelProvider):
        name = "nofetch"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

    with pytest.raises(TypeError):
        NoFetch()  # type: ignore[abstract]


@pytest.mark.parametrize("bad_name", ["Fake", "fa ke", "fa-ke", "1fake", "", " fake", "fake "])
def test_subclass_rejects_bad_name(bad_name: str) -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = bad_name
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover - never reached
                raise AssertionError


@pytest.mark.parametrize("bad_name", ["fake\n", "\nfake", "fake\nfake", "fake\r\n", "fake\r"])
def test_subclass_rejects_name_with_newline(bad_name: str) -> None:
    """`re.match` with `$` accepts a trailing newline; fullmatch must reject it."""
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = bad_name
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


def test_subclass_rejects_missing_name() -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


def test_subclass_rejects_empty_capabilities() -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = frozenset()
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


def test_subclass_rejects_non_frozenset_capabilities() -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = {IntelCapability.LOOKUP_IP}  # type: ignore[assignment]
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


def test_subclass_rejects_non_capability_member() -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = frozenset({"lookup_ip"})  # type: ignore[arg-type]
            required_env = ()
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


@pytest.mark.parametrize(
    "bad_env",
    [
        ["FXAPK_X"],  # non-tuple
        ("FXAPK_X", "FXAPK_X"),  # duplicate
        ("bad name",),  # invalid grammar
        ("1BAD",),  # leading digit
    ],
)
def test_subclass_rejects_malformed_required_env(bad_env) -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = bad_env
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


@pytest.mark.parametrize("bad_env", [("FXAPK_X\n",), ("\nFXAPK_X",), ("FXAPK_X\nFXAPK_Y",)])
def test_subclass_rejects_required_env_with_newline(bad_env) -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = bad_env
            active = False

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


@pytest.mark.parametrize("bad_active", [0, "", None, True, 1])
def test_subclass_rejects_active_not_exactly_false(bad_active) -> None:
    with pytest.raises((ValueError, TypeError)):

        class _Bad(IntelProvider):
            name = "bad"
            capabilities = frozenset({IntelCapability.LOOKUP_IP})
            required_env = ()
            active = bad_active

            def _fetch(self, capability, query):  # pragma: no cover
                raise AssertionError


# ===========================================================================
# Real usability: __init__ DI, private helpers, constants, inheritance shapes
# ===========================================================================


def test_provider_may_inject_client_and_use_private_helper() -> None:
    """A provider can take a client via __init__, keep constants, use helpers."""

    class ClientProvider(IntelProvider):
        name = "clientp"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        _CONST = "geo"  # a plain class constant is allowed

        def __init__(self, client) -> None:
            self._client = client  # injected dependency

        def _label(self) -> str:  # a private helper is allowed
            return f"{type(self).name}:{self._CONST}"

        def _fetch(self, capability, query):
            assert self._label() == "clientp:geo"
            evidence = _evidence(self._client.provider_name, query)
            return IntelResult.success(type(self).name, capability, query, (evidence,))

    class _Client:
        provider_name = "clientp"

    provider = ClientProvider(_Client())
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.SUCCESS
    assert result.evidence[0].source == "clientp"


def test_provider_may_declare_slots() -> None:
    """A provider may declare its own __slots__ for per-instance fields."""

    class SlottedProvider(IntelProvider):
        name = "slotted"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False
        __slots__ = ("_token",)

        def __init__(self, token: str) -> None:
            self._token = token

        def _fetch(self, capability, query):
            return IntelResult.empty(type(self).name, capability, query)

    provider = SlottedProvider("t")
    assert provider._token == "t"
    assert provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4")).status is IntelStatus.EMPTY


def test_indirect_subclass_is_supported() -> None:
    """An abstract intermediate layer + a concrete leaf is a valid shape."""

    class BaseHttpProvider(IntelProvider):
        # Intermediate layer: declares nothing concrete, stays abstract because
        # it does not implement _fetch. Must NOT be rejected at definition.
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        def _shared(self) -> str:
            return "shared"

    class LeafProvider(BaseHttpProvider):
        name = "leaf"

        def _fetch(self, capability, query):
            assert self._shared() == "shared"
            return IntelResult.empty(type(self).name, capability, query)

    provider = LeafProvider()
    assert provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4")).status is IntelStatus.EMPTY


def test_multiple_inheritance_with_mixin_is_supported() -> None:
    """A provider may mix in an orthogonal helper base."""

    class TimingMixin:
        def elapsed(self) -> float:
            return 0.0

    class MixedProvider(TimingMixin, IntelProvider):
        name = "mixed"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        def _fetch(self, capability, query):
            assert self.elapsed() == 0.0
            return IntelResult.empty(type(self).name, capability, query)

    provider = MixedProvider()
    assert provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4")).status is IntelStatus.EMPTY


# ===========================================================================
# Non-polymorphic enforcement: a same-named adapter helper must NOT be able to
# override declaration validation or the core dispatch guards. The four-decl
# check and the three core guards (canonical value, credential availability,
# post-fetch contract) are module-level functions called directly by name, not
# dispatched through self/cls; _fetch is the ONLY polymorphic query hook.
# ===========================================================================


def test_same_named_validate_helper_cannot_smuggle_illegal_leaf() -> None:
    """A mid layer defining a `_validate_declarations` helper must not let a
    concrete leaf ship an illegal declaration (active=True) past definition-time
    validation."""

    class Mid(IntelProvider):
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        # A same-named helper on the class must NOT be the thing dispatch/validation
        # calls: validation is a module-level function, so this is dead weight.
        def _validate_declarations(self) -> None:  # pragma: no cover - never called
            return None

    with pytest.raises(ValueError):

        class Leaf(Mid):
            name = "leaf"
            active = True  # illegal: must still be rejected at definition

            def _fetch(self, capability, query):  # pragma: no cover - never reached
                raise AssertionError


def test_same_named_canonical_helper_cannot_bypass_guard() -> None:
    """A provider's own `_require_canonical_value` must not bypass the real
    canonical check: a non-canonical value still raises before _fetch."""

    class Sneaky(IntelProvider):
        name = "sneakycanon"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        def __init__(self) -> None:
            self.called = False

        def _require_canonical_value(self, capability, query) -> None:
            # Adapter tries to neuter the canonical guard; must be ignored.
            return None

        def _fetch(self, capability, query):
            self.called = True
            return IntelResult.empty("sneakycanon", capability, query)

    provider = Sneaky()
    with pytest.raises(ValueError):
        provider.lookup_ip(_entity(NetworkEntityType.IP, "01.2.3.4"))
    assert provider.called is False


def test_same_named_credentials_helper_cannot_bypass_guard(monkeypatch) -> None:
    """A provider's own `_missing_credentials` must not fake credential
    availability: an unconfigured required_env still yields UNAVAILABLE."""
    monkeypatch.delenv("FXAPK_PRIMARY", raising=False)

    class Sneaky(IntelProvider):
        name = "sneakycreds"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ("FXAPK_PRIMARY",)
        active = False

        def __init__(self) -> None:
            self.called = False

        def _missing_credentials(self, *args, **kwargs) -> tuple[str, ...]:
            # Adapter tries to claim credentials are always present; must be ignored.
            return ()

        def _fetch(self, capability, query):
            self.called = True
            return IntelResult.empty("sneakycreds", capability, query)

    provider = Sneaky()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.UNAVAILABLE
    assert result.missing_env == ("FXAPK_PRIMARY",)
    assert provider.called is False


def test_same_named_post_fetch_helper_cannot_bypass_contract() -> None:
    """A provider's own `_validate_fetched` must not wave through a mismatched
    _fetch result: a provider-mismatched result still becomes FAILURE."""

    class Sneaky(IntelProvider):
        name = "sneakypost"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        def _validate_fetched(self, *args, **kwargs):
            # Adapter tries to rubber-stamp its own result; must be ignored.
            return args[-1]

        def _fetch(self, capability, query):
            # Wrong provider name -> real post-fetch contract must reject it.
            return IntelResult.empty("other", capability, query)

    provider = Sneaky()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_same_named_dispatch_helper_cannot_bypass_dispatch(monkeypatch) -> None:
    """A provider's own `_dispatch` must not divert the public lookup_*: the
    template calls the module-level dispatch directly, so the real guards still
    run (missing credentials -> UNAVAILABLE, fake _fetch never called)."""
    monkeypatch.delenv("FXAPK_MISSING", raising=False)

    class Sneaky(IntelProvider):
        name = "sneakydispatch"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ("FXAPK_MISSING",)
        active = False

        def __init__(self) -> None:
            self.called = False

        def _dispatch(self, *args, **kwargs):  # pragma: no cover - never called
            # Adapter tries to hijack dispatch entirely; must be ignored.
            return "BYPASSED"

        def _fetch(self, capability, query):
            self.called = True
            return IntelResult.empty("sneakydispatch", capability, query)

    provider = Sneaky()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    # Not the adapter's "BYPASSED": the real module dispatch ran the guards.
    assert isinstance(result, IntelResult)
    assert result.status is IntelStatus.UNAVAILABLE
    assert result.missing_env == ("FXAPK_MISSING",)
    assert provider.called is False


# ===========================================================================
# Dispatch guards
# ===========================================================================


def test_unsupported_capability_not_declared() -> None:
    class IpOnly(IntelProvider):
        name = "iponly"
        capabilities = frozenset({IntelCapability.LOOKUP_IP})
        required_env = ()
        active = False

        def __init__(self) -> None:
            self.called = False

        def _fetch(self, capability, query):
            self.called = True
            return IntelResult.empty("iponly", capability, query)

    provider = IpOnly()
    result = provider.lookup_domain(_entity(NetworkEntityType.DOMAIN, "example.com"))
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "capability_not_supported"
    assert provider.called is False


def test_unsupported_entity_kind_mismatch() -> None:
    provider = FakeProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.DOMAIN, "example.com"))
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "entity_kind_mismatch"
    assert provider.calls == []


def test_dispatch_rejects_non_network_entity() -> None:
    provider = FakeProvider()
    with pytest.raises(TypeError):
        provider.lookup_ip("1.2.3.4")  # type: ignore[arg-type]


def test_lookup_cert_accepts_canonical() -> None:
    provider = FakeProvider()
    result = provider.lookup_cert(_entity(NetworkEntityType.CERTIFICATE, _CANONICAL_CERT))
    assert result.status is IntelStatus.EMPTY
    assert provider.calls == [(IntelCapability.LOOKUP_CERT, _CANONICAL_CERT)]


# ---- canonical query matrix ----


_CANONICAL_MATRIX = [
    (IntelCapability.LOOKUP_IP, NetworkEntityType.IP, "1.2.3.4"),
    (IntelCapability.LOOKUP_IP, NetworkEntityType.IP, "2001:db8::1"),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "example.com"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, _CANONICAL_CERT),
]

_NONCANONICAL_MATRIX = [
    # IP: leading zero (ambiguous octal), uppercase IPv6 (must be compressed lowercase).
    (IntelCapability.LOOKUP_IP, NetworkEntityType.IP, "01.2.3.4"),
    (IntelCapability.LOOKUP_IP, NetworkEntityType.IP, "2001:DB8::1"),
    # DOMAIN: uppercase, trailing dot, Unicode (IDNA/punycode), IP literal, invalid empty label.
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "Example.COM"),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "example.com."),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "bücher.de"),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "1.2.3.4"),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.DOMAIN, "example..com"),
    # CERT: uppercase hex, wrong length, wrong separator, 0x prefix, other algorithm.
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, f"sha256:{'A' * 64}"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, f"sha256:{'a' * 63}"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, f"sha256-{'a' * 64}"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, f"0x{'a' * 64}"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.CERTIFICATE, f"sha1:{'a' * 40}"),
]

#: kind confusion: a well-formed value carried by the wrong entity kind must be
#: rejected by the entity-kind guard (UNSUPPORTED, entity_kind_mismatch) before
#: _fetch, never dispatched.
_KIND_CONFUSION_MATRIX = [
    (IntelCapability.LOOKUP_IP, NetworkEntityType.DOMAIN, "example.com"),
    (IntelCapability.LOOKUP_IP, NetworkEntityType.CERTIFICATE, _CANONICAL_CERT),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.IP, "1.2.3.4"),
    (IntelCapability.LOOKUP_DOMAIN, NetworkEntityType.CERTIFICATE, _CANONICAL_CERT),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.IP, "1.2.3.4"),
    (IntelCapability.LOOKUP_CERT, NetworkEntityType.DOMAIN, "example.com"),
]


@pytest.mark.parametrize("capability,kind,value", _CANONICAL_MATRIX)
def test_canonical_query_matrix_reaches_fetch(capability, kind, value) -> None:
    provider = FakeProvider()
    method = getattr(provider, capability.value)
    result = method(_entity(kind, value))
    assert result.status is IntelStatus.EMPTY
    assert provider.calls == [(capability, value)]


@pytest.mark.parametrize("capability,kind,value", _NONCANONICAL_MATRIX)
def test_noncanonical_query_matrix_rejected_before_fetch(capability, kind, value) -> None:
    provider = FakeProvider()
    method = getattr(provider, capability.value)
    with pytest.raises(ValueError):
        method(_entity(kind, value))
    assert provider.calls == []


@pytest.mark.parametrize("capability,kind,value", _KIND_CONFUSION_MATRIX)
def test_kind_confusion_rejected_before_fetch(capability, kind, value) -> None:
    provider = FakeProvider()
    method = getattr(provider, capability.value)
    result = method(_entity(kind, value))
    assert result.status is IntelStatus.UNSUPPORTED
    assert result.reason == "entity_kind_mismatch"
    assert provider.calls == []


# ===========================================================================
# required_env matrix
# ===========================================================================


class _EnvProvider(IntelProvider):
    name = "envp"
    capabilities = frozenset({IntelCapability.LOOKUP_IP})
    required_env = ("FXAPK_PRIMARY", "FXAPK_ALIAS")
    active = False

    def __init__(self) -> None:
        self.calls = 0

    def _fetch(self, capability, query):
        self.calls += 1
        return IntelResult.empty(type(self).name, capability, query)


def test_required_env_unset_is_unavailable(monkeypatch) -> None:
    monkeypatch.delenv("FXAPK_PRIMARY", raising=False)
    monkeypatch.delenv("FXAPK_ALIAS", raising=False)
    provider = _EnvProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.UNAVAILABLE
    assert result.missing_env == ("FXAPK_ALIAS", "FXAPK_PRIMARY")
    assert provider.calls == 0


def test_required_env_empty_string_is_unavailable(monkeypatch) -> None:
    monkeypatch.setenv("FXAPK_PRIMARY", "")
    monkeypatch.delenv("FXAPK_ALIAS", raising=False)
    provider = _EnvProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.UNAVAILABLE
    assert provider.calls == 0


def test_required_env_whitespace_is_unavailable(monkeypatch) -> None:
    monkeypatch.setenv("FXAPK_PRIMARY", "   ")
    monkeypatch.delenv("FXAPK_ALIAS", raising=False)
    provider = _EnvProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.UNAVAILABLE
    assert provider.calls == 0


def test_required_env_alias_enables_fetch(monkeypatch) -> None:
    monkeypatch.delenv("FXAPK_PRIMARY", raising=False)
    monkeypatch.setenv("FXAPK_ALIAS", "token")
    provider = _EnvProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.EMPTY
    assert provider.calls == 1


def test_empty_required_env_reaches_fetch() -> None:
    provider = FakeProvider()
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.EMPTY
    assert provider.calls == [(IntelCapability.LOOKUP_IP, "1.2.3.4")]


def test_configured_lookup_returns_fetch_result_unchanged() -> None:
    def factory(self, capability, query):
        return IntelResult.success(
            type(self).name, capability, query, (_evidence(type(self).name, query),)
        )

    provider = FakeProvider(result_factory=factory)
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.SUCCESS
    assert result.evidence[0].source == "fake"


# ===========================================================================
# Post-fetch contract (adversarial)
# ===========================================================================


def test_post_fetch_non_result_becomes_failure() -> None:
    provider = FakeProvider(result_factory=lambda self, cap, q: {"not": "a result"})
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_post_fetch_provider_mismatch_becomes_failure() -> None:
    provider = FakeProvider(
        result_factory=lambda self, cap, q: IntelResult.empty("other", cap, q)
    )
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_post_fetch_capability_mismatch_becomes_failure() -> None:
    provider = FakeProvider(
        result_factory=lambda self, cap, q: IntelResult.empty(
            type(self).name, IntelCapability.LOOKUP_DOMAIN, q
        )
    )
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_post_fetch_query_mismatch_becomes_failure() -> None:
    provider = FakeProvider(
        result_factory=lambda self, cap, q: IntelResult.empty(
            type(self).name, cap, _entity(NetworkEntityType.IP, "9.9.9.9")
        )
    )
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_post_fetch_query_sources_mismatch_becomes_failure() -> None:
    provider = FakeProvider(
        result_factory=lambda self, cap, q: IntelResult.empty(
            type(self).name, cap, _entity(NetworkEntityType.IP, q.value, ("different",))
        )
    )
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4", ("pcap",)))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


def test_post_fetch_bad_status_becomes_failure() -> None:
    provider = FakeProvider(
        result_factory=lambda self, cap, q: IntelResult.unavailable(
            type(self).name, cap, q, ("FXAPK_X",)
        )
    )
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderContractError"


# ===========================================================================
# Secret-safe failure + logging
# ===========================================================================


def _raiser(exc: Exception):
    def factory(self, capability, query):
        raise exc

    return factory


def test_fetch_exception_becomes_sanitized_failure(caplog) -> None:
    secret_url = "https://api.example.com/v1?key=SECRET&q=1.2.3.4"

    class BoomError(Exception):
        pass

    provider = FakeProvider(result_factory=_raiser(BoomError(secret_url)))
    with caplog.at_level(logging.DEBUG):
        result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))

    assert result.status is IntelStatus.FAILURE
    assert result.reason == "BoomError"

    serialized = json.dumps(result.to_dict())
    logs = "\n".join(r.getMessage() for r in caplog.records)
    for haystack in (result.reason, serialized, logs):
        assert "SECRET" not in haystack
        assert "key=SECRET" not in haystack
        assert secret_url not in haystack

    assert "fake" in logs
    assert "lookup_ip" in logs
    assert "BoomError" in logs


def test_fetch_exception_with_non_identifier_type_falls_back() -> None:
    weird = type("bad name!", (Exception,), {})
    provider = FakeProvider(result_factory=_raiser(weird("boom")))
    result = provider.lookup_ip(_entity(NetworkEntityType.IP, "1.2.3.4"))
    assert result.status is IntelStatus.FAILURE
    assert result.reason == "ProviderError"


# ===========================================================================
# @final template methods (static-only sealing; caught by Pyright, not runtime)
# ===========================================================================


@pytest.mark.parametrize("method", ["lookup_ip", "lookup_domain", "lookup_cert"])
def test_template_methods_marked_final(method: str) -> None:
    """The public lookup_* templates carry typing.final so Pyright flags an
    unintended PR6 adapter override. This is static-only; there is no runtime
    sealing. `@final` sets __final__ on the function (CPython 3.11+). The shared
    dispatch is a module-level function (not a class method), so it cannot be
    overridden at all and is not part of the class surface."""
    func = getattr(IntelProvider, method)
    assert func.__final__ is True


# ===========================================================================
# Public exports
# ===========================================================================


def test_top_level_exports() -> None:
    import apkscan.intel as intel

    assert intel.__all__ == [
        "CAPABILITY_ENTITY_KIND",
        "IntelCapability",
        "IntelProvider",
        "IntelResult",
        "IntelStatus",
        "ProviderContractError",
        "validate_certificate_value",
    ]
    for name in intel.__all__:
        assert hasattr(intel, name)


def test_providers_subpackage_exports() -> None:
    import apkscan.intel.providers as providers

    assert providers.IntelProvider is IntelProvider
    assert ProviderContractErrorReexport is ProviderContractError
    assert providers.__all__ == [
        "IntelProvider",
        "ProviderContractError",
    ]
    for name in providers.__all__:
        assert hasattr(providers, name)


def test_capability_entity_kind_reachable_from_top_level() -> None:
    assert CAPABILITY_ENTITY_KIND[IntelCapability.LOOKUP_CERT] is NetworkEntityType.CERTIFICATE
    assert validate_certificate_value(_CANONICAL_CERT) == _CANONICAL_CERT
