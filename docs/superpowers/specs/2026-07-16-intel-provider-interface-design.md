# Passive Intel Provider Interface Design

**Date:** 2026-07-16
**Scope:** PR5 only

## Objective

Define one immutable, typed contract that every future passive intelligence
adapter (FOFA, Hunter, Shodan, Censys, crt.sh, …) implements to answer three
passive lookups — `lookup_ip`, `lookup_domain`, `lookup_cert` — and return
normalized `AttributionEvidence` that PR3/PR4 already consume.

The interface makes capability, "not configured", "no records", and "failed"
explicit and distinguishable, guarantees evidence provenance and result-shape
determinism, keeps PR5-owned failure/configuration paths free of credentials
and raw secrets, and is a passive-only **declaration** enforced at
class-definition time.

PR5 delivers the contract and its validation. It ships no real adapter and
performs zero network I/O.

## Boundaries

PR5 does **not**:

- perform any real HTTP/API/network call or active scanning;
- implement any concrete provider (no FOFA/Hunter/Shodan/Censys adapter);
- redesign environment/secret handling; it reuses the existing
  `apkscan/core/dotenv.py` → `os.environ` convention and the `required_env`
  opt-in pattern already used by the enrichers, matching the exact
  `(os.environ.get(name) or "").strip()` "any one value enables" semantics
  in `apkscan/enrichers/multisource.py::_credential`;
- add or wire a cache; caching is a later adapter concern;
- change the CLI, `report.json` schema, `digest`, letters, or any analyzer;
- touch the existing `apkscan/enrichers/*` runtime;
- modify `apkscan/network/*` — `NetworkEntity`/`NetworkEntityType` are consumed
  as-is (no new `CERTIFICATE` grammar is added to the entity itself; PR5
  validates the certificate query shape inside the provider);
- invent a parallel evidence type; it returns the existing
  `apkscan.attribution.models.AttributionEvidence`;
- infer an operator, resource owner, or criminal subject from any lookup.

## Package Layout (user-mandated)

New package `apkscan/intel`:

- `apkscan/intel/__init__.py` — top-level public re-exports:
  `IntelCapability`, `IntelStatus`, `IntelResult`, `IntelProvider`,
  `ProviderContractError`, `CAPABILITY_ENTITY_KIND`, and
  `validate_certificate_value`. Mirrors the export style of
  `apkscan/attribution/__init__.py`.
- `apkscan/intel/models.py` — `IntelCapability`, `IntelStatus`,
  `ProviderContractError`, `IntelResult`, the capability→`NetworkEntityType`
  map `CAPABILITY_ENTITY_KIND`, the provider/env-name grammars, and
  `validate_certificate_value(value: object) -> str`.
- `apkscan/intel/providers/__init__.py` — provider-subpackage exports
  (re-exports `IntelProvider` and `ProviderContractError` from `.base`).
- `apkscan/intel/providers/base.py` — the `IntelProvider` abstract base.

There is **no** `apkscan/intel/provider.py`. Concrete adapters land under
`apkscan/intel/providers/` in PR6.

## Considered Approaches

### 1. Extend the enricher base with new methods

Reuse the enricher base and add `lookup_*` methods. Rejected: the enricher base
is coupled to `Endpoint`/`EnrichmentResult` (loosely-typed `dict` payloads), to
two-pass `phase` scheduling, and to auto-discovery. PR5 must return the strongly
typed `AttributionEvidence` and stay decoupled from the report pipeline, so
overloading the enricher contract would blur both.

### 2. Free functions per provider returning raw dicts

A module of `lookup_ip(provider, entity)` helpers returning `dict`. Rejected:
loses the typed evidence guarantee, makes capability/failure semantics
implicit, and gives future adapters nothing to implement against.

### 3. Abstract `IntelProvider` base with a typed `IntelResult` (selected)

A stateless ABC exposing three concrete public `lookup_*` methods that guard
entity kind, declared capability, capability-specific query canonicality, and
credential availability, then delegate to one private `_fetch` hook each
adapter implements. Lookups return an immutable `IntelResult` carrying an
explicit status, the normalized evidence, and a credential-free reason.
**This is the selected approach.** It keeps the contract typed, shape-
deterministic, provenance-preserving, and passive-by-declaration, and gives
every future adapter exactly one hook to implement — whose returned result is
itself validated against the contract before it reaches the caller.

## Public Model

### `IntelCapability`

A `str, Enum` naming the three passive lookups, values matching the public
method names:

- `LOOKUP_IP = "lookup_ip"`
- `LOOKUP_DOMAIN = "lookup_domain"`
- `LOOKUP_CERT = "lookup_cert"`

Each capability maps (via a read-only `MappingProxyType`) to exactly one
expected `NetworkEntityType`: `IP`, `DOMAIN`, `CERTIFICATE` respectively. The
map covers every capability exactly once.

### `IntelStatus`

A `str, Enum` with five mutually exclusive outcomes:

- `SUCCESS = "success"` — the lookup ran and produced at least one evidence
  item.
- `EMPTY = "empty"` — the lookup ran and the upstream had no records (a
  legitimate "queried, nothing found", distinct from an error; mirrors the
  Shodan 404 `_ShodanMiss` discipline and the enrichers' EMPTY mapping).
- `UNSUPPORTED = "unsupported"` — the provider structurally cannot answer:
  the capability is not declared, or the entity kind does not match the
  capability. No attempt is made.
- `UNAVAILABLE = "unavailable"` — the provider could answer but is not
  configured: a required credential/opt-in variable is absent. No attempt is
  made and no network touched.
- `FAILURE = "failure"` — an attempt was made and errored (adapter raised, or
  the adapter returned a contract-violating result); the reason is a **safe
  Python-identifier token only** (an exception type name, `ProviderError`, or
  `ProviderContractError`), never a message (which may embed a
  credential-bearing URL).

### `ProviderContractError`

A dedicated exception type raised internally when a `_fetch` return value
violates the post-fetch contract (see `_dispatch`). It is caught by the
dispatch wrapper and surfaced as `FAILURE` with `reason == "ProviderContractError"`.
Exported for adapter authors and tests.

### `IntelResult`

Frozen, keyword-only dataclass — the single normalized return type of every
lookup:

| field | type | meaning |
|---|---|---|
| `provider` | `str` | canonical provider `name`; `^[a-z][a-z0-9_]*$` |
| `capability` | `IntelCapability` | which lookup produced this result |
| `query` | `NetworkEntity` | the entity that was looked up (provenance) |
| `status` | `IntelStatus` | one of the five outcomes |
| `evidence` | `tuple[AttributionEvidence, ...]` | normalized findings; `()` unless `SUCCESS` |
| `reason` | `str \| None` | credential-free machine reason (see below) |
| `missing_env` | `tuple[str, ...]` | required env **variable names only** (never values); non-empty only for `UNAVAILABLE` |

**Direct-construction invariants** — fully closed per status in
`__post_init__`, so a contradictory result cannot be built even by bypassing
the factories. Base coercions first:

- `provider` is a canonical stable name matching `^[a-z][a-z0-9_]*$`;
  `capability` coerces from `IntelCapability` or its string value; `status`
  coerces likewise. The provider grammar also prevents control-character log
  injection.
- `query` is a `NetworkEntity`.
- Every `AttributionEvidence` in `evidence` must have `source == provider`
  (provenance guarantee: a provider cannot emit evidence attributed to a source
  it is not).
- Evidence is de-duplicated and sorted by the stable key
  `(id, source, type, target.kind.value, target.value)`; a duplicate evidence
  `id` bound to a different full `to_dict()` payload is rejected (mirrors the
  `RoleAssessment` conflicting-id discipline).
- `missing_env` entries are non-blank strings matching the env-name grammar
  `^[A-Za-z_][A-Za-z0-9_]*$`, sorted and de-duplicated.
- `reason`, when present, is a non-blank string.

Then a **closed per-status check** — each status admits exactly one shape:

| status | `reason` | `evidence` | `missing_env` |
|---|---|---|---|
| `SUCCESS` | exactly `None` | non-empty | empty |
| `EMPTY` | exactly `"no_records"` | empty | empty |
| `UNSUPPORTED` | in `{"capability_not_supported", "entity_kind_mismatch"}` | empty | empty |
| `UNAVAILABLE` | exactly `"credentials_unavailable"` | empty | non-empty, all valid env names |
| `FAILURE` | a safe Python identifier (`str.isidentifier()`), never `None` | empty | empty |

Any deviation raises `ValueError`/`TypeError` at construction. The five
factories below produce only valid results, but the invariants — not the
factories — are the enforcement boundary.

`reason` vocabulary (enumerated, credential-free):

- `SUCCESS` → `None`.
- `EMPTY` → `"no_records"`.
- `UNSUPPORTED` → `"capability_not_supported"` or `"entity_kind_mismatch"`.
- `UNAVAILABLE` → `"credentials_unavailable"` (details carried as names in
  `missing_env`).
- `FAILURE` → a safe identifier: the caught exception's `type(exc).__name__`
  when it `isidentifier()`, else the fallback `"ProviderError"`; or
  `"ProviderContractError"` for a post-fetch contract violation.

Ergonomic classmethod factories that construct only valid results:

- `IntelResult.success(provider, capability, query, evidence)`
- `IntelResult.empty(provider, capability, query)`
- `IntelResult.unsupported(provider, capability, query, reason)`
- `IntelResult.unavailable(provider, capability, query, missing_env)`
- `IntelResult.failure(provider, capability, query, reason)`

`to_dict()` returns deterministic, JSON-safe data (round-trips through
`json.dumps`), nesting `AttributionEvidence.to_dict()` and
`NetworkEntity.to_dict()` (which includes `sources`):

```json
{
  "provider": "example",
  "capability": "lookup_ip",
  "query": {"type": "IP", "value": "1.2.3.4", "sources": ["pcap"]},
  "status": "success",
  "evidence": [ ... AttributionEvidence.to_dict() ... ],
  "reason": null,
  "missing_env": []
}
```

### Canonical certificate query (`lookup_cert` v1)

`lookup_cert`'s canonical query is
`NetworkEntity(NetworkEntityType.CERTIFICATE, "sha256:<64 lowercase hex>")` —
the SHA-256 fingerprint of the **leaf certificate's DER encoding**. A module
helper `validate_certificate_value(value: object) -> str` returns an already
canonical string unchanged and validates the grammar
`^sha256:[0-9a-f]{64}$`; non-strings raise `TypeError`, while non-canonical
strings raise `ValueError`:

- exactly the lowercase `sha256:` prefix;
- exactly 64 lowercase hex characters;
- no uppercase, no whitespace, no alternate separators (`:`-delimited pairs,
  spaces, `0x`), no other hash algorithm.

`lookup_cert` applies this helper to the already-normalized `entity.value` and
raises `ValueError` for any remaining non-canonical value **before** `_fetch`
is reached (after the kind check, before the credential check). Because
`NetworkEntity` strips surrounding whitespace at construction, only the raw
helper can prove that raw input whitespace is rejected; lookup-level tests do
not claim to recover stripped input. SPKI hashes, serial numbers, and PEM/DER
blobs are explicitly deferred to a future capability/version and are out of
scope for PR5.

### `IntelProvider`

Stateless abstract base in `apkscan/intel/providers/base.py`. Class attributes
an adapter sets:

- `name: str` — canonical stable identifier matching
  `^[a-z][a-z0-9_]*$` (used as evidence `source` and for logs).
- `capabilities: frozenset[IntelCapability]` — the lookups this provider
  answers; must be a non-empty `frozenset` whose members are all
  `IntelCapability`.
- `required_env: tuple[str, ...] = ()` — env variable names; **any one**
  non-empty value enables the provider (same `(os.environ.get(name) or "").strip()`
  semantics as the enrichers). Must be a tuple of unique names each matching
  `^[A-Za-z_][A-Za-z0-9_]*$`; declaration order is preserved for credential
  alias priority, while `IntelResult` independently sorts `missing_env` for
  deterministic output. Empty tuple means no credential needed.
- `active: bool = False` — a **passive-only auditable declaration**. It must be
  *exactly* `False` (identity check, not merely falsy); `__init_subclass__`
  rejects any other value. PR5 admits no active provider and performs no
  network itself regardless of the flag; the flag exists so PR6 adapters carry
  an auditable "I am passive" assertion.

`__init_subclass__` validation (fail-fast at class-definition time, mirroring
the enrichers' non-silent discipline):

- `name` must be a string matching `^[a-z][a-z0-9_]*$`;
- `capabilities` must be a non-empty `frozenset[IntelCapability]`;
- `required_env` must be a tuple of unique names each matching the env-name
  grammar (malformed declarations — non-tuple, duplicate, or bad name — fail);
- `active` must be exactly `False`.

Public concrete methods (the contract):

```python
def lookup_ip(self, entity: NetworkEntity) -> IntelResult: ...
def lookup_domain(self, entity: NetworkEntity) -> IntelResult: ...
def lookup_cert(self, entity: NetworkEntity) -> IntelResult: ...
```

Each is a thin template method delegating to a shared guard:

```python
def _dispatch(self, capability, expected_kind, entity) -> IntelResult
```

`_dispatch` performs, in order:

1. type-check `entity` is a `NetworkEntity` (else `TypeError`);
2. if `capability not in self.capabilities` →
   `unsupported(reason="capability_not_supported")`;
3. if `entity.kind is not expected_kind` →
   `unsupported(reason="entity_kind_mismatch")`;
4. validate the value for the selected capability before credentials and
   `_fetch`: `LOOKUP_IP` requires `normalize_ip(entity.value) == entity.value`;
   `LOOKUP_DOMAIN` requires
   `normalize_domain(entity.value) == entity.value`; `LOOKUP_CERT` requires
   `validate_certificate_value(entity.value) == entity.value`. Invalid or
   valid-but-noncanonical values raise `ValueError`, so malformed queries do
   not consume quota;
5. if `required_env` is non-empty and no listed variable resolves to a
   non-empty stripped value → `unavailable(missing_env=self.required_env)`
   (no network touched);
6. otherwise call `self._fetch(capability, entity)` inside a secret-safe
   wrapper (below).

**Post-fetch contract validation.** The value returned by `_fetch` is not
trusted blindly. `_dispatch` verifies it is an `IntelResult` whose
`provider == self.name`, `capability == capability`, and
`query.to_dict() == entity.to_dict()` (exact, including `sources`), and whose
`status` is exactly `SUCCESS` or `EMPTY` (an adapter may not manufacture
`UNSUPPORTED`/`UNAVAILABLE`/`FAILURE` — those are dispatch's job). Any
non-`IntelResult`, any field mismatch, or any other status raises
`ProviderContractError`, which the wrapper converts to a sanitized `FAILURE`
with `reason="ProviderContractError"`.

**Secret-safe exception wrapper.** The `_fetch` call and its post-fetch
validation run inside a `try/except Exception`. On any exception the base:

- logs at `debug` with **only** the provider name, the capability value, and
  the sanitized exception type name — never the exception object, its message,
  its traceback, or `exc_info=True`; the repo rule against silent swallowing is
  honored by logging (not suppressing) at `debug`;
- returns `failure(reason=<safe token>)` where the token is
  `type(exc).__name__` if that string `isidentifier()`, else the fallback
  `"ProviderError"` (and `"ProviderContractError"` for the contract case).

So a raising or misbehaving adapter can neither leak a credential-bearing
message into `reason`/`to_dict()`/logs, nor crash the caller.

Abstract hook each adapter implements exactly once:

```python
def _fetch(self, capability: IntelCapability, entity: NetworkEntity) -> IntelResult: ...
```

`_fetch` is only ever reached for a declared capability, a matching entity
kind, a canonical value for that kind, and satisfied credentials. It must
return a `SUCCESS`/`EMPTY` `IntelResult` for the same
`provider`/`capability`/`query`. PR5 documents this contract, validates it, but
provides no implementation.

Credential presence is checked with a base helper that reads only
`os.environ` **value presence** via `(os.environ.get(name) or "").strip()`
(never logs or returns values), reusing the `.env` → `os.environ` injection
already performed at CLI entry.

## Determinism, Provenance, and Passive Discipline

- **Determinism (scope-limited):** `IntelResult` normalization is
  deterministic — evidence is sorted and de-duplicated by a stable key, and
  `to_dict()` emits sorted, JSON-safe data. This determinism claim covers
  `IntelResult` normalization **only**. Stable evidence-`id` generation is the
  **adapter's** responsibility and is documented as a PR6 concern; PR5 does not
  and cannot guarantee adapter ID stability.
- **Provenance:** `query` records the looked-up entity (including `sources`);
  every evidence `source` must equal the provider `name`; PR3/PR4 keep
  consuming the exact `AttributionEvidence` objects unchanged.
- **Passive (by declaration):** `active` must be exactly `False` at subclass
  definition; the PR5 contract performs zero network I/O itself. PR6 adapters
  must call only **fixed, provider-owned API authorities** (e.g.
  `api.shodan.io`), must **never** use the looked-up entity as a URL authority
  (no SSRF-style "fetch the entity"), and must avoid double quota consumption
  (see compatibility matrix). The `active=False` declaration is auditable.
- **Secret safety:** only env **names** ever appear (in `missing_env`, all
  grammar-checked); failure reasons are safe identifier tokens; the base wraps
  `_fetch` so a leaked message cannot escape into the result, its JSON, or the
  logs. **PR6 note:** a *successful* adapter's `AttributionEvidence.raw_reference`
  could still embed a credential-bearing URL; sanitizing `raw_reference` is
  explicitly PR6's responsibility and must be documented and tested there. PR5
  does not construct successful evidence.

## PR6 Compatibility Matrix (informative — no PR5 code)

For the four passive sources PR6 will adapt, so the interface fits without
disrupting the existing enrichers:

| provider | existing location | env aliases (canonical order) | maps to capabilities | EMPTY / 404 mapping | coexistence & migration |
|---|---|---|---|---|---|
| FOFA | `apkscan/enrichers/multisource.py` (`name="fofa"`) | `FXAPK_FOFA_KEY` | `LOOKUP_IP`, `LOOKUP_DOMAIN`, `LOOKUP_CERT` | no-record response → `EMPTY` | certificate lookup is one passive certificate-fingerprint query |
| Hunter | `apkscan/enrichers/multisource.py` (`name="hunter"`) | `FXAPK_HUNTER_KEY` | `LOOKUP_IP`, `LOOKUP_DOMAIN` | empty result set → `EMPTY` | enricher remains unchanged; provider-owned API authority is enforced in PR6 |
| Shodan | `apkscan/enrichers/shodan.py` (`name="shodan"`) | `FXAPK_SHODAN_KEY`, `SHODAN_API_KEY` | `LOOKUP_IP`, `LOOKUP_DOMAIN` (DNS resolve only) | 404 / `_ShodanMiss` → `EMPTY` | domain lookup performs resolve only; any host lookup is a separate caller-requested `lookup_ip` |
| Censys | `apkscan/enrichers/multisource.py` (`name="censys"`) | `FXAPK_CENSYS_TOKEN`, `CENSYS_API_TOKEN` | `LOOKUP_IP`, `LOOKUP_CERT` | host/certificate-not-found → `EMPTY` | certificate lookup is one passive fingerprint query; existing enricher remains IP-only |

Migration/coexistence rules: PR6 ships these adapters **unwired** from the
existing enrichment pipeline, so the same case/target is not automatically
queried through both paths. Later orchestration must choose or reuse one path,
not invoke both. Each explicit `lookup_*` performs at most one upstream call;
Shodan domain lookup stops after DNS resolve and never chains a host lookup.
Adapters map "queried, nothing found" to `EMPTY`, reserving `FAILURE` for
genuine errors.

## Tests

PR5 adds focused pytest coverage (a fake in-memory provider; no network):

- `IntelCapability`/`IntelStatus` value stability; both are `str, Enum`
  (JSON-safe); capability→entity-kind map covers each capability once;
- `IntelResult` frozen, keyword-only, validated; each factory builds only a
  valid result; **direct construction** of every contradictory per-status shape
  raises (SUCCESS/EMPTY/UNSUPPORTED/UNAVAILABLE/FAILURE closed forms);
- evidence `source` must equal `provider` (provenance guarantee);
- evidence de-duplication, stable ordering, and conflicting-id rejection;
- `missing_env` allowed only for `UNAVAILABLE`, names-only, grammar-validated
  (`^[A-Za-z_][A-Za-z0-9_]*$`), sorted/de-duplicated;
- `reason` vocabulary per status and JSON-safe deterministic `to_dict()`
  round-trip;
- `__init_subclass__` rejects a provider name outside
  `^[a-z][a-z0-9_]*$`, empty/ill-typed capabilities,
  malformed `required_env` (non-tuple, duplicate, bad grammar), and any
  `active` other than exactly `False`;
- `lookup_*` returns `UNSUPPORTED`/`capability_not_supported` for undeclared
  capability and `UNSUPPORTED`/`entity_kind_mismatch` for kind mismatch, each
  without calling `_fetch`; a non-`NetworkEntity` argument raises `TypeError`;
- the raw `validate_certificate_value` helper rejects whitespace and all other
  noncanonical forms; `lookup_cert` accepts the canonical
  `sha256:<64 lowercase hex>` entity value and rejects remaining uppercase,
  wrong-length, separator, prefix, and algorithm errors before `_fetch`;
- `lookup_ip`/`lookup_domain` reject invalid and valid-but-noncanonical values
  (compressed IPv4/IPv6 and lower-case IDNA domain without trailing dot are
  required), including IP/domain kind confusion, before `_fetch`;
- `required_env`: unset → `UNAVAILABLE` with
  `missing_env == tuple(sorted(required_env))` and
  no `_fetch`; empty-string and whitespace-only values → still `UNAVAILABLE`;
  an alternate alias set (second name) → reaches `_fetch`; empty `required_env`
  → reaches `_fetch` with no env var;
- **post-fetch contract**: a `_fetch` returning a non-`IntelResult`, a mismatched
  `provider`/`capability`/`query` (including a differing `sources`), or a status
  other than `SUCCESS`/`EMPTY` becomes a sanitized `FAILURE`
  (`reason="ProviderContractError"`); adversarial cases included;
- a `_fetch` raising an exception whose message embeds a fake `?key=SECRET` URL
  yields `FAILURE` with `reason == type(exc).__name__` (or `"ProviderError"`
  fallback when the type name is not an identifier), and a `caplog` assertion
  proving `?key=SECRET` appears **nowhere** in the result, its `to_dict()` JSON,
  or the captured logs;
- a declared, configured, kind-matching, canonical-value lookup reaches
  `_fetch` and returns its `SUCCESS`/`EMPTY` result unchanged;
- deterministic package exports from `apkscan.intel` (sorted `__all__`) and from
  `apkscan.intel.providers`.
