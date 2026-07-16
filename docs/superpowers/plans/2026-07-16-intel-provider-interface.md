# Passive Intel Provider Interface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`
> task-by-task, and use `superpowers:test-driven-development` for every
> implementation change. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PR5 — one immutable, typed `IntelProvider` contract with three
passive lookups (`lookup_ip`, `lookup_domain`, `lookup_cert`) that return
normalized `AttributionEvidence` and expose explicit
capability/unsupported/unavailable/failure semantics, with no real provider,
network call, cache, env redesign, CLI/report, or analyzer change.

**Architecture:** A stateless abstract `IntelProvider` (in
`apkscan/intel/providers/base.py`) exposes three concrete public `lookup_*`
template methods. Each delegates to a shared `_dispatch` guard that checks
entity type, declared capability, entity-kind match, capability-specific
canonical query value, and credential availability, then calls the
adapter's single `_fetch` hook inside a secret-safe `try/except`. The value
returned by `_fetch` is validated against the contract (exact
provider/capability/query, `SUCCESS`/`EMPTY` only) before it reaches the
caller; violations become a sanitized `FAILURE`. Every lookup returns an
immutable `IntelResult` carrying an explicit `IntelStatus`, deterministic
normalized `AttributionEvidence`, a credential-free `reason`, and env **names**
only. Reuse the existing `apkscan.attribution.models.AttributionEvidence`,
`apkscan.network.NetworkEntity`/`NetworkEntityType`, and the
`.env` → `os.environ` / `required_env` conventions
(`(os.environ.get(name) or "").strip()`, any one value enables); invent no
parallel types and do not modify `apkscan/network/*`.

**Tech Stack:** Python 3.11+, frozen keyword-only dataclasses, `str` enums,
`frozenset`/`tuple` immutables, `MappingProxyType`, pytest, Ruff, Pyright.

## Global Constraints

- No real HTTP/API/network call and no active scanning anywhere in PR5.
- No concrete provider implementation (no FOFA/Hunter/Shodan/Censys adapter).
- No environment/secret redesign; reuse `apkscan/core/dotenv.py` and the
  enrichers' `required_env` opt-in pattern. Read only env **value presence**,
  never values.
- No cache, no CLI, no `report.json`/`digest`/letters, no analyzer/enricher
  runtime changes, no `apkscan/network/*` change. Public Python exports for the
  PR5 value objects and base are in scope.
- Return the existing `AttributionEvidence`; do not define a new evidence type.
- Secret safety: only env variable **names** may appear (`missing_env`, grammar
  `^[A-Za-z_][A-Za-z0-9_]*$`); failure `reason` is a safe Python-identifier
  token only (exception type name, `ProviderError` fallback, or
  `ProviderContractError`); never log or return an exception object, message,
  traceback, or `exc_info`.
- `active` must be exactly `False` for every provider; enforce at subclass
  definition. It is an auditable passive declaration.
- Preserve deterministic `IntelResult` normalization and JSON-safe
  serialization. Adapter evidence-`id` stability is a PR6 responsibility, not a
  PR5 guarantee.
- Complete the full final gates before PR submission.

## File Structure (user-mandated layout)

- Create `apkscan/intel/__init__.py`: top-level re-exports (`IntelCapability`,
  `IntelStatus`, `IntelResult`, `IntelProvider`, `ProviderContractError`,
  `CAPABILITY_ENTITY_KIND`, `validate_certificate_value`); sorted `__all__`.
- Create `apkscan/intel/models.py`: `IntelCapability`, `IntelStatus`,
  `ProviderContractError`, `IntelResult`, the capability→`NetworkEntityType`
  map `CAPABILITY_ENTITY_KIND`, the provider/env-name grammars, and
  `validate_certificate_value(value: object) -> str`.
- Create `apkscan/intel/providers/__init__.py`: re-export `IntelProvider` and
  `ProviderContractError` from `.base`.
- Create `apkscan/intel/providers/base.py`: `IntelProvider` abstract base with
  `lookup_ip`/`lookup_domain`/`lookup_cert`, `_dispatch`, the env-presence
  helper, the post-fetch contract validation, the secret-safe wrapper, and the
  abstract `_fetch` hook.
- Do **not** create `apkscan/intel/provider.py`.
- Create `tests/test_intel_models.py`: value-object validation, direct-
  construction invariants, factories, cert-value validator, determinism, JSON
  safety.
- Create `tests/test_intel_provider.py`: dispatch guards, subclass validation,
  `required_env` matrix, post-fetch contract, secret-safe failure/logging,
  exports — using an in-memory fake provider.
- Do not modify `apkscan/attribution/*`, `apkscan/network/*`,
  `apkscan/enrichers/*`, `apkscan/core/*`, the CLI, or the report layer.

---

### Task 1: `IntelCapability`, `IntelStatus`, the capability→kind map, and cert-value validator

**Files:**
- Create: `apkscan/intel/models.py`
- Test: `tests/test_intel_models.py`

- [ ] Write failing tests: `IntelCapability` members/values are
  `lookup_ip`/`lookup_domain`/`lookup_cert`; `IntelStatus` members/values are
  `success`/`empty`/`unsupported`/`unavailable`/`failure`; both are
  `str, Enum` (JSON-safe); the capability→`NetworkEntityType` map returns
  `IP`/`DOMAIN`/`CERTIFICATE`; the exact public symbol
  `CAPABILITY_ENTITY_KIND` is a read-only `MappingProxyType` and covers
  every capability exactly once.
- [ ] Write failing tests for
  `validate_certificate_value(value: object) -> str`: returns an already
  canonical value unchanged; accepts
  `"sha256:" + 64 lowercase hex`; rejects uppercase hex, wrong length, colon-
  pair separators, spaces, `0x`/other prefixes, `sha1:`/other algorithms, and
  non-str. Explain in a test docstring that v1 = SHA-256 leaf-cert DER
  fingerprint; SPKI/serial/PEM deferred.
- [ ] Implement the two enums, `CAPABILITY_ENTITY_KIND`, and
  `validate_certificate_value` with `TypeError` for non-strings and
  `ValueError` for non-canonical strings.
- [ ] Run: `python -m pytest tests/test_intel_models.py -q`

### Task 2: `IntelResult` value object and closed per-status invariants

**Files:**
- Modify: `apkscan/intel/models.py`
- Test: `tests/test_intel_models.py`

- [ ] Write failing tests for a frozen, keyword-only `IntelResult`:
  - `provider` must match `^[a-z][a-z0-9_]*$` (reject whitespace, uppercase,
    punctuation, and control characters); `capability`/`status` coerce from
    enum or string value; `query` must be a `NetworkEntity`;
  - every evidence item's `source` must equal `provider` (provenance) — a
    mismatch raises;
  - evidence is de-duplicated and sorted by
    `(id, source, type, target.kind.value, target.value)`; a duplicate `id`
    with a differing `to_dict()` payload raises;
  - `missing_env` names match `^[A-Za-z_][A-Za-z0-9_]*$`, are sorted and
    de-duplicated;
  - **closed per-status direct-construction invariants** (bypassing factories):
    - `SUCCESS` requires `reason is None`, non-empty `evidence`, empty
      `missing_env`;
    - `EMPTY` requires `reason == "no_records"`, empty `evidence`, empty
      `missing_env`;
    - `UNSUPPORTED` requires `reason in {"capability_not_supported",
      "entity_kind_mismatch"}`, empty `evidence`, empty `missing_env`;
    - `UNAVAILABLE` requires `reason == "credentials_unavailable"`, empty
      `evidence`, non-empty valid `missing_env`;
    - `FAILURE` requires a non-`None` `reason` that `str.isidentifier()`, empty
      `evidence`, empty `missing_env`;
    - every contradictory combination raises `ValueError`/`TypeError`;
  - `to_dict()` is deterministic and JSON-safe (round-trips through
    `json.dumps`) and nests `AttributionEvidence.to_dict()` and
    `NetworkEntity.to_dict()` (including `sources`).
- [ ] Implement `IntelResult` and `ProviderContractError` with `__post_init__`
  validation (base coercions, then the closed per-status table), mirroring the
  `AttributionEvidence`/`RoleAssessment` normalization style.
- [ ] Run: `python -m pytest tests/test_intel_models.py -q`

### Task 3: `IntelResult` factory classmethods

**Files:**
- Modify: `apkscan/intel/models.py`
- Test: `tests/test_intel_models.py`

- [ ] Write failing tests: `success` requires evidence, sets `SUCCESS`/`reason
  None`; `empty` sets `EMPTY`/`"no_records"`; `unsupported` accepts only the
  two closed reasons; `unavailable` sets `UNAVAILABLE`/`"credentials_unavailable"`
  and requires non-empty valid `missing_env`; `failure` sets `FAILURE` with a
  safe-identifier reason and rejects a non-identifier reason; each factory
  yields a valid result and rejects contradictory input.
- [ ] Implement the five classmethods on top of the invariants from Task 2.
- [ ] Run: `python -m pytest tests/test_intel_models.py -q`

### Task 4: `IntelProvider` subclass validation

**Files:**
- Create: `apkscan/intel/providers/base.py`
- Test: `tests/test_intel_provider.py`

- [ ] Write failing tests using minimal subclasses: `__init_subclass__` rejects
  missing `name` or any name outside `^[a-z][a-z0-9_]*$` (including leading or
  trailing whitespace, uppercase, punctuation, and control characters); empty
  or non-`frozenset[IntelCapability]`
  `capabilities`; malformed `required_env` (non-tuple, duplicate name, or a
  name failing `^[A-Za-z_][A-Za-z0-9_]*$`); and any `active` that is not exactly
  `False` (including `0`, `""`, `None`, and truthy values). A valid subclass
  (canonical name, non-empty capabilities, well-formed `required_env`,
  `active=False`) is accepted; `IntelProvider` itself remains abstract (cannot
  instantiate; `_fetch` abstract).
- [ ] Implement `IntelProvider` ABC in `providers/base.py` with class
  attributes and `__init_subclass__` fail-fast validation (identity check
  `active is False`).
- [ ] Run: `python -m pytest tests/test_intel_provider.py -q`

### Task 5: Dispatch guards, cert-query check, credential check, secret-safe failure, and post-fetch contract

**Files:**
- Modify: `apkscan/intel/providers/base.py`
- Test: `tests/test_intel_provider.py`

- [ ] Write failing tests with an in-memory `FakeProvider` (records whether
  `_fetch` was called; no network):
  - `lookup_*` returns `UNSUPPORTED`/`"capability_not_supported"` when the
    capability is not declared, without calling `_fetch`;
  - `lookup_*` returns `UNSUPPORTED`/`"entity_kind_mismatch"` when the entity
    kind does not match the capability, without calling `_fetch`;
  - passing a non-`NetworkEntity` raises `TypeError`;
  - `lookup_ip` rejects invalid values and valid-but-noncanonical IPv4/IPv6;
    `lookup_domain` rejects invalid values, IP literals, uppercase/Unicode or
    trailing-dot forms whose `normalize_domain` output differs; every rejection
    occurs before `_fetch`;
  - `lookup_cert` raises `ValueError` for non-canonical entity values
    (uppercase, wrong length, colon-pair separators, `0x`, other algorithms)
    before `_fetch`; accepts the canonical value. Raw surrounding whitespace is
    tested on `validate_certificate_value`, because `NetworkEntity` strips it
    before dispatch;
  - **`required_env` matrix** (all via `monkeypatch`): unset → `UNAVAILABLE`
    with `missing_env == tuple(sorted(required_env))`, no `_fetch`;
    empty-string value → still
    `UNAVAILABLE`; whitespace-only value → still `UNAVAILABLE`; alternate alias
    (second declared name set) → reaches `_fetch`; empty `required_env` →
    reaches `_fetch` with no env var;
  - a declared, configured, kind-matching, canonical-value lookup reaches
    `_fetch` and returns its `SUCCESS`/`EMPTY` result unchanged;
  - **post-fetch contract (adversarial):** a `_fetch` returning a
    non-`IntelResult`; a result with a mismatched `provider`; mismatched
    `capability`; a `query` whose `to_dict()` differs (including a differing
    `sources`); or a status other than `SUCCESS`/`EMPTY` — each becomes
    `FAILURE` with `reason == "ProviderContractError"`;
  - **secret-safe failure + logging:** a `_fetch` raising an exception whose
    message embeds a fake `?key=SECRET` URL yields `FAILURE` with
    `reason == type(exc).__name__`; an exception whose type name is not an
    identifier yields `reason == "ProviderError"`; a `caplog` assertion proves
    `?key=SECRET` (and the raw message) appear **nowhere** in the result, its
    `to_dict()` JSON, or the captured logs, and that the debug log line
    contains only provider name + capability value + sanitized type.
- [ ] Implement `_dispatch`, the three public `lookup_*` methods, the
  env-presence helper (`(os.environ.get(name) or "").strip()`, presence only),
  reject-if-noncanonical query validation using existing `normalize_ip`,
  `normalize_domain`, and `validate_certificate_value`,
  the post-fetch contract validation raising `ProviderContractError`, and the
  secret-safe `try/except` wrapper (log at `debug` with sanitized fields only,
  never swallow silently, never `exc_info`).
- [ ] Run: `python -m pytest tests/test_intel_provider.py -q`

### Task 6: Public exports

**Files:**
- Create: `apkscan/intel/__init__.py`, `apkscan/intel/providers/__init__.py`
- Test: `tests/test_intel_provider.py` (or a small export assertion)

- [ ] Write a failing test importing `IntelCapability`, `IntelStatus`,
  `IntelResult`, `IntelProvider`, `ProviderContractError`,
  `CAPABILITY_ENTITY_KIND`, and `validate_certificate_value` from `apkscan.intel`,
  and `IntelProvider`/`ProviderContractError` from `apkscan.intel.providers`,
  asserting a sorted `__all__` in each.
- [ ] Implement both `__init__.py` files mirroring
  `apkscan/attribution/__init__.py`.
- [ ] Run: `python -m pytest tests/test_intel_models.py tests/test_intel_provider.py -q`

### Task 7: Final gates

Run the full gates exactly (local focused loops from Tasks 1–6 may remain):

- [ ] `python -m ruff check apkscan tests`
- [ ] `python -m pyright apkscan`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`

## Final-review hardening amendment

Before PR submission, confirm:

- The public `IntelResult` cannot be constructed in a contradictory state even
  by bypassing the factories: the closed per-status table (status ⇄ reason ⇄
  evidence ⇄ missing_env), provenance (`evidence.source == provider`),
  `missing_env` grammar and `UNAVAILABLE`-only restriction, and JSON round-trip
  determinism are all enforced in `__post_init__` and covered by regression
  tests.
- No `_fetch` message, exception object, traceback, or `exc_info` can escape
  into `reason`, `to_dict()`, or logs; `?key=SECRET` is proven absent from
  result, JSON, and logs via `caplog`.
- The post-fetch contract rejects non-`IntelResult`, provider/capability/query
  mismatches (including `sources`), and non-`SUCCESS`/`EMPTY` statuses as
  `ProviderContractError`.
- No PR5 code performs network I/O, sets `active` to anything but `False`, or
  modifies `apkscan/network/*`.
- Documented-and-deferred to PR6: successful-adapter `raw_reference` credential
  sanitization; adapter stable-`id` generation; concrete FOFA/Hunter/Shodan/
  Censys adapters honoring the compatibility matrix (fixed provider-owned API
  authorities, entity never used as URL authority, adapters initially unwired
  from existing enrichers, one upstream call per explicit lookup, EMPTY/404
  mapping).
