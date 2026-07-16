# Passive Intel Provider Adapters Implementation Plan (PR6)

> **For agentic workers:** use test-driven development for every implementation
> change (red → green → refactor). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship four concrete passive `IntelProvider` adapters — FOFA, Hunter,
Shodan, Censys — on the PR5 contract. Each makes **exactly one** bounded upstream
GET to a fixed provider-owned HTTPS authority and normalizes the response into
atomic scalar `AttributionEvidence`. Adapters are **unwired** and validated with
injected fake sessions only. No live key, no network, no runtime/report/CLI
change. See `docs/superpowers/specs/2026-07-16-intel-provider-adapters-design.md`.

**Architecture:** A shared intermediate abstract base
`_HttpIntelProvider(IntelProvider)` (in `apkscan/intel/providers/_http.py`) keeps
`_fetch` abstract, holds the injected session behind a name-mangled attribute,
and exposes one transport template `_fetch_via_http` plus two pure hooks
`_request_spec` / `_interpret`. Each adapter's `_fetch` is a one-line delegation.
The transport is the package's only `session.get` call-site: one GET,
`allow_redirects=False`, `stream=True`, `timeout=(5, 15)`, streamed byte cap,
wall deadline, `try/finally` close, typed message-free exceptions that PR5's base
sanitizes into `FAILURE`. Reuse `AttributionEvidence`,
`NetworkEntity`/`NetworkEntityType`, `normalize_ip`/`normalize_domain`/
`stable_digest`, and the `os.environ` any-one-non-empty credential convention.

**Tech stack:** Python 3.11+, `requests`, frozen dataclasses, pytest, Ruff,
Pyright.

## Global constraints

- Exactly one upstream GET per lookup; fixed constant authority; no redirects,
  retries, pagination, fallback, or implicit second request. Shodan domain =
  single `/dns/resolve`, no host chain (structurally enforced — hooks get no
  session).
- Bounded everything: `timeout=(5, 15)`, `_WALL_DEADLINE=30`,
  `_MAX_RESPONSE_BYTES=5 MiB` (decompressed, streamed), `_MAX_RECORDS=100`,
  `_MAX_SCALAR_LEN=512`, `_MAX_EVIDENCE=256`. Always close the response.
- Atomic scalar `AttributionEvidence`; arrays/nested dicts split into per-scalar
  records; `value` is always a JSON scalar. Deterministic dedup + sort;
  `_MAX_EVIDENCE` applied after dedup + sort.
- `id = stable_digest(f"apkscan.intel/{provider}", {"t":type,"k":kind,"e":target,
  "v":value})`; `confidence = 0.5` flat; `timestamp = None`;
  `raw_reference = f"{provider}:{capability.value}"` (no `?#&=`/whitespace,
  never derived from URL/headers/body).
- Secret safety: no adapter logging; never `str()` a requests exception; typed
  message-free exceptions only; credential read from `os.environ` inside
  `_request_spec`, never stored on the instance; no `FXAPK_*_URL` authority
  override.
- Resource/hosting/ownership evidence only; never infer operator/actor. Excluded:
  titles, tags, reputation, pulses, OS guesses.
- `active = False` (explicit per adapter); `required_env` byte-identical to the
  legacy enrichers.
- Adapters unwired: no auto-discovery, no runtime references anywhere under
  `apkscan/` outside `apkscan/intel/`.

## File structure

- Create `apkscan/intel/providers/_http.py`: `_HttpIntelProvider` ABC,
  `_RequestSpec`, bound constants, exception taxonomy, credential helper,
  evidence-normalization helpers (`_stable_evidence`, `_coerce_asn`,
  `_bounded_text`, `_finalize_evidence`).
- Create `apkscan/intel/providers/fofa.py`: `FofaIntelProvider`.
- Create `apkscan/intel/providers/hunter.py`: `HunterIntelProvider`.
- Create `apkscan/intel/providers/shodan.py`: `ShodanIntelProvider`.
- Create `apkscan/intel/providers/censys.py`: `CensysIntelProvider`.
- Modify `apkscan/intel/providers/__init__.py`: export the four adapters +
  `IntelProvider` + `ProviderContractError`; sorted `__all__`.
- Create `tests/intel_provider_fakes.py`: `FakeResponse`, `FakeSession`, the
  env-scrub autouse fixture, and shared assert helpers.
- Create `tests/test_intel_providers_contract.py`: cross-provider invariants.
- Create `tests/test_intel_provider_fofa.py`, `_hunter.py`, `_shodan.py`,
  `_censys.py`: provider-specific behavior.
- Create `tests/test_intel_providers_scope.py`: scope/compat conformance.
- Modify `tests/test_intel_provider.py`: extend the `test_providers_subpackage_exports`
  assertion to the new sorted `__all__` (extend, never weaken). Do **not** touch
  `apkscan/intel/__init__.py`, `apkscan/intel/models.py`,
  `apkscan/intel/providers/base.py`, or any file outside `apkscan/intel/providers/`
  and `tests/`.

---

### Task 1: Shared bounded transport `_HttpIntelProvider` + `_RequestSpec` + exceptions

**Files:** Create `apkscan/intel/providers/_http.py`; test
`tests/intel_provider_fakes.py`, `tests/test_intel_providers_contract.py` (start
with a minimal in-test adapter fixture).

- [ ] Write `FakeResponse` / `FakeSession` and the env-scrub autouse fixture in
  `tests/intel_provider_fakes.py`. `FakeSession.get` records the full call and
  pops one queued response/exception; a second `get` raises `AssertionError`.
- [ ] Write failing tests using a minimal in-test `_HttpIntelProvider` subclass
  (fixed `_API_AUTHORITY`, trivial `_request_spec`/`_interpret`):
  - exactly one `get` with `allow_redirects=False`, `stream=True`,
    `timeout=(5.0, 15.0)`; URL = `https://<authority><path>`; entity value never
    in netloc;
  - status gate: `200`→interpret; `404`+`empty_on_404`→EMPTY; `404` without the
    flag / `3xx` / `401` / `403` / `429` / `4xx` / `5xx` / other → the matching
    typed exception, surfaced by PR5 dispatch as `FAILURE` with the class name as
    `reason` (identifier), zero evidence, one request, response closed;
  - Content-Length over cap → `OversizeResponseError` with no body read; streamed
    body over cap → `OversizeResponseError` mid-stream; patched `monotonic` past
    `_WALL_DEADLINE` → `UpstreamTimeoutError`;
  - non-JSON body → requests `JSONDecodeError`-class reason; top-level non-dict →
    `MalformedPayloadError`; response closed on every path;
  - `_RequestSpec` rejects a path without a leading `/` or containing
    `://`/`?`/`#`/whitespace, and a header name outside the allowlist;
  - `_API_AUTHORITY` validated at class-definition (a bad authority fails).
- [ ] Implement `_HttpIntelProvider` (name-mangled session,
  `HTTPAdapter(max_retries=0)` when self-constructed), `_fetch_via_http`, the
  `_RequestSpec` frozen dataclass, the bound constants, the exception taxonomy,
  and the `__init_subclass__` authority check.
- [ ] Run: `python -m pytest tests/test_intel_providers_contract.py -q`

### Task 2: Evidence normalization helpers

**Files:** Modify `apkscan/intel/providers/_http.py`; test in a focused module or
within the contract test.

- [ ] Write failing tests: `_stable_evidence(provider, capability, type, target,
  value)` builds an `AttributionEvidence` whose `id` equals a recomputed
  `stable_digest(f"apkscan.intel/{provider}", {...})`, `confidence == 0.5`,
  `timestamp is None`, `raw_reference == f"{provider}:{capability.value}"` (no
  `?#&=`/whitespace); `_coerce_asn` strips `AS`, range-checks, skips invalid;
  `_bounded_text` strips + truncates to `_MAX_SCALAR_LEN`, drops blanks;
  `_finalize_evidence` dedups by id, sorts by the `IntelResult` key, and caps at
  `_MAX_EVIDENCE` deterministically. `value` is always a JSON scalar.
- [ ] Implement the helpers.
- [ ] Run the focused test.

### Task 3: FOFA adapter

**Files:** Create `apkscan/intel/providers/fofa.py`; test
`tests/test_intel_provider_fofa.py`.

- [ ] Write failing tests: capabilities == `{LOOKUP_IP, LOOKUP_DOMAIN}` and
  `lookup_cert` → UNSUPPORTED with zero request; `required_env ==
  ('FXAPK_FOFA_KEY',)`; IP query `qbase64` decodes to `ip="<value>"`, domain to
  `domain="<value>"`; a positional-row body splits into the expected atomic
  `(type, value)` set on the queried IP with recomputed ids and `source=='fofa'`;
  domain lookup emits only `related_ip`/`related_hostname` (no asn/geo/port);
  `error:true` → FAILURE with the `errmsg` absent everywhere; `error:false`+empty
  `results` → EMPTY; `results` wrong type → FAILURE; 500-row body → bounded,
  deterministic; `FXAPK_FOFA_URL=http://evil.example` is ignored (request still
  to `https://fofa.info`).
- [ ] Implement `FofaIntelProvider` (`_request_spec` builds the qbase64 query and
  reads `FXAPK_FOFA_KEY`; `_interpret` checks `error`, maps rows).
- [ ] Run: `python -m pytest tests/test_intel_provider_fofa.py -q`

### Task 4: Hunter adapter

**Files:** Create `apkscan/intel/providers/hunter.py`; test
`tests/test_intel_provider_hunter.py`.

- [ ] Write failing tests: capabilities == `{LOOKUP_IP, LOOKUP_DOMAIN}`;
  `required_env == ('FXAPK_HUNTER_KEY',)`; `search` param is urlsafe-b64 of the
  `ip=`/`domain=` query; `code:200`+`data.arr` splits into atomic evidence on the
  IP; domain → `related_ip`/`related_hostname` only; `code` not in `{200,'200'}`
  (401, 40205) → FAILURE with the message absent; `code:200`+empty/`null`
  `arr`/`list` → EMPTY; `total` large still one request, `page==1`; overflow
  truncated.
- [ ] Implement `HunterIntelProvider`.
- [ ] Run: `python -m pytest tests/test_intel_provider_hunter.py -q`

### Task 5: Shodan adapter (host + resolve-only domain)

**Files:** Create `apkscan/intel/providers/shodan.py`; test
`tests/test_intel_provider_shodan.py`.

- [ ] Write failing tests: capabilities == `{LOOKUP_IP, LOOKUP_DOMAIN}`;
  `required_env == ('FXAPK_SHODAN_KEY','SHODAN_API_KEY')` (legacy alias alone
  enables); host success splits `ports[]`/`hostnames[]`/services into atomic
  records on the IP, excludes `tags`/`http.title`; host 404 → EMPTY (one call);
  **domain resolve → exactly one `resolved_ip` evidence (normalized) and the fake
  session received exactly one GET to `/dns/resolve`, never `/shodan/host`**;
  resolve null/missing key → EMPTY; resolve non-IP value → FAILURE; ports
  overflow truncated; the key never appears in `to_dict`/logs/`raw_reference`.
- [ ] Implement `ShodanIntelProvider` (`_request_spec` branches on capability;
  domain returns the resolve spec; `_interpret` for domain emits a single
  `resolved_ip` and cannot reach the host path).
- [ ] Run: `python -m pytest tests/test_intel_provider_shodan.py -q`

### Task 6: Censys adapter (host + certificate)

**Files:** Create `apkscan/intel/providers/censys.py`; test
`tests/test_intel_provider_censys.py`.

- [ ] Write failing tests: capabilities == `{LOOKUP_IP, LOOKUP_CERT}` and
  `lookup_domain` → UNSUPPORTED zero request; `required_env ==
  ('FXAPK_CENSYS_TOKEN','CENSYS_API_TOKEN')`; host uses `Authorization: Bearer
  <token>` (no query string) + the confirmed host media type; `result` and
  `data` envelopes produce byte-identical evidence; host 404 → EMPTY; cert path
  is `/v3/global/asset/certificate/<64hex>` (prefix stripped) with
  `Accept: application/json`; cert success splits SAN (`names[]` ∪ `dns_names[]`),
  CN, issuer org into atomic records on the CERTIFICATE; a returned fingerprint
  != queried → FAILURE (`CertificateMismatchError`) with no evidence; cert 404 →
  EMPTY with no second (host-history) call; token never in `to_dict`/logs.
- [ ] Implement `CensysIntelProvider`.
- [ ] Run: `python -m pytest tests/test_intel_provider_censys.py -q`

### Task 7: Exports + cross-provider contract + scope conformance

**Files:** Modify `apkscan/intel/providers/__init__.py`; create
`tests/test_intel_providers_scope.py`; extend
`tests/test_intel_providers_contract.py` to run over all four real adapters;
modify the `test_providers_subpackage_exports` assertion in
`tests/test_intel_provider.py`.

- [ ] Write failing tests:
  - `apkscan.intel.providers.__all__` is sorted and equals the four adapter
    classes plus `IntelProvider`, `ProviderContractError`; `apkscan.intel.__all__`
    unchanged (PR5 seven names); importing `apkscan.intel.providers` is
    side-effect-free under a socket/env guard;
  - scope: adapters not in `discover_enrichers()` and not `BaseEnricher`
    subclasses; `configured_case_close_enrichers()` name-set unchanged; no
    `apkscan/**` module outside `apkscan/intel/` contains the text
    `apkscan.intel`; `required_env` parity with the legacy enricher constants;
    `active is False` declared per adapter; exact capability frozensets;
  - the full cross-provider contract matrix (Task-1 invariants) parametrized over
    all four real adapters × capabilities, including the secret-absence and
    deterministic-`to_dict` assertions.
- [ ] Implement the `providers/__init__.py` export update.
- [ ] Run: `python -m pytest tests/test_intel_provider.py
  tests/test_intel_providers_contract.py tests/test_intel_providers_scope.py -q`

### Task 8: Final gates

Run the full gates and save the results:

- [ ] `python -m ruff check apkscan tests`
- [ ] `python -m pyright apkscan`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`

## Final-review hardening checklist

Before PR submission confirm:

- Every adapter makes **exactly one** `session.get`; the only `session.get`
  call-site in the package is in `_http.py`; Shodan domain never chains
  `/shodan/host`; Censys cert never chains host-history.
- No credential, request URL, header, or upstream body fragment can reach
  `raw_reference`, `value`, `reason`, `to_dict()`, or logs; a secret injected via
  env is proven absent from every SUCCESS and FAILURE output via `caplog` +
  `json.dumps(to_dict())`, with a positive control confirming the key was sent
  upstream.
- Every `evidence.value` is a JSON scalar; ids are recomputed-stable; confidence
  is a flat 0.5; timestamp is None; dedup/sort/truncation are deterministic.
- FOFA declares no `LOOKUP_CERT`; the `FXAPK_FOFA_URL` override is ignored; no
  adapter reads a `FXAPK_*_URL` authority override.
- Adapters are unwired (no auto-discovery, no runtime reference), `active is
  False`, `required_env` matches the legacy enrichers, capability frozensets are
  exact, and only files under `apkscan/intel/providers/` + `tests/` changed
  (plus the one extended PR5 export assertion).
- No PR6 code performs an active scan, follows a redirect, exceeds the bounds, or
  modifies frozen layers.
