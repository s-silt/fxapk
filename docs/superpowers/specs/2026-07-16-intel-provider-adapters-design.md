# Passive Intel Provider Adapters Design (FOFA / Hunter / Shodan / Censys)

**Date:** 2026-07-16
**Scope:** PR6 only

## Objective

Implement the first four concrete passive `IntelProvider` adapters on top of the
PR5 contract (`apkscan/intel/providers/base.py`): **FOFA**, **Hunter**,
**Shodan**, **Censys**. Each answers one or more of the three passive lookups
(`lookup_ip`, `lookup_domain`, `lookup_cert`) by making **exactly one** upstream
request to a fixed, provider-owned HTTPS authority and normalizing the response
into atomic scalar `AttributionEvidence`.

The adapters ship **unwired**: nothing in the runtime (pipeline, enrichment,
closure, CLI, report, digest, letters, cache) invokes them. They exist to be
called explicitly via `lookup_*` and are validated entirely with injected fake
sessions. No real API key is read and no network is touched in tests.

## Boundaries

PR6 does **not**:

- wire the adapters into any runtime path (no auto-discovery, no
  `configured_case_close_enrichers`, no pipeline/CLI/report/digest/letters/cache
  change);
- modify `apkscan/enrichers/*`, `apkscan/network/*`, `apkscan/attribution/*`,
  `apkscan/core/*`, `apkscan/intel/models.py`, `apkscan/intel/providers/base.py`,
  or `apkscan/intel/__init__.py`;
- add a fifth provider, web-check, ZoomEye, VirusTotal, OTX, urlscan,
  AbuseIPDB, or Quake adapter;
- perform active scanning, exploitation, retries, pagination, redirects,
  fallback lookups, or any implicit second request;
- infer a service operator, app operator, resource owner **as operator**, or
  criminal actor from any response — ASN / cloud / IDC / company / ICP data is
  **resource / hosting / ownership evidence only**;
- invent an unverified upstream API contract. Where an exact query syntax or
  response field is not confirmed from official docs or current repository
  behavior, we narrow capability rather than fabricate (see FOFA cert below).

New files live under `apkscan/intel/providers/` and `tests/` only. The single
in-scope edit outside new files is `apkscan/intel/providers/__init__.py`
(exports) and the PR5 export assertion in `tests/test_intel_provider.py`
(extended, never weakened).

## Provider → capability matrix

| provider | capabilities | env (canonical order, any-one enables) | fixed authority | 404 → EMPTY |
|---|---|---|---|---|
| `fofa` | `LOOKUP_IP`, `LOOKUP_DOMAIN` | `FXAPK_FOFA_KEY` | `fofa.info` | no (404 = FAILURE) |
| `hunter` | `LOOKUP_IP`, `LOOKUP_DOMAIN` | `FXAPK_HUNTER_KEY` | `hunter.qianxin.com` | no (404 = FAILURE) |
| `shodan` | `LOOKUP_IP`, `LOOKUP_DOMAIN` | `FXAPK_SHODAN_KEY`, `SHODAN_API_KEY` | `api.shodan.io` | yes (host) |
| `censys` | `LOOKUP_IP`, `LOOKUP_CERT` | `FXAPK_CENSYS_TOKEN`, `CENSYS_API_TOKEN` | `api.platform.censys.io` | yes (asset) |

`required_env` tuples are byte-identical, in the same preference order, to the
existing enrichers (`multisource.py` / `shodan.py`), so the intel adapters and
the legacy enrichers read the same keys with the same "first non-empty wins,
`FXAPK_` prefix first" behavior. `active = False` on every adapter (auditable
passive declaration; PR5 enforces "exactly False" at class-definition time).

### FOFA certificate capability is deliberately dropped

The canonical `lookup_cert` value is `sha256:<64 lowercase hex>` — the SHA-256
fingerprint of the leaf certificate's DER encoding. FOFA's `cert="..."` operator
matches certificate **content** substrings (subject / issuer / SAN text), and no
confirmed FOFA query field takes a SHA-256 fingerprint. Declaring `LOOKUP_CERT`
would force inventing an unverified API contract, so per the handoff we narrow:
`FofaIntelProvider.capabilities == frozenset({LOOKUP_IP, LOOKUP_DOMAIN})`.
Certificate coverage is provided by Censys, whose asset id **is** the SHA-256
fingerprint. (The stale PR5 compatibility table still lists FOFA `LOOKUP_CERT`;
the narrowed handoff supersedes it. Correcting that table is a later docs-only
change, not part of PR6.)

## Architecture: one shared bounded transport, two pure hooks per adapter

### `apkscan/intel/providers/_http.py`

An **intermediate abstract base** `_HttpIntelProvider(IntelProvider)` that does
**not** implement `_fetch` (so PR5's `__init_subclass__` correctly skips
declaration validation for this dependency-injection layer, exactly the escape
hatch PR5 documents). It provides:

- `__init__(self, session: requests.Session | None = None)` — stores the
  session behind a **name-mangled** private attribute `self.__session`
  (`_HttpIntelProvider__session`). When `session is None` it constructs one and
  mounts `HTTPAdapter(max_retries=0)` on `https://` to pin urllib3 retries off.
  The session is unreachable from adapter code without reaching into mangled
  internals.
- `_fetch_via_http(self, capability, query) -> IntelResult` — a concrete
  template holding the **only** `session.get(...)` call-site in the package.
- Two **abstract pure hooks** each adapter implements (neither receives the
  session, so an adapter physically cannot issue a second request):
  - `_request_spec(self, capability, query) -> _RequestSpec` — returns the
    request shape (path + params + headers + `empty_on_404`), reading its own
    credential from `os.environ` and encoding the canonical value into a query
    param or path segment. No I/O.
  - `_interpret(self, capability, query, payload) -> tuple[AttributionEvidence, ...]`
    — receives the already-bounded parsed JSON and returns atomic evidence.
    Raises on a provider-declared error or a malformed / all-invalid payload;
    returns `()` for a valid no-record response.

Each concrete adapter's `_fetch` is the one-line delegation
`return self._fetch_via_http(capability, query)`. `_fetch` stays the sole
polymorphic hook the PR5 dispatch sees; the shared transport and both pure hooks
are non-overridable-by-accident because the session never flows to a hook.

### `_RequestSpec` (frozen dataclass in `_http.py`)

| field | type | rule |
|---|---|---|
| `path` | `str` | must start with `/`; reject `://`, `?`, `#`, and any whitespace |
| `params` | `Mapping[str, str]` | query params (may carry the API key for FOFA/Hunter/Shodan) |
| `headers` | `Mapping[str, str]` | closed name allowlist: `Authorization`, `Accept`, `User-Agent`, `X-Organization-ID` |
| `empty_on_404` | `bool = False` | `True` only for Shodan host and Censys asset endpoints |

The transport builds the URL itself as `"https://" + type(self)._API_AUTHORITY +
spec.path`. `_API_AUTHORITY` is a per-adapter class constant validated once at
class-definition time via `normalize_authority` (domain only, no port → HTTPS
implies 443, no userinfo). The hook returns path/params/headers only and
**cannot** supply an authority or scheme, so the looked-up entity can never
become the URL host. Entity values interpolated into a path (Shodan
`/shodan/host/{ip}`, Censys `/v3/global/asset/host/{ip}` and
`/certificate/{sha256}`) are additionally `urllib.parse.quote(value, safe="")`
encoded (defense-in-depth; dispatch already guaranteed a canonical value).

There is **no** `FXAPK_*_URL` authority override. The legacy enrichers'
`FXAPK_FOFA_URL` / `FXAPK_ZOOMEYE_URL` override is an explicit anti-pattern PR6
does not copy: a poisoned environment must not be able to redirect a
key-bearing request to an attacker host.

### `_fetch_via_http` guard order

PR5 dispatch has already run (query type → declared capability → entity-kind
match → canonical value → `required_env` presence). The transport then runs, in
order:

1. `spec = self._request_spec(capability, query)` (pure; validates path shape).
2. Single `session.get(url, params=spec.params, headers=spec.headers,
   timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT), allow_redirects=False,
   stream=True)` inside `try/finally response.close()`.
3. Status gate (no `raise_for_status()` — it embeds the key-bearing URL in its
   message): `200` → proceed; `404 and spec.empty_on_404` → return
   `IntelResult.empty(...)` (a **value**, since `_fetch` may only return
   SUCCESS/EMPTY); `3xx` → `RedirectResponseError`; `401/403` → `AuthError`;
   `429` → `RateLimitedError`; other `4xx` → `ClientError`; `5xx` →
   `ServerError`; any other → `UnexpectedStatusError`.
4. Content-Length pre-check (reject before reading a byte if present and over
   cap).
5. Streamed bounded read: `iter_content(_CHUNK_SIZE)` accumulating
   **decompressed** bytes; raise `OversizeResponseError` the moment total >
   `_MAX_RESPONSE_BYTES`; raise `UpstreamTimeoutError` if `time.monotonic()`
   passes a `_WALL_DEADLINE` since the read began.
6. `json.loads`; top-level must be a `dict` else `MalformedPayloadError`.
   (A pathologically nested body raises `RecursionError` inside `json.loads`,
   which PR5's base converts to a sanitized `FAILURE` — a valid backstop.)
7. `evidence = self._interpret(capability, query, payload)` (bounded caps;
   raises on declared error / malformed / all-invalid); return
   `IntelResult.success(...)` if non-empty else `IntelResult.empty(...)`.

Every genuine error is **raised** (never caught in the transport) so PR5's
secret-safe wrapper (`_safe_exception_name`) turns it into `FAILURE` with a
bare-identifier `reason`. The transport never constructs `FAILURE` itself and
never returns `UNSUPPORTED`/`UNAVAILABLE` (those are dispatch's job).

### Exception taxonomy (in `_http.py`)

A closed set of `IntelProvider`-internal exception classes whose **name is the
diagnostic** and which carry **no message or a static string only** — never a
URL, header, status text, or body fragment:

`RedirectResponseError`, `AuthError`, `RateLimitedError`, `ClientError`,
`ServerError`, `UnexpectedStatusError`, `OversizeResponseError`,
`UpstreamTimeoutError`, `MalformedPayloadError`, `ProviderDeclaredError`,
`CredentialMissingError`, `CertificateMismatchError`.

Each class name is a valid Python identifier, so PR5's `_safe_exception_name`
yields it verbatim as the `reason` and models.py's `isidentifier()` FAILURE
check accepts it. `requests`' own exceptions (`Timeout`, `SSLError`,
`ConnectionError`, `JSONDecodeError`) are allowed to propagate; their **type
name** (also an identifier) becomes the reason, and their message — which may
embed the key-bearing URL — is discarded by the base and never logged.

### Bound constants (module-level in `_http.py`, imported by tests)

| constant | value | purpose |
|---|---|---|
| `_CONNECT_TIMEOUT` | `5.0` | connect timeout (seconds) |
| `_READ_TIMEOUT` | `15.0` | per-read timeout (seconds) |
| `_WALL_DEADLINE` | `30.0` | total wall-clock ceiling per read (defeats slow-drip) |
| `_MAX_RESPONSE_BYTES` | `5_242_880` (5 MiB) | decompressed body cap |
| `_CHUNK_SIZE` | `65_536` | stream chunk size |
| `_MAX_RECORDS` | `100` | max array items considered per JSON array |
| `_MAX_SCALAR_LEN` | `512` | descriptive-string truncation length |
| `_MAX_EVIDENCE` | `256` | max evidence records per result, applied after dedup+sort |

Truncation is deterministic: descriptive strings are truncated to
`_MAX_SCALAR_LEN`; identity-bearing values (IP / domain / SHA-256) are instead
re-validated with `normalize_ip` / `normalize_domain` and **skipped if invalid**
rather than truncated; the `_MAX_EVIDENCE` cap is applied after dedup + sort so
the kept subset is reproducible.

## Evidence model

### Closed evidence `type` vocabulary (resource / hosting / ownership only)

Provider-neutral types (the provider is already recorded in `source`), targeting
the queried entity:

- **IP target** (`kind=IP`): `asn` (int), `as_org`, `hosting_org`, `isp`,
  `company`, `icp`, `bgp_prefix`, `geo_country`, `geo_region`, `geo_city`,
  `open_port` (int), `service_product`, `service_version`, `service_server`,
  `related_hostname`.
- **DOMAIN target** (`kind=DOMAIN`): `resolved_ip` (value = IP), `related_ip`
  (value = IP), `related_hostname`. IP-scoped facts (asn / geo / ports /
  service_*) are **never** attached to a DOMAIN target — a domain has no ASN.
  The resolved / related IP is surfaced as a scalar value so a future pipeline
  can enqueue a fresh explicit IP lookup instead of the adapter chaining a
  request or minting an entity.
- **CERTIFICATE target** (`kind=CERTIFICATE`): `cert_fingerprint_sha256`,
  `cert_subject_cn`, `cert_subject_dn`, `cert_issuer_cn`, `cert_issuer_org`,
  `cert_issuer_dn`, `cert_san_dns`, `cert_not_before`, `cert_not_after`
  (all str values).

Explicitly **excluded**: web/page titles, `tags` / reputation / pulses /
analysis stats (threat labels), OS guesses, and any operator/actor label. These
would drift from infrastructure attribution into operator/actor attribution.

### `AttributionEvidence` construction

- `id = stable_digest(f"apkscan.intel/{provider}", {"t": type, "k":
  target.kind.value, "e": target.value, "v": value})` — full 64-hex digest, not
  truncated. The payload is exactly the identity-bearing tuple; it deliberately
  **omits** `confidence`, `timestamp`, `raw_reference`, and `target.sources` so
  the id is a pure function of the fact. Two genuinely different facts (port 80
  vs 443; `asn` vs `as_org` on one IP) get different ids; an identical fact
  reproduces the same id, so `IntelResult`'s per-id dedup never fires a
  false "conflicting evidence" rejection.
- `source = provider` (the adapter `name`; PR5 requires `evidence.source ==
  provider`).
- `value` is always a **JSON scalar** (`str | int | float | bool | None`). Every
  array element and every nested service/location/AS field is decomposed into
  its own record; a container is never stored as `value`.
- `confidence = 0.5` — one flat module constant for every record. A single
  passive OSINT observation is corroborating, never confirming; 0.5 is an
  explicit "material but unconfirmed single source" prior that sits below the
  fusion layer's ≥2-strong-signal confirmation bar. A flat constant is also
  deterministic, which id/dedup stability requires (a value-dependent confidence
  could make two identical facts carry differing payloads and trip the conflict
  check).
- `timestamp = None` for all PR6 evidence. Provider record times mean "when the
  provider last saw the asset", not "when we collected it"; using them would
  fabricate freshness and add a non-deterministic field. Certificate validity
  dates are captured as **values** (`cert_not_before` / `cert_not_after`), never
  as the evidence timestamp.
- `raw_reference = f"{provider}:{capability.value}"` (e.g. `"fofa:lookup_ip"`).
  **Load-bearing rule:** `raw_reference` is assembled **only** from the closed
  set {provider name constant, capability enum value}. It is forbidden to derive
  `raw_reference` (or `id`, `value`, `reason`) from the request URL, query
  params, headers, or any response / exception text. FOFA / Hunter / Shodan
  carry the API key in the query string and Censys carries a Bearer token in a
  header; assembling `raw_reference` from compile-time constants makes leakage
  impossible by construction. Structural invariant: `raw_reference` contains no
  `?`, `#`, `&`, `=`, or whitespace.

### Scalar coercion discipline

- ASN → int: strip a leading `AS`/`as`, decimal-parse, keep only
  `1 ≤ n ≤ 4_294_967_294`, else skip the record.
- port → int (skip non-int / out of `1..65535`).
- org / isp / company / icp / geo / server / product / version / hostname / CN /
  DN / SAN / date → stripped, length-bounded `str`; skip empty / blank; drop any
  non-finite float. Never store a container.

`_validate_value` (in `AttributionEvidence`) then never raises.

## Per-provider request / parse contracts

### FOFA (`fofa.py`, `LOOKUP_IP`, `LOOKUP_DOMAIN`)

- `GET https://fofa.info/api/v1/search/all`; params `key=<FXAPK_FOFA_KEY value>`,
  `qbase64=base64(query)`, `fields=<bounded set>`, `size=<_MAX_RECORDS>`.
  Query: `ip="<value>"` for IP, `domain="<value>"` for DOMAIN.
- `fields = "host,ip,port,protocol,server,country,region,city,as_number,as_organization"`
  (page/title excluded — content, not infrastructure). Rows are positional lists
  aligned to `fields`.
- IP target mapping: `port→open_port`, `server→service_server`,
  `country→geo_country`, `region→geo_region`, `city→geo_city`,
  `as_number→asn`, `as_organization→as_org`, `host→related_hostname`.
- DOMAIN target mapping (domain-scoped only): row `ip→related_ip`,
  `host→related_hostname`.
- Declared error: truthy `root["error"]` → `ProviderDeclaredError` (FOFA uses
  `error:true`+`errmsg`, **inverted** from the generic `success:false`). No
  records (`error:false` + empty/absent `results`, or all cells null) → `()`
  (EMPTY). Wrong envelope type (`results` not a list) → `MalformedPayloadError`.

### Hunter (`hunter.py`, `LOOKUP_IP`, `LOOKUP_DOMAIN`)

- `GET https://hunter.qianxin.com/openApi/search`; params
  `api-key=<FXAPK_HUNTER_KEY value>`, `search=urlsafe_b64(query)`, `page=1`,
  `page_size=<_MAX_RECORDS>`, `is_web=3`. Query `ip="<value>"` / `domain="<value>"`.
- Response `{"code":200,"data":{"arr"|"list":[{...}]}}`. Hunter's `code==200`
  means OK (HTTP-style code embedded in JSON). Declared error: `code` not in
  `{200, "200"}` → `ProviderDeclaredError` (e.g. 401 auth, 40205 rate-limit).
- IP target: `as_number/number→asn`, `as_org/as_organization→as_org`,
  `isp→isp`, `company→company`, ICP field (`icp`/`number`)→`icp`,
  `country→geo_country`, `province/region→geo_region`, `city→geo_city`,
  `port→open_port`, `server→service_server`, `component/product→service_product`.
  DOMAIN target: `ip→related_ip`, discovered host→`related_hostname` only.
- No records (`code:200` + empty/absent `arr`/`list`) → `()` (EMPTY). No
  pagination (single page regardless of `total`).

### Shodan (`shodan.py`, `LOOKUP_IP`, `LOOKUP_DOMAIN` = resolve-only)

- **IP (host):** `GET https://api.shodan.io/shodan/host/{ip}`; params
  `key=<FXAPK_SHODAN_KEY|SHODAN_API_KEY value>`; `empty_on_404=True`. Split
  `ports[]→open_port`, `hostnames[]→related_hostname`, per-service
  `product→service_product` / `version→service_version` /
  `http.server→service_server`, plus `org→hosting_org`, `isp→isp`, `asn→asn`,
  `country_name/country_code→geo_country`. Target = queried IP. `tags` /
  `http.title` excluded.
- **DOMAIN (resolve-only):** `GET https://api.shodan.io/dns/resolve`; params
  `hostnames=<domain>`, `key=<key>`; `empty_on_404=False`. Response
  `{"<domain>":"1.2.3.4"}`. Emit **exactly one** `resolved_ip` evidence
  (target = queried DOMAIN, value = `normalize_ip(ip)`) and return — **never**
  build `/shodan/host/{ip}`, never issue a second request. Absent / null / blank
  value → `()` (EMPTY). A non-IP value → `MalformedPayloadError` (FAILURE). This
  is the sharpest divergence from the legacy enricher, which chains
  resolve→host; the shared transport makes the chain structurally impossible.

### Censys (`censys.py`, `LOOKUP_IP`, `LOOKUP_CERT`)

- **IP (host):** `GET https://api.platform.censys.io/v3/global/asset/host/{ip}`;
  headers `Authorization: Bearer <FXAPK_CENSYS_TOKEN|CENSYS_API_TOKEN value>`,
  `Accept: application/vnd.censys.api.v3.host.v1+json` (confirmed from the
  current enricher), optional `X-Organization-ID` from `FXAPK_CENSYS_ORG_ID` if
  present; `empty_on_404=True`. Single-asset body wrapped `{"result":{...}}` or
  `{"data":{...}}` (tolerate both — one response, one request). Map
  `autonomous_system.asn→asn`, `.name/.organization→as_org`,
  `.bgp_prefix→bgp_prefix`, `location country_code→geo_country`,
  `region/province→geo_region`, `city→geo_city`, `services[]` port/product/
  version/server → `open_port`/`service_product`/`service_version`/
  `service_server`. Target = queried IP.
- **CERT:** `GET https://api.platform.censys.io/v3/global/asset/certificate/{sha256}`,
  where `{sha256}` is the 64-hex from stripping the `sha256:` prefix off the
  canonical value; headers `Authorization: Bearer <token>`,
  `Accept: application/json` (the vendored certificate media type is **not**
  confirmed, so we use generic JSON rather than invent
  `...certificate.v1+json` and risk a 406); `empty_on_404=True`. Never chain
  certificate host-history / threat-hunting calls. Parse confirmed paths:
  `fingerprint_sha256→cert_fingerprint_sha256`,
  `parsed.subject_dn→cert_subject_dn`,
  `parsed.subject.common_name[]→cert_subject_cn`,
  `parsed.issuer_dn→cert_issuer_dn`,
  `parsed.issuer.common_name[]→cert_issuer_cn`,
  `parsed.issuer.organization[]→cert_issuer_org`,
  `names[]` ∪ `parsed.extensions.subject_alt_name.dns_names[]` (dedup) →
  `cert_san_dns`, `parsed.validity_period.not_before/not_after` →
  `cert_not_before`/`cert_not_after`. Target = queried CERTIFICATE.
- **Corroboration guard:** the returned `fingerprint_sha256` must equal the
  queried 64-hex (case-insensitive); a mismatch raises
  `CertificateMismatchError` (FAILURE, no evidence) rather than emitting
  evidence for the wrong certificate.

## Determinism, provenance, secret safety

- **Determinism:** ids, confidence (flat 0.5), timestamp (None), and
  `raw_reference` (constant token) are pure functions of the fact, so the same
  response yields byte-identical `to_dict()` across runs, and `IntelResult` dedup
  + sort produce a stable tuple. Truncation caps are applied after dedup + sort.
- **Provenance:** every `evidence.source` equals the adapter `name`; `query`
  records the looked-up entity including `sources`.
- **Passive by declaration:** `active = False`; exactly one bounded, fixed-
  authority, no-redirect GET per lookup; the session is unreachable from hooks.
- **Secret safety (PR6-owned surface):** PR5 already seals the exception→reason
  and base-log paths. PR6 owns three additional leak surfaces and closes each:
  (1) `raw_reference` — assembled only from provider+capability constants;
  (2) adapter logging — **none**; adapters never log, never `str()` a requests
  exception, never format URLs/params/headers/bodies; (3) request shape —
  `allow_redirects=False` + fixed constant authority stop the key-bearing query
  string (three providers) and the Bearer header (Censys) from being re-sent to
  a Location host. The credential is read from `os.environ` inside
  `_request_spec` (any-one non-empty over `required_env`) and never stored on the
  instance. Residual risk documented (not code-fixed) in PR6: with a real
  session under global `DEBUG` logging, `urllib3.connectionpool` logs the request
  line with the query string — forensic runs must not enable urllib3 DEBUG.

## Tests (fake sessions, no network, no real keys)

Test files:

- `tests/intel_provider_fakes.py` — reusable `FakeResponse` (byte body;
  `status_code`, `headers`, `iter_content(chunk)` counting emitted bytes,
  `json()` parsing from bytes, `close()` setting `closed`, `__enter__/__exit__`;
  faithfully mirrors requests semantics — only `>=400` would raise if
  `raise_for_status` were used, but the transport does its own status gate) and
  `FakeSession` (records `(url, params, headers, timeout, allow_redirects,
  stream)` per `get`; pops a queued `FakeResponse` or raises a queued exception;
  **raises `AssertionError` on a second `get`** so the one-request invariant is a
  tripwire everywhere). An `autouse` fixture scrubs all six env vars plus the
  legacy `FXAPK_FOFA_URL` / `FXAPK_CENSYS_ORG_ID` (the dev machine's real `.env`
  must never leak into a test).
- `tests/test_intel_providers_contract.py` — parametrized over the four adapters
  × their declared capabilities: `UNAVAILABLE` with zero request;
  `UNSUPPORTED`/`capability_not_supported` (FOFA cert, Censys domain) and
  `entity_kind_mismatch` with zero request; non-canonical value raises before
  the wire; exactly-one-request on SUCCESS/EMPTY/each FAILURE and zero on
  UNAVAILABLE/UNSUPPORTED/non-canonical; response closed on every path; fixed
  HTTPS authority with the entity absent from the netloc; timeout tuple present;
  `allow_redirects=False`; 3xx → FAILURE not followed; the FAILURE matrix
  (Timeout, SSLError, 401, 429, 500, non-JSON, wrong-envelope, oversize,
  deep-nested) → sanitized identifier reason with empty evidence; secret absent
  from `reason` / logs / `to_dict()` / `raw_reference`; byte-identical `to_dict()`
  across runs and stable under input-row shuffle.
- `tests/test_intel_provider_{fofa,hunter,shodan,censys}.py` — provider-specific
  query construction (qbase64 / urlsafe-b64 / path segment), atomic-evidence
  splitting with recomputed `stable_digest` ids, the EMPTY-vs-FAILURE boundary
  (declared error, empty results, wrong envelope), truncation caps, and the
  narrowed/critical behaviors: FOFA `lookup_cert` → UNSUPPORTED and
  `FXAPK_FOFA_URL` override ignored; Shodan domain single `/dns/resolve` with no
  `/shodan/host` chain; Censys Bearer-only (no query string), `result`/`data`
  envelope equivalence, cert path fingerprint form, and fingerprint-mismatch →
  FAILURE.

Scope-conformance tests: adapters absent from `discover_enrichers()` and not
`BaseEnricher` subclasses; `configured_case_close_enrichers()` name-set
unchanged; no `apkscan/**` module outside `apkscan/intel/` references
`apkscan.intel`; `required_env` parity with the legacy enrichers; `active is
False` declared per adapter; exact capability frozensets;
`apkscan.intel.providers.__all__` sorted and extended; `apkscan.intel.__all__`
unchanged; import of `apkscan.intel.providers` is side-effect-free (no network,
no env-value read) under a socket guard.
