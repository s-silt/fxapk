# Infrastructure Attribution Graph Design

**Date:** 2026-07-16
**Scope:** PR7 only

## Objective

Add an **in-memory, deterministic, explainable infrastructure attribution
graph** value model plus a **pure builder** that assembles it from facts already
produced by PR1–PR6 (`Observation`, `AttributionEvidence` inside a
`ConversionResult`, `RoleScore`, and `IntelResult`). Every node and edge carries
provenance back to the supporting observation/evidence ids, so the graph answers
"why is this here?" for every element.

Like PR1–PR6 it ships **unwired**: nothing in the runtime constructs it, and it
changes no `report.json` schema (wiring a `network_attribution` output is PR9).
New code lives in `apkscan/attribution/graph.py` + `tests/`, with one additive
export line in `apkscan/attribution/__init__.py`.

## This is NOT the legacy graph

`apkscan/graph/` (Kuzu `Apk`/`Entity`/`OBSERVED` property-graph store, with
`store.py`/`query.py`/`ingest.py`/`weight.py`) and `apkscan/commands/graph.py` /
`track.py` are a **frozen, deprecated** product. PR7 must **not** import, touch,
revive, or resemble it. Hard rules:

- No `import apkscan.graph` / `from apkscan import graph`; the legacy importer set
  does not grow.
- No heavyweight DB: no `kuzu`, no `sqlite3`, no persistence/DDL vocabulary
  (`NODE TABLE`, `REL TABLE`, `PRIMARY KEY`, `.kuzu`), no `store`/`query`/`ingest`
  API, no new dependency.
- No class named `Entity`, no edge named `OBSERVED`, no `"{kind}:{value}"` string
  primary key, no `first_seen`/`last_seen`/`weight` field names.
- This is also distinct from `apkscan/core/attribution.py` (the wired five-layer
  resource-attribution enricher) — do not touch or confuse it.

A guard test asserts importing `apkscan.attribution.graph` pulls in no
`apkscan.graph.*`, `kuzu`, or `sqlite3`, and the module source contains no
`OBSERVED` token.

## Boundaries

PR7 does **not**: wire into pipeline/report/digest/letters/CLI; change
`report.json`; modify `apkscan/network/*`, `apkscan/attribution/{models,roles,
scorer}.py`, `apkscan/intel/*`, `apkscan/core/*`, `apkscan/graph/*`, or the CLI;
add a dependency; perform any I/O or network; re-run `RoleClassifier`/
`EvidenceScorer` (roles are consumed verbatim); mutate the frozen
`NetworkEntityType` enum; synthesize clusters or infer an operator/actor.

New files only under `apkscan/attribution/` + `tests/`, plus one additive export
line in `apkscan/attribution/__init__.py`.

## Value model (`apkscan/attribution/graph.py`)

Frozen, keyword-only dataclasses mirroring the `AttributionEvidence` /
`RoleScore` / `Observation` house style (`__post_init__` + `object.__setattr__`
normalization, tuple-only collections, deterministic `to_dict()`).

### `GraphNodeType` (str, Enum)

A **graph-local** node vocabulary — `APK`, `DOMAIN`, `IP`, `CERTIFICATE`, `ASN`.
`DOMAIN`/`IP`/`CERTIFICATE`/`ASN` mirror the corresponding `NetworkEntityType`
values 1:1; `APK` has no `NetworkEntityType` counterpart and represents the
analyzed sample (value = the builder's `artifact_id`). Introducing a graph-local
enum keeps the frozen `NetworkEntityType` (8 members) untouched — a test asserts
its membership is unchanged. `PROVIDER`, `NETWORK_CLUSTER`, `URL`, `HOST`, and a
`ROLE` node are **not** graph node kinds in v1 (see below).

### `GraphRelation` (str, Enum)

The closed v1 relation vocabulary (snake_case values, never `OBSERVED`). Edges
are derived from **`AttributionEvidence` only** (see the builder section) — the
converters emit a single-target evidence for every edge-worthy fact, so working
from evidence avoids the double-counting of also parsing the parallel
observation. `derived from` names the evidence `type` and its exact endpoint
mapping (all converter evidence is `confidence=1.0`):

| relation | endpoints | derived from (evidence type → endpoints) |
|---|---|---|
| `CONTACTED` | APK → DOMAIN\|IP | live-capture evidence whose target is a directly-contacted endpoint: `network_flow` (→IP target), `tls_sni` (→DOMAIN target), `http_request`/`http_response`/`http_redirect` (→host target) ⇒ APK CONTACTED target |
| `RESOLVES_TO` | DOMAIN → IP | `dns_resolution` (**inverted**: target=answer IP, value=qname) ⇒ DOMAIN(value) RESOLVES_TO IP(target); Shodan `resolved_ip` (target=DOMAIN, value=IP) ⇒ DOMAIN(target) RESOLVES_TO IP(value) |
| `ALIAS_OF` | DOMAIN → DOMAIN | `dns_alias` (target=qname, value=alias) ⇒ qname ALIAS_OF alias (CNAME direction) |
| `SERVED_AT` | DOMAIN → IP | `tls_sni` (target=DOMAIN, value=dst IP) ⇒ DOMAIN SERVED_AT IP — "the client addressed this name at this IP"; distinct from `RESOLVES_TO` (their divergence is the fronting/cloaking signal) |
| `REDIRECTS_TO` | DOMAIN\|IP → DOMAIN\|IP | `http_redirect` (target=host, value=sanitized location URL → extract host) ⇒ host REDIRECTS_TO location-host |
| `INTEL_RELATED` | DOMAIN\|IP → DOMAIN\|IP | FOFA/Hunter `related_ip` (target=DOMAIN, value=IP), `related_hostname` (target=IP\|DOMAIN, value=hostname) — **deliberately weaker** than resolution; an asset-row association, never a resolve/hosting claim |
| `IN_ASN` | IP → ASN | intel `asn` (target=IP, value=int → canonical `AS<int>` node) |
| `CERTIFIES` | CERTIFICATE → DOMAIN | `cert_san_dns` (target=CERTIFICATE, value=DNS name) |

**No host→certificate edge.** `cert_fingerprint_sha256` in `censys.py` targets the
CERTIFICATE with its own fingerprint as value (a self-verification attribute) — no
producer emits a host↔cert link, so "DOMAIN SHARE CERT" is realized only as
`CERTIFIES` to SAN domains (a 2-hop shared-cert relation, never a materialized
symmetric edge). Certificate components may be disconnected from captured-traffic
components in v1; a real ServerHello→cert observation (roadmap) will connect them
later without a model change.

### `GraphNode`

`node_type: GraphNodeType`, `value: str`, `sources: tuple[str, ...]`,
`roles: tuple[RoleScore, ...] = ()`, `provenance: tuple[str, ...]`.

- `value` is normalized per kind (IP → `normalize_ip`, DOMAIN → `normalize_domain`,
  CERTIFICATE → `validate_certificate_value`, ASN → `AS<int>`, APK → non-blank
  string); `sources` sorted+deduped (mirror `NetworkEntity._coerce_sources`).
- `roles`: each `RoleScore.target` must match the node's `(kind, value)`; sorted by
  `role.value` and deduped; a duplicate `(target, role)` with a differing
  `to_dict()` raises (conflicting-id iron law). **Roles are node annotations, not a
  separate ROLE node or `HAS_ROLE` edge** — a role is a per-target assessment, not a
  relation between entities.
- `provenance`: **non-empty**, sorted, deduped tuple of supporting observation/
  evidence ids — an unexplained node is not constructible.
- `to_dict()` → `{"type", "value", "sources", "roles": [r.to_dict()...],
  "provenance"}`.

### `GraphEdge`

`source_type`, `source_value`, `relation: GraphRelation`, `target_type`,
`target_value`, `provenance: tuple[str, ...]`, `confidence: float | None = None`.

- **Edge identity / id** = `stable_digest("apkscan.attribution/graph-edge",
  {relation, source_type, source_value, target_type, target_value})` — **fact-only**:
  provenance, confidence, and timestamps are **excluded** so the same edge keeps a
  stable id as corroborating facts accumulate (mirrors intel `_stable_evidence`).
- Endpoint kinds validated against the relation's allowed `(src_kind, dst_kind)`
  table; **no self-loops** (source key == target key raises).
- `provenance` non-empty/sorted/deduped; `confidence` `None` or a finite `[0,1]`
  float.
- `to_dict()` → `{"id", "relation", "source": {type,value}, "target": {type,value},
  "provenance", "confidence"}`.

### `GraphIssue`

`stage: str`, `reference: str`, `reason: str` — mirrors `ConversionIssue` but
references the **offending fact id** (evidence/observation id, or
`provider:capability` for intel), not a positional index. Quarantines a bad fact
(e.g. a `cert_san_dns` value that fails `normalize_domain`) without aborting the
build.

### `InfrastructureGraph`

`artifact_id: str`, `nodes: tuple[GraphNode, ...]`, `edges: tuple[GraphEdge, ...]`,
`issues: tuple[GraphIssue, ...] = ()`.

- `nodes` unique by `(node_type, value)`, sorted by `(node_type.value, value)`; a
  duplicate key raises (merging is the builder's job, the container is a dumb
  validator).
- `edges` unique by identity key, sorted by `(relation.value, src_type.value,
  src_value, dst_type.value, dst_value)`.
- **Referential integrity**: every edge endpoint `(type, value)` must exist in
  `nodes` (a dangling edge raises — a dangling edge is the shape of a speculative
  assertion).
- `issues` sorted by `(stage, reference, reason)`.
- Empty graph (valid `artifact_id`, no nodes/edges) is legal.
- `to_dict()` is deterministic and round-trips through `json.dumps`
  (`allow_nan=False`-safe).

## Builder (`build_infrastructure_graph`)

One module-level **pure, keyword-only** function:

```python
def build_infrastructure_graph(
    *, artifact_id: str,
    conversions: Iterable[ConversionResult] = (),
    role_scores: Iterable[RoleScore] = (),
    extra_evidence: Iterable[AttributionEvidence] = (),
) -> InfrastructureGraph: ...
```

- **No `intel_results` channel / no intel import.** `apkscan.attribution.graph`
  imports **no** `apkscan.intel` — importing even `apkscan.intel.models` would
  transitively load `apkscan.intel.__init__` → the four provider adapters →
  `requests`, coupling every `import apkscan.attribution` to the intel/HTTP stack
  and reversing the intel→attribution dependency direction. Intel evidence reaches
  the graph through `extra_evidence`: a caller (PR9) extracts the SUCCESS
  `IntelResult.evidence` and passes it in. This keeps the graph a pure consumer of
  `AttributionEvidence` with no knowledge of where it came from.
- **Interop:** normalize `conversions` via `merge_conversion_results(*conversions)`
  first (no new merge logic; guarantees
  `build([a,b]) == build([merge_conversion_results(a,b)])`).
- **Evidence pool:** a single global registry keyed by evidence/observation id,
  built before edge lifting, so a fact arriving via multiple channels
  (`ConversionResult.evidence`, `extra_evidence`) contributes one provenance entry.
- **Edge derivation = a single closed evidence registry** (the anti-speculation
  core). Edges come from `AttributionEvidence` only: the converters emit a
  single-target evidence for every edge-worthy fact (`network_flow`, `tls_sni`,
  `dns_resolution`, `dns_alias`, `http_request`/`response`/`redirect`), so deriving
  from evidence — rather than also parsing the parallel `Observation` — avoids
  double-counting and the fragile entity-tuple-position parsing.
  - A per-`evidence.type` `MappingProxyType` registry maps each edge-worthy type to
    an **explicit endpoint rule** (which of target/value is the edge source, and the
    far node's kind), covered by an exact-equality policy test (mirrors
    `_ROLE_POLICIES`). Critical: `dns_resolution` evidence is **inverted**
    (target = answer IP, value = qname) → `DOMAIN(value) RESOLVES_TO IP(target)`.
    Before minting a far-end node from `evidence.value`, the value must pass the far
    kind's normalizer (`normalize_ip`/`normalize_domain`/`AS<int>`, and for
    `http_redirect` the location URL's host via `normalize_authority`); failure →
    `GraphIssue`, no node, no edge.
  - An evidence type in **neither** the edge registry nor the (also-frozen)
    attribute allowlist (`as_org`, `geo_*`, `open_port`, `service_*`, `cert_subject_*`,
    `cert_fingerprint_sha256`, `network_flow`/`http_request`/`http_response`
    summaries, …) is **not** an issue — it contributes provenance to its target node
    only (future evidence types fail safe, never spray issues).
  - **Observations contribute provenance only.** For every already-admitted node,
    the ids of observations whose `entities` include it are folded into the node's
    provenance (full traceability), but an observation never *creates* a node —
    which is exactly what drops the analysis device's `network_flow` source IP (it is
    no evidence target and no edge endpoint). A domain that appears **only** in a
    `dns_query` observation with no answer (a blocked/NXDOMAIN lookup) therefore does
    not enter the v1 graph; capturing those is a documented v1 gap for a later pass.
- **Roles consumed verbatim:** each `RoleScore` attaches to its target node as a
  role annotation, serialized exactly as `RoleScore.to_dict()`. The builder must not
  import `RoleClassifier`/`EvidenceScorer` or recompute eligibility/points; ineligible
  assessments are kept (negatives are explainability). A `RoleScore` whose target has
  no other fact still admits the node (its provenance is the contribution evidence
  ids).
- **HOST/URL folding:** HOST entities (`example.com:8443`) fold onto the underlying
  DOMAIN/IP (deterministic `normalize_authority`, not speculative merging). URLs never
  become nodes (the URL string stays in the `http_redirect` provenance).
- **Node admission:** a node enters iff it is (a) an endpoint of a derived edge,
  (b) the target of an attribute-registry evidence, or (c) the target of a
  `RoleScore`. The analysis device's `network_flow` source IP participates in no
  registered edge and carries no evidence, so it drops out with no RFC1918 heuristic.
- **APK linkage:** `CONTACTED` edges anchor on the explicit `artifact_id`
  (single-artifact scope; `Observation` carries no `artifact_id` field, so it is never
  inferred from ids). The APK node's `value` is `artifact_id`.
- **Conflict handling:**
  - *Structural* (same id, differing `to_dict()`) → raise `ValueError` (conflicting
    evidence for id), byte-for-byte the PR3/PR4/PR5 iron law. Raising is
    permutation-invariant (a conflict raises in any order).
  - *Semantic* (same IP asserted in two different ASNs; a domain resolving to two IPs)
    → **parallel edges**, each with its own provenance — never a confidence/recency/
    source-priority merge (that would be a nondeterministic merge and would decide for
    the analyst).
  - Same-key edge from multiple supporting facts → one edge, provenance = union
    (sorted, deduped by fact id), confidence = **max** of the supporting evidence
    confidences (the only order-free monotone choice).
- **Referential integrity / dangling provenance:** every provenance id must exist in
  the input pool; a dangling reference quarantines that edge as a `GraphIssue` and the
  rest of the build proceeds.
- **Failure posture:** container-level programmer errors raise `TypeError`/`ValueError`
  (blank `artifact_id`, a non-`ConversionResult`/`RoleScore`/`AttributionEvidence` in the
  channels); per-fact data problems skip-and-record via `GraphIssue`. One dirty fact
  never aborts a build.
- **No network, no I/O, no role re-derivation.**

## Determinism, provenance, anti-over-inference

- **Determinism:** fact-only node/edge ids via `stable_digest`; every collection
  `set → tuple(sorted(...))`; enums sorted by `.value`; nested JSON via the
  `_sorted_json` recipe; `to_dict()` returns a fresh container each call.
  Permutation-invariance is a first-class law: shuffling any input iterable yields a
  byte-identical `json.dumps(to_dict(), sort_keys=True)`.
- **Provenance:** every node and edge is traceable to input observation/evidence ids
  (non-empty by construction); the builder verifies referential closure.
- **No operator/actor, ever:** enforced three ways — (1) a closed `GraphNodeType` with
  no OPERATOR/ACTOR/PERSON/COMPANY member (asserted by exact membership test); (2) the
  frozen derivation tables (unmapped ⇒ no edge); (3) topology-only relation names
  (`IN_ASN`, never `OPERATED_BY`/`OWNED_BY`). ASN/org data stays a resource fact.
- **No speculative clustering:** `NETWORK_CLUSTER`/`MEMBER_OF` and `PROVIDER` are
  **deferred** — the legacy graph's core is Apk-Entity-Apk connected-component
  clustering, so any component-walk cluster inference would both revive it and violate
  the scope. The only defensible v1 shared-infrastructure fact (a shared leaf
  certificate) is already expressed losslessly by a `CERTIFICATE` node with multiple
  `CERTIFIES` edges. "Same ASN alone ≠ same origin" is a mandatory negative test.

## Tests (frozen-dataclass style, no network, no files)

- `tests/test_attribution_graph_models.py` — value objects: frozen/kw-only, per-kind
  value normalization, per-relation endpoint typing, non-empty sorted provenance as a
  **constructor** invariant, no self-loops, conflicting-role rejection, container
  uniqueness + referential integrity + sort, JSON round-trip; `NetworkEntityType`
  still has exactly its 8 members.
- `tests/test_attribution_graph_builder.py` — per-source derivation from real PR2/PR5
  fact shapes: `dns_resolution` observation **and** inverted `dns_resolution` evidence
  both → `DOMAIN → IP`; `resolved_ip` → `RESOLVES_TO`; `related_ip` → `INTEL_RELATED`
  only (no resolve/served edge); `asn` → `IN_ASN` with `AS<int>` node (bool/oob value →
  issue); `cert_san_dns` → `CERTIFIES` (wildcard/garbage SAN → issue); `cert_fingerprint`
  → no edge; unknown type → provenance-only, no edge, no issue; `RoleScore` verbatim
  (monkeypatched classifier/scorer that raise prove no re-derivation); merge-equivalence;
  container-level raise vs per-fact issue.
- `tests/test_attribution_graph_determinism.py` — dedup/idempotency, fact-only edge id
  stability when unrelated facts are added, byte-identical `to_dict()` across runs and
  under seeded shuffle, conflicting-id → raise, semantic conflict → parallel edges,
  provenance dedup, to_dict non-aliasing.
- `tests/test_attribution_graph_acceptance.py` — the original acceptance scenarios as
  graph assertions, built through real `convert_*` + `merge_conversion_results`:
  APK → domestic IP → overseas IP chain; shared-cert star (N SANs → N `CERTIFIES`
  edges to one cert node, linear not O(N²)); and the **negatives** — a Cloudflare
  ordinary site keeps its resolve edges but gets **no** origin role annotation (roles
  consumed, not re-derived); two IPs sharing only an ASN get `IN_ASN` edges to one ASN
  node but **no** cross edge / cluster / `MEMBER_OF`; the serialized graph contains no
  operator/actor field; every provenance id resolves to an input id.
- `tests/test_attribution_graph_scope.py` — legacy isolation: `apkscan.attribution.graph`
  imports no `apkscan.graph`/`kuzu`/`sqlite3` and its source has no `OBSERVED`; the
  module is unwired (no `apkscan/**` outside `apkscan/attribution/` references
  `attribution.graph`); exports are sorted and additive; import is side-effect-free.
