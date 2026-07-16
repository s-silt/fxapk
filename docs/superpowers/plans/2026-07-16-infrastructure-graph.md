# Infrastructure Attribution Graph Implementation Plan (PR7)

> Use test-driven development (red → green → refactor) for every change.

**Goal:** an in-memory, deterministic, explainable infrastructure attribution
graph value model + a pure builder that assembles it from PR1–PR6 facts
(`Observation`/`AttributionEvidence` in a `ConversionResult`, `RoleScore`,
`IntelResult`). Unwired; no `report.json`/CLI change; no legacy `apkscan/graph`
revival; no DB. See `docs/superpowers/specs/2026-07-16-infrastructure-graph-design.md`.

**Architecture:** `apkscan/attribution/graph.py` holds frozen kw-only
`GraphNodeType`/`GraphRelation` enums, `GraphNode`/`GraphEdge`/`GraphIssue`/
`InfrastructureGraph` value objects (house style of `models.py`/`scorer.py`), and
the pure `build_infrastructure_graph(*, artifact_id, conversions, role_scores,
intel_results, extra_evidence)`. Reuse `stable_digest`, `normalize_ip`/
`normalize_domain`/`normalize_authority`, `validate_certificate_value`,
`merge_conversion_results`. Edge derivation is a closed two-channel
`MappingProxyType` registry.

## Global constraints

- Fact-only node/edge ids (`stable_digest`, identity excludes provenance/
  confidence/timestamp); every node/edge provenance non-empty; deterministic
  sort + dedup; byte-identical `to_dict()` under input shuffle.
- Closed derivation registries; unmapped types = provenance-only (not issues);
  malformed values = `GraphIssue`; conflicting-id = raise; semantic conflict =
  parallel edges; same-key merge = provenance union + confidence max.
- Roles consumed verbatim (no `RoleClassifier`/`EvidenceScorer` import, no
  re-derivation); role = node annotation, no ROLE node/edge.
- No APK/ROLE mutation of `NetworkEntityType` (graph-local `GraphNodeType`); no
  CLUSTER/PROVIDER/URL node; HOST folded to DOMAIN/IP.
- No `import apkscan.graph`, no `kuzu`/`sqlite3`, no I/O/network, no persistence;
  no `Entity` class / `OBSERVED` edge name; new files only under
  `apkscan/attribution/` + `tests/` (+ one additive export line).

## File structure

- Create `apkscan/attribution/graph.py`.
- Modify `apkscan/attribution/__init__.py`: additive re-export of the new public
  names (sorted `__all__`).
- Create `tests/test_attribution_graph_models.py`,
  `tests/test_attribution_graph_builder.py`,
  `tests/test_attribution_graph_determinism.py`,
  `tests/test_attribution_graph_acceptance.py`,
  `tests/test_attribution_graph_scope.py`.

---

### Task 1: enums + `GraphNode`/`GraphEdge`/`GraphIssue` value objects

- [ ] Failing tests (`test_attribution_graph_models.py`): `GraphNodeType`
  members == {APK, DOMAIN, IP, CERTIFICATE, ASN}; `GraphRelation` members ==
  the closed v1 set; both `str, Enum`. `GraphNode` frozen/kw-only, per-kind value
  normalization, sorted/deduped `sources`, `roles` sorted/deduped with
  target-match and conflicting-`(target,role)` rejection, **non-empty**
  provenance. `GraphEdge` fact-only id == recomputed `stable_digest`, per-relation
  endpoint typing (reject wrong kinds), no self-loop, non-empty provenance,
  confidence `None`/`[0,1]`. `GraphIssue` shape. JSON round-trip. Assert
  `NetworkEntityType` still has its 8 members.
- [ ] Implement the enums + three value objects.
- [ ] Run the models test.

### Task 2: `InfrastructureGraph` container

- [ ] Failing tests: node key uniqueness + sort, edge identity uniqueness + sort,
  **referential integrity** (dangling edge endpoint raises), issue sort, empty
  graph legal, deterministic JSON-safe `to_dict()` (round-trip, `to_dict()`
  non-aliasing).
- [ ] Implement `InfrastructureGraph`.
- [ ] Run the models test.

### Task 3: closed evidence derivation registry + edge/attribute lifting helpers

- [ ] Failing tests (`test_attribution_graph_builder.py`, using hand-built
  `AttributionEvidence`): per-evidence-type edges with explicit endpoints
  (**inverted** `dns_resolution` evidence target=IP/value=qname → DOMAIN
  RESOLVES_TO IP; `resolved_ip` → RESOLVES_TO; `tls_sni` → SERVED_AT + APK
  CONTACTED DOMAIN; `network_flow` → APK CONTACTED IP; `dns_alias` → ALIAS_OF;
  `http_redirect` → REDIRECTS_TO host-of-location; `related_ip`/`related_hostname`
  → INTEL_RELATED only; `asn` int → IN_ASN `AS<int>` node, bool/oob → issue;
  `cert_san_dns` → CERTIFIES, wildcard/garbage → issue; `cert_fingerprint_sha256`
  → no edge); unmapped type → provenance-only, no edge, no issue; attribute-only
  evidence stays a node attribute; observation ids fold into an admitted node's
  provenance while the device src IP is never admitted. Registry exact-equality
  policy test.
- [ ] Implement the `MappingProxyType` edge registry + attribute allowlist + the
  pure lifting helpers (endpoint resolution, value normalization → issue on
  failure, node admission, HOST folding).
- [ ] Run the builder test.

### Task 4: `build_infrastructure_graph` orchestration

- [ ] Failing tests: `merge_conversion_results` delegation + merge-equivalence;
  global evidence pool (`ConversionResult.evidence` + `extra_evidence`) + duplicate
  absorption; roles consumed verbatim (monkeypatched `RoleClassifier.assess`/
  `EvidenceScorer.score` that raise prove no re-derivation; ineligible role kept;
  role-only target admits node); container-level raise (`artifact_id=''`, wrong
  channel type) vs per-fact issue; APK anchored on `artifact_id`. The builder
  imports no `apkscan.intel` (intel SUCCESS evidence arrives via `extra_evidence`).
- [ ] Implement the builder.
- [ ] Run the builder test.

### Task 5: determinism + conflict + provenance

- [ ] Failing tests (`test_attribution_graph_determinism.py`): permutation-
  invariance (seeded shuffle → byte-identical `to_dict()`); fact-only edge id
  stable when unrelated facts added; two-timestamp same-resolution → one edge, two
  provenance ids; conflicting-id → `ValueError`; semantic conflict (two ASN) →
  parallel edges; provenance dedup; referential-integrity quarantine of a dangling
  provenance id.
- [ ] Fix any nondeterminism uncovered.
- [ ] Run the determinism test.

### Task 6: acceptance scenarios + anti-over-inference negatives

- [ ] Failing tests (`test_attribution_graph_acceptance.py`, built via real
  `convert_*` + `merge_conversion_results`): APK → domestic IP → overseas IP
  chain; shared-cert star (N SANs → N `CERTIFIES` to one cert node, linear);
  **negatives** — Cloudflare ordinary site keeps resolve edges but no origin role
  annotation (roles consumed not re-derived); two IPs sharing only an ASN → one
  ASN node, `IN_ASN` edges, **no** cross edge/cluster/`MEMBER_OF`; no operator/
  actor field anywhere in `to_dict()`; every provenance id resolves to an input id.
- [ ] Run the acceptance test.

### Task 7: exports + scope conformance

- [ ] Failing tests (`test_attribution_graph_scope.py`): additive sorted
  `apkscan.attribution.__all__` including the new names; import of
  `apkscan.attribution.graph` pulls in no `apkscan.graph`/`kuzu`/`sqlite3` and its
  source has no `OBSERVED`; no `apkscan/**` module outside `apkscan/attribution/`
  references `attribution.graph`; import side-effect-free.
- [ ] Update `apkscan/attribution/__init__.py`.
- [ ] Run the scope test.

### Task 8: final gates

- [ ] `python -m ruff check apkscan tests`
- [ ] `python -m pyright apkscan`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`

## Final-review hardening checklist

- Every node/edge has non-empty provenance resolving to an input id; edge ids are
  fact-only and stable under added corroboration; `to_dict()` is byte-identical
  under input shuffle.
- `dns_resolution` evidence direction is correct (DOMAIN → IP despite target=IP);
  `related_ip`/`related_hostname` are `INTEL_RELATED` only; `cert_fingerprint_sha256`
  makes no edge; unmapped types make no edge and no issue; malformed values become
  issues without aborting the build.
- Roles are verbatim (no re-derivation); no ROLE/CLUSTER/PROVIDER node; same-ASN
  alone makes no cross edge/cluster; no operator/actor field exists.
- No `apkscan.graph`/`kuzu`/`sqlite3` import; `NetworkEntityType` unchanged; only
  `apkscan/attribution/graph.py` + tests + one export line changed; unwired.
