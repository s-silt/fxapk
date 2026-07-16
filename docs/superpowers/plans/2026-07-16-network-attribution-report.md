# network_attribution Report Output Implementation Plan (PR9)

> Use test-driven development (red → green → refactor) for every change.

**Goal:** an additive, schema-compatible `report.meta["network_attribution"]`
assembled deterministically from facts already on the report (PR7 graph + PR3/4/8
role candidates), passive (no new network), no over-inference. See
`docs/superpowers/specs/2026-07-16-network-attribution-report-design.md`.

**Architecture:** one pure function `build_network_attribution(endpoints, *,
artifact_id, phase) -> dict | None` in `apkscan/attribution/assemble.py` (bridge
facts → `AttributionEvidence` + `RoleFeature` → `RoleClassifier`/`EvidenceScorer`
+ `build_infrastructure_graph`), called from a new pipeline stage, from
`close_report`, and surfaced by `build_digest`. Reuse `stable_digest`,
`normalize_ip`/`normalize_domain`, the frozen PR7 graph and PR3/4/8 roles/scorer.

## Global constraints

- Passive: reads only `endpoint.enrichment/evidences/value/kind` + `meta`; no
  network, no enricher/`build_endpoint_attribution` re-run, no file I/O, no import
  of `apkscan.core.enrichment`/intel/`requests`/`socket`.
- Determinism: fact-only `stable_digest` ids; **constant confidence per
  (source,type), timestamp None**; sorted collections; canonical endpoint order.
- No over-inference: one fact → at most one signal; the four static signals only
  (`direct_connection`, `domestic_network`, `public_cdn`, `non_public_cdn`);
  behavioral signals stay absent; no static-only eligible cloaking/edge/relay/origin.
- Additive: `meta` key only; no `REPORT_SCHEMA_VERSION` bump; no top-level/report
  field; no operator/actor/owner field; no feedback into closure gaps/leads/exit.
- Frozen: zero diff in `attribution/{graph,models,roles,scorer}.py`,
  `network/converters.py`, `core/attribution.py`.

## File structure

- Create `apkscan/attribution/assemble.py`.
- Modify `apkscan/core/pipeline.py`: `_stage_network_attribution` + `_run_stage`
  registration after `credibility`.
- Modify `apkscan/core/closure.py`: populate `meta["network_attribution"]` after
  `meta["closure"]`, guarded.
- Modify `apkscan/report/digest.py`: compact block + summary counter.
- Create `tests/test_network_attribution.py`; modify
  `tests/test_pipeline_stages.py` (`_EXPECTED_STAGES`) and add a
  `tests/test_digest.py` case.

---

### Task 1: the fact → evidence bridge

- [ ] Failing tests (`test_network_attribution.py`): each enrichment field → its
  expected `AttributionEvidence` (type, target, normalized value, source,
  constant confidence, timestamp None, recomputed stable id); dns.ips∪hosting
  union; cname → dns_alias per hop; strict ASN parse (int / `AS<int>` / garbage →
  skip+issue); certs/shodan hostnames → related_hostname; runtime → tls_sni /
  network_flow; a malformed subtree skips that endpoint and records an issue,
  never raises; NO cert_san_dns/CERTIFICATE synthesized.
- [ ] Implement the bridge (evidence minting, dedup by id, the confidence table).
- [ ] Run the bridge tests.

### Task 2: the fact → RoleSignal compiler + scoring

- [ ] Failing tests: `direct_connection` only from kind==ip + runtime; each
  `domestic_network` licensing fact (asn CN / icp / telecom+CN) and the refused
  org-name case; `public_cdn` from edge tier confirmed/probable (reused, not
  re-derived) or cdn category; `non_public_cdn` triple-gate; every behavioral
  signal **absent**; one-fact-one-signal (a CDN identity licenses public_cdn
  only). Scoring: assessments emitted per role with ≥1 present signal (ineligible
  included, full trace); only eligible RoleScores annotate graph nodes; the
  **cloaking-never-static** invariant.
- [ ] Implement the signal compiler + `RoleClassifier`/`EvidenceScorer` scoring +
  the eligible-only graph feed.
- [ ] Run the signal tests.

### Task 3: assembly + output shape

- [ ] Failing tests: `build_network_attribution` returns the fixed-key dict
  (version/phase/artifact_id/disclaimer/graph/evidence/endpoints/skipped); graph
  embedded verbatim; `resource_context` scalar snapshot (no five-layer dup, no
  `service_operator`); no operator/actor/owner key anywhere; `None` when no
  bridgeable endpoint; per-endpoint skip on failure; `json.dumps` round-trips;
  permuted endpoint order → byte-identical output.
- [ ] Implement the assembler.
- [ ] Run the assembly tests.

### Task 4: pipeline + closure + digest wiring

- [ ] Failing tests: `_EXPECTED_STAGES` includes `"network_attribution"` after
  `credibility`; the stage writes `meta["network_attribution"]` (via a FakeContext
  pipeline run or a direct stage call) and is `_run_stage`-guarded; `close_report`
  populates `phase="close"` after `closure`, guarded (a failing assembler leaves a
  minimal error marker, never raises, never mutates `closure`); `build_digest`
  emits the compact block + `summary.attributed_role_candidates`, degrading to an
  empty block on malformed input; a report round-trip preserves the `meta` key.
- [ ] Implement the pipeline stage, the closure hook, and the digest block.
- [ ] Run the wiring tests.

### Task 5: passive + compat + acceptance

- [ ] Failing tests: a `socket`-blocking guard proves assembly touches no network;
  an import assertion (subprocess) that `apkscan.attribution.assemble` imports no
  `apkscan.core.enrichment`/intel/`requests`/`socket`; the acceptance negatives
  (Cloudflare endpoint → no eligible origin/relay + no operator field; two
  same-ASN IPs → one ASN node, `IN_ASN` edges, no cross edge/cluster; bare cloud
  IP → no operator claim); a no-frozen-diff assertion.
- [ ] Fix anything the acceptance/passive tests surface.
- [ ] Run the full attribution + pipeline + digest tests.

### Task 6: final gates

- [ ] `python -m ruff check apkscan tests`
- [ ] `python -m pyright apkscan`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`

## Final-review hardening checklist

- Every bridged evidence has a fact-only stable id, constant confidence, None
  timestamp; re-runs are byte-identical; no same-id/different-payload crash.
- Only the four static signals are derived; no behavioral signal is synthesized;
  no static-only report yields an eligible cloaking/edge/relay/origin; one fact
  licenses at most one signal.
- No operator/actor/owner field; the five-layer is referenced not duplicated;
  `service_operator` never copied; the disclaimer constant is present.
- Additive `meta` key only; no schema bump; no top-level/frozen-module change; no
  closure/lead/exit feedback; passive (no network/enricher/file I/O); the digest
  block and closure hook never raise.
