# Cloaking Edge Node Subtype Implementation Plan (PR8)

> Use test-driven development (red → green → refactor) for every change.

**Goal:** implement `cloaking_edge_node` (a subtype of `edge_candidate`) in the
classifier + scorer under strong multi-signal rules; ordinary OpenResty / plain
edge stays a negative. See
`docs/superpowers/specs/2026-07-16-cloaking-edge-node-design.md`.

**Architecture:** add one `_RoleDefinition` (roles.py) and one `_RolePolicy`
(scorer.py) for cloaking and remove the three PR4 "reserved" rejections —
atomically. Reuse the existing `_Requirement`/`_RoleDefinition`/`_RolePolicy`/
`EvidenceScorer` machinery; add no new `RoleSignal`. Only
`apkscan/attribution/{roles,scorer}.py` + tests change; `__all__` and every other
module are untouched.

## Global constraints

- `_CLOAKING_STRONG = {CONTENT_DIFFERENCE, COOKIE_CHALLENGE, REDIRECT}` ⊂
  `_EDGE_SIGNALS`; cloaking eligible ⇔ ≥2 strong (no blocker). `blockers=∅`;
  `context={MANY_SHARED_DOMAINS, SHARED_TLS, PUBLIC_CDN}`; `supporting=_CLOAKING_STRONG`.
- Policy `{content_difference:40, cookie_challenge:30, redirect:20,
  many_shared_domains:0, shared_tls:0, public_cdn:0}`. Positive-weight==supporting,
  zero-weight==context, negative-weight==blockers (the convention all four roles obey).
- The three existing roles' behavior is byte-identical; `assess()` returns a 4-tuple
  (cloaking last); `_ROLE_POLICIES` has 4 entries; subtype implication
  (cloaking-eligible ⇒ edge-eligible) holds.
- No `RoleSignal`, model, graph, intel, core, CLI, `report.json`, or `__all__` change.

## File structure

- Modify `apkscan/attribution/roles.py`: `_CLOAKING_STRONG` constant + the 4th
  `_RoleDefinition`.
- Modify `apkscan/attribution/scorer.py`: `_CLOAKING_WEIGHTS` + the `_ROLE_POLICIES`
  entry; delete the three cloaking `raise` guards.
- Modify `tests/test_attribution_roles.py` + `tests/test_attribution_scorer.py`: flip
  the ~5 "reserved" assertions and the redirect+cookie `classify()` ripple tests.
- Create `tests/test_attribution_cloaking.py`: the new positive/negative/invariant/
  scorer/graph-annotation cases (keeps the new coverage in one auditable file).

---

### Task 1: classifier definition

- [ ] Failing tests (in `tests/test_attribution_cloaking.py`): content_difference +
  cookie_challenge ⇒ cloaking **and** edge eligible; cookie_challenge + redirect ⇒
  eligible; many_shared_domains + shared_tls ⇒ edge eligible, cloaking ineligible with
  `missing_evidence == _CLOAKING_STRONG`; each single strong signal ⇒ ineligible;
  content_difference + shared_tls ⇒ cloaking ineligible; public_cdn + 2 strong ⇒
  eligible with `public_cdn` in `context_features`; the exhaustive 64-subset
  `cloaking ⇒ edge` implication; the structural parent-subtype invariant; the
  first-three assessments unchanged vs a pre-PR8 fixture; `assess()` is a 4-tuple.
- [ ] Implement `_CLOAKING_STRONG` + the 4th `_RoleDefinition` in `roles.py`.
- [ ] Update `tests/test_attribution_roles.py`: `…never_cloaking` → `…including_cloaking`
  (append cloaking, `not in`→`in`, keep all-ineligible); update the redirect+cookie
  `classify()` exact lists to `[EDGE_CANDIDATE, CLOAKING_EDGE_NODE]`.
- [ ] Run: `python -m pytest tests/test_attribution_roles.py tests/test_attribution_cloaking.py -q`

### Task 2: scorer policy + remove rejections

- [ ] Failing tests: a canonical cloaking `RoleScore` (via `assess` + `score`) scores
  with `raw_score == sum` and `confidence == score/100`; policy conformance holds; a
  tampered cloaking `RoleScore` (off-policy points) raises; a non-canonical cloaking
  assessment raises on the reconstruction mismatch; the policy⇄definition
  self-consistency invariant holds for all four roles.
- [ ] Implement `_CLOAKING_WEIGHTS` + the `_ROLE_POLICIES` entry; delete the three
  cloaking `raise` guards (scorer.py `RoleScore.__post_init__`, `_RolePolicy.__post_init__`,
  `EvidenceScorer.score`).
- [ ] Update `tests/test_attribution_scorer.py`: flip the policy-set test to four roles
  + add the cloaking weight row; flip `test_role_policy_rejects_cloaking_edge_node` to a
  construct-success; convert `test_role_score_rejects_cloaking_role` to a positive build
  (+ tampered-raises companion); split `test_scorer_rejects_non_assessment_and_cloaking_role`.
- [ ] Run: `python -m pytest tests/test_attribution_scorer.py tests/test_attribution_cloaking.py -q`

### Task 3: forward-compat graph annotation

- [ ] Failing test (`tests/test_attribution_cloaking.py`): a cloaking `RoleScore`
  attaches to its target `GraphNode` as a role annotation via the PR7 builder (proves
  zero graph change needed).
- [ ] No implementation (already works) — the test documents the contract.
- [ ] Run: `python -m pytest tests/test_attribution_cloaking.py -q`

### Task 4: final gates

- [ ] `python -m ruff check apkscan tests`
- [ ] `python -m pyright apkscan`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`

## Final-review hardening checklist

- Cloaking eligible ⇔ ≥2 of `{content_difference, cookie_challenge, redirect}`; a
  single strong signal, or weak-only (OpenResty), is never eligible; `missing_evidence`
  lists the absent strong signals.
- `PUBLIC_CDN` is context, not a blocker; a public-CDN cloaking case stays eligible with
  the CDN visible in `context_features`.
- cloaking-eligible ⇒ edge-eligible (64-subset); the three existing roles are unchanged;
  policy⇄definition self-consistency holds for all four; scorer conformance passes for
  cloaking.
- Only `apkscan/attribution/{roles,scorer}.py` + tests changed; `__all__`, models,
  graph, intel, core, CLI, and `report.json` untouched.
