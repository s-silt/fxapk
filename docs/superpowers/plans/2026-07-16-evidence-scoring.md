# Explainable Evidence Scoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or
> `superpowers:executing-plans` task-by-task, and use
> `superpowers:test-driven-development` for every implementation change.

**Goal:** Add PR4 deterministic evidence scoring for PR3 role assessments with
fully traceable positive, negative, missing, and zero-weight evidence.

**Architecture:** A private immutable role-policy table maps `RoleSignal` values
to signed integer weights. `EvidenceScorer` consumes a structured
`RoleAssessment`, groups its exact `RoleFeature` objects by signal, and returns
an immutable `RoleScore`. PR3 eligibility remains the safety gate; PR4 score
never changes it.

**Tech Stack:** Python 3.11+, frozen dataclasses, mappings made immutable with
`MappingProxyType`, pytest, Ruff, Pyright.

## Global Constraints

- No external/network API integration, active scanning, analyzer, CLI, graph,
  report, or corpus changes. Public Python exports for the PR4 value objects and
  scorer are in scope.
- No machine learning or probabilistic claims.
- Do not classify or score `cloaking_edge_node` in PR4.
- Do not infer operators or criminal subjects.
- Award a signal's weight once while retaining all supporting evidence.
- Preserve deterministic ordering and JSON-safe serialization.
- Complete Ruff, Pyright, pytest, and `git diff --check` before PR submission.

## Final-review hardening amendment

Before PR submission, the public `RoleScore` constructor must validate exact
policy weights, complete positive missing evidence, PR3-derived eligibility,
and canonical feature relevance. Evidence IDs must be globally consistent
across contributions. `EvidenceScorer` must serialize canonical signals omitted
from a policy as zero-point context instead of dropping them. These requirements
supersede any earlier task snippet that treated `RoleScore` as arithmetic-only.

## File Structure

- Create `apkscan/attribution/scorer.py`.
- Modify `apkscan/attribution/roles.py` only to retain domestic historical-DNS
  evidence as optional support.
- Modify `apkscan/attribution/__init__.py` to export the public PR4 API.
- Create `tests/test_attribution_scorer.py`.
- Extend `tests/test_attribution_roles.py` with the historical-DNS retention
  regression only if needed.

### Task 1: Score value objects and validation

**Files:**
- Create: `apkscan/attribution/scorer.py`
- Test: `tests/test_attribution_scorer.py`

- [ ] Write failing tests for frozen keyword-only `ScoreContribution`,
  `MissingScoreEvidence`, and `RoleScore` models.
- [ ] Cover invalid points, score/confidence ranges, cross-target features,
  signal mismatches, deterministic ordering, and JSON-safe output.
- [ ] Add contradiction tests requiring `raw_score` to equal contribution sum,
  `score` to equal the clamped raw score, and `confidence` to follow eligibility
  and score exactly.
- [ ] Add direct-construction adversarial tests for off-policy weights,
  incomplete or wrong missing evidence, irrelevant role features, and fabricated
  eligibility.
- [ ] Reject conflicting reuse of one evidence ID across contributions in both
  input orders while allowing identical payload reuse across signals.
- [ ] Run `python -m pytest tests/test_attribution_scorer.py -q` and confirm the
  expected import/behavior failures.
- [ ] Implement the smallest validated immutable models and rerun the tests.
- [ ] Run Ruff and Pyright on the touched module and tests.

### Task 2: Declarative policy and scoring engine

**Files:**
- Modify: `apkscan/attribution/scorer.py`
- Test: `tests/test_attribution_scorer.py`

- [ ] Add failing exact-map tests for every role policy so extra, omitted, or
  changed weights fail. Include edge `public_cdn` explicitly as zero-weight
  context policy.
- [ ] Add tests proving multiple evidence items retain provenance but award one
  signal weight.
- [ ] Add raw-score, lower/upper clamp, eligible confidence, and ineligible
  confidence tests.
- [ ] Add public-CDN blocker/negative contribution and zero-weight edge context
  tests.
- [ ] Add adversarial tests for an eligible origin with `public_cdn` misplaced
  as context and for manually asserted eligibility without PR3 requirements.
- [ ] Implement private immutable policies and `EvidenceScorer.score()`.
- [ ] Reconstruct the canonical assessment with `RoleClassifier` and reject
  manually fabricated eligibility, misplaced blockers/context, or inconsistent
  missing evidence before awarding points.
- [ ] Derive missing weighted evidence from policy and preserve unweighted
  matched/context features.
- [ ] Preserve a canonical signal omitted from the active policy as a
  deterministic zero-point context contribution.
- [ ] Reject unsupported cloaking assessments explicitly.
- [ ] Rerun focused tests, Ruff, and Pyright.

### Task 3: Domestic historical DNS retention and exports

**Files:**
- Modify: `apkscan/attribution/roles.py`
- Modify: `apkscan/attribution/__init__.py`
- Test: `tests/test_attribution_roles.py`
- Test: `tests/test_attribution_scorer.py`

- [ ] Add a failing regression proving domestic-relay assessment retains
  `historical_dns` as matched optional evidence without changing eligibility.
- [ ] Add `historical_dns` to the domestic supporting set only.
- [ ] Add public exports for `EvidenceScorer`, `RoleScore`,
  `ScoreContribution`, and `MissingScoreEvidence`.
- [ ] Test package-root imports and deterministic `__all__` coverage.
- [ ] Run both attribution test modules, Ruff, and Pyright.

### Task 4: Adversarial review and repository verification

- [ ] Review against the PR4 design and original false-positive requirements.
- [ ] Verify ordinary Cloudflare/public-CDN infrastructure cannot receive
  origin confidence and generic OpenResty evidence has no scoring signal.
- [ ] Verify source evidence confidence remains unchanged and does not scale
  integer signal weights.
- [ ] Run `python -m ruff check apkscan tests`.
- [ ] Run `python -m pyright apkscan`.
- [ ] Run `python -m pytest -q`.
- [ ] Run `git diff --check` and inspect the complete branch diff.
- [ ] Commit, push, open the PR, wait for every CI job, and merge only when CI
  is green.
