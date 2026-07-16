# Explainable Evidence Scoring Design

**Date:** 2026-07-16
**Scope:** PR4 only

## Objective

Add deterministic, explainable scoring for PR3 `RoleAssessment` objects. A
score must expose which normalized evidence added or removed points, which
weighted evidence is still missing, and why the result is or is not a role
candidate.

PR4 quantifies an assessment; it does not replace PR3 eligibility gates.

## Boundaries

PR4 does not:

- call external/network intelligence APIs or perform active scanning;
- modify analyzers, CLI output, or the existing report JSON schema;
- add machine learning, learned weights, or opaque probability calibration;
- classify `cloaking_edge_node`; that subtype remains reserved for PR8;
- infer an operator, resource owner, or criminal subject from infrastructure
  evidence;
- rank entities globally or mutate the infrastructure graph.

## Considered Approaches

### 1. Imperative role-specific conditionals

Implement one scoring function per role with nested `if` statements. This is
short initially, but makes weights, omissions, and negative evidence difficult
to audit consistently.

### 2. Declarative weight tables plus typed contributions

Define immutable per-role positive and negative weight tables. Apply those
tables to the structured `RoleFeature` buckets from PR3 and return typed,
JSON-safe contribution objects. **This is the selected approach.** It keeps
policy visible and preserves exact signal-to-evidence provenance.

### 3. External YAML or a rule DSL

Load scoring rules from configuration. This adds parsing, validation, versioning,
and deployment surface before any operational need exists. A later PR may add
versioned policy loading without changing the public score result model.

## Public API

`apkscan/attribution/scorer.py` defines:

- `ScoreContribution`: one weighted signal, its signed point value, and every
  exact `RoleFeature` supporting that signal;
- `MissingScoreEvidence`: one absent positive signal and the points it could
  contribute;
- `RoleScore`: immutable result containing the original role identity and
  eligibility, `raw_score`, bounded `score`, `confidence`, positive evidence,
  negative evidence, missing weighted evidence, and zero-weight contextual or
  matched features;
- `EvidenceScorer`: stateless deterministic scorer accepting one
  `RoleAssessment`.

The scorer rejects assessments for roles without a PR4 scoring policy. In
particular, a manually constructed `cloaking_edge_node` assessment is not
silently scored as an edge.

The scorer also does not trust a caller-supplied `eligible` flag or arbitrary
bucket placement. It reconstructs the canonical assessment for the same target
and supplied features through `RoleClassifier`, selects the requested role,
and requires the complete assessment to match. Misplaced blockers, fabricated
eligibility, incomplete missing-evidence lists, and unsupported signals are
rejected before scoring. This reuses PR3 as the single eligibility authority
instead of duplicating its safety gates in PR4.

## Weight Policy

Weights are integer points and intentionally explicit.

### Domestic relay candidate

| Signal | Points |
|---|---:|
| direct APK connection | +40 |
| domestic network | +15 |
| subsequent overseas connection | +20 |
| redirect | +15 |
| historical DNS | +15 |
| non-public CDN | +10 |
| public CDN | -60 |

PR4 adds `historical_dns` to the PR3 domestic-relay supporting set so the
classifier retains its evidence for scoring. It remains optional and does not
alter eligibility.

### Origin candidate

| Signal | Points |
|---|---:|
| business API | +30 |
| login endpoint | +15 |
| stable IP | +15 |
| business certificate | +15 |
| non-public CDN | +20 |
| historical DNS | +15 |
| public CDN | -60 |

The login signal receives an explicit first-version weight because it is a
documented positive origin feature and an eligibility correlation in PR3.

### Edge candidate

| Signal | Points |
|---|---:|
| many shared domains | +15 |
| redirect | +15 |
| cookie challenge | +20 |
| shared TLS | +15 |
| content difference | +25 |

`public_cdn` remains zero-point explanatory context for an edge. It cannot make
an edge eligible by itself.

## Score and Confidence Contract

- `raw_score` is the signed sum of all positive and negative contributions.
- `score` is `raw_score` clamped to the inclusive range `0..100`.
- `confidence` is `score / 100` only when the PR3 assessment is eligible.
- `confidence` is exactly `0.0` when the assessment is ineligible, even when
  partial evidence produces a non-zero score.

This separation prevents a large partial score from bypassing required
multi-evidence gates or a public-CDN blocker. `confidence` is an explainable
role-confidence indicator, not a statistically calibrated probability.

`RoleScore` validates these arithmetic invariants at construction:

- `raw_score` equals the sum of every signed contribution;
- `score` equals the bounded raw score;
- `confidence` exactly follows eligibility and score.

A caller therefore cannot construct a contradictory serialized result even
when bypassing `EvidenceScorer`.

## Explanation Contract

- Positive and negative contributions preserve complete `RoleFeature` objects;
  points are awarded once per distinct signal, not once per evidence item.
- Multiple independent evidence items for one signal are all retained without
  multiplying its weight.
- Each source `AttributionEvidence.confidence` value is preserved unchanged as
  provenance and never scales the integer signal weight. Evidence confidence
  and role confidence remain distinct axes.
- Missing weighted evidence is derived from the role's positive weight table,
  not copied blindly from an arbitrary assessment payload.
- Matched or contextual features without a PR4 weight remain visible as
  zero-point explanatory features.
- Output ordering is deterministic by signal value and evidence ID.
- The score result is JSON-safe and does not mutate or extend the existing
  report schema.

## Validation and Safety

- The scorer accepts only a `RoleAssessment`.
- The assessment must equal the canonical PR3 classifier result reconstructed
  from its target and feature buckets; inconsistent manual assessments fail.
- Contribution and result models are frozen, keyword-only, and validate point,
  score, confidence, target, role, and feature consistency.
- A contribution cannot contain a feature for a different signal or target.
- Role policy is private and immutable; callers cannot inject arbitrary weights
  in PR4.
- Ordinary public-CDN infrastructure remains blocked from origin/domestic role
  confidence, while public-CDN evidence may still explain an edge assessment.

## Tests

PR4 adds focused pytest coverage for:

- all documented positive and negative weights;
- raw-score summing and `0..100` clamping;
- eligible versus ineligible confidence behavior;
- exact evidence preservation and one-weight-per-signal behavior;
- missing weighted evidence and zero-weight context;
- public-CDN origin/domestic negative evidence;
- Cloudflare-like ordinary edge not becoming an origin;
- deterministic JSON serialization and frozen-model validation;
- contradictory score arithmetic and manually fabricated eligibility/bucket
  placement rejection;
- rejection of unsupported cloaking scoring;
- the domestic `historical_dns` retention regression.
