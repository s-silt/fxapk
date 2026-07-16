# Cloaking Edge Node Subtype Design

**Date:** 2026-07-16
**Scope:** PR8 only

## Objective

Implement the `cloaking_edge_node` role — "疑似流量伪装边缘节点", a **subtype** of
`edge_candidate` — that PR3/PR4 reserved (the `InfrastructureRole.CLOAKING_EDGE_NODE`
enum member + its `.parent` hook exist, but the classifier never emits it and the
scorer explicitly rejects it). PR8 teaches `RoleClassifier` to emit it and
`EvidenceScorer` to score it, under **strong multi-signal** rules: a confirmed
cloaking edge needs **≥2 independent strong behavioral signals**. Weak signals (a
lone server banner such as OpenResty/nginx/PHP, a public-CDN membership, a generic
cache header) must **never** solo-trigger it. It is a forensic role *hypothesis*,
never an operator/actor accusation.

Mandatory negatives (original acceptance): an **ordinary OpenResty site is not
cloaking**; a plain shared-hosting **edge is not automatically cloaking**.

## Boundaries

PR8 changes only `apkscan/attribution/roles.py` and `apkscan/attribution/scorer.py`
plus tests. It does **not**: add a `RoleSignal`; change the fact models
(`NetworkEntity`/`AttributionEvidence`/`Observation`); change the PR7 graph, the
intel packages, `apkscan/core`, the CLI, or `report.json`; change the behavior of
the three existing roles (relay/origin/edge stay byte-for-byte identical); or add a
public export (`apkscan/attribution/__init__.py` `__all__` is unchanged — the enum
member and classes already exist). Report/CLI surfacing is PR9.

## Signal model

Strong cloaking signals (behavioral, hard to fake, each requires the peer to
actively implement it), a **strict subset** of the existing `_EDGE_SIGNALS`:

```python
_CLOAKING_STRONG = frozenset({
    RoleSignal.CONTENT_DIFFERENCE,   # different clients get different content
    RoleSignal.COOKIE_CHALLENGE,     # challenge cookie
    RoleSignal.REDIRECT,             # redirect after the challenge
})
```

`MANY_SHARED_DOMAINS` and `SHARED_TLS` are ordinary shared-hosting / CDN
infrastructure facts (cheap, non-behavioral) — they corroborate an *edge* but never
prove cloaking, so they are **context**, never a requirement. Server banners
(OpenResty/nginx/PHP) are **not** `RoleSignal`s (they are enricher payloads); a
banner-only entity produces no signal, so `present == ∅` and it is ineligible for
every role — the "weak never solo-triggers" rule is structural, not a special case.
PR8 adds **no** new signal (a `TEMPLATE_REUSE` signal would have to enter
`_EDGE_SIGNALS` to keep the subset invariant, which would change `EDGE_CANDIDATE`).

## Classifier definition (`roles.py`)

Append a 4th `_RoleDefinition` after `EDGE_CANDIDATE` (order matters — `assess()`
returns one assessment per definition, so the first three positions stay identical):

```python
_RoleDefinition(
    role=InfrastructureRole.CLOAKING_EDGE_NODE,
    supporting=_CLOAKING_STRONG,
    requirements=(_Requirement(_CLOAKING_STRONG, minimum=2),),
    blockers=frozenset(),
    context=frozenset({RoleSignal.MANY_SHARED_DOMAINS, RoleSignal.SHARED_TLS, RoleSignal.PUBLIC_CDN}),
)
```

- **Eligible** ⇔ `|_CLOAKING_STRONG ∩ present| ≥ 2` (no blocker exists). By the
  pigeonhole rule any qualifying pair is two behavioral signals, so a single strong
  signal never qualifies and no weak signal can pad the count.
- **`matched_features`** = strong signals present; **`context_features`** = the weak
  edge signals + `PUBLIC_CDN` present; **`missing_evidence`** = the absent strong
  signals — a precise "what strong evidence is still missing" explanation on the
  negative.
- **Subtype implication (cloaking-eligible ⇒ edge-eligible)** is structural, not a
  runtime hook: `_CLOAKING_STRONG ⊆ _EDGE_SIGNALS` and both requirements use
  `minimum=2` with no blocker, so ≥2 strong signals are ≥2 edge signals. An
  exhaustive 64-subset test over `_EDGE_SIGNALS ∪ {PUBLIC_CDN}` pins it.

### PUBLIC_CDN is context, not a blocker

`blockers = ∅` (mirroring the parent `edge_candidate`, which has no blocker).
Cloaking-as-front SaaS runs *at scale* on public CDN products (e.g. an Aliyun ESA
anti-red instance), so a `PUBLIC_CDN` blocker would systematically false-negative the
highest-value targets. False positives (a legitimate Cloudflare "under attack mode"
genuinely emitting `cookie_challenge`+`redirect`) are contained three ways: the
`PUBLIC_CDN` evidence stays visible in `context_features` for PR9 to annotate; the
role name is always a "疑似" hypothesis and the five-layer `service_operator` stays
`unknown`; and the observation ("client was challenged then redirected") is factually
true regardless of intent. Keeping `blockers = ∅` also preserves the parent/child
consistency (a subtype only *tightens the behavioral requirement*, it never adds a
veto the parent lacks).

## Scorer policy (`scorer.py`)

Add a `_RolePolicy` for cloaking and remove the three PR4 rejections
(`RoleScore.__post_init__`, `_RolePolicy.__post_init__`, `EvidenceScorer.score`) —
**atomically, in one commit**, so `assess()` never emits a role that `score()` cannot
weight.

```python
_CLOAKING_WEIGHTS = {
    RoleSignal.CONTENT_DIFFERENCE: 40,
    RoleSignal.COOKIE_CHALLENGE: 30,
    RoleSignal.REDIRECT: 20,
    RoleSignal.MANY_SHARED_DOMAINS: 0,
    RoleSignal.SHARED_TLS: 0,
    RoleSignal.PUBLIC_CDN: 0,
}
```

**Policy⇄definition self-consistency** (a convention every existing role already
obeys — PR8 makes it an explicit, tested invariant): a policy's **positive-weight**
signals equal `definition.supporting`, its **zero-weight** signals equal
`definition.context`, and its **negative-weight** signals equal `definition.blockers`.
For cloaking: positive = `{content_difference, cookie_challenge, redirect}` =
supporting; zero = `{many_shared_domains, shared_tls, public_cdn}` = context; negative
= `∅` = blockers. This alignment is exactly what lets `EvidenceScorer` re-run the
classifier and pass `_validate_policy_conformance` + `_validate_classifier_conformance`
(the scorer builds one contribution per present policy signal; the union must equal
the classifier's matched+context+negative features, and `RoleScore.missing` must equal
the absent positive-weight signals). A 2-strong cloaking (e.g. content_difference +
cookie_challenge) scores `40+30 = 70` → `confidence 0.70`.

Both `edge_candidate` and `cloaking_edge_node` `RoleScore`s are emitted when both are
eligible (no parent suppression); PR7's graph annotates a node with both side by side
(it keys annotations by `role.value`, so this needs zero graph change — the reason to
score cloaking rather than leave it classification-only).

## Compatibility & the tests that must change

`apkscan/attribution/__init__.py` is untouched (no new symbol). No module outside
`apkscan/attribution/` imports `roles`/`scorer` symbols (`apkscan/core/attribution.py`
is the separate five-layer enricher; PR7 graph keys roles generically; intel uses only
`AttributionEvidence`), and `report.json` is unaffected. `assess()` now returns a
**4-tuple** and `_ROLE_POLICIES` has **4** entries — update the tests that pin those:

- `tests/test_attribution_roles.py`
  - `test_role_vocabulary_and_cloaking_parent_are_stable` — **unchanged** (a
    regression anchor that must keep passing).
  - `test_assess_returns_ineligible_explanations_but_never_cloaking` — append
    `CLOAKING_EDGE_NODE` (last) to the expected role list, flip `not in` → `in`, keep
    `all(not eligible)` (empty features ⇒ cloaking ineligible too), rename.
  - The `classify()` exact-list tests whose fixture is **redirect + cookie_challenge**
    now also classify as cloaking (2 strong signals) — update those exact lists from
    `[EDGE_CANDIDATE]` to `[EDGE_CANDIDATE, CLOAKING_EDGE_NODE]` (never weaken to a
    subset/`in` assertion).
- `tests/test_attribution_scorer.py`
  - `test_role_score_rejects_cloaking_role` → a **positive** test: build a canonical
    cloaking `RoleScore` via `assess` + `score`, reconstruct it, assert `role is
    CLOAKING_EDGE_NODE`; plus a companion "tampered cloaking points still raise" test.
  - the policy-set test (`… not in _ROLE_POLICIES` / "reserved for PR8") → include
    `CLOAKING_EDGE_NODE` (exact set of **four**), and add
    `(CLOAKING_EDGE_NODE, _CLOAKING_WEIGHTS)` to the parametrized weight-table test.
  - `test_role_policy_rejects_cloaking_edge_node` → assert `_RolePolicy(cloaking, …)`
    **constructs**.
  - `test_scorer_rejects_non_assessment_and_cloaking_role` → split: keep the
    `TypeError` on a non-assessment; replace the cloaking half with (a) a canonical
    eligible cloaking assessment scoring successfully and (b) a hand-built
    non-canonical cloaking assessment still raising (now on the "canonical
    reconstruction" mismatch, not the removed reserved-role guard).

## Tests (new)

- **Positive**: content_difference + cookie_challenge ⇒ cloaking eligible **and** edge
  eligible (subtype instance); cookie_challenge + redirect ⇒ eligible;
  public_cdn + content_difference + cookie_challenge ⇒ eligible with `public_cdn` in
  `context_features` (pins PUBLIC_CDN = context, guarding against a future blocker
  regression).
- **Negative**: many_shared_domains + shared_tls (ordinary OpenResty/shared-hosting
  edge) ⇒ edge eligible, cloaking **ineligible** with `missing_evidence` = the three
  strong signals; each single strong signal alone ⇒ ineligible; content_difference +
  shared_tls (1 strong + 1 weak) ⇒ edge eligible, cloaking ineligible.
- **Invariants**: exhaustive 64-subset `cloaking-eligible ⇒ edge-eligible`; a
  structural parent-subtype test (for every role with `.parent`: requirement signals ⊆
  parent's, supporting ⊆ parent's, blockers ⊇ parent's, minimum ≥ parent's); a
  policy⇄definition self-consistency test over all four roles (positive==supporting,
  zero==context, negative==blockers); the first-three assessments stay field-for-field
  identical to the pre-PR8 output.
- **Scorer**: a cloaking `RoleScore` scores correctly (raw_score/score/confidence);
  policy conformance holds; a cloaking `RoleScore` is a valid PR7 `GraphNode`
  annotation (a small forward-compatible graph test).
