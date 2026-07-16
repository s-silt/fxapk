# Infrastructure Role Classifier Design

**Date:** 2026-07-16
**Scope:** PR3 only

## Objective

Add an explainable, deterministic first-pass role classifier for normalized
infrastructure facts. PR3 identifies eligible candidates for these top-level
roles:

- `domestic_relay_candidate`
- `origin_candidate`
- `edge_candidate`

`cloaking_edge_node` is reserved as an `edge_candidate` subtype, but PR3 does
not evaluate it. Its behavioral rules remain in PR8.

## Boundaries

PR3 does not:

- assign weights, scores, confidence, or thresholds; PR4 owns scoring;
- call external intelligence APIs; PR5 and PR6 own providers;
- build or mutate the infrastructure graph; PR7 owns graph integration;
- detect cloaking behavior; PR8 owns that subtype;
- modify analyzers, the existing report schema, or CLI output;
- infer an operator or criminal subject from an ASN, provider, or resource
  holder.

## Considered Approaches

### 1. Imperative observation parser

Read `Observation` objects directly and implement role logic as nested
conditionals. This is initially small, but it couples protocol parsing, feature
normalization, role eligibility, and future scoring. Adding passive-intel facts
would require repeatedly changing the classifier.

### 2. Normalized signals plus declarative role definitions

Convert facts into named `RoleSignal` values, retain the exact
`AttributionEvidence` supporting each signal, and evaluate declarative role
definitions. This keeps facts, inference, and scoring separate and makes every
result explainable. **This is the selected approach.**

### 3. General graph query or rule DSL

Represent eligibility as graph queries or a configurable rule language. This
would be extensible, but it prematurely consumes work assigned to PR7 and adds
validation, parsing, and compatibility surface that PR3 does not need.

## Public Model

`apkscan/attribution/roles.py` defines:

- `InfrastructureRole`: the four stable role identifiers. The cloaking member
  exposes `edge_candidate` as its parent but is disabled for classification.
- `RoleSignal`: normalized, non-numeric features used by PR3 and later PR4.
- `RoleFeature`: an immutable pair of one `RoleSignal` and the exact
  `AttributionEvidence` that supports it.
- `RoleAssessment`: an immutable explanation containing the target entity,
  role, eligibility, structured matched/context/negative `RoleFeature`
  collections, and missing expected signals. Derived signal and evidence
  accessors remain available, but the structured collections preserve the
  exact signal-to-evidence relationship. It deliberately has no score or
  confidence field.
- `RoleClassifier`: a stateless deterministic evaluator with `assess()` and
  `classify()` entry points.

The classifier consumes explicit normalized features instead of guessing
country, CDN status, ownership, or business meaning from provider strings.
Later adapters may derive these features from PR2 observations and PR5/PR6
intelligence evidence without changing the role rules.

## Signal Vocabulary

The initial vocabulary is:

- traffic: `direct_connection`, `redirect`,
  `subsequent_overseas_connection`;
- location and infrastructure: `domestic_network`, `non_public_cdn`,
  `public_cdn`;
- origin behavior/correlation: `business_api`, `login_endpoint`, `stable_ip`,
  `historical_dns`, `business_certificate`;
- edge behavior/correlation: `many_shared_domains`, `cookie_challenge`,
  `shared_tls`, `content_difference`.

Generic server banners such as OpenResty, nginx, or PHP are intentionally not
eligibility signals. A caller therefore cannot classify an edge or cloaking
node from those weak strings alone.

## Eligibility Rules

Eligibility gates are boolean safety constraints, not scores.

### Domestic relay candidate

Requires all of:

- direct APK connection;
- domestic network evidence;
- at least one transition indicator: redirect or a subsequent overseas
  connection.

`non_public_cdn` is expected supporting evidence but is not a hard gate so PR4
can express incomplete cases. `public_cdn` is blocking negative evidence.

### Origin candidate

Requires all of:

- business API traffic;
- at least one independent correlation: login endpoint, stable IP, historical
  DNS, or business certificate.

`non_public_cdn` is expected supporting evidence. `public_cdn` blocks the
candidate, preventing an ordinary Cloudflare edge from being called an origin.

### Edge candidate

Requires at least two distinct signals from:

- many shared domains;
- redirect behavior;
- cookie challenge;
- shared TLS;
- content difference.

This avoids classifying a normal site from a single redirect or generic server
banner. Public-CDN context is retained in a separate non-qualifying context
collection and does not independently make an edge candidate or appear as
missing evidence when absent.

### Cloaking edge node

The enum value and parent relationship exist for forward compatibility.
`RoleClassifier` does not return a cloaking assessment or candidate in PR3.

## Determinism and Validation

- A feature is only considered when its evidence target equals the assessed
  entity by entity identity; `sources` do not affect entity equality.
- Duplicate `(signal, evidence.id)` pairs with identical full evidence payloads
  are collapsed. For one assessed target, an evidence ID is globally bound to
  one complete `AttributionEvidence.to_dict()` payload across all signals and
  explanation buckets; conflicting reuse is rejected.
- Output roles, signals, and evidence are sorted using stable explicit keys.
- Invalid signal/evidence objects are rejected at model construction rather
  than silently converted.
- `to_dict()` returns JSON-safe deterministic data and does not alter existing
  report output.

## Tests

PR3 adds focused pytest coverage for:

- domestic relay, origin, and edge positive cases;
- Cloudflare/public-CDN origin rejection;
- a generic OpenResty-like banner producing no candidate;
- one shared ASN having no role meaning by itself;
- missing and negative evidence explanations;
- cloaking reservation without classification;
- target isolation, duplicate handling, deterministic ordering, JSON safety,
  and validation.
- exact signal-to-evidence mapping, cross-signal evidence-ID consistency, and
  retention of non-qualifying public-CDN edge context.
