# P1-A JADX Persistent Index Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an explicit-cache-root, fail-closed, content-addressed JADX usage index with verified DEX inputs, deterministic bounded postings, immutable publication, and a replayable ledger projection boundary without changing CLI, report/case schema, or runtime dependencies.

**Architecture:** `JadxIndexStore` receives an ephemeral mapping from each lineage item to a safe source-relative DEX path and declared digest, verifies the bytes before invoking JADX, and derives a domain-separated key from canonical lineage/tool/options/schema bytes. Per-lineage shards and a final manifest are canonical JSON artifacts published create-only under a contained cache root; loaders verify every digest and reject invalid artifacts. A small ledger adapter consumes an already proposed and authorized action, records a typed outcome with manifest/shard/query anchors, and emits positive observations only through `append_event` and `replay`.

**Tech Stack:** Python 3.11 standard library, existing `recognition_codec.canonical_json_v1`, `apkscan.core.atomic.atomic_create_bytes`, existing JADX analyzer/process ownership helpers, pytest, and the existing `judgment_ledger`/`recognition_contract` types.

---

## File Map

- Create: `apkscan/core/jadx_index.py` — immutable cache model, validated input mapping, key derivation, build/load/query operations, path safety, and structured cache results.
- Create: `apkscan/core/jadx_index_ledger.py` — optional explicit projection adapter that accepts an existing authorized ledger action and appends legal outcome/observation events.
- Create: `tests/test_jadx_index.py` — unit and integration coverage for identity, verification, publication, safety, deterministic postings, and result classification.
- Create: `tests/test_jadx_index_ledger.py` — event-chain/status/anchor tests for every cache/build state.
- Modify: `tests/test_jadx.py` — one regression test proving ordinary analyzer operation does not create or consult a persistent index when no explicit store is supplied.
- Reference only: `apkscan/core/recognition_codec.py`, `apkscan/core/recognition_contract.py`, `apkscan/core/judgment_ledger.py`, `apkscan/core/atomic.py`, and `tests/recognition_fixtures.py`.

No CLI, report schema, case-package schema, corpus schema, or dependency-file changes are part of P1-A.

### Task 1: Lock the verified input and result contracts

**Files:**
- Create: `apkscan/core/jadx_index.py`
- Test: `tests/test_jadx_index.py`

- [ ] **Step 1: Write failing contract tests.** Define tests for immutable dataclasses representing `DexLineage`, ephemeral `DexInput`, `JadxIndexManifest`, `CacheMiss`, `CacheUnavailable`, `IndexBuildResult`, `LoadedIndex`, and `UsageHit`. Assert that a `DexInput` contains `role`, `ordinal`, `source_label`, slash-normalized `relative_path`, and `declared_digest`, while serialized lineage contains no absolute path.

- [ ] **Step 2: Run the focused tests and verify they fail.**

Run: `pytest tests/test_jadx_index.py -q`

Expected: collection or assertion failures because the new module and contracts do not exist.

- [ ] **Step 3: Implement the minimal typed contract.** Keep public methods compatible with the spec but make the result distinction explicit:

```python
def load_index(
    self, index_key: str
) -> LoadedIndex | CacheMiss | CacheUnavailable: ...
```

`CacheMiss` is a valid rebuildable cache state with stable reason codes such as `absent`, `malformed`, `schema_drift`, `tool_drift`, `key_mismatch`, `shard_digest_mismatch`, `duplicate_posting`, and `path_escape`. `CacheUnavailable` is an operational inability to use persistence with codes such as `permission_denied`, `atomic_create_unsupported`, `lock_contended`, and `io_error`; it must never be silently converted to `CacheMiss`. `IndexBuildResult` must carry build state (`built`, `reused`, `partial`, `failed`, or `unavailable`), coverage, manifest/shard locators when available, and diagnostics without sensitive source text.

- [ ] **Step 4: Re-run the contract tests.**

Run: `pytest tests/test_jadx_index.py -q`

Expected: PASS for the type/serialization contract tests.

- [ ] **Step 5: Commit the contract slice.**

```bash
git add apkscan/core/jadx_index.py tests/test_jadx_index.py
git commit -m "feat: define JADX index contracts"
```

### Task 2: Verify DEX mappings and canonical lineage identity

**Files:**
- Modify: `apkscan/core/jadx_index.py`
- Test: `tests/test_jadx_index.py`

- [ ] **Step 1: Add red tests for byte verification and collisions.** Cover a declared digest mismatch against actual bytes, missing/non-regular mapped files, duplicate identical lineage rejection, equal bytes with distinct role/ordinal/label remaining distinct, and two source paths that collide after NFC normalization or case-folding.

- [ ] **Step 2: Run the identity tests to confirm the missing safeguards.**

Run: `pytest tests/test_jadx_index.py -k "digest or lineage or collision" -q`

Expected: FAIL before validation is implemented.

- [ ] **Step 3: Implement explicit input-side mapping.** Require every manifest lineage item to have exactly one ephemeral `DexInput` mapping. Normalize only safe relative POSIX paths for lookup; reject absolute, drive-qualified, UNC, `..`, separator-ambiguous, empty, or unresolved paths. Resolve each path under `source_root`, read bytes, recompute SHA-256, and reject any mismatch before JADX runs. Reject duplicate canonical `(role, ordinal, source_label, digest)` records and reject any two mapped paths whose NFC/case-fold key is equal. Never derive a filesystem path from the opaque `source_label` and never persist `source_root` or an absolute path.

- [ ] **Step 4: Implement domain-separated canonical key bytes.** Build one ordered key-material object containing `dex_lineage`, `jadx_version`, `options_digest`, and `index_schema_version`; encode it with `canonical_json_v1`; hash `b"fxapk.jadx.index/key/v1\\0" + encoded`. Use the same explicit domain-separated construction for shard keys, with the canonical lineage item and tool/options/schema identity. Validate digest syntax as lowercase `sha256:` plus 64 hex characters.

- [ ] **Step 5: Re-run identity tests and add fixed-vector assertions.** Assert key bytes are stable across dict insertion order, differ for every drift dimension (lineage, JADX version, options digest, schema), and match a checked-in expected digest for one canonical vector.

Run: `pytest tests/test_jadx_index.py -k "digest or lineage or collision or key" -q`

Expected: PASS.

- [ ] **Step 6: Commit the identity slice.**

```bash
git add apkscan/core/jadx_index.py tests/test_jadx_index.py
git commit -m "feat: verify DEX inputs and derive canonical index keys"
```

### Task 3: Implement contained immutable manifest and shard publication

**Files:**
- Modify: `apkscan/core/jadx_index.py`
- Test: `tests/test_jadx_index.py`

- [ ] **Step 1: Write publication and root-safety tests.** Cover a new cache root, cache root equal to/below/containing a protected root, relative/drive-relative/UNC/`file:`/empty roots, `..` and absolute locators, case-folded aliases, symlink/junction/reparse escapes where supported, and cross-root traversal. Add tests for same-content concurrent shard/manifest publication, conflicting-content publication, crash before manifest, malformed/tampered/partially written artifacts, and preservation of an older valid index.

- [ ] **Step 2: Run the safety/publication tests to establish red state.**

Run: `pytest tests/test_jadx_index.py -k "root or locator or symlink or junction or reparse or publish or concurrent or crash or tamper" -q`

Expected: FAIL until containment and create-only publication exist.

- [ ] **Step 3: Implement resolved component containment.** Resolve `cache_root` and each protected root before use; compare resolved components case-insensitively and reject overlap in either direction. Create temporary files only inside the resolved cache directory. Validate slash-normalized manifest/shard locators against the index root after resolution, checking each existing component for symlink, junction, or Windows reparse-point escape. Do not use string-prefix checks.

- [ ] **Step 4: Implement immutable publication.** Serialize manifest and shards with `canonical_json_v1`; write and flush/fsync a uniquely named same-directory temporary file; publish with `atomic_create_bytes`. Treat an existing identical artifact as reuse, an existing differing artifact as a cache conflict, and permission/unsupported atomic-create/lock errors as `CacheUnavailable`. Publish all shards before the manifest. A crash before manifest leaves no trusted index; do not repair, overwrite, or replace an older artifact.

- [ ] **Step 5: Implement fail-closed loading.** For an existing manifest, validate schema/tool/options/key material, canonical bytes, shard locators, shard digests, duplicate postings, and source-relative path containment before returning `LoadedIndex`. Return `CacheMiss` for invalid or absent artifacts and `CacheUnavailable` only for operational access failures.

- [ ] **Step 6: Re-run publication and safety tests.**

Run: `pytest tests/test_jadx_index.py -k "root or locator or symlink or junction or reparse or publish or concurrent or crash or tamper" -q`

Expected: PASS, with platform-specific link tests skipped only when the host cannot create that link type.

- [ ] **Step 7: Commit the publication slice.**

```bash
git add apkscan/core/jadx_index.py tests/test_jadx_index.py
git commit -m "feat: publish JADX index artifacts immutably"
```

### Task 4: Build deterministic bounded source postings and incremental shards

**Files:**
- Modify: `apkscan/core/jadx_index.py`
- Test: `tests/test_jadx_index.py`

- [ ] **Step 1: Write red tests for deterministic postings and reuse.** Use the same Java files created in different directory enumeration orders and assert byte-identical shards and query ordering. Verify 1-based line/column, lineage references, `ownership="unknown"`, bounded value digests instead of raw values, empty/over-limit/malformed queries returning no hits, extra-Dex shard reuse, and incremental manifest construction.

- [ ] **Step 2: Run the posting tests and verify failure.**

Run: `pytest tests/test_jadx_index.py -k "posting or usage or extra_dex or bounded or deterministic" -q`

Expected: FAIL before enumeration and shard reuse are implemented.

- [ ] **Step 3: Implement deterministic enumeration and bounded matching.** Enumerate selected Java files beneath the JADX output root, normalize relative paths to NFC/lowercase POSIX form, reject path collisions, and sort by `(casefold, original)`. Parse bounded lines without persisting source snippets; record relative path, 1-based line/column, a bounded digest of the matched value, bounded class/method identifiers, and the source lineage reference. Compare the exact query value only in memory during build/query. Enforce explicit byte/count/query limits and mark truncation/read failures in coverage.

- [ ] **Step 4: Implement shard reuse and aggregate coverage.** Key one shard per canonical lineage item plus tool/options/schema identity. Reuse a verified immutable shard when its bytes match; rebuild only missing lineage shards. Construct a manifest whose ordered shard references, coverage statuses, and aggregate digest are deterministic. Partial enumeration, read failures, timeout, or JADX failure must never generate a negative observation.

- [ ] **Step 5: Re-run posting tests and the existing JADX suite.**

Run: `pytest tests/test_jadx_index.py -k "posting or usage or extra_dex or bounded or deterministic" -q tests/test_jadx.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the posting slice.**

```bash
git add apkscan/core/jadx_index.py tests/test_jadx_index.py
git commit -m "feat: add deterministic bounded JADX postings"
```

### Task 5: Define and implement the ledger projection adapter

**Files:**
- Create: `apkscan/core/jadx_index_ledger.py`
- Test: `tests/test_jadx_index_ledger.py`

- [ ] **Step 1: Write status-matrix and replay tests.** Build fixtures from `tests/recognition_fixtures.py` ending in an existing `ACTION_PROPOSED` plus matching `ACTION_AUTHORIZED`. Test cache hit, cache miss followed by successful rebuild, reused extra-Dex shard, corruption/schema/tool drift followed by rebuild, timeout, JADX failure, and `CacheUnavailable`. Assert each result's `OutcomeStatus`, `CoverageSource.JADX_INDEX`/status, stable reason codes, and whether an observation is allowed.

- [ ] **Step 2: Run the ledger tests to verify the contract is not yet implemented.**

Run: `pytest tests/test_jadx_index_ledger.py -q`

Expected: FAIL because the adapter and status matrix do not exist.

- [ ] **Step 3: Implement an adapter that receives an existing authorized action.** Expose a function such as:

```python
def append_jadx_query_projection(
    events: tuple[LedgerEvent, ...],
    *,
    action_id: str,
    result: IndexQueryResult,
    actor: Actor,
    occurred_at: str,
) -> tuple[LedgerEvent, ...]: ...
```

Validate via `replay` that `action_id` is already proposed and authorized; reject a detached action, wrong action type, missing authorization, or mismatched subject. Append exactly one `ACTION_OUTCOME_RECORDED` with `ActionOutcome.action_id`, mapped `OutcomeStatus`, `ActionUsage`, reason codes, diagnostics locator on failure, and `CoverageAssertion(source=CoverageSource.JADX_INDEX, ...)`. Add manifest/shard evidence anchors (`EvidenceAnchorType.JADX_INDEX`, content digests) and a query receipt locator to the outcome.

- [ ] **Step 4: Implement the explicit status mapping.** Use `COMPLETE` + `CoverageStatus.COMPLETE` for a verified cache hit or successful rebuild; use `PARTIAL` + `PARTIAL` for usable positive hits with incomplete enumeration; use `FAILED` + `FAILED` for JADX/process failure with no usable positive result; use `FAILED` + `UNAVAILABLE` for `CacheUnavailable`; use `PARTIAL` + `TIMEOUT` for timeout with partial positive output and `FAILED` + `TIMEOUT` when no usable output exists. Cache miss/corruption/schema/tool drift are reason codes on the rebuild outcome, not negative findings. Do not emit any observation for empty results or absence.

- [ ] **Step 5: Append observations only through the ledger state machine.** For each positive `UsageHit`, append one `OBSERVATION_ADDED` after the outcome, referencing the registered index anchor and `origin_outcome_id`; use `ObservationStrength.OBSERVED`, `OwnershipValue.UNKNOWN`, and a bounded categorical/reference value. Call `append_event` for every append and `replay` before returning. Never construct a detached `ActionOutcome`/`Observation`, `ClaimCandidate`, or `ReviewDecision`, and never interpret partial/timeout/failed/unavailable coverage as absence.

- [ ] **Step 6: Re-run ledger tests and tamper/replay regression tests.**

Run: `pytest tests/test_jadx_index_ledger.py tests/test_judgment_ledger.py -q`

Expected: PASS, including rejection of detached events, missing anchors, unauthorized outcomes, negative observations, and non-replayable event chains.

- [ ] **Step 7: Commit the ledger slice.**

```bash
git add apkscan/core/jadx_index_ledger.py tests/test_jadx_index_ledger.py
git commit -m "feat: project JADX index results through ledger"
```

### Task 6: Preserve analyzer opt-in behavior and run the full verification matrix

**Files:**
- Modify: `tests/test_jadx.py`
- Test: `tests/test_jadx_index.py`, `tests/test_jadx_index_ledger.py`

- [ ] **Step 1: Add the no-persistence regression test.** Run `JadxAnalyzer` with no explicit `JadxIndexStore` or cache root and assert the existing receipt/status behavior is unchanged and no index directory/artifact is created.

- [ ] **Step 2: Run the focused P1-A matrix.**

Run: `pytest tests/test_jadx_index.py tests/test_jadx_index_ledger.py tests/test_jadx.py -q`

Expected: PASS with no runtime dependency installation.

- [ ] **Step 3: Run repository contract and import checks.**

Run: `pytest tests/test_judgment_ledger.py tests/test_recognition_codec.py tests/test_case_package.py -q`

Expected: PASS; the new module imports through the standard-library-only path and does not alter existing ledger or codec behavior.

- [ ] **Step 4: Run the complete test suite and inspect the diff.**

Run: `pytest -q` and `git diff --check`

Expected: all existing tests pass, no whitespace errors, and only the planned P1-A files are changed.

- [ ] **Step 5: Commit the integration/test slice.**

```bash
git add tests/test_jadx.py tests/test_jadx_index.py tests/test_jadx_index_ledger.py
git commit -m "test: verify JADX index opt-in and regression contracts"
```

### Self-review checklist

- [ ] Every DEX digest is recomputed from bytes selected by an explicit safe-relative input mapping; no opaque label is converted into a path.
- [ ] NFC/case-fold collisions, duplicate lineage, and all key drift dimensions are rejected or produce distinct keys deterministically.
- [ ] `CacheMiss` is rebuildable; `CacheUnavailable` is operational and never triggers a rebuild implicitly.
- [ ] Shards and manifests are canonical, fsynced, create-only, immutable, digest-verified, and published manifest-last.
- [ ] Cache/protected-root and locator checks use resolved component containment and account for symlink/junction/reparse escapes.
- [ ] Postings are deterministic, bounded, non-sensitive, source-relative, and ownership-unknown.
- [ ] Every ledger projection starts from an existing authorized action, records explicit outcome/coverage/diagnostic mappings, registers anchors, and replays successfully.
- [ ] No partial/timeout/failed/unavailable result creates a negative observation; no Claim/Review/CLI/report/schema/dependency changes are introduced.
