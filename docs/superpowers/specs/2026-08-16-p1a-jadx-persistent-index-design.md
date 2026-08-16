# P1-A JADX Persistent Index Design

## Goal

Add a persistence-neutral, fail-closed JADX index that supports deterministic
`find_value_usage` queries and extra-Dex incremental reuse without changing the
CLI, report schema, or the authority boundary of the P0-A judgment ledger.

## Scope

P1-A adds a standard-library-only index module and tests. The caller must opt in
by providing an explicit cache root. Normal analysis continues to run without a
persistent index. The first query is value usage; call-path tracing, code-region
diffs, ownership attribution, CLI flags, report meta wiring, SQLite, models, and
KnowledgePack are out of scope.

## Design Options

1. Cache the complete JADX output tree. This is simple but cannot reuse individual
   extra-Dex inputs and would couple locators to temporary absolute paths.
2. Store a content-addressed manifest with immutable per-input shards. This is
   the selected design: it supports incremental extra-Dex reuse, version drift,
   atomic publication, and deterministic lookup while keeping paths relative.
3. Store the index in SQLite. This would add locking, migration, and platform
   state for a single query and is rejected for P1-A.

## Public API

The new module is `apkscan/core/jadx_index.py`.

```python
class JadxIndexStore:
    def __init__(
        self,
        cache_root: str | os.PathLike[str],
        *,
        protected_roots: Iterable[str | os.PathLike[str]] = (),
    ) -> None: ...

    def build_index(
        self,
        source_root: str | os.PathLike[str],
        manifest: JadxIndexManifest,
    ) -> IndexBuildResult: ...

    def load_index(self, index_key: str) -> LoadedIndex | CacheMiss: ...

    def find_value_usage(
        self,
        index: LoadedIndex,
        value: str,
    ) -> tuple[UsageHit, ...]: ...
```

`cache_root` is required and must be non-empty. The library does not read cwd,
the APK parent, the repository, or an environment-variable default. A future
CLI may pass an explicit `--cache-root`, but P1-A does not add that flag.

## Cache Identity and Lineage

Each input DEX has a canonical lineage record containing:

- a role (`apk_dex` or `extra_dex`);
- a caller-provided ordinal within that role;
- the DEX content digest (`sha256:<64 lowercase hex>`);
- the canonical source label, which is an opaque caller label and never an
  absolute filesystem path.

The lineage is sorted by `(role, ordinal, source_label, digest)`. Duplicate
digests are retained when their lineage differs; duplicate identical lineage
records are rejected. The index key is:

```text
sha256(canonical_json_v1({
  "dex_lineage": [...],
  "jadx_version": "...",
  "options_digest": "sha256:...",
  "index_schema_version": "1.0",
}))
```

The key therefore does not incorrectly reuse an index when equal DEX bytes came
from different logical inputs. Shards are keyed by the same canonical lineage
item plus tool/options/schema identity. A manifest records every shard digest,
the complete key material, and the ordered lineage. A loaded index verifies all
of these values before exposing a query surface.

## Manifest and Shards

The manifest and shard files are canonical JSON encoded with the existing
`recognition_codec.canonical_json_v1`. They are immutable create-only artifacts:

1. Build and fsync every new shard in a same-directory temporary file.
2. Publish each shard with `atomic_create_bytes`; an existing differing shard is
   a cache conflict, not an overwrite.
3. Publish the manifest last with `atomic_create_bytes`.
4. A crash before publication leaves at most uniquely named temporary files and
   no trusted manifest.

The manifest contains only schema/tool/options/key material, lineage, shard
references, coverage status, and aggregate digests. A shard contains normalized
source-relative file records and usage postings. No source-root absolute path,
raw APK path, credentials, raw IOC, or source snippet is persisted.

`load_index` returns `CacheMiss` for absent files, malformed JSON, schema/tool
drift, key mismatch, shard digest mismatch, duplicate postings, or any path
escape. It never repairs or overwrites an existing artifact. Callers may rebuild
from the current source tree.

## Path and Cache-root Safety

The store resolves `cache_root` and every protected root before use. It rejects:

- empty, relative, drive-relative, UNC, `file:` URI, and unresolved paths;
- a cache root equal to, below, or containing a protected root after
  case-insensitive containment comparison;
- symlink, junction, or Windows reparse-point escapes for the root, temporary
  files, manifest, or shard paths;
- `..`, absolute, drive-qualified, or separator-ambiguous shard/locator names.

The implementation uses resolved component containment, not string prefixes.
Temporary files are created only inside the resolved cache directory. Index
locators are slash-normalized relative paths and are checked to remain inside
the index root. Tests cover Windows drive/UNC forms, case-folded aliases,
parent/child overlap, symlink/junction/reparse behavior where supported, and
cross-root traversal.

## Indexed Usage Data

The source tree is enumerated deterministically using NFC-normalized, lowercase,
POSIX relative paths sorted by `(casefold, original)`. Each selected Java file
contributes bounded usage records:

- relative path;
- 1-based line and column;
- a bounded digest of the matched string value, never the raw value;
- bounded class and method context identifiers when available;
- the source DEX lineage reference;
- `ownership="unknown"`.

The exact value supplied to `find_value_usage` is compared in memory while
building postings. Query results are sorted by lineage, relative path, line,
column, and context. Empty, over-limit, or malformed values return no hits.
Partial source enumeration, read failures, per-file truncation, timeout, or
JADX failure are recorded in coverage and never produce a negative Observation.

## Ledger Projection Boundary

The index query itself is not a judgment. A future or explicit adapter must
project a successful hit through the existing ledger state machine:

```text
ActionProposed
  -> ActionAuthorized
  -> ActionOutcomeRecorded
  -> ObservationAdded
```

The adapter records the index manifest/shard as evidence anchors and the query
receipt as an action outcome. Cache hit, rebuild, cache miss, corruption,
schema/tool drift, timeout, and failure have explicit status/coverage values.
Only successful or explicitly partial positive observations may be emitted;
partial/timeout/failed states cannot be interpreted as absence. The adapter
must use `append_event`/`replay` and cannot construct a detached Outcome or
Observation, a ClaimCandidate, or a ReviewDecision.

## Failure and Concurrency Contract

Concurrent builders may race to publish the same shard. The first complete
artifact wins; a loser verifies the existing bytes and treats equal content as
success, but rejects a conflicting artifact. Manifest publication follows the
same create-only rule. Reads verify complete bytes before returning.

Atomic-write failures, permission failures, unsupported create-only publication,
and lock contention are surfaced as structured cache-unavailable results. They
do not corrupt or replace an older index and do not block the caller's ordinary
non-persistent JADX analysis.

## Verification

P1-A tests must cover:

- deterministic key and posting order;
- equal DEX bytes with distinct lineage not colliding;
- duplicate identical lineage rejection;
- extra-Dex shard reuse and incremental manifest construction;
- schema/tool/options drift and key mismatch as cache misses;
- missing, malformed, tampered, and partially written artifacts;
- create-only publication, concurrent writers, and crash-before-manifest;
- cache-root and locator containment attacks;
- bounded non-sensitive postings and ownership unknown;
- hit/rebuild/miss/corrupt/timeout/failed coverage semantics;
- legal ledger event-chain projection and rejection of detached events;
- default analyzer behavior producing no persistent index.

The implementation must preserve all existing tests and must not add a runtime
dependency or modify the report/case-package/corpus schema.
