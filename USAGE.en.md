# fxapk command and data conventions

[Project overview](README.en.md) · [中文](USAGE.md)

Full flags: `fxapk --help`; if `fxapk` is not installed as a command, use `python -m apkscan.cli`.

## Command table

| Goal | Command |
|---|---|
| Analyse an APK (**online by default** for attribution) | `fxapk analyze app.apk --out out`; add `--offline` for no network |
| Authorized online retention of HTTP redirects and responses (no JS execution) | `fxapk capture-web https://example.invalid/start --authorized --out private/capture.har` |
| Analyse saved HTML/JS/HAR (offline by default) | `fxapk analyze-web <dir> --out out`; `--online` enables attribution enrichment only |
| Batch | `fxapk batch <dir>` |
| Full pipeline (dynamic runs only on a rooted device; **modifies the device**) | `fxapk auto app.apk --out out`; add `--strict-case` for the acceptance gate (exit 0/5/6 = complete/partial/failed) |
| Multi-source lookups and five-layer attribution on an existing report | `fxapk case close out/app.json` |
| Freeze a Phase-1 evidence package | `fxapk case package out/app.json --case-id CASE-001 --producer analyst --out out/case-package.json` |
| Verify a package and reconcile against the out-of-worktree corpus (dry-run by default) | `fxapk corpus reconcile out/case-package.json --corpus <dir> [--apply]` |
| Phase-2 review record | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --gate-receipt phase2/gate-receipt.json --out out/case-review.json` |
| View the four states side by side | `fxapk case status out/case-package.json --review out/case-review.json` |
| One-page digest (**redacted by default**) | `fxapk digest out/app.json`; add `--no-redact` for raw values |
| Android UI screenshots, layouts and fixed actions (optional plugin) | `fxapk ui --help`, see [ANDROID-UI.en.md](ANDROID-UI.en.md) |
| Capture traffic on a device | `fxapk capture <package>` |
| Device health check | `fxapk doctor --no-fix` checks only; `fxapk doctor` **makes repairs** (installs frida-server / CA) |
| Environment self-check | `fxapk selfcheck` |
| Batch target lists (default `--dry-run` only estimates quota; `--resume` supported) | `fxapk enrich batch -t targets.txt -o enrich_out` |
| Report ingest / cross-version regression / reverse lookup / shared build environment | `fxapk corpus add out/app.json` / `regress` / `seen <value>` / `shared-build-env` (all need `--corpus <dir>`) |
| Cross-case candidates (raw values; scores are not probabilities) | `fxapk corpus link-candidates --corpus <dir> [--model <model.json>]` |
| Label validation / offline evaluation / duplicate-anchor discovery (aggregate output; discover emits no raw values by default) | `fxapk corpus link-labels-validate --labels <jsonl>` / `link-evaluate` / `link-discover` |
| Explain a candidate / anonymous relationship graph | `fxapk corpus link-explain <SHA> <SHA>` / `link-groups` (default `--evidence-values omit`) |
| Training gate / experimental reranker (model writes only outside the worktree) | `fxapk corpus link-readiness` / `link-train --model-out <model.json>` |
| Export CSV / diff / JSONL | `fxapk export out/app.json` / `fxapk diff a.json b.json` / `fxapk jsonl out/app.json` |
| JADX usage locations, call paths, family comparison | `fxapk jadx usage <value> --jadx-cache-root <cache> --apk-sha256 <sha>` / `jadx callpath` / `jadx compare <a.json> <b.json>` |
| DEX string-reference query and import (optional fxapk-asc isolated worker) | `fxapk dex query` / `fxapk dex import`, see [plugins/fxapk-asc/README.md](plugins/fxapk-asc/README.md) |
| Flutter AOT static analysis (optional plugin, offline container) | `fxapk flutter capabilities` / `analyze` / `query` / `attach`, see [plugins/fxapk-flutter/README.md](plugins/fxapk-flutter/README.md) |
| Recognition line (read-only/offline; exit 4 when the promotion gate fails) | `fxapk recognize reanalysis` / `labels validate` / `split build\|validate` / `evaluate` |

## Saved web evidence

Saved web evidence accepts `--evidence-handoff <JSON outside the evidence directory>`.
The `fxapk.web-evidence-handoff.v1` contract binds original file hashes/sizes,
capture provenance, HAR entries, and upstream coverage gaps. Text offsets use decoded
codepoints; HAR body offsets also carry an entry JSON pointer, not a raw-byte coordinate.
Truncation, ignored TLS verification, unknown request associations, and rendered DOM
remain review signals. A matching hash proves neither authenticity nor target-app attribution.
See `meta.web_capture_visibility` and `meta.web_evidence.handoff` for the full boundaries.

## Capture and probe records

- The `no-proxy` observation round does not request TLS-verification changes. Preserve it,
  the original `floor-only` baseline and MITM rounds separately. OkHttp never replays
  request-body `writeTo()`; `not_read_non_interference` means unread, not empty. SQLCipher
  observes paths/keys without exporting through the application's connection;
  `not_attempted_non_interference` is not an export failure.
- Installation, triggering, dropped observations and truncation have separate receipts.
  Java bridge readiness does not confirm hook registration. Missing receipts stay unknown;
  an unavailable API or untriggered hook does not establish anti-analysis or absence of behavior.
- Probe-log import preserves the raw-byte hash, decoded-text hash, line and codepoint
  coordinates. Inputs over 8 MiB or 10,000 imported leads fail rather than silently truncate.
  Bundled event references bind the runtime report's exact read bytes and original array JSON
  pointer; distinct occurrences survive aggregation. Missing identities stay unavailable;
  hashes do not prove authenticity or target-App attribution.
- `meta.capture_safety_comparison` and its compact `digest.capture_safety` projection require
  the same original APK, foreground confirmation, explicit onboarding/network outcomes,
  matching declared action/initial-state/environment digests and hash-bound check artifacts.
  Outcomes are `inconclusive`, `reported_regression`, `baseline_failed` or
  `no_reported_regression`, never proof of causality or universal non-interference.
  Capture completion is not onboarding success; zero traffic is not network failure.
  No automatic app-data clearing or device-state reset is performed.

HTTP `messages[].ts` uses epoch seconds; Frida event timestamps use milliseconds.
Imported `observed_at` values use seconds, while `event_time_semantics` preserves the
producer unit. Unknown channels or invalid times remain unavailable. Handlers bind
each spawned PID and script hash before script loading; retry and late events retain
their original identity. Unbound PID/UID/script identity is never filled from the final
capture summary and carries `process_binding_missing`. Endpoints and events share a
bounded read and original hash; malformed or oversized reports are unavailable/partial,
not successful zero-finding reports.

## Passive resource profiles and batch enrichment

`enrich batch` can explicitly select `--providers fofa_profile,fofa_host,daydaymap_profile`. Dry-run first to verify the services, disclosure scope and budget, then add `--no-dry-run`. Search returns a bounded first page only and records reported totals, actual returns and coverage status; unknown totals, missing fields and permission failures do not mean "no assets". Product, certificate and survey times help judge the service type; they cannot alone confirm a cloud instance, tenant or operator.

Results append per target to `enrich.ndjson`; `enrich.csv` is a rebuilt projection. Response hashes are reconciliation anchors and normalized fields are bounded redacted previews, not raw-response archives. After permission/quota errors and consecutive-failure breakers, the remaining targets of that run are marked skipped. `--credential-slot 2` supports Quake, DayDayMap and their profiles; it does not rotate credentials automatically.

When `https://fofoapi.com` is configured, an HTTP 200 explicitly marked "official error message [-403] insufficient access permission" <!-- leak-scan: allow public relay API hostname required for provider-specific protocol compatibility -->
is recorded as `failed/upstream_permission_denied`; it cannot be used to declare the local relay key invalid.

After service recovery add `--recover-transient`: calls are spaced per source (`--provider-interval`, default 2 s); transient rate limits, timeouts or resolution failures get at most one retry per source (`--retry-delay`, default 15 s); Retry-After over 60 s defers; authentication, permission and quota errors are not retried. The original failure and the retry are recorded separately — recovery does not erase historical gaps.

Hunter reads the account's free balance before searching and reserves credits in a local ledger (`~/.fxapk/hunter-quota.sqlite3`, overridable via `FXAPK_HUNTER_QUOTA_DB`); the same account shares a daily 500-point cap by UTC+8 date, and an unknown balance or failed reservation stops the search. `FXAPK_HUNTER_CREDIT_MODE=free_only` returns `disabled / free_only_billing_unverified` before any request. Account configuration: [.env.example](.env.example).

- Enrichment separates query execution time, uninterpreted provider time fields and source
  family. Shodan and InternetDB are not independent corroboration. Request candidates include
  service roles, identifiers, event windows/timezones, records to obtain and verification
  questions. An edge provider may supply account/domain/origin bindings without being the
  Origin or App operator. Legal channels and historical relationships remain unverified.
  `digest.closure.request_targets` is bounded; consult full closure and source receipts for decisions.

## JADX index

Multi-index queries read `fxapk-jadx-index-map.json` at the cache root by default (or `--index-map`). Older 1.6 indexes keep postings only for the values selected when the index was built; `coverage=complete` does not guarantee coverage of new values, and queries also report `query_coverage`. New analyses run with `--jadx-cache-root` save bounded Java snapshots under `query-sources` for later queries on new values. Snapshots and the `--out` receipt contain controlled material — do not publish them. `callpath`'s `name_unique` only means the simple name is unique; it does not prove method binding. `jadx compare` similarity does not mean the same operator.

## Corpus

Every `corpus` subcommand needs `--corpus <dir>` or `FXAPK_CORPUS` pointing at a library directory **outside the git worktree**.

- Report content can be rebuilt into `manifest.jsonl`; human-confirmed cross-case links, quarantine state and ingest order live only in the non-derived `catalog.jsonl`. One report can bind multiple `case_id`s; ordinary queries exclude `quarantined` by default. For legacy/dev versions run `corpus versions` to audit first, then explicitly `corpus quarantine-version --apply`; the tool never deletes historical evidence automatically.
- After rules-v2, an older manifest without `repack_identity_verdict` makes `link-candidates` return `status=partial` plus `migration.next_action`; run `fxapk corpus reindex --corpus <dir>` to rebuild the projection (report bytes are not changed). If the field is still missing afterwards, that report was never evaluated and must be re-analysed with the current fxapk — "unassessed" cannot be rewritten as `unknown`.
- The case-level IOC index only accepts `Lead.source_refs[]` / `Endpoint.evidences[]` entries carrying at least one explicit `case_evidence` scope.
- `corpus migrate-catalog` moves the old `manifest.case_id` into `catalog.jsonl`: dry-run first, then `--apply`. **Migration is not reversible — back up the whole directory before `--apply`**: a manifest restored by `corpus restore` is re-materialized into the catalog immediately, and deleting `catalog.jsonl` by hand fail-closes the whole library.
- `corpus reconcile` is read-only and lists the plan by default; `--apply` only adds immutable reports or merges case relations. Byte conflicts, quarantine records or package-hash changes exit non-zero. Phase 2 always consumes exact package hashes.

## Cross-stage evidence contract and the four states

Phase 1 produces the report, attachments and the immutable `case-package.json`; Phase 2 is read-only verification producing a separate `case-review.json` and must not overwrite Phase 1. A package requires three reproduction anchors: a 64-hex `sample_sha256`, a non-empty `tool_version` and a 16-hex `ruleset_digest`; a missing field or an `unknown` placeholder refuses the package.

- `package_integrity`: whether manifest, path boundaries and attachment hashes agree
- `analysis`: whether analyzers/pipeline ran completely
- `closure`: whether runtime, attribution and evidence-request targets are closed
- `review`: whether the exact package hash was accepted, change-requested or invalidated

The four states do not imply each other; after a report or attachment changes, old reviews show `stale`. `closure=complete` requires evidence on all five layers of the primary target (runtime, resource registration, BGP announcement, hosting/distribution, final attributed party); a target still fronted by a CDN with no origin located is not judged complete.

Since report schema 1.2 every Evidence carries `scope`: `case_evidence` (direct evidence for the current case), `batch_reference` (batch/cross-case reference, review aid only — cannot be promoted to "recommend evidence request" or satisfy closure), `legacy_unspecified` (migrated old reports). This qualification gate applies to digests, evidence-request letters, IOCs, JSONL and HTML/PDF; `--only-investigate` excludes reference values. Closure goes through the same safe projection: a claimed `complete` with an empty target list is consumed as `failed`, and a target without explicit `case_evidence` can only be consumed as `partial`; Phase-1 packaging rejects a false `complete` outright. `evidence_scope` cannot be revoked with `lead restore/replay`.

Persisted JSON rejects `NaN` / `Infinity`; a failed write does not overwrite an existing report.

### Evidence sources and admission

In report schema 1.3, Evidence may carry `provenance`, `locator`,
`structure_status`, `reference_status`, `reachability`, and `suspicions`.
A stable `occurrence_id` is emitted only when real provenance and coordinates
are both available; legacy reports retain unknown/empty values rather than
inventing locations.

Admission is assessed per occurrence and purpose: `passive_enrichment`, `lead_priority`,
`closure_candidate`, `dex_query`, `model_summary`, and `corpus_relation`. Results are
`allowed`, `review`, or `blocked`; admitting one occurrence does not admit every reference
to the same value. Static candidates are not runtime observations or proof of business ownership.

### Two field groups not to confuse

- `visibility` (was the sample's content visible) vs `analysis_status` (did the tooling run healthy): every analyzer succeeding while the DEX is a stub and six conclusions cannot be made can both be true at once. `blocked_claims` names the conclusions that cannot be made; `next_actions` says how to close the gap.
- `repack_identity`: `self_built` still requires excluding public SDKs, packers and shared infrastructure; under `repack_suspected` the inherited vs added scope is unresolved and must be diffed against the official package of the same version. The tool only says "suspected re-signing", not "what was injected".

## Output

- `out/app.html` — single-file internal evidence view containing raw values; review separately before sharing
- `out/app.json` — full data; `report.meta.closure` holds the acceptance verdict, five-layer evidence, source coverage, gaps and next steps
- `case-package.json` / `case-review.json` — Phase-1 package and Phase-2 review record
- `--fmt pdf` exports PDF (needs local Chrome or Edge)

## Parser budgets

DEX decoding reuses count, character and snapshot-size budgets. These limits do not
isolate parser processes; isolation is enabled separately through the settings below.

Parser process limits are opt-in. Set both `FXAPK_PARSER_TIMEOUT_SEC` and
`FXAPK_PARSER_MEMORY_MB`; `FXAPK_PARSER_OUTPUT_MB` is optional and defaults to a 64 MiB
IPC output cap. Missing or invalid required configuration fails closed. Limits apply
per parse operation and per isolated lazy read, not to the total analysis and not as
a native-code sandbox. With no configuration, parsing remains in-process and the
receipt explicitly says `not_enforced`; no default performance benefit is claimed.
Linux uses an address-space limit (RLIMIT_AS), not measured RSS; Windows uses a Job
Object whose enforcement must be verified on Windows rather than inferred from Linux
tests. If macOS cannot enforce the requested memory limit, parsing fails closed.
An analyze parser failure writes a separate `*.parser-failure.json` receipt and does
not create an empty report.

## Pinned dependencies and reproduction

Parsing is owned by upstream libraries — a different androguard version may produce a different report. [`requirements.lock`](requirements.lock) pins the runtime dependencies:

```bash
python -m venv .venv-forensic
.venv-forensic/bin/pip install -r requirements.lock
.venv-forensic/bin/pip install --no-deps .
```

To reproduce an old report use the code, rules and dependency lock of that time (`meta.dependency_versions` can be checked), and preserve the sample hashes, parameters, external tools, caches and raw responses. Online data and device state change over time; pinned dependencies do not guarantee byte-identical output.

## Developing from source

```bash
git config core.hooksPath .githooks
```

The hook scans staged added lines and by default blocks suspected real IPs, credentials, case names, contact identifiers, secondary package names, and unjustified or bulk exemptions. An inline exception must be written as `leak-scan:` + `allow` + a per-line reason. For committed changes use `fxapk leak-scan --base origin/master --strict` to check the entire candidate diff. Prefer the reserved ranges for test data — `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `example.com`; when a reserved value cannot trigger the code path, use a mock or a justified synthetic fixture. A real address cannot be taken back once pushed.

Code behavior changes pass `python -m ruff check apkscan tests`, `python -m pyright apkscan` and `python -m pytest -q` locally.

## Compliance boundaries

For authorized security research and analysis only; no offensive or exploitation capability is provided. Passive by default: overseas servers get passive attribution only (RDAP / WHOIS / DNS / ASN / CT), sample business URLs are not actively fetched, but DNS queries may be observed. The few capabilities that send requests to a target are off by default and enabled only by explicit authorization flags; `capture-web` needs `--authorized` and performs bounded GETs only on targets inside the allowlist. Unpacking applies to the sample itself and runs on an authorized analysis machine.

## Pre-report materials

```bash
fxapk case source-catalog --category all                      # read-only source catalog; sends no queries
fxapk case provider-plan private/report.json --out private/provider-plan.json   # provider-role review queue
fxapk case package private/demo/pkg/report.json --case-id DEMO --producer analyst --out private/demo/pkg/case-package.json
fxapk case prepare-materials private/demo --out private/demo/pre-report.json
```

`review_required`, `partial` and `failed` are not confirmations of completion. The three capture rounds are filed separately; counts are not spliced across rounds. See [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Optional Android UI plugin

`fxapk-android-ui 0.1.1` provides `ui capabilities` / `ui snapshot` / `ui run-plan`; device commands take an explicit `--serial`, and observations/plans also require `--package` and a new `--out`. Installing the plugin does not automatically attach UI observation to `auto`/`capture`. Screenshots, layouts and diagnostics may contain raw values. See [ANDROID-UI.en.md](ANDROID-UI.en.md).

## Optional Flutter AOT plugin

`fxapk-flutter` (release-attachment wheel, or `python -m pip install -e ./plugins/fxapk-flutter` in the source tree; requires core >=1.23.0) performs offline AOT static analysis on APKs identified as Flutter (Android ARM64 only). `analyze` controls the stage via `--flutter auto` (default) / `off` / `required`, where `required` preserves the report but exits 4 on failure; `--flutter-toolchain` points to a local toolchain.json (falling back to `FXAPK_FLUTTER_TOOLCHAIN` or `~/.fxapk/flutter/toolchain.json`); `--flutter-timeout` accepts 1-1800 seconds (default 300) and bounds a single container run only - it is not a whole-pipeline deadline. The `auto` command has no Flutter options. A missing plugin or toolchain is recorded as a coverage gap; nothing is installed automatically. `analyze` also compares the parse-time snapshot with the final fingerprint: if the input file changed during analysis, it keeps the snapshot-bound report and exits 4 (this applies to `--flutter auto` as well).

```text
fxapk analyze sample.apk --offline --flutter auto --out analysis
fxapk analyze sample.apk --offline --flutter required --out analysis-required
fxapk flutter analyze sample.apk --out flutter-result
fxapk flutter query flutter-result --symbol UploadService.uploadContacts
fxapk flutter query flutter-result --text contacts
fxapk flutter attach flutter-result --report analysis/sample.json --out new-revision
```

`attach` requires the report `meta.sample_sha256` to equal the bundle's bound APK hash and writes to a new output directory; original report bytes are preserved as `source-report.json` and lead grading/closure are not recomputed. Cache and manifest hashes prove byte equality, not content truth. Queries and evidence bundles are not redacted. Configuration, cache keys and supported scope: [plugins/fxapk-flutter/README.md](plugins/fxapk-flutter/README.md).

## License

[MIT](LICENSE)
