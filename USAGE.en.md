# fxapk command and data reference

[Project overview](README.en.md) · [中文](USAGE.md)

## Command table

If you'd rather type commands yourself, these are the common ones. Full flags: `fxapk --help`; if
`fxapk` isn't on your PATH, swap in `python -m apkscan.cli`.

| Goal | Command |
|---|---|
| Analyse an APK (**online by default**) | `fxapk analyze app.apk --out out` |
| Same, but **offline** (no domain / IP leaves the machine) | `fxapk analyze app.apk --offline --out out` |
| Capture authorized HTTP responses (GET only, no browser JS) | `fxapk capture-web https://example.invalid/start --authorized --out private/capture.har` |
| Analyse saved HTML/JS/HAR (offline by default; `--online` enables enrichment only) | `fxapk analyze-web <dir> --out out` |
| Run a whole folder | `fxapk batch <dir>` |
| Full pipeline: doctor → static → unpack/reanalyze → PCAP → general probes → targeted capture → merge (changes an authorized test device; without a device, dynamic steps are skipped) | `fxapk auto app.apk --out out` |
| Same, as an acceptance gate (exit 0/5/6 = complete/partial/failed) | `fxapk auto app.apk --out out --strict-case` |
| Top up an existing report with multi-source lookups and five-layer attribution | `fxapk case close out/app.json` |
| Review an exact evidence package (requires a valid PASS receipt and its sibling materials) | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --gate-receipt phase2/gate-receipt.json --out out/case-review.json` |
| Squeeze a report into a one-page summary (**redacted by default**) | `fxapk digest out/app.json` |
| Same, but with raw values for the sensitive fields | `fxapk digest out/app.json --no-redact` |
| Android UI screenshots, layouts and fixed actions (optional plugin) | [Setup and plan examples](ANDROID-UI.en.md); `fxapk ui --help` |
| Capture traffic on a device | `fxapk capture <package>` |
| Device health check (**fixes by default**: deploys frida-server / installs CA) | `fxapk doctor` |
| Check only, change nothing | `fxapk doctor --no-fix` |
| Environment self-check (what works / doesn't / how to fix) | `fxapk selfcheck` |
| Batch-enrich a target list (`--dry-run` by default: estimates quota, sends nothing; resumable) | `fxapk enrich batch -t targets.txt -o enrich_out` |
| Ingest a report into the corpus | `fxapk corpus add out/app.json --corpus <dir>` |
| See whether detection improved or regressed across versions | `fxapk corpus regress --corpus <dir>` |
| Have I seen this value before (look it up across samples) | `fxapk corpus seen <value> --corpus <dir>` |
| Find samples built in the same environment | `fxapk corpus shared-build-env --corpus <dir>` |
| Rank explainable technical-link candidates (raw identifiers; review priority, not probability) | `fxapk corpus link-candidates --corpus <dir>` |
| Validate an append-only private label file outside the worktree (aggregate only) | `fxapk corpus link-labels-validate --labels <labels.jsonl>` |
| Evaluate rules-v2 against independent labels (circular labels excluded; aggregate only) | `fxapk corpus link-evaluate --corpus <dir> --labels <labels.jsonl>` |
| Discover recurring anchors inside reviewed groups (raw values omitted by default) | `fxapk corpus link-discover --corpus <dir> --labels <labels.jsonl>` |
| Explain a pair / build anonymous review groups (defaults to `omit`) | `fxapk corpus link-explain <SHA> <SHA> --corpus <dir>` / `fxapk corpus link-groups --corpus <dir>` |
| Check the train/holdout component-split data gate (aggregate only) | `fxapk corpus link-readiness --corpus <dir> --labels <labels.jsonl>` |
| Train an experimental reranker after the gate passes (otherwise `blocked`) | `fxapk corpus link-train --corpus <dir> --labels <labels.jsonl> --model-out <model.json>` |
| Shadow-rerank deterministic candidates without expanding recall or bypassing caps | `fxapk corpus link-candidates --corpus <dir> --model <model.json>` |
| Export leads as CSV | `fxapk export out/app.json` |
| Diff two reports / flatten a report into agent-readable JSONL | `fxapk diff a.json b.json`, `fxapk jsonl out/app.json` |
| Query a built JADX persistent index: where a value is used / whether a static call path exists between two methods (**bounded**; an empty result ≠ unreachable; `resolution` is only `name_unique` / `ambiguous` / `not_in_index` — not method binding) | `fxapk jadx usage <value> --jadx-cache-root <cache> --jadx-index <key>`, `fxapk jadx callpath 'cls#m/0' 'cls#n/1' --jadx-cache-root <cache> --jadx-index <key>` |
| Recognition line (read-only / offline; models can only write `proposed`): project reanalysis requests from the judgment ledger / validate label files / build & validate leak-proof splits / evaluate with an explicit promotion gate (exit 4 when the gate fails — usable as a CI gate) | `fxapk recognize reanalysis <ledger> --out <requests.jsonl>`, `fxapk recognize labels validate …`, `fxapk recognize split build\|validate …`, `fxapk recognize evaluate …` |

Every `corpus` command that reads or writes the sample library needs a library directory: pass
`--corpus <dir>`, or set `FXAPK_CORPUS` beforehand. The library root holds sample data — keep it
outside the code repository.

After upgrading to rules-v2, an older manifest without `repack_identity_verdict` makes
`link-candidates` return `status=partial` plus a structured `migration.next_action`, because the
repack ownership cap cannot be trusted without that projection. Run
`fxapk corpus reindex --corpus <dir>` explicitly to rebuild it from the stored reports; report bytes
are not changed. A present value outside `self_built|repack_suspected|unknown` is also treated as
unassessed. If fields are still missing afterwards, those reports were never assessed and must
be re-analysed with the current fxapk, then re-added/reindexed. Reindex never converts unassessed to
`unknown`. For large connected components, `link-groups` emits the exact
`transitive_only_pair_count` and at most 100 stable preview pairs instead of materializing the full
transitive closure.

The verdict lands in `report.meta.closure`: `complete` means all five layers of the primary target
carry evidence (runtime, resource registration, BGP announcement, hosting / distribution, final
attributed party); `partial` means there's a named gap; `failed` means static analysis itself failed,
or dynamic evidence was required but no business traffic was captured, or there was no target to
close on at all. A target still behind a CDN with no origin located never counts as complete.

### Don't confuse "couldn't see it" with "the tool failed"

`visibility` in the report says whether the **sample's content** was visible; `analysis_status` says
whether the **tooling** ran healthy. Every analyzer succeeding (`analysis_status=complete`) while the
DEX is a stub and six conclusions are off the table — both true at once. `blocked_claims` names the
claims that can't be made yet; `next_actions` says how to close the gap.

### Self-built shell vs. a repackaged legitimate app

`repack_identity` returns `self_built`, `repack_suspected` or `unknown`. Self-built does not mean
every endpoint, domain or build path belongs to the operator: exclude SDKs, packers and shared
infrastructure individually. For suspected repacks, inherited and added assets remain unresolved
until compared with the official build of the same version. Do not assign all assets to either party.

When a sample looks repackaged, the tool states only that it appears **resigned** — never that
something was injected. Establishing that requires a file-by-file diff against the official build of
the same version, which the sample alone cannot provide.

## Output

For `app.apk`, the basename is `app`; web reports use the evidence directory/origin label.

- `out/app.html` — self-contained single file (internal evidence view; review sensitive values before sharing)
- `out/app.json` — full structured data (machine-readable)
- `--fmt pdf` — optional PDF export (needs local Chrome / Edge)

## Capture, enrichment and evidence contracts

CLI `auto` defaults to three observation rounds after unpack/reanalysis: PCAP, general probes,
then supported targeted observers. Use `--single-round` for the older route; programmatic
`auto.run` remains opt-in. Rounds retain separate identity, failures, artifacts and quality.
They do not grant behavior-modification authorization, or allow combining unrelated payload
counts into complete evidence. Default capture/auto still require Frida; explicit
`capture --mode floor-only` needs adb, root and device-side tcpdump.

Passive profiles are explicitly selected as `fofa_profile,fofa_host,daydaymap_profile` in
`enrich batch --stage api --providers ...`. Batch defaults to dry-run; add `--no-dry-run`
only with target disclosure, provider access and budget authorized. FOFA views are one source
family, not independent corroboration. Results are bounded first-page observations; missing
fields, unknown totals and permission failures do not establish absence. Quake and DayDayMap
(including its profile) support `--credential-slot 2`; credentials never rotate automatically.

Use `case package` to freeze report/attachment hashes, then `corpus reconcile` to preview library
changes (explicit `--apply` writes). `case phase2 --help` lists inventory, triage, decision,
materialize and gate commands. The case directory contains direct child package directories;
the manifest determines report names. Keep `coverage.json` and `decisions.jsonl` beside the gate
receipt. `case review` requires that matching PASS receipt. `case prepare-materials` produces
review materials, not a final report or attribution decision.

Package integrity, analysis, closure and review are separate states. Accepted review does not
turn partial closure into complete closure. Preserve historical packages and generate new
materials in a working copy. Legacy scripts and native CLI have different filename assumptions;
see the [pre-report workflow](PRE-REPORT-WORKFLOW.md) and the extended [Chinese reference](USAGE.md).

## Reproducibility

Use the code, rules and `requirements.lock` saved for the intended version, in an isolated
environment. Install the lock first, then the project with `--no-deps`. The report records
`meta.dependency_versions`; current pins do not recreate every historical environment.
Preserve sample hashes, parameters, external tools, caches, raw responses, device state and
capture times. Fixed dependencies alone cannot make online/dynamic reports byte-identical.

## Developing from source

Run this once after cloning to enable the pre-commit sensitive-data scan:

```bash
git config core.hooksPath .githooks
```

The hook scans **staged added lines**. Default blockers include suspected real IPs, credentials, case
names, contact identifiers, secondary package names, unjustified exemptions and bulk exemptions.
Strict mode also blocks domain/context findings. An inline exception needs `leak-scan:` followed by
`allow` and a valid line-specific reason. For committed changes, run
`fxapk leak-scan --base origin/master --strict`; an empty staging area does not validate the branch.
CI checks the PR diff and tracked source/tests independently.

Prefer documentation-reserved ranges for test fixtures (`192.0.2.0/24` / `198.51.100.0/24` /
`203.0.113.0/24` / `2001:db8::/32` / `example.com`). If a predicate cannot be exercised with these,
use mocks or auditable synthetic fixtures with line-specific reasons, never case values. A real
address, once pushed, is **irreversible** —
rewriting history does not remove the platform's cached copies, so the only reliable fix is never
writing it in the first place.

## Compliance

Use only within lawful authorization. Default enrichment queries third-party services and DNS; it does not directly request sample business URLs, but it does not guarantee zero observable traffic. Active collection requires the corresponding explicit authorization flags. Device operations require an authorized test device.

## License

[MIT](LICENSE)

## Explicit transient recovery

Use `fxapk enrich batch --help` to inspect `--recover-transient`, `--provider-interval` (default 2 seconds) and `--retry-delay` (default 15 seconds). First dry-run the bounded batch, including recovery calls; add `--no-dry-run` only within the authorized query scope. Recovery is opt-in: one provider receives at most one additional adapter call in the batch, and each attempt is retained. Server cooldowns and local rate limits still apply; Retry-After over 60 seconds defers recovery, and a failed retry stops that source. Authentication, upstream permissions, paid-credit uncertainty and quota errors do not become automatic retry candidates. A failed Shodan DNS resolution remains scoped to that target. Resume skips existing successful targets without erasing earlier gaps.

FOFA relay upstream permission denial is distinct from relay-key authentication failure. Hunter reads the current account balance and uses durable reservations under a conservative local 500-point daily cap; this is not a guarantee of provider-wide free entitlement or control over another client's spending. Preserve partial results and read per-source receipts instead of treating failures as no records.

Hunter's default `provider_default` mode checks the account's current free balance before searching and reserves credits in a durable local ledger. Unknown balance or a failed reservation stops the search. Reservations for the same account share a conservative 500-point daily cap using UTC+8 dates. The default ledger is `.fxapk/hunter-quota.sqlite3` under the user directory; `FXAPK_HUNTER_QUOTA_DB` must select an absolute path. This does not control other clients or guarantee free entitlement or server-side billing. Explicit `FXAPK_HUNTER_CREDIT_MODE=free_only` still returns `disabled / free_only_billing_unverified` before requests. See [.env.example](.env.example).

## Android UI observation

Core 1.18.1 with independent `fxapk-android-ui 0.1.1` provides `ui capabilities`, `ui snapshot` and `ui run-plan`. Install Android CLI and adb separately. Device commands require an explicit `--serial`; observations/plans also require `--package` and a new `--out` directory.

See the [Android UI guide](ANDROID-UI.en.md) for installation, exact flags, a synthetic plan, permissions, outputs and recovery. Installing the plugin does not automatically attach UI observations to auto/capture CLI commands; round integration currently requires the programmatic API. Screenshots, layouts and diagnostics may contain raw values; digest redaction does not cover these files.
