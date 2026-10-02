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
| Analyse saved web files | `fxapk analyze-web <dir> --out out` |
| Run a whole folder | `fxapk batch <dir>` |
| Full pipeline: doctor → static → unpack → capture → merge (dynamic steps only with a rooted device; without one they're skipped and you still get the static report) | `fxapk auto app.apk --out out` |
| Same, as an acceptance gate (exit 0/5/6 = complete/partial/failed) | `fxapk auto app.apk --out out --strict-case` |
| Top up an existing report with multi-source lookups and five-layer attribution | `fxapk case close out/app.json` |
| Review an exact evidence package (requires a valid PASS receipt and its sibling materials) | `fxapk case review out/case-package.json --reviewer reviewer --status accepted --gate-receipt phase2/gate-receipt.json --out out/case-review.json` |
| Squeeze a report into a one-page summary (**redacted by default**) | `fxapk digest out/app.json` |
| Same, but with raw values for the sensitive fields | `fxapk digest out/app.json --no-redact` |
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

`repack_identity` returns a three-state verdict, and it needs reading first: interface, domain and
build-path **ownership inverts** between the two. A self-built app's belong to its operator; a
repackaged one's belong to the **impersonated vendor**, so listing them as investigation leads points
at an uninvolved company.

When a sample looks repackaged, the tool states only that it appears **resigned** — never that
something was injected. Establishing that requires a file-by-file diff against the official build of
the same version, which the sample alone cannot provide.

## Output

- `out/report.html` — self-contained single file (internal evidence view; review sensitive values before sharing)
- `out/report.json` — full structured data (machine-readable)
- `--fmt pdf` — optional PDF export (needs local Chrome / Edge)

## Developing from source

Run this once after cloning to enable the pre-commit sensitive-data scan:

```bash
git config core.hooksPath .githooks
```

It looks only at **staged added lines**. Three classes block the commit by default: suspected real
addresses, suspected credentials, and un-justified exemptions; domains and context words are reported
but do not block (`FXAPK_LEAK_SCAN_STRICT=1` blocks those too). To allow a single line you must state
why — add `leak-scan:` followed by `allow` and a line-specific reason inline. CI scans the PR diff again, so `--no-verify` does not get
past the final gate.

Test fixtures must use documentation-reserved ranges (`192.0.2.0/24` / `198.51.100.0/24` /
`203.0.113.0/24` / `2001:db8::/32` / `example.com`). A real address, once pushed, is **irreversible** —
rewriting history does not remove the platform's cached copies, so the only reliable fix is never
writing it in the first place.

## Compliance

Use only within lawful authorization. Default enrichment queries third-party services and DNS; it does not directly request sample business URLs, but it does not guarantee zero observable traffic. Active collection requires the corresponding explicit authorization flags. Device operations require an authorized test device.

## License

[MIT](LICENSE)
