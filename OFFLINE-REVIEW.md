# Offline evidence review and fxfetch intake

These commands operate on explicitly supplied local evidence. They do not acquire URLs,
launch apps, install collectors, modify samples, or upgrade evidence closure.
Output directories must be new. Existing reports are copied into a new revision.

For explicit device DEX/JNI acquisition followed by reanalysis, target-method checks
and native execution, see [the executable recovery pipeline](RECOVERY-PIPELINE.md).
`evidence-review` also supports `dex`, `jni`, `emulate`, `recover` and `acquisition`
tasks. Native execution and DEX parsing use owned, bounded worker processes.

## Intake from fxfetch

Save the task evidence ZIP from an authorized fxfetch acquisition, then run:

```powershell
fxapk intake-fetch task-evidence.zip --fxfetch <trusted-fxfetch-executable> --out intake-001
```

The adapter calls the installed **fxfetch CLI**, without importing its Python internals.
It consumes `fxfetch.analysis-handoff.v1`, including task-evidence v1/v2 archives supported
by that CLI. It validates the copied source hash, preserves the source archive, uses
fxfetch's provenance-aware offline web analysis, and separately analyzes each validated
original APK with `fxapk analyze --offline`. IPA, rejected originals, missing external
package bytes, missing tools, timeouts and incomplete child reports remain explicit.
Certificates remain original archive attachments and are counted; they are not treated
as application content. Generated WebView APKs are not substituted for original packages.

`intake.json` records all stages; `index.html` links the individual reports. Child stdout
and stderr remain local logs. Console progress contains stage states and reason codes,
not evidence contents. CLI process success is checked against report hashes, sample hash,
offline flags and analysis status. Source authenticity and full case closure remain unverified.

`--timeout` is a shared process budget (default 600 seconds, maximum 3600), with process-tree
ownership, a 2 GiB subprocess memory limit and 1 MiB per output stream. At most eight APKs
are analyzed, each at most 512 MiB. Other packages are recorded as not run. The input ZIP
limit is 2 GiB; fxfetch also enforces its own archive and projection budgets. The budget
also bounds targeted review workers; cleanup and report publication can extend wall time.
macOS cannot enforce the requested address-space limit: these bounded stages are
`unsupported / platform_memory_limit_unavailable` without launching a child. An intake
with no usable result is `failed`, including when every stage is unsupported.

By default the fxfetch handoff uses the console entry point belonging to the current
Python interpreter, while original-APK analysis uses that interpreter with `-m apkscan.cli`.
Source-only installations without that console entry point must supply `--fxapk`. An
explicit override is trusted configuration. Offline children set `FXAPK_NO_DEVICE_PROBE=1`
to suppress incidental adb probing and cleanup; the parent environment is unchanged.

To continue directly into a targeted review of one matching APK:

```powershell
fxapk intake-fetch task-evidence.zip --fxfetch <trusted-fxfetch-executable> --out intake-002 --review-manifest review-plan.json
```

The manifest sample hash must match exactly one analyzed APK. The review creates another
report revision and is included in the intake index. Without a manifest, targeted review
is visibly `not_run / explicit_review_manifest_required`.

## Review existing evidence

```powershell
pip install -e ".[review]"
fxapk evidence-review review-plan.json --report existing-report.json --out review-001
```

The optional dependencies are pyelftools, Capstone 5, cryptography and Unicorn 2. Missing dependencies
yield `unsupported`, and later independent tasks continue. The report argument is optional;
without it the command creates a standalone review report. Required per-input SHA-256 checks
bind the exact bytes reviewed; the declared sample hash alone does not verify their provenance.

```json
{
  "schema_version": "fxapk.offline-review.v1",
  "sample_sha256": "<64 lowercase hexadecimal characters>",
  "tasks": [
    {
      "id": "native-info", "kind": "native",
      "input": "libexample.so", "sha256": "<input SHA-256>", "query": "info"
    },
    {
      "id": "buffer", "kind": "trace",
      "input": "trace.jsonl", "sha256": "<input SHA-256>",
      "run_id": "window-1", "address_space": "pid-123-mapping-1",
      "address": "0x1000", "size": 16
    }
  ]
}
```

Paths are relative to the manifest or absolute. Task IDs must be unique, including case,
and may not collide with output filenames. Maximum 32 tasks, 32 MiB per input, 100,000
JSONL events, 64 KiB per event. Invalid, empty, duplicate-key, over-budget and missing
inputs produce explicit failures or coverage gaps; they are never silently skipped.

Outputs are `review.json`, per-task receipts, `report.json`, `digest.json` and `report.html`.
Report/digest/HTML carry the task states and reasons. Raw strings, reconstructed buffers
and filesystem paths stay in the per-task local receipts. The source report is not overwritten. Its existing analysis health is preserved; a
standalone report derives health from the task results. The new revision projects the
latest review only; retain prior review directories and their detailed receipts separately.
Exit codes: 0 all requested work succeeded within its declared scope; 5 partial/unsupported;
6 failed; 2 invalid command/manifest or publication failure. None means case closure.

## Supported tasks

| kind | Inputs and options | Coverage |
|---|---|---|
| `native` | ELF input; `query`: `info`, `map`, `strings`, `symbols`, `jni`, `disasm`, `callers`, `strrefs` | Static file only; dynamic registration and indirect calls unresolved |
| `trace` | Normalized JSONL; run ID, address space, requested address/size | Observed writes only; unknown bytes stay `??` |
| `filesystem` | Normalized JSONL; run ID, backend, clock basis, capture completeness | Supplied event review; device collection not performed |
| `crypto` | Explicit AES hypothesis JSON and separate fit/validation vectors | Supplied vectors only; no key discovery or automatic white-box recovery |

ELF `map` requires `address_kind: file` or `elf_va`; BSS addresses return no file offset.
`strings` requires an ASCII `needle`. Disassembly/call/reference queries support only
little-endian AArch64 and require `address` (ELF VA) and a four-byte-aligned `size` (maximum
4 MiB). `callers`/`strrefs` also require `target` (ELF VA). Callers cover direct `BL` only;
string references are ADR or adjacent ADRP+ADD candidates, not a complete dataflow analysis.
`limit` is 1–1000 (default 200); result/decode gaps are visible. Compressed/extended ELF
tables are explicitly unsupported. No runtime base is inferred.

Trace event example (data is bytes in ascending address order, not a host-endian integer):

```json
{"run_id":"window-1","address_space":"pid-123-mapping-1","seq":1,"op":"write","address":"0x1000","size":4,"data_hex":"01020304"}
```

`op` is `read`, `write`, or `lost` with positive `count`. Sequence starts at 1. Lost,
malformed, out-of-order or foreign-scope records invalidate known memory conservatively.
Missing write data invalidates the written bytes; read conflicts invalidate conflicting
bytes. Writes intersecting the selected range are clipped with a count. Nothing becomes
zero merely because it was not observed. Trace normalization must preserve raw logs and
document the producer/clock/process mapping; this tool does not parse arbitrary text traces.

Filesystem task options include `backend: inotify|fanotify|unknown`,
`timestamp_basis: unix_ns|monotonic_ns`, `run_id`, and `capture_complete: true|false`:

```json
{"run_id":"window-1","seq":1,"timestamp":1000,"op":"create","path":"/data/user/10/example/cache/item","pid":123}
```

Operations: create/modify/delete/move_from/move_to/open/close, or lost with count.
Keep Android user directories unchanged. Inotify events do not establish process identity;
fanotify PID values remain candidates without independent process/UID/time correlation.
Events do not prove file contents. The collector interface and offline review are implemented;
device acquisition is not implemented or accepted by this command. Match the actual backend
and version of an authorized collector such as [fsmon](https://github.com/nowsecure/fsmon),
retain its original output, and document any normalization.

Crypto input is an object with `algorithm: AES-GCM|AES-CBC-PKCS7`, `key_hex`, and 1–32
`vectors`. Each vector supplies `role: fit|validation`, `iv_hex`, `ciphertext_hex`, optional
`aad_hex`, and optional `expected_plaintext_hex`. GCM ciphertext includes its 16-byte tag;
CBC requires block-aligned ciphertext and a 16-byte IV. Hex must be exact, without truncation,
whitespace or odd lengths. Distinct successful fit and validation inputs are required to
confirm the supplied hypothesis. Roles and output provenance remain caller-declared.
GCM also flips a tag bit and checks rejection. CBC padding success is unauthenticated and
remains partial. Keys/plaintext never appear in output; byte comparisons and hashes do.
Authentication follows the library's [AEAD API](https://cryptography.io/en/latest/hazmat/primitives/aead/). <!-- leak-scan: allow official cryptography API documentation, not case infrastructure. -->

These tools were inspired by useful workflows in MobileRE-Skill, but are independent
implementations. They do not execute upstream scripts or assume their runtime/API compatibility.
