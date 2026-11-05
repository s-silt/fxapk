# Runtime recovery and verification

`fxapk recover-runtime PLAN.json --out NEW_DIRECTORY` connects a selected device
observation to recovered DEX, offline reanalysis, JADX checks, JNI receipts,
explicit native function execution and report/digest/HTML output. It never
installs or starts an app, starts Frida, changes proxy settings, or modifies a
target function. Prepare an authorized observation window first.

The original APK and every supplied offline input require SHA-256. Output must
be a new directory. A matching declared hash is not proof that runtime bytes
originated from that APK: `source_binding_verified` remains false. Check PID,
process start time, installed APK and the original capture window separately.

```json
{
  "schema_version": "fxapk.runtime-recovery.v1",
  "apk": "original.apk",
  "sample_sha256": "<64 lowercase hex characters>",
  "capture": {
    "backend": "frida",
    "serial": "<explicit device serial>",
    "pid": 12345,
    "process_name": "example.authorized.app",
    "ranges": [{"address": "0x7000000000", "size": 4096}],
    "seconds": 15,
    "jni": true,
    "modules": ["libexample.so"]
  },
  "targets": ["Lexample/Decoder;->decode([B)[B"],
  "tasks": []
}
```

Select actual page-aligned readable ranges from this PID. Alternatively use
`map_name_contains` with a specific mapped filename instead of `ranges`.
At most 32 ranges / 32 MiB total / 8 MiB per range are read. This is targeted
collection, not a claim that all process memory or all DEX was recovered.

`backend: "proc_mem"` uses root `/proc/PID/mem` reads without ptrace, process
freezing or code injection. It does not observe JNI. `backend: "frida"` uses
Frida's current pointer/module APIs, bounded DEX scans, RegisterNatives and
selected exported JNI function observations. No bypass modules are enabled.
Already completed registrations cannot be reconstructed from an empty window.
Raw argument/return pointer observations are not decoded Java values.

The CLI saves original dump bytes and records duplicate locations by hash;
it never repairs checksums in place. Each DEX gets fixed-table/header checks,
an Androguard parse, exact class/name/descriptor target lookup and instruction
coverage, plus a real serial JADX subprocess. The recovered files also pass
through `analyze --offline --extra-dex`. DEX and JADX worker processes have
time, memory and output limits and owned-tree cleanup. Valid headers, decoded
methods and decompiled source remain separate from semantic completeness. Reanalysis
uses the current Python interpreter and disables incidental device probing. It must
report every unique captured DEX as requested and loaded with zero failures; counts
and top-level analysis health are carried into the recovery receipt.

These memory-bounded stages run on Windows and Linux. macOS reports
`unsupported / platform_memory_limit_unavailable` before launching them. Linux uses
RLIMIT_AS (virtual address space, not total tree RSS); a JVM that cannot initialize
inside the budget remains a visible JADX gap. Linux nested owned sessions inherit
cleanup markers; adversarial environment clearing plus session escape is outside
this mechanism. Windows uses a Job Object. An unreadable same-UID process is ignored only when it predates
the invocation; otherwise termination stays unverified while known descendants
are still cleaned up. Prepare an existing adb server before
a recovery run: a server started inside a bounded worker belongs to that worker
and may be terminated during cleanup. Real-device Frida/proc_mem acceptance remains
unverified; synthetic regressions do not establish that acceptance.

## Offline tasks and fxfetch

The same task objects run through `fxapk evidence-review` and
`fxapk intake-fetch saved-task.zip --review-manifest PLAN.json --out NEW_DIRECTORY`.
The latter selects the original APK by hash and never revisits the source URL.
For runtime follow-up, use the verified original APK retained in the intake
directory as `apk` above. Runtime observation is always an explicit command.

In addition to `native`, `trace`, `filesystem` and `crypto`, supported task kinds:

| Kind | Input and options | Actual result |
|---|---|---|
| `dex` | DEX bytes; `targets`, `jadx: true` | Header/parser/target-body/JADX receipts |
| `jni` | Observer JSONL; `run_id` | Installed hooks, registrations, calls, gaps |
| `emulate` | AArch64 bytes; format, entry, vectors | Actual Unicorn execution and output comparisons |
| `recover` | ELF; `functions` with address/size/object_argument | Call-based name candidates and offset/width field candidates |
| `acquisition` | Recovery stage receipt | Upstream capture/reanalysis failures in final reports |

Every task needs `id`, `kind`, `input`, `sha256`. Paths resolve relative to the
manifest. Optional `depends_on` references earlier task IDs; a predecessor
other than `ok` produces `not_run/dependency_not_verified`, while independent
tasks continue. `feedback.json` classifies dependency, budget, coverage and
verification gaps with input/manifest/receipt hashes for reproduction. It
does not change methods, skills or global memory automatically.

Example function task (`add.bin`: `0000018bc0035fd6`, add x0,x0,x1; ret):

```json
{
  "id": "function_check", "kind": "emulate",
  "input": "add.bin", "sha256": "<hash of exact code bytes>",
  "format": "raw_aarch64", "base": "0x100000", "entry": 0,
  "instruction_limit": 100000, "timeout_ms": 1000,
  "vectors": [
    {"args": [3, 4], "expected_return": 7},
    {"args": [9, 5], "expected_return": 14}
  ]
}
```

`format: "elf"` maps AArch64 little-endian PT_LOAD segments with permissions;
entry is an ELF virtual address and `base` is the load bias. Dynamic-linker/TLS
segments are explicitly unsupported. Raw mode requires explicit function bytes
and entry offset. AAPCS64 x0–x7 arguments support integers or bounded buffers:
`{"hex":"00","size":1,"expected_hex":"07"}`. SP/LR and a return sentinel
are initialized. Missing memory/imports, system instructions, budget exhaustion
and output mismatch fail; no unknown call returns zero automatically. Explicit
constant-return `stubs` need address/return_value/reason and limit the result to
partial. Two distinct inputs are required for an `ok` comparison. Emulation of
the original code is never labeled an independently implemented algorithm.

`recover` function windows are explicit, up to 32 × 16 KiB. Field provenance is
limited to linear AArch64 register aliases and is cleared at control-flow
boundaries. Cross-function object identity is a supplied hypothesis, not an
inferred fact. Inferred integer types, names and observed minimum extent do not
recover original source names, final structure size, padding or all fields.

## Visible completion

Progress events are JSON on stderr. Exit 0 means requested checks passed;
5 means partial; 6 means failed; 2 means preflight/publication error. The current
recovery chain always leaves source binding unverified, so a usable capture remains
at most partial (exit 5); exit 0 is not a reachable claim of full runtime recovery.
A failed or unsupported capture without any independent useful result exits 6.
Inspect `recovery.json`, `reviewed/review.json`, per-task receipts,
`reviewed/feedback.json`, `reviewed/report.json`, `reviewed/digest.json` and
`reviewed/report.html`. A successful downstream task cannot erase a failed
capture, zero JNI hits, dependency skip, timeout or unknown sample association.
These artifacts support the existing case evidence/release workflow; they do
not automatically close an investigation or publish a formal PDF/XLSX.

The older `unpack` command also reports an error when its requested reanalysis
fails while preserving the recovered files; it no longer returns `done` solely
because a dump exists.

API references: [Frida JavaScript API](https://frida.re/docs/javascript-api/)
and [Unicorn programming tutorial](https://www.unicorn-engine.org/docs/tutorial.html). <!-- leak-scan: allow official Unicorn API documentation, not case infrastructure. -->
