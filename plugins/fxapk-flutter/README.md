# fxapk-flutter

Offline Flutter AOT analysis with a prepared Blutter executable. Installed as an
optional `fxapk.plugins` distribution; core analysis remains usable without it.
The implementation analyzes Android ARM64 `libapp.so`, using the same APK's
`libflutter.so` to identify Dart. It does not execute the APK, contact its servers,
inject the generated Frida template, or claim full Dart source recovery.

## Local installation and toolchain

```powershell
python -m pip install -e ./plugins/fxapk-flutter
fxapk flutter capabilities --apk sample.apk
```

Configuration comes from `--toolchain` / `--flutter-toolchain`, then
`FXAPK_FLUTTER_TOOLCHAIN`, then `~/.fxapk/flutter/toolchain.json`. Example structure:

```json
{
  "schema_version": "fxapk-flutter-toolchain/1",
  "docker": "docker",
  "cache_dir": "<absolute local cache directory>",
  "entries": [{
    "dart_version": "<exact Dart version>",
    "snapshot": "<32 hex snapshot identifier>",
    "abi": "android_arm64",
    "compressed_pointers": true,
    "snapshot_flags": ["<exact sorted flags from the snapshot>"],
    "binary": "<absolute path to prepared Linux Blutter executable>",
    "binary_sha256": "<executable SHA-256>",
    "image_id": "sha256:<prepared Docker image ID>",
    "blutter_revision": "<source revision used for this executable>"
  }]
}
```

Prepare dependencies separately. Match snapshot, ABI, version and all recorded
flags; record the Blutter revision, executable digest and Docker image ID. The
runtime image needs Python 3 and the executable's shared libraries. For the locally
accepted Dart 3.10.9 build this is Debian trixie with ICU and Capstone. Build on the
container's own filesystem, then export the executable. No analysis command pulls
images, fetches source, installs packages or automatically recompiles.

The backend mounts inputs and executable read-only, disables network and runs
without additional Linux capabilities, with 2 CPUs, 6 GiB memory, a 64-process
limit, per-file/aggregate artifact limits and a configurable timeout. Only the
uniquely named task container is removed. A per-cache lock enforces one analysis
at a time; a stale lock after abrupt host termination must be investigated before
manual removal. Do not remove a lock belonging to an active job.

## Usage

```text
fxapk analyze sample.apk --offline --flutter auto --out analysis
fxapk analyze sample.apk --offline --flutter required --out analysis-required
fxapk flutter analyze sample.apk --out flutter-result
fxapk flutter query flutter-result --symbol UploadService.uploadContacts
fxapk flutter query flutter-result --text contacts
fxapk flutter attach flutter-result --report analysis/sample.json --out new-revision
```

`auto` runs the prepared backend for identified Flutter APKs. Missing/incompatible
tools leave explicit coverage errors while other analyzers continue. `off` skips
deep analysis. `required` returns a nonzero exit after preserving the report if
Flutter analysis did not succeed. `--flutter-timeout` controls the per-analysis container
deadline; standalone `analyze` uses `--timeout`. `--no-cache` forces a fresh run.

Every standalone output directory must be new. The content cache keys include
both library digests, exact compatibility, toolchain identity, plugin and index
versions. Cache hits validate every artifact and rebind the result to the current
APK. Invalid cache entries are retained under an `invalid-*` name and recomputed.

## Evidence and limitations

The bundle contains exact library copies, Blutter assembly/object dumps, SQLite
function/call/string indexes, an execution receipt and a hashed file manifest.
Every direct ARM64 `BL` edge is checked against the original ELF instruction,
using ELF segment address translation; mismatches remain explicitly unverified.
Indirect/virtual calls are counted as coverage gaps. Function indexing includes
abstract classes, static methods and constructors. Symbol availability depends
on the input; zero matches never proves absence of behavior.

Queries return exact local strings and are not redacted. Routine command summaries
contain only counts and states. Keep bundles and query output in controlled local
case storage. Generated Frida scripts are retained as unexecuted artifacts.

URLs are only extracted as literal candidates, with function/instruction/source
references. No base/path concatenation or upload-destination claim is inferred
from adjacent strings. Framework URLs still pass through existing fxapk noise
and enrichment admission rules. `derived-native`, `runtime_observed=false` and
unknown reachability prevent these records from becoming actual transmission
proof. Build-path candidates are distinguished from Dart package namespaces and
dependency paths. The manifest's `ok` means the bounded tool/index run finished,
not that every function or business path was recovered.

`attach` requires an exact `meta.sample_sha256` match, writes a new report and
copies the bundle. Original report bytes are retained; existing report fields,
lead grades and closure remain unchanged. Older attachments remain at the explicit
`source_report.source_artifact_base`; package builders must include the new bundle
and resolve any prior attachment references when creating a self-contained package.
Hashes establish byte consistency, not artifact authenticity or actual App behavior.

Output and cache directories must be disjoint from each other and from the bundle; overlapping paths are rejected before any write. A missing or invalid toolchain configuration fails before the output directory is created, so no failure.json is produced in that case. Pipeline invocations bind the parser's APK snapshot hash before and after the backend run.

Upstream: https://github.com/worawit/blutter (MIT). This plugin is an adapter; the
upstream executable and Dart sources are kept in the local toolchain, not vendored
with case material into fxapk. First locally accepted combination: Android ARM64,
Dart 3.10.9 with the tested snapshot/flags. Other combinations require a separate
prepared entry and real-sample acceptance.
