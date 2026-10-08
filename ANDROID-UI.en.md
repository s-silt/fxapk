# Android UI observation and fixed actions

[Project overview](README.en.md) · [Command reference](USAGE.en.md) · [中文](ANDROID-UI.md)

This guide covers core `fxapk 1.18.1` and optional `fxapk-android-ui 0.1.1`. The plugin saves screenshots and layouts using Google's Android CLI and performs bounded fixed actions through adb. UI observations complement PCAP, probes and static evidence; successful screenshots do not establish business connections, operator attribution or case closure.

## Installation and prerequisites

Use Python 3.11+ and install the core and plugin in the same Python environment. The core bundles neither the plugin nor Android CLI. Standalone UI commands need no Frida. PCAP `floor-only` still needs adb, device root and device-side tcpdump; default capture/auto still require Frida.

Obtain Android CLI for your platform from the [official download page](https://developer.android.com/tools/agents) and follow its [installation instructions](https://developer.android.com/tools/agents/android-cli), including SDK and platform requirements. Put the `android` executable on PATH; the legacy SDK tool with the same name is not this CLI. Consult the official page for platform support. Checked on 2026-10-08, it lists limitations for Windows emulator commands and PowerShell downloads. fxapk does not mirror or bundle the third-party binary.

Download the release files and verify `SHA256SUMS.txt` before installing the independent plugin wheel:

```bash
python -m pip install "fxapk==1.18.1"
python -m pip install ./fxapk_android_ui-0.1.1-py3-none-any.whl
fxapk --version
fxapk ui --help
```

Alternatively, install from the root of the matching source checkout:

```bash
python -m pip install .
python -m pip install ./plugins/fxapk-android-ui
```

These commands may download declared dependencies; the wheels are not complete offline dependency bundles. Plugin and core versions are independent. Installing only the core does not provide `ui`. Plugins load through the `fxapk.plugins` entry point and run in the host Python process; install trusted packages only.

Use a device authorized for this operation, with USB debugging enabled and the host accepted by adb. The target App must already be installed. Check its serial with `adb devices -l` and use the same identity in every command and plan. `TEST_SERIAL` and `com.example.synthetic` are synthetic placeholders, not real targets.

## Check the CLI and save an observation

Inspect the flags before checking the external tool version:

```bash
fxapk ui capabilities --help
fxapk ui snapshot --help
fxapk ui run-plan --help
fxapk ui capabilities --serial TEST_SERIAL
```

`capabilities` checks the local Android CLI path and `--version`. It does not verify device connectivity, permissions or successful screenshot/layout support on that device. `capabilities` and `snapshot` accept `--android <executable-path>`; `run-plan` finds the executable on PATH and has no such option. The plugin supplies Android CLI's `--no-metrics`; this does not control App traffic or other tools.

`snapshot` does not launch the App. Bring the authorized target to the foreground first:

```bash
fxapk ui snapshot --serial TEST_SERIAL --package com.example.synthetic --out evidence/ui-001
fxapk ui snapshot --serial TEST_SERIAL --package com.example.synthetic --annotate --full --no-idle --out evidence/ui-002
```

Use an output directory that **does not exist yet**. Existing empty directories, files and symlinks are also rejected to preserve prior materials. `--annotate` saves an annotated screenshot; `--full` requests the full layout. `--no-idle` disables layout's idle wait for cases such as continuous animation; foreground checks remain active. See the official [screen capture](https://developer.android.com/tools/agents/android-cli/commands/screen_capture) and [layout](https://developer.android.com/tools/agents/android-cli/commands/layout) interfaces.

## Run a reviewable plan

Copy the repository's [synthetic plan](examples/ui-plan.example.json) to `inputs/ui-plan.json` in your analysis directory. Replace its `serial` and `package` together with the command arguments using the authorized target. The example launches the target, waits for confirmed foreground identity, then saves one observation:

```bash
fxapk ui run-plan --serial TEST_SERIAL --package com.example.synthetic --plan inputs/ui-plan.json --out evidence/ui-plan-001
```

The schema is `ui-plan/1`. Device and package must exactly match the command. `max_steps` is 1–32 and `max_duration_sec` is 1–300 seconds. The actions array must be nonempty; exceeding a step or time budget stops the plan and retains partial results. Every action is validated before the first device operation.

| Action `kind` | Fields and limits |
| --- | --- |
| `launch` | Launch the selected package; does not install or replace an APK |
| `wait_for_foreground` | Optional `timeout_sec`, default 5 seconds; wait at most 30 seconds |
| `snapshot` | Optional boolean `no_idle`; save screenshot, layout and receipt |
| `tap` | Integer `x` and `y`, each 0–20000; check foreground before and after |
| `input_text` | `value`: 1–256 printable ASCII characters, excluding literal `%s`; check foreground before and after |
| `back` | Fixed back action with foreground checks before and after |
| `wait` | `seconds`; at most 30 seconds per step, bounded by the shared deadline |

Arbitrary shell commands, scripts and dynamic code are not actions. If injection is denied, inspect `injection_permission_denied` in the receipt; adb can report a zero exit code while the action fails. Add `--root-actions` with a **new output directory** only when root tap/text/back on this device are authorized. It never escalates automatically and does not guarantee injection permission.

## Outputs, failures and recovery

| Output | Contents |
| --- | --- |
| `observation.json` | `ui-observation/1`; device, requested and observed foreground packages, UTC times, status, operation reasons, file sizes and SHA-256 |
| `screen.png` or `screen.annotated.png` | Successfully obtained screenshot |
| `layout.json` | Successfully obtained layout |
| `operations.json` | `ui-plan-result/1`; device, package, original plan-byte hash, root choice, start/end times and each step's result |
| `snapshot-N/` | Observation materials for plan step N |
| `.diagnostics/` | Bounded tool output; up to 64 KiB per stream, with full-output hash, truncation and output format |

An observation is `complete` only when both artifacts are valid and the target foreground is confirmed before and after. Some valid artifacts yield `partial`; none yield `failed`. Unknown foreground, App switches, failed steps or budget exhaustion stop a plan rather than continuing input in another App. Non-`complete` snapshot/run-plan results exit with code 1; read the status and individual reasons together.

For missing tools, check PATH and capabilities. For foreground mismatches, check the target and permission dialogs. For timeouts or missing layouts, inspect receipts and controlled diagnostics; retry with `--no-idle` when appropriate and authorized. Preserve the previous output and use a new directory for the next attempt. Do not combine separate partial attempts into one success. UTF-8 normalized diagnostics are identified by `output_format`, not represented as untouched original pipe bytes.

## Capture rounds and Phase 2

Installing the plugin enables standalone `fxapk ui ...` commands. The current auto/capture CLI has no UI switch and does not automatically execute a plan. Programmatic `apkscan.dynamic.auto.run` integrates round observations only with an explicit `android_ui_plugin` and `three_rounds=True`. A pinned device serial and target package are also required; otherwise observation is skipped. `CaptureRoundContext` binds sample SHA, round, runtime variant, output directory and shared deadline. UI observations do not extend the capture budget.

Keep UI and PCAP/probe artifacts, timestamps and provenance separately and verify them using the [pre-report workflow](PRE-REPORT-WORKFLOW.md). UI does not replace Survey's package/sample/capture bindings or resolve missing connection and bidirectional-payload evidence.

Screenshots, layouts, diagnostics and action results may contain personal information or credentials. They are controlled evidence; digest's limited redaction does not cover them. Review before external sharing. Synthetic tests and CI do not establish real-device acceptance for every Android CLI platform, permission dialog, App switch or short connection.
