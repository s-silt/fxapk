<h1 align="center">fxapk</h1>

<p align="center">
  APK forensic analysis CLI<br>
  <sub>Turns samples, traffic and existing web evidence into leads, preserving sources, coverage and open items.<br>Outputs support review; they do not replace original evidence or human attribution.</sub>
</p>

<p align="center"><a href="README.md">中文</a> &nbsp;·&nbsp; <strong>English</strong></p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.19.0">v1.19.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

Command `fxapk` (alias `apkscan`), PyPI package `fxapk`. For people and AI assistants running the source or the Python package directly; no exe or GUI is provided. See [CHANGELOG.md](CHANGELOG.md) for changes.

| Core capability | Description |
| --- | --- |
| **Static extraction** | Parses configuration, endpoints, components and packer signals in the APK; marks gaps explicitly when a capability is missing |
| **Dynamic evidence** | Collects PCAP, socket attribution and probe data on authorized devices, recorded per round; an optional UI plugin adds screenshots and layouts |
| **Infrastructure attribution** | Records resource holder, BGP, hosting/CDN and operator roles separately, with per-source receipts |
| **Packaging and review** | Hash-pins reports and attachments; Phase-2 coverage, decisions and review status are recorded independently |

```text
APK / saved web evidence        Authorized device capture
          │                            │
          └────► Structured report ◄───┘
                         │
           Sources, coverage, gaps and next steps
                         │
            Immutable Phase-1 evidence package
                         │
        Phase-2 inventory → human decision → gate
```

Static analysis needs no JDK or device; some analyzers and dynamic capabilities need additional tools. `selfcheck` shows current capabilities; `analyzer_status` and `source_status` in the report describe what actually ran. Not found does not mean absent, and a completed capture does not mean evidence closure.

## Quick start

```bash
python -m pip install "fxapk==1.19.0"     # or clone, then python -m pip install -e .
fxapk selfcheck
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

The [release page](https://github.com/s-silt/fxapk/releases/tag/v1.19.0) provides the wheel, source archives and `SHA256SUMS.txt`; verify hashes before installing. Configure online-service credentials locally per [.env.example](.env.example); they are never written into reports or the repository. If the command is not on PATH, use `python -m apkscan.cli` instead of `fxapk`.

`digest` is for triage and navigation; formal conclusions must go back to the structured fields and original evidence in `report.json`. When delegating to an AI assistant, give it [AGENTS.md](AGENTS.md), the sample path, and whether network and device operations are in scope.

| Task | Entry point |
| --- | --- |
| Saved web pages, JS or HAR | `fxapk analyze-web <directory> --out out` |
| Web supplement | Add `--web-supplement <local JSON>` to the first analysis; for an existing report use `fxapk supplement-web <report.json> --web-supplement <config> --out <new-out-dir>` (does not re-run the APK, does not touch devices) |
| Device troubleshooting | `fxapk doctor --no-fix`, then repair per authorization |
| PCAP floor without Frida | `fxapk capture <package> --mode floor-only` (still needs adb, root and device-side tcpdump) |
| Multi-round automatic capture | `fxapk auto app.apk --strict-case` (authorized dedicated devices only) |
| Android UI screenshots and action plans | Optional plugin `fxapk ui ...`, see [ANDROID-UI.en.md](ANDROID-UI.en.md) |
| Follow-up queries and closure on an existing report | `fxapk case close out/app.json` (requires network and write-back authorization) |
| Full command reference | [USAGE.en.md](USAGE.en.md) · `fxapk --help` |

### Optional REA plugin (web observation / native address recovery)

Disabled by default: even when installed it is not imported, registers no commands, and is not used for automatic supplement. Only when explicitly needed, set `FXAPK_ENABLE_REA=1` for that process (PowerShell `$env:FXAPK_ENABLE_REA='1'`). Enabling it does not authorize browser, device or network operations. `import` / `inspect` / `trace` only collect; `attach` only mounts verified observations into a new directory; they do not close cases automatically and do not promote observations into leads or runtime. Real Android WebView has not been device-verified. Commands, limits and boundaries: [plugins/fxapk-rea/README.md](plugins/fxapk-rea/README.md).

## Evidence packages and Phase-2 review

The code repository and case materials are kept separate: evidence packages, the corpus and historical materials live outside the worktree, and `FXAPK_CORPUS` points explicitly at the corpus directory. `case phase2 ... --case-dir <case-directory>` verifies a package by manifest-registered paths and hashes; `case review` requires `--gate-receipt`, and matching `coverage.json` and `decisions.jsonl` must sit beside it. On upgrade, preserve originals and generate new Phase-2 materials in a working copy. See [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md) for details.

| State | What it answers |
| --- | --- |
| `package_integrity` | Whether manifest, paths and attachment hashes agree |
| `analysis` | Whether analyzers ran completely |
| `closure` | Whether runtime, attribution and evidence-request targets pass the evidence gates |
| `review` | Whether the exact package hash was accepted on review |

The four states do not imply each other. `review=accepted` does not turn `closure=partial` into complete. `auto --strict-case` exits `0 / 5 / 6` for `complete / partial / failed`.

## Defaults and limits

- **`analyze` is online by default.** Domain/IP values go to third-party enrichment services and DNS queries may be observed; it does not proactively fetch sample business URLs but does not promise zero traffic. For offline use `--offline`.
- **`doctor` repairs devices by default; `auto` installs and runs the sample.** The unpack-and-repackage bypass additionally needs an original baseline, a tool recommendation, and the `--allow-behavior-modification --antidetect java` double gate; behavior-modification evidence cannot close a case alone.
- **`digest` applies limited redaction by default.** Sensitive category values and fixed-pattern privacy fields in lead free text are masked; names, addresses, overseas numbers and other free text are not guaranteed to be removed. `--no-redact` restores raw values.

Other outputs emit sensitive values as-is and need separate review: `jsonl`, `diff`, `lead show/restore/replay`, `corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`, `probe-leads`, `pcap-leads`, CSV, HTML/PDF, generated documents, corpus records, `case_correlation.json` and `report.json`. `corpus link-discover/link-explain/link-groups` default to `--evidence-values omit`; explicit `raw` restores original values; `link-labels-validate/link-evaluate/link-readiness/link-train` output aggregates only.

Collect and analyze only within lawful authorization. Shared CDN, ASN, certificates or technical anchors alone cannot prove an operator or common ownership. This version has synthetic regression and cross-platform CI; it does not claim real-device or all third-party account acceptance.

## Development

Before developing from source run `git config core.hooksPath .githooks`. For code behavior changes run Ruff, Pyright, pytest and the strict incremental leak scan; fixtures use synthetic data, and case values or credentials must never enter the repository. See [USAGE.en.md](USAGE.en.md#developing-from-source), [ARCHITECTURE.md](ARCHITECTURE.md), [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md).

License: [MIT](LICENSE).
