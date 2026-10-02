<h1 align="center">fxapk</h1>

<p align="center">
  APK forensic analysis CLI<br>
  <sub>Turn samples, traffic and saved web evidence into traceable leads.<br>Preserve sources, coverage and gaps; outputs support review, not automatic attribution.</sub>
</p>

<p align="center"><a href="README.md">中文</a> &nbsp;·&nbsp; <strong>English</strong></p>
<p align="center">
  <a href="#how">How it works</a> &nbsp;·&nbsp; <a href="#start">Quick start</a> &nbsp;·&nbsp;
  <a href="#handoff">Handoff</a> &nbsp;·&nbsp; <a href="#limits">Limits</a> &nbsp;·&nbsp; <a href="#docs">Docs</a>
</p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.17.0">v1.17.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

CLI command and PyPI package: `fxapk`; compatible command alias: `apkscan`. Run from Python or source, directly or through an AI assistant. No exe or GUI is provided.

**1.17.0** adds package-bound Phase-2 review gates, per-round capture records, HTTP/HAR evidence inputs and provider-role review plans. Publishing the code does not migrate historical cases, change devices or query third-party services. See [CHANGELOG.md](CHANGELOG.md).

| Capability | Scope |
| --- | --- |
| **Static extraction** | APK configuration, endpoints, components and packer signals; unavailable capabilities remain explicit |
| **Dynamic evidence** | PCAP, socket attribution and available probes on authorized devices, with separate round records |
| **Infrastructure attribution** | Resource holder, BGP, hosting/CDN and operator roles stay distinct, with per-source receipts |
| **Packaging and review** | Hash-bound reports and attachments, separate Phase-2 coverage, decisions and review status |

<a id="how"></a>

## How it works

```text
APK / saved web evidence       Authorized device capture
             └────────► Structured report ◄────────┘
                              │
                    Sources, coverage and gaps
                              │
                   Immutable Phase-1 package
                              │
              Phase-2 inventory → decisions → gate
                              │
                  Independent review materials
```

Core static analysis needs no JDK or device. Some analyzers and dynamic capabilities require additional tools. `selfcheck` reports available capabilities; `analyzer_status` and `source_status` report what actually ran. Not found does not mean absent, and capture completion does not establish evidence closure.

<a id="start"></a>

## Quick start

Requires **Python 3.11+**. Start with offline static analysis; review the [default behaviors](#limits) before online or device operations.

### 1. Install and check the version

```bash
python -m pip install "fxapk==1.17.0"
fxapk --version
fxapk selfcheck
```

The [v1.17.0 release](https://github.com/s-silt/fxapk/releases/tag/v1.17.0) includes a wheel, source archive and `SHA256SUMS.txt`. Before installing a downloaded wheel, compare `Get-FileHash <file> -Algorithm SHA256` in PowerShell, or run `sha256sum -c SHA256SUMS.txt` on Linux. These files are not a complete offline dependency bundle.

To obtain the released source, clone its tag; use the default master branch for current development:

```bash
git clone --branch v1.17.0 https://github.com/s-silt/fxapk.git
cd fxapk
python -m pip install -e .
```

Configure local service credentials using [.env.example](.env.example); keep them out of reports, shared commands and public repositories. `selfcheck` does not validate every account entitlement; query receipts record actual provider outcomes.

### 2. Analyze and read the digest

```bash
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

An AI assistant can follow [AGENTS.md](AGENTS.md), given a sample path and explicit network/device scope. If the command is not on PATH, use `python -m apkscan.cli` instead of `fxapk`. Use the digest for navigation; verify conclusions against structured reports and original evidence.

### 3. Continue within the authorized scope

| Task | Entry point and requirements |
| --- | --- |
| Saved HTML, JS or HAR | `fxapk analyze-web <directory> --out out`; reads local evidence, with enrichment controlled separately |
| Device inspection | `fxapk doctor --no-fix`; authorize repairs separately |
| PCAP without Frida | `fxapk capture <package> --mode floor-only`; still requires adb, root and device-side tcpdump |
| Multi-round automatic capture | `fxapk auto app.apk --strict-case` on an authorized dedicated device |
| Enrichment and closure | `fxapk case close out/app.json`; requires network and report-write authorization |
| Full command reference | [USAGE.en.md](USAGE.en.md) · `fxapk --help` |

<a id="handoff"></a>

## Evidence packages and handoff

Keep code separate from case materials. Existing handoff `cases/`, `corpus/` and legacy workflow directories can remain in place. `FXAPK_CORPUS` points outside the code worktree. For legacy scripts, set `FXAPK_ROOT` to the active source checkout and `FXAPK_HANDOFF_ROOT` to the handoff root.

`case phase2 ... --case-dir <case-directory>` reads `case-package.json` in direct child package directories and verifies manifest-registered paths and hashes. Legacy scripts that assume `report.json` need the new CLI when the manifest names another file; do not rename historical evidence. Generate new Phase-2 materials in a working copy.

`case review` requires `--gate-receipt` plus matching `coverage.json` and `decisions.jsonl` beside the receipt. `corpus add --package` requires byte-identical report content. See the [handoff workflow](PRE-REPORT-WORKFLOW.md) for details.

| State | Meaning |
| --- | --- |
| `package_integrity` | Manifest, paths and attachment hashes agree |
| `analysis` | Analyzers completed their work |
| `closure` | Runtime, attribution and evidence-request targets satisfy evidence gates |
| `review` | The exact package hash was reviewed |

These states are independent. An accepted review cannot turn partial closure into complete closure; changed materials invalidate previous reviews. `auto --strict-case` exits `0 / 5 / 6` for `complete / partial / failed`.

<a id="limits"></a>

## Defaults and limits

- **`analyze` is online by default.** Domain/IP queries go to third-party enrichment services; recursive and authoritative DNS may observe queries. Default enrichment does not directly fetch sample business URLs, but it does not promise zero observable traffic. Use `--offline`.
- **`doctor` repairs devices by default; `auto` installs and runs samples.** Automatic bypass additionally needs an original baseline, a recommendation and both `--allow-behavior-modification --antidetect java`. Modified-runtime evidence cannot independently close a case. Default capture/auto still require Frida.
- **`digest` provides limited redaction by default.** Sensitive category values and some pattern-shaped PII in lead text are masked. Names, addresses, non-Chinese phone numbers and other free text are not guaranteed to be removed. `--no-redact` restores raw values.

**Review other raw-value outputs separately:** `jsonl`, `diff`, `lead show/restore/replay`, `corpus events/ls/seen/shared-config/shared-native/shared-build-env/link-candidates`, `probe-leads`, `pcap-leads`, CSV, HTML/PDF, generated letters, corpus records, `case_correlation.json` and `report.json`. Internal evidence views are not sanitized publications.

`corpus link-discover/link-explain/link-groups` default to `--evidence-values omit`; explicit `raw` restores original values. `link-labels-validate/link-evaluate/link-readiness/link-train` return aggregates. These separate projections do not broaden the digest guarantee.

Use only within lawful authorization. Shared CDN, ASN, certificates or technical anchors cannot alone establish an operator or common ownership. The source catalog does not prove account access, free quota or available budget. Synthetic regression and cross-platform CI do not establish real-device, provider-account or OneDrive sync-conflict acceptance.

<a id="docs"></a>

## Documentation and development

| Topic | Reference |
| --- | --- |
| Commands, outputs and corpus | [USAGE.en.md](USAGE.en.md) · [Chinese reference](USAGE.md) |
| Agent operations and authorization | [AGENTS.md](AGENTS.md) |
| Capture rounds, Phase 2 and handoff | [PRE-REPORT-WORKFLOW.md](PRE-REPORT-WORKFLOW.md) |
| Architecture and evidence semantics | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Companion tools | [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md) · [tools/TOOLCHAIN.md](tools/TOOLCHAIN.md) |
| Changes | [CHANGELOG.md](CHANGELOG.md) |

Enable `git config core.hooksPath .githooks` before development. For behavior changes, run Ruff, Pyright, pytest and the strict incremental leak scan. Documentation-only changes require format, reference, relevant contract and leak checks; required CI must still pass before merging. Use synthetic fixtures; never commit case values or credentials. License: [MIT](LICENSE).
