<h1 align="center">fxapk</h1>

<p align="center">
  APK forensic analysis CLI<br>
  <sub>Turns samples, traffic and existing web evidence into leads, preserving sources, coverage and open items.<br>Outputs support review; they do not replace original evidence or human attribution.</sub>
</p>

<p align="center"><a href="README.md">中文</a> &nbsp;·&nbsp; <strong>English</strong></p>
<p align="center">
  <a href="https://github.com/s-silt/fxapk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/s-silt/fxapk/releases/tag/v1.25.0">v1.25.0</a> &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; <a href="LICENSE">MIT</a>
</p>

`fxapk` (alias `apkscan`) extracts leads from APKs, authorized device traffic and saved web evidence, recording sources, attribution and coverage gaps. It is a Python CLI; no exe or GUI is provided.

## Quick start

```bash
python -m pip install "fxapk==1.25.0"
fxapk selfcheck
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

Static analysis needs no device. Download artifacts and checksums from the [release](https://github.com/s-silt/fxapk/releases/tag/v1.25.0); see [USAGE.en.md](USAGE.en.md) for source installation, credentials and optional tools.

## Common tasks

| Task | Command |
| --- | --- |
| Analyze saved web evidence | `fxapk analyze-web <directory> --out out` |
| Ingest a saved fxfetch task | `fxapk intake-fetch <ZIP> --fxfetch <trusted-local-CLI> --out <new-directory>` |
| Review targeted offline evidence | `fxapk evidence-review <manifest> --out <new-directory>` |
| Archive and verify original bytes | `fxapk evidence pack <directory> --out evidence.zip` · `fxapk evidence verify evidence.zip` |
| Inspect device setup | `fxapk doctor --no-fix` |

`analyze` is online by default; `doctor` repairs devices and `auto` installs and runs samples, requiring corresponding authorization. `digest` provides limited redaction; reports and archives may contain raw values. See [privacy boundaries](USAGE.en.md#privacy-and-output). Check original evidence before drawing conclusions. Storage integrity, analysis completion, case closure and human acceptance are independent states.

## Documentation

- [Commands and flags](USAGE.en.md) · [Agent guide](AGENTS.md) · [Toolchain setup](tools/TOOLCHAIN.en.md)
- [Evidence archives](EVIDENCE-ARCHIVE.md) · [Offline review](OFFLINE-REVIEW.md) · [Targeted recovery](RECOVERY-PIPELINE.md) · [Pre-report workflow](PRE-REPORT-WORKFLOW.md)
- [Optional plugins and companion tools](COMPANION-TOOLS.en.md) · [Architecture](ARCHITECTURE.md) · [Changelog](CHANGELOG.md)
