# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI command `fxapk` (alias `apkscan`) · PyPI package `fxapk`* · **中文**: [README.md](README.md)

An APK / iOS IPA **static + dynamic analysis CLI**: extracts real app config (AppID / AppKey / channel IDs / uni-app app ID, etc.), network endpoints, third-party components and packer fingerprints; traces the **encrypted remote-config chain** (finds OSS / CDN config objects, multi-layer decodes / decrypts the dynamic backend domain / IP pool inside, assembles a single control chain, and — for obfuscated samples where the standard crypto API can't be recognized — surfaces **decrypt leads** carrying the full ciphertext for manual / AI recovery); attributes domains / IPs with a **five-layer, non-collapsing infrastructure model** (resource holder → BGP ASN → cloud / IDC → CDN / edge proxy → operator — each layer carries its source and confidence, and is marked unknown when not found); captures traffic **PCAP-first** (TLS / QUIC handshake parsing + five-tuple socket attribution); and outputs a **structured HTML / JSON report**.

Runs its core analysis with **zero environment** (`pip install`, no JDK / emulator / device). Unpacking and traffic capture of hardened apps are optional on-device steps.

## Install

Requires **Python 3.11+**.

```bash
pip install fxapk

# Or from source
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

Dynamic unpack / capture, the sample corpus and other features need optional deps installed on demand; when missing, the relevant command prints a hint and core analysis is unaffected.

## Usage

```bash
# Static analysis, HTML + JSON into out/
fxapk analyze app.apk --out out

# One-click full pipeline (rooted device / emulator attached):
#   doctor → static → unpack → capture → merge into one report
fxapk auto app.apk --out out       # no device? dynamic steps are skipped, static report still produced
```

Main commands: `analyze` (static), `auto` (one-click: static + dynamic when a device is present), `capture` (on-device capture), `doctor` (device env check + auto-fix), `corpus` (sample library: ingest past reports, cross-version regression, look up a value across samples). Full commands and flags: `fxapk --help`.

When not installed as a command, use `python -m apkscan.cli <…>`.

## Output

- `out/report.html` — self-contained single file (share directly / open on phone)
- `out/report.json` — full structured data (machine-readable)
- `--fmt pdf` — optional PDF export (needs local Chrome / Edge)

![fxapk report example](docs/images/report-demo.png)

## Compliance

For **authorized security research / analysis** only. It performs static / dynamic analysis and information extraction, and provides **no attack / exploitation / active-probing capability against any third party**. **Passive by default**: overseas servers are only passively attributed (RDAP / WHOIS / DNS / ASN / certificate transparency), with zero active traffic to the target; the few capabilities that do reach the target (e.g. retrieving a config object the sample itself references) are off by default and only enabled under an explicit `--mode authorized-active`. Unpacking observes the **sample itself** on your own authorized analysis machine. Use only within lawful authorization.

## License

[MIT](LICENSE)
