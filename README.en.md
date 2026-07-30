# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI command `fxapk` (alias `apkscan`) · PyPI package `fxapk`* · **中文**: [README.md](README.md)

An APK **static + dynamic analysis CLI**: extracts real app config (AppID / AppKey / channel IDs / uni-app app ID, etc.), network endpoints, third-party components and packer fingerprints; traces the **encrypted remote-config chain** (finds OSS / CDN config objects, multi-layer decodes / decrypts the dynamic backend domain / IP pool inside, assembles a single control chain, and — for obfuscated samples where the standard crypto API can't be recognized — surfaces **decrypt leads** carrying the full ciphertext for manual / AI recovery); attributes domains / IPs with a **five-layer, non-collapsing infrastructure model** (resource holder → BGP ASN → cloud / IDC → CDN / edge proxy → operator — each layer carries its source and confidence, and is marked unknown when not found); captures traffic **PCAP-first** (TLS / QUIC handshake parsing + five-tuple socket attribution); and outputs a **structured HTML / JSON report**.

Runs its core analysis with **zero environment** (`pip install`, no JDK / emulator / device). Unpacking and traffic capture of hardened apps are optional on-device steps.

## Install

Requires **Python 3.11+**.

```bash
pip install fxapk

# Or from source
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

Dynamic unpack / capture, the sample corpus and other features need optional deps installed on demand; when missing, the relevant command prints a hint and core analysis is unaffected.

> Online-enrichment API keys, dynamic-analysis external tools, and companion scripts / MCP servers / probe libraries around the reports are all **bring-your-own — not shipped by this project**. See [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md).

## Usage

```bash
# Static analysis, HTML + JSON into out/
fxapk analyze app.apk --out out

# Already-captured web evidence is a first-class input:
#   reads .html / .body / .js / .headers recursively, never re-fetches over the network
fxapk analyze-web <evidence-dir> --out out

# One-click full pipeline (rooted device / emulator attached):
#   doctor → static → unpack → capture → merge into one report
fxapk auto app.apk --out out       # no device? dynamic steps are skipped, static report still produced

# Did detection get better or worse across versions, on the same real samples?
# (ingest both versions' reports with `corpus add` first)
fxapk corpus regress --corpus <library-dir>

# Passively enrich a list of targets (one IP / domain per line).
# --dry-run is the DEFAULT: it only estimates each source's quota and sends no requests.
fxapk enrich batch -t targets.txt -o enrich_out
```

Main commands: `analyze` (static), `analyze-web` (already-captured web evidence), `auto` (one-click: static + dynamic when a device is present), `capture` (on-device capture), `doctor` (device env check + auto-fix), `enrich batch` (resumable passive batch enrichment), `corpus` (sample library: ingest past reports, cross-version regression, look up a value across samples). Full commands and flags: `fxapk --help`.

When not installed as a command, use `python -m apkscan.cli <…>`.

### Read "what we could not see" before reading conclusions

Reports and `fxapk digest` carry a `visibility` section, placed **ahead of the leads**. It answers one
question: given what this run actually saw, which conclusions are eligible. A hardened sample often
leaves nothing but a stub DEX, and there "no network endpoints found" means *we could not see*, not
*there are none*. `blocked_claims` names the exhaustiveness claims that cannot be made, and
`next_actions` says how to close the gap — unpack, capture, or rerun under authorization to fetch
remote config.

This is orthogonal to `analysis_status`: that one reports whether the **tooling** ran healthy, this one
whether the **sample's content** was visible. Every analyzer succeeding and the DEX being a stub are
both true at once.

### Self-built shell vs. a repackaged legitimate app

`repack_identity` returns a three-state verdict, and it needs reading first: interface, domain and
build-path **ownership inverts** between the two. A self-built app's belong to its operator; a
repackaged one's belong to the **impersonated vendor**, so listing them as investigation leads points
at an uninvolved company.

When a sample looks repackaged, the tool states only that it appears **resigned** — never that
something was injected. Establishing that requires a file-by-file diff against the official build of
the same version, which the sample alone cannot provide.

## Output

- `out/report.html` — self-contained single file (share directly / open on phone)
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
why — add `leak-scan: allow <reason>` inline. CI scans the PR diff again, so `--no-verify` does not get
past the final gate.

Test fixtures must use documentation-reserved ranges (`192.0.2.0/24` / `198.51.100.0/24` /
`203.0.113.0/24` / `2001:db8::/32` / `example.com`). A real address, once pushed, is **irreversible** —
rewriting history does not remove the platform's cached copies, so the only reliable fix is never
writing it in the first place.

## Compliance

For **authorized security research / analysis** only. It performs static / dynamic analysis and information extraction, and provides **no attack / exploitation / active-probing capability against any third party**. **Passive by default**: overseas servers are only passively attributed (RDAP / WHOIS / DNS / ASN / certificate transparency), with zero active traffic to the target; the few capabilities that do reach the target (e.g. retrieving a config object the sample itself references) are off by default and only enabled under an explicit `--mode authorized-active`. Unpacking observes the **sample itself** on your own authorized analysis machine. Use only within lawful authorization.

## License

[MIT](LICENSE)
