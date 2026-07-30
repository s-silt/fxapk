# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI command `fxapk` (alias `apkscan`) · PyPI package `fxapk`* · **中文**: [README.md](README.md)

An APK **static + dynamic analysis CLI**: extracts real app config (AppID / AppKey / channel IDs / uni-app app ID, etc.), network endpoints, third-party components and packer fingerprints; traces the **encrypted remote-config chain** (finds OSS / CDN config objects, multi-layer decodes / decrypts the dynamic backend domain / IP pool inside, assembles a single control chain, and — for obfuscated samples where the standard crypto API can't be recognized — surfaces **decrypt leads** carrying the full ciphertext for manual / AI recovery); attributes domains / IPs with a **five-layer, non-collapsing infrastructure model** (resource holder → BGP ASN → cloud / IDC → CDN / edge proxy → operator — each layer carries its source and confidence, and is marked unknown when not found); captures traffic **PCAP-first** (TLS / QUIC handshake parsing + five-tuple socket attribution); and outputs a **structured HTML / JSON report**.

Runs its core analysis with **zero environment** (`pip install`, no JDK / emulator / device). Unpacking and traffic capture of hardened apps are optional on-device steps.

## How to use it: tell your AI three things

This tool is meant to be driven by an AI assistant (Claude Code, Codex, and the like). **You don't
need to memorise commands — just a few sentences**: say these three once to get set up, then one
sentence every time you actually want something analysed.

### The first time, say these three

**1. "Deploy github.com/s-silt/fxapk"**

The AI installs it:

```bash
pip install fxapk
```

Say "deploy from source" instead if you want the code too (to read or change it):

```bash
git clone https://github.com/s-silt/fxapk.git && cd fxapk && pip install -e .
```

Requires **Python 3.11+**. If the `fxapk` command doesn't end up on your PATH, use
`python -m apkscan.cli` instead — same arguments.

**2. "Run a self-check and set up the environment"**

The AI runs:

```bash
fxapk selfcheck
```

It lists, item by item: **what works, what doesn't, and what to install for the ones that don't.**
The AI reads that and knows how far this machine can go and what to ask you to install — no need to
probe by trial and error.

Core static analysis needs no optional tools — it works right after install. Unpacking, traffic
capture and online attribution lookups are optional; missing one only affects that part, and the
self-check spells out which.

**3. "Set up .env"**

Don't skip this one. Finding out who owns a server and where it sits means asking several public
databases at once — any single one may have nothing. **The more you can ask, the more complete the
picture.** RDAP, WHOIS, DNS, ASN and certificate transparency need no key; the commercial scanning
and threat-intel sources (FOFA, Shodan, VirusTotal, Hunter, Quake, ZoomEye, Censys, OTX, AbuseIPDB,
…) each need their own API key, and keys live in a `.env` file at the project root.

```bash
cp .env.example .env    # then fill in whichever keys you have
```

`.env.example` lists every supported source and its variable name. **Fill in as many as you have —
none at all still works**, attribution lookups are simply weaker: a source without a key is never
guessed at, the report marks it *not queried* (`disabled`) rather than *queried, nothing found*
(`no_record`). Those are two very different things; don't read one as the other.

Keys stay on your machine — never in reports, never in logs, never committed (`.env` is already in
`.gitignore`). To see which sources actually answered on a given run, read `source_status` in the
report — `fxapk selfcheck` only reports whether online enrichment works **at all**, it does not
check sources one by one.

### Every time after that, just one sentence

**"Analyse" plus a path**

```
analyse D:\samples\app.apk
analyse D:\evidence\some-site-dir
analyse out/app.json
```

The AI looks at what you gave it and picks the command:

| What you give it | What the AI runs | What happens |
|---|---|---|
| an `.apk` file | `fxapk analyze <path> --out out`, then `fxapk digest out/<name>.json` | produces a report, then squeezes it into a one-page summary |
| a folder of saved web files (`.html` / `.js` …) | `fxapk analyze-web <dir> --out out` | reads only the files you saved; never goes online to fetch that site |
| an existing `report.json` | `fxapk digest <file>` | squeezes a long report into a one-page summary |
| a folder full of APKs | `fxapk batch <dir>` | runs them one by one, skipping ones already done |

Want it to look up server ownership too? Just add "and look it up online" — the AI adds `--online`.

**How to read the report**: start with the "what we could see this time" section. It spells out
**which statements can't be made yet, why, and how to fix that**. If an app is hardened and its real
code only decrypts at runtime, then "no server addresses found" means *we couldn't see any*, not
*there are none*. Read that section first and the leads below won't mislead you.

More commands and flags: `fxapk --help`. The detailed operating contract for AI drivers is in
[AGENTS.md](AGENTS.md).

### What this tool does not do

So you don't go looking:

- **Android APKs only** — it does not analyse Apple `.ipa` files. (You'll find the string `.ipa` in
  the code; that's just an entry in a "don't read these as text" list, not an analysis capability.)
- **It does not touch the target's servers.** Looking up overseas infrastructure only reads public
  databases — not a single packet goes to the target. The few features that genuinely need to send a
  request are off by default; see "Compliance" below.
- **It ends at the report.** This repository produces report files (HTML / JSON / PDF) plus a flat
  CSV export of the leads (`fxapk export`); whatever you aggregate or build on top of that is out of
  scope.

> Online-enrichment API keys, dynamic-analysis external tools, and companion scripts / MCP servers / probe libraries around the reports are all **bring-your-own — not shipped by this project**. See [COMPANION-TOOLS.en.md](COMPANION-TOOLS.en.md).

## Command table

If you'd rather type commands yourself, these are the common ones. Full flags: `fxapk --help`; if
`fxapk` isn't on your PATH, swap in `python -m apkscan.cli`.

| Goal | Command |
|---|---|
| Analyse an APK | `fxapk analyze app.apk --out out` |
| Same, with online attribution lookups | `fxapk analyze app.apk --online --out out` |
| Analyse saved web files | `fxapk analyze-web <dir> --out out` |
| Run a whole folder | `fxapk batch <dir>` |
| Full pipeline: doctor → static → unpack → capture → merge (dynamic steps only with a rooted device; without one they're skipped and you still get the static report) | `fxapk auto app.apk --out out` |
| Same, as an acceptance gate (exit 0/5/6 = complete/partial/failed) | `fxapk auto app.apk --out out --strict-case` |
| Top up an existing report with multi-source lookups and five-layer attribution | `fxapk case close out/app.json` |
| Squeeze a report into a one-page summary | `fxapk digest out/app.json` |
| Capture traffic on a device | `fxapk capture <package>` |
| Device health check, with auto-fix | `fxapk doctor --fix` |
| Environment self-check (what works / doesn't / how to fix) | `fxapk selfcheck` |
| Batch-enrich a target list (`--dry-run` by default: estimates quota, sends nothing; resumable) | `fxapk enrich batch -t targets.txt -o enrich_out` |
| Ingest a report into the corpus | `fxapk corpus add out/app.json --corpus <dir>` |
| See whether detection improved or regressed across versions | `fxapk corpus regress --corpus <dir>` |
| Have I seen this value before (look it up across samples) | `fxapk corpus seen <value> --corpus <dir>` |
| Find samples built in the same environment | `fxapk corpus shared-build-env --corpus <dir>` |
| Export leads as CSV | `fxapk export out/app.json` |

Every `corpus` command needs a library directory: pass `--corpus <dir>`, or set `FXAPK_CORPUS`
beforehand. The library root holds sample data — keep it outside the code repository.

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
