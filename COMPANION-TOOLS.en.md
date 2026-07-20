# External Dependencies & Companion Tools (bring your own — not shipped)

*中文: [COMPANION-TOOLS.md](COMPANION-TOOLS.md)*

This repository ships **the core analysis CLI only**. The core analysis runs with zero environment,
out of the box. Everything else — online enrichment, dynamic analysis, companion scripts / MCP servers /
probe libraries — **depends on external resources (API keys, external tools, scripts you build yourself)**,
and **none of those are bundled with this repository**. You supply / install / build them yourself. When
something is missing, the relevant command prints a hint and core analysis is unaffected.

> In one line: **the core is in the repo; the keys and companion tools are yours to bring.** This project
> ships no API keys, no probe libraries, no MCP servers, and no reporting / messaging scripts.

---

## 0. What this repo provides / does not

| | Contents |
|---|---|
| ✅ Provided (via `pip install fxapk`) | Static-analysis core, report rendering, `--mode` gating, `case close` closure, built-in passive-enrichment **wiring** (reads keys you configure) |
| ❌ Not provided (bring your own / build) | Any **third-party API key**, dynamic-analysis **external tools** (jadx / adb / frida / mitmproxy), **MCP servers**, **frida probe libraries**, reporting / spreadsheet / messaging **companion scripts** |

---

## 1. Core analysis — zero config

```bash
pip install fxapk
fxapk analyze app.apk --out out
```

No JDK / emulator / device / keys required. Everything below is an **optional enhancement**.

## 2. Online enrichment API keys (bring your own)

fxapk includes wiring for several **passive OSINT / internet-measurement** sources (they read publicly
available registry / scan data from third parties). The repo **provides the wiring only, not the keys** —
apply for your own at each service and put them in the project-root `.env` (see `.env.example`, which is
gitignored). **All optional**: without a key you simply lose that source; core analysis and `case close`
still run, and unconfigured sources are recorded as `disabled` in the source-status output.

| Environment variable | Service | Sign-up |
|---|---|---|
| `FXAPK_SHODAN_KEY` | Shodan | account.shodan.io |
| `FXAPK_FOFA_KEY` / `FXAPK_FOFA_URL` | FOFA | fofa.info |
| `FXAPK_HUNTER_KEY` | Hunter | hunter.qianxin.com |
| `FXAPK_QUAKE_KEY` / `FXAPK_QUAKE_KEY2` / `FXAPK_QUAKE_URL` | Quake | quake.360.net |
| `FXAPK_CENSYS_ORG_ID` / `FXAPK_CENSYS_TOKEN` | Censys | censys.io |
| `FXAPK_DAYDAYMAP_KEY` / `FXAPK_DAYDAYMAP_KEY2` | DayDayMap | daydaymap.com |
| `FXAPK_ZOOMEYE_KEY` / `FXAPK_ZOOMEYE_URL` | ZoomEye | zoomeye.org |
| `FXAPK_VT_KEY` | VirusTotal | virustotal.com |
| `FXAPK_OTX_KEY` | AlienVault OTX | otx.alienvault.com |
| `FXAPK_URLSCAN_KEY` | urlscan.io | urlscan.io |
| `FXAPK_ABUSEIPDB_KEY` | AbuseIPDB | abuseipdb.com |

> Keys are credentials between you and each service; `.env` is gitignored and never committed.
> **This project distributes no keys.**

## 3. Optional Python extras

| Capability | Install | Use |
|---|---|---|
| Decrypt extra | `pip install cryptography` | Decrypt runtime `{data,timestamp}` encrypted envelopes |
| Graph extra | `pip install fxapk[graph]` (kuzu) | Local case graph |

## 4. Dynamic-analysis external tools (install yourself)

Dynamic unpacking / capture needs external tools **you install** plus a rooted device / emulator. fxapk
auto-detects them, degrades gracefully when missing, and prints a fix hint (see `fxapk selfcheck` /
`fxapk doctor`).

| Tool / capability | Install yourself | Use |
|---|---|---|
| jadx | on PATH (or the fxapk-jadx plugin bundle) | deeper decompile for endpoints / secrets |
| adb | Android platform-tools | device communication |
| frida / frida-tools | `pip install frida-tools` + a device-side frida-server | runtime injection |
| frida-dexdump | `pip install frida-dexdump` | unpacking |
| mitmproxy | `pip install mitmproxy` | capture parsing |
| device | a rooted device / emulator connected over adb | on-device unpack / capture |

## 5. PDF export

`--fmt pdf` needs **Chrome / Edge** installed locally (headless render). Without it, PDF is skipped and
HTML / JSON are produced as usual.

## 6. Companion tooling (not provided — build your own)

Beyond the keys and external tools above, some **auxiliary workflows** around fxapk reports can be built
yourself. These scripts / services are **not in this repository and are not shipped with fxapk** — if you
want them, implement them your own way; credentials and implementation are yours:

- **Standalone / batch enrichment scripts, enrichment MCP servers**: batch or ad-hoc IP / domain enrichment
  outside fxapk. fxapk only wires passive enrichment inside `case close` (the keys in §2); standalone
  scripts / MCP are yours to build.
- **Cross-report correlation MCP server**: cross-reference IOCs across multiple `report.json` files. The
  protocol side is standard MCP and the `report.json` schema is in the repo; the implementation is yours.
- **Reporting / spreadsheet generators**: post-process `report.json` / the IOC CSV into custom templates.
  fxapk ships HTML / JSON / optional PDF plus `fxapk export` (IOC CSV); fancier templates are yours to write.
- **Dynamic-analysis probe libraries (frida scripts)**: the dynamic engine can load frida probes via
  `-l <script>.js`, but **this project bundles no probe library** — write / maintain your own probe scripts.
- **Messaging / handoff integrations**: any bridge that pushes results to a chat / ticketing system is out
  of scope for this project; configure your own.

---

## Behavior when something is missing (graceful degradation)

fxapk **degrades, never crashes**, for every optional item: sources without a key are recorded `disabled`,
missing tools make the relevant command print a one-line fix hint, and core static analysis always runs.
Use `fxapk selfcheck` (or `fxapk doctor`) to see at a glance what is ready, what is missing, and how to fix each.

```bash
fxapk selfcheck            # lists readiness of core / keys / external tools / dynamic capabilities + fix hints
```
