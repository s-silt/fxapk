# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI command `fxapk` (alias `apkscan`); PyPI package `fxapk`.* · **中文**: [README.md](README.md)

> An APK / iOS IPA **static + dynamic analysis CLI** — extracts app config, network
> endpoints, third-party components and packer fingerprints, enriches domains/IPs with
> ownership attribution, and outputs a **structured analysis report**; correlates across samples.

Runs its core features with **zero environment** (`pip install`, no JDK / emulator / device).
It extracts the **real configured key values** (AppID / AppKey / AppSecret / channel IDs /
uni-app app ID), maps third-party SDKs and packers to **registered owners / service providers**,
classifies domains/IPs by **ownership**, and separates app-owned backends from hundreds of
library/CDN infrastructure noise entries.

> Notice: this project is for **authorized security research / analysis** only. It performs
> static / dynamic analysis and information extraction, and provides **no attack / exploitation /
> active-probing capability against any third party**. Use only within lawful authorization.

---

## What it produces (the key difference)

Ordinary tools just tell you "some push SDK detected"; fxapk gives you **the value + the owner + ownership class**:

```
Config keys (CONFIG_KEY)
  PUSH_APPID     = aBcD1234EfGh5678   -> push provider (example)        [app-owned, focus]
  PUSH_APPSECRET = zZ9yX8wV7uT6sR5q   -> push provider (example)        [strong cred]
  UNIAPP_ID      = __UNI__A1B2C3D     -> cross-platform framework (ex.) [focus]
   (illustrative, redacted values)

App-owned / suspected backend domains (focus)
  *.api-xxxxx.vip   -> owner via registrar / ICP filing / cloud provider
Third-party infrastructure (skip, collapsed by default)
  map / push / public CDN shared domains ...

Note: the config values above trace back to the provider-side registration entity and app info.
```

Actual rendered HTML report (**demo, redacted data**):

![fxapk report example](docs/images/report-demo.png)

---

## Install

Requires **Python 3.11+**.

```bash
# From PyPI
python -m pip install fxapk

# Or from source
git clone https://github.com/s-silt/fxapk.git
cd fxapk
python -m pip install -e .
```

Core deps: `androguard`, `jinja2`, `typer`, `python-whois`, `requests`, `pyyaml`.
Unit tests need none of androguard/network/device (they use a `FakeContext`):

```bash
python -m pip install jinja2 typer python-whois requests pyyaml pytest
python -m pytest -q          # run all unit tests (offline, no device)
```

Optional (gracefully skipped when missing): `jadx` (deep decompile — on PATH),
`frida-tools` + `frida-dexdump` (`unpack`), `mitmproxy` (`capture`), Chrome/Edge/Chromium (`--fmt pdf`).

---

## Quick start

```bash
# Default: online enrichment, HTML + JSON into out/
fxapk analyze app.apk --out out

# Offline, also export PDF
fxapk analyze app.apk --out out --offline --fmt html,json,pdf

# JSON only
fxapk analyze app.apk --fmt json
```

**One-click full pipeline** (with a rooted device/emulator attached — chains doctor → static → unpack → capture → merge):

```bash
fxapk doctor                  # env health check (device/root/ABI/frida-server/CA), auto-fixes what it can
fxapk auto app.apk --out out  # one command end to end; prompts you to operate the app during capture
                              # no device? unpack/capture are skipped, static report still produced
```

| Command | What it does |
|---|---|
| `analyze APK` | static analysis (zero-env) → structured lead sheet; with `--dynamic` and a device, auto unpack+capture and **merge runtime endpoints back into the main report** |
| `auto APK` | one-click: `doctor`→static→unpack→capture→merge into one report (dynamic steps skipped if no device) |
| `doctor` | env health check: online device / root / ABI / host frida / device frida-server / mitmproxy / CA, per-item `[OK]`/`[FAIL]`; `--fix` auto-fixes (deploy frida-server, install CA); exits 1 when a critical item fails |
| `unpack APK` | rooted-device unpack: frida-dexdump dumps hidden DEX, re-analyzed |
| `capture PACKAGE` | rooted-device capture: mitmproxy + frida SSL-unpinning, runtime endpoints |
| Flag | Meaning |
|---|---|
| `--out DIR` | report output dir (default `out`) |
| `--fmt html,json,pdf` | output formats (default `html,json`; `pdf` needs Chrome/Edge) |
| `--online` / `--offline` | enrich WHOIS / ICP filing / IP-ASN (default online) |
| `--extra-dex PATH` | merge unpacked `.dex` (file or dir) into static analysis |
| `--dynamic` | after static, auto run `unpack` + `capture` if a device is detected |

Output: `out/report.html` (self-contained), `out/report.json`, `out/report.pdf`.

---

## Analyzers

`config_keys` (★ real `key=value` + owner), `sdk_fingerprint` (SDK → vendor),
`payment` (aggregators / merchant IDs / USDT / wallet addresses), `endpoints`
(URLs/domains/IPs, strict denoise), `js_bundle` (extract from JS string literals in
uni-app/H5/RN bundles), `crypto_recipe` (app-layer crypto recipe from bundled JS, for offline decryption),
`re_toolkit` (identifies bundled runtime hook / anti-debug / anti-analysis capability — defensive
detection, no exploitation — to gauge dynamic-observation feasibility and correlate),
`native_obfuscation` (native `.so` encryption / virtualization heuristic: high entropy + few readable
strings → native logic not statically recoverable, prefer runtime observation; heuristic signal, not exact),
`jadx` (deep decompile, needs jadx), `packing` (packer identification;
**evidence-tiered** — only a real `.so`/feature file marks it hardened, bare dex name strings
are downgraded to a note, avoiding false positives),
`certificate` (cross-sample dev correlation), `contacts` (QQ/WeChat/Telegram/email/phone),
`permissions` / `components` / `manifest` / `crypto`, `ios_plist` (iOS IPA: Info.plist display name /
URL scheme / ATS cleartext / permission usage).

Enrichers (online, `--offline` to disable, cached, **concurrent** lookups for suspicious endpoints):
`rdap` (HTTPS — registrar/dates/status/NS, more reliable than port-43 whois, falls back to `whois`),
`whois`, `icp`, `dns` (DoH resolve domain→IP + hosting cloud lookup, to locate the real backend), `asn`.
Ownership grading lives in `core/infra.py` (known infra/CDN/libs → skip).

---

## Dynamic completion (doctor / auto / unpack / capture)

Hardened apps hide the true backend from static analysis; you unpack + capture on a rooted
device/emulator. **With a device attached, just use `fxapk auto`**; or run steps individually:

```bash
fxapk doctor                            # env check: device/root/ABI/frida-server/CA, auto-fix
fxapk auto app.apk --out out            # one-click: doctor→static→unpack→capture→merge
fxapk unpack app.apk --out out          # rooted device + frida-dexdump unpack, re-analyze
fxapk capture <package> --duration 60   # mitmproxy + frida SSL-unpinning, runtime endpoints
```

**Auto-provisioning**: `doctor` (and `auto`) can **download & deploy frida-server** matching the
device ABI + host frida version (stdlib-only download) and **install the mitmproxy CA into the
system trust store** (root). When it can't, it degrades honestly with copy-paste commands —
the HTTPS-decryption linchpin never fakes success.
**Runtime endpoints merged back**: `auto` / `analyze --dynamic` fold captured runtime endpoints
(`source=runtime`) into the same lead sheet and re-render the report.
**No device/tools** → those steps return `status=skipped` with a copy-paste playbook; the static
report is still produced. See [docs/dynamic-setup.md](docs/dynamic-setup.md) for device/emulator
setup (adb connect, root, ARM compatibility, frida version match, CA install).

---

## Compliance

For **authorized security research / analysis** only. It performs analysis and information
extraction; it provides **no attack / exploitation / active-probing capability against any
third-party server**. Hardening is detected, not stripped (unpacking is an optional on-device step
that observes the **sample itself** on your own authorized device). Overseas servers are
only **passively attributed** (RDAP / WHOIS / ICP / ASN / DNS / certificate transparency) to locate
the real origin IP and extract identifiers — **never actively probed or attacked**. Online
enrichment only queries public WHOIS / ICP / ASN data.

## License

[MIT](LICENSE)
