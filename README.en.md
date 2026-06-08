# fxapk

[![CI](https://github.com/s-silt/fxapk/actions/workflows/ci.yml/badge.svg)](https://github.com/s-silt/fxapk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

*CLI command `fxapk` (alias `apkscan`); PyPI package `fxapk`.* · **中文**: [README.md](README.md)

> An APK static-analysis CLI for **anti-fraud investigation** — instead of just dumping
> IPs/domains, it produces an **investigation lead sheet**: every lead answers
> "**what it is, which company owns it, and whom to subpoena for what evidence**".

Runs its core features with **zero environment** (`pip install`, no JDK / emulator / device).
Built for forensics on fraudulent Android apps: it extracts the **real configured key values**
(AppID / AppKey / AppSecret / channel IDs / uni-app app ID), maps third-party SDKs and packers
to **subpoena-able owners**, grades domains/IPs by **"investigate vs. skip"**, and surfaces the
real fraud servers out of hundreds of library/CDN noise entries.

---

## What it produces (the key difference)

Ordinary tools tell you "GeTui SDK detected"; fxapk tells you **the value + the owner + the advice**:

```
Plugins / Config keys (CONFIG_KEY)
  GETUI_APPID    = aBcD1234EfGh5678   -> Getui (Each Interactive Co., Ltd.)   [INVESTIGATE]
  PUSH_APPSECRET = zZ9yX8wV7uT6sR5q   -> Getui                                [INVESTIGATE, strong cred]
  __UNI__        = __UNI__A1B2C3D     -> DCloud (Digital Heaven, Beijing)     [INVESTIGATE]
   (illustrative, redacted values)

Main-control domains (INVESTIGATE -- app-owned / suspected C2)
  *.api-xxxxx.vip   -> ask registrar / ICP filing / cloud provider for owner & tenant
Associated domains / IPs (SKIP -- known infrastructure, collapsed)
  api.map.baidu.com / *.myqcloud.com / getui.net ...

Advice: with the AppSecret above, ask [Getui] for the developer's real-name account,
        app registration entity, and push delivery logs.
```

Actual rendered HTML report (**demo, redacted data**):

![fxapk report example](docs/images/report-demo.png)

---

## Install

Requires **Python 3.11+**.

```bash
# From PyPI (after release)
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
python -m pytest -q          # 324 passed
```

Optional (gracefully skipped when missing): `jadx` (deep decompile), `frida-tools` +
`frida-dexdump` (`unpack`), `mitmproxy` (`capture`), Chrome/Edge/Chromium (`--fmt pdf`).

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
uni-app/H5/RN bundles), `jadx` (deep decompile, needs jadx), `packing` (hardening vendor),
`certificate` (cross-sample dev correlation), `contacts` (QQ/WeChat/Telegram/email/phone),
`permissions` / `components` / `manifest` / `crypto`.

Enrichers (online, `--offline` to disable, cached): `whois`, `icp`, `asn`.
Investigate-vs-skip grading lives in `core/infra.py` (known infra/CDN/libs → skip).

---

## Dynamic completion (unpack / capture)

```bash
fxapk unpack app.apk --out out          # rooted device + frida-dexdump unpack, re-analyze
fxapk capture <package> --duration 60   # mitmproxy + frida SSL-unpinning, runtime endpoints
```

When no device/tools are present these return `status=skipped` with a **copy-paste playbook**
(install frida-server, push CA, inject unpinning, `--extra-dex` re-ingest), never crashing.

---

## Compliance

For **authorized anti-fraud investigation / security research** only. It performs analysis and
lead extraction; it provides no attack/bypass/evasion capability. Hardening is detected, not
stripped (unpacking is an optional on-device step you must run in your own authorized
environment). Online enrichment only queries public WHOIS / ICP / ASN data.

## License

[MIT](LICENSE)
