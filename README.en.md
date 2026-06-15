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

## ⬇️ Download & run (no Python needed)

Don't want the command line? Grab `fxapk-gui-vX.Y.Z-win64.zip` from
**[Releases](https://github.com/s-silt/fxapk/releases/latest)** — a 64-bit Windows **self-contained**
bundle with frida / mitmproxy / adb built in (**nothing else to install**):

1. Download and **unzip the whole `fxapk-gui` folder** (deps live in `_internal/` — don't copy just the exe).
2. Double-click **`fxapk-gui.exe`** → pick an APK → click "static analysis" or "one-click auto".
3. To unpack / capture: USB-connect a **rooted phone or emulator** (adb is bundled) → click "doctor" to
   auto-provision frida-server + CA → then "one-click auto".
4. *(optional)* For deeper jadx decompilation: download **`fxapk-jadx-*.zip`** (bundles a portable JRE — no
   Java install needed) → click "🔌 Enable jadx" and pick the zip → jadx is then used automatically.

> ⚠️ Unsigned; on first run Windows SmartScreen / AV may warn — choose "More info → Run anyway" or
> allow-list it. frida-server is auto-pushed to the device by ABI. Keep the whole folder together.

Developers / CLI users: use `pip install` below.

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
python -m pytest -q          # 556 passed
```

Optional (gracefully skipped when missing): `jadx` (deep decompile — on PATH, or the standalone
`fxapk-jadx-*.zip` add-on which bundles a portable JRE; GUI users click "🔌 Enable jadx" once),
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
| `analyze APK` | static analysis (zero-env) → investigation lead sheet; with `--dynamic` and a device, auto unpack+capture and **merge runtime endpoints back into the main report** |
| `auto APK` | one-click: `doctor`→static→unpack→capture→merge into one report (dynamic steps skipped if no device) |
| `doctor` | env health check: online device / root / ABI / host frida / device frida-server / mitmproxy / CA, per-item `[OK]`/`[FAIL]`; `--fix` auto-fixes (deploy frida-server, install CA); exits 1 when a critical item fails |
| `unpack APK` | rooted-device unpack: frida-dexdump dumps hidden DEX, re-analyzed |
| `capture PACKAGE` | rooted-device capture: mitmproxy + frida SSL-unpinning, runtime endpoints |
| `gui` | graphical UI (single-window tkinter: doctor / static / one-click auto) |

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
uni-app/H5/RN bundles), `jadx` (deep decompile, needs jadx), `packing` (hardening vendor;
**evidence-tiered** — only a real `.so`/feature file marks it hardened, bare dex name strings
are downgraded to a note, avoiding false positives),
`certificate` (cross-sample dev correlation), `contacts` (QQ/WeChat/Telegram/email/phone),
`permissions` / `components` / `manifest` / `crypto`.

Enrichers (online, `--offline` to disable, cached, **concurrent** lookups for suspicious endpoints):
`rdap` (HTTPS — registrar/dates/status/NS, more reliable than port-43 whois, falls back to `whois`),
`whois`, `icp`, `dns` (DoH resolve domain→IP + hosting cloud lookup, to locate the real backend), `asn`.
Investigate-vs-skip grading lives in `core/infra.py` (known infra/CDN/libs → skip).

---

## Dynamic completion (doctor / auto / unpack / capture)

Real-hardened apps hide the true C2 from static analysis; you unpack + capture on a rooted
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
(the real C2, `source=runtime`) into the same lead sheet and re-render the report.
**No device/tools** → those steps return `status=skipped` with a copy-paste playbook; the static
report is still produced. See [docs/dynamic-setup.md](docs/dynamic-setup.md) for device/emulator
setup (adb connect, root, ARM compatibility, frida version match, CA install).

---

## Compliance

For **authorized anti-fraud investigation / security research** only. It performs analysis and
lead extraction; it provides no attack/bypass/evasion capability. Hardening is detected, not
stripped (unpacking is an optional on-device step you must run in your own authorized
environment). Online enrichment only queries public WHOIS / ICP / ASN data.

## License

[MIT](LICENSE)
