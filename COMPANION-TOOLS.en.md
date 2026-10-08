# Built-in capabilities, dependencies and companion tools

*中文: [COMPANION-TOOLS.md](COMPANION-TOOLS.md)*

fxapk requires Python 3.11+ and the runtime dependencies in [pyproject.toml](pyproject.toml).
The package includes static analysis, reports, evidence packages, Phase-2 review, enrichment
adapters and probes. Credentials, devices and external executables require local configuration.

## What ships

| Included | Additional requirements |
| --- | --- |
| Static analyzers, rules, HTML/JSON, optional PDF, CSV and letter outputs | Evidence inputs; a local Chrome/Edge/Chromium for PDF |
| Enrichment adapters for `analyze`, `case close` and `enrich batch` | Service credentials, entitlements, query authorization and budget |
| Dynamic orchestration, built-in hooks and 8 Frida probes | adb, a rooted device, tcpdump and the Frida/mitmproxy tools required by the selected mode |
| Corpus, Phase-1 packages and Phase-2 CLI | Case/corpus storage outside the worktree; human review |

The bundled `apkscan/dynamic/frida_probes/` contains `coldstart-config`, `objstore-config`,
`native-ssl`, `tls-keylog`, `sms-forward-outbound`, `mqtt-xmpp-im`, `telegram-mtproto` and
`push-c2-inbound`. Additional probes, MCP servers, custom spreadsheets and messaging bridges
are not bundled. Bundled scripts do not install host tools or frida-server, or imply that every
probe runs automatically.

## Start offline

```bash
python -m pip install "fxapk==1.18.0"
fxapk analyze app.apk --offline --out out
fxapk digest out/app.json
```

Basic static analysis needs no JDK, device or API key. Analyzers with unavailable capabilities
may be skipped. Without `--offline`, analyze defaults to online enrichment and discloses target
identifiers to third parties and DNS. `analyze-web` reads saved HTML/JS/HAR offline by default;
its explicit `--online` enables enrichment, not page fetching.

## Online enrichment and credentials

Use [.env.example](.env.example) for configuration names; keep actual secrets out of public files.
Ordinary analysis runs capability- and endpoint-gated basic enrichment. Shodan is limited to
bounded `case close` targets or `enrich batch`, not ordinary `analyze`. DayDayMap is built in
and records per-source outcomes. Products such as ThreatBook and WhoisXML also require checking
account access and explicit batch selection.

```bash
fxapk case source-catalog --category all
fxapk enrich inventory
fxapk enrich batch -t targets.txt -o enrich_out
```

The catalog and inventory do not query targets or prove account access. Batch defaults to dry-run;
add `--no-dry-run` only after checking targets, disclosure, permissions and budget. See
[USAGE.en.md](USAGE.en.md) for profiles, credential slots and coverage limits. Configuration is
not execution: distinguish `hit/no_record/failed/skipped/disabled`; failure is not absence.

## Optional dependencies and device tools

| Purpose | Configuration |
| --- | --- |
| Supported deep PCAP decryption | `python -m pip install "fxapk[pcap]"`; the `dynamic` extra also declares cryptography, not device tools |
| Experimental linkage reranker | `python -m pip install "fxapk[ml]"`; independent-label and training gates still apply |
| jadx, adb, tshark, Frida and frida-dexdump | [Toolchain setup](tools/TOOLCHAIN.en.md) and [Python tool pins](tools/toolchain-requirements.txt) |
| Android UI plugin | Independent `fxapk-android-ui 0.1.0` (core 1.18.0+); external Android CLI, adb and an authorized device; see the [full guide](ANDROID-UI.en.md) |
| mitmproxy | A separate environment with explicit executable mappings, as described in the toolchain guide |

Default capture/auto still require Frida. Explicit `capture --mode floor-only` needs no Frida,
but requires adb, device root and device-side tcpdump. Missing prerequisites can block a step;
not every command can degrade automatically. Use `fxapk selfcheck` for overall capabilities and,
when device inspection is authorized, `fxapk doctor --no-fix`. Selfcheck does not validate every
API key or account entitlement. Doctor repairs devices by default.

## Export and external integration

PDF uses a local browser. Ordinary analyze reports a skipped PDF on failure; other formats are
written only if selected in `--fmt`. Origin-check projection failure has its own nonzero exit and
status receipt. Check actual artifacts. HTML/PDF, JSON, CSV and letters can contain raw values;
they are not sanitized publications. Digest redaction is also limited.

Custom MCP, XLSX and messaging bridges are not prerequisites for the core CLI. Integrations must
preserve report/attachment hashes, provenance, scope and review state; their success cannot replace
evidence gates. See the [pre-report workflow](PRE-REPORT-WORKFLOW.md) for legacy compatibility.
