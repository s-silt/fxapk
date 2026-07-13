# Changelog

Notable changes to fxapk. Versioning is semantic; **behavior changes that
affect automated / CI / agent callers are called out explicitly**.

## 0.9.0 — 2026-07-13

Theme: **result credibility, the passive/active network boundary, and
release hardening** — moving fxapk from "what it can detect" toward "why it
judged this, whether the run was complete, and which network behavior is
permitted". (33 commits since 0.8.0.)

### ⚠️ Behavior changes (read before upgrading automation)

- **`--mode passive|authorized-active` (default `passive`)** on `analyze`,
  `auto`, and `batch`. In the default passive mode, enrichers that send
  traffic to the **target** (the web-check active prober) are blocked at the
  pipeline layer, and the Telegram `getMe` probe is not sent. Pass
  `--mode authorized-active` to allow active probing — this requires
  explicit operator authorization. **If you relied on web-check enrichment,
  you must now pass `--mode authorized-active`.**
- **`--strict`** on `analyze`: non-zero exit when the analysis is
  incomplete — exit code **4** if a *critical* analyzer failed, **3**
  otherwise. Default (non-strict) is unchanged: best-effort, exit **0**.
- **Report schema** gained top-level fields — `schema_version` ("1.0"),
  `analysis_status` (`complete|partial|failed`), `completeness` (0..1),
  `critical_failures`, `skipped_analyzers` — and `meta` keys: `mode`,
  `tool_version`, `ruleset_digest`, `stage_status`, `active_enrichers_*`.
  Existing fields are unchanged; consumers should key off `schema_version`.

### Added

- **Passive/active network mode** enforced in code across config → pipeline
  gate → CLI, fail-closed to passive. `web-check` is the sole active
  enricher and is labelled as such; skipped/enabled active enrichers are
  recorded in `meta` for audit.
- **Report credibility layer**: `analysis_status`, `completeness`
  (capability/platform skips excluded from the denominator),
  `critical_failures`, and `ruleset_digest` (a stable, EOL-normalized
  sha256 over the rule files — reproducibility anchor) + `tool_version`.
- **Finding provenance**: central `analyzer` attribution (stamped in the
  pipeline, no per-analyzer churn) and a `confidence` axis orthogonal to
  severity; explicitly heuristic findings default to LOW confidence.
- **Staged pipeline execution** with per-stage `stage_status` and
  stage-level resilience — a crashing stage no longer aborts the whole run;
  an `analyze`-stage crash marks the report `failed`, other stage crashes at
  least `partial`.
- **Anti-forensic / hardening detection**: open-source packer & hardening
  toolchain signatures, native `.so` symbol/string scanning (rename-
  resistant), ELF PT_NOTE hijack + local high-entropy heuristics,
  Xposed/LSPosed module identity from manifest meta-data, and additional
  hook / anti-detection signatures.
- **Dynamic capture hardening**: out-of-band floor pcap automation, explicit
  frida hook-readiness signal, capture-mode flags (`both/floor-only/
  mitm-only`) + `--serial`, degraded status (no fake "done"), UID socket
  snapshot at the capture window.
- **CI release gates**: OS matrix (Linux / macOS / Windows), 80% coverage
  floor, wheel build + clean-install smoke test (`fxapk --version` + rules
  load from the wheel), and `pip-audit` over the isolated fxapk dependency
  tree.

### Fixed

- Zip-bomb declared-size guard applied to the **parallel** analysis path
  (previously serial-only).
- Connectivity probe no longer false-negatives behind restrictive networks
  — mixed domestic + foreign **numeric** anchors over TCP:443 (no DNS
  dependency, bounded latency).
- Manifest-bomb / manifest-poison parsing robustness (no crash on tag
  namespace; string-pool package-name fallback).
- Review follow-ups: unified effective config (analyzer vs pipeline), audit
  scoped to the project dependency tree.

### Changed

- `run()` refactored into a staged `_PipelineState` pipeline
  (behavior-preserving).

---

Earlier releases (≤ 0.8.0) predate this changelog; see the git history and
GitHub release notes.
