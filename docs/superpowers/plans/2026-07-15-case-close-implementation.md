# Case Close Orchestrator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic `fxapk case close` workflow that re-enriches runtime targets, records per-source outcomes, assembles the investigation five layers, and exposes strict completion status to the CLI and `auto`.

**Architecture:** Add an independent closure service over the existing `Report` model and keep the result in `report.meta["closure"]` for backward compatibility. Reuse the existing enrichment and infrastructure attribution paths, add case-close-only passive sources, and separate capture-channel health from target-attributed business evidence.

**Tech Stack:** Python 3.11+, dataclasses, Typer, requests, pytest, ruff, pyright.

## Global Constraints

- All new target lookups are passive third-party database/API queries unless the existing `authorized-active` gate explicitly permits otherwise.
- Credentials are loaded only from environment variables and must never appear in logs, reports, exceptions, tests, or documentation.
- Tests use RFC 5737 reserved IPs, `.test` domains, and synthetic credentials only.
- `meta.closure.status` is independent from the existing static `Report.analysis_status`.
- `case close --strict` exits `0` for complete, `5` for partial, and `6` for failed.
- Plain `analyze` must not execute `case_close_only` enrichers.
- Existing `auto` remains best effort unless `--strict-case` is selected.
- No case artifacts, APK/PCAP data, local paths, collaboration paths, or machine memory enter Git.

---

## File Map

- `apkscan/core/report_io.py`: lossless Report JSON loading and atomic JSON/optional HTML persistence.
- `apkscan/core/closure.py`: target selection, source outcome normalization, capture-quality evaluation, five-layer assembly, closure decision, and orchestration.
- `apkscan/enrichers/multisource.py`: passive case-close-only adapters and credential/configuration declarations.
- `apkscan/commands/case.py`: Typer `case close` command and strict exit mapping.
- `apkscan/core/registry.py`: `case_close_only` metadata on enrichers.
- `apkscan/core/enrichment.py`: reusable explicit-target enrichment entry point and normal-pipeline exclusion.
- `apkscan/dynamic/capture.py`: structured capture-quality signals in `runtime_report.json`.
- `apkscan/dynamic/merge.py`: optional closure call after runtime evidence is merged.
- `apkscan/dynamic/auto.py`: top-level closure result and optional strict behavior.
- `apkscan/cli.py`: register the `case` command and expose `--strict-case`.
- `apkscan/report/digest.py`: compact closure summary.
- `apkscan/report/templates/report.html.j2`: human-readable closure status, layers, gaps, and source coverage.
- `tests/test_report_io.py`, `tests/test_closure.py`, `tests/test_case_cli.py`, `tests/test_multisource.py`: new focused coverage.
- `tests/test_capture.py`, `tests/test_auto.py`, `tests/test_two_phase_enrichment.py`, `tests/test_digest.py`: compatibility and integration coverage.

### Task 1: Lossless Report I/O

**Files:**
- Create: `apkscan/core/report_io.py`
- Create: `tests/test_report_io.py`
- Modify: `apkscan/cli.py`

**Interfaces:**
- Produces: `report_from_dict(payload: Mapping[str, object]) -> Report`
- Produces: `load_report(path: str | Path) -> Report`
- Produces: `write_report(report: Report, path: str | Path, *, render_existing_html: bool = True) -> list[str]`
- Preserves: `schema_version`, `analysis_status`, `completeness`, `critical_failures`, `skipped_analyzers`, `enricher_status`, and arbitrary `meta` content.
- Preserves unknown top-level extension keys through a private in-memory marker that is removed from `meta` and restored at the JSON root during persistence.

- [ ] **Step 1: Write failing round-trip tests**

```python
def test_report_round_trip_preserves_health_and_closure(tmp_path):
    source = make_report()
    source.analysis_status = "partial"
    source.completeness = 0.75
    source.critical_failures = ["manifest"]
    source.meta["closure"] = {"schema_version": "1.0", "status": "partial"}
    path = tmp_path / "report.json"
    report_json.dump(source, str(path))

    loaded = load_report(path)

    assert loaded.analysis_status == "partial"
    assert loaded.completeness == 0.75
    assert loaded.critical_failures == ["manifest"]
    assert loaded.meta["closure"]["status"] == "partial"
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `python -m pytest -q tests/test_report_io.py --basetemp E:/fxapk-testtmp/case-close-report-io-red`

Expected: collection fails because `apkscan.core.report_io` does not exist.

- [ ] **Step 3: Implement typed reconstruction and atomic persistence**

```python
def load_report(path: str | Path) -> Report:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report root must be an object")
    return report_from_dict(payload)


def write_report(
    report: Report,
    path: str | Path,
    *,
    render_existing_html: bool = True,
) -> list[str]:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    payload = report_json.to_dict(report)
    extensions = payload.get("meta", {}).pop("_report_top_level_extensions", {})
    if isinstance(extensions, dict):
        payload.update({key: value for key, value in extensions.items() if key not in payload})
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(target)
    written = [str(target)]
    html_path = target.with_suffix(".html")
    if render_existing_html and html_path.exists():
        report_html.render(report, str(html_path))
        written.append(str(html_path))
    return written
```

Move the existing `_evidence_from_dict()` and `_report_from_json_dict()` reconstruction logic from `cli.py` into this module, then make the CLI import the shared implementation.

- [ ] **Step 4: Run focused and existing rerender tests**

Run: `python -m pytest -q tests/test_report_io.py tests/test_cli_dynamic.py tests/test_report.py --basetemp E:/fxapk-testtmp/case-close-report-io-green`

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```text
git add apkscan/core/report_io.py apkscan/cli.py tests/test_report_io.py
git commit -m "refactor: centralize report json loading"
```

### Task 2: Closure Model, Target Selection, and Decision Rules

**Files:**
- Create: `apkscan/core/closure.py`
- Create: `tests/test_closure.py`

**Interfaces:**
- Produces: `ClosureConfig(online: bool, mode: str, max_targets: int, refresh: bool, require_dynamic: bool | None)`
- Produces: `select_targets(report: Report, max_targets: int = 6) -> list[Endpoint]`
- Produces: `evaluate_capture_quality(meta: Mapping[str, object]) -> dict[str, object]`
- Produces: `assemble_target_closure(endpoint: Endpoint) -> dict[str, object]`
- Produces: `evaluate_closure(report: Report, targets: Sequence[dict[str, object]], *, require_dynamic: bool | None) -> dict[str, object]`
- Target/source ordering is stable and duplicate endpoint values are removed case-insensitively for domains.

- [ ] **Step 1: Write failing pure-function tests**

```python
def test_select_targets_prioritizes_target_attributed_runtime_endpoint():
    report = report_with_endpoints(
        runtime_ip("198.51.100.20", attribution="target"),
        runtime_ip("198.51.100.10", attribution="ambiguous"),
        static_domain("api.example.test"),
    )
    assert [ep.value for ep in select_targets(report, max_targets=2)] == [
        "198.51.100.20",
        "198.51.100.10",
    ]


def test_cdn_without_origin_cannot_be_complete():
    target = complete_target("198.51.100.10")
    target["origin"] = {"required": True, "status": "missing"}
    closure = evaluate_closure(complete_report(), [target], require_dynamic=False)
    assert closure["status"] == "partial"
    assert "origin" in " ".join(closure["gaps"]).lower()
```

- [ ] **Step 2: Run tests and confirm missing-module failure**

Run: `python -m pytest -q tests/test_closure.py --basetemp E:/fxapk-testtmp/case-close-model-red`

Expected: collection fails because `apkscan.core.closure` does not exist.

- [ ] **Step 3: Implement deterministic selection and closed enums**

```python
CLOSURE_COMPLETE = "complete"
CLOSURE_PARTIAL = "partial"
CLOSURE_FAILED = "failed"
SOURCE_STATUSES = frozenset({"hit", "no_record", "failed", "skipped", "disabled"})
LAYER_NAMES = (
    "runtime_evidence",
    "resource_registration",
    "bgp_announcement",
    "hosting_delivery",
    "request_target",
)


@dataclass(frozen=True)
class ClosureConfig:
    online: bool = True
    mode: str = ANALYSIS_MODE_PASSIVE
    max_targets: int = 6
    refresh: bool = False
    require_dynamic: bool | None = None
```

Implement target ranking from runtime evidence, payload/SNI hints, then static C2 confidence. Treat a valid capture file with no packets as failed, a public business candidate without target attribution as partial, and at least one target-attributed candidate as complete.

- [ ] **Step 4: Run pure-function tests**

Run: `python -m pytest -q tests/test_closure.py --basetemp E:/fxapk-testtmp/case-close-model-green`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```text
git add apkscan/core/closure.py tests/test_closure.py
git commit -m "feat: add case closure model and gates"
```

### Task 3: Reusable Enrichment and Passive Multi-Source Outcomes

**Files:**
- Create: `apkscan/enrichers/multisource.py`
- Create: `tests/test_multisource.py`
- Modify: `apkscan/core/registry.py`
- Modify: `apkscan/core/enrichment.py`
- Modify: `tests/test_two_phase_enrichment.py`

**Interfaces:**
- Adds: `BaseEnricher.case_close_only: bool = False`
- Produces: `enrich_selected_targets(endpoints, enrichers, *, mode, include_case_close, on_result=None) -> list[dict]`
- Produces: `SourceOutcome(provider: str, status: str, data: dict[str, object], error_type: str | None)`
- Produces: `configured_case_close_enrichers() -> list[BaseEnricher]`
- Each adapter returns normalized fields only and maps credentials absent to `disabled`, successful empty results to `no_record`, transport/auth/parse problems to `failed`, and records to `hit`.

- [ ] **Step 1: Write failing metadata and secret-redaction tests**

```python
def test_normal_pipeline_skips_case_close_only_enricher():
    enricher = FakeCaseCloseOnlyEnricher()
    ep = suspicious_ip("198.51.100.10")
    status = enrich_selected_targets(
        [ep], [enricher], mode="passive", include_case_close=False
    )
    assert enricher.calls == 0
    assert status == []


def test_adapter_failure_never_contains_secret(monkeypatch):
    monkeypatch.setenv("FXAPK_FOFA_KEY", "synthetic-secret-value")
    adapter = FofaPassiveEnricher(session=FailingSession("synthetic-secret-value"))
    result = adapter.enrich(suspicious_ip("198.51.100.10"))
    rendered = json.dumps(result.data, ensure_ascii=False) + str(result.error)
    assert "synthetic-secret-value" not in rendered
```

- [ ] **Step 2: Run focused tests and confirm failures**

Run: `python -m pytest -q tests/test_multisource.py tests/test_two_phase_enrichment.py --basetemp E:/fxapk-testtmp/case-close-multisource-red`

Expected: imports/signatures fail before production changes.

- [ ] **Step 3: Add the case-close-only gate and normalized adapter base**

```python
class BaseEnricher(ABC):
    name: str = ""
    applies_to: list[str] = []
    phase: str = "attribution"
    active: bool = False
    case_close_only: bool = False


@dataclass(frozen=True)
class SourceOutcome:
    provider: str
    status: str
    data: dict[str, object] = field(default_factory=dict)
    error_type: str | None = None
```

Implement generic passive JSON lookup behavior with `requests.Session`, bounded timeouts, provider-specific request builders/parsers, and sanitized error classes. Register RIPEstat BGP and optional FOFA, Quake, Hunter, ZoomEye, Censys, VirusTotal, OTX, and urlscan adapters. Existing Shodan, RDAP, DNS, WHOIS, certs, and web-check remain discoverable and are normalized by the closure service.

- [ ] **Step 4: Run focused enrichment tests**

Run: `python -m pytest -q tests/test_multisource.py tests/test_two_phase_enrichment.py tests/test_enrich_concurrency.py --basetemp E:/fxapk-testtmp/case-close-multisource-green`

Expected: all selected tests pass and ordinary enrichment does not call case-close-only providers.

- [ ] **Step 5: Commit**

```text
git add apkscan/core/registry.py apkscan/core/enrichment.py apkscan/enrichers/multisource.py tests/test_multisource.py tests/test_two_phase_enrichment.py
git commit -m "feat: add passive case close enrichment sources"
```

### Task 4: Closure Orchestration and Five-Layer Attribution

**Files:**
- Modify: `apkscan/core/closure.py`
- Modify: `apkscan/core/attribution.py`
- Modify: `tests/test_closure.py`
- Modify: `tests/test_attribution.py`

**Interfaces:**
- Produces: `close_report(report: Report, config: ClosureConfig, *, enrichers: Sequence[BaseEnricher] | None = None) -> dict[str, object]`
- Writes: `report.meta["closure"]`
- Consumes normalized endpoint enrichment keys: `ip_rdap`, `rdap`, `whois`, `dns`, `asn`, `ripestat_bgp`, `shodan`, and case-close-only provider names.
- Updates matching leads without replacing analyst notes or duplicating evidence lists.
- Reuses prior `hit`/`no_record` source outcomes when `refresh=False`; `refresh=True` repeats configured lookups and replaces only machine-generated source data.

- [ ] **Step 1: Write failing orchestration and idempotency tests**

```python
def test_runtime_ip_is_reenriched_and_gets_five_layers():
    report = report_with_endpoints(runtime_ip("198.51.100.10", attribution="target"))
    closure = close_report(report, ClosureConfig(online=True), enrichers=fake_full_enrichers())
    target = closure["targets"][0]
    assert set(target["layers"]) == set(LAYER_NAMES)
    assert target["layers"]["resource_registration"]["evidence"]["cidr"] == "198.51.100.0/24"
    assert target["layers"]["request_target"]["evidence"]["provider"] == "Example Hosting Ltd"


def test_close_report_is_idempotent():
    report = report_with_endpoints(runtime_ip("198.51.100.10", attribution="target"))
    close_report(report, ClosureConfig(online=False), enrichers=[])
    first = copy.deepcopy(report)
    close_report(report, ClosureConfig(online=False), enrichers=[])
    assert report == first
```

- [ ] **Step 2: Run focused tests and verify they fail**

Run: `python -m pytest -q tests/test_closure.py tests/test_attribution.py --basetemp E:/fxapk-testtmp/case-close-orchestrator-red`

Expected: five-layer evidence and `close_report` assertions fail.

- [ ] **Step 3: Implement orchestration and conservative layer assembly**

```python
def close_report(
    report: Report,
    config: ClosureConfig,
    *,
    enrichers: Sequence[BaseEnricher] | None = None,
) -> dict[str, object]:
    selected = select_targets(report, config.max_targets)
    if config.online:
        selected = _targets_requiring_refresh(selected, refresh=config.refresh)
        enrich_selected_targets(
            selected,
            list(enrichers) if enrichers is not None else discover_enrichers(),
            mode=config.mode,
            include_case_close=True,
        )
    targets = [assemble_target_closure(ep, report=report) for ep in selected]
    closure = evaluate_closure(
        report,
        targets,
        require_dynamic=config.require_dynamic,
    )
    report.meta["closure"] = closure
    _update_target_leads(report, targets)
    return closure
```

The layer assembler must not infer the actual app operator from an ASN or hosting banner. A parent allocation alone makes `hosting_delivery` partial; `request_target` is complete only when it names an executable provider/legal request target and the requested evidence fields.

- [ ] **Step 4: Run closure and attribution tests**

Run: `python -m pytest -q tests/test_closure.py tests/test_attribution.py tests/test_enricher_ip_rdap.py --basetemp E:/fxapk-testtmp/case-close-orchestrator-green`

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```text
git add apkscan/core/closure.py apkscan/core/attribution.py tests/test_closure.py tests/test_attribution.py
git commit -m "feat: orchestrate five layer case closure"
```

### Task 5: CLI Command, Strict Exit Codes, and Digest

**Files:**
- Create: `apkscan/commands/case.py`
- Create: `tests/test_case_cli.py`
- Modify: `apkscan/cli.py`
- Modify: `apkscan/report/digest.py`
- Modify: `apkscan/report/templates/report.html.j2`
- Modify: `tests/test_digest.py`
- Modify: `tests/test_report.py`

**Interfaces:**
- Produces Typer group: `case_app`
- Produces: `closure_exit_code(status: object) -> int`
- `case close` loads, closes, atomically writes, prints compact gaps/next actions, and exits according to strict mode.
- Digest includes `closure: {status, target_count, gaps, next_actions, source_summary}` without dumping source payloads.

- [ ] **Step 1: Write failing CLI exit and digest tests**

```python
@pytest.mark.parametrize(
    ("status", "expected"),
    [("complete", 0), ("partial", 5), ("failed", 6)],
)
def test_case_close_strict_exit_codes(monkeypatch, tmp_path, status, expected):
    report_path = write_minimal_report(tmp_path)
    monkeypatch.setattr(case_command, "close_report", lambda report, config: {"status": status})
    result = runner.invoke(app, ["case", "close", str(report_path), "--offline"])
    assert result.exit_code == expected


def test_digest_exposes_compact_closure_only():
    digest = build_digest({"meta": {"closure": synthetic_closure()}, "leads": []})
    assert digest["closure"]["status"] == "partial"
    assert "targets" not in digest["closure"]


def test_html_renders_closure_status_and_gaps(tmp_path):
    report = make_report()
    report.meta["closure"] = synthetic_closure()
    output = tmp_path / "report.html"
    report_html.render(report, str(output))
    rendered = output.read_text(encoding="utf-8")
    assert "案件闭环" in rendered
    assert "partial" in rendered
    assert "Origin" in rendered
```

- [ ] **Step 2: Run tests and confirm command is absent**

Run: `python -m pytest -q tests/test_case_cli.py tests/test_digest.py tests/test_report.py --basetemp E:/fxapk-testtmp/case-close-cli-red`

Expected: `case` command/import assertions fail.

- [ ] **Step 3: Implement command and compact output**

```python
case_app = typer.Typer(help="案件证据闭环编排。")


def closure_exit_code(status: object) -> int:
    if status == "complete":
        return 0
    if status == "partial":
        return 5
    return 6


@case_app.command("close")
def close_command(
    report_json: Path,
    online: bool = True,
    mode: str = ANALYSIS_MODE_PASSIVE,
    max_targets: int = 6,
    strict: bool = True,
    refresh: bool = False,
) -> None:
    report = load_report(report_json)
    closure = close_report(
        report,
        ClosureConfig(online, mode, max_targets, refresh),
    )
    write_report(report, report_json)
    _print_closure_summary(closure)
    code = closure_exit_code(closure.get("status"))
    if strict and code:
        raise typer.Exit(code=code)
```

Register with `app.add_typer(case_app, name="case")` and preserve existing commands.
Add a compact HTML section that iterates only normalized closure fields and never renders raw provider payloads.

- [ ] **Step 4: Run CLI and digest tests**

Run: `python -m pytest -q tests/test_case_cli.py tests/test_digest.py tests/test_report.py tests/test_cli_dynamic.py --basetemp E:/fxapk-testtmp/case-close-cli-green`

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```text
git add apkscan/commands/case.py apkscan/cli.py apkscan/report/digest.py apkscan/report/templates/report.html.j2 tests/test_case_cli.py tests/test_digest.py tests/test_report.py
git commit -m "feat: expose strict case close command"
```

### Task 6: Capture Quality and Auto Integration

**Files:**
- Modify: `apkscan/dynamic/capture.py`
- Modify: `apkscan/dynamic/merge.py`
- Modify: `apkscan/dynamic/auto.py`
- Modify: `apkscan/cli.py`
- Modify: `tests/test_capture.py`
- Modify: `tests/test_merge.py`
- Modify: `tests/test_auto.py`
- Modify: `tests/test_cli_dynamic.py`

**Interfaces:**
- Capture writes `capture_signals.quality` with `channel_ready`, `pcap_valid`, `packet_count`, `business_candidate_count`, `target_attributed_count`, and `dynamic_status`.
- `merge_and_rerender(..., closure_config: ClosureConfig | None = None)` invokes the same `close_report` service after all runtime merge steps and before rendering.
- `auto.run(..., strict_case: bool = False)` returns `status` and `closure`; strict mode makes incomplete closure visible to the CLI exit path without deleting reports.

- [ ] **Step 1: Write failing quality and auto status tests**

```python
def test_empty_floor_pcap_does_not_pass_dynamic_quality():
    quality = evaluate_capture_quality(
        {"channel_ready": True, "pcap_valid": False, "packet_count": 0}
    )
    assert quality["dynamic_status"] == "failed"


def test_auto_returns_partial_when_closure_is_partial(monkeypatch, tmp_path):
    monkeypatch.setattr(auto, "_run_closure", lambda *args, **kwargs: {"status": "partial"})
    result = run_synthetic_auto(tmp_path)
    assert result["status"] == "partial"
    assert result["closure"]["status"] == "partial"
```

- [ ] **Step 2: Run focused integration tests and verify failures**

Run: `python -m pytest -q tests/test_capture.py tests/test_merge.py tests/test_auto.py tests/test_cli_dynamic.py --basetemp E:/fxapk-testtmp/case-close-auto-red`

Expected: quality fields, merge parameter, or top-level auto status assertions fail.

- [ ] **Step 3: Add quality signals without breaking capture command compatibility**

```python
quality = evaluate_capture_quality(
    {
        "channel_ready": mitm_channel_ok or floor_handle is not None,
        "pcap_valid": bool(floor_summary and floor_summary.packet_count > 0),
        "packet_count": int(getattr(floor_summary, "packet_count", 0) or 0),
        "business_candidate_count": len(public_candidates),
        "target_attributed_count": n_target,
    }
)
capture_signals["quality"] = quality
```

Keep existing `capture.run()` `done` semantics for command compatibility. Feed closure configuration into merge/auto, return a top-level status, print it in `_print_auto_result`, and map `--strict-case` partial/failed to exit `5/6`.

- [ ] **Step 4: Run dynamic integration tests**

Run: `python -m pytest -q tests/test_capture.py tests/test_merge.py tests/test_auto.py tests/test_cli_dynamic.py --basetemp E:/fxapk-testtmp/case-close-auto-green`

Expected: all selected tests pass, including the pre-existing quiet-app capture contract.

- [ ] **Step 5: Commit**

```text
git add apkscan/dynamic/capture.py apkscan/dynamic/merge.py apkscan/dynamic/auto.py apkscan/cli.py tests/test_capture.py tests/test_merge.py tests/test_auto.py tests/test_cli_dynamic.py
git commit -m "feat: gate auto results on case closure"
```

### Task 7: Documentation, Security Scan, and Full Verification

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `docs/superpowers/plans/2026-07-15-case-close-implementation.md`

**Interfaces:**
- Documents the difference between static health, capture command completion, and `meta.closure.status`.
- Documents that CDN without Origin remains partial and that actual app operator attribution is separate from server-provider attribution.

- [ ] **Step 1: Add command and status documentation**

```text
fxapk case close out/sample.json --online --strict
fxapk auto sample.apk --strict-case
```

Describe exit codes `0/5/6`, source statuses, five-layer names, passive-only defaults, and the prohibition on interpreting infrastructure ownership as app operator ownership.

- [ ] **Step 2: Run focused regression tests**

Run: `python -m pytest -q -m "not slow" --basetemp E:/fxapk-testtmp/case-close-regression`

Expected: all non-slow tests pass.

- [ ] **Step 3: Run all quality gates**

```text
python -m ruff check apkscan tests
python -m pyright apkscan
python -m pytest -q --basetemp E:/fxapk-testtmp/case-close-full
```

Expected: ruff and pyright exit `0`; pytest passes with only explicitly skipped environment-dependent tests.

- [ ] **Step 4: Run the repository safety scan**

Run a tracked-diff scan for personal drive paths, case names, real targets, credential assignments, authorization headers, APK/PCAP/report artifacts, and high-entropy token-like strings. Inspect every match and remove any local-only content before commit.

Expected: only generic environment-variable names and synthetic reserved examples remain.

- [ ] **Step 5: Review the complete diff**

Check behavior regressions, exception paths, secret leakage, cache/idempotency, deterministic ordering, exit-code compatibility, optional dependency behavior, and the exact complete/partial/failed gates. Record findings in the local handoff; fix all P0/P1/P2 findings before delivery.

- [ ] **Step 6: Commit documentation and plan completion**

```text
git add README.md AGENTS.md docs/superpowers/plans/2026-07-15-case-close-implementation.md
git commit -m "docs: document case closure workflow"
```

- [ ] **Step 7: Prepare Claude handoff without pushing**

Create a local, untracked handoff containing branch name, commit list, quality-gate results, review findings, residual risks, and explicit instructions to push the isolated branch. Do not include secrets or case evidence, and do not push from the Codex session.
