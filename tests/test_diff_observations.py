"""Saved report comparisons must not turn missing observations into changes."""

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from fxapk.core.diff import diff_reports
from fxapk.core.models import Endpoint, Finding, Lead, LeadCategory, Report, Severity
from fxapk.report import json as report_json


@pytest.mark.parametrize(
    ("section", "row", "identity"),
    [
        ("leads", {"category": "example", "value": "synthetic"}, "value"),
        ("endpoints", {"kind": "domain", "value": "sample.example.invalid"}, "kind"),
        ("findings", {"id": "SYNTHETIC"}, "id"),
    ],
)
@pytest.mark.parametrize("bad", ["absent", "null", "object", "row", "identity"])
@pytest.mark.parametrize("reverse", [False, True])
def test_unknown_collection_does_not_invent_change(section, row, identity, bad, reverse):
    valid = {"endpoints": [{"kind": "domain", "value": "other.example.invalid"}]}
    valid[section] = [row]
    invalid = copy.deepcopy(valid)
    if bad == "absent":
        del invalid[section]
    elif bad == "null":
        invalid[section] = None
    elif bad == "object":
        invalid[section] = {}
    elif bad == "row":
        invalid[section] = [7]
    else:
        invalid[section][0][identity] = 7
    pair = (invalid, valid) if reverse else (valid, invalid)
    actual = diff_reports(*pair)
    assert actual[section]["added"] == actual[section]["removed"] == []
    assert actual[section]["comparison"]["status"] == "not_compared"
    assert actual[section]["comparison"]["old" if reverse else "new"]["state"] == (
        "missing" if bad == "absent" else "malformed"
    )
    if section != "endpoints":
        assert actual["endpoints"]["comparison"]["status"] == "compared_report_values"


def _manifest(target, *, package="example.synthetic", manifest_status="ran", anomaly=None):
    return {
        "meta": {
            "package_name": package,
            "min_sdk": 23,
            "target_sdk": target,
            "manifest_anomaly": anomaly,
        },
        "analyzer_status": [{"name": "manifest", "status": manifest_status}],
    }


def test_sdk_comparison_distinguishes_change_and_unchanged():
    diff = diff_reports(_manifest(32), _manifest(34))
    fields = diff["manifest_declarations"]["fields"]
    assert fields["target_sdk"] == {
        "state": "changed", "old": {"value": 32, "reason": ""},
        "new": {"value": 34, "reason": ""},
    }
    assert fields["min_sdk"]["state"] == "unchanged"
    assert "target_sdk" not in diff["meta_changes"]


@pytest.mark.parametrize("value", [None, True, "Tiramisu", "34", 0])
def test_no_sdk_default_when_not_observed(value):
    sdk = diff_reports(_manifest(value), _manifest(34))["manifest_declarations"]["fields"]
    assert sdk["target_sdk"]["state"] == "not_observed"
    assert sdk["target_sdk"]["old"] == {"value": None, "reason": "declaration_unobserved"}


@pytest.mark.parametrize("extra", [{"manifest_status": "error"}, {"anomaly": {"kind": "synthetic"}}])
def test_manifest_failure_does_not_compare_numeric_values(extra):
    sdk = diff_reports(_manifest(32), _manifest(34, **extra))["manifest_declarations"]["fields"]
    assert sdk["target_sdk"]["state"] == "not_observed"
    assert sdk["target_sdk"]["new"]["reason"] == "manifest_unobserved"


def test_only_same_package_reports_compare_declarations():
    result = diff_reports(_manifest(32), _manifest(34, package="example.synthetic.other"))
    assert result["manifest_declarations"] == {
        "status": "not_compared", "reason": "package_not_comparable", "fields": {},
    }


def test_empty_report_list_is_not_equivalent_to_a_missing_or_malformed_list() -> None:
    empty = {"findings": []}
    for incomplete, state in (({}, "missing"), ({"findings": "invalid"}, "malformed")):
        for old, new, side in ((incomplete, empty, "old"), (empty, incomplete, "new")):
            findings = diff_reports(old, new)["findings"]
            assert findings["added"] == findings["removed"] == findings["changed"] == []
            comparison = findings["comparison"]
            assert comparison["status"] == "not_compared"
            assert comparison[side]["state"] == state
            assert comparison["new" if side == "old" else "old"]["state"] == "recorded_empty"
    assert diff_reports(empty, empty)["findings"]["comparison"]["status"] == "compared_report_values"


def test_duplicate_manifest_observations_are_ambiguous_even_if_one_ran() -> None:
    old = _manifest(32)
    current = _manifest(34)
    current["analyzer_status"].append({"name": "manifest", "status": "error"})
    diff = diff_reports(old, current)["manifest_declarations"]
    assert diff["status"] == "not_compared"
    assert diff["fields"]["target_sdk"]["new"] == {"value": None, "reason": "manifest_unobserved"}


@pytest.mark.parametrize(
    ("new_has_list", "status", "new_state", "count"),
    [(False, "not_compared", "missing", 0), (True, "compared_report_values", "recorded_empty", 1)],
)
def test_saved_report_diff_cli_preserves_counts_and_explains_them(
    tmp_path: Path, new_has_list: bool, status: str, new_state: str, count: int,
) -> None:
    row = {"value": "sample.example.invalid", "kind": "domain"}
    old = {**_manifest(32), "endpoints": [row]}
    new = _manifest(34)
    if new_has_list:
        new["endpoints"] = []
    left, right = tmp_path / "old.json", tmp_path / "new.json"
    left.write_text(json.dumps(old), encoding="utf-8")
    right.write_text(json.dumps(new), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", "from fxapk.cli import main; main()",
         "diff", str(left), str(right), "--offline", "--report-details"],
        capture_output=True, text=True, encoding="utf-8", timeout=20,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["summary"]["endpoints_removed"] == count
    assert payload["endpoints"]["removed"] == ([row] if new_has_list else [])
    assert payload["endpoints"]["added"] == []
    comparison = payload["endpoints"]["comparison"]
    assert comparison["status"] == status
    assert comparison["new"]["state"] == new_state
    assert payload["manifest_declarations"]["fields"]["target_sdk"]["state"] == "changed"


def test_diff_reads_serialized_reports_without_losing_rule_instances(tmp_path: Path) -> None:
    def make_report(target_sdk: int, *, new: bool) -> Report:
        package = "example.synthetic"
        findings = [
            Finding("SYNTHETIC", "Fixture", Severity.LOW, "fixture", "first instance"),
        ]
        if new:
            findings.append(
                Finding("SYNTHETIC", "Fixture", Severity.LOW, "fixture", "second instance")
            )
        return Report(
            package_name=package,
            meta={"package_name": package, "min_sdk": 23, "target_sdk": target_sdk},
            leads=[Lead(LeadCategory.SDK_SERVICE, "fixture-sdk")],
            endpoints=[] if new else [Endpoint("sample.example.invalid", "domain")],
            findings=findings,
            analyzer_status=[
                {"name": "manifest", "status": "ran", "reason": ""},
                {"name": "endpoints", "status": "skipped" if new else "ran", "reason": "fixture"},
            ],
        )

    left, right = tmp_path / "old.json", tmp_path / "new.json"
    report_json.dump(make_report(32, new=False), str(left))
    report_json.dump(make_report(34, new=True), str(right))

    result = subprocess.run(
        [sys.executable, "-c", "from fxapk.cli import main; main()",
         "diff", str(left), str(right), "--offline", "--report-details"],
        capture_output=True, text=True, encoding="utf-8", timeout=20,
    )
    assert result.returncode == 0, result.stderr
    diff = json.loads(result.stdout)
    assert diff["summary"]["endpoints_removed"] == 1
    assert diff["summary"]["findings_added"] == 1
    assert diff["analysis_notes"]["new"] == {
        "state": "recorded", "failed": [], "skipped": ["endpoints"],
    }
    assert diff["findings"]["added"][0]["description"] == "second instance"
    assert diff["findings"]["removed"] == diff["findings"]["changed"] == []
    assert diff["leads"]["comparison"]["status"] == "compared_report_values"
    assert diff["leads"]["added"] == diff["leads"]["removed"] == []
    declarations = diff["manifest_declarations"]["fields"]
    assert declarations["min_sdk"]["state"] == "unchanged"
    assert declarations["target_sdk"] == {
        "state": "changed", "old": {"value": 32, "reason": ""}, "new": {"value": 34, "reason": ""},
    }


@pytest.mark.parametrize("state", ["error", "skipped"])
def test_diff_exposes_analysis_gap_without_altering_record_deltas(state: str) -> None:
    old = {"endpoints": [{"kind": "domain", "value": "sample.example.invalid"}]}
    new = {
        "endpoints": [],
        "analysis_status": "complete" if state == "skipped" else "partial",
        "analyzer_status": [
            {"name": "manifest", "status": "ran", "reason": ""},
            {"name": "endpoints", "status": state, "reason": "free form diagnostic"},
        ],
    }
    result = diff_reports(old, new)
    assert result["endpoints"]["comparison"]["status"] == "compared_report_values"
    assert result["summary"]["endpoints_removed"] == 1
    assert result["analysis_notes"] == {
        "old": {"state": "not_recorded", "failed": [], "skipped": []},
        "new": {
            "state": "recorded",
            "failed": ["endpoints"] if state == "error" else [],
            "skipped": ["endpoints"] if state == "skipped" else [],
        },
    }


@pytest.mark.parametrize(
    ("rows", "state"),
    [
        ([], "not_recorded"),
        (None, "invalid"),
        ([{"name": "manifest", "status": "unknown"}], "invalid"),
        ([{"name": "/private/location", "status": "error"}], "invalid"),
        ([
            {"name": "manifest", "status": "ran"},
            {"name": "manifest", "status": "error"},
        ], "invalid"),
    ],
)
def test_diff_does_not_invent_analysis_health(rows, state) -> None:
    diff = diff_reports({}, {"analyzer_status": rows})
    assert diff["analysis_notes"]["new"] == {"state": state, "failed": [], "skipped": []}


def test_diff_accepts_offline_review_task_ids_starting_with_a_hyphen() -> None:
    rows = [
        {"name": "offline_review:-trace", "status": "error"},
        {"name": "manifest", "status": "skipped"},
    ]
    notes = diff_reports({}, {"analyzer_status": rows})["analysis_notes"]["new"]
    assert notes == {
        "state": "recorded", "failed": ["offline_review:-trace"], "skipped": ["manifest"],
    }


def test_cli_details_preserve_java_coverage_evidence(tmp_path) -> None:
    import json
    import subprocess
    import sys


    def write(name, *, receipt=None, scheduler=None, endpoint=False):
        meta = {"package_name": "example.synthetic", "jadx_status": "ok"}
        if receipt is not None:
            meta["jadx_receipt"] = receipt
        if scheduler is not None:
            meta["analyzer_receipts"] = {"jadx": {"execution": scheduler}}
        path = tmp_path / (name + ".json")
        report_json.dump(Report(
            package_name="example.synthetic", meta=meta, leads=[], findings=[],
            endpoints=[Endpoint("sample.example.invalid", "domain")] if endpoint else [],
            analyzer_status=[{"name": "jadx", "status": "ran", "reason": ""}],
        ), str(path))
        return path

    def compare(left, right, *flags):
        result = subprocess.run(
            [sys.executable, "-c", "from fxapk.cli import main; main()",
             "diff", str(left), str(right), "--offline", *flags],
            capture_output=True, text=True, encoding="utf-8", timeout=20,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    old = write("old", endpoint=True)
    incomplete = {"schema": 1, "status": "partial", "complete": False,
                  "reason_codes": ["scan_limit_hit", "producer_partial", "scan_limit_hit",
                                   "raw_diagnostic", "/private/exception", {"bad": True}]}
    new = write("new", receipt=incomplete)
    default = compare(old, new)
    detail = compare(old, new, "--report-details")
    assert "coverage_observations" not in default
    optional = {"coverage_observations", "analysis_notes", "manifest_declarations"}
    assert {key: value for key, value in detail.items() if key not in optional} == default
    assert detail["summary"]["endpoints_removed"] == 1
    assert detail["analysis_notes"]["new"] == {"state": "recorded", "failed": [], "skipped": []}
    assert detail["coverage_observations"]["java"] == {
        "old": {"state": "unknown", "reason_codes": []},
        "new": {"state": "partial", "reason_codes": ["producer_partial", "scan_limit_hit"]},
    }
    complete = {"schema": 1, "status": "ok", "complete": True, "reason_codes": []}
    good = write("good", receipt=complete)
    timeout = write("timeout", receipt=complete, scheduler="scheduler_timeout")
    reverse = compare(timeout, good, "--report-details")
    assert reverse["coverage_observations"]["java"] == {
        "old": {"state": "timeout", "reason_codes": []},
        "new": {"state": "complete", "reason_codes": []},
    }

    input_gap = "producer_dex_input_read_error"
    recorded_gap = write("recorded-gap", receipt={
        "schema": 1, "status": "timeout", "complete": False,
        "reason_codes": ["producer_timeout", input_gap, "/private/exception"],
        "runs": [{"status": "timeout", "ownership_complete": True, "reason_codes": [input_gap]}],
    })
    observed = compare(good, recorded_gap, "--report-details")["coverage_observations"]["java"]
    assert observed["new"] == {"state": "timeout", "reason_codes": [input_gap]}

    output_gap = "producer_java_save_error"
    for confirmed in (False, True):
        partial = write(f"java-save-{confirmed}", receipt={
            "schema": 1, "status": "partial", "complete": False,
            "reason_codes": ["producer_partial", output_gap, "/private/exception"],
            "runs": [{
                "status": "partial", "ownership_complete": confirmed,
                "reason_codes": [output_gap, "synthetic.fixture.Blocked"],
            }],
        })
        detail = compare(good, partial, "--report-details")
        expected = [output_gap, "producer_partial"] if confirmed else ["producer_partial"]
        assert detail["coverage_observations"]["java"]["new"] == {
            "state": "partial", "reason_codes": expected,
        }
        assert "synthetic.fixture.Blocked" not in json.dumps(detail)


@pytest.mark.parametrize(("variant", "expected"), [
    ("byte-limit", ["source_file_truncated"]),
    ("read-failure", ["read_failed"]),
    ("reason-only", []),
    ("counter-only", []),
    ("bool-counter", []),
    ("conflicting-total", []),
    ("future-schema", []),
])
def test_cli_details_distinguishes_confirmed_java_file_gaps(
    tmp_path: Path, variant: str, expected: list[str],
) -> None:
    from typer.testing import CliRunner

    from fxapk.analyzers.jadx import _build_jadx_receipt
    from fxapk.cli import app

    is_read_failure = variant == "read-failure"
    scan = {
        "files_total": 2, "files_selected": 2, "files_scanned": 1 if is_read_failure else 2,
        "read_failed": 1 if is_read_failure else 0, "truncated_files": 0 if is_read_failure else 1,
    }
    receipt = _build_jadx_receipt(
        status="ok", runs=[{
            "options_digest": "synthetic", "ownership_complete": True, "termination_complete": True,
        }], scan=scan, cleanup={"complete": True}, analyzer_error=False,
    )
    if variant == "reason-only":
        receipt["scan"]["truncated_files"] = 0
    elif variant == "counter-only":
        receipt["reason_codes"] = []
    elif variant == "bool-counter":
        receipt["scan"]["truncated_files"] = True
    elif variant == "conflicting-total":
        receipt["scan"]["files_selected"] = 1
    elif variant == "future-schema":
        receipt["schema"] = 2
    receipt["reason_codes"].append("unstructured diagnostic")
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    for path, meta in ((old, {"jadx_status": "ok"}), (new, {"jadx_receipt": receipt})):
        report_json.dump(Report(package_name="example.synthetic", meta=meta, leads=[], endpoints=[], findings=[], analyzer_status=[]), str(path))

    runner = CliRunner()
    args = ["diff", str(old), str(new), "--offline"]
    regular = runner.invoke(app, args)
    detailed = runner.invoke(app, [*args, "--report-details"])
    assert regular.exit_code == detailed.exit_code == 0, (regular.output, detailed.output)
    assert "coverage_observations" not in json.loads(regular.stdout)
    assert json.loads(detailed.stdout)["coverage_observations"]["java"]["new"] == {
        "state": "partial", "reason_codes": expected,
    }


def test_saved_diff_does_not_compare_sdk_from_rejected_apk(tmp_path, monkeypatch) -> None:
    from typer.testing import CliRunner

    from fxapk import cli
    from fxapk.analyzers.manifest import ManifestAnalyzer
    from fxapk.core import pipeline
    from fxapk.core.models import AnalysisConfig
    from tests.conftest import FakeContext
    from tests.test_pipeline_stages import _stub_discovery

    _stub_discovery(monkeypatch, analyzers=[ManifestAnalyzer()])
    runner = CliRunner()

    def invoke(*args):
        result = runner.invoke(cli.app, list(args))
        assert result.exit_code == 0, result.output
        return json.loads(result.stdout)

    def report(sdk, *, verified=True):
        xml = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">'
            f'<uses-sdk android:targetSdkVersion="{sdk}"/><application/></manifest>'
        )
        context = FakeContext(manifest_xml=xml)
        context.apk_validation_ok = verified
        saved = pipeline.run(context, AnalysisConfig(online=False))
        assert saved.meta["target_sdk"] == sdk  # recorded, but not necessarily eligible
        assert any(row["name"] == "manifest" and row["status"] == "ran"
                   for row in saved.analyzer_status)
        path = tmp_path / f"{sdk}-{verified}.json"
        report_json.dump(saved, str(path))
        return str(path)

    old, valid, rejected = report(32), report(34), report(35, verified=False)
    assert invoke("digest", rejected)["visibility"]["sources"]["manifest"] == "unavailable"
    normal = invoke("diff", old, valid, "--offline", "--report-details")
    assert normal["manifest_declarations"]["fields"]["target_sdk"]["state"] == "changed"
    for left, right, side in ((old, rejected, "new"), (rejected, old, "old")):
        result = invoke("diff", left, right, "--offline", "--report-details")
        projection = result.pop("manifest_declarations")
        assert projection["status"] == "not_compared"
        target = projection["fields"]["target_sdk"]
        assert target["state"] == "not_observed"
        assert target[side] == {"value": None, "reason": "manifest_unobserved"}
        result.pop("analysis_notes")
        result.pop("coverage_observations")
        assert result == invoke("diff", left, right, "--offline")


@pytest.mark.parametrize(
    ("old_package", "new_package", "different", "invalid"),
    [
        ("com.example.old", "com.example.new", True, False),
        ("com.example.new", "com.example.old", True, False),
        ("com.example.same", "com.example.same", False, False),
        (None, "com.example.new", False, True),
        ("com.example.old", " ", False, True),
        (123, "com.example.new", False, True),
        (None, " ", False, False),
    ],
)
def test_cli_identifies_cross_package_reports_without_suppressing_deltas(
    tmp_path: Path, old_package: str | int | None, new_package: str, different: bool, invalid: bool,
) -> None:
    old_data = {
        "meta": {"package_name": old_package},
        "endpoints": [{"kind": "domain", "value": "synthetic.example.invalid"}],
    }
    new_data = {"meta": {"package_name": new_package}, "endpoints": []}
    files = (tmp_path / "old.json", tmp_path / "new.json")
    for path, data in zip(files, (old_data, new_data), strict=True):
        path.write_text(json.dumps(data), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "fxapk.cli", "diff", *map(str, files), "--offline"],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0, result.stderr
    assert ("包名不同" in result.stderr) is different
    assert ("包名记录不可用" in result.stderr) is invalid
    assert ("不能当作同一应用的版本变化" in result.stderr) is (different or invalid)
    assert "com.example." not in result.stderr
    expected = diff_reports(old_data, new_data)
    expected.pop("manifest_declarations")
    expected.pop("analysis_notes")
    assert json.loads(result.stdout) == expected


_PACKAGE_A = "com.example.fixture_a"
_PACKAGE_B = "com.example.fixture_b"
_PACKAGE_ALIAS = "com.example.stale"
_MISSING_PACKAGE = object()
_UNDERSCORE_A = "com._fixture"
_UNDERSCORE_B = "_example._fixture"
_MAX_LENGTH_PACKAGE = "a" + "b" * 252 + ".c"


@pytest.mark.parametrize(("old_names", "new_names", "warning", "compared"), [
    pytest.param((_PACKAGE_A, _PACKAGE_A), (_PACKAGE_A, _PACKAGE_A), None, True, id="same"),
    pytest.param((_PACKAGE_A, _PACKAGE_A), (_PACKAGE_B, _PACKAGE_B), "different", False, id="different"),
    pytest.param((_PACKAGE_A, _MISSING_PACKAGE), (_PACKAGE_B, _MISSING_PACKAGE), "different", False,
                 id="top-only-different"),
    pytest.param((_PACKAGE_A, _MISSING_PACKAGE), (_PACKAGE_A, _MISSING_PACKAGE), None, True, id="top-only-same"),
    pytest.param((_MISSING_PACKAGE, _PACKAGE_A), (_MISSING_PACKAGE, _PACKAGE_A), None, True, id="metadata-only"),
    pytest.param((_PACKAGE_A, _MISSING_PACKAGE), (_MISSING_PACKAGE, _PACKAGE_A), None, True, id="legacy-mixed"),
    pytest.param((_PACKAGE_A, _PACKAGE_A), (_PACKAGE_B, _PACKAGE_A), "conflict", False, id="conflict"),
    pytest.param((_PACKAGE_A, _PACKAGE_ALIAS), (_PACKAGE_B, _PACKAGE_ALIAS), "conflict", False, id="both-conflict"),
    pytest.param((_UNDERSCORE_A, _UNDERSCORE_A), (_UNDERSCORE_A, _UNDERSCORE_A), None, True,
                 id="underscore-same"),
    pytest.param((_UNDERSCORE_A, _UNDERSCORE_A), (_UNDERSCORE_B, _UNDERSCORE_B), "different", False,
                 id="underscore-different"),
    pytest.param(("android", _MISSING_PACKAGE), (_MISSING_PACKAGE, "android"), None, True,
                 id="historical-single-segment"),
    pytest.param((_MISSING_PACKAGE, _MISSING_PACKAGE), (_MISSING_PACKAGE, _MISSING_PACKAGE),
                 None, False, id="both-absent"),
    pytest.param((_MISSING_PACKAGE, "unknown"), (None, " "), None, False, id="no-valid-alias"),
    pytest.param(({}, _PACKAGE_A), (_PACKAGE_A, _PACKAGE_A), "invalid", False, id="malformed-top"),
    pytest.param((12, _PACKAGE_A), (False, _PACKAGE_B), "invalid", False, id="invalid-distinct-meta"),
    pytest.param((_PACKAGE_A, None), (_PACKAGE_A, _PACKAGE_A), "invalid", False, id="null-is-not-absent"),
    pytest.param((_PACKAGE_A, " "), (_PACKAGE_A, " "), "invalid", False, id="blank-is-not-identity"),
    pytest.param((_PACKAGE_A, "unknown"), (_PACKAGE_A, "unknown"), "invalid", False, id="unknown-is-not-identity"),
    pytest.param((_PACKAGE_A, "fixture bad identifier"), (_PACKAGE_A, "fixture bad identifier"),
                 "invalid", False, id="invalid-recorded-identifier"),
    pytest.param((_PACKAGE_A + "\n", _PACKAGE_A), (_PACKAGE_A, _PACKAGE_A), "invalid", False, id="fullmatch"),
    pytest.param((_MAX_LENGTH_PACKAGE, _MISSING_PACKAGE), (_MISSING_PACKAGE, _MAX_LENGTH_PACKAGE),
                 None, True, id="255-chars-allowed"),
    pytest.param((_MAX_LENGTH_PACKAGE + "d", _MISSING_PACKAGE), (_PACKAGE_A, _PACKAGE_A),
                 "invalid", False, id="256-chars-invalid"),
])
def test_cli_diff_agrees_on_saved_report_package_identity(
    tmp_path: Path, old_names: tuple[object, object], new_names: tuple[object, object],
    warning: str | None, compared: bool,
) -> None:
    files = (tmp_path / "old.json", tmp_path / "new.json")
    originals = []
    for path, names, sdk in zip(files, (old_names, new_names), (32, 34), strict=True):
        top, meta = names
        data = _manifest(sdk)
        if top is not _MISSING_PACKAGE:
            data["package_name"] = top
        if meta is _MISSING_PACKAGE:
            del data["meta"]["package_name"]
        else:
            data["meta"]["package_name"] = meta
        data["endpoints"] = [{"kind": "domain", "value": "fixture.example.invalid"}] if sdk == 32 else []
        raw = json.dumps(data).encode()
        path.write_bytes(raw)
        originals.append(raw)

    def run(*flags: str):
        result = subprocess.run(
            [sys.executable, "-B", "-m", "fxapk.cli", "diff", *map(str, files), "--offline", *flags],
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        assert result.returncode == 0, result.stderr
        assert ("包名不同" in result.stderr) is (warning == "different")
        assert ("包名记录冲突" in result.stderr) is (warning == "conflict")
        assert ("包名记录不可用" in result.stderr) is (warning == "invalid")
        assert result.stderr.count("不能当作同一应用的版本变化") == int(warning is not None)
        assert "com.example." not in result.stderr and "fixture bad identifier" not in result.stderr
        assert _UNDERSCORE_A not in result.stderr and _UNDERSCORE_B not in result.stderr
        return json.loads(result.stdout)

    default = run()
    details = run("--report-details")
    declarations = details.pop("manifest_declarations")
    details.pop("analysis_notes")
    details.pop("coverage_observations")
    assert details == default
    assert default["summary"]["endpoints_removed"] == 1
    if compared:
        assert declarations["status"] == "compared_report_values"
        assert declarations["fields"]["target_sdk"] == {
            "state": "changed", "old": {"value": 32, "reason": ""}, "new": {"value": 34, "reason": ""},
        }
    else:
        assert declarations == {"status": "not_compared", "reason": "package_not_comparable", "fields": {}}
    assert [path.read_bytes() for path in files] == originals
