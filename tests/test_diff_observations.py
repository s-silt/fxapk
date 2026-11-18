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
         "diff", str(left), str(right), "--offline"],
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
         "diff", str(left), str(right), "--offline"],
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
