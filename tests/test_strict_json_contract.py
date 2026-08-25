"""Report/package JSON boundaries reject non-standard non-finite numbers."""

from __future__ import annotations

import json

import pytest

from apkscan.core.json_contract import JsonContractError
from apkscan.core import case_package
from apkscan.core.case_package import create_case_package, verify_case_package
from apkscan.core.models import Report
from apkscan.core.report_io import load_report, write_report
from apkscan.report import json as report_json


def _typed_report(meta: dict) -> Report:
    return Report(
        package_name="x",
        meta=meta,
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_report_loader_rejects_nonfinite_json_constant(tmp_path, constant: str) -> None:  # noqa: ANN001
    path = tmp_path / "report.json"
    path.write_text(
        '{"schema_version":"1.2","package_name":"x","meta":{"bad":'
        + constant
        + "}}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-finite"):
        load_report(path)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_package_loader_rejects_nonfinite_json_constant(tmp_path, constant: str) -> None:  # noqa: ANN001
    manifest = tmp_path / "case-package.json"
    manifest.write_text('{"bad":' + constant + "}", encoding="utf-8")

    result = verify_case_package(manifest)

    assert result["status"] == "failed"
    assert any("non-finite" in issue for issue in result["issues"])


def test_report_atomic_writer_rejects_nonfinite_without_touching_target(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "report.json"
    original = b'{"preserve":true}'
    path.write_bytes(original)
    report = _typed_report({"bad": float("nan")})

    with pytest.raises(ValueError):
        write_report(report, path, render_existing_html=False)

    assert path.read_bytes() == original
    assert not path.with_suffix(path.suffix + ".tmp").exists()


def test_report_dump_rejects_nonfinite_without_touching_target(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "report.json"
    original = b'{"preserve":true}'
    path.write_bytes(original)

    with pytest.raises(ValueError):
        report_json.dump(_typed_report({"bad": float("inf")}), str(path))

    assert path.read_bytes() == original


def test_package_json_writer_rejects_nonfinite_before_creating_target(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "case-package.json"

    with pytest.raises(ValueError):
        case_package._write_new_json(path, {"bad": float("-inf")})

    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_nonfinite_report_cannot_create_phase1_package(tmp_path) -> None:  # noqa: ANN001
    report = tmp_path / "report.json"
    report.write_text(
        """{
          "schema_version": "1.2",
          "package_name": "x",
          "analysis_status": "complete",
          "meta": {
            "sample_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tool_version": "1.5.4",
            "ruleset_digest": "bbbbbbbbbbbbbbbb",
            "bad": NaN
          }
        }""",
        encoding="utf-8",
    )
    manifest = tmp_path / "case-package.json"

    # JSON 契约违例现在是独立的窄异常，携带固定文案与稳定错误码（不回显触发 token）。
    with pytest.raises(JsonContractError) as excinfo:
        create_case_package(
            report,
            manifest,
            case_id="case-001",
            producer="analyst-a",
        )
    assert excinfo.value.diagnostic_code == "non_finite_json_number"
    # 触发它的原始 token 来自不可信 JSON，不得回显。
    assert "NaN" not in excinfo.value.public_message

    assert not manifest.exists()


def test_finite_float_remains_valid_at_report_and_package_boundaries(tmp_path) -> None:  # noqa: ANN001
    report_path = tmp_path / "report.json"
    report = _typed_report(
        {
            "sample_sha256": "a" * 64,
            "tool_version": "1.5.4+local",
            "ruleset_digest": "b" * 16,
            "confidence_score": 0.75,
        }
    )
    write_report(report, report_path, render_existing_html=False)
    manifest = tmp_path / "case-package.json"

    loaded = load_report(report_path)
    create_case_package(
        report_path,
        manifest,
        case_id="case-001",
        producer="analyst-a",
    )

    assert loaded.meta["confidence_score"] == 0.75
    assert verify_case_package(manifest)["status"] == "verified"
    assert json.loads(report_path.read_text(encoding="utf-8"))["meta"][
        "confidence_score"
    ] == 0.75
