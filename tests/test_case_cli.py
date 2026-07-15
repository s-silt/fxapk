from __future__ import annotations

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.commands import case as case_command
from apkscan.core.models import Report
from apkscan.report import json as report_json

runner = CliRunner()


def _write_report(tmp_path) -> object:  # noqa: ANN001
    path = tmp_path / "report.json"
    report_json.dump(
        Report(
            package_name="com.example.synthetic",
            meta={},
            leads=[],
            endpoints=[],
            findings=[],
            analyzer_status=[],
        ),
        str(path),
    )
    return path


@pytest.mark.parametrize(
    ("status", "expected"),
    [("complete", 0), ("partial", 5), ("failed", 6)],
)
def test_case_close_strict_exit_codes(monkeypatch, tmp_path, status, expected) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)

    def fake_close(report, config):  # noqa: ANN001, ANN202
        closure = {
            "status": status,
            "targets": [],
            "gaps": ["synthetic gap"] if status != "complete" else [],
            "next_actions": [],
            "source_summary": {},
        }
        report.meta["closure"] = closure
        return closure

    monkeypatch.setattr(case_command, "close_report", fake_close)

    result = runner.invoke(cli.app, ["case", "close", str(report_path), "--offline"])

    assert result.exit_code == expected
    assert f"闭环状态：{status}" in result.output


def test_case_close_no_strict_keeps_partial_exit_zero(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)

    def fake_close(report, config):  # noqa: ANN001, ANN202
        closure = {
            "status": "partial",
            "targets": [],
            "gaps": ["synthetic gap"],
            "next_actions": ["resolve it"],
            "source_summary": {},
        }
        report.meta["closure"] = closure
        return closure

    monkeypatch.setattr(case_command, "close_report", fake_close)

    result = runner.invoke(
        cli.app,
        ["case", "close", str(report_path), "--offline", "--no-strict"],
    )

    assert result.exit_code == 0
    assert "synthetic gap" in result.output
    assert "resolve it" in result.output


def test_case_close_invalid_json_exits_one(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    result = runner.invoke(cli.app, ["case", "close", str(path), "--offline"])

    assert result.exit_code == 1
    assert "报告读取失败" in result.output


def test_closure_exit_code_is_fail_closed() -> None:
    assert case_command.closure_exit_code("complete") == 0
    assert case_command.closure_exit_code("partial") == 5
    assert case_command.closure_exit_code("failed") == 6
    assert case_command.closure_exit_code("unexpected") == 6
