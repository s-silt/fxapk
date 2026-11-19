from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from fxapk import cli
from fxapk.commands import case as case_command
from fxapk.core.models import Report
from fxapk.report import json as report_json
from tests.test_case_package import _passing_receipt

runner = CliRunner()


def _write_report(tmp_path, *, tool_version: str | None = None) -> object:  # noqa: ANN001
    path = tmp_path / "report.json"
    version = tool_version if tool_version is not None else "1.5.4"
    report_json.dump(
        Report(
            package_name="com.example.synthetic",
            meta={
                "sample_sha256": "a" * 64,
                "tool_version": version,
                "ruleset_digest": "b" * 16,
            },
            leads=[],
            endpoints=[],
            findings=[],
            analyzer_status=[],
        ),
        str(path),
    )
    return path


def test_case_close_warns_on_revision_mismatch_without_blocking(
    tmp_path,
) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path, tool_version="0.0.0-old")

    result = runner.invoke(
        cli.app,
        ["case", "close", str(report_path), "--offline", "--no-strict"],
    )

    assert result.exit_code == 0
    assert "分析修订与当前 fxapk 不一致" in result.stderr
    persisted = report_path.read_text(encoding="utf-8")
    assert '"closure"' in persisted
    assert "分析修订与当前 fxapk 不一致" not in persisted


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


def test_case_close_invalid_json_uses_strict_failure_exit(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    result = runner.invoke(cli.app, ["case", "close", str(path), "--offline"])

    assert result.exit_code == 6
    assert "报告读取失败" in result.output


def test_case_close_invalid_json_no_strict_remains_operational_error(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    result = runner.invoke(
        cli.app,
        ["case", "close", str(path), "--offline", "--no-strict"],
    )

    assert result.exit_code == 1
    assert "报告读取失败" in result.output


def test_case_close_refuses_future_schema_without_rewriting_file(tmp_path) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["schema_version"] = "9.0"
    original = json.dumps(payload, ensure_ascii=False, indent=2)
    report_path.write_text(original, encoding="utf-8")

    result = runner.invoke(cli.app, ["case", "close", str(report_path), "--offline"])

    assert result.exit_code == 6
    assert "报告读取失败" in result.output
    assert report_path.read_text(encoding="utf-8") == original


def test_case_close_internal_failure_uses_strict_failure_exit(
    monkeypatch, tmp_path, caplog
) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)

    def fail_close(report, config):  # noqa: ANN001, ANN202
        del report, config
        raise RuntimeError("sensitive-provider-detail")

    monkeypatch.setattr(case_command, "close_report", fail_close)

    result = runner.invoke(cli.app, ["case", "close", str(report_path), "--offline"])

    assert result.exit_code == 6
    assert "案件闭环执行失败（RuntimeError）" in result.output
    assert "sensitive-provider-detail" not in result.output
    # ★脱敏不变量：异常消息（可能夹带 provider 敏感响应片段）绝不进日志。
    assert "sensitive-provider-detail" not in caplog.text
    # ★但排障线索必须留：日志记异常调用栈位置（文件:行:函数），而非只有类型名。
    assert "closure failed (RuntimeError) at" in caplog.text
    assert "case.py:" in caplog.text  # 抛出点所在文件出现在帧位置里


def test_closure_exit_code_is_fail_closed() -> None:
    assert case_command.closure_exit_code("complete") == 0
    assert case_command.closure_exit_code("partial") == 5
    assert case_command.closure_exit_code("failed") == 6
    assert case_command.closure_exit_code("unexpected") == 6


def test_case_package_status_and_review_cli_keep_phase_boundary(tmp_path) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)
    package_path = tmp_path / "case-package.json"
    review_path = tmp_path / "case-review.json"

    packaged = runner.invoke(
        cli.app,
        [
            "case",
            "package",
            str(report_path),
            "--case-id",
            "case-001",
            "--producer",
            "analyst-a",
            "--out",
            str(package_path),
        ],
    )
    receipt_path = _passing_receipt(tmp_path, package_path)
    reviewed = runner.invoke(
        cli.app,
        [
            "case",
            "review",
            str(package_path),
            "--reviewer",
            "analyst-a",
            "--status",
            "accepted",
            "--out",
            str(review_path),
            "--gate-receipt",
            str(receipt_path),
        ],
    )
    shown = runner.invoke(
        cli.app,
        ["case", "status", str(package_path), "--review", str(review_path), "--json"],
    )

    assert packaged.exit_code == 0, packaged.output
    assert reviewed.exit_code == 0, reviewed.output
    assert shown.exit_code == 0, shown.output
    status = json.loads(shown.stdout)
    assert status["package_integrity"] == "verified"
    assert status["review"] == "accepted"


def test_case_review_refuses_missing_gate_receipt(tmp_path) -> None:  # noqa: ANN001
    report_path = _write_report(tmp_path)
    package_path = tmp_path / "case-package.json"
    review_path = tmp_path / "case-review.json"
    packaged = runner.invoke(
        cli.app,
        [
            "case", "package", str(report_path),
            "--case-id", "case-001", "--producer", "analyst-a", "--out", str(package_path),
        ],
    )
    assert packaged.exit_code == 0, packaged.output

    reviewed = runner.invoke(
        cli.app,
        [
            "case", "review", str(package_path),
            "--reviewer", "analyst-a", "--status", "accepted", "--out", str(review_path),
        ],
    )

    assert reviewed.exit_code == 2
    assert not review_path.exists()


@pytest.mark.parametrize(("failed_format", "strict", "exit_code"), [
    ("json", True, 6), ("html", True, 6), ("html", False, 1),
])
def test_case_close_distinguishes_json_and_html_delivery(
    tmp_path, monkeypatch, caplog, failed_format, strict, exit_code,
) -> None:
    from fxapk.core import report_io
    from fxapk.report import html as report_html

    path = _write_report(tmp_path)
    initial = path.read_bytes()
    sibling = path.with_suffix(".html")
    sibling.write_text("old inert HTML", encoding="utf-8")

    def calculate(report, _config):
        closure = {"status": "complete", "targets": [], "gaps": []}
        report.meta["closure"] = closure
        return closure

    def fail_before_replacement(*_, **__):
        raise OSError("do not print synthetic private output detail")

    monkeypatch.setattr(case_command, "close_report", calculate)
    if failed_format == "json":
        monkeypatch.setattr(report_io, "atomic_write_text", fail_before_replacement)
    else:
        monkeypatch.setattr(report_html, "render", fail_before_replacement)

    flags = ["--offline", "--strict" if strict else "--no-strict"]
    result = runner.invoke(cli.app, ["case", "close", str(path), *flags])
    assert result.exit_code == exit_code
    assert "do not print synthetic private output detail" not in result.output + caplog.text
    assert sibling.read_text(encoding="utf-8") == "old inert HTML"
    if failed_format == "html":
        assert json.loads(path.read_text())["meta"]["closure"]["status"] == "complete"
        assert "JSON 已写出" in result.output and "HTML 副本未写回" in result.output
    else:
        assert path.read_bytes() == initial
        assert "JSON 未写回" in result.output and "JSON 已写出" not in result.output
