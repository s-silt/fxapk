"""Presentation-only auto contracts; no orchestration, APKs, or devices."""
from __future__ import annotations

from typing import get_args

import pytest

from fxapk.cli import _print_auto_result
from fxapk.core.report_delivery import ReportDelivery
from fxapk.dynamic.auto import StepStatus, _finish_run, _step


def test_all_documented_step_states_keep_distinct_labels(capsys):
    labels = {"done": "[OK]", "skipped": "[SKIP]", "error": "[ERR]", "degraded": "[DEGRADED]"}
    assert set(labels) == set(get_args(StepStatus))
    steps = [{"name": name, "status": name, "detail": ""} for name in labels]
    steps.append({"name": "newer status", "status": "unexpected", "detail": ""})
    _print_auto_result({"steps": steps, "closure": {"status": "complete"}})
    result = capsys.readouterr()
    for name, tag in labels.items():
        assert any(line.startswith(tag) and line.endswith(f" {name}") for line in result.out.splitlines())
    assert any(line.startswith("[?]") and line.endswith(" newer status") for line in result.out.splitlines())
    assert result.err == ""


def test_completed_closure_and_later_success_do_not_hide_required_write_failure(capsys):
    failed = ReportDelivery(("json",), (), ("json",), ())
    later = ReportDelivery(("json",), ("json",), (), ())
    payload = _finish_run(
        status="complete", closure={"status": "complete"}, strict_case=False,
        steps=[_step("first stage", "error", "known reason"), _step("later stage", "done", "")],
        report_paths=["synthetic.json"], package_name="", out_dir="",
        delivery_sink=[failed, later],
    )
    _print_auto_result(payload)
    output = capsys.readouterr()
    assert "first stage：known reason" in output.out and "later stage" in output.out
    assert "案件闭环：complete" in output.out
    assert "报告写出：必需格式曾写出失败（json）" in output.out
    assert "synthetic.json" in output.out and output.err == ""


@pytest.mark.parametrize("written", [("json",), ()])
def test_explicit_optional_skip_is_not_mislabeled_as_a_required_format_failure(capsys, written):
    delivery = ReportDelivery(("json", "pdf") if written else ("pdf",), written, (), ("pdf",))
    _print_auto_result({"report_delivery": delivery})
    output = capsys.readouterr().out
    assert "报告写出：可选 PDF 已跳过" in output
    assert "必需格式曾写出失败" not in output
    assert ("未写出请求的报告" in output) is not bool(written)


def test_cancellation_and_legacy_success_do_not_invent_steps_or_delivery(capsys):
    _print_auto_result({
        "status": "cancelled",
        "steps": [{"name": "synthetic", "status": "skipped", "detail": "not selected"}],
        "closure": {"status": "not_run"},
    })
    output = capsys.readouterr().out
    assert "[SKIP] synthetic：not selected" in output and "案件闭环：not_run" in output
    assert "后续步骤：未执行（已取消）" in output
    assert "报告写出：" not in output
    _print_auto_result({"steps": [], "report_paths": ["synthetic.json"], "closure": {"status": "complete"}})
    assert capsys.readouterr().out == (
        "\n===== 步骤摘要 =====\n\n包名：(未知)  输出目录：\n报告（1）：\n"
        "  - synthetic.json\n\n案件闭环：complete\n"
    )


def test_delivery_summary_uses_only_known_format_labels(capsys):
    delivery = ReportDelivery(("json",), (), ("json", "fixture-only-nonformat"), ())
    _print_auto_result({"report_delivery": delivery})
    said = capsys.readouterr().out
    assert "报告写出：必需格式曾写出失败（json）" in said
    assert "fixture-only-nonformat" not in said


def test_later_pdf_write_is_not_described_as_still_skipped(capsys):
    delivery = ReportDelivery(("pdf",), ("pdf",), (), ("pdf",))
    _print_auto_result({"report_delivery": delivery, "report_paths": ["synthetic.pdf"]})
    result = capsys.readouterr()
    assert "synthetic.pdf" in result.out
    assert "报告写出：" not in result.out
    assert not result.err


@pytest.mark.parametrize(
    ("terminal", "closure_status", "failed", "written", "skipped", "exit_code"),
    [
        ("complete", "complete", ("json",), ("json",), (), 1),
        ("complete", "complete", (), ("json",), ("pdf",), 0),
        ("cancelled", "not_run", ("json",), (), (), 130),
    ],
)
def test_cli_shell_keeps_terminal_exit_precedence(
    monkeypatch, tmp_path, terminal, closure_status, failed, written, skipped, exit_code,
):
    from typer.testing import CliRunner

    from fxapk import cli
    from fxapk.dynamic import auto

    def no_process(*_args, **_kwargs):
        pytest.fail("presentation test attempted to start a subprocess")

    monkeypatch.setattr("subprocess.Popen", no_process)
    monkeypatch.setattr(cli, "_adb_owned_at_start", lambda: False)
    monkeypatch.setattr(cli, "_cleanup_adb_quiet", lambda _owned: None)
    adc = ReportDelivery(("json", "pdf"), written, failed, skipped)
    payload = _finish_run(
        status=terminal, closure={"status": closure_status}, strict_case=True,
        steps=[_step("fixture stage", "degraded", "")], report_paths=[],
        package_name="", out_dir="", delivery_sink=[adc],
    )
    monkeypatch.setattr(auto, "run", lambda *_args, **_kwargs: payload)
    dummy = tmp_path / "dummy.apk"
    dummy.write_bytes(b"not an APK; CLI existence check only")
    result = CliRunner().invoke(cli.app, ["auto", str(dummy), "--offline", "--no-fix", "--strict-case"])
    assert result.exit_code == exit_code, result.output
    assert f"案件闭环：{closure_status}" in result.stdout
    assert "[DEGRADED] fixture stage" in result.stdout
    assert ("必需报告写出失败" in result.stderr) == (exit_code == 1)


@pytest.mark.parametrize("bad_paths", ["fixture-path-not-a-list", ["good.json", 123]])
def test_malformed_result_boundary_does_not_invent_success_or_absence(capsys, bad_paths):
    _print_auto_result({
        "steps": 123,
        "report_paths": bad_paths,
        "report_delivery": "fixture-not-a-delivery",
        "closure": {"status": "not_run"},
    })
    output = capsys.readouterr().out
    assert "步骤摘要：步骤列表格式非预期" in output
    assert "报告路径列表格式非预期，不判断是否已写出" in output
    assert "报告写出：回执格式非预期" in output
    assert "未产出报告" not in output and "报告（" not in output
    assert "fixture-not-a-delivery" not in output and "fixture-path-not-a-list" not in output
    assert "案件闭环：not_run" in output
