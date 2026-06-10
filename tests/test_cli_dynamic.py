"""apkscan.cli 集成单元的单测：doctor 命令 + analyze --dynamic 运行时端点并回。

策略：全程不碰真机/真子进程/真流量。
- doctor 命令：用 typer.testing.CliRunner 调 ``app``，monkeypatch ``doctor.run``
  返回结构化结果，断言逐项打印 / fix_cmd 缩进 / ok=False → 退出码 1 / 模块缺失优雅退出。
- analyze --dynamic 的运行时并入：直接测 ``_run_dynamic_after_static`` /
  ``_merge_runtime_into_report``（惰性 import 的 unpack/capture/merge 在其源模块处
  monkeypatch），断言 capture done → 调 merge、skipped/error → 不调 merge、
  merge 异常不破坏静态报告、并入用的是 runtime_report.json 路径、新签名传 report+formats。

铁律呼应：cli 是唯一可 typer.echo 的薄包装；核心逻辑（doctor/merge）只返回结构化数据，
本测试锁定 cli 仅做打印 + 退出码 + 调度，不重复核心逻辑。
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import Report
from apkscan.dynamic import STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED

runner = CliRunner()


def _make_report(package_name: str = "com.x") -> Report:
    """构造字段齐全的最小 Report（Report 所有字段必填）。"""
    return Report(
        package_name=package_name,
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


# ---------------------------------------------------------------------------
# doctor 命令（薄包装 doctor.run）
# ---------------------------------------------------------------------------


def _patch_doctor_run(monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]) -> dict[str, Any]:
    """monkeypatch doctor.run 返回固定结构化结果，返回调用记录。"""
    from apkscan.dynamic import doctor

    calls: dict[str, Any] = {"called": False, "kwargs": None}

    def _fake_run(**kwargs: Any) -> dict[str, Any]:
        calls["called"] = True
        calls["kwargs"] = kwargs
        # 触发 on_progress 一次，确认 cli 传入的回调可被安全调用（GUI-ready 呼应）。
        cb = kwargs.get("on_progress")
        if cb is not None:
            cb("探测中")
        return result

    monkeypatch.setattr(doctor, "run", _fake_run)
    return calls


def test_doctor_command_invokes_doctor_run(monkeypatch):
    result = {
        "ok": True,
        "items": [{"name": "在线设备", "ok": True, "detail": "在线设备：emulator-5554", "fix_cmd": []}],
    }
    calls = _patch_doctor_run(monkeypatch, result)

    res = runner.invoke(cli.app, ["doctor", "--serial", "emulator-5554", "--no-fix"])

    assert res.exit_code == 0
    assert calls["called"] is True
    # 新签名透传 serial / auto_fix / on_progress。
    assert calls["kwargs"]["serial"] == "emulator-5554"
    assert calls["kwargs"]["auto_fix"] is False
    assert callable(calls["kwargs"]["on_progress"])


def test_doctor_command_prints_items_and_fix_cmd(monkeypatch):
    result = {
        "ok": False,
        "items": [
            {"name": "在线设备", "ok": True, "detail": "在线设备：x", "fix_cmd": []},
            {
                "name": "mitmproxy 已安装",
                "ok": False,
                "detail": "mitmproxy 不在 PATH",
                "fix_cmd": ["pip install mitmproxy"],
            },
        ],
    }
    _patch_doctor_run(monkeypatch, result)

    res = runner.invoke(cli.app, ["doctor"])

    out = res.output
    assert "[OK]" in out
    assert "[FAIL]" in out
    assert "在线设备" in out
    assert "mitmproxy 已安装" in out
    # fix_cmd 应缩进列出。
    assert "pip install mitmproxy" in out


def test_doctor_command_exit_1_when_not_ok(monkeypatch):
    result = {
        "ok": False,
        "items": [{"name": "在线设备", "ok": False, "detail": "无设备", "fix_cmd": ["adb devices"]}],
    }
    _patch_doctor_run(monkeypatch, result)

    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 1


def test_doctor_command_exit_0_when_ok(monkeypatch):
    result = {"ok": True, "items": [{"name": "在线设备", "ok": True, "detail": "x", "fix_cmd": []}]}
    _patch_doctor_run(monkeypatch, result)

    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 0


def test_doctor_cleans_adb_on_exit(monkeypatch):
    """问题 1：doctor 命令退出时 finally 收掉自起的 adb server（含体检失败 rc=1 路径）。"""
    from apkscan.core import tools

    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))
    # 体检失败（ok=False → rc=1），断言即便 raise typer.Exit(1) 仍穿过 finally 收 adb。
    _patch_doctor_run(
        monkeypatch,
        {"ok": False, "items": [{"name": "在线设备", "ok": False, "detail": "无", "fix_cmd": []}]},
    )

    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 1
    assert calls["n"] == 1  # finally 收了一次（rc=1 也收）


def test_doctor_killserver_repair_cmd_unchanged(monkeypatch):
    """问题 1：doctor 给用户的 "adb kill-server && adb start-server" 修复命令字符串语义未破坏。

    cleanup 收的是程序自起的 server（kill_adb_server），不触碰 doctor 结构化结果里的
    fix_cmd 字符串——它仍是给用户复制的命令。这里断言该修复命令仍能原样打印。
    """
    from apkscan.core import tools

    monkeypatch.setattr(tools, "kill_adb_server", lambda: True)
    _patch_doctor_run(
        monkeypatch,
        {
            "ok": False,
            "items": [
                {
                    "name": "在线设备",
                    "ok": False,
                    "detail": "未检测到在线设备",
                    "fix_cmd": ["adb devices", "adb kill-server && adb start-server"],
                }
            ],
        },
    )
    res = runner.invoke(cli.app, ["doctor"])
    assert "adb kill-server && adb start-server" in res.output


def test_analyze_cleans_adb_on_exit(monkeypatch):
    """问题 1：analyze（纯静态）退出时也无条件收 adb（device.has_device 每次都会起 server）。"""
    from apkscan.core import tools

    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))
    monkeypatch.setattr(cli.device, "has_device", lambda: False)
    monkeypatch.setattr("apkscan.core.pipeline.run", lambda ctx, config: _make_report("com.x"))
    monkeypatch.setattr(cli, "load_app", lambda *a, **k: _FakeCtx())
    monkeypatch.setattr(cli, "_write_reports", lambda *a, **k: None)

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(cli.app, ["analyze", apk, "--offline"])
    assert res.exit_code == 0
    assert calls["n"] == 1  # 纯静态 analyze 也收（has_device 探测已可能起过 server）


def test_doctor_command_module_missing_graceful_exit(monkeypatch):
    """惰性 import doctor 失败 → 打印"该功能未安装" + 退出码 1，不崩。"""
    import builtins
    import sys

    # 让 `from apkscan.dynamic import doctor` 触发真正的 ImportError：
    # 先把已缓存的 doctor 子模块逐出 sys.modules（含父包属性），再在 __import__ 层拦截。
    monkeypatch.delitem(sys.modules, "apkscan.dynamic.doctor", raising=False)
    import apkscan.dynamic as _dyn

    monkeypatch.delattr(_dyn, "doctor", raising=False)

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        fromlist = args[2] if len(args) >= 3 else kwargs.get("fromlist")
        if name == "apkscan.dynamic.doctor" or (
            name == "apkscan.dynamic" and fromlist and "doctor" in fromlist
        ):
            raise ImportError("simulated missing doctor")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 1
    assert "该功能未安装" in res.output


# ---------------------------------------------------------------------------
# analyze --dynamic：运行时端点并回（直接测内部函数，惰性 import 在源模块处打桩）
# ---------------------------------------------------------------------------


def _patch_unpack(monkeypatch: pytest.MonkeyPatch) -> None:
    """脱壳桩：返回 done，不做实事（让 _run_dynamic_after_static 走到 capture 段）。"""
    from apkscan.dynamic import unpack

    monkeypatch.setattr(
        unpack,
        "run",
        lambda *a, **k: {
            "status": STATUS_DONE,
            "reason": "",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )


def _patch_capture(monkeypatch: pytest.MonkeyPatch, result: dict[str, Any]) -> dict[str, Any]:
    """抓包桩：返回给定 DynamicResult，记录被调。"""
    from apkscan.dynamic import capture

    calls: dict[str, Any] = {"called": False}

    def _fake_run(package: str, *a: Any, **k: Any) -> dict[str, Any]:
        calls["called"] = True
        calls["package"] = package
        return result

    monkeypatch.setattr(capture, "run", _fake_run)
    return calls


def _patch_merge(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """merge 桩：记录 load_runtime_endpoints / merge_and_rerender 的入参。"""
    from apkscan.dynamic import merge

    calls: dict[str, Any] = {
        "load_path": None,
        "rerender_called": False,
        "rerender_args": None,
    }

    def _fake_load(path: str) -> list:
        calls["load_path"] = path
        return ["EP"]  # 非空哨兵，断言被透传给 merge_and_rerender

    def _fake_rerender(
        report: Report,
        endpoints: list,
        out_dir: str,
        base: str = "report",
        *,
        formats: Any = None,
        on_progress: Any = None,
    ) -> dict[str, Any]:
        calls["rerender_called"] = True
        calls["rerender_args"] = {
            "report": report,
            "endpoints": endpoints,
            "out_dir": out_dir,
            "base": base,
            "formats": formats,
        }
        if on_progress is not None:
            on_progress("并入运行时端点 ...")
        return {"merged": 2, "new_leads": 1, "total_endpoints": 5, "report_paths": [f"{out_dir}/{base}.json"]}

    monkeypatch.setattr(merge, "load_runtime_endpoints", _fake_load)
    monkeypatch.setattr(merge, "merge_and_rerender", _fake_rerender)
    return calls


def _done_result(report_paths: list[str] | None = None) -> dict[str, Any]:
    return {
        "status": STATUS_DONE,
        "reason": "抓包完成",
        "artifacts": [],
        "playbook": [],
        "report_paths": report_paths or [],
    }


def test_analyze_dynamic_no_device_skips(monkeypatch):
    """无设备时 analyze --dynamic 不进入动态段、不调 capture/merge。"""
    from apkscan.dynamic import capture

    cap_calls = _patch_capture(monkeypatch, _done_result())
    merge_calls = _patch_merge(monkeypatch)
    _patch_unpack(monkeypatch)

    # device.has_device 在 cli 中决定是否进入动态段。
    monkeypatch.setattr(cli.device, "has_device", lambda: False)
    # pipeline.run 用轻量桩，避免真跑分析器。
    monkeypatch.setattr(
        "apkscan.core.pipeline.run", lambda ctx, config: _make_report("com.x")
    )
    monkeypatch.setattr(cli, "load_app", lambda *a, **k: _FakeCtx())
    monkeypatch.setattr(cli, "_write_reports", lambda *a, **k: None)

    # 用一个临时存在的文件冒充 apk（analyze 的 Argument exists=True）。
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(cli.app, ["analyze", apk, "--dynamic", "--offline"])
    assert res.exit_code == 0
    assert "未检测到在线设备" in res.output
    assert cap_calls["called"] is False
    assert merge_calls["rerender_called"] is False
    _ = capture  # silence unused


def test_analyze_dynamic_calls_merge_after_capture_done(monkeypatch):
    _patch_unpack(monkeypatch)
    _patch_capture(monkeypatch, _done_result())
    merge_calls = _patch_merge(monkeypatch)

    report = _make_report("com.x")
    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", report, ["html", "json"], "demo")

    assert merge_calls["rerender_called"] is True
    args = merge_calls["rerender_args"]
    assert args["report"] is report  # 同一 report 就地补全
    assert args["out_dir"] == "outdir"
    assert args["base"] == "demo"  # base 透传给重渲（与静态写出同 base，避免两套报告）
    assert args["formats"] == ["html", "json"]
    assert args["endpoints"] == ["EP"]  # load_runtime_endpoints 的结果被透传


def test_analyze_dynamic_merge_uses_runtime_report_json(monkeypatch):
    """capture report_paths 含 runtime_report.json 时，优先用它作为并入来源路径。"""
    _patch_unpack(monkeypatch)
    _patch_capture(monkeypatch, _done_result(report_paths=["outdir/runtime_report.json"]))
    merge_calls = _patch_merge(monkeypatch)

    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", _make_report("com.x"), ["json"], "demo")

    assert merge_calls["load_path"] == "outdir/runtime_report.json"


def test_analyze_dynamic_merge_falls_back_to_out_dir_path(monkeypatch):
    """capture report_paths 不含 runtime_report.json 时回退 out/runtime_report.json。"""
    import os

    _patch_unpack(monkeypatch)
    _patch_capture(monkeypatch, _done_result(report_paths=[]))
    merge_calls = _patch_merge(monkeypatch)

    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", _make_report("com.x"), ["json"], "demo")

    assert merge_calls["load_path"] == os.path.join("outdir", "runtime_report.json")


@pytest.mark.parametrize("status", [STATUS_SKIPPED, STATUS_ERROR])
def test_analyze_dynamic_capture_skipped_does_not_call_merge(monkeypatch, status):
    _patch_unpack(monkeypatch)
    _patch_capture(
        monkeypatch,
        {
            "status": status,
            "reason": "缺前置",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )
    merge_calls = _patch_merge(monkeypatch)

    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", _make_report("com.x"), ["json"], "demo")

    assert merge_calls["rerender_called"] is False


def test_analyze_dynamic_merge_exception_does_not_break_static_report(monkeypatch):
    """merge 抛异常时被 cli 兜住，不向上冒泡（已产出静态报告不受影响）。"""
    from apkscan.dynamic import merge

    _patch_unpack(monkeypatch)
    _patch_capture(monkeypatch, _done_result())

    def _boom_load(path: str) -> list:
        raise RuntimeError("merge load exploded")

    monkeypatch.setattr(merge, "load_runtime_endpoints", _boom_load)

    # 不应抛出。
    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", _make_report("com.x"), ["json"], "demo")


def test_analyze_dynamic_capture_exception_does_not_call_merge(monkeypatch):
    """capture.run 抛异常时 cli 兜住并 return，不调 merge。"""
    from apkscan.dynamic import capture

    _patch_unpack(monkeypatch)
    merge_calls = _patch_merge(monkeypatch)

    def _boom_run(*a: Any, **k: Any) -> dict[str, Any]:
        raise RuntimeError("capture exploded")

    monkeypatch.setattr(capture, "run", _boom_run)

    cli._run_dynamic_after_static("a.apk", "com.x", "outdir", _make_report("com.x"), ["json"], "demo")
    assert merge_calls["rerender_called"] is False


def test_analyze_dynamic_no_package_skips_capture_and_merge(monkeypatch):
    """包名为空 → 跳过抓包（capture 需包名），自然不调 merge。"""
    _patch_unpack(monkeypatch)
    cap_calls = _patch_capture(monkeypatch, _done_result())
    merge_calls = _patch_merge(monkeypatch)

    cli._run_dynamic_after_static("a.apk", "", "outdir", _make_report("com.x"), ["json"], "demo")

    assert cap_calls["called"] is False
    assert merge_calls["rerender_called"] is False


def test_run_dynamic_after_static_new_signature_passes_report_and_formats(monkeypatch):
    """新签名 _run_dynamic_after_static(apk, package, out, report, formats, base) 把
    report+formats+base 透传给 merge_and_rerender。"""
    _patch_unpack(monkeypatch)
    _patch_capture(monkeypatch, _done_result())
    merge_calls = _patch_merge(monkeypatch)

    report = _make_report("com.sig")
    formats = ["html", "json", "pdf"]
    cli._run_dynamic_after_static("a.apk", "com.sig", "od", report, formats, "myapk")

    args = merge_calls["rerender_args"]
    assert args["report"] is report
    assert args["formats"] == formats
    assert args["base"] == "myapk"  # base 透传，merge 重渲用同 base


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _FakeCtx:
    """load_app 返回值的最小替身（analyze 用到 package_name / platform）。"""

    package_name = "com.x"
    platform = "android"
