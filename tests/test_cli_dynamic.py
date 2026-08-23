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

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import Report
from apkscan.dynamic import STATUS_DEGRADED, STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED


@pytest.fixture(autouse=True)
def _isolate_adb(monkeypatch: pytest.MonkeyPatch) -> None:
    # P0-5：默认起手无 adb server（本次自起、归我们收）——让 cleanup 的 kill 断言不依赖跑测
    # 机器上是否恰好有 adb server 在 5037 监听；需测"外部已存在不杀"的用例在自身内覆写为 True。
    from apkscan.core import tools

    monkeypatch.setattr(tools, "adb_server_running", lambda *a, **k: False)

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


def test_raise_exit_degraded_is_code_3():
    """★ 复审#5：status=degraded → 退出码 3（脚本调用方区分"降级无产出"，不当成功）；done 不抛。"""
    import typer

    with pytest.raises(typer.Exit) as ei:
        cli._raise_exit_for_status(STATUS_DEGRADED)
    assert ei.value.exit_code == 3
    cli._raise_exit_for_status(STATUS_DONE)  # done 不抛（正常返回 0）


def test_cleanup_adb_quiet_skips_kill_when_not_owned(monkeypatch):
    """★ P0-5：owned=False（起手时已有外部/先前 server）→ 收尾【绝不】调 kill_adb_server。"""
    from apkscan.core import tools

    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))
    cli._cleanup_adb_quiet(owned=False)
    assert calls["n"] == 0  # 不归我们、不杀
    cli._cleanup_adb_quiet(owned=True)
    assert calls["n"] == 1  # 归我们、收一次


def test_command_does_not_kill_preexisting_external_adb(monkeypatch):
    """★ P0-5：命令起手时已有外部 adb server（adb_server_running=True）→ 退出收尾不杀，
    避免误杀外部或仍在 pull 落盘 floor.pcap 的 adb。"""
    from apkscan.core import tools

    monkeypatch.setattr(tools, "adb_server_running", lambda *a, **k: True)  # 外部已在跑
    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))
    _patch_doctor_run(
        monkeypatch,
        {"ok": True, "items": [{"name": "在线设备", "ok": True, "detail": "x", "fix_cmd": []}]},
    )
    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 0
    assert calls["n"] == 0  # 外部 server 未被杀


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
    monkeypatch.setattr(cli, "load_apk", lambda *a, **k: _FakeCtx())
    monkeypatch.setattr(cli, "_write_reports", lambda *a, **k: None)

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(cli.app, ["analyze", apk, "--offline"])
    assert res.exit_code == 0
    assert calls["n"] == 1  # 纯静态 analyze 也收（has_device 探测已可能起过 server）


# ---------------------------------------------------------------------------
# 取证完整性：analyze 写 evidence_manifest + sample_sha256 + <base>.sha256 旁文件
# ---------------------------------------------------------------------------


def _stub_analyze_static(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    """把 analyze 的设备/加载/流水线打桩成纯静态、无设备、不收 adb 真动作。"""
    from apkscan.core import tools

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    monkeypatch.setattr(cli.device, "has_device", lambda: False)
    monkeypatch.setattr("apkscan.core.pipeline.run", lambda ctx, config: report)
    monkeypatch.setattr(cli, "load_apk", lambda *a, **k: _FakeCtx())


def test_analyze_writes_evidence_manifest_and_sample_sha256(monkeypatch, tmp_path):
    """analyze 跑完，report.meta 含 evidence_manifest（含真实 sha256）与顶层 sample_sha256。"""
    import hashlib

    report = _make_report("com.x")
    _stub_analyze_static(monkeypatch, report)

    captured: dict[str, Any] = {}
    real_write = cli._write_reports

    def _spy_write(rep, out_dir, formats, base):
        captured["report"] = rep
        return real_write(rep, out_dir, formats, base)

    monkeypatch.setattr(cli, "_write_reports", _spy_write)

    apk = tmp_path / "evil.apk"
    apk.write_bytes(b"PK\x03\x04 fake apk bytes for fingerprint")
    expected_sha = hashlib.sha256(apk.read_bytes()).hexdigest()

    res = runner.invoke(cli.app, ["analyze", str(apk), "--offline", "--out", str(tmp_path / "out")])
    assert res.exit_code == 0

    rep = captured["report"]
    manifest = rep.meta["evidence_manifest"]
    assert manifest["sha256"] == expected_sha
    assert manifest["tool_version"]  # 工具版本已写入
    assert rep.meta["sample_sha256"] == expected_sha  # 顶层快捷键


def test_analyze_writes_sha256_sidecar(monkeypatch, tmp_path):
    """<base>.sha256 旁文件生成：每行 ``<sha256>  <文件名>``（对标 sha256sum）。"""
    import hashlib

    report = _make_report("com.x")
    _stub_analyze_static(monkeypatch, report)

    out_dir = tmp_path / "out"
    apk = tmp_path / "evil.apk"
    apk.write_bytes(b"PK\x03\x04 fake apk bytes")

    res = runner.invoke(
        cli.app, ["analyze", str(apk), "--offline", "--fmt", "json", "--out", str(out_dir)]
    )
    assert res.exit_code == 0

    # base = apk 名去后缀 = "evil"
    json_path = out_dir / "evil.json"
    sidecar = out_dir / "evil.sha256"
    assert json_path.is_file()
    assert sidecar.is_file()

    line = sidecar.read_text(encoding="utf-8").strip()
    expected = hashlib.sha256(json_path.read_bytes()).hexdigest()
    # 行内含产物 sha256 与文件名（sha256sum 风格：哈希 + 双空格 + 名）
    assert expected in line
    assert "evil.json" in line
    assert f"{expected}  evil.json" in line


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
        runtime_report_path: str | None = None,
    ) -> dict[str, Any]:
        calls["rerender_called"] = True
        calls["rerender_args"] = {
            "report": report,
            "endpoints": endpoints,
            "out_dir": out_dir,
            "base": base,
            "formats": formats,
            "runtime_report_path": runtime_report_path,
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
    monkeypatch.setattr(cli, "load_apk", lambda *a, **k: _FakeCtx())
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
    assert merge_calls["rerender_args"]["runtime_report_path"] == "outdir/runtime_report.json"


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


def test_resolve_out_defaults_to_apk_dir(tmp_path: Path) -> None:
    """未给 --out → 默认落到 APK 同目录下的 out/；显式 --out 原样（相对/绝对都不动）。"""
    apk = tmp_path / "sub" / "sample.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"x")
    assert cli._resolve_out(None, apk) == str(apk.resolve().parent / "out")
    assert cli._resolve_out("myout", apk) == "myout"
    assert cli._resolve_out("/abs/out", apk) == "/abs/out"


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
# capture-plan：--json 输出结构化决策（供引擎 / Codex 机器可读消费）
# ---------------------------------------------------------------------------


def test_capture_plan_json_emits_structured_decision(tmp_path: Path) -> None:
    """capture-plan --json 输出纯 JSON 结构化决策（floor_first/预算/秒退阈值/信号）。"""
    import json as _json

    rep = tmp_path / "report.json"
    rep.write_text(
        _json.dumps({"meta": {"crypto_recipe": {"algo": "AES", "key": "x"}}}), encoding="utf-8"
    )
    result = runner.invoke(cli.app, ["capture-plan", str(rep), "--json"])
    assert result.exit_code == 0
    payload = _json.loads(result.stdout)  # 纯 JSON，无人读表头
    assert payload["floor_first"] is True
    assert payload["prefer_offline_decrypt"] is True
    assert payload["total_budget_sec"] == 3600
    assert payload["frida_retreat_threshold"] == 3  # 非加固 → 默认阈值
    assert payload["signals"]["has_crypto_recipe"] is True
    assert payload["reasons"]
    assert "离线" in result.stdout  # 中文未转义 → ensure_ascii=False 契约（机器/人读均友好）


def test_capture_plan_json_packed_lowers_threshold(tmp_path: Path) -> None:
    """--json 端到端锁住『秒退阈值随信号变化』：加固样本 → frida_retreat_threshold=2。"""
    import json as _json

    rep = tmp_path / "report.json"
    rep.write_text(
        _json.dumps({"findings": [{"id": "PACK-DETECTED", "category": "packing"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(cli.app, ["capture-plan", str(rep), "--json"])
    assert result.exit_code == 0
    payload = _json.loads(result.stdout)
    assert payload["frida_retreat_threshold"] == 2
    assert payload["signals"]["packed"] is True
    assert payload["expect_native_protocol"] is True  # 无端点键 → 预判 native


def test_capture_plan_default_still_prints_text_steps(tmp_path: Path) -> None:
    """默认（无 --json）仍打印人读文本打法——向后兼容不破坏。"""
    import json as _json

    rep = tmp_path / "report.json"
    rep.write_text(_json.dumps({}), encoding="utf-8")
    result = runner.invoke(cli.app, ["capture-plan", str(rep)])
    assert result.exit_code == 0
    assert "抓包打法" in result.stdout


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _FakeCtx:
    """load_apk 返回值的最小替身（analyze 用到 package_name / platform）。"""

    package_name = "com.x"
    platform = "android"


# ---------------------------------------------------------------------------
# 组 A · 修复 1：capture/unpack/repackage 业务失败返回非零 exit code
#   STATUS_ERROR → 1；STATUS_SKIPPED → 2（缺 frida/mitmproxy/root，零产出高发）；正常 → 0。
# ---------------------------------------------------------------------------


def _patch_capture_cmd(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    """给 `fxapk capture` 命令桩：capture.run 返回给定 status 的 DynamicResult。"""
    from apkscan.core import tools
    from apkscan.dynamic import capture

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    monkeypatch.setattr(
        capture,
        "run",
        lambda *a, **k: {
            "status": status,
            "reason": "桩",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )


@pytest.mark.parametrize(
    "status,expected",
    [(STATUS_DONE, 0), (STATUS_ERROR, 1), (STATUS_SKIPPED, 2)],
)
def test_capture_cmd_exit_code_by_status(monkeypatch, status, expected):
    _patch_capture_cmd(monkeypatch, status)
    res = runner.invoke(cli.app, ["capture", "com.x", "--out", "out", "--duration", "10"])
    assert res.exit_code == expected


@pytest.mark.parametrize(
    "status,expected",
    [(STATUS_DONE, 0), (STATUS_ERROR, 1), (STATUS_SKIPPED, 2)],
)
def test_unpack_cmd_exit_code_by_status(monkeypatch, tmp_path, status, expected):
    from apkscan.dynamic import unpack

    monkeypatch.setattr(
        unpack,
        "run",
        lambda *a, **k: {
            "status": status,
            "reason": "桩",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK\x03\x04")
    res = runner.invoke(cli.app, ["unpack", str(apk), "--out", str(tmp_path / "o")])
    assert res.exit_code == expected


@pytest.mark.parametrize(
    "status,expected",
    [(STATUS_DONE, 0), (STATUS_ERROR, 1), (STATUS_SKIPPED, 2)],
)
def test_repackage_cmd_exit_code_by_status(monkeypatch, tmp_path, status, expected):
    from apkscan.dynamic import repackage

    monkeypatch.setattr(
        repackage,
        "run",
        lambda *a, **k: {
            "status": status,
            "reason": "桩",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK\x03\x04")
    res = runner.invoke(cli.app, ["repackage", str(apk), "--out", str(tmp_path / "o")])
    assert res.exit_code == expected


def test_capture_cmd_still_cleans_adb_on_nonzero(monkeypatch):
    """业务失败（skipped→rc=2）仍穿过 finally 收 adb server。"""
    from apkscan.core import tools
    from apkscan.dynamic import capture

    calls = {"n": 0}
    monkeypatch.setattr(tools, "kill_adb_server", lambda: calls.__setitem__("n", calls["n"] + 1))
    monkeypatch.setattr(
        capture,
        "run",
        lambda *a, **k: {
            "status": STATUS_SKIPPED,
            "reason": "缺 frida",
            "artifacts": [],
            "playbook": [],
            "report_paths": [],
        },
    )
    res = runner.invoke(cli.app, ["capture", "com.x"])
    assert res.exit_code == 2
    assert calls["n"] == 1  # rc=2 也收 adb


# ---------------------------------------------------------------------------
# 组 A · 修复 2：capture --out 默认口径与 analyze/unpack 一致（不再是相对 cwd 的裸 "out"）
# ---------------------------------------------------------------------------


def test_capture_out_default_resolves_absolute(monkeypatch):
    """不传 --out 时 capture 把 out 解析成绝对路径（与 analyze/unpack 的确定性口径一致），
    而非相对 cwd 的裸字符串 "out"。"""
    from apkscan.core import tools
    from apkscan.dynamic import capture

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    seen: dict[str, Any] = {}

    def _fake_run(package: str, *, out: str, duration: int, serial=None, mode="both", **_kw) -> dict[str, Any]:
        seen["out"] = out
        return _done_result()

    monkeypatch.setattr(capture, "run", _fake_run)
    res = runner.invoke(cli.app, ["capture", "com.x"])
    assert res.exit_code == 0
    assert Path(seen["out"]).is_absolute()  # 已绝对化，口径确定（不再相对 cwd 的裸 "out"）
    assert Path(seen["out"]).name == "out"


def test_cli_capture_rejects_native_antidetect(monkeypatch):
    """★CLI fail-closed：--antidetect native 在调用动态模块前以 exit 2 拒绝。"""
    from apkscan.core import tools

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    res = runner.invoke(cli.app, ["capture", "com.x", "--antidetect", "native"])
    assert res.exit_code == 2


def test_cli_capture_threads_behavior_flags(monkeypatch):
    """★CLI 接线锁：--allow-behavior-modification --antidetect java 透传给 capture.run。

    _fake_run 用显式参数（非 **kw 吞掉）——CLI 不透传则默认 False/off，seen 不匹配即红。
    """
    from apkscan.core import tools
    from apkscan.dynamic import capture

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    seen: dict[str, Any] = {}

    def _fake_run(package: str, *, out: str, duration: int, serial=None, mode="both", allow_behavior_modification=False, antidetect="off") -> dict[str, Any]:
        seen["allow"] = allow_behavior_modification
        seen["antidetect"] = antidetect
        return _done_result()

    monkeypatch.setattr(capture, "run", _fake_run)
    res = runner.invoke(
        cli.app, ["capture", "com.x", "--allow-behavior-modification", "--antidetect", "java"]
    )
    assert res.exit_code == 0
    assert seen == {"allow": True, "antidetect": "java"}


def test_resolve_out_cwd_absolutizes(tmp_path: Path, monkeypatch) -> None:
    """capture 无样本文件 → 用 cwd 基准把裸 out 解析成绝对路径；显式路径原样绝对化。"""
    monkeypatch.chdir(tmp_path)
    assert cli._resolve_out_cwd(None) == str((tmp_path / "out").resolve())
    assert cli._resolve_out_cwd("myout") == str((tmp_path / "myout").resolve())


# ---------------------------------------------------------------------------
# 组 A · 修复 3：--duration 下限 min=1，<1 直接报错（不产出 0-endpoint 空报告）
# ---------------------------------------------------------------------------


def test_capture_duration_zero_rejected(monkeypatch):
    """--duration 0 → typer 参数校验拒绝（非零退出），不进入 capture.run。"""
    from apkscan.core import tools
    from apkscan.dynamic import capture

    monkeypatch.setattr(tools, "kill_adb_server", lambda: None)
    called = {"n": 0}
    monkeypatch.setattr(capture, "run", lambda *a, **k: called.__setitem__("n", called["n"] + 1) or _done_result())

    res = runner.invoke(cli.app, ["capture", "com.x", "--duration", "0"])
    assert res.exit_code != 0
    assert called["n"] == 0  # 参数校验先拦，未触达 capture.run


def test_capture_duration_one_accepted(monkeypatch):
    """--duration 1 是下限，仍合法。"""
    _patch_capture_cmd(monkeypatch, STATUS_DONE)
    res = runner.invoke(cli.app, ["capture", "com.x", "--duration", "1"])
    assert res.exit_code == 0


# ---------------------------------------------------------------------------
# 组 A · 修复 4：probe-leads / pcap-leads --into 后若同目录有 report.html 则重渲
# ---------------------------------------------------------------------------


def _write_min_report_json(
    path: Path,
    leads: list[dict[str, Any]],
    *,
    meta: dict[str, Any] | None = None,
) -> None:
    """写一份最小 report.json（字段与 report/json.py 序列化同构，供 --into 合并 + 重渲）。"""
    import json as _json

    payload = {
        "package_name": "com.x",
        "meta": dict(meta or {}),
        "leads": leads,
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "enricher_status": [],
    }
    path.write_text(_json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_probe_leads_into_warns_before_mutating_old_report(tmp_path: Path) -> None:
    """探针回灌会按当前判据改报告；旧修订必须先告警，但不得阻断真实合并。"""
    import json as _json

    rp = tmp_path / "report.json"
    _write_min_report_json(
        rp, leads=[], meta={"tool_version": "0.0.0-old", "sample_sha256": "0" * 64}
    )
    log = tmp_path / "probe.log"
    log.write_text(
        "[http][LEAD] GET https://backend.example.test/api",
        encoding="utf-8",
    )

    res = runner.invoke(
        cli.app,
        ["probe-leads", str(log), "--into", str(rp), "--sample-sha", "0" * 64],
    )

    assert res.exit_code == 0
    assert "分析修订与当前 fxapk 不一致" in res.stderr
    assert _json.loads(rp.read_text(encoding="utf-8"))["meta"]["runtime_merged"] is True


def test_pcap_leads_into_warns_before_mutating_old_report(
    monkeypatch, tmp_path: Path
) -> None:
    """PCAP 解析可替换，报告合并保持真实，验证告警与写入能同时发生。"""
    import json as _json

    from apkscan.dynamic import pcap_ingest

    rp = tmp_path / "report.json"
    _write_min_report_json(rp, leads=[], meta={"tool_version": "0.0.0-old"})
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00")
    summary = pcap_ingest.PcapSummary(dns_queries={"backend.example.test"})
    monkeypatch.setattr(pcap_ingest, "parse_pcap", lambda _path: summary)

    res = runner.invoke(cli.app, ["pcap-leads", str(pcap), "--into", str(rp)])

    assert res.exit_code == 0
    assert "分析修订与当前 fxapk 不一致" in res.stderr
    assert _json.loads(rp.read_text(encoding="utf-8"))["meta"]["runtime_merged"] is True


def _flow_pair(ip: str, port: int = 30110):
    """一条有双向载荷的 TCP 流，足以产出 IP Lead。"""
    from apkscan.dynamic import pcap_ingest

    return [
        pcap_ingest.Flow(
            proto="tcp", src_ip="10.0.0.2", src_port=50000, dst_ip=ip, dst_port=port,
            packets=8, bytes_=800, payload_bytes=400, first_ts=1.0, last_ts=2.0,
            flags={"syn", "ack", "psh"},
        ),
        pcap_ingest.Flow(
            proto="tcp", src_ip=ip, src_port=port, dst_ip="10.0.0.2", dst_port=50000,
            packets=8, bytes_=900, payload_bytes=500, first_ts=1.1, last_ts=2.1,
            flags={"synack", "ack", "psh"},
        ),
    ]


def test_pcap_leads_ledger_agrees_with_report_on_attribution(
    monkeypatch, tmp_path: Path
) -> None:
    """★ 一条命令的三份产物必须用同一份归因结论。

    此前只有 --into 传了 app_attr：报告里已判"不属目标应用"的节点，
    Markdown 台账仍把它列在调证锚点下、JSON 台账没有任何归因字段——
    同一次执行产出互相冲突的材料，台账会继续把背景流量当案件线索。
    """
    import json as _json

    from apkscan.dynamic import pcap_ingest, socket_attr

    ip = "100.64.9.30"
    rp, pcap = tmp_path / "report.json", tmp_path / "cap.pcap"
    md, js, snap = tmp_path / "ledger.md", tmp_path / "ledger.json", tmp_path / "uid_sockets.txt"
    _write_min_report_json(rp, leads=[])
    pcap.write_bytes(b"\x00")
    snap.write_text("fake", encoding="utf-8")
    monkeypatch.setattr(
        pcap_ingest, "parse_pcap", lambda _path: pcap_ingest.PcapSummary(flows=_flow_pair(ip))
    )
    monkeypatch.setattr(
        socket_attr, "load_socket_tables",
        lambda _paths: (type("T", (), {"target_uid": 10271})(), ["uid_sockets.txt"]),
    )
    monkeypatch.setattr(
        socket_attr, "attribute_remote_endpoints",
        lambda _res, _table: {
            f"tcp/{ip}:30110": {
                "attribution": "unattributed", "is_target_app": False, "score": 0.0,
            }
        },
    )

    res = runner.invoke(cli.app, [
        "pcap-leads", str(pcap), "--uid-sockets", str(snap),
        "--md", str(md), "--json", str(js), "--into", str(rp),
    ])
    assert res.exit_code == 0, res.output

    report = _json.loads(rp.read_text(encoding="utf-8"))
    report_sources = {
        ev.get("source")
        for lead in report["leads"] if ip in str(lead.get("value"))
        for ev in lead.get("source_refs") or []
    }
    assert report_sources == {"runtime-derived"}, "前置：报告侧应已降档"

    ledger_md = md.read_text(encoding="utf-8")
    assert "不属目标应用" in ledger_md, f"Markdown 台账未标注归因结论：\n{ledger_md}"

    ledger = _json.loads(js.read_text(encoding="utf-8"))
    assert ledger["uid_attributed"] is True
    [entry] = [e for e in ledger["endpoints"] if ip in str(e.get("value"))]
    assert entry["source"] == "runtime-derived"
    assert entry["runtime_contact"] is False
    [remote] = [e for e in ledger["remote_endpoints"] if e.get("ip") == ip]
    assert remote["target_attributed"] is False


def test_pcap_leads_ledger_marks_unattributed_run(monkeypatch, tmp_path: Path) -> None:
    """没做 UID 归因时，台账要明说"未归因"，不得让人误读成"已确认属本样本"。"""
    import json as _json

    from apkscan.dynamic import pcap_ingest

    ip = "100.64.9.31"
    pcap, md, js = tmp_path / "cap.pcap", tmp_path / "ledger.md", tmp_path / "ledger.json"
    pcap.write_bytes(b"\x00")
    monkeypatch.setattr(
        pcap_ingest, "parse_pcap", lambda _path: pcap_ingest.PcapSummary(flows=_flow_pair(ip))
    )

    res = runner.invoke(cli.app, [
        "pcap-leads", str(pcap), "--no-uid-sockets", "--md", str(md), "--json", str(js),
    ])
    assert res.exit_code == 0, res.output

    assert "本次未做 UID 归因" in md.read_text(encoding="utf-8")
    ledger = _json.loads(js.read_text(encoding="utf-8"))
    assert ledger["uid_attributed"] is False
    [remote] = [e for e in ledger["remote_endpoints"] if e.get("ip") == ip]
    assert "target_attributed" not in remote, "没做归因不得写 target_attributed（缺失≠否定）"


def _fake_socket_table(monkeypatch, attr: dict) -> None:
    """把 UID 归因替换成给定结果，免去构造真实 socket 快照。"""
    from apkscan.dynamic import socket_attr

    monkeypatch.setattr(
        socket_attr, "load_socket_tables",
        lambda _paths: (type("T", (), {"target_uid": 10271})(), ["uid_sockets.txt"]),
    )
    monkeypatch.setattr(socket_attr, "attribute_remote_endpoints", lambda _res, _table: attr)


def test_pcap_leads_dns_only_domain_is_not_counted_as_denied(
    monkeypatch, tmp_path: Path
) -> None:
    """纯 DNS 域名没有承载连接，不得被算进"经归因判定不属于目标应用"。

    ★这是**回归锁**，不是差异锁：实测当前纯 DNS 域名的 lead 同样带 `runtime-pcap` 证据，
    所以 `not is_runtime_contact` 与 `is_attribution_denied` 在这条路径上得数相同，
    把 CLI 改回宽判据本用例也不会红。留着是为了钉住"DNS 查询名不是否定证据"这个语义——
    若哪天 DNS 域名 lead 的来源标签变了（比如改钉一个非 observed-contact 来源），
    终端与台账会立刻开始把"查过这个名字"报成"归因判否"，本用例会在那时变红。
    """
    from apkscan.dynamic import pcap_ingest

    ip = "100.64.9.32"
    pcap, md, snap = tmp_path / "cap.pcap", tmp_path / "l.md", tmp_path / "uid_sockets.txt"
    pcap.write_bytes(b"\x00")
    snap.write_text("fake", encoding="utf-8")
    monkeypatch.setattr(
        pcap_ingest, "parse_pcap",
        lambda _p: pcap_ingest.PcapSummary(
            flows=_flow_pair(ip), dns_queries={"queried.example.test"}
        ),
    )
    # 唯一的接入节点确属目标；DNS 域名没有承载连接
    _fake_socket_table(monkeypatch, {
        f"tcp/{ip}:30110": {"attribution": "confirmed", "is_target_app": True, "score": 0.95}
    })

    res = runner.invoke(cli.app, [
        "pcap-leads", str(pcap), "--uid-sockets", str(snap), "--md", str(md),
    ])
    assert res.exit_code == 0, res.output
    assert "不属于目标应用" not in res.output, f"终端误计了纯 DNS 域名：{res.output}"
    assert "不属目标应用" not in md.read_text(encoding="utf-8")


def test_pcap_leads_empty_attribution_is_not_reported_as_unattributed_run(
    monkeypatch, tmp_path: Path
) -> None:
    """★「做了归因但没有可归因远端」≠「没做归因」。

    纯 DNS 采集 + 有效 socket 快照时，归因表是空 dict。若把它塌成假值，
    终端会先说"UID 归因……0 个接入节点"，台账却写"本次未做 UID 归因"——自相矛盾。
    """
    import json as _json

    from apkscan.dynamic import pcap_ingest

    pcap, md, js = tmp_path / "cap.pcap", tmp_path / "l.md", tmp_path / "l.json"
    snap = tmp_path / "uid_sockets.txt"
    pcap.write_bytes(b"\x00")
    snap.write_text("fake", encoding="utf-8")
    monkeypatch.setattr(
        pcap_ingest, "parse_pcap",
        lambda _p: pcap_ingest.PcapSummary(dns_queries={"only.example.test"}),
    )
    _fake_socket_table(monkeypatch, {})  # 做了归因，但没有远端可归

    res = runner.invoke(cli.app, [
        "pcap-leads", str(pcap), "--uid-sockets", str(snap), "--md", str(md), "--json", str(js),
    ])
    assert res.exit_code == 0, res.output
    assert "本次未做 UID 归因" not in md.read_text(encoding="utf-8"), "空归因表被当成了未归因"
    assert _json.loads(js.read_text(encoding="utf-8"))["uid_attributed"] is True


def test_rerender_html_from_report_json_rebuilds_leads(tmp_path: Path) -> None:
    """_rerender_html_if_present 从改后的 report.json 重建 Report 并覆盖写 report.html，
    新 lead 值出现在 html 里。"""
    rp = tmp_path / "report.json"
    hp = tmp_path / "report.html"
    _write_min_report_json(rp, leads=[])
    hp.write_text("<html>OLD</html>", encoding="utf-8")

    # 模拟 --into 已把新线索写进 report.json。
    _write_min_report_json(
        rp,
        leads=[
            {
                "category": "DOMAIN",
                "value": "evil-c2.example.com",
                "subject": None,
                "where_to_request": "注册商",
                "evidence_to_obtain": [],
                "confidence": "HIGH",
                "source_refs": [
                    {"source": "runtime", "location": "probe", "snippet": "", "observed_at": None}
                ],
                "notes": "",
                "advice": "建议调证",
            }
        ],
    )

    out = cli._rerender_html_if_present(str(rp))
    assert out == str(hp)
    html = hp.read_text(encoding="utf-8")
    assert "OLD" not in html  # 已重渲覆盖
    assert "evil-c2.example.com" in html  # 新线索进了 html


def test_rerender_html_noop_when_no_html(tmp_path: Path) -> None:
    """同目录无 report.html → 不重渲、不新建（返回空串）。"""
    rp = tmp_path / "report.json"
    _write_min_report_json(rp, leads=[])
    out = cli._rerender_html_if_present(str(rp))
    assert out == ""
    assert not (tmp_path / "report.html").exists()


def test_probe_leads_into_rerenders_html(monkeypatch, tmp_path: Path):
    """probe-leads --into 改了 report.json 后，若同目录有 report.html 则重渲（内容随之更新）。"""
    from apkscan.dynamic import probe_ingest

    rp = tmp_path / "report.json"
    # 身份门要求 --into 目标先存在且带 sample_sha256；_fake_merge 随后会整体覆写它。
    _write_min_report_json(rp, leads=[], meta={"sample_sha256": "0" * 64})
    hp = tmp_path / "report.html"
    hp.write_text("<html>STALE</html>", encoding="utf-8")

    def _fake_merge(report_json_path: str, leads: list) -> int:
        # 模拟合并：把一条新线索写进 report.json。
        _write_min_report_json(
            Path(report_json_path),
            leads=[
                {
                    "category": "IP",
                    "value": "203.0.113.9",
                    "subject": None,
                    "where_to_request": "IDC",
                    "evidence_to_obtain": [],
                    "confidence": "HIGH",
                    "source_refs": [
                        {"source": "runtime", "location": "probe", "snippet": "", "observed_at": None}
                    ],
                    "notes": "",
                    "advice": "建议调证",
                }
            ],
        )
        return 1

    monkeypatch.setattr(probe_ingest, "parse_probe_log", lambda text: [])
    monkeypatch.setattr(probe_ingest, "dedup", lambda leads: leads)
    monkeypatch.setattr(probe_ingest, "build_ledger_md", lambda leads: "台账")
    monkeypatch.setattr(probe_ingest, "merge_into_report_json", _fake_merge)

    log = tmp_path / "probe.log"
    log.write_text("[LEAD] x", encoding="utf-8")

    res = runner.invoke(
        cli.app,
        ["probe-leads", str(log), "--into", str(rp), "--sample-sha", "0" * 64],
    )
    assert res.exit_code == 0
    html = hp.read_text(encoding="utf-8")
    assert "STALE" not in html
    assert "203.0.113.9" in html


def test_pcap_leads_into_rerenders_html(monkeypatch, tmp_path: Path):
    """pcap-leads --into 改了 report.json 后，若同目录有 report.html 则重渲（内容随之更新）。"""
    from apkscan.dynamic import pcap_ingest

    rp = tmp_path / "report.json"
    hp = tmp_path / "report.html"
    hp.write_text("<html>STALE</html>", encoding="utf-8")

    class _FakeSummary:
        flows = ["f"]
        dns_queries = []

    # 第三个位置参数是 UID 归因表（可选）——替身要跟着签名走，否则 CLI 一传就 TypeError，
    # 而这条测试断的是 exit_code，报出来像是 CLI 坏了。
    def _fake_merge(report_json_path: str, summary: object, app_attr: object = None) -> int:
        _write_min_report_json(
            Path(report_json_path),
            leads=[
                {
                    "category": "DOMAIN",
                    "value": "pcap-sni.example.net",
                    "subject": None,
                    "where_to_request": "注册商",
                    "evidence_to_obtain": [],
                    "confidence": "MEDIUM",
                    "source_refs": [
                        {"source": "runtime", "location": "pcap", "snippet": "", "observed_at": None}
                    ],
                    "notes": "",
                    "advice": "建议调证",
                }
            ],
        )
        return 1

    monkeypatch.setattr(pcap_ingest, "parse_pcap", lambda p: _FakeSummary())
    monkeypatch.setattr(pcap_ingest, "to_report_leads", lambda *a, **k: [])
    monkeypatch.setattr(pcap_ingest, "build_ledger_md", lambda *a, **k: "台账")
    monkeypatch.setattr(pcap_ingest, "merge_into_report_json", _fake_merge)

    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00")

    res = runner.invoke(cli.app, ["pcap-leads", str(pcap), "--into", str(rp)])
    assert res.exit_code == 0
    html = hp.read_text(encoding="utf-8")
    assert "STALE" not in html
    assert "pcap-sni.example.net" in html
