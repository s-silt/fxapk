"""apkscan.dynamic.auto 单测：全 mock，无设备也能锁定行为。

monkeypatch auto 模块内引用 / 惰性 import 的 doctor.run / unpack.run / capture.run /
merge.* / load_apk / pipeline.run / device.has_device，覆盖：

  1. 有设备 happy path：doctor→静态→脱壳→抓包→合并，steps 全 done，confirm 被调用。
  2. 无设备：脱壳/抓包 skipped、静态仍 done、仍出报告。
  3. 某步抛异常：该步 status=error 且后续步骤仍继续（失败不中断）、run 不抛。
  4. confirm/on_progress 被正确调用（且为 None 时不报错）。
  5. load_apk 失败：静态 error 但 run 不崩、脱壳/抓包仍按设备情况进行。

铁律呼应：auto 是 GUI-ready 核心——禁 print/typer/input；本测试锁定它只返回结构化
dict、绝不抛、回调被安全调用。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import Report
from apkscan.dynamic import STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED
from apkscan.dynamic import auto

runner = CliRunner()


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _FakeCtx:
    """load_apk 返回值的最小替身（auto._run_static 只用 package_name）。"""

    def __init__(self, package_name: str = "com.fraud.app") -> None:
        self.package_name = package_name


def _make_report(package_name: str = "com.fraud.app") -> Report:
    """字段齐全的最小 Report（merge 就地补全用）。"""
    return Report(
        package_name=package_name,
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _dynamic_result(status: str, reason: str = "", report_paths: list[str] | None = None) -> dict:
    """构造 DynamicResult（unpack/capture 返回契约）。"""
    return {
        "status": status,
        "reason": reason,
        "artifacts": [],
        "playbook": [],
        "report_paths": report_paths or [],
    }


def _patch_static_ok(
    monkeypatch: pytest.MonkeyPatch, package_name: str = "com.fraud.app"
) -> Report:
    """打桩静态分析：load_apk + pipeline.run 不碰 androguard，写报告替换为 no-op 返回固定路径。

    注意：auto._run_static 惰性 import ``apkscan.core.apk.load_apk`` 与
    ``apkscan.core.pipeline``，故在源模块处打桩。
    """
    import apkscan.core.apk as apk_mod
    import apkscan.core.pipeline as pipeline_mod

    report = _make_report(package_name)
    monkeypatch.setattr(apk_mod, "load_apk", lambda *a, **k: _FakeCtx(package_name))
    monkeypatch.setattr(pipeline_mod, "run", lambda ctx, config: report)
    # 不写真报告：替换 auto 的内部写报告函数，返回固定路径（新签名含 base 关键字参数）。
    monkeypatch.setattr(
        auto,
        "_write_reports",
        lambda report, *, out_dir, formats, base: [f"{out_dir}/{base}.html"],
    )
    return report


def _patch_doctor(monkeypatch: pytest.MonkeyPatch, ok: bool = True) -> dict[str, Any]:
    """打桩 doctor.run，记录被调与 on_progress 透传。"""
    import apkscan.dynamic.doctor as doctor_mod

    calls: dict[str, Any] = {"called": False, "on_progress": None, "serial": None}

    def _fake_run(**kwargs: Any) -> dict[str, Any]:
        calls["called"] = True
        calls["on_progress"] = kwargs.get("on_progress")
        calls["serial"] = kwargs.get("serial")
        cb = kwargs.get("on_progress")
        if cb is not None:
            cb("体检中")
        return {"ok": ok, "items": [{"name": "在线设备", "ok": ok, "detail": "x", "fix_cmd": []}]}

    monkeypatch.setattr(doctor_mod, "run", _fake_run)
    return calls


def _patch_unpack(monkeypatch: pytest.MonkeyPatch, result: dict) -> dict[str, Any]:
    import apkscan.dynamic.unpack as unpack_mod

    calls: dict[str, Any] = {"called": False}

    def _fake_run(apk_path: str, *a: Any, **k: Any) -> dict:
        calls["called"] = True
        calls["apk_path"] = apk_path
        calls["kwargs"] = k
        return result

    monkeypatch.setattr(unpack_mod, "run", _fake_run)
    return calls


def _patch_capture(monkeypatch: pytest.MonkeyPatch, result: dict) -> dict[str, Any]:
    import apkscan.dynamic.capture as capture_mod

    calls: dict[str, Any] = {"called": False}

    def _fake_run(package: str, *a: Any, **k: Any) -> dict:
        calls["called"] = True
        calls["package"] = package
        calls["kwargs"] = k
        return result

    monkeypatch.setattr(capture_mod, "run", _fake_run)
    return calls


def _patch_merge(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import apkscan.dynamic.merge as merge_mod

    calls: dict[str, Any] = {"load_path": None, "rerender_called": False, "rerender_args": None}

    def _fake_load(path: str) -> list:
        calls["load_path"] = path
        return ["EP"]

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
        return {
            "merged": 2,
            "new_leads": 1,
            "total_endpoints": 5,
            "report_paths": [f"{out_dir}/{base}.json"],
        }

    monkeypatch.setattr(merge_mod, "load_runtime_endpoints", _fake_load)
    monkeypatch.setattr(merge_mod, "merge_and_rerender", _fake_rerender)
    return calls


def _set_device(monkeypatch: pytest.MonkeyPatch, present: bool) -> None:
    # auto 现以 select_target_serial() 选定单台设备（多设备/一机多 transport 钉定一个）：
    # present=True → 给一个 serial（has_device 由 serial is not None 推出）；False → None。
    monkeypatch.setattr(
        auto.device, "select_target_serial", lambda: "emulator-5554" if present else None
    )
    # 有设备时 auto 会在脱壳/抓包前调 provision.ensure_frida_server / install_apk；mock 掉
    # 避免单测触发真 adb / frida-ps -U（无设备 → 数秒超时，拖慢测试）。
    import apkscan.dynamic.provision as _prov

    monkeypatch.setattr(
        _prov, "ensure_frida_server", lambda *a, **k: {"ok": True, "action": "already_running"}
    )
    monkeypatch.setattr(_prov, "install_apk", lambda *a, **k: {"ok": True, "detail": "已安装"})


def _status_of(steps: list[dict], name: str) -> str:
    for s in steps:
        if s.get("name") == name:
            return str(s.get("status"))
    raise AssertionError(f"步骤未出现：{name}（steps={[s.get('name') for s in steps]}）")


# ---------------------------------------------------------------------------
# 1) 有设备 happy path：全链路 done，confirm 被调用
# ---------------------------------------------------------------------------


def test_full_pipeline_happy_path_all_done(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE, "脱壳成功"))
    cap_calls = _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, "抓包完成", report_paths=["out/runtime_report.json"]),
    )
    merge_calls = _patch_merge(monkeypatch)

    confirms: list[str] = []
    progresses: list[str] = []

    result = auto.run(
        "sample.apk",
        out_dir="out",
        on_progress=progresses.append,
        confirm=confirms.append,
    )

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_DOCTOR) == STATUS_DONE
    assert _status_of(steps, auto._STEP_STATIC) == STATUS_DONE
    assert _status_of(steps, auto._STEP_UNPACK) == STATUS_DONE
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_DONE
    assert _status_of(steps, auto._STEP_MERGE) == STATUS_DONE

    assert result["package_name"] == "com.fraud.app"
    assert result["out_dir"] == "out"
    # 报告路径含静态 + 重渲。
    assert result["report_paths"]

    # confirm 在抓包前被调用一次，文案含抓包提示与时长。
    assert len(confirms) == 1
    assert "抓包" in confirms[0] and "操作 app" in confirms[0]
    # on_progress 多次上报。
    assert progresses
    # merge 用 runtime_report.json 作并入来源，且 report 透传。
    assert merge_calls["load_path"] == "out/runtime_report.json"
    assert merge_calls["rerender_called"] is True
    # capture 用包名 + out= + duration。
    assert cap_calls["package"] == "com.fraud.app"


# ---------------------------------------------------------------------------
# 2) 无设备：脱壳/抓包 skipped、静态仍 done、仍出报告
# ---------------------------------------------------------------------------


def test_no_device_skips_unpack_and_capture_static_still_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_doctor(monkeypatch, ok=False)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, False)
    # 即便打了桩，无设备时也不应被调用。
    unpack_calls = _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    cap_calls = _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE))
    merge_calls = _patch_merge(monkeypatch)

    confirms: list[str] = []
    result = auto.run("sample.apk", out_dir="out", confirm=confirms.append)

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_STATIC) == STATUS_DONE
    assert _status_of(steps, auto._STEP_UNPACK) == STATUS_SKIPPED
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_SKIPPED
    assert _status_of(steps, auto._STEP_MERGE) == STATUS_SKIPPED

    assert result["report_paths"]  # 静态报告仍产出
    assert unpack_calls["called"] is False
    assert cap_calls["called"] is False
    assert merge_calls["rerender_called"] is False
    # 无设备不抓包 → confirm 不被调用。
    assert confirms == []


# ---------------------------------------------------------------------------
# 3) 某步抛异常 → 该步 error 且后续继续（失败不中断），run 不抛
# ---------------------------------------------------------------------------


def test_doctor_exception_does_not_stop_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.doctor as doctor_mod

    def _boom(**kwargs: Any) -> dict:
        raise RuntimeError("doctor exploded")

    monkeypatch.setattr(doctor_mod, "run", _boom)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, False)

    result = auto.run("sample.apk", out_dir="out")  # 不应抛

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_DOCTOR) == STATUS_ERROR
    # 体检炸了，静态仍跑且 done。
    assert _status_of(steps, auto._STEP_STATIC) == STATUS_DONE
    assert result["report_paths"]


def test_unpack_exception_does_not_stop_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.unpack as unpack_mod

    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)

    def _boom(*a: Any, **k: Any) -> dict:
        raise RuntimeError("unpack exploded")

    monkeypatch.setattr(unpack_mod, "run", _boom)
    cap_calls = _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE, "抓包完成"))
    _patch_merge(monkeypatch)

    result = auto.run("sample.apk", out_dir="out")  # 不应抛

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_UNPACK) == STATUS_ERROR
    # 脱壳炸了，抓包仍继续（失败不中断）。
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_DONE
    assert cap_calls["called"] is True


def test_capture_exception_does_not_stop_merge_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.capture as capture_mod

    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))

    def _boom(*a: Any, **k: Any) -> dict:
        raise RuntimeError("capture exploded")

    monkeypatch.setattr(capture_mod, "run", _boom)
    merge_calls = _patch_merge(monkeypatch)

    result = auto.run("sample.apk", out_dir="out")  # 不应抛

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_ERROR
    # 抓包未成功 → 合并跳过，不调 merge。
    assert _status_of(steps, auto._STEP_MERGE) == STATUS_SKIPPED
    assert merge_calls["rerender_called"] is False


def test_merge_exception_marks_error_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.merge as merge_mod

    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(
        monkeypatch, _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])
    )

    def _boom_load(path: str) -> list:
        raise RuntimeError("merge load exploded")

    monkeypatch.setattr(merge_mod, "load_runtime_endpoints", _boom_load)

    result = auto.run("sample.apk", out_dir="out")  # 不应抛
    assert _status_of(result["steps"], auto._STEP_MERGE) == STATUS_ERROR


# ---------------------------------------------------------------------------
# 4) confirm / on_progress 为 None 时不报错
# ---------------------------------------------------------------------------


def test_callbacks_none_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(
        monkeypatch, _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])
    )
    _patch_merge(monkeypatch)

    # confirm=None / on_progress=None：不等待、不报错，全链路仍跑完。
    result = auto.run("sample.apk", out_dir="out", on_progress=None, confirm=None)
    assert _status_of(result["steps"], auto._STEP_CAPTURE) == STATUS_DONE


def test_confirm_exception_is_swallowed_capture_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """confirm 回调自身抛异常应被吞掉，不阻断抓包（GUI 回调不得炸内核）。"""
    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    cap_calls = _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE))

    def _boom_confirm(msg: str) -> None:
        raise RuntimeError("gui confirm exploded")

    result = auto.run("sample.apk", out_dir="out", confirm=_boom_confirm)
    assert cap_calls["called"] is True
    assert _status_of(result["steps"], auto._STEP_CAPTURE) == STATUS_DONE


# ---------------------------------------------------------------------------
# 5) load_apk 失败 → 静态 error 但 run 不崩
# ---------------------------------------------------------------------------


def test_load_apk_failure_static_error_run_does_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.core.apk as apk_mod

    _patch_doctor(monkeypatch, ok=True)

    def _boom_load(*a: Any, **k: Any) -> Any:
        raise apk_mod.ApkParseError("无法解析 APK")

    monkeypatch.setattr(apk_mod, "load_apk", _boom_load)
    _set_device(monkeypatch, False)

    result = auto.run("broken.apk", out_dir="out")  # 不应抛

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_STATIC) == STATUS_ERROR
    assert result["package_name"] == ""
    # 无设备 → 脱壳/抓包 skipped；合并因无 report skipped。
    assert _status_of(steps, auto._STEP_UNPACK) == STATUS_SKIPPED
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_SKIPPED


def test_load_apk_failure_with_device_still_unpacks_but_capture_skips_no_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """有设备但 load_apk 失败：静态 error、无包名 → 脱壳照跑、抓包因无包名 skipped。"""
    import apkscan.core.apk as apk_mod

    _patch_doctor(monkeypatch, ok=True)
    monkeypatch.setattr(
        apk_mod, "load_apk", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    _set_device(monkeypatch, True)
    unpack_calls = _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    cap_calls = _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE))

    result = auto.run("broken.apk", out_dir="out")

    steps = result["steps"]
    assert _status_of(steps, auto._STEP_STATIC) == STATUS_ERROR
    assert unpack_calls["called"] is True  # 脱壳不依赖包名（unpack 内部自解析）
    assert cap_calls["called"] is False  # 抓包需包名，无包名跳过
    assert _status_of(steps, auto._STEP_CAPTURE) == STATUS_SKIPPED


# ---------------------------------------------------------------------------
# 6) 报告路径去重
# ---------------------------------------------------------------------------


def test_report_paths_deduplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    """静态与重渲产出相同路径时，report_paths 去重保持顺序。"""
    _patch_doctor(monkeypatch, ok=True)
    import apkscan.core.apk as apk_mod
    import apkscan.core.pipeline as pipeline_mod

    report = _make_report("com.fraud.app")
    monkeypatch.setattr(apk_mod, "load_apk", lambda *a, **k: _FakeCtx("com.fraud.app"))
    monkeypatch.setattr(pipeline_mod, "run", lambda ctx, config: report)
    monkeypatch.setattr(
        auto, "_write_reports", lambda report, *, out_dir, formats, base: ["out/report.json"]
    )
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(
        monkeypatch, _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])
    )

    import apkscan.dynamic.merge as merge_mod

    monkeypatch.setattr(merge_mod, "load_runtime_endpoints", lambda p: [])
    # merge 重渲返回与静态相同的 out/report.json → 应去重。
    monkeypatch.setattr(
        merge_mod,
        "merge_and_rerender",
        lambda *a, **k: {"merged": 0, "new_leads": 0, "report_paths": ["out/report.json"]},
    )

    result = auto.run("sample.apk", out_dir="out")
    assert result["report_paths"].count("out/report.json") == 1


# ---------------------------------------------------------------------------
# CLI：fxapk auto（薄包装，参数透传 + 退出码）
# ---------------------------------------------------------------------------


def _patch_auto_run(monkeypatch: pytest.MonkeyPatch, result: dict) -> dict[str, Any]:
    """monkeypatch auto.run，记录入参，触发 on_progress/confirm 确认 cli 回调可安全调用。"""
    calls: dict[str, Any] = {"called": False, "kwargs": None}

    def _fake_run(apk_path: str, **kwargs: Any) -> dict:
        calls["called"] = True
        calls["apk_path"] = apk_path
        calls["kwargs"] = kwargs
        cb = kwargs.get("on_progress")
        if cb is not None:
            cb("跑步骤中")
        return result

    monkeypatch.setattr(auto, "run", _fake_run)
    return calls


def test_cli_auto_passes_args_and_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    import tempfile

    result = {
        "steps": [
            {"name": "环境体检", "status": "done", "detail": "体检通过"},
            {"name": "静态分析", "status": "done", "detail": "包名 com.x"},
            {"name": "脱壳", "status": "skipped", "detail": "无设备"},
            {"name": "抓包", "status": "skipped", "detail": "无设备"},
            {"name": "合并运行时端点", "status": "skipped", "detail": "无运行时端点"},
        ],
        "report_paths": ["out/report.html", "out/report.json"],
        "package_name": "com.x",
        "out_dir": "out",
    }
    calls = _patch_auto_run(monkeypatch, result)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(
        cli.app,
        ["auto", apk, "--out", "myout", "--offline", "--no-fix", "--duration", "30", "--fmt", "json"],
    )

    assert res.exit_code == 0
    assert calls["called"] is True
    kw = calls["kwargs"]
    assert kw["out_dir"] == "myout"
    assert kw["online"] is False
    assert kw["auto_fix"] is False
    assert kw["capture_duration"] == 30
    assert kw["formats"] == ["json"]
    assert callable(kw["on_progress"])
    assert callable(kw["confirm"])
    # 打印步骤摘要 + 报告路径。
    assert "[OK]" in res.output
    assert "[SKIP]" in res.output
    assert "report.html" in res.output


def test_cli_auto_module_missing_graceful_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """惰性 import auto 失败 → 打印"该功能未安装" + 退出码 1，不崩。"""
    import builtins
    import sys
    import tempfile

    monkeypatch.delitem(sys.modules, "apkscan.dynamic.auto", raising=False)
    import apkscan.dynamic as _dyn

    monkeypatch.delattr(_dyn, "auto", raising=False)

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        fromlist = args[2] if len(args) >= 3 else kwargs.get("fromlist")
        if name == "apkscan.dynamic.auto" or (
            name == "apkscan.dynamic" and fromlist and "auto" in fromlist
        ):
            raise ImportError("simulated missing auto")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(cli.app, ["auto", apk])
    assert res.exit_code == 1
    assert "该功能未安装" in res.output


def test_cli_auto_handles_nondict_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto.run 返回非 dict 时 cli 容错打印，不崩。"""
    import tempfile

    monkeypatch.setattr(auto, "run", lambda *a, **k: "not a dict")

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    res = runner.invoke(cli.app, ["auto", apk])
    assert res.exit_code == 0
    assert "非预期格式" in res.output


# ---------------------------------------------------------------------------
# analyze_static：仅静态公共函数（GUI「静态分析」按钮专用，不触发 doctor/动态）
# ---------------------------------------------------------------------------


def test_analyze_static_runs_only_static_not_doctor_or_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """analyze_static 只跑静态：不调 doctor / 不探测设备 / 不调 unpack/capture。"""
    import apkscan.dynamic.capture as capture_mod
    import apkscan.dynamic.doctor as doctor_mod
    import apkscan.dynamic.unpack as unpack_mod

    _patch_static_ok(monkeypatch, "com.fraud.app")

    doctor_called = {"v": False}
    unpack_called = {"v": False}
    capture_called = {"v": False}
    device_called = {"v": False}
    monkeypatch.setattr(doctor_mod, "run", lambda **k: doctor_called.__setitem__("v", True))
    monkeypatch.setattr(unpack_mod, "run", lambda *a, **k: unpack_called.__setitem__("v", True))
    monkeypatch.setattr(capture_mod, "run", lambda *a, **k: capture_called.__setitem__("v", True))
    monkeypatch.setattr(
        auto.device, "has_device", lambda: device_called.__setitem__("v", True) or True
    )

    progresses: list[str] = []
    result = auto.analyze_static(
        "sample.apk", out_dir="out", online=True, formats=["html"], on_progress=progresses.append
    )

    assert _status_of(result["steps"], auto._STEP_STATIC) == STATUS_DONE
    assert len(result["steps"]) == 1  # 仅静态一步
    assert result["package_name"] == "com.fraud.app"
    assert result["out_dir"] == "out"
    assert result["report_paths"]
    assert progresses  # on_progress 透传
    # 关键：不触发体检/设备/动态。
    assert doctor_called["v"] is False
    assert unpack_called["v"] is False
    assert capture_called["v"] is False
    assert device_called["v"] is False


def test_analyze_static_load_failure_returns_error_step_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import apkscan.core.apk as apk_mod

    def _boom(*a: Any, **k: Any) -> Any:
        raise apk_mod.ApkParseError("无法解析 APK")

    monkeypatch.setattr(apk_mod, "load_apk", _boom)

    result = auto.analyze_static("broken.apk", out_dir="out")  # 不应抛
    assert _status_of(result["steps"], auto._STEP_STATIC) == STATUS_ERROR
    assert result["package_name"] == ""
    assert result["report_paths"] == []


def test_analyze_static_callbacks_none_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_static_ok(monkeypatch, "com.x")
    result = auto.analyze_static("sample.apk", out_dir="out", on_progress=None)
    assert _status_of(result["steps"], auto._STEP_STATIC) == STATUS_DONE


# silence unused import warnings for path helper (kept for parity/readability).
_ = Path


def test_run_install_app_done_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.provision as _prov
    from apkscan.dynamic import auto as _auto

    monkeypatch.setattr(_prov, "install_apk", lambda apk, serial=None: {"ok": True, "detail": "已安装"})
    step = _auto._run_install_app("x.apk", on_progress=None)
    assert step["status"] == "done"


def test_run_install_app_error_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import apkscan.dynamic.provision as _prov
    from apkscan.dynamic import auto as _auto

    monkeypatch.setattr(_prov, "install_apk", lambda apk, serial=None: {"ok": False, "detail": "失败"})
    step = _auto._run_install_app("x.apk", on_progress=None)
    assert step["status"] == "error"


# ---------------------------------------------------------------------------
# serial 注入（P0 多设备：auto 选定 serial 后一路传给 frida/install/unpack/capture）
# ---------------------------------------------------------------------------


def test_auto_selects_serial_and_threads_to_all_downstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """select_target_serial 返回某 serial → ensure_frida_server/install_apk/unpack/capture 全收到该 serial。"""
    import apkscan.dynamic.provision as _prov
    import apkscan.dynamic.unpack as unpack_mod
    import apkscan.dynamic.capture as capture_mod

    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _patch_merge(monkeypatch)

    # 多设备/一机多 transport 已被 select_target_serial 钉定为 emulator-5554。
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "emulator-5554")

    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        _prov,
        "ensure_frida_server",
        lambda *a, **k: seen.__setitem__("frida_serial", k.get("serial"))
        or {"ok": True, "action": "already_running"},
    )
    monkeypatch.setattr(
        _prov,
        "install_apk",
        lambda apk, serial=None: seen.__setitem__("install_serial", serial)
        or {"ok": True, "detail": "已安装"},
    )

    def _fake_unpack(apk_path: str, *a: Any, **k: Any) -> dict:
        seen["unpack_serial"] = k.get("serial")
        return _dynamic_result(STATUS_DONE)

    def _fake_capture(package: str, *a: Any, **k: Any) -> dict:
        seen["capture_serial"] = k.get("serial")
        return _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])

    monkeypatch.setattr(unpack_mod, "run", _fake_unpack)
    monkeypatch.setattr(capture_mod, "run", _fake_capture)

    result = auto.run("sample.apk", out_dir="out")

    assert _status_of(result["steps"], auto._STEP_CAPTURE) == STATUS_DONE
    assert seen["frida_serial"] == "emulator-5554"
    assert seen["install_serial"] == "emulator-5554"
    assert seen["unpack_serial"] == "emulator-5554"
    assert seen["capture_serial"] == "emulator-5554"


def test_auto_no_serial_means_no_device_skips_dynamic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """select_target_serial 返回 None → has_device=False → 脱壳/抓包 skipped（与旧无设备路径一致）。"""
    _patch_doctor(monkeypatch, ok=False)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: None)
    unpack_calls = _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    cap_calls = _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_merge(monkeypatch)

    result = auto.run("sample.apk", out_dir="out")

    assert _status_of(result["steps"], auto._STEP_UNPACK) == STATUS_SKIPPED
    assert _status_of(result["steps"], auto._STEP_CAPTURE) == STATUS_SKIPPED
    assert unpack_calls["called"] is False
    assert cap_calls["called"] is False


def test_auto_records_target_serial_in_meta(monkeypatch: pytest.MonkeyPatch) -> None:
    """选定的 serial 记入 report.meta['target_serial']（便于排查）。"""
    report = _patch_static_ok(monkeypatch, "com.fraud.app")
    _patch_doctor(monkeypatch, ok=True)
    _patch_merge(monkeypatch)
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "emulator-5554")

    import apkscan.dynamic.provision as _prov

    monkeypatch.setattr(
        _prov, "ensure_frida_server", lambda *a, **k: {"ok": True, "action": "already_running"}
    )
    monkeypatch.setattr(_prov, "install_apk", lambda *a, **k: {"ok": True, "detail": "ok"})
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(monkeypatch, _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"]))

    auto.run("sample.apk", out_dir="out")
    assert report.meta.get("target_serial") == "emulator-5554"


def test_auto_threads_serial_to_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    """serial 必须在体检之前选定并透传给 doctor.run（多设备/一机多 transport：
    体检/装 CA 阶段也要钉定同一台，否则 `more than one device` 一连串失败）。"""
    doctor_calls = _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)  # select_target_serial → emulator-5554
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(
        monkeypatch, _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])
    )
    _patch_merge(monkeypatch)

    auto.run("sample.apk", out_dir="out")

    assert doctor_calls["serial"] == "emulator-5554"


def test_auto_no_device_threads_none_serial_to_doctor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """无设备（select_target_serial → None）时 doctor.run 收到 serial=None（旧行为不变）。"""
    doctor_calls = _patch_doctor(monkeypatch, ok=False)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: None)

    auto.run("sample.apk", out_dir="out")

    assert doctor_calls["called"] is True
    assert doctor_calls["serial"] is None
