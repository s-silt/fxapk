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

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import Endpoint, Report
from apkscan.dynamic import STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED
from apkscan.dynamic import auto

runner = CliRunner()


@pytest.fixture(autouse=True)
def _avoid_case_close_disk_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    from apkscan.core import report_io

    monkeypatch.setattr(
        report_io,
        "write_report",
        lambda report, path, **kwargs: [str(path)],
    )


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


def test_analyze_static_threads_mode_to_config(monkeypatch: pytest.MonkeyPatch) -> None:
    # 网络模式经 analyze_static → _run_static → AnalysisConfig 透传（默认 passive；可开 authorized-active）。
    import apkscan.core.apk as apk_mod
    import apkscan.core.pipeline as pipeline_mod

    captured: dict[str, str] = {}
    report = _make_report("com.x")
    monkeypatch.setattr(apk_mod, "load_apk", lambda *a, **k: _FakeCtx("com.x"))

    def _run(ctx: object, config: Any) -> Report:
        captured["mode"] = config.mode
        return report

    monkeypatch.setattr(pipeline_mod, "run", _run)
    monkeypatch.setattr(
        auto, "_write_reports", lambda report, *, out_dir, formats, base: [f"{out_dir}/{base}.html"]
    )

    auto.analyze_static("sample.apk", out_dir="out", mode="authorized-active")
    assert captured["mode"] == "authorized-active"

    captured.clear()
    auto.analyze_static("sample.apk", out_dir="out")  # 不传 → 默认 passive
    assert captured["mode"] == "passive"


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
    assert merge_calls["rerender_args"]["runtime_report_path"] == "out/runtime_report.json"
    assert merge_calls["rerender_called"] is True
    # capture 用包名 + out= + duration。
    assert cap_calls["package"] == "com.fraud.app"


# ---------------------------------------------------------------------------
# 1.5) ★脱壳回灌后，后续全程必须切到脱壳版报告
# ---------------------------------------------------------------------------


def _patch_unpack_reanalyzing(
    monkeypatch: pytest.MonkeyPatch, unpacked: Report, dex_count: int = 3
) -> None:
    """打桩 unpack.run：模拟脱壳成功并回灌，通过 on_reanalyzed 交出回灌后的报告。"""
    import apkscan.dynamic.unpack as unpack_mod

    def _fake_run(apk_path: str, *a: Any, **k: Any) -> dict:
        unpacked.meta["unpacked"] = True
        unpacked.meta["unpacked_dex_count"] = dex_count
        cb = k.get("on_reanalyzed")
        if cb is not None:
            cb(unpacked)
        return _dynamic_result(
            STATUS_DONE, f"脱壳成功，dump 出 {dex_count} 个 DEX。",
            report_paths=["out/unpacked_report.json"],
        )

    monkeypatch.setattr(unpack_mod, "run", _fake_run)


def test_unpacked_report_becomes_active_input_for_merge_and_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """★脱壳成功但主报告没换 = 脱壳白做。

    unpack 内部 reanalyze 产出的是**另一份** Report 对象（写成 unpacked_report.json）。若 auto
    只收下路径、不替换手里的 report，则 capture/merge/closure 与最终写出的报告全都还在壳桩上跑：
    步骤显示「脱壳成功」，报告里却一条隐藏端点都没有——一个从数据上看不出来的坑。
    """
    _patch_doctor(monkeypatch, ok=True)
    static = _patch_static_ok(monkeypatch, "com.fraud.app")
    static.meta["is_hardened"] = True          # 壳桩：加固、DEX 里看不到东西
    static.endpoints = []

    unpacked = _make_report("com.fraud.app")   # 脱壳后才看得见的端点
    hidden = Endpoint(value="hidden-c2.example", kind="domain")
    unpacked.endpoints = [hidden]

    _set_device(monkeypatch, True)
    _patch_unpack_reanalyzing(monkeypatch, unpacked, dex_count=3)
    _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, "抓包完成", report_paths=["out/runtime_report.json"]),
    )
    merge_calls = _patch_merge(monkeypatch)

    auto.run("sample.apk", out_dir="out", confirm=lambda _m: None)

    got = merge_calls["rerender_args"]["report"]
    assert got is unpacked, "merge/closure 必须拿到脱壳回灌后的报告，而不是壳桩静态报告"
    assert got.endpoints == [hidden]

    # 血缘：「脱壳成功」与「脱壳结果已成为当前输入」是两件事，必须分别可查。
    lineage = got.meta.get("artifact_lineage")
    assert lineage is not None, "切换了当前报告却不留血缘，事后无法核查最终报告基于什么输入"
    assert lineage["active_input"] == "unpacked"
    assert lineage["unpacked_dex_count"] == 3
    assert lineage["superseded_static_hardened"] is True


def test_adopted_report_inherits_run_context_not_sample_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """★换报告必须带上**运行上下文**，但绝不能带样本结论。

    ``_reanalyze`` 固定以 online=False 跑（回灌只做静态重解），产出的报告里没有 ``online`` 键；
    而 merge 读 ``meta.get("online", True)`` 决定运行时线索要不要标「离线扫描，归属未查询」。
    不继承的话，一次 --offline 运行在脱壳成功后会把「压根没查」渲染成「查过」——正是该字段
    存在意义的反面。反过来 is_hardened 这类**样本**结论脱壳后本就该重算，照搬会把壳桩结论
    糊到去壳报告上。
    """
    _patch_doctor(monkeypatch, ok=True)
    static = _patch_static_ok(monkeypatch, "com.fraud.app")
    static.meta.update({"online": False, "mode": "passive", "is_hardened": True,
                        "packed": "some-packer"})

    unpacked = _make_report("com.fraud.app")
    unpacked.meta["is_hardened"] = False        # 脱壳后重算的样本结论

    _set_device(monkeypatch, True)
    _patch_unpack_reanalyzing(monkeypatch, unpacked, dex_count=2)
    _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, "抓包完成", report_paths=["out/runtime_report.json"]),
    )
    merge_calls = _patch_merge(monkeypatch)

    auto.run("sample.apk", out_dir="out", online=False, confirm=lambda _m: None)

    got = merge_calls["rerender_args"]["report"]
    assert got is unpacked
    # 运行上下文：继承
    assert got.meta["online"] is False, "离线运行的上下文丢了 → 线索会被当成已联网核实过"
    assert got.meta["mode"] == "passive"
    # 样本结论：不继承（脱壳后已重算）
    assert got.meta["is_hardened"] is False, "壳桩的加固结论不该糊到去壳报告上"
    assert "packed" not in got.meta
    # 继承了什么要可查
    assert set(got.meta["artifact_lineage"]["inherited_run_context"]) >= {"online", "mode"}


def test_adopted_report_keeps_target_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    """★换报告后仍要知道「本次在哪台设备上分析」——多设备下这是排查的唯一线索。"""
    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    unpacked = _make_report("com.fraud.app")

    _set_device(monkeypatch, True)
    _patch_unpack_reanalyzing(monkeypatch, unpacked)
    _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, "抓包完成", report_paths=["out/runtime_report.json"]),
    )
    merge_calls = _patch_merge(monkeypatch)

    auto.run("sample.apk", out_dir="out", confirm=lambda _m: None)

    got = merge_calls["rerender_args"]["report"]
    assert got.meta.get("target_serial"), "换报告后设备 serial 丢失，多设备下无从排查"


def test_unpack_without_reanalysis_keeps_static_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """脱壳没回灌（reanalyze 失败/未产出报告）→ 不得凭空切换，仍用静态报告且不留假血缘。"""
    _patch_doctor(monkeypatch, ok=True)
    static = _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE, "脱壳成功但重分析失败"))
    _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, "抓包完成", report_paths=["out/runtime_report.json"]),
    )
    merge_calls = _patch_merge(monkeypatch)

    auto.run("sample.apk", out_dir="out", confirm=lambda _m: None)

    assert merge_calls["rerender_args"]["report"] is static
    assert "artifact_lineage" not in static.meta


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


def test_auto_returns_case_closure_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_doctor(monkeypatch, ok=True)
    _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_capture(
        monkeypatch,
        _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"]),
    )
    _patch_merge(monkeypatch)
    closure = {
        "status": "partial",
        "targets": [],
        "gaps": ["target attribution incomplete"],
        "next_actions": ["collect target-attributed traffic"],
    }
    monkeypatch.setattr(
        auto,
        "_run_closure",
        lambda *args, **kwargs: (
            {"name": "案件闭环", "status": STATUS_DONE, "detail": "闭环状态 partial"},
            closure,
            ["out/sample.json"],
        ),
        raising=False,
    )

    result = auto.run("sample.apk", out_dir="out", repackage=False)

    assert result["status"] == "partial"
    assert result["closure"] == closure
    assert _status_of(result["steps"], "案件闭环") == STATUS_DONE


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


def test_cli_auto_repackage_flag_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-repackage → repackage=False；默认 → repackage=True（透传 auto.run）。"""
    import tempfile

    calls = _patch_auto_run(
        monkeypatch, {"steps": [], "report_paths": [], "package_name": "com.x", "out_dir": "out"}
    )
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    assert runner.invoke(cli.app, ["auto", apk, "--no-repackage", "--offline", "--no-fix"]).exit_code == 0
    assert calls["kwargs"]["repackage"] is False
    assert runner.invoke(cli.app, ["auto", apk, "--offline", "--no-fix"]).exit_code == 0
    assert calls["kwargs"]["repackage"] is True  # 默认开


@pytest.mark.parametrize(("status", "exit_code"), [("partial", 5), ("failed", 6)])
def test_cli_auto_strict_case_exit_codes(
    monkeypatch: pytest.MonkeyPatch, status: str, exit_code: int
) -> None:
    import tempfile

    calls = _patch_auto_run(
        monkeypatch,
        {
            "status": status,
            "closure": {"status": status, "targets": [], "gaps": ["gap"]},
            "steps": [],
            "report_paths": [],
            "package_name": "com.x",
            "out_dir": "out",
        },
    )
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
        apk = fh.name

    result = runner.invoke(
        cli.app,
        ["auto", apk, "--strict-case", "--offline", "--no-fix", "--no-repackage"],
    )

    assert result.exit_code == exit_code
    assert calls["kwargs"]["strict_case"] is True


def test_run_repackage_no_device_skipped() -> None:
    step, wrapper_path = auto._run_repackage(
        "a.apk", "com.x", out_dir="o", has_device=False, on_progress=None
    )
    assert step["status"] == "skipped"
    # P0-c：第二元素改为 wrapper APK 路径（无设备 → 没重打包 → None，而非空列表）。
    assert wrapper_path is None


def test_run_repackage_invokes_repackage_run_with_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    """有设备 → 调 repackage.run 并透传 serial/package_name，折叠成 done step。"""
    seen: dict[str, Any] = {}

    def _fake(apk_path: str, **kw: Any) -> dict:
        seen["apk"] = apk_path
        seen["kw"] = kw
        return {"status": "done", "reason": "去壳成功", "artifacts": ["x.apk"], "playbook": [], "report_paths": []}

    monkeypatch.setattr("apkscan.dynamic.repackage.run", _fake)
    step, _paths = auto._run_repackage(
        "a.apk", "com.x", out_dir="o", has_device=True, serial="emulator-5554", on_progress=None
    )
    assert step["status"] == "done"
    assert seen["kw"]["serial"] == "emulator-5554"  # serial 透传
    assert seen["kw"]["package_name"] == "com.x"


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


def test_auto_threads_static_report_into_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """静态 report 被透传给 capture.run(report=...)，让 decide_capture 的四律决策驱动引擎。"""
    import apkscan.dynamic.capture as capture_mod

    _patch_doctor(monkeypatch, ok=True)
    report = _patch_static_ok(monkeypatch, "com.fraud.app")
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    _patch_merge(monkeypatch)

    seen: dict[str, Any] = {"report": "MISSING"}

    def _fake_capture(package: str, *a: Any, **k: Any) -> dict:
        seen["report"] = k.get("report", "MISSING")
        return _dynamic_result(STATUS_DONE, report_paths=["out/runtime_report.json"])

    monkeypatch.setattr(capture_mod, "run", _fake_capture)

    auto.run("sample.apk", out_dir="out")
    # capture 收到的正是静态阶段那个 report 对象（供 decide_capture 消费）。
    assert seen["report"] is report


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


# ---------------------------------------------------------------------------
# P0-c：两遍编排（第一遍 original 基线 → 判据 → 按需+需授权的旁路轮）
# ---------------------------------------------------------------------------


def _patch_capture_multi(monkeypatch: pytest.MonkeyPatch, results: list[dict]) -> list[dict]:
    """记录**每一次** capture.run 调用（既有 _patch_capture 只记最后一次，两遍测试不够用）。

    results 按调用序依次返回；用尽后重复最后一个。
    """
    import apkscan.dynamic.capture as capture_mod

    calls: list[dict] = []

    def _fake_run(package: str, *a: Any, **k: Any) -> dict:
        calls.append({"package": package, "kwargs": k})
        return results[min(len(calls) - 1, len(results) - 1)]

    monkeypatch.setattr(capture_mod, "run", _fake_run)
    return calls


def _write_pass1_report(out_dir: str, *, endpoint_total: int = 3, signals: dict | None = None) -> str:
    """在 pass1 子目录写一份第一遍 runtime_report.json（判据的输入）。"""
    import json as _json
    from pathlib import Path as _P

    p = _P(out_dir) / "pass1-original"
    p.mkdir(parents=True, exist_ok=True)
    payload = {
        "package_name": "com.fraud.app",
        "source": "runtime",
        "runtime_variant": "original-runtime",
        "endpoint_total": endpoint_total,
        "capture_signals": {
            "hook_ready_status": "confirmed",
            "frida_retreated": False,
            "frida_retreat_count": 0,
            **(signals or {}),
        },
    }
    f = p / "runtime_report.json"
    f.write_text(_json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(f)


def _auto_two_pass_env(monkeypatch: pytest.MonkeyPatch) -> Report:
    """两遍编排测试的公共环境：静态 ok、有设备、脱壳 done、merge 打桩。"""
    report = _patch_static_ok(monkeypatch, "com.fraud.app")
    _patch_doctor(monkeypatch, ok=True)
    _patch_merge(monkeypatch)
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    return report


def _fake_repack_done(wrapper_path: str):
    """替身：去壳重打包成功并产出 wrapper APK 路径。"""

    def _inner(*a: Any, **k: Any):
        return auto._step(auto._STEP_REPACKAGE, "done", "去壳版已装回"), wrapper_path

    return _inner


def test_pass1_runs_original_before_any_bypass(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """★第一遍必须抓原版：产物落 pass1-original，且不带任何行为修改授权。"""
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=3)
    calls = _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])

    auto.run("sample.apk", out_dir=out)

    assert calls, "第一遍必须跑"
    first = calls[0]["kwargs"]
    assert "pass1-original" in str(first.get("out"))
    # 第一遍绝不注入行为修改 shim
    assert first.get("allow_behavior_modification", False) is False
    assert first.get("antidetect", "off") == "off"


def test_no_bypass_when_pass1_healthy(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """第一遍健康（有端点、hook 就绪、未秒退）→ 不跑第二遍，只记一条说明性 skipped。"""
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=3)
    calls = _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])

    result = auto.run("sample.apk", out_dir=out)

    assert len(calls) == 1, "健康时不应有第二遍"
    bypass = [s for s in result["steps"] if s["name"] == auto._STEP_BYPASS]
    assert bypass and bypass[0]["status"] == "skipped"
    assert "无需旁路" in bypass[0]["detail"]
    # ★措辞不得替信号下结论：不能在 hook 状态未知时宣称"hook 就绪"（那是报告一个并不知道的事实）
    assert "hook 就绪" not in bypass[0]["detail"]


def test_bypass_suggested_but_unauthorized_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★判据建议但未授权 → 结构化 skipped + 写明原因，绝不自动提权跑第二遍。"""
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)  # 业务端点为零 → 建议旁路
    calls = _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])

    result = auto.run("sample.apk", out_dir=out)  # 不给授权

    assert len(calls) == 1, "未授权时绝不能跑第二遍"
    bypass = [s for s in result["steps"] if s["name"] == auto._STEP_BYPASS]
    assert bypass and bypass[0]["status"] == "skipped"
    assert "未取得行为修改授权" in bypass[0]["detail"]
    assert "业务端点为零" in bypass[0]["detail"]  # 原因要可查


def test_bypass_refused_without_pass1_baseline(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """★硬前置：第一遍没产出 original 基线 → 即便已授权也拒绝跑第二遍。

    否则唯一的运行时证据将全部来自被我方诱导的那一轮，且无从对照。
    """
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    calls = _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_ERROR, reason="设备掉线")])

    result = auto.run(
        "sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java"
    )

    # ★核心断言钉在**行为**上：没有基线就绝不能有第二次 capture、绝不能重打包。
    #   （只断言 detail 措辞不够——判据函数自己也会拦，那样测的是判据不是这道硬前置。）
    assert len(calls) == 1, "无基线时绝不能跑第二遍"
    assert not any(s["name"].startswith("旁路轮·") for s in result["steps"]), (
        "无基线时不应产生任何旁路轮实际步骤（重打包/抓包）"
    )
    bypass = [s for s in result["steps"] if s["name"] == auto._STEP_BYPASS]
    assert bypass and bypass[0]["status"] == "skipped"
    assert "基线" in bypass[0]["detail"]


def test_bypass_runs_with_shim_when_authorized(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """★判据建议 + 已授权 → 跑第二遍：落 pass2-modified、带 shim 授权、且不把静态 report 传进去。"""
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    pass2_rr = str(tmp_path / "pass2-modified" / "runtime_report.json")
    calls = _patch_capture_multi(
        monkeypatch,
        [
            _dynamic_result(STATUS_DONE, report_paths=[rr]),
            _dynamic_result(STATUS_DONE, report_paths=[pass2_rr]),
        ],
    )
    wrapper = tmp_path / "wrapper.apk"
    wrapper.write_bytes(b"PK\x03\x04wrapper")
    monkeypatch.setattr(auto, "_run_repackage", _fake_repack_done(str(wrapper)))

    auto.run("sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java")

    assert len(calls) == 2, "已授权且判据建议时应跑第二遍"
    second = calls[1]["kwargs"]
    assert "pass2-modified" in str(second.get("out"))
    assert second.get("allow_behavior_modification") is True
    assert second.get("antidetect") == "java"
    # ★第二遍不并入主报告：不把静态 report 传进旁路轮
    assert second.get("report") is None


def test_bypass_failure_does_not_retry_or_break_main(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★旁路失败即退回 PCAP 主链：恰好尝试一次、不重试，主报告与第一遍产物不受影响。"""
    report = _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    calls = _patch_capture_multi(
        monkeypatch,
        [
            _dynamic_result(STATUS_DONE, report_paths=[rr]),
            _dynamic_result(STATUS_ERROR, reason="旁路轮抓包失败"),
        ],
    )
    wrapper = tmp_path / "wrapper.apk"
    wrapper.write_bytes(b"PK\x03\x04wrapper")
    monkeypatch.setattr(auto, "_run_repackage", _fake_repack_done(str(wrapper)))

    result = auto.run(
        "sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java"
    )

    assert len(calls) == 2, "旁路失败后绝不重试（恰好两次：第一遍 + 一次旁路）"
    assert isinstance(result, dict) and result.get("steps"), "旁路失败不得让 auto.run 抛"
    # 主报告仍带第一遍的 original 身份，未被旁路失败污染
    assert report.meta["capture_apk_identity"]["which"] == "original"
    # 旁路失败 → 不挂 pass2 指针
    assert "pass2_runtime_report" not in report.meta["capture_apk_identity"]


def test_main_report_records_original_apk_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★APK 身份贯穿：主报告 meta 记录实际抓的 APK 及其 sha256（路径可同名，哈希才是身份）。"""
    import hashlib as _hl

    report = _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK\x03\x04original-sample")
    expected = _hl.sha256(apk.read_bytes()).hexdigest()
    rr = _write_pass1_report(out, endpoint_total=3)
    _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])

    auto.run(str(apk), out_dir=out)

    identity = report.meta["capture_apk_identity"]
    assert identity["which"] == "original"
    assert identity["original"]["sha256"] == expected
    assert identity["wrapper"] is None


def test_bypass_records_wrapper_identity_and_pointer(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★旁路轮成功 → meta 记 wrapper 身份 + pass2 报告指针（该份是 modified-runtime，不并入主报告）。"""
    import hashlib as _hl

    report = _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    pass2_rr = str(tmp_path / "pass2-modified" / "runtime_report.json")
    _patch_capture_multi(
        monkeypatch,
        [
            _dynamic_result(STATUS_DONE, report_paths=[rr]),
            _dynamic_result(STATUS_DONE, report_paths=[pass2_rr]),
        ],
    )
    wrapper = tmp_path / "wrapper.apk"
    wrapper.write_bytes(b"PK\x03\x04deshelled-wrapper")
    wrapper_sha = _hl.sha256(wrapper.read_bytes()).hexdigest()
    monkeypatch.setattr(auto, "_run_repackage", _fake_repack_done(str(wrapper)))

    auto.run("sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java")

    identity = report.meta["capture_apk_identity"]
    assert identity["wrapper"]["sha256"] == wrapper_sha
    assert identity["wrapper"]["path"] == str(wrapper)
    assert identity["pass2_runtime_report"] == pass2_rr


def test_pass1_suggests_bypass_judgement_table() -> None:
    """判据表：四条各自独立触发；健康态不建议；无基线一律不建议。"""
    healthy = {"endpoint_total": 3, "capture_signals": {"hook_ready_status": "confirmed"}}
    assert auto._pass1_suggests_bypass("done", healthy)[0] is False

    ok, why = auto._pass1_suggests_bypass(
        "done", {"endpoint_total": 0, "capture_signals": {"hook_ready_status": "confirmed"}}
    )
    assert ok and "业务端点为零" in why

    ok, why = auto._pass1_suggests_bypass(
        "done",
        {
            "endpoint_total": 3,
            "capture_signals": {
                "hook_ready_status": "confirmed",
                "frida_retreated": True,
                "frida_retreat_count": 3,
            },
        },
    )
    assert ok and "秒退" in why and "3 次" in why

    ok, why = auto._pass1_suggests_bypass(
        "done", {"endpoint_total": 3, "capture_signals": {"hook_ready_status": "none"}}
    )
    assert ok and "hook 未就绪" in why

    ok, why = auto._pass1_suggests_bypass("degraded", healthy)
    assert ok and "降级" in why

    ok, why = auto._pass1_suggests_bypass("error", healthy)
    assert ok is False and "基线" in why


def test_bypass_refused_when_pass1_report_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★硬前置守的另一半：第一遍 status=done 但产物读不回（写失败/坏 JSON）→ 仍拒绝旁路。

    判据函数只看 status，看不到「报告到底读没读到」——这一条只有编排层的硬前置能拦。
    删掉硬前置里的 runtime_report_path / pass1_payload 校验，本测试必红。
    """
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    # done 但 report_paths 为空 → runtime_report_path 为空串
    calls = _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[])])
    monkeypatch.setattr(
        auto, "_run_repackage", _fake_repack_done(str(tmp_path / "wrapper.apk"))
    )

    result = auto.run(
        "sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java"
    )

    assert len(calls) == 1, "读不回第一遍产物时绝不能跑第二遍"
    assert not any(s["name"].startswith("旁路轮·") for s in result["steps"])
    bypass = [s for s in result["steps"] if s["name"] == auto._STEP_BYPASS]
    assert bypass and bypass[0]["status"] == "skipped"


def test_two_passes_use_distinct_device_floor_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★★证据防丢（codex 复审 P0）：两遍的**设备侧** floor pcap 路径必须不同。

    capture 承诺 pull 失败时保留远端 pcap 供手动重拉；若两遍共用固定远端路径，第二遍起手的
    rm -f 会删掉第一遍特意保留的原始证据（不可恢复）。删掉 pass_tag 透传，本测试必红。
    """
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    pass2_rr = str(tmp_path / "pass2-modified" / "runtime_report.json")
    calls = _patch_capture_multi(
        monkeypatch,
        [
            _dynamic_result(STATUS_DONE, report_paths=[rr]),
            _dynamic_result(STATUS_DONE, report_paths=[pass2_rr]),
        ],
    )
    wrapper = tmp_path / "wrapper.apk"
    wrapper.write_bytes(b"PKw")
    monkeypatch.setattr(auto, "_run_repackage", _fake_repack_done(str(wrapper)))

    auto.run("sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java")

    assert len(calls) == 2
    tag1 = calls[0]["kwargs"].get("pass_tag")
    tag2 = calls[1]["kwargs"].get("pass_tag")
    assert tag1 and tag2 and tag1 != tag2, (
        f"两遍必须用不同的设备侧 floor 路径标识，实得 {tag1!r} / {tag2!r}"
    )


def test_bypass_repackage_uses_main_out_dir_for_dump(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★旁路轮重打包必须传主 out_dir（codex 复审 P1）：repackage 固定从 <out_dir>/dump 取脱壳 DEX，
    而脱壳产物落主 out/dump。传 pass2 子目录会让它恒报「无料可重打包」。"""
    _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    _patch_capture_multi(
        monkeypatch,
        [_dynamic_result(STATUS_DONE, report_paths=[rr]), _dynamic_result(STATUS_DONE, report_paths=["x"])],
    )
    seen: dict = {}

    def _spy_repack(*a: Any, **k: Any):
        seen["out_dir"] = k.get("out_dir")
        return auto._step(auto._STEP_REPACKAGE, "done", "ok"), str(tmp_path / "w.apk")

    monkeypatch.setattr(auto, "_run_repackage", _spy_repack)

    auto.run("sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java")

    assert seen["out_dir"] == out, "重打包必须用主 out_dir（脱壳 DEX 在那），不能用 pass2 子目录"


def test_bypass_records_actual_variant_not_assumed(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★据实记录旁路轮 variant（codex 复审 P1）：授权了但 frida 回退 subprocess 时 shim 没进去，
    capture 会诚实写 original-runtime——主报告不得替它宣称 modified-runtime。"""
    report = _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=0)
    # 第二遍产物：capture 实测判定为 original-runtime（shim 实际未注入）
    p2dir = tmp_path / "pass2-modified"
    p2dir.mkdir(parents=True, exist_ok=True)
    p2 = p2dir / "runtime_report.json"
    p2.write_text(json.dumps({"runtime_variant": "original-runtime", "endpoint_total": 0}), encoding="utf-8")
    _patch_capture_multi(
        monkeypatch,
        [
            _dynamic_result(STATUS_DONE, report_paths=[rr]),
            _dynamic_result(STATUS_DONE, report_paths=[str(p2)]),
        ],
    )
    wrapper = tmp_path / "wrapper.apk"
    wrapper.write_bytes(b"PK")
    monkeypatch.setattr(auto, "_run_repackage", _fake_repack_done(str(wrapper)))

    auto.run("sample.apk", out_dir=out, allow_behavior_modification=True, antidetect="java")

    identity = report.meta["capture_apk_identity"]
    assert identity["pass2_runtime_variant"] == "original-runtime", (
        "必须读回 capture 的实测结论，不能假定旁路轮一定是 modified-runtime"
    )


def test_pass1_baseline_undecidable_refuses_bypass() -> None:
    """★字段缺失 ≠ 端点为零（codex 复审 P1）：payload 缺 endpoint_total/endpoints → 基线不可判定，
    拒绝据以推荐旁路（不可判定不得返回正常值）。"""
    ok, why = auto._pass1_suggests_bypass("done", {"capture_signals": {}})
    assert ok is False and "不可判定" in why
    # 有合法 endpoints 数组时可退而按其长度判
    ok, why = auto._pass1_suggests_bypass(
        "done", {"endpoints": [], "capture_signals": {"hook_ready_status": "confirmed"}}
    )
    assert ok and "业务端点为零" in why


def test_install_failure_marks_apk_identity_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """★★跨运行污染防线（codex 复审新 P0）：装原包失败 → 设备上跑的可能是上次遗留的 wrapper，
    身份必须标 unknown + 告警，绝不能想当然标 original。

    复现场景：上一次旁路轮成功、wrapper 留在设备上；本次原包因签名不同 UPDATE_INCOMPATIBLE，
    流水线继续但第一遍 spawn 的是那个 wrapper。若标 original，其流量会以干净轮身份进主报告。
    """
    report = _auto_two_pass_env(monkeypatch)
    out = str(tmp_path)
    rr = _write_pass1_report(out, endpoint_total=3)
    _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])
    # 装原包失败（签名冲突）
    import apkscan.dynamic.provision as _prov

    monkeypatch.setattr(
        _prov, "install_apk",
        lambda *a, **k: {"ok": False, "detail": "INSTALL_FAILED_UPDATE_INCOMPATIBLE"},
    )

    auto.run("sample.apk", out_dir=out)

    identity = report.meta["capture_apk_identity"]
    assert identity["which"] == "unknown", "装原包失败时身份不可确认，不得标 original"
    assert "identity_warning" in identity
    assert "不可确认" in identity["identity_warning"]


def test_capture_degraded_still_yields_baseline(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """★degraded 判据必须在生产链路可达（codex 复审 P1）：capture 返回 degraded 时
    _run_capture 应保留该状态并照常解析报告路径，否则旁路判据里的 degraded 分支永远走不到。"""
    from apkscan.dynamic import STATUS_DEGRADED

    import apkscan.dynamic.capture as capture_mod

    rr = tmp_path / "runtime_report.json"
    rr.write_text(json.dumps({"endpoint_total": 0}), encoding="utf-8")
    monkeypatch.setattr(
        capture_mod, "run",
        lambda *a, **k: _dynamic_result(STATUS_DEGRADED, "无证据路径", report_paths=[str(rr)]),
    )

    step, path = auto._run_capture(
        "com.fraud.app", out_dir=str(tmp_path), has_device=True, duration=1,
        on_progress=None, confirm=None,
    )

    assert step["status"] == "degraded", "degraded 不应被折成 error（那会让基线与判据都丢失）"
    assert path == str(rr), "degraded 轮同样产出了 runtime_report，必须解析出路径"


def test_negative_endpoint_total_is_undecidable() -> None:
    """★P2：负数计数是坏值，不能当合法基线（会输出「无需旁路」而掩盖问题）。"""
    ok, why = auto._pass1_suggests_bypass("done", {"endpoint_total": -1, "capture_signals": {}})
    assert ok is False and "不可判定" in why


def test_unknown_identity_reaches_quality_gate(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """★★端到端门控锁（codex 复审 P0）：身份 unknown 必须一路传到 quality 门并封顶。

    codex 的复现链：遗留 wrapper → 原包装失败 → which=unknown，但 capture 照写 original-runtime，
    而闭环门只看 runtime_variant → 遗留 wrapper 的流量仍能升 complete。断掉 merge 里注入身份的
    那几行，本测试必红。
    """
    from apkscan.dynamic import merge as merge_mod

    report = _patch_static_ok(monkeypatch, "com.fraud.app")
    _patch_doctor(monkeypatch, ok=True)
    _set_device(monkeypatch, True)
    _patch_unpack(monkeypatch, _dynamic_result(STATUS_DONE))
    out = str(tmp_path)
    # 第一遍产物：capture 诚实写 original-runtime（它不知道设备上装的是遗留 wrapper），
    # 且计数满足 complete 条件
    rr = _write_pass1_report(out, endpoint_total=3)
    payload = json.loads(Path(rr).read_text(encoding="utf-8"))
    payload["capture_signals"].update({
        "channel_ready": True, "pcap_valid": True, "packet_count": 12,
        "business_candidate_count": 1, "target_attributed_count": 1,
        "bidirectional_target_count": 1, "runtime_variant": "original-runtime",
    })
    Path(rr).write_text(json.dumps(payload), encoding="utf-8")
    _patch_capture_multi(monkeypatch, [_dynamic_result(STATUS_DONE, report_paths=[rr])])
    # 装原包失败（遗留 wrapper 签名冲突）
    import apkscan.dynamic.provision as _prov

    monkeypatch.setattr(
        _prov, "install_apk",
        lambda *a, **k: {"ok": False, "detail": "INSTALL_FAILED_UPDATE_INCOMPATIBLE"},
    )
    # 只桩 load（让真 merge_capture_quality 跑），rerender 走真实现的 quality 注入
    monkeypatch.setattr(merge_mod, "load_runtime_endpoints", lambda p: [])

    auto.run("sample.apk", out_dir=out)

    assert report.meta["capture_apk_identity"]["which"] == "unknown"
    quality = report.meta.get("capture_quality") or {}
    assert quality.get("capture_apk_identity_which") == "unknown", (
        "身份必须传到 quality 门，否则机器消费方读不到（只标注不门控＝无效）"
    )
    assert quality.get("dynamic_status") != "complete", "身份不可确认的轮次不得判 complete"
