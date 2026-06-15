"""apkscan.dynamic.unpack 单测：monkeypatch device.* 与 subprocess，离线、无真机。

覆盖三条主路径（与 DynamicResult 契约对齐）：
  1. 无设备 / 缺工具 → status="skipped" + 精确手册（playbook 非空，含关键命令）。
  2. 满足条件 + dump 成功 → status="done" + artifacts（dump 出的 .dex）+ report_paths。
  3. frida-dexdump 失败（非零退出）→ status="error" + reason，不抛。

不依赖 androguard / 网络：load_apk 取包名、reanalyze 全部 monkeypatch。
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
)
from apkscan.dynamic import unpack


# ---------------------------------------------------------------------------
# 辅助：把 device 能力探测全部置为"满足"，单测可按需关掉某一项。
# ---------------------------------------------------------------------------


def _all_capabilities_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """让 unpack 看到的 device.* 全部返回 True（root 设备 + frida + frida-dexdump + frida-server）。

    同时把 tools.frida_invocation 桩成返回纯命令名 ``["frida-dexdump"]``——_dexdump 改用
    tools 解析后，源码态 PATH 无 frida-dexdump 会返回 []，需在此显式给出可读命令前缀，
    令 ``cmd[0]=="frida-dexdump"`` 断言成立、subprocess 桩正常拿到命令。
    """
    monkeypatch.setattr(unpack.device, "has_device", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida_dexdump", lambda: True)
    monkeypatch.setattr(unpack.device, "frida_server_running", lambda serial=None: True)
    monkeypatch.setattr(unpack.tools, "frida_invocation", lambda tool: ["frida-dexdump"])


def _patch_package_name(monkeypatch: pytest.MonkeyPatch, name: str = "com.fraud.app") -> None:
    """跳过真实 androguard：直接给定包名。"""
    monkeypatch.setattr(unpack, "_resolve_package_name", lambda apk_path: name)


class _FakeProc:
    """subprocess.CompletedProcess 的最小替身。"""

    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


# ---------------------------------------------------------------------------
# 1) 无设备 / 缺工具 → skipped + playbook
# ---------------------------------------------------------------------------


def test_no_device_skipped_with_playbook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unpack.device, "has_device", lambda: False)
    monkeypatch.setattr(unpack.device, "has_frida", lambda: False)
    monkeypatch.setattr(unpack.device, "has_frida_dexdump", lambda: False)
    monkeypatch.setattr(unpack.device, "frida_server_running", lambda serial=None: False)

    result = unpack.run("nonexistent.apk")

    assert result["status"] == STATUS_SKIPPED
    assert "缺少" in result["reason"]
    assert result["artifacts"] == []
    assert result["report_paths"] == []
    # 手册非空且含关键精确命令。
    playbook_text = "\n".join(result["playbook"])
    assert result["playbook"]
    assert "adb devices" in playbook_text
    assert "adb push" in playbook_text
    assert "chmod" in playbook_text
    assert "/data/local/tmp" in playbook_text
    assert "pip install" in playbook_text and "frida-dexdump" in playbook_text
    assert "frida-dexdump -FU -f <package>" in playbook_text
    assert "apkscan analyze <apk> --extra-dex" in playbook_text


def test_missing_only_frida_server_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """有设备 + 工具齐，但 frida-server 没跑 → 仍 skipped，reason 点名 frida-server。"""
    monkeypatch.setattr(unpack.device, "has_device", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida_dexdump", lambda: True)
    monkeypatch.setattr(unpack.device, "frida_server_running", lambda serial=None: False)

    result = unpack.run("x.apk")

    assert result["status"] == STATUS_SKIPPED
    assert "frida-server" in result["reason"]
    assert result["playbook"]


def test_missing_frida_dexdump_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unpack.device, "has_device", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida", lambda: True)
    monkeypatch.setattr(unpack.device, "has_frida_dexdump", lambda: False)
    monkeypatch.setattr(unpack.device, "frida_server_running", lambda serial=None: True)

    result = unpack.run("x.apk")

    assert result["status"] == STATUS_SKIPPED
    assert "frida-dexdump" in result["reason"]


# ---------------------------------------------------------------------------
# 2) 满足条件 + dump 成功 → done + artifacts (+ report_paths)
# ---------------------------------------------------------------------------


def test_dump_success_done_with_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch, "com.fraud.app")

    out_dir = tmp_path / "out"

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        # frida-dexdump 命令应携带 -FU -f <package>。
        assert "frida-dexdump" in cmd[0]
        assert "-FU" in cmd
        assert "com.fraud.app" in cmd
        # 模拟脱壳：往 -o 目录写两个 .dex。
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00fake")
        (dump_dir / "classes2.dex").write_bytes(b"dex\n035\x00fake2")
        return _FakeProc(returncode=0, stdout="[+] DexDump finished")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    # reanalyze：避免真实 androguard/pipeline，断言收到的 extra_dex 是 dump 产物。
    captured: dict[str, Any] = {}

    def _fake_reanalyze(apk_path: str, extra_dex: list[str], out: str) -> list[str]:
        captured["apk_path"] = apk_path
        captured["extra_dex"] = list(extra_dex)
        captured["out"] = out
        return [str(Path(out) / "unpacked_report.json"), str(Path(out) / "unpacked_report.html")]

    monkeypatch.setattr(unpack, "_reanalyze", _fake_reanalyze)

    result = unpack.run("sample.apk", out_dir=str(out_dir), reanalyze=True)

    assert result["status"] == STATUS_DONE
    assert len(result["artifacts"]) == 2
    assert all(a.endswith(".dex") for a in result["artifacts"])
    assert all(Path(a).is_file() for a in result["artifacts"])
    # report_paths 来自重分析。
    assert len(result["report_paths"]) == 2
    assert any(p.endswith("unpacked_report.json") for p in result["report_paths"])
    # 重分析确实收到 dump 出来的 dex 路径。
    assert captured["extra_dex"] == result["artifacts"]
    assert captured["apk_path"] == "sample.apk"
    # playbook 含执行过的 dexdump 命令与回灌命令。
    playbook_text = "\n".join(result["playbook"])
    assert "frida-dexdump" in playbook_text
    assert "--extra-dex" in playbook_text


def test_dump_success_no_reanalyze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """reanalyze=False：done + artifacts，report_paths 为空，playbook 给手动回灌命令。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch, "com.fraud.app")

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00fake")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    # reanalyze=False 时不应调用 _reanalyze（调到就炸，做哨兵）。
    def _boom(*args: Any, **kwargs: Any) -> list[str]:
        raise AssertionError("reanalyze=False 不应触发重分析")

    monkeypatch.setattr(unpack, "_reanalyze", _boom)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"), reanalyze=False)

    assert result["status"] == STATUS_DONE
    assert len(result["artifacts"]) == 1
    assert result["report_paths"] == []
    assert any("--extra-dex" in step for step in result["playbook"])


def test_out_keyword_alias(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """CLI 以 out= 调用：out 应覆盖 out_dir，dump 落到 out 指定目录。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    target = tmp_path / "cli_out"

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        # dump 目录应位于 out= 指定的目录下。
        assert str(target) in str(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00x")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)
    monkeypatch.setattr(unpack, "_reanalyze", lambda a, e, o: [])

    result = unpack.run("sample.apk", out=str(target), reanalyze=True)
    assert result["status"] == STATUS_DONE
    assert result["artifacts"]


# ---------------------------------------------------------------------------
# serial 注入（P0 多设备：frida-dexdump 用 -F -D <serial> 钉定那台；None 退回 -FU）
# ---------------------------------------------------------------------------


def test_dexdump_uses_dash_d_when_serial_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """serial 给定 → frida-dexdump 命令含 -F -D <serial>（不含 -FU/-U）；frida-server 探测带 serial。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch, "com.fraud.app")
    seen_serials: list[str | None] = []
    monkeypatch.setattr(
        unpack.device,
        "frida_server_running",
        lambda serial=None: seen_serials.append(serial) or True,
    )

    captured: dict[str, list[str]] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        captured["cmd"] = list(cmd)
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00x")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)
    monkeypatch.setattr(unpack, "_reanalyze", lambda a, e, o: [])

    result = unpack.run(
        "sample.apk", out_dir=str(tmp_path / "out"), reanalyze=True, serial="emulator-5554"
    )
    assert result["status"] == STATUS_DONE
    cmd = captured["cmd"]
    assert "-D" in cmd
    assert "emulator-5554" in cmd
    assert "-FU" not in cmd  # 不再用 USB ambiguous 选择
    assert "-F" in cmd  # 仍 attach 前台
    # frida-server 运行探测也带上了选定 serial（多设备消歧）。
    assert "emulator-5554" in seen_serials


def test_dexdump_keeps_fu_when_serial_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """serial=None（旧路径/测试）→ 仍用 -FU（向后兼容）。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch, "com.fraud.app")

    captured: dict[str, list[str]] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        captured["cmd"] = list(cmd)
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00x")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)
    monkeypatch.setattr(unpack, "_reanalyze", lambda a, e, o: [])

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"), reanalyze=True)
    assert result["status"] == STATUS_DONE
    assert "-FU" in captured["cmd"]
    assert "-D" not in captured["cmd"]


def test_dexdump_does_not_use_pipe_avoids_grandchild_hang(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """回归：frida-dexdump 的 stdout/stderr 绝不能用 PIPE（capture_output=True）。

    frida-dexdump 会派生 frida 孙进程并继承 stdout 管道写端；若用 PIPE，300s 超时后
    subprocess.run 排空管道的 communicate() 会因孙进程未退而**永久阻塞**——超时形同虚设，
    GUI 一键全自动卡在第三步脱壳、进不了第四步抓包。必须重定向到文件（无管道可阻塞）。
    """
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)
    seen: dict[str, Any] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        seen["kwargs"] = kwargs
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00x")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)
    monkeypatch.setattr(unpack, "_reanalyze", lambda a, e, o: [])

    unpack.run("sample.apk", out_dir=str(tmp_path / "out"), reanalyze=True)

    kw = seen["kwargs"]
    assert not kw.get("capture_output"), "不得用 capture_output(=PIPE)，孙进程持管道写端会致超时后卡死"
    assert kw.get("stdout") not in (None, subprocess.PIPE), "stdout 必须重定向到文件，而非 PIPE"
    assert kw.get("stderr") != subprocess.PIPE, "stderr 不得用 PIPE"


# ---------------------------------------------------------------------------
# 3) frida-dexdump 失败 → error
# ---------------------------------------------------------------------------


def test_dexdump_nonzero_exit_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        return _FakeProc(returncode=1, stdout="Failed to spawn: unable to find process")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"))

    assert result["status"] == STATUS_ERROR
    assert "frida-dexdump" in result["reason"]
    assert "returncode=1" in result["reason"]
    assert result["artifacts"] == []


def test_dexdump_timeout_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=unpack._DEXDUMP_TIMEOUT)

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"))

    assert result["status"] == STATUS_ERROR
    assert "超时" in result["reason"]
    assert result["artifacts"] == []


def test_dexdump_zero_exit_but_no_dex_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """退出 0 但目录没产出 .dex → error（避免静默当成功）。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        o_idx = cmd.index("-o")
        Path(cmd[o_idx + 1]).mkdir(parents=True, exist_ok=True)  # 空目录
        return _FakeProc(returncode=0, stdout="done but empty")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"))

    assert result["status"] == STATUS_ERROR
    assert "未 dump" in result["reason"] or "未 dump 出" in result["reason"]
    assert result["artifacts"] == []


def test_subprocess_exception_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """subprocess 抛非超时异常 → error，不外泄。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        raise OSError("frida-dexdump not executable")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"))

    assert result["status"] == STATUS_ERROR
    assert result["artifacts"] == []


def test_empty_package_name_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """load_apk 解析出空包名 → error（frida-dexdump 需 -f <package>）。"""
    _all_capabilities_ok(monkeypatch)
    monkeypatch.setattr(unpack, "_resolve_package_name", lambda apk_path: "")

    result = unpack.run("sample.apk")

    assert result["status"] == STATUS_ERROR
    assert "包名" in result["reason"]


def test_load_apk_raises_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """load_apk 取包名抛异常 → error，不外泄。"""
    _all_capabilities_ok(monkeypatch)

    def _boom(apk_path: str) -> str:
        raise RuntimeError("无法解析 APK")

    monkeypatch.setattr(unpack, "_resolve_package_name", _boom)

    result = unpack.run("broken.apk")

    assert result["status"] == STATUS_ERROR
    assert "无法解析" in result["reason"] or "取包名失败" in result["reason"]


def test_reanalyze_failure_keeps_artifacts_done(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """脱壳成功但重分析炸 → 仍 done（产物在 artifacts），reason 标注重分析失败。"""
    _all_capabilities_ok(monkeypatch)
    _patch_package_name(monkeypatch)

    def _fake_run(cmd: list[str], **kwargs: Any) -> _FakeProc:
        o_idx = cmd.index("-o")
        dump_dir = Path(cmd[o_idx + 1])
        dump_dir.mkdir(parents=True, exist_ok=True)
        (dump_dir / "classes.dex").write_bytes(b"dex\n035\x00x")
        return _FakeProc(returncode=0, stdout="ok")

    monkeypatch.setattr(unpack.subprocess, "run", _fake_run)

    def _boom_reanalyze(apk_path: str, extra_dex: list[str], out: str) -> list[str]:
        raise RuntimeError("androguard 解析 extra dex 失败")

    monkeypatch.setattr(unpack, "_reanalyze", _boom_reanalyze)

    result = unpack.run("sample.apk", out_dir=str(tmp_path / "out"), reanalyze=True)

    assert result["status"] == STATUS_DONE
    assert result["artifacts"]  # 脱壳产物保留
    assert "重分析失败" in result["reason"]
    assert result["report_paths"] == []
