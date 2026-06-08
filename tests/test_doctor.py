"""apkscan.dynamic.doctor 单测：device / provision 全 mock，无真机锁行为。

策略（无真机/无外网）：
- monkeypatch device.adb_devices / has_device / has_mitmproxy / frida_server_running。
- monkeypatch provision.device_abi / host_frida_version / ensure_frida_server /
  ensure_mitm_ca / _adb / _adb_ok / _mitm_ca_path / _subject_hash_old。
- 覆盖：返回结构、全 ok、各项缺失、自动修成功/失败、版本不匹配、单项异常不中断、
  auto_fix=False 不调修复器、on_progress、不抛不 print。
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from apkscan.core import device
from apkscan.dynamic import doctor, provision


# ---------------------------------------------------------------------------
# 公共替身 / 辅助
# ---------------------------------------------------------------------------


class _FakeCompleted:
    """subprocess.CompletedProcess 的最小替身。"""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _item_by_name(result: dict, name: str) -> dict:
    """从 run 结果取指定名称的检查项。"""
    for it in result["items"]:
        if it["name"] == name:
            return it
    raise AssertionError(f"item not found: {name}; items={[i['name'] for i in result['items']]}")


def _all_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """把所有依赖打桩成"环境完备、自动修成功"的状态。"""
    monkeypatch.setattr(device, "adb_devices", lambda: ["emulator-5554"])
    monkeypatch.setattr(device, "has_device", lambda: True)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: True)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    # adb 可用：_check_device 改用 tools.has_adb（取代旧 shutil.which mock）。
    monkeypatch.setattr(doctor.tools, "has_adb", lambda: True)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "arm64-v8a")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "16.5.9")
    # 设备已 root：su -c id → uid=0。
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "uid=0(root)")
    )
    # 设备端 frida-server 版本与主机一致。
    monkeypatch.setattr(doctor, "_device_frida_version", lambda serial=None: "16.5.9")
    monkeypatch.setattr(
        provision,
        "ensure_frida_server",
        lambda serial=None, *, download=True, on_progress=None: {
            "ok": True,
            "action": "already_running",
            "detail": "frida-server 已在运行",
            "version": "16.5.9",
            "abi": "arm64-v8a",
            "fix_cmd": [],
        },
    )
    monkeypatch.setattr(
        provision,
        "ensure_mitm_ca",
        lambda serial=None, *, on_progress=None: {
            "ok": True,
            "action": "installed_system",
            "detail": "已装入系统信任库",
            "ca_path": "/home/u/.mitmproxy/mitmproxy-ca-cert.pem",
            "subject_hash": "c8750f0d",
            "store_path": "/system/etc/security/cacerts/c8750f0d.0",
            "fix_cmd": [],
        },
    )


# ---------------------------------------------------------------------------
# 结构 / 全 ok
# ---------------------------------------------------------------------------


def test_run_returns_items_with_required_keys(monkeypatch):
    _all_present(monkeypatch)
    res = doctor.run()
    assert isinstance(res, dict)
    assert "ok" in res and "items" in res
    assert isinstance(res["items"], list)
    assert res["items"]
    for it in res["items"]:
        assert set(it.keys()) >= {"name", "ok", "detail", "fix_cmd"}
        assert isinstance(it["name"], str)
        assert isinstance(it["ok"], bool)
        assert isinstance(it["detail"], str)
        assert isinstance(it["fix_cmd"], list)


def test_run_all_ok_when_everything_present(monkeypatch):
    _all_present(monkeypatch)
    res = doctor.run()
    assert res["ok"] is True
    # 关键项全 ok。
    for it in res["items"]:
        if it["name"] in doctor._CRITICAL:
            assert it["ok"] is True, it


# ---------------------------------------------------------------------------
# 各项缺失
# ---------------------------------------------------------------------------


def test_run_no_device_item_fail_with_fix_cmd(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "adb_devices", lambda: [])
    monkeypatch.setattr(device, "has_device", lambda: False)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_DEVICE)
    assert item["ok"] is False
    assert any("adb devices" in c for c in item["fix_cmd"])
    assert res["ok"] is False  # 关键项失败 → 整体失败


def test_run_no_device_when_adb_missing(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(doctor.tools, "has_adb", lambda: False)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_DEVICE)
    assert item["ok"] is False
    assert "adb" in item["detail"]


def test_run_no_root_item_fail(monkeypatch):
    _all_present(monkeypatch)
    # su -c id 非零退出 → 未 root。
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: _FakeCompleted(1, ""))
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_ROOT)
    assert item["ok"] is False
    assert item["fix_cmd"]
    # root 非关键项：整体 ok 不应仅因 root 失败而失败（其它关键项都 ok）。
    assert res["ok"] is True


def test_run_abi_item_uses_provision(monkeypatch):
    _all_present(monkeypatch)
    called: dict[str, bool] = {}

    def _abi(serial=None):
        called["abi"] = True
        return "x86_64"

    monkeypatch.setattr(provision, "device_abi", _abi)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_ABI)
    assert called.get("abi") is True
    assert item["ok"] is True
    assert "x86_64" in item["detail"]


def test_run_abi_missing_item_fail(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "")
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_ABI)
    assert item["ok"] is False
    assert any("getprop" in c for c in item["fix_cmd"])
    assert res["ok"] is False


def test_run_host_frida_missing_fix_cmd_pip(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(provision, "host_frida_version", lambda: "")
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_HOST_FRIDA)
    assert item["ok"] is False
    assert "pip install frida-tools" in item["fix_cmd"]
    assert res["ok"] is False


def test_run_mitmproxy_missing_item_fail(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: False)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_MITMPROXY)
    assert item["ok"] is False
    assert "pip install mitmproxy" in item["fix_cmd"]
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# frida-server 自动修 / 版本匹配
# ---------------------------------------------------------------------------


def test_run_frida_server_not_running_autofix_calls_ensure_frida_server(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    called: dict[str, Any] = {}

    def _ensure(serial=None, *, download=True, on_progress=None):
        called["serial"] = serial
        called["download"] = download
        return {
            "ok": True,
            "action": "deployed",
            "detail": "已部署并启动 frida-server 16.5.9",
            "version": "16.5.9",
            "abi": "arm64-v8a",
            "fix_cmd": [],
        }

    monkeypatch.setattr(provision, "ensure_frida_server", _ensure)
    res = doctor.run(serial="dev1")
    item = _item_by_name(res, doctor._NAME_FRIDA_SERVER)
    assert called.get("serial") == "dev1"
    assert called.get("download") is True
    assert item["ok"] is True
    assert "16.5.9" in item["detail"]


def test_run_frida_server_autofix_failure_folded(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)

    def _ensure(serial=None, *, download=True, on_progress=None):
        return {
            "ok": False,
            "action": "error",
            "detail": "chmod 755 失败：设备可能未 root（su 不可用）",
            "version": "16.5.9",
            "abi": "arm64-v8a",
            "fix_cmd": ["adb shell su -c id"],
        }

    monkeypatch.setattr(provision, "ensure_frida_server", _ensure)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_FRIDA_SERVER)
    assert item["ok"] is False
    assert "未 root" in item["detail"]
    assert item["fix_cmd"]
    assert res["ok"] is False


def test_run_frida_version_mismatch_flagged(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    # 设备端 16.0.0 ≠ 主机 16.5.9，auto_fix=False → 仅标记不匹配。
    monkeypatch.setattr(doctor, "_device_frida_version", lambda serial=None: "16.0.0")
    res = doctor.run(auto_fix=False)
    item = _item_by_name(res, doctor._NAME_FRIDA_SERVER)
    assert item["ok"] is False
    assert "16.0.0" in item["detail"]
    assert "16.5.9" in item["detail"]


def test_run_frida_version_mismatch_autofix_redeploys(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    monkeypatch.setattr(doctor, "_device_frida_version", lambda serial=None: "16.0.0")
    called: dict[str, bool] = {}

    def _ensure(serial=None, *, download=True, on_progress=None):
        called["redeploy"] = True
        return {
            "ok": True,
            "action": "deployed",
            "detail": "已部署并启动 frida-server 16.5.9",
            "version": "16.5.9",
            "abi": "arm64-v8a",
            "fix_cmd": [],
        }

    monkeypatch.setattr(provision, "ensure_frida_server", _ensure)
    res = doctor.run(auto_fix=True)
    item = _item_by_name(res, doctor._NAME_FRIDA_SERVER)
    assert called.get("redeploy") is True
    assert item["ok"] is True


def test_run_frida_server_running_version_unknown_is_ok(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: True)
    # 设备端版本拿不到 → best-effort 视作匹配，不判失败。
    monkeypatch.setattr(doctor, "_device_frida_version", lambda serial=None: "")
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_FRIDA_SERVER)
    assert item["ok"] is True


# ---------------------------------------------------------------------------
# CA 自动修 / 只读
# ---------------------------------------------------------------------------


def test_run_ca_item_autofix_calls_ensure_mitm_ca(monkeypatch):
    _all_present(monkeypatch)
    called: dict[str, Any] = {}

    def _ensure_ca(serial=None, *, on_progress=None):
        called["serial"] = serial
        return {
            "ok": True,
            "action": "installed_system",
            "detail": "已装入系统信任库",
            "ca_path": "x",
            "subject_hash": "c8750f0d",
            "store_path": "/system/etc/security/cacerts/c8750f0d.0",
            "fix_cmd": [],
        }

    monkeypatch.setattr(provision, "ensure_mitm_ca", _ensure_ca)
    res = doctor.run(serial="dev1")
    item = _item_by_name(res, doctor._NAME_CA)
    assert called.get("serial") == "dev1"
    assert item["ok"] is True


def test_run_ca_autofix_failure_no_root(monkeypatch):
    _all_present(monkeypatch)

    def _ensure_ca(serial=None, *, on_progress=None):
        return {
            "ok": False,
            "action": "error",
            "detail": "无 root，HTTPS 将只抓到密文",
            "ca_path": "x",
            "subject_hash": "c8750f0d",
            "store_path": "",
            "fix_cmd": ["adb root", "adb remount"],
        }

    monkeypatch.setattr(provision, "ensure_mitm_ca", _ensure_ca)
    res = doctor.run()
    item = _item_by_name(res, doctor._NAME_CA)
    assert item["ok"] is False
    assert "密文" in item["detail"]
    assert item["fix_cmd"]
    assert res["ok"] is False


def test_run_auto_fix_false_does_not_call_provision_fixers(monkeypatch):
    _all_present(monkeypatch)
    # frida-server 已在跑且版本匹配，CA 只读 best-effort。
    def _boom_frida(*a, **k):
        raise AssertionError("ensure_frida_server should NOT be called with auto_fix=False")

    def _boom_ca(*a, **k):
        raise AssertionError("ensure_mitm_ca should NOT be called with auto_fix=False")

    monkeypatch.setattr(provision, "ensure_frida_server", _boom_frida)
    monkeypatch.setattr(provision, "ensure_mitm_ca", _boom_ca)
    # CA 只读探测命中（视作已信任）。
    monkeypatch.setattr(doctor, "_ca_already_trusted", lambda serial=None: True)
    res = doctor.run(auto_fix=False)
    # 没有异常即说明两个修复器都没被调。
    assert isinstance(res, dict)
    ca_item = _item_by_name(res, doctor._NAME_CA)
    assert ca_item["ok"] is True


def test_run_ca_readonly_not_trusted_fails(monkeypatch):
    _all_present(monkeypatch)
    monkeypatch.setattr(provision, "ensure_mitm_ca", lambda *a, **k: pytest.fail("called"))
    monkeypatch.setattr(doctor, "_ca_already_trusted", lambda serial=None: False)
    res = doctor.run(auto_fix=False)
    item = _item_by_name(res, doctor._NAME_CA)
    assert item["ok"] is False
    assert res["ok"] is False


# ---------------------------------------------------------------------------
# 整体 ok / 鲁棒性
# ---------------------------------------------------------------------------


def test_run_overall_ok_false_when_critical_item_fails(monkeypatch):
    _all_present(monkeypatch)
    # mitmproxy 是关键项。
    monkeypatch.setattr(device, "has_mitmproxy", lambda: False)
    res = doctor.run()
    assert res["ok"] is False


def test_run_overall_ok_true_when_only_noncritical_fails(monkeypatch):
    _all_present(monkeypatch)
    # 仅 root（非关键项）失败，其它关键项全 ok → 整体 ok=True。
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: _FakeCompleted(1, ""))
    res = doctor.run()
    assert _item_by_name(res, doctor._NAME_ROOT)["ok"] is False
    assert res["ok"] is True


def test_run_single_item_exception_does_not_abort_others(monkeypatch):
    _all_present(monkeypatch)

    # 让 ABI 检查抛异常，其它项仍应产出。
    def _boom_abi(serial=None):
        raise RuntimeError("getprop exploded")

    monkeypatch.setattr(provision, "device_abi", _boom_abi)
    res = doctor.run()
    # 全部 7 项都在。
    names = {it["name"] for it in res["items"]}
    assert doctor._NAME_DEVICE in names
    assert doctor._NAME_ABI in names
    assert doctor._NAME_CA in names
    abi_item = _item_by_name(res, doctor._NAME_ABI)
    assert abi_item["ok"] is False
    assert "异常" in abi_item["detail"]
    # 其它关键项仍 ok（除被打断的 ABI）。
    assert _item_by_name(res, doctor._NAME_MITMPROXY)["ok"] is True


def test_run_on_progress_called(monkeypatch):
    _all_present(monkeypatch)
    msgs: list[str] = []
    doctor.run(on_progress=msgs.append)
    assert msgs  # 至少上报过若干阶段
    # 每条都是字符串。
    assert all(isinstance(m, str) for m in msgs)


def test_run_on_progress_exception_swallowed(monkeypatch):
    _all_present(monkeypatch)

    def _boom(_msg: str) -> None:
        raise RuntimeError("gui callback exploded")

    # 回调抛异常不应让 run 崩。
    res = doctor.run(on_progress=_boom)
    assert isinstance(res, dict)
    assert "items" in res


def test_run_never_prints_or_raises(monkeypatch, capsys):
    """所有依赖都打成会"返回失败"的状态，run 仍不抛、不打印。"""
    monkeypatch.setattr(device, "adb_devices", lambda: [])
    monkeypatch.setattr(device, "has_device", lambda: False)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: False)
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(doctor.tools, "has_adb", lambda: False)
    monkeypatch.setattr(provision, "device_abi", lambda serial=None: "")
    monkeypatch.setattr(provision, "host_frida_version", lambda: "")
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: None)
    monkeypatch.setattr(
        provision,
        "ensure_frida_server",
        lambda serial=None, *, download=True, on_progress=None: {
            "ok": False,
            "action": "error",
            "detail": "无设备",
            "version": "",
            "abi": "",
            "fix_cmd": ["adb devices"],
        },
    )
    monkeypatch.setattr(
        provision,
        "ensure_mitm_ca",
        lambda serial=None, *, on_progress=None: {
            "ok": False,
            "action": "error",
            "detail": "无 root，HTTPS 只抓密文",
            "ca_path": "",
            "subject_hash": "",
            "store_path": "",
            "fix_cmd": ["adb root"],
        },
    )
    try:
        res = doctor.run()
    except Exception as exc:  # pragma: no cover
        pytest.fail(f"doctor.run raised: {exc}")
    assert res["ok"] is False
    assert len(res["items"]) == 7
    captured = capsys.readouterr()
    assert captured.out == ""


def test_run_outer_exception_returns_structured(monkeypatch):
    """内部 _run_impl 整体抛异常时，外层 run 兜底转结构化结果（不抛）。"""

    def _boom(**kwargs):
        raise RuntimeError("impl exploded")

    monkeypatch.setattr(doctor, "_run_impl", _boom)
    res = doctor.run()
    assert res["ok"] is False
    assert res["items"]
    assert all({"name", "ok", "detail", "fix_cmd"} <= set(it) for it in res["items"])


# ---------------------------------------------------------------------------
# best-effort helpers
# ---------------------------------------------------------------------------


def test_device_is_rooted_true_on_uid0(monkeypatch):
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "uid=0(root) gid=0(root)")
    )
    assert doctor._device_is_rooted() is True


def test_device_is_rooted_false_on_nonzero(monkeypatch):
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: _FakeCompleted(1, ""))
    assert doctor._device_is_rooted() is False


def test_device_is_rooted_false_on_none(monkeypatch):
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: None)
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: False)
    assert doctor._device_is_rooted() is False


def test_device_is_rooted_true_on_adb_root_type(monkeypatch):
    """adb root 型设备（AVD Google APIs / 部分雷电）：无 su，但 adb shell id 即 uid=0。
    仅查 su 会误判未 root；应回退 adb shell id 判定。"""

    def _adb(extra: list[str], serial: str | None = None):
        if "su" in extra:  # su 不存在 → 非零
            return _FakeCompleted(127, "", "su: not found")
        if extra == ["shell", "id"]:  # adbd 已 root
            return _FakeCompleted(0, "uid=0(root) gid=0(root)")
        return _FakeCompleted(0, "")

    monkeypatch.setattr(provision, "_adb", _adb)
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: True)
    assert doctor._device_is_rooted() is True


def test_device_frida_version_parses(monkeypatch):
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "16.5.9\n")
    )
    assert doctor._device_frida_version() == "16.5.9"


def test_device_frida_version_unparseable_empty(monkeypatch):
    monkeypatch.setattr(
        provision, "_adb", lambda extra, serial=None: _FakeCompleted(0, "garbage")
    )
    assert doctor._device_frida_version() == ""


def test_device_frida_version_none_empty(monkeypatch):
    monkeypatch.setattr(provision, "_adb", lambda extra, serial=None: None)
    assert doctor._device_frida_version() == ""


def test_ca_already_trusted_true_when_ls_hits(monkeypatch, tmp_path):
    ca = tmp_path / "mitmproxy-ca-cert.pem"
    ca.write_bytes(b"pem")
    monkeypatch.setattr(provision, "_mitm_ca_path", lambda: ca)
    monkeypatch.setattr(provision, "_subject_hash_old", lambda p: "c8750f0d")
    monkeypatch.setattr(provision, "_adb_ok", lambda extra, serial=None: extra[:2] == ["shell", "ls"])
    assert doctor._ca_already_trusted(None) is True


def test_ca_already_trusted_false_when_ca_missing(monkeypatch, tmp_path):
    ca = tmp_path / "missing.pem"
    monkeypatch.setattr(provision, "_mitm_ca_path", lambda: ca)
    assert doctor._ca_already_trusted(None) is False


# ---------------------------------------------------------------------------
# GUI-ready 源码自检：核心模块无 print / typer.* / sys.exit / input()
# ---------------------------------------------------------------------------


def test_module_has_no_forbidden_calls():
    """用 AST 精确检查真实 Call 节点，不误命中 docstring 里对禁令的说明。"""
    src = Path(doctor.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)

    forbidden_names = {"print", "input"}
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # print(...) / input(...)
        if isinstance(func, ast.Name) and func.id in forbidden_names:
            bad.append(func.id)
        # typer.* / sys.exit
        if isinstance(func, ast.Attribute):
            value = func.value
            if isinstance(value, ast.Name):
                if value.id == "typer":
                    bad.append(f"typer.{func.attr}")
                if value.id == "sys" and func.attr == "exit":
                    bad.append("sys.exit")
    assert not bad, f"forbidden calls in doctor.py: {bad}"


# ---------------------------------------------------------------------------
# A4 回归：--no-fix 也用 frida-ps -U 权威探测，不对已在跑的 frida-server 误报未运行
# ---------------------------------------------------------------------------


def test_no_fix_uses_frida_ps_when_ps_heuristic_misses(monkeypatch):
    """ps 进程名启发式漏判，但 frida-ps -U 能连 → --no-fix 仍报在跑（不误报未运行）。"""
    monkeypatch.setattr(doctor.device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(doctor, "_frida_ps_reachable", lambda serial=None: True)
    monkeypatch.setattr(doctor, "_device_frida_version", lambda serial=None: "")
    item = doctor._check_frida_server(None, "17.11.0", auto_fix=False, on_progress=None)
    assert item["ok"] is True


def test_no_fix_reports_not_running_when_truly_down(monkeypatch):
    """ps 与 frida-ps 都探测不到 → --no-fix 如实报未运行。"""
    monkeypatch.setattr(doctor.device, "frida_server_running", lambda serial=None: False)
    monkeypatch.setattr(doctor, "_frida_ps_reachable", lambda serial=None: False)
    item = doctor._check_frida_server(None, "17.11.0", auto_fix=False, on_progress=None)
    assert item["ok"] is False
    assert "未运行" in item["detail"]


def test_frida_ps_reachable_true_on_exit0(monkeypatch):
    """frida-ps -U exit 0 → 视作可达。"""
    monkeypatch.setattr(doctor.tools, "frida_invocation", lambda tool: ["frida-ps"])

    class _Proc:
        returncode = 0

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: _Proc())
    assert doctor._frida_ps_reachable() is True


def test_frida_ps_reachable_false_when_tool_missing(monkeypatch):
    """frida-ps 不可用 → False（不抛）。"""
    monkeypatch.setattr(doctor.tools, "frida_invocation", lambda tool: [])
    assert doctor._frida_ps_reachable() is False
