"""Frida 17 的 Java bridge 供给 + frida-server 真实运行 UID。

两件事都来自真机实测，且都属同一类：**"看起来就绪"与"真的能用"是两回事**。

1. Frida 17 起 GumJS 不再内置 Java bridge。脚本一引用 ``Java``，运行时会 send 一条
   ``frida:load-bridge`` 向宿主要源码。frida-tools 的 CLI/REPL 自带应答器，Python API 没有——
   于是同一份脚本在 CLI 下跑得通，用 ``create_script`` 就 ``Java is not defined``：
   会话建立、进程存活、事件全空。

2. frida-server 能被 ``frida-ps`` 枚举，不代表它以 root 跑着。实测因 Windows 侧启动命令的引号
   被 adb 拆开，它以 UID=2000 起来了，spawn/attach 一概失败，现象酷似样本反 Frida。
"""

from __future__ import annotations

from typing import Any

import pytest

from apkscan.core import device
from apkscan.dynamic import capture, doctor


# ---------------------------------------------------------------------------
# Java bridge 供给
# ---------------------------------------------------------------------------


class _Script:
    """最小 script 替身：记下 post 出去的内容。"""

    def __init__(self) -> None:
        self.posted: list[dict] = []

    def post(self, obj: dict) -> None:
        self.posted.append(obj)


def _request(name: str = "java") -> dict:
    return {"type": "send", "payload": {"type": "frida:load-bridge", "name": name}}


def test_java_bridge_request_is_answered() -> None:
    """★核心：运行时索取 java bridge 时，宿主必须回源码。

    不回 = 脚本里 Java 未定义 = 全部 Java hook 静默失效，而会话照样"成功"。
    """
    script, state = _Script(), {}
    capture._make_bridge_loader(script, state)(_request(), None)

    assert len(script.posted) == 1, "没有应答 bridge 请求"
    msg = script.posted[0]
    assert msg["type"] == "frida:bridge-loaded"
    assert msg["filename"].endswith(".js")
    assert "Java" in msg["source"] and len(msg["source"]) > 10_000, "回的不像真 bridge 源码"
    assert state["loaded"] == ["java"]
    assert not state.get("missing")


def test_missing_bridge_is_recorded_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """★取不到 bridge 时必须留痕。

    否则表现是"会话建好了、hook 一个没装上、事件全空"——那正是本模块反复要避免的假成功。
    """
    monkeypatch.setattr(capture, "_bridge_source", lambda _n: None)
    script, state = _Script(), {}
    capture._make_bridge_loader(script, state)(_request(), None)

    assert script.posted == []
    assert state["missing"] == ["java"], "取不到 bridge 这件事必须记下来"


@pytest.mark.parametrize("msg", [
    {"type": "error", "payload": {}},
    {"type": "send", "payload": {"type": "别的消息"}},
    {"type": "send", "payload": "不是 dict"},
    "根本不是 dict",
])
def test_loader_ignores_unrelated_messages(msg: Any) -> None:
    """只应答 bridge 请求；别的消息一概不碰（同一条通道上还有 7 路业务事件）。"""
    script, state = _Script(), {}
    capture._make_bridge_loader(script, state)(msg, None)
    assert script.posted == [] and state == {}


def test_session_registers_the_bridge_loader_before_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """★接线锁：应答器必须由 ``_start_frida_session`` 注册，且**先于 script.load()**。

    bridge 请求就是 load 过程中发出来的，晚注册一步就赶不上——表现为会话建立、事件全空。
    只测应答器本身好不好使，挡不住"写了但没接上"。
    """
    order: list[str] = []

    class _Sc:
        def on(self, _name: str, cb: Any) -> None:
            order.append(getattr(cb, "__qualname__", ""))

        def load(self) -> None:
            order.append("LOAD")

        def post(self, _o: dict) -> None:
            pass

    class _Se:
        pid = 1

        def create_script(self, _s: str) -> "_Sc":
            return _Sc()

        def detach(self) -> None:
            pass

    class _Dev:
        def spawn(self, _a: Any) -> int:
            return 1

        def attach(self, _p: int) -> "_Se":
            return _Se()

        def resume(self, _p: int) -> None:
            pass

        def kill(self, _p: int) -> None:
            pass

    import sys
    import types

    fake = types.ModuleType("frida")
    fake.get_usb_device = lambda **_k: _Dev()  # type: ignore[attr-defined]
    fake.get_device = lambda *_a, **_k: _Dev()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "frida", fake)

    session, _script = capture._start_frida_session("com.x", [])
    assert session is not None, "前提：注入路径应当成功"

    bridge_at = next((i for i, q in enumerate(order) if "_make_bridge_loader" in q), None)
    assert bridge_at is not None, "会话没有注册 Java bridge 应答器"
    assert bridge_at < order.index("LOAD"), "应答器晚于 script.load() 注册，赶不上 bridge 请求"


def test_bridge_status_separates_two_kinds_of_failure() -> None:
    """★hook 没装上时，要分得清"宿主没给 bridge"与"样本反检测/ART 不可用"。

    两者的补法完全不同：前者装 frida-tools，后者换探针。
    """
    class _S:
        _fxapk_bridge_state = {"requested": ["java"], "loaded": [], "missing": ["java"]}

    st = capture._frida_bridge_status(_S())
    assert st["missing"] == ["java"] and st["loaded"] == []
    assert capture._frida_bridge_status(None) == {"requested": [], "loaded": [], "missing": []}


# ---------------------------------------------------------------------------
# frida-server 真实运行 UID
# ---------------------------------------------------------------------------


class _P:
    def __init__(self, out: str) -> None:
        self.stdout = out
        self.stderr = ""
        self.returncode = 0


def _fake_adb(pid_out: str, status_out: str):
    def _run(cmd: str, serial: str | None = None) -> Any:
        if "pidof" in cmd:
            return _P(pid_out) if pid_out is not None else None
        if "/status" in cmd:
            return _P(status_out) if status_out is not None else None
        return _P("")
    return _run


def test_uid_reads_real_uid_from_proc_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(device, "_adb_root_command",
                        _fake_adb("4213\n", "Name:\tfrida-server\nUid:\t0\t0\t0\t0\n"))
    assert device.frida_server_uid("dev1") == 0


def test_uid_detects_the_shell_uid_case(monkeypatch: pytest.MonkeyPatch) -> None:
    """★实测那次：引号被拆，frida-server 以 shell（2000）跑着。"""
    monkeypatch.setattr(device, "_adb_root_command",
                        _fake_adb("4213\n", "Name:\tfrida-server\nUid:\t2000\t2000\t2000\t2000\n"))
    assert device.frida_server_uid("dev1") == 2000


@pytest.mark.parametrize("pid_out, status_out", [
    (None, None),          # pidof 都跑不了
    ("", ""),              # 没有该进程
    ("4213\n", None),      # 读不到 /proc
    ("4213\n", "Name:\tfrida-server\n"),  # status 里没有 Uid 行
])
def test_uid_is_none_when_undeterminable(monkeypatch: pytest.MonkeyPatch,
                                         pid_out: Any, status_out: Any) -> None:
    """★读不到必须是 None（不知道），不能猜成 0 或非 0。"""
    monkeypatch.setattr(device, "_adb_root_command", _fake_adb(pid_out, status_out))
    assert device.frida_server_uid("dev1") is None


def test_doctor_fails_the_item_on_non_root_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    """★接线锁：非 root 的 UID 必须把 doctor 那一项判为不就绪。

    只记日志不改判，等于让"进程在但用不了"继续伪装成就绪。
    """
    monkeypatch.setattr(device, "frida_server_uid", lambda _s=None: 2000)
    item = {"name": "设备 frida-server 运行且版本匹配", "ok": True, "detail": "已就绪", "fix_cmd": []}

    out = doctor._annotate_frida_uid(item, "dev1")

    assert out["ok"] is False
    assert "UID=2000" in out["detail"] and "非 root" in out["detail"]
    assert any("pkill" in c for c in out["fix_cmd"])


def test_doctor_does_not_flip_when_uid_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """★读不到 UID 不得改判——"不知道"不是"坏了"。"""
    monkeypatch.setattr(device, "frida_server_uid", lambda _s=None: None)
    item = {"name": "x", "ok": True, "detail": "已就绪", "fix_cmd": []}

    out = doctor._annotate_frida_uid(item, "dev1")

    assert out["ok"] is True
    assert "判不出来" in out["detail"]


def test_doctor_notes_root_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(device, "frida_server_uid", lambda _s=None: 0)
    out = doctor._annotate_frida_uid({"name": "x", "ok": True, "detail": "d", "fix_cmd": []}, None)
    assert out["ok"] is True and "root" in out["detail"]


# ---------------------------------------------------------------------------
# 接线：两个信号都要真的走到出口
# ---------------------------------------------------------------------------


def test_doctor_run_actually_checks_the_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    """★接线锁：``doctor.run`` 必须真的调 UID 核验。

    只测 ``_annotate_frida_uid`` 本身，挡不住"函数写了但 run 里没调"。
    """
    seen: list[Any] = []
    monkeypatch.setattr(device, "frida_server_uid",
                        lambda s=None: (seen.append(s), 2000)[1])

    res = doctor.run(serial="dev1")

    assert seen, "doctor.run 没有核验 frida-server 的运行 UID"
    item = next((i for i in res["items"] if i["name"] == doctor._NAME_FRIDA_SERVER), None)
    assert item is not None and "UID=2000" in item["detail"]


def test_capture_signals_carry_bridge_status() -> None:
    """★接线锁：bridge 供给情况必须进 capture_signals。

    不进去，读报告的人就分不清"hook 没装上"是因为宿主没给 bridge，还是样本反检测——
    两者的补法完全不同。
    """
    import inspect

    src = inspect.getsource(capture._capture)
    assert '"frida_bridges"' in src, "capture_signals 里没有 frida_bridges，状态没人读"
    assert "_frida_bridge_status(frida_session)" in src
