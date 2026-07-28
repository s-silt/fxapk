"""测试套不得依赖开发机装没装 adb。

★这条是被真事逼出来的：本机跑 3300+ 用例 60 秒全绿，另一台装了 adb 的机器上同一份代码
  跑到 1204 秒超时（exit 124），全程在等一个并不存在的设备 ``dev1``。差别只在 PATH 里有没有
  adb —— 我这台没有，于是 ``_run`` 走"命令不在 PATH"分支立刻返回 None，那些没把设备层 mock
  干净的用例就"碰巧"是快的、绿的。

  「我这儿是绿的」于是并不是结论，是环境巧合。本文件把这一点钉成契约。
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from apkscan.core import device, tools


def test_adb_is_invisible_to_the_suite() -> None:
    """★conftest 的 autouse 夹具必须让全套测试都看不见 adb。

    删掉那个夹具，本用例即红——在装了 adb 的机器上。故本断言也要在**没装** adb 的机器上
    成立，才算真守住：``adb_path()`` 恒为空串，与本机实际有无无关。
    """
    assert tools.adb_path() == "", "测试期间不得解析到真实 adb"


def test_device_run_never_shells_out_during_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """★纵使本机装了 adb，``device._run(["adb", ...])`` 也不得真起进程。

    用一个会炸的 subprocess.run 当哨兵：真被调用就抛，测试立刻红。
    """
    def _boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("测试期间起了真实子进程——adb 没被挡住")

    monkeypatch.setattr(subprocess, "run", _boom)
    assert device._run(["adb", "-s", "dev1", "shell", "dumpsys", "connectivity"]) is None


def test_network_state_probe_is_fast_and_unknown() -> None:
    """★``read_network_state`` 在无 adb 时须立刻返回"判不出来"，不是"坏了"。

    它一次要跑 4 条 shell、每条 su + 回退两次调用；真去连一个不存在的设备就是 8 × 超时。
    这里既守速度，也守语义——读不到必须是 unknown，不能被当成"设备断网"。
    """
    state = device.read_network_state("dev1")
    assert state.healthy is None, "读不到 ≠ 坏了；healthy 必须是 None（判不出来）"
    assert state.detail, "要说明为什么判不出来"


def test_tests_that_want_the_real_path_can_still_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """夹具不挡「自己 mock 了设备层」的用例——那是既有写法，不该被误伤。"""
    calls: list[str] = []

    class _P:
        stdout = "default via 192.168.1.1 dev wlan0\ninet 192.168.1.50/24"
        stderr = ""

    monkeypatch.setattr(
        device, "_adb_root_command",
        lambda cmd, serial=None: (calls.append(cmd), _P())[1],
    )
    device.read_network_state("dev1")
    assert calls, "自行 mock 的用例仍应走到设备层"
