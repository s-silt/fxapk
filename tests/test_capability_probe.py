"""抓包能力探测（dynamic/capability_probe）测试 —— mock 掉 adb / 设备探测，不碰真机。

覆盖：主机侧 adb/frida/mitm/tshark；有设备才探设备侧 root/tcpdump；tcpdump 可 push 兜底；
CA 暂不探（保守）；探测异常绝不抛。
"""

from __future__ import annotations

import pytest

import apkscan.dynamic.capability_probe as P
from apkscan.dynamic import capabilities as C


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    adb: bool = False,
    frida: bool = False,
    mitm: bool = False,
    tshark: bool = False,
    dev: bool = False,
    root: bool = False,
    tcpdump: bool = False,
) -> None:
    from apkscan.core import device, tools
    from apkscan.dynamic import provision

    monkeypatch.setattr(tools, "has_adb", lambda: adb)
    monkeypatch.setattr(device, "has_frida", lambda: frida)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: mitm)
    monkeypatch.setattr(device, "has_device", lambda: dev)
    monkeypatch.setattr(P, "_has_tshark", lambda: tshark)

    def _root_shell(cmd: str, serial: str | None = None) -> bool:
        if "id -u" in cmd:
            return root
        if "tcpdump" in cmd:
            return tcpdump
        return False

    monkeypatch.setattr(provision, "_adb_root_shell", _root_shell)


def test_host_side_caps_only_when_no_device(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, adb=True, frida=True, mitm=True, tshark=True, dev=False)
    caps = P.probe_available()
    assert caps == {C.CAP_ADB, C.CAP_FRIDA, C.CAP_MITMPROXY, C.CAP_TSHARK}
    assert C.CAP_DEVICE not in caps and C.CAP_ROOT_CAPTURE not in caps


def test_device_side_root_and_tcpdump(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, adb=True, dev=True, root=True, tcpdump=True)
    caps = P.probe_available("serial1")
    assert {C.CAP_ADB, C.CAP_DEVICE, C.CAP_ROOT_CAPTURE, C.CAP_DEVICE_TCPDUMP} <= caps


def test_device_present_but_no_root_no_tcpdump(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, adb=True, dev=True, root=False, tcpdump=False)
    caps = P.probe_available()
    assert C.CAP_DEVICE in caps
    assert C.CAP_ROOT_CAPTURE not in caps and C.CAP_DEVICE_TCPDUMP not in caps


def test_tcpdump_via_pushable_bin(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """设备无 tcpdump（command -v 不命中）但配了可 push 的 FXAPK_TCPDUMP_BIN → 算 device_tcpdump 可用。"""
    _patch(monkeypatch, adb=True, dev=True, root=True, tcpdump=False)
    binf = tmp_path / "tcpdump"
    binf.write_bytes(b"\x7fELF")
    monkeypatch.setenv("FXAPK_TCPDUMP_BIN", str(binf))
    assert C.CAP_DEVICE_TCPDUMP in P.probe_available()


def test_no_ca_trusted_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    """CA 暂不探（保守）：即便 mitmproxy 在、有设备，也不会加 ca_trusted。"""
    _patch(monkeypatch, adb=True, mitm=True, dev=True, root=True, tcpdump=True)
    assert C.CAP_CA_TRUSTED not in P.probe_available()


def test_probe_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """探测中途异常 → 吞掉、返回已探到的部分，绝不抛。"""
    from apkscan.core import tools

    def _boom() -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(tools, "has_adb", _boom)
    assert P.probe_available() == set()
