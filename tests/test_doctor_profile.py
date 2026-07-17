"""doctor 分层 profile 测试 —— floor-only profile 只把 floor pcap 底座（设备/root/tcpdump）当关键项，
缺 frida/mitmproxy/CA 仍体检但不判环境失败（解决"floor-only 用户被主机没装 frida 挡住"的评价#1 痛点）。

各 _check_* 打桩成固定 item，聚焦验证 profile 的 ok 计算，不碰真机。
"""

from __future__ import annotations

import pytest

from apkscan.dynamic import doctor


def _stub_checks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    floor_ok: bool = True,
    frida_ok: bool = False,
    mitm_ok: bool = False,
    ca_ok: bool = False,
) -> None:
    """把 doctor 各 _check_* 打桩成固定 ok/fail 的 item（floor 底座=设备/root/tcpdump 同步一个开关）。"""
    D = doctor
    monkeypatch.setattr(D, "_check_device", lambda s=None: D._item(D._NAME_DEVICE, floor_ok, ""))
    monkeypatch.setattr(D, "_check_root", lambda s=None: D._item(D._NAME_ROOT, floor_ok, ""))
    monkeypatch.setattr(D, "_check_device_tcpdump", lambda s=None: D._item(D._NAME_DEVICE_TCPDUMP, floor_ok, ""))
    monkeypatch.setattr(D, "_check_abi", lambda s=None: D._item(D._NAME_ABI, True, ""))
    monkeypatch.setattr(D, "_check_host_frida", lambda: (D._item(D._NAME_HOST_FRIDA, frida_ok, ""), ""))
    monkeypatch.setattr(D, "_check_frida_server", lambda *a, **k: D._item(D._NAME_FRIDA_SERVER, frida_ok, ""))
    monkeypatch.setattr(D, "_check_mitmproxy", lambda: D._item(D._NAME_MITMPROXY, mitm_ok, ""))
    monkeypatch.setattr(D, "_check_ca", lambda *a, **k: D._item(D._NAME_CA, ca_ok, ""))
    monkeypatch.setattr(D, "_check_pcap_capabilities", lambda: [])


def test_floor_only_ok_despite_missing_frida_mitm_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    """★floor 底座就绪、frida/mitm/CA 全缺 → floor-only profile 整体 ok=True。"""
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=False, mitm_ok=False, ca_ok=False)
    res = doctor.run(profile="floor-only")
    assert res["ok"] is True and res["profile"] == "floor-only"


def test_full_not_ok_when_frida_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """full profile：frida 是关键项，缺 → ok=False（现状不变）。"""
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=False, mitm_ok=True, ca_ok=True)
    assert doctor.run(profile="full")["ok"] is False


def test_same_caps_floor_ok_but_full_not(monkeypatch: pytest.MonkeyPatch) -> None:
    """★核心：同一份能力（floor ok、frida/mitm/CA 缺）→ floor-only 判 ok、full 判 not ok。"""
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=False, mitm_ok=False, ca_ok=False)
    assert doctor.run(profile="floor-only")["ok"] is True
    assert doctor.run(profile="full")["ok"] is False


def test_floor_only_not_ok_when_tcpdump_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """floor-only：设备 tcpdump 是 floor 底座关键项，缺 → ok=False。"""
    _stub_checks(monkeypatch, floor_ok=False)  # 设备/root/tcpdump 都 fail
    assert doctor.run(profile="floor-only")["ok"] is False


def test_frida_mitm_still_checked_in_floor_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """floor-only profile 仍**体检** frida/mitm/CA（信息性），只是不拉整体 ok。"""
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=False, mitm_ok=False)
    names = {it["name"] for it in doctor.run(profile="floor-only")["items"]}
    assert doctor._NAME_MITMPROXY in names and doctor._NAME_FRIDA_SERVER in names
    assert doctor._NAME_DEVICE_TCPDUMP in names  # 新增的 floor 底座项


def test_invalid_profile_falls_back_to_full(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=False, mitm_ok=True, ca_ok=True)
    res = doctor.run(profile="bogus")
    assert res["profile"] == "full" and res["ok"] is False  # 回退 full，frida 缺 → not ok


def test_full_not_ok_when_root_and_tcpdump_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """★codex 复审 P1-1：full profile 缺 root/tcpdump（floor 底座）→ 即便 frida/mitm/CA 全 ok 也判 not ok。

    _CRITICAL 现已并入 _FLOOR_CRITICAL：both/full 的 PCAP 底座同样需要 root+device_tcpdump，
    否则连 floor.pcap 都抓不到，不能报"完整环境可用"。设备仍在线，单独把 root/tcpdump 打回 fail。
    """
    _stub_checks(monkeypatch, floor_ok=True, frida_ok=True, mitm_ok=True, ca_ok=True)
    monkeypatch.setattr(doctor, "_check_root", lambda s=None: doctor._item(doctor._NAME_ROOT, False, ""))
    monkeypatch.setattr(
        doctor, "_check_device_tcpdump", lambda s=None: doctor._item(doctor._NAME_DEVICE_TCPDUMP, False, "")
    )
    assert doctor.run(profile="full")["ok"] is False


def _spy_enhancement_fix(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """把 frida-server / CA 检查换成记录 auto_fix 入参的探针（覆写 _stub_checks 的桩）。"""
    seen: dict[str, bool] = {}

    def _spy_frida(serial: object, host_ver: object, *, auto_fix: bool, on_progress: object = None) -> dict:
        seen["frida"] = auto_fix
        return doctor._item(doctor._NAME_FRIDA_SERVER, False, "")

    def _spy_ca(serial: object, *, auto_fix: bool, on_progress: object = None) -> dict:
        seen["ca"] = auto_fix
        return doctor._item(doctor._NAME_CA, False, "")

    monkeypatch.setattr(doctor, "_check_frida_server", _spy_frida)
    monkeypatch.setattr(doctor, "_check_ca", _spy_ca)
    return seen


def test_floor_only_does_not_autofix_frida_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    """★codex 复审 P1-3：floor-only profile 即便 auto_fix=True，也只读体检 frida/CA，绝不触发部署/装 CA 副作用。"""
    _stub_checks(monkeypatch, floor_ok=True)
    seen = _spy_enhancement_fix(monkeypatch)
    doctor.run(profile="floor-only", auto_fix=True)
    assert seen == {"frida": False, "ca": False}


def test_full_still_autofixes_frida_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    """full profile 现状不变：auto_fix=True → frida/CA 仍走自动修（enhancement_fix 只对 floor-only 关闭）。"""
    _stub_checks(monkeypatch, floor_ok=True)
    seen = _spy_enhancement_fix(monkeypatch)
    doctor.run(profile="full", auto_fix=True)
    assert seen == {"frida": True, "ca": True}
