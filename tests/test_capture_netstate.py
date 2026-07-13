"""floor 带外抓包的网络态漂移检测（Codex fengzhixin 案抓包交接 §5.1）单测。

全程不碰真机：monkeypatch ``capture._adb_capture``，只验证解析 + 漂移判定 + sidecar 落盘。
"""

from __future__ import annotations

import json

from apkscan.dynamic import capture


def _fake_adb_capture(route: str | None, wifi: str | None):
    """按 adb 子命令分派返回值，模拟 ``ip route get`` 与 ``dumpsys wifi``。"""

    def _cap(args, serial=None):
        _ = serial  # 对齐真实 _adb_capture 签名，本 fake 不用
        cmd = " ".join(args)
        if "route" in cmd:
            return route
        if "dumpsys" in cmd and "wifi" in cmd:
            return wifi
        return ""

    return _cap


def test_snapshot_netstate_parses_route_and_ssid(monkeypatch):
    monkeypatch.setattr(
        capture,
        "_adb_capture",
        _fake_adb_capture(
            "8.8.8.8 via 172.20.10.1 dev wlan0 src 172.20.10.3 uid 2000 \n    cache ",
            'mWifiInfo ... SSID: "so", BSSID: 02:11:22:33:44:55, MAC ...',
        ),
    )
    st = capture._snapshot_netstate("SER")
    assert st == {"iface": "wlan0", "src": "172.20.10.3", "gateway": "172.20.10.1", "ssid": "so"}


def test_snapshot_netstate_empty_when_unavailable(monkeypatch):
    # ip route 取不到 + SSID 被系统隐藏 → 空/部分，绝不抛。
    monkeypatch.setattr(capture, "_adb_capture", _fake_adb_capture(None, "SSID: <unknown ssid>, "))
    assert capture._snapshot_netstate() == {}


def test_write_floor_netstate_flags_drift(tmp_path):
    # 复刻真实案例：从热点 so(172.20.10.3) 漂移到 SHFXIFS-EDILAB(192.168.10.233)。
    start = {"iface": "wlan0", "src": "172.20.10.3", "gateway": "172.20.10.1", "ssid": "so"}
    end = {"iface": "wlan0", "src": "192.168.10.233", "gateway": "192.168.10.1", "ssid": "SHFXIFS-EDILAB"}
    drifted = capture._write_floor_netstate(tmp_path, start, end)
    assert drifted is True
    side = tmp_path / capture._FLOOR_NETSTATE_NAME
    assert side.is_file()
    payload = json.loads(side.read_text(encoding="utf-8"))
    assert payload["drifted"] is True
    assert payload["changed_fields"] == ["gateway", "src", "ssid"]  # iface 一致不入列
    assert payload["start"] == start and payload["end"] == end
    assert "污染" in payload["note"]


def test_write_floor_netstate_no_drift(tmp_path):
    same = {"iface": "wlan0", "src": "172.20.10.3", "gateway": "172.20.10.1", "ssid": "so"}
    assert capture._write_floor_netstate(tmp_path, dict(same), dict(same)) is False
    payload = json.loads((tmp_path / capture._FLOOR_NETSTATE_NAME).read_text(encoding="utf-8"))
    assert payload["drifted"] is False and payload["changed_fields"] == []


def test_write_floor_netstate_uncollected_no_false_alarm(tmp_path):
    # 一端未采集 → 不做漂移判定（不误报），仍留痕。
    assert capture._write_floor_netstate(tmp_path, {}, {"src": "10.0.0.2"}) is False
    payload = json.loads((tmp_path / capture._FLOOR_NETSTATE_NAME).read_text(encoding="utf-8"))
    assert payload["drifted"] is False
    assert "未完整采集" in payload["note"]


def test_write_floor_netstate_partial_fields_only_compares_shared(tmp_path):
    # src 两端都有且不同 → 漂移；ssid 只有一端 → 不参与判定。
    drifted = capture._write_floor_netstate(
        tmp_path,
        {"src": "172.20.10.3", "ssid": "so"},
        {"src": "192.168.10.233"},
    )
    assert drifted is True
    payload = json.loads((tmp_path / capture._FLOOR_NETSTATE_NAME).read_text(encoding="utf-8"))
    assert payload["changed_fields"] == ["src"]
