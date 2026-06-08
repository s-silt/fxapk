"""apkscan.dynamic.capture 的单测。

策略：全程不碰真机/真子进程/真流量。monkeypatch：
- apkscan.core.device.has_device / has_frida / has_mitmproxy（控制前置）。
- capture._start_mitmdump / _start_frida_unpinning / _adb* / _wait / _terminate
  （编排步骤替身，避免真起子进程）。
- capture._parse_flows（注入假端点，断言运行时端点提取 + 报告写出）。

覆盖：
- 无设备 → status="skipped"，reason 写明缺啥，playbook 非空（含 mitmdump/adb 代理/CA/frida/抓 duration）。
- 缺 frida / 缺 mitmproxy → skipped + reason。
- 有设备+frida+mitmproxy → status="done"，提取 runtime 端点（source="runtime"），写 runtime_report.json。
- 真解析 flows：monkeypatch mitmproxy reader，断言从假流抽出 url/host 端点。
- 编排异常 → status="error"，仍清理子进程（finally）。
- 子进程清理：_terminate 被调用（finally 保证）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from apkscan.core import device
from apkscan.core.models import Endpoint, Evidence
from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
)
from apkscan.dynamic import capture


# ---------------------------------------------------------------------------
# 测试替身
# ---------------------------------------------------------------------------


class _FakeProc:
    """subprocess.Popen 的最小替身：记录是否被 terminate/kill。"""

    def __init__(self) -> None:
        self.terminated = False
        self.killed = False
        self._alive = True

    def poll(self) -> int | None:
        return None if self._alive else 0

    def terminate(self) -> None:
        self.terminated = True
        self._alive = False

    def kill(self) -> None:
        self.killed = True
        self._alive = False

    def wait(self, timeout: float | None = None) -> int:
        self._alive = False
        return 0


def _set_capabilities(
    monkeypatch: pytest.MonkeyPatch,
    *,
    has_device: bool = True,
    has_frida: bool = True,
    has_mitmproxy: bool = True,
    frida_server_running: bool = True,
) -> None:
    monkeypatch.setattr(device, "has_device", lambda: has_device)
    monkeypatch.setattr(device, "has_frida", lambda: has_frida)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: has_mitmproxy)
    # 与 unpack 口径一致：capture 也探测设备上 frida-server 是否在跑。
    monkeypatch.setattr(device, "frida_server_running", lambda serial=None: frida_server_running)


def _stub_orchestration(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mitm: _FakeProc | None = None,
    frida: _FakeProc | None = None,
    wait_raises: bool = False,
) -> dict[str, Any]:
    """把真编排步骤换成无副作用替身，返回调用记录。

    抓包加固引入的新副作用（provision.ensure_mitm_ca / _check_frida_version_match）
    在此默认 monkeypatch 为"全 OK、无告警"，保证既有 done/error 用例不因真实
    adb/frida 调用而行为漂移；针对加固路径的新用例会再覆写这两个桩。
    """
    calls: dict[str, Any] = {
        "mitm": mitm,
        "frida": frida,
        "terminated": [],
        "adb": [],
        "waited": False,
        "ensure_ca_called": False,
        "version_check_called": False,
    }

    monkeypatch.setattr(capture, "_start_mitmdump", lambda flows_file: mitm)
    monkeypatch.setattr(
        capture, "_start_frida_unpinning", lambda package, out_path: frida
    )
    monkeypatch.setattr(capture, "_adb_reverse", lambda: (calls["adb"].append("reverse") or True))
    monkeypatch.setattr(capture, "_adb_set_proxy", lambda: (calls["adb"].append("proxy") or True))
    monkeypatch.setattr(capture, "_adb_clear_proxy", lambda: calls["adb"].append("clear_proxy"))
    monkeypatch.setattr(capture, "_adb_remove_reverse", lambda: calls["adb"].append("remove_reverse"))

    # 加固新调用：默认 CA 成功、版本匹配，无告警（避免污染既有用例的 reason 断言）。
    def _fake_ensure_ca(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls["ensure_ca_called"] = True
        return {"ok": True, "action": "installed_system", "detail": ""}

    def _fake_version_match(*args: Any, **kwargs: Any) -> tuple[bool, str]:
        calls["version_check_called"] = True
        return True, ""

    monkeypatch.setattr(capture.provision, "ensure_mitm_ca", _fake_ensure_ca)
    monkeypatch.setattr(capture, "_check_frida_version_match", _fake_version_match)

    def _fake_wait(duration: int) -> None:
        calls["waited"] = True
        if wait_raises:
            raise RuntimeError("boom during capture")

    monkeypatch.setattr(capture, "_wait", _fake_wait)

    def _fake_terminate(proc: Any, label: str) -> None:
        calls["terminated"].append(label)
        if proc is not None:
            proc.terminate()

    monkeypatch.setattr(capture, "_terminate", _fake_terminate)
    return calls


# ---------------------------------------------------------------------------
# 无前置 → skipped + playbook
# ---------------------------------------------------------------------------


def test_no_device_skipped_with_playbook(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch, has_device=False)
    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=30)

    assert result["status"] == STATUS_SKIPPED
    assert "在线 adb 设备" in result["reason"]
    assert result["artifacts"] == []
    assert result["report_paths"] == []
    # playbook 应覆盖关键取证步骤
    pb = "\n".join(result["playbook"])
    assert result["playbook"]
    assert "mitmdump" in pb
    assert "http_proxy" in pb or "reverse" in pb
    assert "mitm" in pb.lower()  # CA / mitm.it
    assert "frida" in pb
    assert "30" in pb  # duration 体现在手册


def test_missing_frida_reason(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch, has_frida=False)
    result = capture.run("com.test.app", out_dir=str(tmp_path))
    assert result["status"] == STATUS_SKIPPED
    assert "frida" in result["reason"]
    assert result["playbook"]


def test_missing_mitmproxy_reason(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch, has_mitmproxy=False)
    result = capture.run("com.test.app", out_dir=str(tmp_path))
    assert result["status"] == STATUS_SKIPPED
    assert "mitmproxy" in result["reason"]


def test_multiple_missing_listed_in_reason(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch, has_device=False, has_frida=False, has_mitmproxy=False)
    result = capture.run("com.test.app", out_dir=str(tmp_path))
    assert result["status"] == STATUS_SKIPPED
    assert "在线 adb 设备" in result["reason"]
    assert "frida" in result["reason"]
    assert "mitmproxy" in result["reason"]


def test_device_probe_exception_treated_as_missing(monkeypatch, tmp_path):
    def _boom() -> bool:
        raise RuntimeError("adb exploded")

    monkeypatch.setattr(device, "has_device", _boom)
    monkeypatch.setattr(device, "has_frida", lambda: True)
    monkeypatch.setattr(device, "has_mitmproxy", lambda: True)
    result = capture.run("com.test.app", out_dir=str(tmp_path))
    assert result["status"] == STATUS_SKIPPED
    assert "在线 adb 设备" in result["reason"]


# ---------------------------------------------------------------------------
# 前置满足 → done + 运行时端点
# ---------------------------------------------------------------------------


def test_capture_done_extracts_runtime_endpoints(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch)
    mitm = _FakeProc()
    frida = _FakeProc()
    calls = _stub_orchestration(monkeypatch, mitm=mitm, frida=frida)

    # 假 flows 文件 + 假解析结果（运行时端点）
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00fake-flow-bytes")

    fake_eps = [
        Endpoint(
            value="https://api.fraud-gw.cn/v1/pay",
            kind="url",
            evidences=[Evidence(source="runtime", location=str(flows_file), snippet="x")],
        ),
        Endpoint(
            value="api.fraud-gw.cn",
            kind="domain",
            evidences=[Evidence(source="runtime", location=str(flows_file), snippet="x")],
        ),
    ]
    monkeypatch.setattr(capture, "_parse_flows", lambda f: fake_eps)

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=5)

    assert result["status"] == STATUS_DONE
    # artifacts 含 flows 文件
    assert str(flows_file) in result["artifacts"]
    # report_paths 含 runtime_report.json
    report_file = tmp_path / "runtime_report.json"
    assert str(report_file) in result["report_paths"]
    assert report_file.exists()

    # 报告内容：运行时端点，source=runtime
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["package_name"] == "com.test.app"
    assert data["source"] == "runtime"
    assert data["endpoint_total"] == 2
    values = {ep["value"] for ep in data["endpoints"]}
    assert "https://api.fraud-gw.cn/v1/pay" in values
    assert "api.fraud-gw.cn" in values
    for ep in data["endpoints"]:
        assert any(ev["source"] == "runtime" for ev in ep["evidences"])

    # 编排被执行：等待 + adb 代理 + 清理子进程
    assert calls["waited"] is True
    assert "proxy" in calls["adb"]
    assert "reverse" in calls["adb"]
    assert "clear_proxy" in calls["adb"]
    assert "remove_reverse" in calls["adb"]
    # 两个子进程都被清理
    assert "mitmdump" in calls["terminated"]
    assert "frida" in calls["terminated"]
    assert mitm.terminated is True
    assert frida.terminated is True


def test_capture_done_no_flows_still_done(monkeypatch, tmp_path):
    """流文件未生成（无端点）仍应 done，端点为 0。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    assert result["status"] == STATUS_DONE
    # 无 flows 文件 → artifacts 不含它
    assert result["artifacts"] == []
    report_file = tmp_path / "runtime_report.json"
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["endpoint_total"] == 0


# ---------------------------------------------------------------------------
# 异常 → error，且仍清理子进程
# ---------------------------------------------------------------------------


def test_capture_exception_yields_error_and_cleans_up(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch)
    mitm = _FakeProc()
    frida = _FakeProc()
    calls = _stub_orchestration(
        monkeypatch, mitm=mitm, frida=frida, wait_raises=True
    )
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=5)

    assert result["status"] == STATUS_ERROR
    assert result["reason"]
    # finally 仍清理子进程与代理
    assert "mitmdump" in calls["terminated"]
    assert "frida" in calls["terminated"]
    assert "clear_proxy" in calls["adb"]
    assert "remove_reverse" in calls["adb"]


def test_outdir_creation_failure_returns_error(monkeypatch, tmp_path):
    _set_capabilities(monkeypatch)

    def _boom_mkdir(*args: Any, **kwargs: Any) -> None:
        raise OSError("cannot mkdir")

    monkeypatch.setattr(Path, "mkdir", _boom_mkdir)
    result = capture.run("com.test.app", out_dir=str(tmp_path / "nope"))
    assert result["status"] == STATUS_ERROR
    assert result["reason"]


# ---------------------------------------------------------------------------
# _parse_flows：真解析逻辑（monkeypatch mitmproxy reader）
# ---------------------------------------------------------------------------


class _FakeRequest:
    def __init__(self, url: str, host: str, scheme: str) -> None:
        self.pretty_url = url
        self.pretty_host = host
        self.scheme = scheme


class _FakeHTTPFlow:
    def __init__(self, request: _FakeRequest) -> None:
        self.request = request


def test_parse_flows_missing_file_returns_empty(tmp_path):
    assert capture._parse_flows(tmp_path / "nope.mitm") == []


def test_parse_flows_extracts_url_and_host(monkeypatch, tmp_path):
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    flows = [
        _FakeHTTPFlow(
            _FakeRequest("http://gw.fraud-gw.cn/notify", "gw.fraud-gw.cn", "http")
        ),
        _FakeHTTPFlow(
            _FakeRequest("https://api.fraud-gw.cn/v1", "api.fraud-gw.cn", "https")
        ),
        _FakeHTTPFlow(
            _FakeRequest("https://api.fraud-gw.cn/v1", "api.fraud-gw.cn", "https")
        ),  # 重复，去重
    ]

    fake_io = type(
        "io",
        (),
        {"FlowReader": staticmethod(lambda fh: type("R", (), {"stream": lambda self: iter(flows)})())},
    )
    fake_http = type("http", (), {"HTTPFlow": _FakeHTTPFlow})

    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", type("m", (), {}))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", fake_io)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)

    eps = capture._parse_flows(flows_file)
    by_value = {ep.value: ep for ep in eps}

    # url + host 各成端点；http URL 标明文
    assert "http://gw.fraud-gw.cn/notify" in by_value
    assert by_value["http://gw.fraud-gw.cn/notify"].is_cleartext is True
    assert by_value["http://gw.fraud-gw.cn/notify"].kind == "url"
    assert "gw.fraud-gw.cn" in by_value
    assert by_value["gw.fraud-gw.cn"].kind == "domain"
    assert "https://api.fraud-gw.cn/v1" in by_value
    assert by_value["https://api.fraud-gw.cn/v1"].is_cleartext is False
    # 重复 url 去重为 1 个
    assert sum(1 for ep in eps if ep.value == "https://api.fraud-gw.cn/v1") == 1
    # source 一律 runtime
    for ep in eps:
        assert all(ev.source == "runtime" for ev in ep.evidences)


def test_parse_flows_no_mitmproxy_package_returns_empty(monkeypatch, tmp_path):
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    import builtins

    real_import = builtins.__import__

    def _no_mitmproxy(name: str, *args: Any, **kwargs: Any):
        if name.startswith("mitmproxy"):
            raise ImportError("no mitmproxy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_mitmproxy)
    assert capture._parse_flows(flows_file) == []


# ---------------------------------------------------------------------------
# 内置 frida unpinning 脚本完整性
# ---------------------------------------------------------------------------


def test_frida_unpinning_js_covers_common_pinning():
    js = capture.FRIDA_UNPINNING_JS
    assert "Java.perform" in js
    assert "CertificatePinner" in js  # OkHttp3
    assert "X509TrustManager" in js
    assert "TrustManagerImpl" in js


# ---------------------------------------------------------------------------
# _terminate 行为
# ---------------------------------------------------------------------------


def test_terminate_none_is_noop():
    capture._terminate(None, "x")  # 不抛即通过


def test_terminate_calls_terminate_on_live_proc():
    proc = _FakeProc()
    capture._terminate(proc, "mitmdump")
    assert proc.terminated is True


# ---------------------------------------------------------------------------
# 抓包加固：CA 注入 + frida 版本一致性校验（不阻断抓包，写入 reason/playbook）
# ---------------------------------------------------------------------------


def test_capture_calls_ensure_mitm_ca_before_capture(monkeypatch, tmp_path):
    """抓包前必须调用 provision.ensure_mitm_ca（HTTPS 命门）。"""
    _set_capabilities(monkeypatch)
    calls = _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    assert result["status"] == STATUS_DONE
    assert calls["ensure_ca_called"] is True
    assert calls["version_check_called"] is True


def test_capture_ca_failure_does_not_abort_but_notes_in_reason(monkeypatch, tmp_path):
    """CA 装入失败（ok=False）：仍 done，但 reason/playbook 含 CA 降级说明，不假成功。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _ca_fail(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "ok": False,
            "action": "error",
            "detail": "无法把 CA 装入系统信任库（设备无 root）",
        }

    monkeypatch.setattr(capture.provision, "ensure_mitm_ca", _ca_fail)

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    # 抓包不被 CA 失败阻断（HTTP 仍可抓）
    assert result["status"] == STATUS_DONE
    # reason 必须点明 CA 降级 + HTTPS 可能仅密文，避免假成功
    assert "CA" in result["reason"]
    assert "密文" in result["reason"]
    assert "无法把 CA 装入系统信任库（设备无 root）" in result["reason"]
    # playbook 也记录降级
    pb = "\n".join(result["playbook"])
    assert "CA 未装入系统信任库" in pb


def test_capture_frida_version_mismatch_warns_in_reason(monkeypatch, tmp_path):
    """frida 主机/设备版本不一致：不阻断注入，但 reason 含版本警告。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _mismatch(*args: Any, **kwargs: Any) -> tuple[bool, str]:
        return False, "主机 frida 16.5.9 与设备 frida-server 16.1.0 版本不一致，注入可能失败"

    monkeypatch.setattr(capture, "_check_frida_version_match", _mismatch)

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    # 不阻断：仍 done
    assert result["status"] == STATUS_DONE
    assert "版本不一致" in result["reason"]
    pb = "\n".join(result["playbook"])
    assert "版本不一致" in pb


def test_capture_frida_version_match_no_warning(monkeypatch, tmp_path):
    """frida 版本一致：reason 无版本警告（仅正常完成文案）。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    assert result["status"] == STATUS_DONE
    assert "版本不一致" not in result["reason"]
    assert "抓包完成" in result["reason"]


class _DeadFridaProc(_FakeProc):
    """frida 秒退替身：poll() 立即返回非 None（已退出），communicate 给 stderr 尾部。"""

    def __init__(self, stderr: bytes = b"Failed to spawn: unable to find process") -> None:
        super().__init__()
        self._alive = False
        self.returncode = 1
        self._stderr = stderr

    def poll(self) -> int | None:
        return 1  # 始终已退出

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        return b"", self._stderr


def test_capture_frida_dead_after_start_warns_in_reason(monkeypatch, tmp_path):
    """frida 注入后秒退（版本不匹配/包名不存在/spawn 失败）：不阻断（HTTP 仍抓），
    但 reason/playbook 必须如实降级，不假成功（HTTPS 命门）。"""
    _set_capabilities(monkeypatch)
    dead_frida = _DeadFridaProc()
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=dead_frida)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    # 不阻断：仍 done。
    assert result["status"] == STATUS_DONE
    # reason 必须点明 frida 注入失败/秒退 + HTTPS 可能仅密文。
    assert "frida" in result["reason"].lower()
    assert "密文" in result["reason"]
    pb = "\n".join(result["playbook"])
    assert "秒退" in pb or "注入失败" in pb


def test_capture_frida_none_warns_no_unpinning(monkeypatch, tmp_path):
    """frida 未启动（_start_frida_unpinning 返回 None）：reason 点明无 unpinning。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    assert result["status"] == STATUS_DONE
    assert "密文" in result["reason"]
    pb = "\n".join(result["playbook"])
    assert "unpinning" in pb.lower()


def test_capture_frida_alive_no_warning(monkeypatch, tmp_path):
    """frida 注入后存活：无降级告警（仅正常完成文案）。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=_FakeProc())
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    assert result["status"] == STATUS_DONE
    assert "秒退" not in result["reason"]
    assert "密文" not in result["reason"]
    assert "抓包完成" in result["reason"]


def test_existing_done_test_still_passes_with_new_hooks_mocked(monkeypatch, tmp_path):
    """锁定无回归：默认桩下（CA ok、版本匹配）done 路径行为不变。"""
    _set_capabilities(monkeypatch)
    mitm = _FakeProc()
    frida = _FakeProc()
    calls = _stub_orchestration(monkeypatch, mitm=mitm, frida=frida)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)

    assert result["status"] == STATUS_DONE
    # 子进程仍被清理（finally 行为不变）
    assert "mitmdump" in calls["terminated"]
    assert "frida" in calls["terminated"]
    assert mitm.terminated is True
    assert frida.terminated is True
    # 默认桩无告警 → reason 不含降级文案
    assert "密文" not in result["reason"]
    assert "版本不一致" not in result["reason"]


# ---------------------------------------------------------------------------
# _check_frida_version_match / _device_frida_version 单元行为
# ---------------------------------------------------------------------------


def test_version_match_returns_true_when_either_version_missing(monkeypatch):
    """任一版本取不到 → 无法比对 → (True, '')（只校在跑，不阻断）。"""
    monkeypatch.setattr(capture.provision, "host_frida_version", lambda: "")
    monkeypatch.setattr(capture, "_device_frida_version", lambda serial=None: "16.5.9")
    assert capture._check_frida_version_match() == (True, "")

    monkeypatch.setattr(capture.provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(capture, "_device_frida_version", lambda serial=None: "")
    assert capture._check_frida_version_match() == (True, "")


def test_version_match_true_when_equal(monkeypatch):
    monkeypatch.setattr(capture.provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(capture, "_device_frida_version", lambda serial=None: "16.5.9")
    ok, msg = capture._check_frida_version_match()
    assert ok is True
    assert msg == ""


def test_version_match_false_when_mismatch(monkeypatch):
    monkeypatch.setattr(capture.provision, "host_frida_version", lambda: "16.5.9")
    monkeypatch.setattr(capture, "_device_frida_version", lambda serial=None: "16.1.0")
    ok, msg = capture._check_frida_version_match()
    assert ok is False
    assert "16.5.9" in msg
    assert "16.1.0" in msg


def test_device_frida_version_no_adb_returns_empty(monkeypatch):
    monkeypatch.setattr(capture.shutil, "which", lambda name: None)
    assert capture._device_frida_version() == ""


def test_device_frida_version_parses_semver(monkeypatch):
    monkeypatch.setattr(capture.shutil, "which", lambda name: "adb")

    class _CP:
        returncode = 0
        stdout = "16.5.9\n"
        stderr = ""

    monkeypatch.setattr(capture.subprocess, "run", lambda *a, **k: _CP())
    assert capture._device_frida_version() == "16.5.9"


def test_device_frida_version_timeout_returns_empty(monkeypatch):
    monkeypatch.setattr(capture.shutil, "which", lambda name: "adb")

    def _boom(*a: Any, **k: Any):
        raise capture.subprocess.TimeoutExpired(cmd="adb", timeout=5.0)

    monkeypatch.setattr(capture.subprocess, "run", _boom)
    assert capture._device_frida_version() == ""
