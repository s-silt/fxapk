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
    # P0：默认让 frida-core 会话路径不可用（返回 (None, None)），既有用例继续走 subprocess
    # 回退路径（_start_frida_unpinning），行为零漂移；针对会话路径的新用例会再覆写此桩。
    monkeypatch.setattr(
        capture,
        "_start_frida_session",
        lambda package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None: (None, None),
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
# C5b：_parse_messages 报文体提取（供 merge 信封解密）
# ---------------------------------------------------------------------------


class _FakeMessage:
    """mitmproxy 请求/响应的最小替身：带 .text。"""

    def __init__(self, text: str) -> None:
        self.text = text
        self.content = text.encode("utf-8")


class _FakeFullFlow:
    def __init__(self, request: object, response: object) -> None:
        self.request = request
        self.response = response


def _inject_fake_mitmproxy(monkeypatch, flows: list[object]) -> None:
    fake_io = type(
        "io",
        (),
        {"FlowReader": staticmethod(lambda fh: type("R", (), {"stream": lambda self: iter(flows)})())},
    )
    fake_http = type("http", (), {"HTTPFlow": _FakeFullFlow})
    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", type("m", (), {}))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", fake_io)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)


def test_parse_messages_extracts_envelope_bodies(monkeypatch, tmp_path):
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    class _Req:
        pretty_url = "https://api.fraud-gw.cn/post"
        url = "https://api.fraud-gw.cn/post"

    req = _Req()
    req_msg = _FakeMessage('{"data":"abc","timestamp":123}')
    resp_msg = _FakeMessage('{"data":"def","timestamp":456}')
    # 给 request 对象补 text/content（_body_text 从中取）。
    req.text = req_msg.text  # type: ignore[attr-defined]
    req.content = req_msg.content  # type: ignore[attr-defined]
    flow = _FakeFullFlow(req, resp_msg)

    _inject_fake_mitmproxy(monkeypatch, [flow])
    msgs = capture._parse_messages(flows_file)
    assert len(msgs) == 1
    assert msgs[0]["url"] == "https://api.fraud-gw.cn/post"
    assert '"data"' in msgs[0]["request_body"]
    assert '"data"' in msgs[0]["response_body"]


def test_parse_messages_skips_non_envelope(monkeypatch, tmp_path):
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    class _Req:
        pretty_url = "https://api.fraud-gw.cn/x"
        url = "https://api.fraud-gw.cn/x"
        text = '{"foo":"bar"}'
        content = b'{"foo":"bar"}'

    flow = _FakeFullFlow(_Req(), _FakeMessage('{"foo":"bar"}'))
    _inject_fake_mitmproxy(monkeypatch, [flow])
    assert capture._parse_messages(flows_file) == []


def test_parse_messages_missing_file_returns_empty(tmp_path):
    assert capture._parse_messages(tmp_path / "nope.mitm") == []


def test_runtime_report_includes_messages_field(tmp_path):
    """_write_runtime_report 写出 messages 字段（默认空数组，向后兼容）。"""
    report_path = capture._write_runtime_report(
        "com.test.app", tmp_path, [], complete=True
    )
    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert "messages" in payload
    assert payload["messages"] == []


def test_runtime_report_persists_messages(tmp_path):
    msgs = [{"url": "u", "request_body": "{}", "response_body": '{"data":"x","timestamp":1}'}]
    report_path = capture._write_runtime_report(
        "com.test.app", tmp_path, [], complete=True, messages=msgs
    )
    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert payload["messages"] == msgs


# ---------------------------------------------------------------------------
# P0：frida-core 会话（运行时密钥 hook）+ crypto_events 落盘
# ---------------------------------------------------------------------------


def test_runtime_report_crypto_events_default_empty(tmp_path):
    """_write_runtime_report 默认写出空 crypto_events（向后兼容）。"""
    report_path = capture._write_runtime_report("com.test.app", tmp_path, [], complete=True)
    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert "crypto_events" in payload
    assert payload["crypto_events"] == []


def test_runtime_report_persists_crypto_events(tmp_path):
    events = [{"src": "cipher", "event": "init", "key_hex": "55f0", "iv_hex": None}]
    report_path = capture._write_runtime_report(
        "com.test.app", tmp_path, [], complete=True, crypto_events=events
    )
    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    assert payload["crypto_events"] == events


def test_start_frida_session_falls_back_when_frida_core_missing(monkeypatch):
    """frida-core（import frida）不可用 → 返回 (None, None)，由调用方回退 subprocess。"""
    import sys

    # sys.modules['frida']=None 让 `import frida` 抛 ImportError。
    monkeypatch.setitem(sys.modules, "frida", None)
    session, script = capture._start_frida_session("com.test.app", [])
    assert session is None
    assert script is None


def test_start_frida_session_attaches_and_loads_script(monkeypatch):
    """注入假 frida-core：断言注入脚本同时含 unpinning + 运行时密钥 hook，且注册了 on_message。"""
    import sys
    import types

    captured: dict[str, Any] = {}

    class _FakeScript:
        def __init__(self, source: str) -> None:
            captured["source"] = source
            self.on_calls: list[tuple[str, Any]] = []
            self.loaded = False

        def on(self, name: str, cb: Any) -> None:
            self.on_calls.append((name, cb))
            captured["on"] = (name, cb)

        def load(self) -> None:
            self.loaded = True
            captured["loaded"] = True

    class _FakeSession:
        def create_script(self, source: str) -> _FakeScript:
            return _FakeScript(source)

        def detach(self) -> None:
            captured["detached"] = True

    class _FakeDevice:
        def spawn(self, argv: Any) -> int:
            captured["spawned"] = argv
            return 4321

        def attach(self, pid: int) -> _FakeSession:
            captured["attached_pid"] = pid
            return _FakeSession()

        def resume(self, pid: int) -> None:
            captured["resumed"] = pid

        def kill(self, pid: int) -> None:
            captured["killed"] = pid

    fake_frida = types.SimpleNamespace(get_usb_device=lambda timeout=None: _FakeDevice())
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    sink: list[dict[str, Any]] = []
    session, script = capture._start_frida_session("com.test.app", sink)

    assert session is not None
    assert script is not None
    # 注入脚本同时含 unpinning（TrustManager）与运行时密钥 hook（Cipher）。
    src = captured["source"]
    assert "Java.perform" in src
    assert "javax.crypto.Cipher" in src
    assert "X509TrustManager" in src  # unpinning 也在
    # 注册了 message 回调、脚本已 load、app 已 resume。
    assert captured["on"][0] == "message"
    assert captured["loaded"] is True
    assert captured["spawned"] == ["com.test.app"]
    assert captured["resumed"] == 4321


def test_start_frida_session_cleans_up_on_load_failure(monkeypatch):
    """脚本 load 失败 → kill 已 spawn 的进程 + detach，返回 (None,None)（避免回退路径二次 spawn 冲突）。"""
    import sys
    import types

    captured: dict[str, Any] = {}

    class _FakeScript:
        def __init__(self, source: str) -> None:
            pass

        def on(self, name: str, cb: Any) -> None:
            pass

        def load(self) -> None:
            raise RuntimeError("script load boom")

    class _FakeSession:
        def create_script(self, source: str) -> _FakeScript:
            return _FakeScript(source)

        def detach(self) -> None:
            captured["detached"] = True

    class _FakeDevice:
        def spawn(self, argv: Any) -> int:
            return 999

        def attach(self, pid: int) -> _FakeSession:
            return _FakeSession()

        def resume(self, pid: int) -> None:
            captured["resumed"] = pid

        def kill(self, pid: int) -> None:
            captured["killed"] = pid

    fake_frida = types.SimpleNamespace(get_usb_device=lambda timeout=None: _FakeDevice())
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    session, script = capture._start_frida_session("com.test.app", [])
    assert session is None and script is None
    # 清理：已 spawn 的进程被 kill、会话被 detach；resume 未发生（load 在 resume 前失败）。
    assert captured.get("killed") == 999
    assert captured.get("detached") is True
    assert "resumed" not in captured


def test_start_frida_session_kills_pid_on_attach_failure(monkeypatch):
    """attach 失败（pid 已 spawn、session 仍 None）→ kill(pid) 但不 detach，返回 (None,None)。"""
    import sys
    import types

    captured: dict[str, Any] = {}

    class _FakeDevice:
        def spawn(self, argv: Any) -> int:
            return 777

        def attach(self, pid: int) -> Any:
            raise RuntimeError("attach denied")

        def resume(self, pid: int) -> None:
            captured["resumed"] = pid

        def kill(self, pid: int) -> None:
            captured["killed"] = pid

    fake_frida = types.SimpleNamespace(get_usb_device=lambda timeout=None: _FakeDevice())
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    session, script = capture._start_frida_session("com.test.app", [])
    assert session is None and script is None
    # 不变量 #3：已 spawn 的 pid 必须被 kill（否则 subprocess 回退 -f 二次 spawn 冲突）。
    assert captured.get("killed") == 777
    assert "detached" not in captured  # session 为 None，无可 detach
    assert "resumed" not in captured


def test_start_frida_session_no_kill_on_spawn_failure(monkeypatch):
    """spawn 失败（pid 未生成）→ 既不 kill 也不 detach，返回 (None,None)（不误杀别的进程）。"""
    import sys
    import types

    captured: dict[str, Any] = {}

    class _FakeDevice:
        def spawn(self, argv: Any) -> int:
            raise RuntimeError("spawn failed: app not installed")

        def kill(self, pid: int) -> None:
            captured["killed"] = pid

    fake_frida = types.SimpleNamespace(get_usb_device=lambda timeout=None: _FakeDevice())
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    session, script = capture._start_frida_session("com.test.app", [])
    assert session is None and script is None
    assert "killed" not in captured  # pid 未生成，不该误 kill


def test_capped_sentinel_filtered_from_runtime_report(monkeypatch, tmp_path):
    """sink 上限占位 {_capped:True} 不得写进 runtime_report.json（只留真事件）。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _fake_session(package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None):
        sink.append({"src": "cipher", "event": "init", "key_hex": "55f0"})
        sink.append({"_capped": True})  # 上限占位
        return object(), object()

    monkeypatch.setattr(capture, "_start_frida_session", _fake_session)

    capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert len(payload["crypto_events"]) == 1  # _capped 占位被过滤
    assert all(not e.get("_capped") for e in payload["crypto_events"])


def test_capture_done_collects_crypto_events_via_session(monkeypatch, tmp_path):
    """frida-core 会话路径：on_message 收到的活体 crypto 事件落进 runtime_report.json。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    fake_events = [
        {"src": "cipher", "event": "init", "key_hex": "55f0", "iv_hex": None},
        {"src": "cipher", "event": "doFinal", "key_hex": "55f0", "plaintext_b64": "eyJhIjoxfQ=="},
    ]

    def _fake_session(package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None):
        # 模拟 on_message 回调把 2 条事件写进共享 sink。
        sink.extend(fake_events)
        return object(), object()  # 非 None 会话/脚本（teardown 对 dummy 容错）

    monkeypatch.setattr(capture, "_start_frida_session", _fake_session)

    result = capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    assert result["status"] == STATUS_DONE

    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert len(payload["crypto_events"]) == 2
    assert {e["event"] for e in payload["crypto_events"]} == {"init", "doFinal"}


def test_capture_collects_jsbridge_and_sensitive_api_events(monkeypatch, tmp_path):
    """P1：会话路径把 JS-bridge / 敏感 API 事件分别落进 runtime_report.json。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _fake_session(package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None):
        if jsbridge_sink is not None:
            jsbridge_sink.append({"event": "register", "iface": "AndroidNative"})
        if api_sink is not None:
            api_sink.append({"event": "call", "api": "TelephonyManager.getDeviceId"})
        return object(), object()

    monkeypatch.setattr(capture, "_start_frida_session", _fake_session)

    capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert payload["jsbridge_events"] == [{"event": "register", "iface": "AndroidNative"}]
    assert payload["sensitive_api_events"] == [{"event": "call", "api": "TelephonyManager.getDeviceId"}]


def test_runtime_report_p1_events_default_empty(tmp_path):
    """_write_runtime_report 默认写出空 jsbridge_events/sensitive_api_events/antidetect_events。"""
    rp = capture._write_runtime_report("com.test.app", tmp_path, [], complete=True)
    payload = json.loads(Path(rp).read_text(encoding="utf-8"))
    assert payload["jsbridge_events"] == []
    assert payload["sensitive_api_events"] == []
    assert payload["antidetect_events"] == []


def test_capture_collects_antidetect_events(monkeypatch, tmp_path):
    """P3：会话路径把反检测探测事件落进 runtime_report.json。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _fake_session(package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None):
        if antidetect_sink is not None:
            antidetect_sink.append({"kind": "root", "probe": "File.exists: /system/bin/su", "bypassed": True})
        return object(), object()

    monkeypatch.setattr(capture, "_start_frida_session", _fake_session)
    capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert payload["antidetect_events"] == [
        {"kind": "root", "probe": "File.exists: /system/bin/su", "bypassed": True}
    ]


def test_capture_collects_credential_events_via_session(monkeypatch, tmp_path):
    """P2：会话路径把 OkHttp 凭据事件落进 runtime_report.json。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])
    # 不触真 adb pull（无 shared_prefs）。
    monkeypatch.setattr(capture, "_pull_shared_prefs_credentials", lambda pkg, op, sink: None)

    def _fake_session(package, sink, jsbridge_sink=None, api_sink=None, antidetect_sink=None, credential_sink=None, sqlcipher_sink=None):
        if credential_sink is not None:
            credential_sink.append(
                {"source": "okhttp", "url": "https://api.fraud-c2.cn/login", "method": "POST",
                 "headers": {}, "body": ""}
            )
        return object(), object()

    monkeypatch.setattr(capture, "_start_frida_session", _fake_session)
    capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert len(payload["credential_events"]) == 1
    assert payload["credential_events"][0]["source"] == "okhttp"


def test_capture_pulls_shared_prefs_credentials_at_teardown(monkeypatch, tmp_path):
    """P2：收尾 _pull_shared_prefs_credentials 把落地凭据写进 credential_events。"""
    _set_capabilities(monkeypatch)
    _stub_orchestration(monkeypatch, mitm=_FakeProc(), frida=None)
    monkeypatch.setattr(capture, "_parse_flows", lambda f: [])

    def _fake_pull(pkg, out_path, sink):
        sink.append({"source": "sharedprefs", "name": "token", "value": "Abc1…f456", "file": "p.xml"})

    monkeypatch.setattr(capture, "_pull_shared_prefs_credentials", _fake_pull)
    capture.run("com.test.app", out_dir=str(tmp_path), duration=1)
    payload = json.loads((tmp_path / "runtime_report.json").read_text(encoding="utf-8"))
    assert payload["credential_events"] == [
        {"source": "sharedprefs", "name": "token", "value": "Abc1…f456", "file": "p.xml"}
    ]


def test_runtime_report_credential_events_default_empty(tmp_path):
    """_write_runtime_report 默认写出空 credential_events（向后兼容旧消费方）。"""
    rp = capture._write_runtime_report("com.test.app", tmp_path, [], complete=True)
    payload = json.loads(Path(rp).read_text(encoding="utf-8"))
    assert payload["credential_events"] == []


def test_pull_shared_prefs_no_adb_is_noop(monkeypatch):
    """无 adb（_adb_capture 全 None）→ 不抠任何凭据、不抛。"""
    monkeypatch.setattr(capture, "_adb_capture", lambda extra: None)
    sink: list[dict[str, Any]] = []
    capture._pull_shared_prefs_credentials("com.test.app", Path("."), sink)
    assert sink == []


def test_pull_shared_prefs_extracts_via_run_as(monkeypatch, tmp_path):
    """run-as 列 xml + cat 内容 → 抠出脱敏凭据进 sink。"""
    prefs_xml = (
        "<?xml version='1.0'?><map>"
        '<string name="token">Abc123Xyz789Def456Ghi012</string>'
        '<string name="nickname">张三</string>'
        "</map>"
    )

    def _fake_capture(extra):
        if "ls" in extra:
            return "user_prefs.xml\nother.txt\n"
        if "cat" in extra:
            return prefs_xml
        return None

    monkeypatch.setattr(capture, "_adb_capture", _fake_capture)
    sink: list[dict[str, Any]] = []
    capture._pull_shared_prefs_credentials("com.test.app", tmp_path, sink)
    names = {c["name"] for c in sink}
    assert "token" in names
    assert "nickname" not in names  # 非敏感键不抠
    # 脱敏：token 不留全文
    token = next(c for c in sink if c["name"] == "token")
    assert "Abc123Xyz789Def456Ghi012" not in token["value"]


def test_frida_session_script_includes_antidetect(monkeypatch):
    """会话注入脚本应含反检测绕过段（与 unpinning/crypto/jsbridge/api 拼接）。"""
    import sys
    import types

    captured: dict[str, Any] = {}

    class _FakeScript:
        def __init__(self, source: str) -> None:
            captured["source"] = source

        def on(self, name: str, cb: Any) -> None:
            pass

        def load(self) -> None:
            pass

    class _FakeSession:
        def create_script(self, source: str) -> _FakeScript:
            return _FakeScript(source)

        def detach(self) -> None:
            pass

    class _FakeDevice:
        def spawn(self, argv: Any) -> int:
            return 1

        def attach(self, pid: int) -> _FakeSession:
            return _FakeSession()

        def resume(self, pid: int) -> None:
            pass

        def kill(self, pid: int) -> None:
            pass

    monkeypatch.setitem(sys.modules, "frida", types.SimpleNamespace(get_usb_device=lambda timeout=None: _FakeDevice()))
    capture._start_frida_session("com.x", [], [], [], [])
    assert "apkscan-antidetect" in captured["source"]
    assert "addJavascriptInterface" in captured["source"]  # P1 也在


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
    # adb 不可用：tools.adb_path 返回 ""（取代旧 shutil.which mock）。
    monkeypatch.setattr(capture.tools, "adb_path", lambda: "")
    assert capture._device_frida_version() == ""


def test_device_frida_version_parses_semver(monkeypatch):
    monkeypatch.setattr(capture.tools, "adb_path", lambda: "adb")

    class _CP:
        returncode = 0
        stdout = "16.5.9\n"
        stderr = ""

    monkeypatch.setattr(capture.subprocess, "run", lambda *a, **k: _CP())
    assert capture._device_frida_version() == "16.5.9"


def test_device_frida_version_timeout_returns_empty(monkeypatch):
    monkeypatch.setattr(capture.tools, "adb_path", lambda: "adb")

    def _boom(*a: Any, **k: Any):
        raise capture.subprocess.TimeoutExpired(cmd="adb", timeout=5.0)

    monkeypatch.setattr(capture.subprocess, "run", _boom)
    assert capture._device_frida_version() == ""


# ---------------------------------------------------------------------------
# A1 回归：frida unpinning 不再无脑传 --no-pause（≥14 删除该参数会秒退失效）
# ---------------------------------------------------------------------------


def _capture_popen_args(monkeypatch, host_ver: str, tmp_path):
    """跑 _start_frida_unpinning，捕获传给 subprocess.Popen 的 args。"""
    monkeypatch.setattr(capture.tools, "frida_invocation", lambda tool: ["frida"])
    monkeypatch.setattr(capture.provision, "host_frida_version", lambda: host_ver)
    captured: dict[str, list[str]] = {}

    class _FakePopen:
        def __init__(self, args, **kwargs):
            captured["args"] = args

    monkeypatch.setattr(capture.subprocess, "Popen", _FakePopen)
    capture._start_frida_unpinning("com.x.y", tmp_path)
    return captured["args"]


def test_frida_unpinning_drops_no_pause_on_new_frida(monkeypatch, tmp_path):
    """frida-tools ≥14：不传 --no-pause（默认就不暂停；传了会 unrecognized arguments 秒退）。"""
    args = _capture_popen_args(monkeypatch, "17.11.0", tmp_path)
    assert "--no-pause" not in args
    assert "-f" in args and "com.x.y" in args


def test_frida_unpinning_keeps_no_pause_on_old_frida(monkeypatch, tmp_path):
    """frida-tools <14：补 --no-pause 以保持不暂停。"""
    args = _capture_popen_args(monkeypatch, "12.5.0", tmp_path)
    assert "--no-pause" in args


def test_frida_unpinning_no_no_pause_when_version_unknown(monkeypatch, tmp_path):
    """版本拿不到 → 按新版处理，不加 --no-pause。"""
    args = _capture_popen_args(monkeypatch, "", tmp_path)
    assert "--no-pause" not in args


# ---------------------------------------------------------------------------
# 包名形态校验（防御性：样本可控的畸形包名不下发到 frida/adb）
# ---------------------------------------------------------------------------


def test_is_valid_package() -> None:
    assert device.is_valid_package("com.evil.app") is True
    assert device.is_valid_package("com.x_y.App2") is True
    assert device.is_valid_package("") is False
    assert device.is_valid_package("com.x;rm -rf /") is False  # 含 shell 元字符
    assert device.is_valid_package("com.x app") is False  # 含空格
    assert device.is_valid_package("com/x") is False  # 含斜杠


def test_capture_rejects_malformed_package(tmp_path) -> None:  # noqa: ANN001
    """畸形包名 → capture.run 早返回 error，不进入设备探测/下发。"""
    res = capture.run("com.x;evil", out_dir=str(tmp_path), duration=1)
    assert res["status"] == STATUS_ERROR
    assert "包名形态非法" in res["reason"]


# ---------------------------------------------------------------------------
# frida-core 会话收尾：kill spawned app（避免堆叠孤儿进程）
# ---------------------------------------------------------------------------


def test_teardown_kills_spawned_pid(monkeypatch) -> None:  # noqa: ANN001
    """有真实 int pid 的会话 → 收尾调 _kill_spawned_app(pid)。"""
    killed: list[int] = []
    monkeypatch.setattr(capture, "_kill_spawned_app", lambda pid: killed.append(pid))

    class _Sess:
        pid = 4321

        def detach(self) -> None: ...

    class _Script:
        def unload(self) -> None: ...

    capture._teardown_frida_session(_Sess(), _Script())
    assert killed == [4321]


def test_teardown_no_kill_when_session_has_no_pid(monkeypatch) -> None:  # noqa: ANN001
    """会话无 pid（如测试替身 object()）→ 不触发 kill（不误调真 frida）。"""
    killed: list[int] = []
    monkeypatch.setattr(capture, "_kill_spawned_app", lambda pid: killed.append(pid))
    capture._teardown_frida_session(object(), object())
    assert killed == []


class _FakeServerConn:
    def __init__(self, peername) -> None:  # noqa: ANN001
        self.peername = peername


class _FakeFlowWithConn:
    def __init__(self, request: "_FakeRequest", server_conn: "_FakeServerConn") -> None:
        self.request = request
        self.server_conn = server_conn


def test_parse_flows_extracts_server_ip(monkeypatch, tmp_path):  # noqa: ANN001
    """server_conn.peername 的**实连服务器 IP** 作为运行时端点产出（C2 真实落点，调证关键）。"""
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    flows = [
        _FakeFlowWithConn(
            _FakeRequest("https://gw.hxhcapi.vip/cfg", "gw.hxhcapi.vip", "https"),
            _FakeServerConn(("203.0.113.9", 443)),
        ),
    ]
    fake_io = type(
        "io",
        (),
        {"FlowReader": staticmethod(lambda fh: type("R", (), {"stream": lambda self: iter(flows)})())},
    )
    fake_http = type("http", (), {"HTTPFlow": _FakeFlowWithConn})

    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", type("m", (), {}))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", fake_io)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)

    eps = capture._parse_flows(flows_file)
    by_value = {ep.value: ep for ep in eps}

    assert "203.0.113.9" in by_value  # 实连服务器 IP 被抽出
    assert by_value["203.0.113.9"].kind == "ip"
    assert "gw.hxhcapi.vip" in by_value  # 域名也在
    assert all(ev.source == "runtime" for ep in eps for ev in ep.evidences)


# ---------------------------------------------------------------------------
# 噪音过滤：模拟器/系统自身流量
# ---------------------------------------------------------------------------


def test_is_noise_host_matching():
    pats = (".pool.ntp.org", "connectivitycheck.gstatic.com", ".mumu.com")
    assert capture._is_noise_host("a.pool.ntp.org", pats) is True  # 后缀
    assert capture._is_noise_host("pool.ntp.org", pats) is True  # 后缀含自身
    assert capture._is_noise_host("connectivitycheck.gstatic.com", pats) is True  # 精确
    assert capture._is_noise_host("update.mumu.com", pats) is True
    assert capture._is_noise_host("gw.hxhcapi.vip", pats) is False  # 真涉诈域名不误杀
    assert capture._is_noise_host("maps.googleapis.com", pats) is False  # app SDK 不误杀
    assert capture._is_noise_host("", pats) is False


def test_mumu_netease_domain_is_noise():
    """MuMu（网易）走 163 域名的自身流量（store-api.mumu.163.com）算噪音；合法 163.com 不误杀。

    回归锁：真机实测中 MuMu 模拟器自身的 store-api.mumu.163.com（及其实连 IP）被误判成被分析
    app 的 C2·实连。读真实 capture_noise.yaml，断言已被过滤、且 mail.163.com 这类合法域名不连坐。
    """
    pats = capture._load_noise_patterns()  # 读真实 rules/capture_noise.yaml
    assert capture._is_noise_host("store-api.mumu.163.com", pats) is True
    assert capture._is_noise_host("update.mumu.163.com", pats) is True
    assert capture._is_noise_host("mail.163.com", pats) is False  # 合法网易域名不误杀
    assert capture._is_noise_host("163.com", pats) is False


def test_cleanup_diag_removes_empty_keeps_nonempty(tmp_path):
    """成功抓包后：.diag/ 下的空 stderr 日志删掉、非空的保留（供排障）。"""
    diag = tmp_path / ".diag"
    diag.mkdir()
    (diag / "mitmdump.stderr.log").write_bytes(b"")  # 空 → 删
    (diag / "frida.stderr.log").write_bytes(b"boom")  # 非空 → 留
    capture._cleanup_diag(tmp_path)
    assert not (diag / "mitmdump.stderr.log").exists()
    assert (diag / "frida.stderr.log").exists()


def test_cleanup_diag_removes_empty_dir(tmp_path):
    """.diag/ 全空 → 连目录一起删（不在主输出目录留杂物）。"""
    diag = tmp_path / ".diag"
    diag.mkdir()
    (diag / "mitmdump.stderr.log").write_bytes(b"")
    capture._cleanup_diag(tmp_path)
    assert not diag.exists()


def test_cleanup_diag_no_diag_is_noop(tmp_path):
    """无 .diag 目录 → no-op，不抛。"""
    capture._cleanup_diag(tmp_path)  # 不抛即通过


def test_parse_flows_filters_emulator_noise(monkeypatch, tmp_path):
    """模拟器/系统自身流量（连通性检测/授时/模拟器遥测）→ 整条跳过，不入运行时端点。"""
    monkeypatch.setattr(capture, "_NOISE_PATTERNS_CACHE", None)  # 重置进程内缓存
    flows_file = tmp_path / "flows.mitm"
    flows_file.write_bytes(b"\x00data")

    flows = [
        _FakeFlowWithConn(  # 噪音：连通性检测
            _FakeRequest("http://connectivitycheck.gstatic.com/generate_204", "connectivitycheck.gstatic.com", "http"),
            _FakeServerConn(("142.250.0.1", 80)),
        ),
        _FakeFlowWithConn(  # 噪音：MuMu 遥测
            _FakeRequest("https://log.mumu.com/report", "log.mumu.com", "https"),
            _FakeServerConn(("1.2.3.4", 443)),
        ),
        _FakeFlowWithConn(  # 真涉诈端点
            _FakeRequest("https://gw.hxhcapi.vip/cfg", "gw.hxhcapi.vip", "https"),
            _FakeServerConn(("203.0.113.9", 443)),
        ),
    ]
    fake_io = type("io", (), {"FlowReader": staticmethod(lambda fh: type("R", (), {"stream": lambda self: iter(flows)})())})
    fake_http = type("http", (), {"HTTPFlow": _FakeFlowWithConn})

    import sys

    monkeypatch.setitem(sys.modules, "mitmproxy", type("m", (), {}))
    monkeypatch.setitem(sys.modules, "mitmproxy.io", fake_io)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)

    values = {ep.value for ep in capture._parse_flows(flows_file)}
    # 真涉诈域名 + 其实连 IP 保留
    assert "gw.hxhcapi.vip" in values
    assert "203.0.113.9" in values
    # 噪音 host / url / 其 IP 全被滤掉
    assert "connectivitycheck.gstatic.com" not in values
    assert "log.mumu.com" not in values
    assert "142.250.0.1" not in values  # 噪音流的实连 IP 也不入
    assert "1.2.3.4" not in values


def test_load_noise_patterns_rule_override(monkeypatch):
    """rules/capture_noise.yaml 给了 noise_hosts 即整体覆盖内置兜底。"""
    monkeypatch.setattr(capture, "_NOISE_PATTERNS_CACHE", None)
    from apkscan.core import registry

    monkeypatch.setattr(registry, "load_rules", lambda name: {"noise_hosts": ["evil-noise.test"]})
    pats = capture._load_noise_patterns()
    assert "evil-noise.test" in pats
    assert ".mumu.com" not in pats  # 规则覆盖了兜底


def test_load_noise_patterns_fallback_on_bad_rules(monkeypatch):
    monkeypatch.setattr(capture, "_NOISE_PATTERNS_CACHE", None)
    from apkscan.core import registry

    monkeypatch.setattr(registry, "load_rules", lambda name: "garbage")
    pats = capture._load_noise_patterns()
    assert ".mumu.com" in pats  # 坏规则 → 用内置兜底
