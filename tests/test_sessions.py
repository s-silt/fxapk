"""通信会话时序重建（B.2）纯逻辑单测。

capture 侧给运行时报文加 flow_id + ts（flow.id / request.timestamp_start）；merge 侧
merge_runtime_sessions 按 ts 升序重建会话时序，写 report.meta['comm_sessions']。

真机部分（mitmproxy 真抓 flow）无法单测，由用户在 MuMu 复验；本测覆盖纯函数提取与排序。
"""

from __future__ import annotations

import json
from typing import Any

from apkscan.core.models import Report
from apkscan.dynamic import merge
from apkscan.dynamic.capture import _flow_meta, _message_from_flow


class _Req:
    def __init__(self, url: str, body: str, ts: float | None) -> None:
        self.pretty_url = url
        self.text = body
        self.timestamp_start = ts


class _Resp:
    def __init__(self, body: str) -> None:
        self.text = body


class _Flow:
    def __init__(self, fid: str, req: object, resp: object) -> None:
        self.id = fid
        self.request = req
        self.response = resp


def _make_report(meta: dict[str, Any] | None = None) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


# ---- capture 侧：flow_id + ts 提取 ----------------------------------------


def test_flow_meta_extracts_id_and_ts() -> None:
    flow = _Flow("flow-abc", _Req("https://evil.com/api", "{}", 1700000000.5), _Resp(""))
    assert _flow_meta(flow) == ("flow-abc", 1700000000.5)


def test_flow_meta_missing_is_graceful() -> None:
    assert _flow_meta(object()) == ("", None)


def test_message_from_flow_carries_flow_id_and_ts() -> None:
    # 信封报文（含 data 与 timestamp）才保留；附 flow_id + ts。
    env = '{"data":"AAAA","timestamp":111}'
    flow = _Flow("f1", _Req("https://evil.com/up", env, 1700000123.0), _Resp(""))
    msg = _message_from_flow(flow)
    assert msg is not None
    assert msg["flow_id"] == "f1"
    assert msg["ts"] == 1700000123.0


# ---- merge 侧：会话时序重建 -----------------------------------------------


def test_merge_runtime_sessions_orders_by_ts(tmp_path) -> None:
    rr = tmp_path / "runtime_report.json"
    rr.write_text(
        json.dumps(
            {
                "messages": [
                    {"url": "https://b.com/2", "ts": 200.0, "flow_id": "f2",
                     "request_body": "x", "response_body": ""},
                    {"url": "https://a.com/1", "ts": 100.0, "flow_id": "f1",
                     "request_body": "", "response_body": "y"},
                    {"url": "https://c.com/3", "flow_id": "f3"},  # 无 ts → 末尾
                ]
            }
        ),
        encoding="utf-8",
    )
    report = _make_report()
    stats = merge.merge_runtime_sessions(report, str(rr))
    assert stats["sessions"] == 3
    sessions = report.meta["comm_sessions"]
    assert [s["flow_id"] for s in sessions] == ["f1", "f2", "f3"]  # 按 ts 升序、无 ts 末尾
    assert sessions[0]["host"] == "a.com"
    assert sessions[0]["has_response_body"] is True and sessions[0]["has_request_body"] is False
    assert sessions[1]["has_request_body"] is True


def test_merge_runtime_sessions_no_messages(tmp_path) -> None:
    rr = tmp_path / "runtime_report.json"
    rr.write_text(json.dumps({"messages": []}), encoding="utf-8")
    report = _make_report()
    assert merge.merge_runtime_sessions(report, str(rr))["sessions"] == 0
    assert "comm_sessions" not in report.meta


def test_merge_runtime_sessions_bad_path_never_throws() -> None:
    report = _make_report()
    assert merge.merge_runtime_sessions(report, "/no/such/runtime_report.json")["sessions"] == 0
