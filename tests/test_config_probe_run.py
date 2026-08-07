"""执行配置探测预案：默认零流量、三种结果分得开、回灌不冒充运行时实测。

这条链路一头连着对外发包、一头连着报告出口，两端都不容含糊：
- 发不发包由**显式开关**决定，不能因为某个参数没传就悄悄发出去；
- "取到了但里面没东西" 和 "压根没取成" 必须是两种状态，混起来报告里的
  「未发现下发域名」就成了一句不知深浅的话。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from apkscan.config.fetch import FetchResult
from apkscan.core import config_probe_run
from apkscan.core.config_probe_run import ProbeRunResult, run_plan

_PLAN = {
    "candidates": [
        {"url": "https://api.example.com/api/home/config", "host": "api.example.com",
         "path": "/api/home/config"},
        {"url": "https://cdn.example.net/app_init", "host": "cdn.example.net",
         "path": "/app_init"},
    ]
}


class _Recorder:
    """替身：记录被请求了哪些 URL，并按预设返回。**不发真包**。"""

    def __init__(self, responses: dict[str, FetchResult]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str, **_: Any) -> FetchResult:
        self.calls.append(url)
        return self.responses.get(
            url, FetchResult(url, False, None, 404, "HTTP 404")
        )


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch):
    """把下载函数换成替身并交出它——凡是发包都会被记下来。"""
    def _install(responses: dict[str, FetchResult]) -> _Recorder:
        rec = _Recorder(responses)
        monkeypatch.setattr("apkscan.config.fetch.fetch_config_object", rec)
        return rec

    return _install


# ---------------------------------------------------------------------------
# 1. 默认不发包
# ---------------------------------------------------------------------------


def test_default_run_sends_nothing(no_network) -> None:
    """★没有显式授权就一个包都不许发——这是主被动隔离的第一道门。

    ★变异验证：把 run_plan 里 ``if not authorized`` 那段删掉，本测试必红。
    """
    rec = no_network({})
    result = run_plan(_PLAN)

    assert rec.calls == [], f"未授权却发出了请求：{rec.calls}"
    assert result.counts() == {"planned": 2}
    assert result.endpoints == []
    assert result.authorized is False


def test_authorized_run_requests_every_candidate(no_network) -> None:
    rec = no_network({})
    run_plan(_PLAN, authorized=True)
    assert rec.calls == [c["url"] for c in _PLAN["candidates"]]


# ---------------------------------------------------------------------------
# 2. 三种结果分得开
# ---------------------------------------------------------------------------


def test_fetched_but_empty_is_not_the_same_as_never_fetched(no_network, monkeypatch) -> None:
    """★「取到了但没解出东西」≠「没取成」。

    前者是真的"查了没有"，可以写进报告支撑"未发现下发域名"；后者只是没查成，
    拿它当"没有"就是把证据边界抹掉了。
    """
    ok_url, bad_url = (c["url"] for c in _PLAN["candidates"])
    rec = no_network({ok_url: FetchResult(ok_url, True, b"{}", 200, None)})

    class _Empty:
        decoded = True
        text = "{}"
        decode_chain = ("json",)
        domains: tuple[str, ...] = ()
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Empty())
    result = run_plan(_PLAN, authorized=True)

    by_url = {o.url: o for o in result.outcomes}
    assert by_url[ok_url].status == "no_content", "取到了就不能记成没取成"
    assert by_url[bad_url].status == "failed"
    assert by_url[bad_url].error, "没取成必须留下原因，否则读者无从判断该不该重试"
    assert rec.calls == [ok_url, bad_url]


def test_hit_yields_endpoints_marked_as_config_not_runtime(no_network, monkeypatch) -> None:
    """★解出的域名是"配置里出现的"，不是运行时实测接触——source 标错会误升确认徽标。"""
    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ("base64", "json")
        domains = ("c2.example.org",)
        ips = ("198.51.100.7",)  # leak-scan: allow 测试夹具：RFC5737 文档地址段

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    result = run_plan(_PLAN, authorized=True)

    assert result.counts()["hit"] == 1
    assert {e.value for e in result.endpoints} == {"c2.example.org", "198.51.100.7"}  # leak-scan: allow 测试夹具：RFC5737 文档地址段
    for ep in result.endpoints:
        src = ep.evidences[0].source
        assert src == "remote-config", f"source={src!r}"
        assert not src.startswith("runtime"), "不得被 is_runtime_seen 之类的判据认成运行时实测"


def test_decode_failure_still_counts_as_fetched(no_network, monkeypatch) -> None:
    """解码炸了仍然是「取到了」——退化成 failed 会把"取到一坨解不开的东西"说成"没取到"。"""
    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    def _boom(*_a, **_k):
        raise ValueError("坏包")

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob", _boom)
    outcome = next(o for o in run_plan(_PLAN, authorized=True).outcomes if o.url == ok_url)
    assert outcome.status == "no_content"
    assert outcome.sha256 and outcome.size == 4, "原始字节的事实要留住"


def test_fetch_exception_is_contained_to_one_candidate(no_network, monkeypatch) -> None:
    """单个候选炸了不能带走整批。"""
    def _boom(url: str, **_: Any):
        if "home" in url:
            raise OSError("连接重置")
        return FetchResult(url, False, None, 404, "HTTP 404")

    monkeypatch.setattr("apkscan.config.fetch.fetch_config_object", _boom)
    result = run_plan(_PLAN, authorized=True)
    assert len(result.outcomes) == 2
    assert all(o.status == "failed" for o in result.outcomes)


# ---------------------------------------------------------------------------
# 3. 上限与截断可见
# ---------------------------------------------------------------------------


def test_limit_truncates_and_says_so(no_network) -> None:
    """★截断必须说出来：静默截断会让"都探过了"变成一句假话。"""
    rec = no_network({})
    result = run_plan(_PLAN, authorized=True, limit=1)
    assert len(rec.calls) == 1
    assert result.truncated == 1
    assert result.to_meta()["truncated"] == 1


def test_hard_cap_survives_a_tampered_plan(no_network) -> None:
    """预案是从报告里读的，可能被手改。内建硬帽是第二道，别让它变成批量请求器。"""
    rec = no_network({})
    huge = {"candidates": [{"url": f"https://h{i}.example.com/c"} for i in range(500)]}
    result = run_plan(huge, authorized=True, limit=10_000)
    assert len(rec.calls) <= 40
    assert result.truncated == 500 - len(rec.calls)


@pytest.mark.parametrize("plan", [None, {}, [], "x", {"candidates": "x"},
                                  {"candidates": [{"no_url": 1}, None]}])
def test_bad_plans_yield_nothing_and_never_raise(plan: object, no_network) -> None:
    rec = no_network({})
    result = run_plan(plan, authorized=True)
    assert isinstance(result, ProbeRunResult)
    assert result.outcomes == [] and rec.calls == []


# ---------------------------------------------------------------------------
# 4. ★接线：pipeline 与 CLI 用的是同一份构造，不会分叉
# ---------------------------------------------------------------------------


def test_pipeline_shares_the_same_endpoint_construction() -> None:
    """★两条路径（analyze 内的授权档下载 / config-probe 命令）产出同一类证据。

    各写一份的话，迟早在 source 标记或 stored_path 形状上分叉，而报告读起来都"正常"。
    ★变异验证：把 pipeline 里的别名改回独立实现，本测试必红。
    """
    from apkscan.core import pipeline

    assert pipeline._config_endpoint is config_probe_run.config_endpoint
    assert pipeline._archive_blob is config_probe_run.archive_blob
    assert pipeline._REMOTE_CONFIG_SUBDIR == config_probe_run.REMOTE_CONFIG_SUBDIR


def test_archive_failure_does_not_lose_the_leads(tmp_path: Path, no_network, monkeypatch) -> None:
    """落盘失败（只读盘/磁盘满）不得连累已解出的线索。"""
    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ()
        domains = ("c2.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    monkeypatch.setattr("apkscan.core.config_probe_run.atomic_write_bytes",
                        lambda *_a, **_k: (_ for _ in ()).throw(OSError("只读")))
    outcome = next(o for o in
                   run_plan(_PLAN, authorized=True, archive_dir=tmp_path).outcomes
                   if o.url == ok_url)
    assert outcome.status == "hit" and outcome.domains == ("c2.example.org",)
    assert outcome.stored_path is None, "落盘没成就该如实为 None，不能假装存了"


def test_archive_writes_the_raw_bytes(tmp_path: Path, no_network, monkeypatch) -> None:
    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"raw-blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ()
        domains = ("c2.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    outcome = next(o for o in
                   run_plan(_PLAN, authorized=True, archive_dir=tmp_path).outcomes
                   if o.url == ok_url)
    assert outcome.stored_path
    written = tmp_path / f"{outcome.sha256}.bin"
    assert written.read_bytes() == b"raw-blob"


# ---------------------------------------------------------------------------
# 5. CLI 回灌
# ---------------------------------------------------------------------------


def _report_with_plan(tmp_path: Path) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "meta": {"config_probe_plan": _PLAN},
        "endpoints": [{"kind": "domain", "value": "known.example.com", "evidences": []}],
        "leads": [],
    }, ensure_ascii=False), encoding="utf-8")
    return path


def test_cli_default_is_a_dry_run(tmp_path: Path, no_network, capsys) -> None:
    """★CLI 侧的门：不加 --authorized-active 就只列不发。"""
    from typer.testing import CliRunner

    from apkscan.cli import app

    rec = no_network({})
    res = CliRunner().invoke(app, ["config-probe", str(_report_with_plan(tmp_path))])
    assert res.exit_code == 0, res.output
    assert rec.calls == [], "预演模式发出了请求"
    assert "未发出任何请求" in res.output


def test_cli_merges_endpoints_without_claiming_runtime(
    tmp_path: Path, no_network, monkeypatch
) -> None:
    """回灌进 report.json 的端点标 remote-config，且不重复既有端点。"""
    from typer.testing import CliRunner

    from apkscan.cli import app

    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ()
        # 一个新域名 + 一个报告里已有的，验去重。
        domains = ("c2.example.org", "known.example.com")
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    report = _report_with_plan(tmp_path)
    res = CliRunner().invoke(app, ["config-probe", str(report),
                                   "--authorized-active", "--into", str(report)])
    assert res.exit_code == 0, res.output

    payload = json.loads(report.read_text(encoding="utf-8"))
    values = [e["value"] for e in payload["endpoints"]]
    assert values.count("known.example.com") == 1, "已有端点被重复追加"
    assert "c2.example.org" in values
    fresh = next(e for e in payload["endpoints"] if e["value"] == "c2.example.org")
    assert fresh["evidences"][0]["source"] == "remote-config"
    assert payload["meta"]["config_probe_run"]["counts"]["hit"] == 1


def test_cli_reports_a_missing_plan_instead_of_pretending(tmp_path: Path) -> None:
    """没有预案就说没有——不能静默成功让人以为探过了。"""
    from typer.testing import CliRunner

    from apkscan.cli import app

    path = tmp_path / "report.json"
    path.write_text(json.dumps({"meta": {}}), encoding="utf-8")
    res = CliRunner().invoke(app, ["config-probe", str(path)])
    assert res.exit_code == 1
