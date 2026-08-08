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


def test_undecoded_is_not_the_same_as_decoded_and_empty(no_network, monkeypatch) -> None:
    """★★「解不开」≠「解开了里面没有」——这两者曾被合成一档。

    一坨解不开的密文，内容是**未知**的；一份解开了的 JSON 里确实没有域名，才是"查了没有"。
    合成一档之后，「取回 3 个候选全是密文」会打印成「取到但无内容 3」，报告里顺手就写成
    "未发现下发域名"——拿看不懂的字节当了否定结论。

    ★变异验证：把 _fetch_one 的 status 判断改回只看 domains/ips（不看 decoded），本测试必红。
    """
    opaque_url, plain_url = (c["url"] for c in _PLAN["candidates"])
    no_network({
        opaque_url: FetchResult(opaque_url, True, b"\x9c\x1f" * 64, 200, None),
        plain_url: FetchResult(plain_url, True, b'{"ver":1}', 200, None),
    })

    class _Opaque:      # 解码链没走通：内容未知
        decoded = False
        text = None
        decode_chain: tuple[str, ...] = ()
        domains: tuple[str, ...] = ()
        ips: tuple[str, ...] = ()

    class _PlainEmpty:  # 解开了，里面确实没有
        decoded = True
        text = '{"ver":1}'
        decode_chain = ("json",)
        domains: tuple[str, ...] = ()
        ips: tuple[str, ...] = ()

    monkeypatch.setattr(
        "apkscan.config.decode.decode_config_blob",
        lambda raw, **_k: _Opaque() if raw.startswith(b"\x9c") else _PlainEmpty(),
    )
    by_url = {o.url: o for o in run_plan(_PLAN, authorized=True).outcomes}

    assert by_url[opaque_url].status == "undecoded", "解不开不能记成「查了没有」"
    assert by_url[opaque_url].decoded is False
    assert by_url[opaque_url].error, "解不开要说明原因，否则读者以为是空的"
    assert by_url[plain_url].status == "no_content"
    assert by_url[plain_url].decoded is True
    # ★两者在汇总层也必须分得开——counts 是 CLI 直接打印的那一行。
    counts = run_plan(_PLAN, authorized=True).counts()
    assert counts.get("undecoded") == 1 and counts.get("no_content") == 1


def test_decoded_flag_is_always_emitted_for_fetched_outcomes(no_network, monkeypatch) -> None:
    """★decoded 必须出现在序列化输出里，哪怕值是 False。

    to_dict 对假值一律省略，decoded=False 若跟着这个惯例被省掉，读 JSON 的人就再也
    分不出「内容未知」和「确实没有」——修好的三分会在出口处重新塌回去。
    """
    url = _PLAN["candidates"][0]["url"]
    no_network({url: FetchResult(url, True, b"xx", 200, None)})

    class _Opaque:
        decoded = False
        text = None
        decode_chain: tuple[str, ...] = ()
        domains: tuple[str, ...] = ()
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Opaque())
    d = next(o for o in run_plan(_PLAN, authorized=True).outcomes
             if o.url == url).to_dict()
    assert "decoded" in d and d["decoded"] is False


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
    """解码炸了仍然是「取到了」——退化成 failed 会把"取到一坨解不开的东西"说成"没取到"。

    归 ``undecoded`` 而非 ``no_content``：抛异常与解码链走不通是同一种处境——
    字节在手上，内容不知道。
    """
    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    def _boom(*_a, **_k):
        raise ValueError("坏包")

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob", _boom)
    outcome = next(o for o in run_plan(_PLAN, authorized=True).outcomes if o.url == ok_url)
    assert outcome.status == "undecoded"
    assert outcome.decoded is False
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


def test_stored_path_locates_the_archived_bytes(tmp_path: Path, no_network, monkeypatch) -> None:
    """★stored_path 必须定位到实际落盘的文件——按调用方给的 archive_dir 原样登记。

    曾恒定拼 ``remote_config/`` 前缀：那只是 analyze 流水线自己的布局
    （archive_dir=out_dir/remote_config）；``fxapk config-probe --archive <任意目录>``
    时登记出的路径指向不存在的位置，实发请求换来的一手件只能靠 sha 全盘搜。
    """
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
    monkeypatch.chdir(tmp_path)  # 复刻在工作目录里跑 `--archive blobs` 的形态
    outcome = next(o for o in
                   run_plan(_PLAN, authorized=True, archive_dir=Path("blobs")).outcomes
                   if o.url == ok_url)
    assert outcome.stored_path is not None
    located = Path(outcome.stored_path)
    assert located.is_file(), f"stored_path={outcome.stored_path!r} 定位不到落盘文件"
    assert located.read_bytes() == b"raw-blob", "定位到了文件但字节不保真"


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


def test_cli_merge_produces_leads_reachable_by_the_real_exports(
    tmp_path: Path, no_network, monkeypatch
) -> None:
    """★★接线锁：取回的域名必须能走到真出口，光进 endpoints 等于没做。

    文书套打、IOC 导出、闭环目标、digest、corpus 入库**全部只读 leads**。曾经只往
    endpoints 里塞，于是实发请求换来的下发池躺在 JSON 里，五个出口一条都看不到。

    这里不只断言 leads 数组有值——那还是在原地打转；而是把回灌后的报告真喂给
    IOC 导出，看那个域名有没有出现在最终产物里。

    ★变异验证：把 _merge_config_probe_into_report 里产 Lead 的那段删掉，本测试必红。
    """
    import json as _json

    from typer.testing import CliRunner

    from apkscan.cli import app
    from apkscan.report import ioc

    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ("json",)
        domains = ("c2-from-config.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    report = _report_with_plan(tmp_path)
    res = CliRunner().invoke(app, ["config-probe", str(report),
                                   "--authorized-active", "--into", str(report)])
    assert res.exit_code == 0, res.output

    payload = _json.loads(report.read_text(encoding="utf-8"))
    lead = next((x for x in payload["leads"]
                 if x.get("value") == "c2-from-config.example.org"), None)
    assert lead is not None, "取回的域名没进 leads——所有出口都读不到它"
    assert lead.get("advice"), "Lead 必须带研判档位，否则出口的闸门筛不到它"

    # ★真出口：喂给 IOC 导出，看它到不到得了最终产物。
    rows = ioc.leads_to_ioc_rows(payload)
    assert any("c2-from-config.example.org" in str(r) for r in rows), (
        "回灌的域名到不了 IOC 导出——leads 这一层接上了，出口那层还是断的"
    )


def test_cli_merge_quarantines_repack_sample_domains(
    tmp_path: Path, no_network, monkeypatch
) -> None:
    """★★重打包件取回的域名属被仿冒的正版厂商，不得以最高档进出口。

    产 Lead 的链有四步——advice 分级 / 默认兜底 / base_advice 封存 / **重打包隔离**。
    前三步曾经做了、第四步漏了，于是同一份报告：静态链把厂商域名降到「待核」，
    这条路却把它放行到出口，会导致向无关的正版厂商发函。

    ★变异验证：删掉 _merge_config_probe_into_report 里的 apply_repack_quarantine 调用，
    本测试必红。
    """
    import json as _json

    from typer.testing import CliRunner

    from apkscan.cli import app
    from apkscan.core.leads import _VERDICT_REPACK_SUSPECTED
    from apkscan.report import ioc

    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ("json",)
        domains = ("api.vendor-from-config.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())

    report = tmp_path / "repack_report.json"
    report.write_text(_json.dumps({
        "meta": {
            "config_probe_plan": _PLAN,
            # 样本被判为正版重打包——这是隔离生效的前提。
            "repack_identity": {"verdict": _VERDICT_REPACK_SUSPECTED},
        },
        "endpoints": [],
        "leads": [],
    }, ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(app, ["config-probe", str(report),
                                   "--authorized-active", "--into", str(report)])
    assert res.exit_code == 0, res.output

    payload = _json.loads(report.read_text(encoding="utf-8"))
    lead = next(x for x in payload["leads"]
                if x.get("value") == "api.vendor-from-config.example.org")
    assert lead["advice"] != "建议调证", (  # leak-scan: allow 判据档位常量本身，测的正是这一档不该出现
        f"重打包件的厂商域名档位是 {lead['advice']!r}——隔离没生效"
    )
    # 审计要留痕，否则被降档的人无从知道为什么。
    assert payload["meta"]["repack_quarantine"]["count"] >= 1

    # ★真出口：ioc --only-investigate 的闸门是 advice，这批不该出现在里面。
    rows = ioc.leads_to_ioc_rows(payload, only_investigate=True)
    assert not any("api.vendor-from-config.example.org" in str(r) for r in rows), (
        "被仿冒厂商的域名走到了出口"
    )


def test_cli_merge_feeds_the_control_chain_artifacts_key(
    tmp_path: Path, no_network, monkeypatch
) -> None:
    """★取回的配置对象要进 remote_config_artifacts——config-chain / corpus 串联 / closure
    解密三处只读这一个键。

    只写 config_probe_runs 的话，同一份配置能不能串案就取决于走哪条路取回，
    而控制链会永远缺最后一段。

    ★变异验证：删掉回灌里写 remote_config_artifacts 的那段，本测试必红。
    """
    import json as _json

    from typer.testing import CliRunner

    from apkscan.cli import app
    from apkscan.config.chain import build_control_chains

    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"blob", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ("base64", "json")
        domains = ("chain.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    report = _report_with_plan(tmp_path)
    res = CliRunner().invoke(app, ["config-probe", str(report),
                                   "--authorized-active", "--into", str(report)])
    assert res.exit_code == 0, res.output

    payload = _json.loads(report.read_text(encoding="utf-8"))
    arts = payload["meta"]["remote_config_artifacts"]
    assert len(arts) == 1
    art = arts[0]
    # 形状要与 pipeline 那条路逐字段对齐，否则消费方按名取值会取到 None。
    for field in ("source_url", "sha256", "size", "decoded", "decode_chain",
                  "domains", "ips", "stored_path"):
        assert field in art, f"artifact 缺字段 {field}——与 pipeline 那条路不同构"
    assert art["decoded"] is True and art["domains"] == ["chain.example.org"]

    # ★真消费方：控制链组装读的就是这个键。
    chains = build_control_chains(arts, None, [])
    assert chains, "取回的配置对象没能进控制链"

    # 重复回灌不该把同一个对象记两遍。
    CliRunner().invoke(app, ["config-probe", str(report),
                             "--authorized-active", "--into", str(report)])
    again = _json.loads(report.read_text(encoding="utf-8"))
    assert len(again["meta"]["remote_config_artifacts"]) == 1, "同一对象被重复登记"


def test_cli_merge_marks_the_run_as_active(tmp_path: Path, no_network, monkeypatch) -> None:
    """★发过请求就不能再声称全程被动——mode 只升不降。

    corpus manifest 与 jsonl 头把 mode 当可信度/可复现性的依据在读；静态那轮是 passive
    是事实，"此后又做过授权档主动取回"同样是事实，报告要如实。
    """
    import json as _json

    from typer.testing import CliRunner

    from apkscan.cli import app

    ok_url = _PLAN["candidates"][0]["url"]
    no_network({ok_url: FetchResult(ok_url, True, b"x", 200, None)})

    class _Found:
        decoded = True
        text = ""
        decode_chain = ()
        domains = ("m.example.org",)
        ips: tuple[str, ...] = ()

    monkeypatch.setattr("apkscan.config.decode.decode_config_blob",
                        lambda *_a, **_k: _Found())
    report = _report_with_plan(tmp_path)
    payload = _json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["mode"] = "passive"
    report.write_text(_json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    CliRunner().invoke(app, ["config-probe", str(report),
                             "--authorized-active", "--into", str(report)])
    assert _json.loads(report.read_text(encoding="utf-8"))["meta"]["mode"] == \
        "authorized-active"


def test_cli_refuses_to_write_into_a_different_sample(
    tmp_path: Path, no_network, capsys
) -> None:
    """★--into 指向别的样本时必须在**发请求之前**拦下。

    预案与解码配方取自 report_path，结果却写进 --into；两者不是同一样本的话，
    取回的下发池会被安到别的案子头上。而请求一旦发出就撤不回来。
    """
    import json as _json

    from typer.testing import CliRunner

    from apkscan.cli import app

    rec = no_network({})
    src = _report_with_plan(tmp_path)
    payload = _json.loads(src.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "a" * 64
    src.write_text(_json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    other = tmp_path / "other_sample.json"
    other.write_text(_json.dumps(
        {"meta": {"sample_sha256": "b" * 64}, "endpoints": [], "leads": []},
        ensure_ascii=False), encoding="utf-8")

    res = CliRunner().invoke(app, ["config-probe", str(src),
                                   "--authorized-active", "--into", str(other)])
    assert res.exit_code == 2, res.output
    assert rec.calls == [], "拦下之前已经把请求发出去了"


def test_cli_reports_a_missing_plan_instead_of_pretending(tmp_path: Path) -> None:
    """没有预案就说没有——不能静默成功让人以为探过了。"""
    from typer.testing import CliRunner

    from apkscan.cli import app

    path = tmp_path / "report.json"
    path.write_text(json.dumps({"meta": {}}), encoding="utf-8")
    res = CliRunner().invoke(app, ["config-probe", str(path)])
    assert res.exit_code == 1
