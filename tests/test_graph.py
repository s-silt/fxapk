"""本地 Kuzu 案件图谱串案地基（apkscan.graph）测试。

T1 schema 幂等 / T2 摄入去重 / T3 指纹→实体映射 / T4 link·query·cluster /
T5 置信排名 / T6 坏报告不抛 / T7 kuzu 缺失优雅降级。

每测用 tmp_path 建独立 DB，用完即关（Windows 句柄）。合成 report 按 correlate.py 的
meta/leads 结构构造，零真机、零联网。
"""

from __future__ import annotations

import sys

import pytest

pytest.importorskip("kuzu")  # 未装 kuzu 时整体跳过（CI 装 .[graph]）

from typer.testing import CliRunner  # noqa: E402

from apkscan.graph import (  # noqa: E402
    GraphStore,
    ingest_report,
    query_by_kind,
    query_clusters,
    query_link,
    query_stats,
)


def _report(
    sha: str,
    *,
    sign: str | None = None,
    subject: str = "CN=Evil Corp",
    uni: str | None = None,
    addrs: list[str] | None = None,
    c2: list[str] | None = None,
    fb: str | None = None,
    tg: list[str] | None = None,
    package: str = "com.evil.app",
) -> dict:
    """构造一份 report.json 形态的 dict（meta + leads），含 sample_sha256。"""
    leads = [
        {"category": "DOMAIN", "value": v, "is_c2": True, "is_runtime_seen": False}
        for v in (c2 or [])
    ]
    meta: dict = {"sign_subject": subject, "sample_sha256": sha, "package_name": package}
    if sign is not None:
        meta["sign_sha256"] = sign
    if uni is not None:
        meta["uni_appid"] = uni
    if addrs is not None:
        meta["crypto_addresses"] = addrs
    if fb is not None:
        meta["firebase_project_id"] = fb
    if tg is not None:
        meta["telegram_bot_tokens"] = tg
    return {"meta": meta, "leads": leads}


def _db(tmp_path) -> str:
    return str(tmp_path / "cases.kuzu")


def test_schema_ddl_idempotency(tmp_path) -> None:
    """同路径二次打开（DDL 跑两遍）不抛，且数据持久。"""
    db = _db(tmp_path)
    with GraphStore(db) as s1:
        s1.upsert_apk("sha_a", package="p")
    # 重开同库 → ensure_schema 再跑一遍，必须不抛
    with GraphStore(db) as s2:
        rows = s2.query_rows("MATCH (a:Apk) RETURN COUNT(a) AS c")
    assert rows[0]["c"] == 1


def test_ingest_upsert_dedup(tmp_path) -> None:
    """同 sha256 重摄：apk/entity/edge 计数不变，first_seen 不变、last_seen 推进。"""
    with GraphStore(_db(tmp_path)) as store:
        rep = _report("sha_x", sign="CERT", c2=["evil.example.com"])
        ingest_report(rep, store, sha256="sha_x")
        st1 = query_stats(store)
        e1 = store.query_rows(
            "MATCH (e:Entity {id:$i}) RETURN e.first_seen AS f, e.last_seen AS l", {"i": "sign:CERT"}
        )[0]

        ingest_report(rep, store, sha256="sha_x")  # 重摄一次
        st2 = query_stats(store)
        e2 = store.query_rows(
            "MATCH (e:Entity {id:$i}) RETURN e.first_seen AS f, e.last_seen AS l", {"i": "sign:CERT"}
        )[0]

        assert st1["apk_count"] == st2["apk_count"] == 1
        assert st1["entity_count"] == st2["entity_count"] == 2  # sign + c2
        assert st1["edge_count"] == st2["edge_count"] == 2
        assert e2["f"] == e1["f"]  # first_seen 仅创建时写
        assert e2["l"] >= e1["l"]  # last_seen 每次推进


def test_extract_fingerprints_to_entity_mapping(tmp_path) -> None:
    """6 种 kind 全覆盖：每个 Fingerprint 映射到一个对应 kind/value 的 Entity。"""
    with GraphStore(_db(tmp_path)) as store:
        rep = _report(
            "sha_all",
            sign="S",
            uni="U",
            addrs=["TXxxxAddr"],
            c2=["c2.example.com"],
            fb="proj-1",
            tg=["123:tok"],
        )
        ingest_report(rep, store, sha256="sha_all")
        rows = store.query_rows("MATCH (e:Entity) RETURN e.kind AS kind, e.value AS value")
        got = {(r["kind"], r["value"]) for r in rows}
    assert got == {
        ("sign", "S"),
        ("uni_appid", "U"),
        ("crypto_addr", "TXxxxAddr"),
        ("c2", "c2.example.com"),
        ("firebase_project", "proj-1"),
        ("telegram_bot", "123:tok"),
    }


def test_link_query_cluster_synthetic_3apk(tmp_path) -> None:
    """A、B 共享 sign=SHARED 成簇；C 用 UNIQUE 孤立。link/query/cluster 三视角一致。"""
    with GraphStore(_db(tmp_path)) as store:
        ingest_report(_report("sha_a", sign="SHARED"), store)  # 走 meta.sample_sha256 路径
        ingest_report(_report("sha_b", sign="SHARED"), store)
        ingest_report(_report("sha_c", sign="UNIQUE"), store)

        link = query_link(store, "sha_a")
        assert {r["sha256"] for r in link["related"]} == {"sha_b"}
        assert link["related"][0]["strong_shared_count"] == 1

        q = query_by_kind(store, "sign", "SHARED")
        assert {a["sha256"] for a in q["apks"]} == {"sha_a", "sha_b"}
        assert q["count"] == 2

        cl = query_clusters(store)
        assert cl["cluster_count"] == 1
        assert set(cl["clusters"][0]["members"]) == {"sha_a", "sha_b"}
        shared = {(s["kind"], s["value"]) for s in cl["clusters"][0]["shared"]}
        assert ("sign", "SHARED") in shared


def test_confidence_ranking_strong_vs_medium(tmp_path) -> None:
    """共享强指纹(sign)的簇置信 > 仅共享中指纹(uni_appid+firebase)的簇（只断相对序）。"""
    with GraphStore(_db(tmp_path)) as store:
        ingest_report(_report("a1", sign="CERT1"), store)
        ingest_report(_report("a2", sign="CERT1"), store)
        ingest_report(_report("b1", uni="UNI1", fb="FB1"), store)
        ingest_report(_report("b2", uni="UNI1", fb="FB1"), store)

        cl = query_clusters(store)
        by_members = {tuple(sorted(c["members"])): c for c in cl["clusters"]}
        c_strong = by_members[("a1", "a2")]
        c_medium = by_members[("b1", "b2")]
        assert c_strong["confidence"] > c_medium["confidence"]
        assert c_strong["rationale"]["strong_kind_count"] == 1


def test_bad_corrupt_report_never_throws(tmp_path) -> None:
    """坏/残缺 report 摄入不抛（log+跳过），好 report 仍入图。"""
    with GraphStore(_db(tmp_path)) as store:
        bad_inputs = [
            None,
            12345,
            {"meta": None},
            {"meta": {}},  # 缺 sha256
            {"meta": {"sample_sha256": ""}},  # 空 sha256
            {"leads": {"x": 1}, "meta": {"sample_sha256": "sX"}},  # leads 非 list
        ]
        for bad in bad_inputs:
            res = ingest_report(bad, store)  # 关键：不抛
            assert res in (True, False)

        assert ingest_report(_report("good", sign="G"), store, sha256="good") is True
        st = query_stats(store)
        assert st["apk_count"] >= 1  # 好报告确实入图


def test_kuzu_not_installed_graceful(monkeypatch) -> None:
    """kuzu 缺失：graph 命令提示安装 + exit 1；非 graph 命令不受影响。"""
    monkeypatch.setitem(sys.modules, "kuzu", None)  # 让 `import kuzu` 抛 ImportError
    from apkscan import cli

    runner = CliRunner()
    res = runner.invoke(cli.app, ["graph", "stats"])
    assert res.exit_code == 1
    assert "pip install kuzu" in res.output

    res2 = runner.invoke(cli.app, ["--version"])
    assert res2.exit_code == 0
