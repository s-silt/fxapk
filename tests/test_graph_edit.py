"""阶段1（图谱层：只入强档 + 删除 + prune）单元测试。

零真 kuzu、零联网：
- ingest 只链强档：mock GraphStore 记录 link 调用。
- delete_entity / unlink：注入假连接捕获每条 query + params，断言参数化 Cypher。
- prune_weak：只删非强档、返回清理数。
- kuzu 缺失 / 查询异常：delete_entity/unlink/prune_weak 一律返 0、绝不抛。

注意：本文件不 importorskip kuzu —— 全程 mock，不触发真 import kuzu。
"""

from __future__ import annotations

from typing import Any

from apkscan.graph.ingest import ingest_report
from apkscan.graph.query import prune_weak
from apkscan.graph.store import GraphStore


# ---- 假连接：捕获 conn.execute(query, params) 并按预设返回结果 -----------------
class _FakeResult:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def rows_as_dict(self) -> "_FakeResult":
        return self

    def get_all(self) -> list[dict]:
        return list(self._rows)


class _FakeConn:
    """记录每次 execute 的 (query, params)，按调用顺序回放预设结果。"""

    def __init__(self, results: list[list[dict]] | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._results = list(results or [])

    def execute(self, query: str, params: dict | None = None) -> _FakeResult:
        self.calls.append((query, params or {}))
        rows = self._results.pop(0) if self._results else []
        return _FakeResult(rows)


def _store_with_conn(conn: _FakeConn) -> GraphStore:
    """造一个已注入假连接的 GraphStore：_ensure_open 直接返回它，永不 import kuzu。"""
    store = GraphStore("ignored.kuzu")
    store._conn = conn  # type: ignore[attr-defined]  # 测试桩：跳过真 kuzu 打开
    return store


# ---- ingest：只链强档，中档被丢 ----------------------------------------------
class _RecordingStore:
    """记录 upsert_entity / link 调用的 GraphStore 替身（ingest 单元测试用）。"""

    def __init__(self) -> None:
        self.apks: list[str] = []
        self.entities: list[tuple[str, str]] = []
        self.links: list[tuple[str, str, str]] = []

    def upsert_apk(self, sha256: str, **_kw: Any) -> None:
        self.apks.append(sha256)

    def upsert_entity(self, kind: str, value: str) -> str:
        self.entities.append((kind, value))
        return f"{kind}:{value}"

    def link(self, apk_sha256: str, entity_kind: str, entity_value: str, weight: float = 1.0) -> None:
        self.links.append((apk_sha256, entity_kind, entity_value))


def _report_strong_and_medium(sha: str) -> dict:
    """构造含强档(sign/c2/telegram_bot)与中档(uni_appid/firebase_project)的 report。"""
    return {
        "meta": {
            "sample_sha256": sha,
            "sign_subject": "CN=Evil",
            "sign_sha256": "CERT",  # 强
            "uni_appid": "UNI",  # 中
            "firebase_project_id": "FB",  # 中
            "telegram_bot_tokens": ["123:tok"],  # 强
        },
        "leads": [{"category": "DOMAIN", "value": "c2.example.com", "is_c2": True}],
    }


def test_ingest_links_only_strong() -> None:
    store = _RecordingStore()
    ok = ingest_report(_report_strong_and_medium("shaX"), store, sha256="shaX")  # type: ignore[arg-type]
    assert ok is True
    linked_kinds = {kind for _sha, kind, _v in store.links}
    # 强档全入。
    assert linked_kinds == {"sign", "c2", "telegram_bot"}
    # 中档被丢：既不 upsert_entity 也不 link。
    assert "uni_appid" not in linked_kinds
    assert "firebase_project" not in linked_kinds
    entity_kinds = {k for k, _v in store.entities}
    assert "uni_appid" not in entity_kinds
    assert "firebase_project" not in entity_kinds


# ---- delete_entity：参数化 Cypher（先删边、计数、再删节点） --------------------
def test_delete_entity_parametrized_cypher() -> None:
    # 第 2 条 query（COUNT 节点）回放 1 行，使返回 1。
    conn = _FakeConn(results=[[], [{"c": 1}], []])
    store = _store_with_conn(conn)
    n = store.delete_entity("sign", "CERT")
    assert n == 1
    # 三条 query：删边 / 计数 / 删节点；全部用 $id 参数化、id 不内插进 query 文本。
    assert len(conn.calls) == 3
    q_del_edge, p1 = conn.calls[0]
    q_count, p2 = conn.calls[1]
    q_del_node, p3 = conn.calls[2]
    assert "DELETE r" in q_del_edge and "$id" in q_del_edge
    assert "COUNT(e)" in q_count and "$id" in q_count
    assert "DELETE e" in q_del_node and "$id" in q_del_node
    # value 走 params，不拼进 query 文本（防注入）。
    assert p1 == p2 == p3 == {"id": "sign:CERT"}
    assert "CERT" not in q_del_edge


def test_delete_entity_missing_returns_zero() -> None:
    # COUNT 返回 0（实体不存在）→ 返 0，仍执行三条不抛。
    conn = _FakeConn(results=[[], [{"c": 0}], []])
    store = _store_with_conn(conn)
    assert store.delete_entity("c2", "nope.example.com") == 0


# ---- unlink：参数化 Cypher（计数边、删边） -----------------------------------
def test_unlink_parametrized_cypher() -> None:
    conn = _FakeConn(results=[[{"c": 1}], []])
    store = _store_with_conn(conn)
    n = store.unlink("shaA", "sign", "CERT")
    assert n == 1
    assert len(conn.calls) == 2
    q_count, p1 = conn.calls[0]
    q_del, p2 = conn.calls[1]
    assert "COUNT(r)" in q_count and "$sha" in q_count and "$id" in q_count
    assert "DELETE r" in q_del and "$sha" in q_del and "$id" in q_del
    assert p1 == p2 == {"sha": "shaA", "id": "sign:CERT"}
    # 不内插值进 query 文本。
    assert "shaA" not in q_del and "CERT" not in q_del


def test_unlink_no_edge_returns_zero() -> None:
    conn = _FakeConn(results=[[{"c": 0}], []])
    store = _store_with_conn(conn)
    assert store.unlink("shaA", "sign", "CERT") == 0


# ---- never-throw：kuzu 缺失 / 查询异常 → 返 0 不抛 ---------------------------
class _RaisingConn:
    def execute(self, query: str, params: dict | None = None) -> Any:
        raise RuntimeError("boom (simulate kuzu/query failure)")


def test_delete_entity_never_throws_returns_zero() -> None:
    store = _store_with_conn(_RaisingConn())  # type: ignore[arg-type]
    assert store.delete_entity("sign", "CERT") == 0


def test_unlink_never_throws_returns_zero() -> None:
    store = _store_with_conn(_RaisingConn())  # type: ignore[arg-type]
    assert store.unlink("shaA", "sign", "CERT") == 0


def test_delete_entity_kuzu_missing_returns_zero(monkeypatch) -> None:
    # 不注入连接 → _ensure_open 真去 import kuzu；让其抛 ImportError，验证被吞成 0。
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kw: Any) -> Any:
        if name == "kuzu":
            raise ImportError("no kuzu")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    store = GraphStore("ignored.kuzu")
    assert store.delete_entity("sign", "CERT") == 0
    assert store.unlink("shaA", "sign", "CERT") == 0


# ---- prune_weak：只删非强档，返回清理数 -------------------------------------
class _PruneStore:
    """枚举返回固定实体集；记录被 delete_entity 的 (kind,value)，每删返回 1。"""

    def __init__(self, entities: list[dict]) -> None:
        self._entities = entities
        self.deleted: list[tuple[str, str]] = []

    def query_rows(self, query: str, params: dict | None = None) -> list[dict]:
        return list(self._entities)

    def delete_entity(self, kind: str, value: str) -> int:
        self.deleted.append((kind, value))
        return 1


def test_prune_weak_deletes_only_weak() -> None:
    store = _PruneStore(
        [
            {"kind": "sign", "value": "CERT"},  # 强 → 留
            {"kind": "uni_appid", "value": "UNI"},  # 中 → 删
            {"kind": "firebase_project", "value": "FB"},  # 中 → 删
            {"kind": "c2", "value": "c2.example.com"},  # 强 → 留
            {"kind": "unknown_kind", "value": "X"},  # 未注册=非强 → 删
        ]
    )
    n = prune_weak(store)  # type: ignore[arg-type]
    assert n == 3
    assert set(store.deleted) == {
        ("uni_appid", "UNI"),
        ("firebase_project", "FB"),
        ("unknown_kind", "X"),
    }
    # 强档绝不被删。
    assert ("sign", "CERT") not in store.deleted
    assert ("c2", "c2.example.com") not in store.deleted


class _RaisingPruneStore:
    def query_rows(self, query: str, params: dict | None = None) -> list[dict]:
        raise RuntimeError("boom")

    def delete_entity(self, kind: str, value: str) -> int:  # pragma: no cover - 不应被调
        raise AssertionError("不应到这")


def test_prune_weak_never_throws_returns_zero() -> None:
    assert prune_weak(_RaisingPruneStore()) == 0  # type: ignore[arg-type]


class _PartialFailPruneStore:
    """枚举返回固定集；指定 value 的 delete_entity 返 0（模拟删失败），其余返 1。"""

    def __init__(self, entities: list[dict], fail_value: str) -> None:
        self._entities = entities
        self._fail = fail_value
        self.attempted: list[tuple[str, str]] = []

    def query_rows(self, query: str, params: dict | None = None) -> list[dict]:
        return list(self._entities)

    def delete_entity(self, kind: str, value: str) -> int:
        self.attempted.append((kind, value))
        return 0 if value == self._fail else 1


def test_prune_weak_continues_past_failed_delete() -> None:
    """中途某个 delete_entity 失败(返0)不中断循环：仍遍历完所有 weak、只计成功数。"""
    store = _PartialFailPruneStore(
        [
            {"kind": "uni_appid", "value": "A"},          # 弱 → 删成功(1)
            {"kind": "firebase_project", "value": "B"},   # 弱 → 删失败(0)
            {"kind": "unknown_kind", "value": "C"},       # 弱 → 删成功(1)
            {"kind": "sign", "value": "CERT"},            # 强 → 跳过、不尝试
        ],
        fail_value="B",
    )
    n = prune_weak(store)  # type: ignore[arg-type]
    assert n == 2  # 3 个 weak、1 个失败 → 返 2
    assert store.attempted == [
        ("uni_appid", "A"),
        ("firebase_project", "B"),
        ("unknown_kind", "C"),
    ]  # 失败后仍继续遍历，强档未被尝试删除
