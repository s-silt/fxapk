"""阶段3 CLI 图谱删除命令测试：graph rm-entity / unlink / prune-weak。

零真 kuzu、零联网：
- mock GraphStore（_graph_session 内构造）捕获 delete_entity/unlink 调用、ensure_ready 探活。
- mock prune_weak 验证 prune-weak 命令打印清理数。
- kuzu 缺失（ensure_ready 抛 ImportError）→ 统一安装提示 + exit 1。
"""

from __future__ import annotations

from typing import Any

from typer.testing import CliRunner

from apkscan import cli

runner = CliRunner()


class _FakeStore:
    """记录调用的 GraphStore 替身；ensure_ready 按 kuzu_missing 决定是否抛 ImportError。"""

    def __init__(self, *, kuzu_missing: bool = False) -> None:
        self.kuzu_missing = kuzu_missing
        self.ready = False
        self.deleted: list[tuple[str, str]] = []
        self.unlinked: list[tuple[str, str, str]] = []
        self.closed = False
        self.db_path = "fake.kuzu"

    def ensure_ready(self) -> None:
        if self.kuzu_missing:
            raise ImportError("no kuzu")
        self.ready = True

    def delete_entity(self, kind: str, value: str) -> int:
        self.deleted.append((kind, value))
        return 1

    def unlink(self, sha256: str, kind: str, value: str) -> int:
        self.unlinked.append((sha256, kind, value))
        return 2

    def close(self) -> None:
        self.closed = True


def _patch_store(monkeypatch: Any, store: _FakeStore) -> None:
    """让 _graph_session 内 `from apkscan.graph import GraphStore` 拿到替身。"""
    import apkscan.graph as graph_mod

    monkeypatch.setattr(graph_mod, "GraphStore", lambda *a, **k: store)


# ---------------------------------------------------------------------------
# rm-entity
# ---------------------------------------------------------------------------


def test_rm_entity(monkeypatch: Any) -> None:
    store = _FakeStore()
    _patch_store(monkeypatch, store)
    res = runner.invoke(cli.app, ["graph", "rm-entity", "c2", "evil.com"])
    assert res.exit_code == 0, res.output
    assert store.deleted == [("c2", "evil.com")]
    assert '"deleted": 1' in res.output
    assert store.ready is True
    assert store.closed is True


def test_rm_entity_kuzu_missing(monkeypatch: Any) -> None:
    store = _FakeStore(kuzu_missing=True)
    _patch_store(monkeypatch, store)
    res = runner.invoke(cli.app, ["graph", "rm-entity", "c2", "evil.com"])
    assert res.exit_code == 1
    assert "pip install kuzu" in res.output
    assert store.deleted == []  # 探活失败，没走到删除


# ---------------------------------------------------------------------------
# unlink
# ---------------------------------------------------------------------------


def test_unlink(monkeypatch: Any) -> None:
    store = _FakeStore()
    _patch_store(monkeypatch, store)
    res = runner.invoke(cli.app, ["graph", "unlink", "a" * 64, "sign", "CERT"])
    assert res.exit_code == 0, res.output
    assert store.unlinked == [("a" * 64, "sign", "CERT")]
    assert '"removed": 2' in res.output


def test_unlink_kuzu_missing(monkeypatch: Any) -> None:
    store = _FakeStore(kuzu_missing=True)
    _patch_store(monkeypatch, store)
    res = runner.invoke(cli.app, ["graph", "unlink", "a" * 64, "sign", "CERT"])
    assert res.exit_code == 1
    assert "pip install kuzu" in res.output
    assert store.unlinked == []


# ---------------------------------------------------------------------------
# prune-weak
# ---------------------------------------------------------------------------


def test_prune_weak(monkeypatch: Any) -> None:
    store = _FakeStore()
    _patch_store(monkeypatch, store)
    import apkscan.graph as graph_mod

    monkeypatch.setattr(graph_mod, "prune_weak", lambda s: 7)
    res = runner.invoke(cli.app, ["graph", "prune-weak"])
    assert res.exit_code == 0, res.output
    assert '"pruned": 7' in res.output
    assert store.ready is True


def test_prune_weak_kuzu_missing(monkeypatch: Any) -> None:
    store = _FakeStore(kuzu_missing=True)
    _patch_store(monkeypatch, store)
    import apkscan.graph as graph_mod

    def _should_not_run(_s: Any) -> int:  # pragma: no cover - 不应被调
        raise AssertionError("ensure_ready 应先抛 ImportError")

    monkeypatch.setattr(graph_mod, "prune_weak", _should_not_run)
    res = runner.invoke(cli.app, ["graph", "prune-weak"])
    assert res.exit_code == 1
    assert "pip install kuzu" in res.output
