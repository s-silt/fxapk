"""阶段2 网页 + CLI track 命令测试（flask test_client，不开真浏览器/不联网）。

覆盖（spec §8）：
- GET / 渲染单页（200）。
- GET /api/tracking 返全量台账。
- POST /api/apk · /api/lead · /api/history 单条更新落台账。
- 令牌鉴权：非 loopback 自动启用、错 token 401、对 token 放行、--no-auth 放行、loopback 不强制。
- 坏入参 4xx。
- track 命令在 flask 缺失时优雅退出（mock import 失败）。
"""

from __future__ import annotations

import builtins
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan.track import web
from apkscan.track.ledger import TrackingLedger

# flask 是可选 extra（pip install -e .[track]）；未装则整模块跳过（CI 装了 track extra 会真跑）。
pytest.importorskip("flask")

runner = CliRunner()


# ---------------------------------------------------------------------------
# 夹具：一个有内容的台账（一个 APK + 一条线索）
# ---------------------------------------------------------------------------


def _seed_ledger(tmp_path: Path) -> tuple[TrackingLedger, str, str]:
    """造一个含 1 APK + 1 线索的台账，返回 (ledger, sha256, lead_key)。"""
    led = TrackingLedger(tmp_path / "tracking.json")
    sha = "a" * 64
    lead_key = "DOMAIN:bad.example.com"
    led._data = {  # 直接构造（避免依赖 Report 对象）
        "version": 1,
        "apks": {
            sha: {
                "package": "com.evil.app",
                "label": "杀猪盘",
                "report_path": "out/r.json",
                "apk_status": "待处理",
                "apk_notes": "",
                "first_seen": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "leads": {
                    lead_key: {
                        "category": "DOMAIN",
                        "value": "bad.example.com",
                        "subject": "主控域名",
                        "status": "待办",
                        "notes": "",
                        "history": [],
                        "first_seen": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                    }
                },
            }
        },
    }
    led._save()
    return led, sha, lead_key


# ---------------------------------------------------------------------------
# loopback 判定
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("192.168.1.10", False),
        ("example.lan", False),  # 主机名从严当非 loopback
        ("", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert web._is_loopback(host) is expected


# ---------------------------------------------------------------------------
# 路由（无鉴权，loopback 自用语义）
# ---------------------------------------------------------------------------


def test_index_renders(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    client = app.test_client()
    res = client.get("/")
    assert res.status_code == 200
    assert b"track" in res.data.lower() or "线索追踪".encode() in res.data


def test_api_tracking(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().get("/api/tracking")
    assert res.status_code == 200
    data = res.get_json()
    assert sha in data["apks"]
    assert data["apks"][sha]["package"] == "com.evil.app"


def test_post_apk_updates_ledger(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", json={"sha256": sha, "status": "调查中"})
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
    # 落盘验证：重新读
    fresh = TrackingLedger(tmp_path / "tracking.json")
    assert fresh.all()["apks"][sha]["apk_status"] == "调查中"


def test_post_lead_updates_ledger(tmp_path: Path) -> None:
    led, sha, lead_key = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/lead", json={"sha256": sha, "lead_key": lead_key, "status": "已出函", "notes": "出函XX"}
    )
    assert res.status_code == 200
    fresh = TrackingLedger(tmp_path / "tracking.json")
    lead = fresh.all()["apks"][sha]["leads"][lead_key]
    assert lead["status"] == "已出函"
    assert lead["notes"] == "出函XX"


def test_post_history_appends(tmp_path: Path) -> None:
    led, sha, lead_key = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/history", json={"sha256": sha, "lead_key": lead_key, "text": "已收注册商数据"}
    )
    assert res.status_code == 200
    fresh = TrackingLedger(tmp_path / "tracking.json")
    hist = fresh.all()["apks"][sha]["leads"][lead_key]["history"]
    assert len(hist) == 1
    assert hist[0]["text"] == "已收注册商数据"
    assert "at" in hist[0]


# ---------------------------------------------------------------------------
# 坏入参 4xx
# ---------------------------------------------------------------------------


def test_post_apk_missing_sha_400(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", json={"status": "调查中"})
    assert res.status_code == 400
    assert res.get_json()["ok"] is False


def test_post_apk_no_fields_400(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", json={"sha256": sha})
    assert res.status_code == 400


def test_post_apk_not_found_404(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", json={"sha256": "b" * 64, "status": "x"})
    assert res.status_code == 404


def test_post_lead_not_found_404(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/lead", json={"sha256": sha, "lead_key": "NOPE:x", "status": "y"}
    )
    assert res.status_code == 404


def test_post_history_missing_text_400(tmp_path: Path) -> None:
    led, sha, lead_key = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/history", json={"sha256": sha, "lead_key": lead_key, "text": "  "}
    )
    assert res.status_code == 400


def test_post_non_json_body_400(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", data="not json", content_type="text/plain")
    assert res.status_code == 400


def test_post_apk_non_string_status_400(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/apk", json={"sha256": sha, "status": 123})
    assert res.status_code == 400


# ---------------------------------------------------------------------------
# 令牌鉴权
# ---------------------------------------------------------------------------


def test_no_token_no_auth(tmp_path: Path) -> None:
    """token=None：不带 token 也放行（loopback / --no-auth 语义）。"""
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    assert app.test_client().get("/api/tracking").status_code == 200


def test_token_missing_401(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    res = app.test_client().get("/api/tracking")
    assert res.status_code == 401
    assert res.get_json()["ok"] is False


def test_token_wrong_401(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    res = app.test_client().get("/api/tracking?token=wrong")
    assert res.status_code == 401


def test_token_query_ok(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    res = app.test_client().get("/api/tracking?token=secret-tok")
    assert res.status_code == 200


def test_token_header_ok(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    res = app.test_client().get("/api/tracking", headers={"X-Track-Token": "secret-tok"})
    assert res.status_code == 200


def test_token_protects_post(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    res = app.test_client().post("/api/apk", json={"sha256": sha, "status": "x"})
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# 阶段3：手动加线索 /api/lead/add
# ---------------------------------------------------------------------------


def test_lead_add_creates_manual_lead(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/lead/add",
        json={"sha256": sha, "category": "IP", "value": "1.2.3.4", "subject": "C2", "notes": "n"},
    )
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
    fresh = TrackingLedger(tmp_path / "tracking.json")
    lead = fresh.all()["apks"][sha]["leads"]["IP:1.2.3.4"]
    assert lead["manual"] is True
    assert lead["subject"] == "C2"
    assert lead["notes"] == "n"


def test_lead_add_creates_apk_shell(tmp_path: Path) -> None:
    """APK 不在台账 → add_lead 建壳。"""
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    new_sha = "c" * 64
    res = app.test_client().post(
        "/api/lead/add", json={"sha256": new_sha, "category": "DOMAIN", "value": "x.com"}
    )
    assert res.status_code == 200
    fresh = TrackingLedger(tmp_path / "tracking.json")
    assert "DOMAIN:x.com" in fresh.all()["apks"][new_sha]["leads"]


def test_lead_add_duplicate_400(tmp_path: Path) -> None:
    """已存在的 lead_key → add_lead 返 False → 400。"""
    led, sha, lead_key = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    # seed 里 lead_key = DOMAIN:bad.example.com
    res = app.test_client().post(
        "/api/lead/add", json={"sha256": sha, "category": "DOMAIN", "value": "bad.example.com"}
    )
    assert res.status_code == 400
    assert res.get_json()["ok"] is False


def test_lead_add_missing_value_400(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/lead/add", json={"sha256": sha, "category": "IP"})
    assert res.status_code == 400


# ---------------------------------------------------------------------------
# 阶段3：图谱路由（mock query_link/GraphStore；不碰真 kuzu）
# ---------------------------------------------------------------------------


class _FakeStore:
    """记录图谱写调用、按预设回放读结果的 GraphStore 替身。"""

    def __init__(self) -> None:
        self.upserts: list[tuple[str, str]] = []
        self.links: list[tuple[str, str, str]] = []
        self.deleted: list[tuple[str, str]] = []
        self.unlinked: list[tuple[str, str, str]] = []

    def ensure_ready(self) -> None:
        pass

    def upsert_entity(self, kind: str, value: str) -> str:
        self.upserts.append((kind, value))
        return f"{kind}:{value}"

    def link(self, sha256: str, kind: str, value: str, weight: float = 1.0) -> None:
        self.links.append((sha256, kind, value))

    def delete_entity(self, kind: str, value: str) -> int:
        self.deleted.append((kind, value))
        return 1

    def unlink(self, sha256: str, kind: str, value: str) -> int:
        self.unlinked.append((sha256, kind, value))
        return 1

    def close(self) -> None:
        pass


def _patch_graph(monkeypatch: pytest.MonkeyPatch, store: Any, link_result: Any = None) -> None:
    """让 web._with_graph 用 _FakeStore，query_link 返预设。"""
    import apkscan.graph as graph_mod

    monkeypatch.setattr(graph_mod, "GraphStore", lambda *a, **k: store)
    monkeypatch.setattr(graph_mod, "query_link", lambda s, sha: link_result or {"related": []})
    monkeypatch.setattr(graph_mod, "get_weight", lambda kind: 9.0)


def test_graph_get_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    store = _FakeStore()
    _patch_graph(monkeypatch, store, link_result={"apk": {"sha256": sha}, "related": []})
    app = web.create_app(led, token=None)
    res = app.test_client().get(f"/api/graph?sha256={sha}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["graph"]["related"] == []


def test_graph_get_missing_sha_400(tmp_path: Path) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    assert app.test_client().get("/api/graph").status_code == 400


def test_graph_get_bad_sha256_400(tmp_path: Path) -> None:
    """畸形 sha256（非 64 位 hex）→ 400（spec §5：写/读路由 sha256 须 hex 校验）。"""
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    assert app.test_client().get("/api/graph?sha256=zz").status_code == 400


def test_lead_add_bad_sha256_400(tmp_path: Path) -> None:
    """/api/lead/add 喂畸形 sha256 → 400，不进台账建脏壳。"""
    led, _, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/lead/add", json={"sha256": "nothex", "category": "DOMAIN", "value": "x.com"}
    )
    assert res.status_code == 400


def test_graph_entity_upsert_and_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    store = _FakeStore()
    _patch_graph(monkeypatch, store)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/graph/entity", json={"sha256": sha, "kind": "c2", "value": "evil.com"}
    )
    assert res.status_code == 200
    assert res.get_json()["ok"] is True
    assert store.upserts == [("c2", "evil.com")]
    assert store.links == [(sha, "c2", "evil.com")]


def test_graph_delete_entity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led, _, _ = _seed_ledger(tmp_path)
    store = _FakeStore()
    _patch_graph(monkeypatch, store)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/graph/delete_entity", json={"kind": "c2", "value": "evil.com"}
    )
    assert res.status_code == 200
    assert res.get_json()["deleted"] == 1
    assert store.deleted == [("c2", "evil.com")]


def test_graph_unlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    store = _FakeStore()
    _patch_graph(monkeypatch, store)
    app = web.create_app(led, token=None)
    res = app.test_client().post(
        "/api/graph/unlink", json={"sha256": sha, "kind": "c2", "value": "evil.com"}
    )
    assert res.status_code == 200
    assert res.get_json()["removed"] == 1
    assert store.unlinked == [(sha, "c2", "evil.com")]


def test_graph_entity_bad_input_400(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token=None)
    res = app.test_client().post("/api/graph/entity", json={"sha256": sha, "kind": "c2"})
    assert res.status_code == 400


def test_graph_route_kuzu_missing_degrades(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """kuzu 缺失：GraphStore 打开即抛 ImportError → 路由返 ok=false（200，不 500）。"""
    led, sha, _ = _seed_ledger(tmp_path)

    class _ImportRaisingStore:
        """模拟 kuzu 缺失：ensure_ready 探活即抛 ImportError（真实：_ensure_open import kuzu 失败）。
        关键——delete_entity/unlink 照真实语义吞 ImportError 返 0（不抛），证明四路降级靠
        ensure_ready 探活、而非靠 delete/unlink 自己抛错（防 false-green 回归）。"""

        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def ensure_ready(self) -> None:
            raise ImportError("no kuzu")

        def upsert_entity(self, *a: Any, **k: Any) -> str:
            raise ImportError("no kuzu")

        def link(self, *a: Any, **k: Any) -> None:
            raise ImportError("no kuzu")

        def delete_entity(self, *a: Any, **k: Any) -> int:
            return 0  # 真实 store 吞 ImportError 返 0；降级须由 ensure_ready 触发

        def unlink(self, *a: Any, **k: Any) -> int:
            return 0  # 同上

        def close(self) -> None:
            pass

    import apkscan.graph as graph_mod

    monkeypatch.setattr(graph_mod, "GraphStore", _ImportRaisingStore)

    def _raise_link(_s: Any, _sha: str) -> Any:
        raise ImportError("no kuzu")

    monkeypatch.setattr(graph_mod, "query_link", _raise_link)
    monkeypatch.setattr(graph_mod, "get_weight", lambda kind: 9.0)

    app = web.create_app(led, token=None)
    client = app.test_client()

    r1 = client.get(f"/api/graph?sha256={sha}")
    assert r1.status_code == 200 and r1.get_json()["ok"] is False
    r2 = client.post("/api/graph/entity", json={"sha256": sha, "kind": "c2", "value": "x"})
    assert r2.status_code == 200 and r2.get_json()["ok"] is False
    r3 = client.post("/api/graph/delete_entity", json={"kind": "c2", "value": "x"})
    assert r3.status_code == 200 and r3.get_json()["ok"] is False
    r4 = client.post("/api/graph/unlink", json={"sha256": sha, "kind": "c2", "value": "x"})
    assert r4.status_code == 200 and r4.get_json()["ok"] is False


def test_graph_route_token_protected(tmp_path: Path) -> None:
    led, sha, _ = _seed_ledger(tmp_path)
    app = web.create_app(led, token="secret-tok")
    assert app.test_client().get(f"/api/graph?sha256={sha}").status_code == 401
    assert (
        app.test_client()
        .post("/api/graph/delete_entity", json={"kind": "c2", "value": "x"})
        .status_code
        == 401
    )


# ---------------------------------------------------------------------------
# serve：鉴权策略（非 loopback 自动生成 token；loopback / --no-auth 不强制）
# ---------------------------------------------------------------------------


def test_serve_non_loopback_auto_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """绑定 0.0.0.0 → 自动启用令牌（create_app 收到非空 token）。"""
    led, _, _ = _seed_ledger(tmp_path)
    captured: dict[str, Any] = {}

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None, graph_db: str = ""):  # type: ignore[no-untyped-def]
        captured["token"] = token

        class _App:
            def run(self, **kwargs: Any) -> None:
                captured["run"] = kwargs

        return _App()

    monkeypatch.setattr(web, "create_app", _fake_create_app)
    web.serve(host="0.0.0.0", port=9999, ledger=led)
    assert captured["token"]  # 非空令牌
    assert captured["run"]["host"] == "0.0.0.0"
    assert captured["run"]["threaded"] is True


def test_serve_loopback_no_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """绑定 127.0.0.1 → 不强制令牌（token=None）。"""
    led, _, _ = _seed_ledger(tmp_path)
    captured: dict[str, Any] = {}

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None, graph_db: str = ""):  # type: ignore[no-untyped-def]
        captured["token"] = token

        class _App:
            def run(self, **kwargs: Any) -> None:
                pass

        return _App()

    monkeypatch.setattr(web, "create_app", _fake_create_app)
    web.serve(host="127.0.0.1", port=9999, ledger=led)
    assert captured["token"] is None


def test_serve_no_auth_disables_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--no-auth 即使绑非 loopback 也不生成令牌。"""
    led, _, _ = _seed_ledger(tmp_path)
    captured: dict[str, Any] = {}

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None, graph_db: str = ""):  # type: ignore[no-untyped-def]
        captured["token"] = token

        class _App:
            def run(self, **kwargs: Any) -> None:
                pass

        return _App()

    monkeypatch.setattr(web, "create_app", _fake_create_app)
    web.serve(host="0.0.0.0", port=9999, ledger=led, no_auth=True)
    assert captured["token"] is None


# ---------------------------------------------------------------------------
# track CLI 命令：flask 缺失 → 优雅退出（exit 1，不崩）
# ---------------------------------------------------------------------------


def test_track_command_flask_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from apkscan import cli

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "flask":
            raise ImportError("simulated missing flask")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    res = runner.invoke(cli.app, ["track"])
    assert res.exit_code == 1
    assert "该功能未安装" in res.output
    assert "pip install -e .[track]" in res.output


def test_track_command_starts_serve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """track 命令惰性导入成功时调 web.serve（用 monkeypatch 拦 serve，不真起服务）。"""
    from apkscan import cli
    from apkscan.track import web as _web

    captured: dict[str, Any] = {}

    def _fake_serve(host: str = "127.0.0.1", port: int = 8787, **kwargs: Any) -> None:
        captured["host"] = host
        captured["port"] = port
        captured["no_auth"] = kwargs.get("no_auth")

    monkeypatch.setattr(_web, "serve", _fake_serve)
    ledger_path = str(tmp_path / "t.json")
    res = runner.invoke(
        cli.app, ["track", "--host", "0.0.0.0", "--port", "1234", "--ledger", ledger_path, "--no-auth"]
    )
    assert res.exit_code == 0, res.output
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 1234
    assert captured["no_auth"] is True
