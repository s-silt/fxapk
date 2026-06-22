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
# serve：鉴权策略（非 loopback 自动生成 token；loopback / --no-auth 不强制）
# ---------------------------------------------------------------------------


def test_serve_non_loopback_auto_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """绑定 0.0.0.0 → 自动启用令牌（create_app 收到非空 token）。"""
    led, _, _ = _seed_ledger(tmp_path)
    captured: dict[str, Any] = {}

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None):  # type: ignore[no-untyped-def]
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

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None):  # type: ignore[no-untyped-def]
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

    def _fake_create_app(ledger: TrackingLedger, *, token: str | None = None):  # type: ignore[no-untyped-def]
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
