"""自检诊断（AI 友好）测试：结构稳定、每项含 status+fix、webcheck opt-in、CLI 出 JSON。"""

from __future__ import annotations


import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.selfcheck import run_selfcheck

runner = CliRunner()


def test_selfcheck_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FXAPK_WEBCHECK_URL", raising=False)
    res = run_selfcheck(online=False, probe_network=False)
    assert isinstance(res["components"], list) and res["components"]
    assert isinstance(res["summary"], dict)
    assert isinstance(res["ok"], bool)
    for c in res["components"]:
        assert set(c) >= {"name", "category", "status", "detail", "fix"}
        assert c["status"] in {"ok", "missing", "disabled", "unreachable"}
    names = {c["name"] for c in res["components"]}
    assert {"core", "graph", "webcheck", "online-enrichment"} <= names


def test_core_always_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FXAPK_WEBCHECK_URL", raising=False)
    res = run_selfcheck(online=False, probe_network=False)
    core = next(c for c in res["components"] if c["name"] == "core")
    assert core["status"] == "ok"


def test_webcheck_disabled_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FXAPK_WEBCHECK_URL", raising=False)
    res = run_selfcheck(online=True, probe_network=False)
    wc = next(c for c in res["components"] if c["name"] == "webcheck")
    assert wc["status"] == "disabled"
    assert "FXAPK_WEBCHECK_URL" in wc["fix"]


def test_webcheck_configured_no_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FXAPK_WEBCHECK_URL", "http://localhost:3000")
    res = run_selfcheck(online=True, probe_network=False)
    wc = next(c for c in res["components"] if c["name"] == "webcheck")
    assert wc["status"] == "ok"  # 配置了且未探测 → 视为就绪


def test_cli_selfcheck_emits_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FXAPK_WEBCHECK_URL", raising=False)
    res = runner.invoke(cli.app, ["selfcheck", "--offline", "--no-probe"])
    assert res.exit_code == 0
    assert '"components"' in res.output
    assert '"core"' in res.output
