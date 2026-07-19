"""自检诊断（AI 友好）测试：结构稳定、每项含 status+fix、CLI 出 JSON。"""

from __future__ import annotations


from typer.testing import CliRunner

from apkscan import cli
from apkscan.selfcheck import run_selfcheck

runner = CliRunner()


def test_selfcheck_structure() -> None:
    res = run_selfcheck(online=False, probe_network=False)
    assert isinstance(res["components"], list) and res["components"]
    assert isinstance(res["summary"], dict)
    assert isinstance(res["ok"], bool)
    for c in res["components"]:
        assert set(c) >= {"name", "category", "status", "detail", "fix"}
        assert c["status"] in {"ok", "missing", "disabled", "unreachable"}
    names = {c["name"] for c in res["components"]}
    assert {"core", "graph", "online-enrichment"} <= names


def test_core_always_ok() -> None:
    res = run_selfcheck(online=False, probe_network=False)
    core = next(c for c in res["components"] if c["name"] == "core")
    assert core["status"] == "ok"


def test_cli_selfcheck_emits_json() -> None:
    res = runner.invoke(cli.app, ["selfcheck", "--offline", "--no-probe"])
    assert res.exit_code == 0
    assert '"components"' in res.output
    assert '"core"' in res.output
