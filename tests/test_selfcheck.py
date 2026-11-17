"""自检诊断（AI 友好）测试：结构稳定、每项含 status+fix、CLI 出 JSON。"""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from fxapk import cli
from fxapk.plugins import registry
from fxapk.selfcheck import run_selfcheck

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
    assert {"core", "decrypt", "online-enrichment"} <= names


def test_core_always_ok() -> None:
    res = run_selfcheck(online=False, probe_network=False)
    core = next(c for c in res["components"] if c["name"] == "core")
    assert core["status"] == "ok"


def test_cli_selfcheck_emits_json() -> None:
    res = runner.invoke(cli.app, ["selfcheck", "--offline", "--no-probe"])
    assert res.exit_code == 0
    assert '"components"' in res.output
    assert '"core"' in res.output


def test_selfcheck_reports_installed_rea_disabled_without_loading(monkeypatch) -> None:
    def fail_load():
        raise RuntimeError("disabled plugin imported")

    entry = SimpleNamespace(
        name="rea",
        value="fxapk_rea.plugin:plugin_factory",
        dist=SimpleNamespace(metadata={"Name": "fxapk-rea"}),
        load=fail_load,
    )
    monkeypatch.setattr(registry, "_entry_points", lambda: [entry])
    monkeypatch.delenv("FXAPK_ENABLE_REA", raising=False)
    monkeypatch.setattr("fxapk.core.registry.detect_capabilities", lambda **_kwargs: set())
    monkeypatch.setattr("fxapk.selfcheck.build_credential_components", lambda: [])

    res = run_selfcheck(online=False, probe_network=False)

    rea = next(item for item in res["components"] if item["name"] == "plugin:rea")
    assert rea["status"] == "disabled"
    assert rea["detail"] == "rea_opt_in_required"
    assert "FXAPK_ENABLE_REA=1" in rea["fix"]
    assert "安装" not in rea["fix"]
    core = next(item for item in res["components"] if item["name"] == "core")
    assert core["status"] == "ok"


def test_cli_selfcheck_preserves_diagnostic_payload_and_offline_flags(monkeypatch) -> None:
    import json

    calls = []
    payload = {
        "components": [{
            "name": "version", "category": "core", "status": "ok",
            "detail": "distribution=读取失败 | distribution_status=error consistency=unverifiable",
            "fix": "",
        }],
        "summary": {"ok": 1}, "ok": True,
    }

    def synthetic_selfcheck(*, online, probe_network):
        calls.append((online, probe_network))
        return payload

    monkeypatch.setattr("fxapk.selfcheck.run_selfcheck", synthetic_selfcheck)
    result = runner.invoke(cli.app, ["selfcheck", "--offline", "--no-probe"])
    assert result.exit_code == 0
    assert calls == [(False, False)]
    assert json.loads(result.output) == payload
    assert "读取失败" in result.output
