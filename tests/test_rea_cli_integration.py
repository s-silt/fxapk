"""Offline rea attach through the real Typer app, then digest and HTML."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from tests.test_rea_attach import _case, _cdp_bundle


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


def test_attach_cli_then_digest_and_html_without_rea(plugin_src: Path, tmp_path: Path) -> None:
    from fxapk_rea.plugin import attach_local_capabilities, rea_app, trace_local_capabilities

    bundle = tmp_path / "bundle"
    report = tmp_path / "case.json"
    out = tmp_path / "delivery"
    _case(report)
    raw_sha = _cdp_bundle(plugin_src, bundle)
    runner = CliRunner()
    attached = runner.invoke(
        rea_app,
        ["attach", "--bundle", str(bundle), "--report", str(report), "--out", str(out)],
    )
    assert attached.exit_code == 0, attached.stdout
    assert raw_sha in attached.stdout
    assert (out / "report.json").is_file()
    assert (out / "report.html").is_file()
    assert (out / "report.digest.json").is_file()
    digested = runner.invoke(app, ["digest", str(out / "report.json")])
    assert digested.exit_code == 0, digested.stdout
    summary = json.loads(digested.stdout)
    assert summary["web_observations"]["closure_evaluated"] is False
    assert "外部网页观察" in (out / "report.html").read_text(encoding="utf-8")
    help_text = runner.invoke(rea_app, ["trace", "--help"])
    assert help_text.exit_code == 0
    assert "--related-origin" in help_text.stdout
    attach_info = attach_local_capabilities()
    assert attach_info["capabilities"]["attach"] == "offline_available"
    assert attach_info["browser"] == "not_probed"
    trace_info = trace_local_capabilities()
    assert trace_info["browser"] == "not_probed"
    assert "websockets_version" in trace_info
    probed = runner.invoke(rea_app, ["capabilities", "--provider", "attach"])
    assert probed.exit_code == 0
    assert json.loads(probed.stdout)["capabilities"]["attach"] == "offline_available"
    traced = runner.invoke(rea_app, ["capabilities", "--provider", "trace"])
    assert json.loads(traced.stdout)["browser"] == "not_probed"
