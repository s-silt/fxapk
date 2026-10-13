"""缺插件时 dex query 帮助可用，且不把查询原文写到 stdout。"""

from __future__ import annotations

import json
import sys
import pytest

from typer.testing import CliRunner

from apkscan.cli import app


def test_missing_plugin_query_is_unavailable_and_hides_the_query(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.dex_query.resolve_worker_argv", lambda: None)
    loaded = {name for name in sys.modules if name == "droidasc" or name.startswith("droidasc.")}
    token = "xref-token-example"
    help_result = CliRunner().invoke(app, ["dex", "--help"])
    assert help_result.exit_code == 0
    assert "query" in help_result.stdout
    assert "import" in help_result.stdout
    result = CliRunner().invoke(app, ["dex", "query", "missing.apk", "--value", token])
    payload = json.loads(result.stdout)
    assert result.exit_code != 0
    assert payload["reason"] == "provider_unavailable"
    assert token not in result.stdout
    assert {name for name in sys.modules if name == "droidasc" or name.startswith("droidasc.")} == loaded
