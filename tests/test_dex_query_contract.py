"""DEX 查询契约：缺插件时帮助和 capabilities 仍可用，且核心不装载 ASC。"""

from __future__ import annotations

import json
import sys
import pytest

from typer.testing import CliRunner

from apkscan.cli import app


def test_dex_capabilities_reports_provider_unavailable_without_loading_asc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.dex_query.resolve_worker_argv", lambda: None)
    loaded = {name for name in sys.modules if name == "droidasc" or name.startswith("droidasc.")}
    result = CliRunner().invoke(app, ["dex", "capabilities"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["schema_version"] == "dex-query-receipt/1"
    assert payload["provider"] == "asc"
    assert payload["available"] is False
    assert payload["reason"] == "provider_unavailable"
    assert payload["engine_executed"] is False
    assert {name for name in sys.modules if name == "droidasc" or name.startswith("droidasc.")} == loaded
