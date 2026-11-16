"""Fresh-process import contracts, not machine-dependent timing thresholds."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = r'''
import importlib.abc
import importlib.metadata
import runpy
import sys

class NoHTTPImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "fxapk.config.fetch" or fullname.split(".")[0] == "requests":
            raise AssertionError("HTTP implementation imported during lightweight CLI startup")

# Isolate core startup from arbitrary installed plugins, while proving discovery runs.
selected = []
class Entries:
    def select(self, **kwargs):
        selected.append(kwargs.get("group"))
        return []
importlib.metadata.entry_points = lambda: Entries()
sys.meta_path.insert(0, NoHTTPImports())
args = sys.argv[1:]
if not args:
    import fxapk.cli
else:
    sys.argv = ["fxapk", *args]
    try:
        runpy.run_module("fxapk.cli", run_name="__main__")
    except SystemExit as exc:
        assert exc.code in (None, 0)
assert "fxapk.plugins" in selected
assert "requests" not in sys.modules
assert "fxapk.config.fetch" not in sys.modules
'''


@pytest.mark.parametrize("args", [[], ["--version"], ["leak-scan", "--diff", "-"]])
def test_lightweight_cli_does_not_load_http_implementation(args: list[str]) -> None:
    env = dict(os.environ)
    for name in ("PYTHONPATH", "FXHX_API_KEY", "CLIPROXYAPI_API_KEY"):
        env.pop(name, None)
    # Pin both ends of this test-owned pipe, independently of the host locale.
    env["PYTHONIOENCODING"] = "utf-8:strict"
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT, *args], cwd=_ROOT, env=env,
        input="", capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_origin_ip_validation_still_delegates_to_shared_policy(monkeypatch) -> None:
    import fxapk.config.fetch as fetch
    from fxapk.core.origin_check import _public_ip

    seen = []

    def reject(address):
        seen.append(str(address))
        return True

    monkeypatch.setattr(fetch, "_ip_is_blocked", reject)
    with pytest.raises(ValueError, match="not a public Internet address"):
        _public_ip("192.0.2.1")
    assert seen == ["192.0.2.1"]
