"""Directional boundaries for collection and pre-report composition."""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "apkscan"


def _imports(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
        elif isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)


@pytest.mark.parametrize("layer", ["dynamic", "analyzers", "enrichers"])
def test_collection_does_not_depend_on_downstream_review_or_cli(layer):
    bad = [(str(path.relative_to(ROOT)), name)
           for path in sorted((ROOT / layer).rglob("*.py"))
           for name in _imports(path)
           if name.startswith(("apkscan.core.phase2", "apkscan.commands", "apkscan.cli"))]
    assert bad == []


def test_run_review_is_pure_and_does_not_import_orchestrator():
    module = ROOT / "core/phase2/run_review.py"
    assert module.is_file()
    forbidden = ("apkscan.commands", "apkscan.dynamic", "apkscan.core.phase2.preparation",
                 "apkscan.core.phase2.inventory", "subprocess", "requests", "socket")
    assert not [name for name in _imports(module) if name.startswith(forbidden)]


def test_shared_json_io_does_not_depend_on_analysis_or_review():
    module = ROOT / "core/json_io.py"
    assert module.is_file()
    forbidden = ("apkscan.dynamic", "apkscan.commands", "apkscan.core.phase2", "apkscan.analyzers")
    assert not [name for name in _imports(module) if name.startswith(forbidden)]
