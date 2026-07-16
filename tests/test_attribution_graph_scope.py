"""PR7 scope conformance: legacy isolation, unwired, additive exports."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

import apkscan
import apkscan.attribution as attribution
import apkscan.attribution.graph as graph_mod

_GRAPH_SOURCE = pathlib.Path(graph_mod.__file__)


def test_attribution_exports_are_sorted_and_additive() -> None:
    assert attribution.__all__ == sorted(attribution.__all__)
    for name in (
        "GraphEdge", "GraphIssue", "GraphNode", "GraphNodeType",
        "GraphRelation", "InfrastructureGraph", "build_infrastructure_graph",
    ):
        assert name in attribution.__all__
        assert hasattr(attribution, name)
    # the PR3/PR4/PR5 names are still exported (additive, never weakened)
    for name in ("AttributionEvidence", "RoleScore", "EvidenceScorer", "RoleClassifier"):
        assert name in attribution.__all__


_BAD_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+.*\b(?:kuzu|sqlite3)\b|^\s*(?:from|import)\s+apkscan\.graph\b",
    re.MULTILINE,
)


def test_graph_module_imports_no_legacy_or_db() -> None:
    # docstring prose legitimately names the legacy store to disclaim it; only
    # actual import statements are forbidden (the subprocess test below is the
    # definitive runtime proof).
    text = _GRAPH_SOURCE.read_text(encoding="utf-8")
    assert _BAD_IMPORT.search(text) is None
    # no relation is named after the legacy Kuzu OBSERVED table
    from apkscan.attribution.graph import GraphRelation

    assert "OBSERVED" not in {r.name for r in GraphRelation}
    assert "observed" not in {r.value for r in GraphRelation}


def test_importing_graph_loads_no_kuzu_or_legacy_graph() -> None:
    code = (
        "import apkscan.attribution.graph, sys;"
        "bad=[m for m in sys.modules if m=='kuzu' or m=='sqlite3' or m.startswith('apkscan.graph')];"
        "print(sorted(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == "[]", out


_GRAPH_SYMBOLS = re.compile(
    r"attribution\.graph|build_infrastructure_graph|InfrastructureGraph|GraphNodeType|GraphRelation"
)


def test_no_runtime_module_references_the_graph() -> None:
    root = pathlib.Path(apkscan.__file__).parent
    attribution_dir = root / "attribution"
    offenders = []
    for path in root.rglob("*.py"):
        if attribution_dir in path.parents or path == attribution_dir:
            continue
        if _GRAPH_SYMBOLS.search(path.read_text(encoding="utf-8")):
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == [], f"graph must stay unwired: {offenders}"


def test_import_touches_no_network() -> None:
    # a fresh interpreter that arms a socket tripwire BEFORE importing the module;
    # a subprocess (not importlib.reload) avoids corrupting this process's classes.
    code = (
        "import socket\n"
        "def _boom(*a, **k):\n"
        "    raise AssertionError('network at import time')\n"
        "socket.socket = _boom\n"
        "import apkscan.attribution.graph\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
