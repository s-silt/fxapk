"""Directional boundaries for collection and pre-report composition.

Documented import edges relevant to the reported origin_enrichment/restore cycle
(audited 2026-11-28, no such cycle exists):

- ``fxapk/core/origin_enrichment.py`` (line 15) imports ``fxapk.commands.enrich``
  **lazily inside the function body** — a deliberate, documented use of the bounded
  batch interface. ``fxapk/commands/enrich.py`` imports only ``fxapk.core.batch_enrich``,
  ``fxapk.core.json_io`` and ``fxapk.core.models``; none of those import
  ``origin_enrichment`` back. No cycle.
- ``fxapk/core/restore.py`` lazily imports ``fxapk.core.models`` (line 162) and
  ``fxapk/core/models.py`` lazily imports ``fxapk.core.restore``. Both modules live in
  the same ``fxapk.core`` layer and the mutual imports are function-local, so module
  load order never deadlocks; this is intra-layer coupling, not a boundary violation.

The guard below resolves relative imports via ``ast.ImportFrom.level`` plus the
importing file's package context, and matches forbidden prefixes on dotted segment
boundaries only (``fxapk.commands`` matches ``fxapk.commands.enrich`` but never
``fxapk.commands_extra``).
"""
import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "fxapk"


def _package_parts(package: str) -> list[str]:
    return package.split(".") if package else []


def _resolve_import_from(node: ast.ImportFrom, package: str) -> Iterator[str]:
    """Yield absolute dotted names for an ``ImportFrom`` under ``package`` context.

    ``from . import sibling`` in package ``fxapk.core`` yields ``fxapk.core.sibling``;
    ``from ..commands import name`` in package ``fxapk.core`` yields ``fxapk.commands``.
    For ``from x.y import z`` the alias ``z`` may itself be a submodule, so both the
    base ``x.y`` and the candidate submodule path ``x.y.z`` are yielded; otherwise
    ``from ..core import phase2`` would hide the forbidden edge ``fxapk.core.phase2``.
    Over-yielding is safe: a nonexistent leaf never matches a forbidden prefix unless
    the base already did.
    """
    if node.level:
        parts = _package_parts(package)
        keep = len(parts) - (node.level - 1)
        base = parts[:max(keep, 0)]
        if node.module:
            base = base + node.module.split(".")
    else:
        base = node.module.split(".") if node.module else []
    prefix = ".".join(base)
    if node.module:
        if prefix:
            yield prefix
        for alias in node.names:
            if alias.name == "*":
                continue
            yield f"{prefix}.{alias.name}" if prefix else alias.name
    else:
        for alias in node.names:
            yield f"{prefix}.{alias.name}" if prefix else alias.name


def _imports_from_source(source: str, package: str) -> Iterator[str]:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            yield from _resolve_import_from(node, package)
        elif isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)


def _package_of(path: Path) -> str:
    rel = path.relative_to(ROOT)
    return ".".join(["fxapk", *rel.parent.parts])


def _imports(path: Path) -> Iterator[str]:
    yield from _imports_from_source(path.read_text(encoding="utf-8"), _package_of(path))


def _hits(name: str, prefixes: Iterable[str]) -> bool:
    """Dotted-boundary match: exact segment match, never a raw string prefix."""
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


@pytest.mark.parametrize("layer", ["dynamic", "analyzers", "enrichers"])
def test_collection_does_not_depend_on_downstream_review_or_cli(layer: str) -> None:
    forbidden = ("fxapk.core.phase2", "fxapk.commands", "fxapk.cli")
    bad = [(str(path.relative_to(ROOT)), name)
           for path in sorted((ROOT / layer).rglob("*.py"))
           for name in _imports(path)
           if _hits(name, forbidden)]
    assert bad == []


#: Offline pure-review denyset. ``socketserver`` is listed by exact name because the
#: dotted-boundary matcher (correctly) never lets ``socket`` cover ``socketserver``.
_RUN_REVIEW_FORBIDDEN: tuple[str, ...] = (
    "fxapk.commands", "fxapk.dynamic", "fxapk.core.phase2.preparation",
    "fxapk.core.phase2.inventory", "subprocess", "requests", "socket", "socketserver",
)


def test_run_review_is_pure_and_does_not_import_orchestrator() -> None:
    module = ROOT / "core/phase2/run_review.py"
    assert module.is_file()
    assert not [name for name in _imports(module) if _hits(name, _RUN_REVIEW_FORBIDDEN)]


def test_shared_json_io_does_not_depend_on_analysis_or_review() -> None:
    module = ROOT / "core/json_io.py"
    assert module.is_file()
    forbidden = ("fxapk.dynamic", "fxapk.commands", "fxapk.core.phase2", "fxapk.analyzers")
    assert not [name for name in _imports(module) if _hits(name, forbidden)]


# --- Inert detection proofs: synthetic sources only, never scan the repo. ---
# These pin the resolver and matcher so a regression in either cannot silently
# weaken the scanning tests above; they do not tighten any existing allowance.

def test_relative_sibling_import_resolves_to_absolute_name() -> None:
    names = list(_imports_from_source("from . import sibling\n", "fxapk.core"))
    assert "fxapk.core.sibling" in names


def test_relative_parent_import_resolves_against_package_context() -> None:
    names = list(_imports_from_source("from ..commands import batch\n", "fxapk.core"))
    assert "fxapk.commands" in names


def test_relative_import_detection_catches_synthetic_forbidden_edge() -> None:
    source = "def f():\n    from ..commands import batch\n"
    names = list(_imports_from_source(source, "fxapk.core"))
    assert any(_hits(name, ("fxapk.commands",)) for name in names)


def test_dotted_boundary_rejects_string_prefix_lookalikes() -> None:
    assert not _hits("fxapk.commands_extra", ("fxapk.commands",))
    assert not _hits("fxapk.core.phase2x", ("fxapk.core.phase2",))
    assert _hits("fxapk.commands", ("fxapk.commands",))
    assert _hits("fxapk.commands.enrich", ("fxapk.commands",))


def test_absolute_imports_and_plain_imports_still_resolve() -> None:
    names = list(_imports_from_source(
        "import fxapk.cli\nfrom fxapk.commands.enrich import batch\n", "fxapk.core"))
    assert "fxapk.cli" in names
    assert "fxapk.commands.enrich" in names


def test_relative_parent_alias_form_exposes_forbidden_submodule_edge() -> None:
    """``from ..core import phase2`` in ``fxapk.dynamic`` must surface ``fxapk.core.phase2``."""
    names = list(_imports_from_source("from ..core import phase2\n", "fxapk.dynamic"))
    assert "fxapk.core.phase2" in names
    assert any(_hits(name, ("fxapk.core.phase2",)) for name in names)


def test_absolute_alias_form_exposes_forbidden_submodule_edge() -> None:
    """``from fxapk.core import phase2`` must surface ``fxapk.core.phase2`` as well."""
    names = list(_imports_from_source("from fxapk.core import phase2\n", "fxapk.dynamic"))
    assert "fxapk.core.phase2" in names
    assert any(_hits(name, ("fxapk.core.phase2",)) for name in names)


def test_alias_resolution_retains_base_module_name() -> None:
    """The base module is still yielded: ``from fxapk.commands import x`` hits ``fxapk.commands``."""
    names = list(_imports_from_source("from fxapk.commands import batch\n", "fxapk.core"))
    assert "fxapk.commands" in names
    assert any(_hits(name, ("fxapk.commands",)) for name in names)


def test_alias_over_yield_does_not_invent_forbidden_hits_for_clean_edges() -> None:
    """Importing a sibling submodule of an allowed package must stay inert-negative."""
    names = list(_imports_from_source("from ..core import models\n", "fxapk.dynamic"))
    assert not [name for name in names if _hits(name, ("fxapk.core.phase2", "fxapk.commands", "fxapk.cli"))]


def test_offline_review_denyset_catches_socketserver_by_exact_name() -> None:
    """Synthetic: plain, aliased and lazy ``socketserver`` imports all hit the denyset.

    ``import x as y`` must resolve to ``x`` (alias semantics), and ``socket`` alone must
    not be what catches it, so dropping the exact entry turns this red.
    """
    assert not _hits("socketserver", ("socket",))
    for source in ("import socketserver\n", "import socketserver as ss\n",
                   "def f():\n    from socketserver import TCPServer as S\n"):
        names = list(_imports_from_source(source, "fxapk.core.phase2"))
        assert "socketserver" in names, source
        assert any(_hits(name, _RUN_REVIEW_FORBIDDEN) for name in names), source
    assert not _hits("socketserverx", _RUN_REVIEW_FORBIDDEN)
