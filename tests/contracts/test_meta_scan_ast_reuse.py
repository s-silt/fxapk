"""Fresh AST reuse must not turn repository scans into cached snapshots."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.contracts import meta_scan


def test_scan_source_parses_once_without_changing_accesses(monkeypatch):
    parse = ast.parse
    calls = []

    def counted(source, *args, **kwargs):
        calls.append(source)
        return parse(source, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted)
    src = 'from demo import KEY\nreport.meta[KEY] = 1\nx = report.meta.get(KEY)'
    accesses = meta_scan.scan_source(src, symbols={"demo": {"KEY": "shared"}})
    assert [(a.key, a.kind, a.line) for a in accesses] == [
        ("shared", "write", 2), ("shared", "read", 3),
    ]
    assert calls == [src]


def test_source_helpers_keep_standalone_syntax_error_behavior():
    assert meta_scan.collect_module_constants("bad syntax!") == {}
    assert meta_scan._import_map("bad syntax!", {}) == ({}, {})
    with pytest.raises(SyntaxError):
        meta_scan.scan_source("bad syntax!")


def test_reused_tree_is_not_mutated_by_helpers():
    src = 'K = "safe"\nfrom demo import KEY\nreport.meta[K] = 1'
    tree = ast.parse(src)
    before = ast.dump(tree, include_attributes=True)
    assert meta_scan.collect_module_constants(src, _tree=tree) == {"K": "safe"}
    assert meta_scan._import_map(src, {"demo": {"KEY": "imported"}}, _tree=tree) == (
        {"KEY": "imported"}, {},
    )
    assert ast.dump(tree, include_attributes=True) == before


def test_repository_scan_refreshes_files_and_does_not_share_results(tmp_path: Path):
    prod = tmp_path / "custom_prod"
    checks = tmp_path / "custom_tests"
    prod.mkdir()
    checks.mkdir()
    source = prod / "a.py"
    consumer = checks / "test_a.py"
    source.write_text('report.meta["old"] = 1', encoding="utf-8")
    consumer.write_text('x = report.meta.get("old")', encoding="utf-8")
    first = meta_scan.scan_repository(tmp_path, prod_dir="custom_prod", test_dir="custom_tests")
    assert set(first.produced) == {"old"}
    assert set(first.test_consumed) == {"old"}
    first.produced.clear()
    source.write_text('report.meta["new"] = 1', encoding="utf-8")
    consumer.unlink()
    second = meta_scan.scan_repository(tmp_path, prod_dir="custom_prod", test_dir="custom_tests")
    assert set(second.produced) == {"new"}
    assert not second.test_consumed
