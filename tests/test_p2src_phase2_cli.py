# -*- coding: utf-8 -*-
"""统一 Phase2 CLI：无需机器环境变量即可完成清单→工作队列→状态审计。"""
from __future__ import annotations

from pathlib import Path

import apkscan.commands.phase2 as cli
from tests.phase2_fixtures import write_verified_package


def _case(tmp_path: Path) -> tuple[Path, Path]:
    case_dir = tmp_path / "synthetic-case"
    write_verified_package(case_dir, "package", leads=[{
        "category": "DOMAIN", "value": "api.example.test",
        "source_refs": [{"evidence_id": "ev-1", "scope": "case_evidence"}],
    }])
    clues = tmp_path / "clues.jsonl"
    clues.write_text("", encoding="utf-8")
    return case_dir, clues


def test_init_coverage_then_status_names_next_action(tmp_path: Path, capsys) -> None:
    case_dir, clues = _case(tmp_path)
    snapshot = tmp_path / "review-coverage.json"
    assert cli.main([
        "init-coverage", "--case-dir", str(case_dir), "--out", str(snapshot),
    ]) == 0
    assert snapshot.exists()
    assert cli.main([
        "status", "--case-dir", str(case_dir), "--coverage", str(snapshot),
        "--clues", str(clues),
    ]) == 1, "pending 工作队列尚不能被 status 表述为就绪"
    output = capsys.readouterr().out
    assert "待补证/待审核 1" in output
    assert "NEXT ACTION" in output


def test_init_coverage_refuses_overwrite(tmp_path: Path) -> None:
    case_dir, _clues = _case(tmp_path)
    snapshot = tmp_path / "review-coverage.json"
    snapshot.write_text("do-not-overwrite", encoding="utf-8")
    assert cli.main([
        "init-coverage", "--case-dir", str(case_dir), "--out", str(snapshot),
    ]) == 2
    assert snapshot.read_text(encoding="utf-8") == "do-not-overwrite"
