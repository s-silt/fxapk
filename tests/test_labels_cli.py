"""P4-C 红态契约：``fxapk recognize labels validate``（只读标签校验器）。

设计见本地 P4 v2 spec §3/§6.5：exit 0=有效（空文件也算，0 条计数）；exit 2=非法，
stderr 报首个违规（行号+稳定 code，不带值）；零网络/零子进程/不写任何文件；
挂在 P3-D 建立的 recognize 组下。
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli

runner = CliRunner()

HEX_A = "a" * 64


def _family(**over):
    record = {
        "kind": "family_assignment",
        "schema_version": "1.0",
        "record_id": "rec-0001",
        "status": "confirmed",
        "layer": "silver",
        "author_kind": "human",
        "label_basis": ["independent-review"],
        "evidence_ref": "bundle:2026/fixture-0001",
        "label_lineage": "unspecified",
        "confidence": 0.9,
        "supersedes": None,
        "reason_codes": ["fixture-reason"],
        "sample_sha256": HEX_A,
        "level": "platform_family",
        "family_id": "fixture-family",
    }
    record.update(over)
    return record


def _write(tmp_path: Path, *records) -> Path:
    path = tmp_path / "labels.jsonl"
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


def _validate(path: Path):
    return runner.invoke(
        cli.app, ["recognize", "labels", "validate", "--labels", str(path)]
    )


def test_valid_file_exits_zero_with_counts(tmp_path):
    second = _family(record_id="rec-0002", family_id="second-family", status="proposed")
    result = _validate(_write(tmp_path, _family(), second))
    assert result.exit_code == 0, result.output
    assert "family_assignment" in result.output
    assert "confirmed" in result.output and "proposed" in result.output
    assert "silver" in result.output


def test_empty_file_is_valid_zero_records(tmp_path):
    path = tmp_path / "labels.jsonl"
    path.write_text("", encoding="utf-8")
    result = _validate(path)
    assert result.exit_code == 0
    assert "0" in result.output


def test_invalid_record_reports_line_and_code_without_values(tmp_path):
    bad = _family(record_id="rec-0002", family_id="unknown")  # 保留字
    result = _validate(_write(tmp_path, _family(), bad))
    assert result.exit_code == 2
    # 精确锁：stdout 全空、stderr 恰为 code+行号一行（codex 复审：宽松包含会漏泄露）。
    assert result.stdout == ""
    assert result.stderr.strip() == "error: family_id_reserved at line 2"
    assert "rec-0002" not in result.stderr  # 违规记录的字段值绝不回显


def test_duplicate_record_id_fails(tmp_path):
    result = _validate(
        _write(tmp_path, _family(), _family(family_id="another-family"))
    )
    assert result.exit_code == 2
    assert "record_id_duplicate" in result.output + result.stderr


def test_broken_json_fails_closed(tmp_path):
    path = tmp_path / "labels.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    result = _validate(path)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "not json" not in result.stderr  # 原始记录内容不回显


def test_missing_file_reports_stable_file_level_code(tmp_path):
    # 文件级错误统一稳定形式：行号 0 = 文件级（codex 复审 P1 的契约化）。
    target = tmp_path / "absent.jsonl"
    result = _validate(target)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "error: labels_unreadable at line 0"
    assert str(target) not in result.stderr  # 路径不回显


def test_validate_writes_nothing(tmp_path, monkeypatch):
    import socket
    import subprocess

    def _boom(*_args, **_kwargs):
        raise AssertionError("labels validate 不得触网/起子进程")

    for target in ("run", "Popen", "check_output", "check_call", "call"):
        monkeypatch.setattr(subprocess, target, _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    path = _write(tmp_path, _family())
    before = sorted(p.name for p in tmp_path.iterdir())
    assert _validate(path).exit_code == 0
    after = sorted(p.name for p in tmp_path.iterdir())
    assert after == before  # 只读：不产生任何新文件


def test_labels_flag_is_required():
    result = runner.invoke(cli.app, ["recognize", "labels", "validate"])
    assert result.exit_code == 2
