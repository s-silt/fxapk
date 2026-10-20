"""有界 JSON 读取：超限与超深输入不得再走无界 read_text / json.loads。"""
from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from apkscan import cli
from apkscan.commands.evaluate_cli import _read_json
from apkscan.core import case_package
from apkscan.core.case_package import CasePackageError, CasePackageErrorCode
from apkscan.core.json_io import (
    JSON_MAX_DEPTH,
    BoundedJsonError,
    json_depth,
    loads_bounded,
    read_bytes_bounded,
    read_json_bounded,
    read_text_bounded,
)


def _nested_arrays(depth: int) -> str:
    return "[" * depth + "]" * depth


def _visible(result: object) -> str:
    output = getattr(result, "output", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    return f"{output}\n{stderr}"


def test_read_text_bounded_over_limit_is_value_error(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_bytes(b"x" * 20)
    with pytest.raises(BoundedJsonError) as excinfo:
        read_text_bounded(path, 8)
    assert isinstance(excinfo.value, ValueError)
    assert issubclass(BoundedJsonError, ValueError)


def test_read_text_bounded_normalizes_newlines(tmp_path: Path) -> None:
    path = tmp_path / "lines.txt"
    path.write_bytes(b"a\r\nb\rc\n")
    assert read_text_bounded(path, 100) == "a\nb\nc\n"
    assert read_text_bounded(path, 100) == path.read_text(encoding="utf-8")


def test_loads_bounded_maps_recursion_error() -> None:
    with pytest.raises(BoundedJsonError) as excinfo:
        loads_bounded(_nested_arrays(100_000))
    assert not isinstance(excinfo.value, RecursionError)
    assert isinstance(excinfo.value.__cause__, RecursionError)


def test_loads_bounded_depth_limit() -> None:
    accepted = loads_bounded(_nested_arrays(JSON_MAX_DEPTH))
    assert json_depth(accepted) == JSON_MAX_DEPTH
    with pytest.raises(BoundedJsonError):
        loads_bounded(_nested_arrays(JSON_MAX_DEPTH + 1))


def test_read_json_bounded_deep_input_raises_overflow(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    text = _nested_arrays(100_000)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(OverflowError, match="JSON depth"):
        read_json_bounded(path, len(text.encode("utf-8")), JSON_MAX_DEPTH)


def test_read_bytes_bounded_rejects_over_limit(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    payload = b"abcdef"
    path.write_bytes(payload)
    assert read_bytes_bounded(path, len(payload)) == payload
    with pytest.raises(BoundedJsonError, match="file exceeds 3 bytes"):
        read_bytes_bounded(path, 3)


def test_load_object_rejects_oversize_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(case_package, "REPORT_JSON_MAX_BYTES", 1024)
    path = tmp_path / "package.json"
    path.write_bytes(b'{"pad":"' + b"x" * 1100 + b'"}')
    with pytest.raises(CasePackageError) as excinfo:
        case_package._load_object(path)
    assert excinfo.value.code == CasePackageErrorCode.JSON_RECORD_UNREADABLE


def test_load_object_rejects_deep_json(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text(_nested_arrays(200_000), encoding="utf-8")
    with pytest.raises(CasePackageError) as excinfo:
        case_package._load_object(path)
    assert excinfo.value.code == CasePackageErrorCode.JSON_RECORD_UNREADABLE


def test_evaluate_read_json_rejects_deep_file(tmp_path: Path) -> None:
    path = tmp_path / "params.json"
    path.write_text(_nested_arrays(200_000), encoding="utf-8")
    with pytest.raises(typer.Exit) as excinfo:
        _read_json(path, "params_invalid")
    assert excinfo.value.exit_code == 2


def test_cli_digest_rejects_deep_report_without_traceback(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(_nested_arrays(200_000), encoding="utf-8")
    result = CliRunner().invoke(cli.app, ["digest", str(path)])
    rendered = _visible(result)
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in rendered


def test_cli_digest_oversize_reports_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import apkscan.core.json_io as json_io

    monkeypatch.setattr(json_io, "REPORT_JSON_MAX_BYTES", 1024)
    path = tmp_path / "report.json"
    path.write_bytes(b'{"pad":"' + b"x" * 1100 + b'"}')
    result = CliRunner().invoke(cli.app, ["digest", str(path)])
    rendered = _visible(result)
    assert result.exit_code == 1
    assert "读取报告文件失败" in rendered
    assert "Traceback" not in rendered
