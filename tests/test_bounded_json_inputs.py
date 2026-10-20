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


def test_loads_bounded_utf8_bom_bytes() -> None:
    assert loads_bounded(b"\xef\xbb\xbf{\"a\": 1}") == {"a": 1}


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


def _assert_typer_exit_2_without_traceback(callback, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        callback()
    assert excinfo.value.exit_code == 2
    assert not isinstance(excinfo.value, RecursionError)
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def _invoke_split_reader(target: str, path: Path) -> None:
    import apkscan.commands.split_cli as split_cli

    if target == "read_json":
        split_cli._read_json(path, "time_table_invalid")
    elif target == "labels":
        split_cli._load_labels(path)
    else:
        split_cli.validate(path)


@pytest.mark.parametrize("target", ["read_json", "labels", "manifest"])
def test_split_cli_rejects_oversize_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
) -> None:
    import apkscan.commands.split_cli as split_cli

    monkeypatch.setattr(split_cli, "SMALL_JSON_MAX_BYTES", 8)
    path = tmp_path / f"{target}.json"
    path.write_bytes(b'{"pad":"' + b"x" * 64 + b'"}')
    _assert_typer_exit_2_without_traceback(lambda: _invoke_split_reader(target, path), capsys)


@pytest.mark.parametrize("target", ["read_json", "labels", "manifest"])
def test_split_cli_rejects_deep_json_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    path = tmp_path / f"{target}.json"
    path.write_text(_nested_arrays(200_000), encoding="utf-8")
    _assert_typer_exit_2_without_traceback(lambda: _invoke_split_reader(target, path), capsys)


def test_recognition_labels_deep_line_is_jsonl_invalid(tmp_path: Path) -> None:
    from apkscan.core.recognition_labels import (
        RecognitionLabelValidationError,
        load_recognition_labels,
    )

    path = tmp_path / "labels.jsonl"
    path.write_text("[" * 5000 + "]" * 5000 + "\n", encoding="utf-8")
    with pytest.raises(RecognitionLabelValidationError) as excinfo:
        load_recognition_labels(path)
    assert excinfo.value.code == "jsonl_invalid"
    assert excinfo.value.line == 1
    assert not isinstance(excinfo.value, RecursionError)


def test_package_binding_uses_report_json_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import apkscan.commands.corpus as corpus_cmd
    import apkscan.core.json_io as json_io
    from apkscan.core import case_package
    from tests.phase2_fixtures import write_verified_package

    # 把小文件上限压到 1 后仍能读过验包：绑定必须跟 _load_object 用同一档。
    monkeypatch.setattr(json_io, "SMALL_JSON_MAX_BYTES", 1)
    monkeypatch.setattr(corpus_cmd, "SMALL_JSON_MAX_BYTES", 1, raising=False)
    seen: list[int] = []
    real_load = corpus_cmd.load_json_file

    def spy(path: Path, *, limit: int, **kwargs: object) -> object:
        seen.append(limit)
        return real_load(path, limit=limit, **kwargs)

    monkeypatch.setattr(corpus_cmd, "load_json_file", spy)
    package = write_verified_package(tmp_path, "pkg", case_id="case-001")
    bound, package_id, report_hash = corpus_cmd._package_binding(
        package / "case-package.json", ""
    )
    assert bound == "case-001"
    assert isinstance(package_id, str) and len(package_id) == 64
    assert isinstance(report_hash, str) and len(report_hash) == 64
    assert seen == [case_package.REPORT_JSON_MAX_BYTES]
    assert seen[0] == json_io.REPORT_JSON_MAX_BYTES


def test_enrich_batch_deep_scope_matches_bad_json_exit(tmp_path: Path) -> None:
    from apkscan.commands.enrich import enrich_app

    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.1\n", encoding="utf-8")

    def invoke(name: str, text: str):
        out = tmp_path / name
        out.mkdir()
        (out / "enrichment-scope.json").write_text(text, encoding="utf-8")
        return CliRunner().invoke(
            enrich_app,
            ["batch", "--targets", str(targets), "--out", str(out), "--case-id", "case-1"],
        )

    bad = invoke("bad", "{")
    deep = invoke("deep", _nested_arrays(200_000))
    rendered = _visible(deep)
    assert bad.exit_code == deep.exit_code == 2
    assert "富化目录与本案未绑定" in rendered
    assert "Traceback" not in rendered
    assert "RecursionError" not in rendered
    assert deep.exception is None or isinstance(deep.exception, SystemExit)


def test_origin_check_deep_report_matches_bad_json_exit(tmp_path: Path) -> None:
    def invoke(name: str, text: str):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return CliRunner().invoke(cli.app, [
            "origin-check",
            "--reference-url", "https://cdn.example.com/a",
            "--candidate-url", "https://origin.example.com/a",
            "--case-id", "fixture",
            "--source-note", "synthetic",
            "--report", str(path),
            "--mode", "passive",
        ])

    bad = invoke("bad.json", "{")
    deep = invoke("deep.json", _nested_arrays(200_000))
    rendered = _visible(deep)
    assert bad.exit_code == deep.exit_code == 2
    assert "origin-check failed:" in rendered
    assert "Traceback" not in rendered
    assert "RecursionError" not in rendered
    assert deep.exception is None or isinstance(deep.exception, SystemExit)


def test_lead_load_report_deep_json_matches_bad_json_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from apkscan.commands.lead import _load_report_payload

    def run(name: str, text: str) -> int:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        with pytest.raises(typer.Exit) as excinfo:
            _load_report_payload(path)
        assert not isinstance(excinfo.value, RecursionError)
        return int(excinfo.value.exit_code)

    assert run("bad.json", "{") == run("deep.json", _nested_arrays(200_000)) == 1
    captured = capsys.readouterr()
    assert "报告读取/解析失败" in captured.err
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "RecursionError" not in captured.err


def test_jadx_selection_deep_map_matches_bad_json(tmp_path: Path) -> None:
    from apkscan.commands.jadx_query import _selection

    cache = tmp_path / "cache"
    cache.mkdir()
    apk_sha = "ab" * 32

    def run(name: str, text: str) -> None:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        with pytest.raises(typer.BadParameter, match="索引映射格式无效") as excinfo:
            _selection(cache, None, apk_sha, path)
        assert not isinstance(excinfo.value, RecursionError)
        assert "Traceback" not in str(excinfo.value)

    run("bad.json", "{")
    run("deep.json", _nested_arrays(200_000))


def test_phase2_inventory_match_deep_json_matches_bad_json(tmp_path: Path) -> None:
    import apkscan.commands.phase2 as phase2

    bad = tmp_path / "bad.json"
    deep = tmp_path / "deep.json"
    bad.write_text("{", encoding="utf-8")
    deep.write_text(_nested_arrays(200_000), encoding="utf-8")
    assert phase2._inventory_file_matches(bad, tmp_path, object()) is False
    assert phase2._inventory_file_matches(deep, tmp_path, object()) is False
