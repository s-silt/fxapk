"""Offline report revisions must not erase unreadable enrichment statistics."""
from __future__ import annotations

import json
import socket
from dataclasses import fields
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fxapk.cli import app
from fxapk.core.models import Report
from fxapk.core.offline_review import runner

_SAMPLE = "a" * 64
_MARKER = "offline_review_enricher_status_incomplete"
_HTML_NOTE = "离线修订未能保留全部富化统计"
_RAW_MARKER = "FIXTURE_UNREADABLE_ENRICHMENT_VALUE"
_LEGACY_OK = {"provider": "fixture", "attempted": 10, "ok": 9, "failed": 1}
_ZERO = {"provider": "fixture", "attempted": 0, "ok": 0, "failed": 0}
_LOW = {"provider": "fixture", "attempted": 10, "ok": 1, "failed": 9}
_MISSING_COUNT = {"provider": "fixture", "attempted": 10}
_NO_RECORD = {"provider": "fixture", "attempted": 10, "ok": 7, "no_record": 2, "failed": 1}


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("synthetic offline review attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def _write_input(
    root: Path, enrichment: dict[str, object], *, manifest_sample: str = _SAMPLE,
) -> tuple[Path, Path, bytes]:
    source, plan = root / "source.json", root / "plan.json"
    meta = enrichment.get("meta", {})
    assert isinstance(meta, dict)
    original = json.dumps({
        "package_name": "com.example.synthetic", "analysis_status": "complete", "completeness": 1.0,
        **enrichment, "meta": {"sample_sha256": _SAMPLE, **meta},
    }).encode()
    source.write_bytes(original)
    plan.write_text(json.dumps({
        "schema_version": "fxapk.offline-review.v1", "sample_sha256": manifest_sample,
        "tasks": [{"id": "synthetic-inert", "kind": "fixture_unsupported"}],
    }), encoding="utf-8")
    return source, plan, original


@pytest.mark.parametrize(("source_fields", "retained", "incomplete", "rate", "issue"), [
    pytest.param({}, [], False, None, False, id="legacy-missing"),
    pytest.param({"enricher_status": []}, [], False, None, False, id="empty-list"),
    pytest.param({"enricher_status": [_ZERO]}, [_ZERO], False, None, False, id="real-zeros"),
    pytest.param({"enricher_status": [_LEGACY_OK]}, [_LEGACY_OK], False, 0.9, False, id="legacy-without-no-record"),
    pytest.param({"enricher_status": [_NO_RECORD]}, [_NO_RECORD], False, 0.9, False, id="with-no-record"),
    pytest.param({"enricher_status": None}, [], True, None, True, id="explicit-null"),
    pytest.param({"enricher_status": {"unexpected": _RAW_MARKER}}, [], True, None, True, id="not-a-list"),
    pytest.param({"enricher_status": [None]}, [], True, None, True, id="no-readable-rows"),
    pytest.param({"enricher_status": [_LEGACY_OK, _RAW_MARKER]}, [_LEGACY_OK], True, 0.9, True, id="mixed"),
    pytest.param({"enricher_status": [_MISSING_COUNT]}, [_MISSING_COUNT], False, None, True, id="kept-malformed-count"),
    pytest.param({"enricher_status": [_LOW, _RAW_MARKER]}, [_LOW], True, 0.1, True, id="low-rate-and-unreadable-row"),
    pytest.param({"enricher_status": [_LEGACY_OK], "meta": {_MARKER: True}},
                 [_LEGACY_OK], True, 0.9, True, id="inherited-true"),
    pytest.param({"enricher_status": [], "meta": {_MARKER: 1}},
                 [], False, None, False, id="integer-not-a-marker"),
    pytest.param({"enricher_status": [], "meta": {_MARKER: {"unexpected": _RAW_MARKER}}},
                 [], False, None, False, id="marker-values-not-copied"),
    pytest.param({"enricher_status": None, "meta": {_MARKER: False}},
                 [], True, None, True, id="false-does-not-clear-current-loss"),
])
def test_offline_revision_preserves_enrichment_statistics_uncertainty(
    tmp_path: Path, source_fields: dict[str, object], retained: list[dict[str, object]],
    incomplete: bool, rate: float | None, issue: bool,
) -> None:
    source, plan, original = _write_input(tmp_path, source_fields)
    cli = CliRunner()
    direct = cli.invoke(app, ["digest", str(source)])
    assert direct.exit_code == 0
    integrity = json.loads(direct.stdout)["integrity"]
    assert (integrity["analysis_status"], integrity["completeness"]) == ("complete", 1.0)
    assert integrity["enrichment_ok_rate"] == rate
    assert integrity["reliable"] is (not issue)
    warnings = integrity["warnings"]
    assert sum("富化统计含异常条目" in warning for warning in warnings) == int(issue)
    assert sum("富化成功终态率" in warning for warning in warnings) == int(rate == 0.1)

    parent = source
    for number in (1, 2):
        parent_bytes = parent.read_bytes()
        out = tmp_path / f"revision-{number}"
        review = cli.invoke(app, ["evidence-review", str(plan), "--report", str(parent), "--out", str(out)])
        assert review.exit_code == 5, review.output
        assert json.loads(review.stdout)["state"] == "partial"
        receipt = json.loads((out / "review.json").read_text(encoding="utf-8"))
        assert receipt["publication"] == "ok" and receipt["tasks"][0]["state"] == "unsupported"
        assert not (out / "inputs").exists()
        assert parent.read_bytes() == parent_bytes and source.read_bytes() == original

        parent = out / "report.json"
        report_text = parent.read_text(encoding="utf-8")
        digest_text = (out / "digest.json").read_text(encoding="utf-8")
        html = (out / "report.html").read_text(encoding="utf-8")
        published = json.loads(report_text)
        assert set(published) == {field.name for field in fields(Report)}
        assert published["enricher_status"] == retained
        if incomplete:
            assert published["meta"][_MARKER] is True
        else:
            assert _MARKER not in published["meta"]
        assert (_HTML_NOTE in html) is incomplete
        assert ("富化器状态</h3>" in html) is bool(retained)
        replay = cli.invoke(app, ["digest", str(parent)])
        assert replay.exit_code == 0
        assert json.loads(digest_text)["integrity"] == json.loads(replay.stdout)["integrity"] == integrity
        assert _RAW_MARKER not in report_text + digest_text + html + replay.stdout + direct.stdout


def test_enrichment_loss_does_not_publish_for_an_unbound_source(tmp_path: Path) -> None:
    source, plan, original = _write_input(tmp_path, {"enricher_status": None}, manifest_sample="b" * 64)
    out = tmp_path / "unbound"
    result = CliRunner().invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["reason_code"] == "review_report_sample_mismatch"
    assert not out.exists() and source.read_bytes() == original


def test_enrichment_loss_does_not_publish_after_failed_report_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, plan, original = _write_input(tmp_path, {"enricher_status": [None]})
    write_json = runner.write_json

    def fail_report(path: Path, value: object, *, allow_nan: bool = True) -> None:
        if path.name == "report.json":
            raise OSError("synthetic failure before report publication")
        write_json(path, value, allow_nan=allow_nan)

    monkeypatch.setattr(runner, "write_json", fail_report)
    out = tmp_path / "failed"
    result = CliRunner().invoke(app, ["evidence-review", str(plan), "--report", str(source), "--out", str(out)])
    assert result.exit_code == 2
    assert json.loads(result.stderr.strip().splitlines()[-1])["reason_code"] == "review_publication_failed"
    receipt = json.loads((out / "review.json").read_text(encoding="utf-8"))
    assert (receipt["state"], receipt["publication"]) == ("failed", "failed")
    assert all(not (out / name).exists() for name in ("report.json", "report.html", "digest.json"))
    assert source.read_bytes() == original
