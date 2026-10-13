"""Unknown-package CDP deferral, three-round not-executed receipts, SDK native gap."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from apkscan.core import infra
from apkscan.core.leads import build_endpoint_leads
from apkscan.core.models import Endpoint, Evidence, Report
from apkscan.core.native_handoff import project_native_handoff
from apkscan.core.web_observation_plan import build_plan
from apkscan.dynamic import auto, capture
from apkscan.report.digest import build_digest
from apkscan.report.json import _to_jsonable
from tests.test_web_supplement_routing import _body


def _report(package: str) -> Report:
    return Report(
        package_name=package,
        meta={"platform": "android", "web_observation_plan": build_plan(None, platform="android", meta={})},
        endpoints=[],
        leads=[],
        findings=[],
        analyzer_status=[],
    )


def _run_auto(tmp_path: Path, monkeypatch, package: str, *, three_rounds: bool, request: dict) -> dict:  # noqa: ANN001
    out = tmp_path / ("three" if three_rounds else "single")
    report = _report(package)
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"synthetic-only")
    monkeypatch.setattr(auto.device, "select_target_serial", lambda: "synthetic-mocked-device")
    monkeypatch.setattr(auto, "_run_doctor", lambda **_kw: {"name": "doctor", "status": "skipped", "detail": "mocked"})
    monkeypatch.setattr(auto, "_ensure_root_frida_server", lambda **_kw: None)
    monkeypatch.setattr(auto, "_run_install_app", lambda *_a, **_kw: {"name": "install", "status": "done", "detail": "mocked"})
    monkeypatch.setattr(auto, "_run_unpack", lambda *_a, **_kw: ({"name": "unpack", "status": "skipped", "detail": "mocked"}, [], None))

    def static(*_args, **_kwargs):  # noqa: ANN002, ANN003
        paths = auto._write_reports(report, out_dir=str(out), formats=["json"], base="report")
        return {"name": "static", "status": "done", "detail": "mocked context"}, report, package, paths, "report"

    monkeypatch.setattr(auto, "_run_static", static)

    def fail_capture(*_args, **kwargs):  # noqa: ANN002, ANN003
        tag = kwargs.get("pass_tag")
        if tag == "round1":
            report.meta.setdefault("web_supplement_runtime", []).append({
                "status": "executed",
                "reason": "executed",
                "round_id": "round1",
                "capture_started": True,
                "marker": "observer-started",
            })
            return {"status": "skipped", "reason": "synthetic-started"}
        if kwargs.get("web_observer") is None and three_rounds:
            raise AssertionError("observer factory was not supplied")
        raise RuntimeError("synthetic failure before observer.start")

    monkeypatch.setattr(capture, "run", fail_capture)

    def closure(current, **_kw):  # noqa: ANN001
        return (
            {"name": "closure", "status": "skipped", "detail": "mocked"},
            {"status": "partial"},
            auto._write_reports(current, out_dir=str(out), formats=["json"], base="report"),
        )

    monkeypatch.setattr(auto, "_run_closure", closure)
    auto.run(
        str(apk), out_dir=str(out), online=False, auto_fix=False, formats=["json"],
        three_rounds=three_rounds, web_supplement_request=request,
    )
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_unknown_package_records_cdp_deferred(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    payload = _run_auto(tmp_path, monkeypatch, "", three_rounds=False, request=_body())
    runtime = payload["meta"]["web_supplement_runtime"]
    assert runtime[-1]["reason"] == "cdp_deferred"
    assert runtime[-1]["execution"] == "not_executed"
    assert runtime[-1]["deferral"] == "pre_observer_failure"
    assert runtime[-1]["capture_started"] is False
    handoff = build_digest(payload)["web_observation_plan"]["agent_handoff"]
    assert handoff["why"] == "cdp_deferred"
    assert handoff["why"] != "no_web_signal"


def test_mode_off_unknown_package_stays_without_deferred(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    payload = _run_auto(tmp_path, monkeypatch, "", three_rounds=False, request=_body(mode="off"))
    assert payload["meta"].get("web_supplement_runtime") in (None, [])


def test_three_rounds_keep_started_receipt_and_defer_later_rounds(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    payload = _run_auto(tmp_path, monkeypatch, "com.example.synthetic", three_rounds=True, request=_body())
    runtime = payload["meta"]["web_supplement_runtime"]
    assert runtime[0]["marker"] == "observer-started"
    assert runtime[0]["capture_started"] is True
    deferred = [item for item in runtime if item.get("reason") == "cdp_deferred"]
    assert [item["round_id"] for item in deferred] == ["round2"]
    assert all(item["execution"] == "not_executed" for item in deferred)
    assert all(item["observer_started"] is False for item in deferred)
    assert runtime[0]["marker"] == "observer-started"


def test_native_gap_ignores_sdk_classified_domain_and_keeps_business(monkeypatch) -> None:  # noqa: ANN001
    del monkeypatch
    endpoint = Endpoint(
        value="sdk.example.test",
        kind="domain",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    business = Endpoint(
        value="app.example.test",
        kind="domain",
        evidences=[Evidence(source="dex", location="classes.dex")],
    )
    original = infra._matched_infra

    def matched(value: str) -> str | None:
        if value == endpoint.value:
            return "synthetic-sdk-rule"
        return original(value)

    with patch.object(infra, "_matched_infra", side_effect=matched):
        leads = build_endpoint_leads([endpoint], online=False)
        assert leads[0].advice == "无需调证"
        report = Report(
            package_name="com.example.synthetic",
            endpoints=[endpoint],
            leads=leads,
            findings=[],
            analyzer_status=[],
            meta={"native_lib_hashes": [{"sha256": "a" * 64}]},
        )
        payload = _to_jsonable(report)
        assert payload["endpoints"][0]["enrichment"] == {}
        assert payload["endpoints"][0]["evidences"][0]["source"] == "dex"
        handoff = project_native_handoff(payload)
        assert handoff is not None
        assert "native_hash_endpoint_gap" in handoff["reasons"]
        positive = _to_jsonable(Report(
            package_name="com.example.synthetic",
            endpoints=[business],
            leads=[],
            findings=[{"id": "DEX-STRING-POOL-OPAQUE"}],
            analyzer_status=[],
            meta={"native_lib_hashes": [{"sha256": "b" * 64}]},
        ))
        covered = project_native_handoff(positive)
        assert covered is not None
        assert "native_hash_endpoint_gap" not in covered["reasons"]
        assert "dex_string_pool_opaque" in covered["reasons"]
