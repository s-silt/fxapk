from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.integrity import sha256_file
from apkscan.core.models import Report
from apkscan.dynamic import merge


def test_ui_observations_accumulate_across_rounds(tmp_path: Path) -> None:
    report = Report(
        package_name="com.example.synthetic",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    for index, kind in enumerate(("pcap", "probe", "targeted"), 1):
        runtime = tmp_path / f"round{index}" / "runtime_report.json"
        runtime.parent.mkdir(parents=True)
        runtime.write_text(
            json.dumps(
                {
                    "endpoints": [],
                    "runtime_variant": "original-runtime",
                    "capture_signals": {},
                    "ui_observations": [
                        {"round_id": f"round{index}", "kind": kind, "status": "complete"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        merge.merge_and_rerender(
            report,
            [],
            str(tmp_path),
            base=f"report{index}",
            runtime_report_path=str(runtime),
        )

    observations = report.meta["ui_observations"]
    assert [item["kind"] for item in observations] == ["pcap", "probe", "targeted"]
    for index, item in enumerate(observations, 1):
        runtime = tmp_path / f"round{index}" / "runtime_report.json"
        assert item["runtime_report_sha256"] == sha256_file(runtime)
        assert item["round_id"] == f"round{index}"



def test_ui_binding_is_derived_from_actual_runtime_file_and_rounds_do_not_collide(tmp_path: Path) -> None:
    report = Report(package_name="com.example.synthetic", meta={}, leads=[], endpoints=[], findings=[], analyzer_status=[])
    runtimes = []
    for run in ("run-a", "run-b"):
        runtime = tmp_path / run / "runtime_report.json"
        runtime.parent.mkdir()
        runtime.write_text(json.dumps({"endpoints": [], "capture_signals": {}, "ui_observations": [
            {"round_id": "round1", "status": "complete", "runtime_report_path": "forged.json",
             "runtime_report_sha256": "f" * 64}]}), encoding="utf-8")
        runtimes.append(runtime)
        merge.merge_and_rerender(report, [], str(tmp_path), base=run, formats=["json"], runtime_report_path=str(runtime))
    assert len(report.meta["ui_observations"]) == 2
    for observation, runtime in zip(report.meta["ui_observations"], runtimes):
        assert observation["runtime_report_path"] == str(runtime.resolve())
        assert observation["runtime_report_sha256"] == sha256_file(runtime)
    merge.merge_and_rerender(report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtimes[-1]))
    assert len(report.meta["ui_observations"]) == 2



def test_ui_observations_without_ids_are_idempotent_on_remerge(tmp_path: Path) -> None:
    report = Report(package_name="com.example.synthetic", meta={}, leads=[], endpoints=[], findings=[], analyzer_status=[])
    runtime = tmp_path / "runtime_report.json"
    runtime.write_text(json.dumps({"endpoints": [], "capture_signals": {}, "ui_observations": [
        {"status": "complete"}, {"status": "partial"}]}), encoding="utf-8")
    for _ in range(2):
        merge.merge_and_rerender(report, [], str(tmp_path), formats=["json"], runtime_report_path=str(runtime))
    assert [item["status"] for item in report.meta["ui_observations"]] == ["complete", "partial"]
