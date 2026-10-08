from __future__ import annotations

import json
from pathlib import Path

from apkscan.dynamic import capture_sequence


def _report() -> dict:
    return {"meta": {"crypto_recipe": {"synthetic": True}}, "leads": []}


def test_round_interaction_is_forwarded_only_when_requested(tmp_path: Path) -> None:
    calls = []
    interactions = []

    def runner(_package: str, **kwargs):
        calls.append(kwargs)
        callback = kwargs.get("interaction")
        if callback is not None:
            interactions.append(callback())
        out = Path(kwargs["out"])
        out.mkdir(parents=True)
        (out / "runtime_report.json").write_text(
            json.dumps({"endpoints": [], "runtime_variant": "original-runtime", "capture_signals": {}}),
            encoding="utf-8",
        )
        return {"status": "done", "reason": "", "report_paths": [str(out / "runtime_report.json")]}

    records = capture_sequence.run_rounds(
        "com.example.synthetic",
        report=_report(),
        unpacked=True,
        out_dir=str(tmp_path),
        serial="device-1",
        runner=runner,
        during_round=lambda number, kind, mode, out: {"round": number, "kind": kind, "mode": mode, "out": str(out)},
    )

    assert len(records) == 3
    assert [item["round"] for item in interactions] == [1, 2, 3]
    assert all("interaction" in call for call in calls)


def test_round_interaction_is_omitted_without_driver(tmp_path: Path) -> None:
    calls = []

    def runner(_package: str, **kwargs):
        calls.append(kwargs)
        out = Path(kwargs["out"])
        out.mkdir(parents=True)
        (out / "runtime_report.json").write_text("{}", encoding="utf-8")
        return {"status": "done", "reason": "", "report_paths": []}

    capture_sequence.run_rounds(
        "com.example.synthetic", report=_report(), unpacked=True, out_dir=str(tmp_path), runner=runner
    )

    assert all("interaction" not in call for call in calls)


def test_round_interaction_forwards_absolute_deadline_when_supported(tmp_path: Path) -> None:
    observed = []

    def interaction(number, kind, mode, out, *, deadline_monotonic):
        observed.append((number, kind, deadline_monotonic))
        return {"status": "complete"}

    def runner(_package, **kwargs):
        kwargs["interaction"](deadline_monotonic=123.0)
        out = Path(kwargs["out"])
        out.mkdir(parents=True)
        (out / "runtime_report.json").write_text("{}", encoding="utf-8")
        return {"status": "done", "reason": "", "report_paths": []}

    records = capture_sequence.run_rounds(
        "com.example.synthetic", report=_report(), unpacked=True,
        out_dir=str(tmp_path), serial="device-1", runner=runner, during_round=interaction,
    )

    assert observed == [(1, "pcap", 123.0), (2, "probe", 123.0), (3, "targeted", 123.0)]
    assert [row["status"] for row in records] == ["done", "done", "done"]
