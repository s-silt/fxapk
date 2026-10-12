"""Multi-hop legacy frame identity and legacy migration outside the added-field budget."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fxapk_rea.bundlecompat import assess
from tests.test_rea_review_phase6 import _plugin, _publish_legacy, _raw_cross_frame
from tests.test_rea_trace_extended import _call, _ctx, _envelope, _parsed, _request, _source


@pytest.fixture
def plugin_src(monkeypatch: pytest.MonkeyPatch) -> Path:
    src = Path(__file__).parents[1] / "plugins" / "fxapk-rea" / "src"
    monkeypatch.syspath_prepend(str(src))
    return src


def _two_hop_raw() -> bytes:
    raw = json.loads(_raw_cross_frame())
    redirect = _request(
        "req",
        "FRAME-C",
        6,
        {"callFrames": [], "parent": {"callFrames": [_call("9", 0, 0, "parent")]}},
        loader="LOAD-C",
    )
    redirect["params"]["redirectResponse"] = {
        "url": raw["events"][-1]["params"]["request"]["url"],
        "status": 302,
    }
    redirect["params"]["request"]["url"] += "?redirected=1"
    raw["events"].append(_ctx(3, "u3", "FRAME-C", 5))
    raw["events"].append(redirect)
    return json.dumps(raw).encode()


def test_multi_hop_root_migrates_only_with_first_hop(plugin_src: Path, tmp_path: Path) -> None:
    trace, attachment = _plugin(plugin_src)
    raw = _two_hop_raw()
    fresh, _files = trace.project_trace(raw)
    request = fresh["requests"][0]
    assert len(request["hops"]) == 2
    assert request["hops"][0]["frame_id"] != request["hops"][1]["frame_id"]
    assert request["stack_groups"] == request["hops"][0]["stack_groups"]
    bundle, observation = _publish_legacy(plugin_src, tmp_path, raw, "two-hop")
    compat = assess(json.loads(observation), fresh)
    assert compat.ok is True
    assert compat.legacy_frame_paths
    assert "script_frame_id" not in "".join(compat.added_paths)
    report = tmp_path / "input.json"
    report.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {},
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }), encoding="utf-8")
    attached = attachment.attach(bundle, report, tmp_path / "attached")
    copied = tmp_path / "attached" / "external_observations" / attached["source_sha256"]
    assert (copied / "observation.json").read_bytes() == observation
    forged = json.loads(observation)
    forged["requests"][0]["stack_groups"][1]["frames"][0]["frame_id"] = request["hops"][1]["frame_id"]
    assert assess(forged, fresh).ok is False
    forged_hop = json.loads(observation)
    forged_hop["requests"][0]["hops"][1]["frame_id"] = "FRAME-FORGED"
    assert assess(forged_hop, fresh).ok is False


def _many(count: int, depth: int = 1) -> bytes:
    events = [_ctx(1, "u1", "FRAME-A", 1), _ctx(2, "u2", "FRAME-B", 2), _parsed("9", 2, 3)]
    events.extend(
        _request(
            f"req{index}",
            "FRAME-A",
            index + 4,
            {"callFrames": [], "parent": {"callFrames": [_call("9", 0, 0, "parent") for _ in range(depth)]}},
            loader="LOAD-A",
        )
        for index in range(count)
    )
    return _envelope(events, [_source("9", 3, 2, "function parent(){return 1}\n")])


def test_legacy_script_frames_do_not_spend_added_field_budget(
    plugin_src: Path, tmp_path: Path,
) -> None:
    trace, attachment = _plugin(plugin_src)
    report = tmp_path / "input.json"
    report.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {},
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }), encoding="utf-8")
    for count in (33, 40):
        raw = _many(count)
        fresh, _files = trace.project_trace(raw)
        bundle, observation = _publish_legacy(plugin_src, tmp_path, raw, f"budget-{count}")
        compat = assess(json.loads(observation), fresh)
        assert compat.ok is True
        assert len(compat.added_paths) <= 64
        assert len(compat.legacy_frame_paths) == count * 2
        out = tmp_path / f"out-{count}"
        summary = attachment.attach(bundle, report, out)
        stored = out / "external_observations" / summary["source_sha256"] / "observation.json"
        assert stored.read_bytes() == observation
        assert summary["closure_evaluated"] is False
    tampered = json.loads((tmp_path / "budget-33" / "observation.json").read_bytes())
    tampered["requests"][0]["hops"][0]["stack_groups"][1]["frames"][0]["frame_id"] = "FRAME-FORGED"
    (tmp_path / "budget-33" / "observation.json").write_text(json.dumps(tampered), encoding="utf-8")
    rejected = tmp_path / "rejected-frame"
    with pytest.raises(attachment.AttachError):
        attachment.attach(tmp_path / "budget-33", report, rejected)
    assert not rejected.exists()
    extra = json.loads((tmp_path / "budget-40" / "observation.json").read_bytes())
    extra["requests"][0]["unrelated_added"] = "synthetic"
    (tmp_path / "budget-40" / "observation.json").write_text(json.dumps(extra), encoding="utf-8")
    rejected_extra = tmp_path / "rejected-extra"
    with pytest.raises(attachment.AttachError):
        attachment.attach(tmp_path / "budget-40", report, rejected_extra)
    assert not rejected_extra.exists()
    source = tmp_path / "budget-33" / "cdp-trace-original.json"
    source.write_bytes(source.read_bytes() + b" ")
    rejected_source = tmp_path / "rejected-source"
    with pytest.raises(attachment.AttachError):
        attachment.attach(tmp_path / "budget-33", report, rejected_source)
    assert not rejected_source.exists()


def test_many_async_frames_migrate_without_a_path_cap(plugin_src: Path, tmp_path: Path) -> None:
    trace, attachment = _plugin(plugin_src)
    raw = _many(350, 3)
    fresh, _files = trace.project_trace(raw)
    bundle, indented = _publish_legacy(plugin_src, tmp_path, raw, "budget-350")
    # 缩进投影超过既有 2MiB 观察读取上限。紧凑编码保留全部字段，不截断证据。
    observation = (
        json.dumps(json.loads(indented), ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    assert len(observation) <= 2 * 1024 * 1024
    (bundle / "observation.json").write_bytes(observation)
    compat = assess(json.loads(observation), fresh)
    assert compat.ok is True
    assert len(compat.added_paths) <= 64
    assert len(compat.legacy_frame_paths) == 2100
    report = tmp_path / "input.json"
    report.write_text(json.dumps({
        "package_name": "com.example.synthetic",
        "meta": {},
        "endpoints": [],
        "leads": [],
        "findings": [],
        "analyzer_status": [],
    }), encoding="utf-8")
    out = tmp_path / "attached-350"
    summary = attachment.attach(bundle, report, out)
    stored = out / "external_observations" / summary["source_sha256"]
    assert (stored / "observation.json").read_bytes() == observation
    record = json.loads((stored / "projection-record.json").read_text(encoding="utf-8"))
    assert record["certification_upgraded"] is False
    assert len(record["legacy_frame_paths"]) == 2100
    forged = json.loads(observation)
    forged["requests"][0]["hops"][0]["stack_groups"][1]["frames"][0]["frame_id"] = "FRAME-FORGED"
    (bundle / "observation.json").write_bytes(
        (json.dumps(forged, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()
    )
    rejected = tmp_path / "rejected-350"
    with pytest.raises(attachment.AttachError):
        attachment.attach(bundle, report, rejected)
    assert not rejected.exists()
    assert (stored / "observation.json").read_bytes() == observation
