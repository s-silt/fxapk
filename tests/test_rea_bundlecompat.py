"""旧 CDP 观察回执与当前投影的字段契约。"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from fxapk_rea.bundlecompat import TRACE_SESSION_REVISION, assess
from fxapk_rea.trace import project_trace

_MATRIX = Path(__file__).parents[1] / "out_rea_trace_20261012" / "live-matrix.json"


def _historical() -> tuple[dict[str, object], dict[str, object]]:
    if not _MATRIX.is_file():
        pytest.skip("historical live matrix is not on this machine")
    rows = json.loads(_MATRIX.read_text(encoding="utf-8"))
    bundle = Path(rows[0]["run_dir"]) / "bundle"
    observation = bundle / "observation.json"
    raw_path = bundle / "cdp-trace-original.json"
    if not observation.is_file() or not raw_path.is_file():
        pytest.skip("historical live bundle is not on this machine")
    saved = json.loads(observation.read_text(encoding="utf-8"))
    fresh, _files = project_trace(raw_path.read_bytes())
    return saved, fresh


def test_historical_v1_allows_only_listed_additions_and_gap_order() -> None:
    saved, fresh = _historical()
    result = assess(saved, fresh)
    assert result.ok is True
    assert result.gap_reordered is True
    assert result.added_paths
    assert all(
        path.endswith("/session_id") or path.endswith("/target_id") for path in result.added_paths
    )
    assert any(path.startswith("requests[") and path.endswith("/session_id") for path in result.added_paths)
    assert any("/hops[" in path and path.endswith("/session_id") for path in result.added_paths)


@pytest.mark.parametrize(
    "mutate",
    ["requests", "capture", "source", "hop_bridge", "hop_frame", "request_url", "unknown"],
)
def test_historical_v1_rejects_deleted_or_changed_fields(mutate: str) -> None:
    saved, fresh = _historical()
    if mutate == "requests":
        del saved["requests"]
    elif mutate == "capture":
        del saved["capture"]
    elif mutate == "source":
        del saved["source"]
    elif mutate == "hop_bridge":
        del saved["requests"][0]["hops"][0]["observed_identity_bridge"]
    elif mutate == "hop_frame":
        del saved["requests"][0]["hops"][0]["frame_id"]
    elif mutate == "request_url":
        saved["requests"][0]["hops"][0]["url"] = "http://127.0.0.1/tampered"
    else:
        fresh = copy.deepcopy(fresh)
        fresh["unlisted_field"] = {"status": "partial"}
    assert assess(saved, fresh).ok is False


def test_session_revision_makes_new_identity_required() -> None:
    saved, fresh = _historical()
    saved = copy.deepcopy(saved)
    fresh = copy.deepcopy(fresh)
    saved["projection_revision"] = TRACE_SESSION_REVISION
    fresh["projection_revision"] = TRACE_SESSION_REVISION
    assert assess(saved, fresh).ok is False
    for request in saved["requests"]:
        match = next(item for item in fresh["requests"] if item["request_id"] == request["request_id"])
        request["session_id"] = match["session_id"]
        request["target_id"] = match["target_id"]
        for hop, fresh_hop in zip(request["hops"], match["hops"], strict=True):
            hop["session_id"] = fresh_hop["session_id"]
    result = assess(saved, fresh)
    assert result.ok is True
    assert not any(path.endswith("/session_id") or path.endswith("/target_id") for path in result.added_paths)


def test_revision_must_match_and_be_known() -> None:
    saved, fresh = _historical()
    fresh = copy.deepcopy(fresh)
    fresh["projection_revision"] = TRACE_SESSION_REVISION
    assert assess(saved, fresh).ok is False
    saved = copy.deepcopy(saved)
    saved["projection_revision"] = "trace-v1-unknown"
    fresh["projection_revision"] = "trace-v1-unknown"
    assert assess(saved, fresh).ok is False
