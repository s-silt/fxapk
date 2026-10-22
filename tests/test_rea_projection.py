"""M1：REA 脚本投影不得把未证实的位置写成唯一绑定。"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

import pytest

from fxapk_rea.evidence import import_observation, project

_ORIGIN = "http://127.0.0.1:8080"
_PAGE = f"{_ORIGIN}/"
_SCRIPT = f"{_ORIGIN}/app.js"


def test_unknown_attachment_state_is_preserved() -> None:
    payload = _payload()
    payload["data"]["normalized_result"]["target"]["attached"] = None
    raw = json.dumps(payload).encode()
    receipt, files = project(raw)
    assert receipt["target"]["attached"] is None
    assert files["rea-original.json"] == raw
    assert receipt["coverage"]["status"] == "partial"


def _artifact(text: str) -> dict[str, object]:
    raw = text.encode("utf-8")
    return {
        "text": text,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "media_type": "text/javascript",
    }


def _script(
    text: str | None,
    *,
    url: str = _SCRIPT,
    frame_id: str = "frame-1",
    start_line: int | None = None,
    start_column: int | None = None,
) -> dict[str, object]:
    if text is None:
        source: dict[str, object] = {"included": False}
    else:
        source = {"included": True, "artifact": _artifact(text)}
    row: dict[str, object] = {
        "url": url,
        "frame_id": frame_id,
        "origin": _ORIGIN,
        "source": source,
        "cdp_hash": "a" * 64,
    }
    if start_line is not None:
        row["start_line"] = start_line
        row["start_column"] = 0 if start_column is None else start_column
    return row


def _payload(
    text: str = "const value = 1;\n",
    *,
    line: int = 0,
    column: int = 0,
    initiator_type: str = "script",
    initiator_url: str | None = None,
    scripts: list[dict[str, object]] | None = None,
    frames: list[dict[str, object]] | None = None,
    page_url: str = _PAGE,
    frame_origin: str = _ORIGIN,
) -> dict[str, object]:
    return {
        "ok": True,
        "data": {
            "operation": "inspect_web_page",
            "predicate_type": "rea.web-page-inspection",
            "provider": {"id": "rea-cdp-browser", "version": "2"},
            "parameters": {
                "target_id": "synthetic-target",
                "observation_ms": 1000,
                "allowed_origins": [_ORIGIN],
            },
            "normalized_result": {
                "target": {
                    "target_id": "synthetic-target",
                    "origin": _ORIGIN,
                    "url": _PAGE,
                },
                "capture_window": {
                    "started_at": "2026-10-11T12:00:00Z",
                    "ended_at": "2026-10-11T12:00:01Z",
                    "observation_ms": 1000,
                },
                "completeness": {"status": "policy_filtered"},
                "frames": frames
                if frames is not None
                else [
                    {
                        "frame_id": "frame-1",
                        "parent_frame_id": None,
                        "url": page_url,
                        "origin": frame_origin,
                    }
                ],
                "scripts": {
                    "items": scripts if scripts is not None else [_script(text)],
                },
                "network": {
                    "requests": [
                        {
                            "request_id": "1",
                            "url": f"{_ORIGIN}/api",
                            "origin": _ORIGIN,
                            "method": "GET",
                            "status": 200,
                            "initiator": {
                                "type": initiator_type,
                                "url": _SCRIPT if initiator_url is None else initiator_url,
                                "line": line,
                                "column": column,
                            },
                        }
                    ]
                },
                "console": {"events": []},
            },
        },
    }


def _projection(payload: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    receipt, _files = project(json.dumps(payload).encode())
    initiator = receipt["requests"][0]["initiator"]
    return receipt, initiator


def _resolve(document: object, reference: str) -> object:
    assert reference.startswith("rea-original.json#/")
    current = document
    for part in reference.split("#", 1)[1][1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        assert isinstance(current, (dict, list))
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


@pytest.mark.parametrize("top,nested", [(False, False), (True, False), (False, True), (True, True)])
def test_limitations_refs_follow_key_presence(top: bool, nested: bool) -> None:
    document = _payload()
    data = document["data"]
    assert isinstance(data, dict)
    result = data["normalized_result"]
    assert isinstance(result, dict)
    if top:
        data["limitations"] = ["top"]
    if nested:
        result["limitations"] = ["nested"]
    raw = json.dumps(document).encode()
    receipt, files = project(raw)
    assert files["rea-original.json"] == raw
    refs = receipt["coverage"]["limitations_refs"]
    assert len(refs) == int(top) + int(nested)
    for ref in refs:
        _resolve(document, ref)
    assert "acquisition" not in receipt


@pytest.mark.parametrize("value", [None, []])
def test_null_or_empty_limitations_still_have_pointers(value: object) -> None:
    document = _payload()
    data = document["data"]
    assert isinstance(data, dict)
    result = data["normalized_result"]
    assert isinstance(result, dict)
    data["limitations"] = value
    result["limitations"] = value
    receipt, _files = project(json.dumps(document).encode())
    refs = receipt["coverage"]["limitations_refs"]
    assert refs == [
        "rea-original.json#/data/limitations",
        "rea-original.json#/data/normalized_result/limitations",
    ]
    for ref in refs:
        assert _resolve(document, ref) is value or _resolve(document, ref) == value


def test_generated_pointers_roundtrip() -> None:
    document = _payload()
    data = document["data"]
    assert isinstance(data, dict)
    result = data["normalized_result"]
    assert isinstance(result, dict)
    console = result["console"]
    assert isinstance(console, dict)
    console_ms = datetime.fromisoformat("2026-10-11T12:00:00+00:00").timestamp() * 1000 + 500
    console["events"] = [{"timestamp": console_ms}]
    data["limitations"] = None
    result["limitations"] = []
    receipt, _files = project(json.dumps(document).encode())
    limitation_refs = receipt["coverage"]["limitations_refs"]
    assert _resolve(document, limitation_refs[0]) is None
    assert _resolve(document, limitation_refs[1]) == []
    request = _resolve(document, receipt["requests"][0]["source_ref"])
    assert isinstance(request, dict)
    assert request["request_id"] == "1"
    assert request["url"] == f"{_ORIGIN}/api"
    script = _resolve(document, receipt["scripts"][0]["source_ref"])
    assert isinstance(script, dict)
    assert script["frame_id"] == "frame-1"
    assert script["url"] == _SCRIPT
    event = _resolve(document, receipt["console_events"][0]["source_ref"])
    assert isinstance(event, dict)
    assert event["timestamp"] == console_ms
    assert receipt["console_events"][0]["timestamp_ms"] == console_ms


@pytest.mark.parametrize("checked", [False, True])
def test_offline_import_does_not_upgrade_authentication(tmp_path, checked: bool) -> None:
    raw = json.dumps(_payload()).encode()
    source = tmp_path / "source.json"
    source.write_bytes(raw)
    expected = hashlib.sha256(raw).hexdigest() if checked else None
    out = tmp_path / "bundle"
    receipt = import_observation(source, out, expected)
    assert receipt["acquisition"] == {"kind": "offline_import"}
    assert receipt["tool_version"] is None
    assert receipt["provenance_authenticated"] is False
    assert receipt["click_attribution_verified"] is False
    assert receipt["target_app_attribution_verified"] is False
    assert receipt["closure_evaluated"] is False
    assert receipt["coverage"]["status"] == "partial"
    assert (out / "rea-original.json").read_bytes() == raw
    projected, _files = project(raw)
    assert "acquisition" not in projected


def test_only_script_initiator_binds_and_type_is_preserved() -> None:
    receipt, initiator = _projection(_payload(initiator_type="parser"))
    assert initiator["type"] == "parser"
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert initiator["frame_identity_verified"] is False
    assert initiator["binding"] == "unresolved"
    assert "initiator_type_unsupported" in receipt["coverage"]["gaps"]
    assert receipt["provenance_authenticated"] is False
    assert receipt["click_attribution_verified"] is False
    assert receipt["requests"][0]["observed_at"] is None
    assert receipt["requests"][0]["raw_body_available"] is False


def test_same_url_records_are_ambiguous_even_when_one_source_is_missing() -> None:
    text = "const value = 1;\n"
    receipt, initiator = _projection(
        _payload(scripts=[_script(text), _script(None)])
    )
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert initiator["binding"] != "unique_url_match"
    assert "initiator_source_ambiguous" in receipt["coverage"]["gaps"]


def test_unknown_duplicate_and_outside_frames_do_not_bind() -> None:
    base = _payload()
    unknown = _payload(scripts=[_script("const value = 1;\n", frame_id="missing")])
    _receipt, initiator = _projection(unknown)
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "frame_unresolved" in _receipt["coverage"]["gaps"]

    duplicated = _payload()
    frames = duplicated["data"]["normalized_result"]["frames"]
    frames.append(dict(frames[0]))
    receipt, initiator = _projection(duplicated)
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "frame_id_conflict" in receipt["coverage"]["gaps"]

    outside = _payload(
        page_url="https://outside.example.test/",
        frame_origin="https://outside.example.test",
    )
    receipt, initiator = _projection(outside)
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "frame_origin_rejected" in receipt["coverage"]["gaps"]
    assert base["data"]["normalized_result"]["network"]["requests"][0]["url"].endswith("/api")


def test_request_url_does_not_select_a_frame() -> None:
    payload = _payload(scripts=[_script("const value = 1;\n", frame_id="missing")])
    payload["data"]["normalized_result"]["frames"].append(
        {
            "frame_id": "other",
            "parent_frame_id": None,
            "url": f"{_ORIGIN}/api",
            "origin": _ORIGIN,
        }
    )
    _receipt, initiator = _projection(payload)
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None


def test_out_of_range_and_inline_without_offsets_stay_unresolved() -> None:
    receipt, initiator = _projection(_payload(line=4, column=0))
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "initiator_coordinates_out_of_range" in receipt["coverage"]["gaps"]

    inline, initiator = _projection(
        _payload(text="const value = 1;\n", scripts=[_script("const value = 1;\n", url=_PAGE)], initiator_url=_PAGE)
    )
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "initiator_inline_offsets_missing" in inline["coverage"]["gaps"]

    located, initiator = _projection(
        _payload(
            text="const value = 1;\n",
            scripts=[_script("const value = 1;\n", url=_PAGE, start_line=0, start_column=0)],
            initiator_url=_PAGE,
        )
    )
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"]
    assert initiator["binding"] == "url_candidate_unverified"
    assert initiator["frame_identity_verified"] is False
    assert "initiator_frame_identity_unverified" in located["coverage"]["gaps"]
    assert located["click_attribution_verified"] is False


def test_utf16_column_and_javascript_line_terminators() -> None:
    text = "const s = '🙂';"
    units = len(text.encode("utf-16-le")) // 2
    _receipt, initiator = _projection(_payload(text=text, line=0, column=units - 1))
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"]
    assert initiator["binding"] == "url_candidate_unverified"
    assert initiator["frame_identity_verified"] is False
    _receipt, initiator = _projection(_payload(text=text, line=0, column=units + 1))
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None

    vertical = "ab\vcd"
    column = len("ab\v".encode("utf-16-le")) // 2
    _receipt, initiator = _projection(_payload(text=vertical, line=0, column=column))
    assert initiator["candidate_script_path"]
    _receipt, initiator = _projection(_payload(text=vertical, line=1, column=0))
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None

    separated = "ab\u2028cd"
    _receipt, initiator = _projection(_payload(text=separated, line=1, column=0))
    assert initiator["candidate_script_path"]
    crlf = "ab\r\ncd"
    _receipt, initiator = _projection(_payload(text=crlf, line=1, column=1))
    assert initiator["candidate_script_path"]


def test_cdp_hash_match_does_not_verify_provenance_and_artifact_is_utf8(tmp_path) -> None:
    text = "const s = '🙂';\n"
    raw_source = text.encode("utf-8")
    payload = _payload(text=text)
    script = payload["data"]["normalized_result"]["scripts"]["items"][0]
    script["cdp_hash"] = hashlib.sha256(raw_source).hexdigest()
    body = (json.dumps(payload, ensure_ascii=False, indent=1) + "\n").encode()
    source = tmp_path / "source.json"
    source.write_bytes(body)
    out = tmp_path / "imported"
    receipt = import_observation(source, out)
    assert (out / "rea-original.json").read_bytes() == body
    artifacts = [item for item in receipt["artifacts"] if item["kind"] == "script_source"]
    assert artifacts
    assert all(item["representation"] == "rea_source_text_utf8" for item in artifacts)
    assert (out / artifacts[0]["relative_path"]).read_bytes() == raw_source
    assert receipt["scripts"][0]["cdp_hash_relation"] == "unverified"
    assert "cdp_hash_relation_unverified" in receipt["coverage"]["gaps"]
    assert receipt["coverage"]["status"] == "partial"
    assert receipt["provenance_authenticated"] is False
    assert receipt["target_app_attribution_verified"] is False


@pytest.mark.parametrize(
    ("start_line", "start_column", "line", "column"),
    [(5, 0, 2, 2), (0, 10, 0, 2)],
)
def test_inline_nonzero_offsets_do_not_become_candidates(
    start_line: int, start_column: int, line: int, column: int
) -> None:
    text = "// synthetic inline source line\n" * 10
    receipt, initiator = _projection(
        _payload(
            text=text,
            line=line,
            column=column,
            scripts=[
                _script(text, url=_PAGE, start_line=start_line, start_column=start_column)
            ],
            initiator_url=_PAGE,
        )
    )
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "initiator_inline_offset_basis_unresolved" in receipt["coverage"]["gaps"]


def test_conflicting_inline_offset_declarations_stay_unresolved() -> None:
    text = "const value = 1;\n"
    payload = _payload(
        text=text,
        scripts=[_script(text, url=_PAGE, start_line=0, start_column=0)],
        initiator_url=_PAGE,
    )
    script = payload["data"]["normalized_result"]["scripts"]["items"][0]
    script["startLine"] = 4
    script["startColumn"] = 0
    receipt, initiator = _projection(payload)
    assert initiator["script_path"] is None
    assert initiator["candidate_script_path"] is None
    assert "initiator_inline_offset_basis_unresolved" in receipt["coverage"]["gaps"]

    payload = _payload(
        text=text,
        scripts=[_script(text, url=_PAGE, start_line=0, start_column=0)],
        initiator_url=_PAGE,
    )
    script = payload["data"]["normalized_result"]["scripts"]["items"][0]
    script["source"]["start_line"] = 1
    script["source"]["start_column"] = 0
    receipt, initiator = _projection(payload)
    assert initiator["candidate_script_path"] is None
    assert "initiator_inline_offset_basis_unresolved" in receipt["coverage"]["gaps"]
