"""Bounded REA projections. Original bytes are authoritative, never rewritten."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.rea_intake import write_rea_bundle_marker

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 4096
SOURCE_REF = "rea-original.json#/data/normalized_result"


class EvidenceError(ValueError):
    """Stable public reason code, without untrusted source values."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(value: bool, code: str = "invalid_rea_contract") -> None:
    if not value:
        raise EvidenceError(code)


def _object(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict))
    return value


def _array(value: Any) -> list[Any]:
    _require(isinstance(value, list) and len(value) <= MAX_ITEMS)
    return value


def _text(value: Any) -> str:
    _require(
        isinstance(value, str) and 0 < len(value) <= 8192 and not any(ord(c) < 32 for c in value)
    )
    return value


def origin_of(value: Any) -> str:
    text = _text(value)
    try:
        parsed = urlsplit(text)
        _require(parsed.scheme in ("http", "https") and bool(parsed.hostname))
        _require(parsed.username is None and parsed.password is None)
        _ = parsed.port
        return f"{parsed.scheme}://{parsed.netloc.lower()}"
    except ValueError:
        raise EvidenceError("invalid_url") from None


def timestamp(value: Any) -> float:
    try:
        date = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
        _require(date.utcoffset() is not None, "timestamp_timezone_missing")
        return date.timestamp() * 1000
    except (ValueError, OverflowError):
        raise EvidenceError("invalid_timestamp") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(_: str) -> Any:
    raise EvidenceError("nonfinite_json_number")


def _javascript_lines(text: str) -> list[str]:
    """按 JS 行终止符切分。不使用 ``str.splitlines``，避免把 VT/FF 当成换行。"""
    lines: list[str] = []
    start = 0
    index = 0
    limit = len(text)
    while index < limit:
        if text.startswith("\r\n", index):
            lines.append(text[start:index])
            index += 2
            start = index
            continue
        if text[index] in "\n\r\u2028\u2029":
            lines.append(text[start:index])
            index += 1
            start = index
            continue
        index += 1
    lines.append(text[start:])
    return lines


def _utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _origin_matches(url: Any, origin: Any) -> bool:
    if not isinstance(origin, str):
        return False
    try:
        return origin_of(url) == origin
    except EvidenceError:
        return False


def _script_offsets(item: dict[str, Any]) -> tuple[int, int] | None | str:
    """内联偏移没有 v2 坐标基准契约。

    没有任何声明时返回 None。全部声明都是 0,0 时返回该对。
    非零、残缺、类型不对，或 snake/camel、条目/source 彼此不一致时返回 ``unresolved``。
    不取第一对，也不把偏移减进发起者坐标。
    """
    containers: list[dict[str, Any]] = [item]
    source = item.get("source")
    if isinstance(source, dict):
        containers.append(source)
    found: list[tuple[int, int]] = []
    for container in containers:
        for line_key, column_key in (
            ("start_line", "start_column"),
            ("startLine", "startColumn"),
        ):
            if line_key not in container and column_key not in container:
                continue
            line = container.get(line_key)
            column = container.get(column_key)
            if type(line) is not int or type(column) is not int or line < 0 or column < 0:
                return "unresolved"
            found.append((line, column))
    if not found:
        return None
    if any(pair != (0, 0) for pair in found):
        return "unresolved"
    return (0, 0)


def _frame_records(result: dict[str, Any]) -> list[dict[str, Any]]:
    if "frames" not in result:
        return []
    raw = result["frames"]
    if isinstance(raw, dict):
        raw = raw.get("items")
    return [_object(item) for item in _array(raw)]


def _frame_gap(
    fact: dict[str, Any],
    frames_by_id: dict[str, list[dict[str, Any]]],
    origins: list[Any],
) -> str | None:
    frame_id = fact.get("frame_id")
    if not isinstance(frame_id, str) or not frame_id:
        return "frame_unresolved"
    matches = frames_by_id.get(frame_id, [])
    if not matches:
        return "frame_unresolved"
    if len(matches) > 1:
        return "frame_id_conflict"
    frame = matches[0]
    origin = frame.get("origin")
    if origin not in origins or not _origin_matches(frame.get("url"), origin):
        return "frame_origin_rejected"
    script_origin = fact.get("origin")
    if isinstance(script_origin, str) and script_origin != origin:
        return "frame_origin_rejected"
    if not _origin_matches(fact.get("url"), origin):
        return "frame_origin_rejected"
    return None


def _unresolved(gap: str) -> tuple[None, None, str, bool, str]:
    return None, None, "unresolved", False, gap


def _bind_initiator(
    initiator: dict[str, Any],
    facts: list[dict[str, Any]],
    frames_by_id: dict[str, list[dict[str, Any]]],
    origins: list[Any],
) -> tuple[str | None, str | None, str, bool, str | None]:
    """坐标核对通过也只产生未验证的 URL 候选，不证明请求所在 frame。

    返回 ``script_path, candidate_script_path, binding, frame_identity_verified, gap``。
    """
    if initiator.get("type") != "script":
        return _unresolved("initiator_type_unsupported")
    same = [fact for fact in facts if fact["url"] == initiator.get("url")]
    if len(same) != 1:
        return _unresolved("initiator_source_ambiguous")
    fact = same[0]
    if not fact.get("artifact_path") or not isinstance(fact.get("text"), str):
        return _unresolved("initiator_source_unresolved")
    frame_problem = _frame_gap(fact, frames_by_id, origins)
    if frame_problem is not None:
        return _unresolved(frame_problem)
    frame = frames_by_id[fact["frame_id"]][0]
    if fact["url"] == frame.get("url"):
        offsets = fact.get("offsets")
        if offsets is None:
            return _unresolved("initiator_inline_offsets_missing")
        # 只有明确一致的 0,0 才继续核对捕获源码。非零偏移没有可减的基准。
        if offsets != (0, 0):
            return _unresolved("initiator_inline_offset_basis_unresolved")
    line = initiator.get("line")
    column = initiator.get("column")
    if type(line) is not int or type(column) is not int:
        return _unresolved("initiator_coordinates_missing")
    rows = _javascript_lines(fact["text"])
    if line >= len(rows) or column > _utf16_units(rows[line]):
        return _unresolved("initiator_coordinates_out_of_range")
    return (
        None,
        fact["artifact_path"],
        "url_candidate_unverified",
        False,
        "initiator_frame_identity_unverified",
    )


def parse_json(raw: bytes) -> dict[str, Any]:
    _require(0 < len(raw) <= MAX_INPUT_BYTES, "input_size_limit")
    try:
        payload = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_nonfinite
        )
        stack = [(payload, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            _require(nodes <= 100000 and depth <= 48, "json_complexity_limit")
            if isinstance(value, str):
                value.encode("utf-8")
            if isinstance(value, float):
                _require(math.isfinite(value), "nonfinite_json_number")
            if isinstance(value, (list, dict)):
                if isinstance(value, dict):
                    for key in value:
                        key.encode("utf-8")
                _require(len(value) <= MAX_ITEMS, "collection_size_limit")
                stack.extend(
                    (child, depth + 1)
                    for child in (value.values() if isinstance(value, dict) else value)
                )
        return _object(payload)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("invalid_json") from None


def read_bounded(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    _require(path.is_file() and not path.is_symlink(), "input_not_regular_file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, "input_size_limit")
    return raw


def project(raw: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    payload = parse_json(raw)
    _require(payload.get("ok") is True, "rea_operation_failed")
    data = _object(payload.get("data"))
    _require(
        data.get("operation") == "inspect_web_page"
        and data.get("predicate_type") == "rea.web-page-inspection",
        "unsupported_operation",
    )
    provider = _object(data.get("provider"))
    _require(
        provider.get("id") == "rea-cdp-browser" and provider.get("version") == "2",
        "unsupported_provider",
    )
    params = _object(data.get("parameters"))
    result = _object(data.get("normalized_result"))
    target = _object(result.get("target"))
    target_id = _text(target.get("target_id"))
    _require(target_id == params.get("target_id"), "target_binding_mismatch")
    origins = _array(params.get("allowed_origins"))
    _require(0 < len(origins) <= 16)
    for origin in origins:
        _require(origin_of(origin) == origin, "invalid_origin")
    _require(
        target.get("origin") in origins and origin_of(target.get("url")) == target.get("origin"),
        "target_origin_mismatch",
    )
    window = _object(result.get("capture_window"))
    start, end = timestamp(window.get("started_at")), timestamp(window.get("ended_at"))
    _require(start <= end, "invalid_window_order")
    duration = window.get("observation_ms")
    _require(
        type(duration) is int
        and 0 <= duration <= 60000
        and type(params.get("observation_ms")) is int
        and duration == params["observation_ms"],
        "window_duration_mismatch",
    )
    completeness = _object(result.get("completeness"))
    _text(completeness.get("status"))
    gaps = {
        "raw_network_bodies_unavailable",
        "per_request_time_unavailable",
        "target_app_identity_unverified",
        "click_attribution_unverified",
    }
    files = {"rea-original.json": raw}
    scripts = []
    script_facts: list[dict[str, Any]] = []
    for index, item in enumerate(_array(_object(result.get("scripts")).get("items"))):
        item = _object(item)
        _require(origin_of(item.get("url")) in origins, "script_origin_mismatch")
        row = {
            "url": item["url"],
            "frame_id": item.get("frame_id"),
            "source_ref": f"{SOURCE_REF}/scripts/items/{index}",
            "artifact_path": None,
            # CDP hash 没有已证实的 UTF-8 等价契约，相等也不认证来源。
            "cdp_hash_relation": "unverified",
        }
        if isinstance(item.get("cdp_hash"), str):
            gaps.add("cdp_hash_relation_unverified")
        else:
            gaps.add("cdp_hash_unavailable")
        source = _object(item.get("source"))
        captured: str | None = None
        if source.get("included") is True:
            artifact = _object(source.get("artifact"))
            _require(isinstance(artifact.get("text"), str), "script_text_missing")
            try:
                content = artifact["text"].encode("utf-8")
            except UnicodeError:
                raise EvidenceError("invalid_script_encoding") from None
            sha = digest(content)
            _require(
                type(artifact.get("bytes")) is int and artifact["bytes"] == len(content),
                "script_size_mismatch",
            )
            _require(artifact.get("sha256") == sha, "script_hash_mismatch")
            path = f"scripts/{sha}.js"
            files[path] = content
            row["artifact_path"] = path
            captured = artifact["text"]
        else:
            gaps.add("script_source_unavailable")
        scripts.append(row)
        script_facts.append(
            {
                "url": item["url"],
                "frame_id": item.get("frame_id"),
                "origin": item.get("origin") if isinstance(item.get("origin"), str) else None,
                "text": captured,
                "artifact_path": row["artifact_path"],
                "offsets": _script_offsets(item),
            }
        )
    frames_by_id: dict[str, list[dict[str, Any]]] = {}
    for frame in _frame_records(result):
        frame_id = frame.get("frame_id")
        if isinstance(frame_id, str) and frame_id:
            frames_by_id.setdefault(frame_id, []).append(frame)
    requests, request_ids = [], set()
    for index, item in enumerate(_array(_object(result.get("network")).get("requests"))):
        item = _object(item)
        identity = _text(item.get("request_id"))
        _require(identity not in request_ids, "duplicate_request_id")
        request_ids.add(identity)
        _require(
            origin_of(item.get("url")) in origins and origin_of(item["url"]) == item.get("origin"),
            "request_origin_mismatch",
        )
        method = _text(item.get("method"))
        _require(re.fullmatch(r"[A-Z]{1,32}", method) is not None)
        status = item.get("status")
        _require(status is None or (type(status) is int and 0 <= status <= 599))
        initiator = _object(item.get("initiator"))
        for field in ("line", "column"):
            coordinate = initiator.get(field)
            _require(
                coordinate is None or (type(coordinate) is int and coordinate >= 0),
                "invalid_source_coordinate",
            )
        linked, candidate, binding, frame_verified, problem = _bind_initiator(
            initiator, script_facts, frames_by_id, origins
        )
        if problem is not None:
            gaps.add(problem)
        requests.append(
            {
                "request_id": identity,
                "url": item["url"],
                "method": method,
                "status": status,
                "observed_at": None,
                "raw_body_available": False,
                "source_ref": f"{SOURCE_REF}/network/requests/{index}",
                "initiator": {
                    "type": initiator.get("type"),
                    "url": initiator.get("url"),
                    "line_zero_based": initiator.get("line"),
                    "column_zero_based": initiator.get("column"),
                    "script_path": linked,
                    "candidate_script_path": candidate,
                    "binding": binding,
                    "frame_identity_verified": frame_verified,
                },
            }
        )
    events = []
    for index, item in enumerate(_array(_object(result.get("console")).get("events"))):
        item = _object(item)
        value = item.get("timestamp")
        # Reject booleans, huge integers and non-calendar values before float conversion.
        numeric_time: float | None = None
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and 0 < value < 253402300800000
        ):
            numeric_time = float(value)
        membership = (
            ("inside" if start <= numeric_time <= end else "outside")
            if numeric_time is not None
            else "unknown"
        )
        if membership != "inside":
            gaps.add(
                "console_outside_window" if membership == "outside" else "console_time_unknown"
            )
        events.append(
            {
                "source_ref": f"{SOURCE_REF}/console/events/{index}",
                "timestamp_ms": numeric_time,
                "window_membership": membership,
            }
        )
    receipt = {
        "schema_version": "rea-web-observation/1",
        "producer": "rea",
        "status": "ok",
        "source": {"relative_path": "rea-original.json", "size": len(raw), "sha256": digest(raw)},
        "provider": {"id": provider["id"], "version": provider["version"]},
        "tool_version": None,
        "imported_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "allowed_origins": origins,
        "capture_window": window,
        "coverage": {
            "status": "partial",
            "gaps": sorted(gaps),
            "provider_completeness": completeness,
            "limitations_refs": [
                ref
                for ref, present in (
                    ("rea-original.json#/data/limitations", "limitations" in data),
                    (f"{SOURCE_REF}/limitations", "limitations" in result),
                )
                if present
            ],
        },
        "scripts": scripts,
        "requests": requests,
        "console_events": events,
        "target_app_attribution_verified": False,
        "click_attribution_verified": False,
        "closure_evaluated": False,
        "provenance_authenticated": False,
    }
    return receipt, files


def claim_output(out: Path) -> None:
    for path in (out, *out.parents):
        _require(
            not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(),
            "output_link_forbidden",
        )
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise EvidenceError("output_exists_refuse_overwrite") from None
    # 标记必须先于 rea-original / scripts / execution。失败或只写了部分产物时，
    # 入口仍能认出这个目录；不删除已经留下的字节。
    try:
        write_rea_bundle_marker(out)
    except OSError:
        raise EvidenceError("bundle_marker_unwritable") from None


def publish(out: Path, receipt: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    attachments = []
    for name, raw in files.items():
        if not atomic_create_bytes(out / name, raw):
            raise EvidenceError("artifact_exists_refuse_overwrite")
        kind = "original_json" if name == "rea-original.json" else "script_source"
        attachment = {
            "producer": "rea",
            "schema_version": "rea-web-observation/1",
            "relative_path": name,
            "kind": kind,
            "size": len(raw),
            "sha256": digest(raw),
            "scope": "unverified_external_observation",
        }
        if kind == "script_source":
            # 提供方源码字符串的 UTF-8，不是 HTTP 响应原始字节。
            attachment["representation"] = "rea_source_text_utf8"
        attachments.append(attachment)
    receipt["artifacts"] = attachments
    encoded = (json.dumps(receipt, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if not atomic_create_bytes(out / "observation.json", encoded):
        raise EvidenceError("receipt_exists_refuse_overwrite")
    return receipt


def import_observation(
    source: Path, out: Path, expected_sha256: str | None = None
) -> dict[str, Any]:
    _require(not out.exists(), "output_exists_refuse_overwrite")
    raw = read_bounded(source)
    if expected_sha256 is not None:
        _require(
            re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256) is not None
            and digest(raw) == expected_sha256.lower(),
            "source_hash_mismatch",
        )
    receipt, files = project(raw)
    receipt["acquisition"] = {"kind": "offline_import"}
    claim_output(out)
    return publish(out, receipt, files)
