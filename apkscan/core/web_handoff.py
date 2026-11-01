"""Hash-bound, offline capture metadata. Producer claims never establish ownership."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from apkscan.core.bounded_io import read_limited
from apkscan.core.models import AnalyzerResult, Evidence

SCHEMA = "fxapk.web-evidence-handoff.v1"
MAX_BYTES = 8 * 1024 * 1024
MAX_FILES = 2001
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_POINTER = re.compile(r"/log/entries/(0|[1-9][0-9]{0,5})\Z")


def _object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("handoff_duplicate_key")
        result[key] = value
    return result


def _capture(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("handoff_capture_invalid")
    if value.get("complete") is not None and type(value["complete"]) is not bool:
        raise ValueError("handoff_complete_invalid")
    for field, allowed in (
        ("tls_verification", ("verified", "required", "ignored", "unknown", "not_applicable")),
        ("request_association", ("known", "unknown")),
    ):
        if value.get(field, "unknown") not in allowed:
            raise ValueError("handoff_capture_invalid")
    return value


def load_handoff(path: Path, ctx: Any) -> None:
    """Bind to the bytes actually loaded, not a second filesystem read."""
    if path.resolve().is_relative_to(Path(ctx.source_dir).resolve()) or path.is_symlink():
        raise ValueError("handoff_must_be_external_regular_file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("handoff_must_be_external_regular_file")
        raw = read_limited(stream, MAX_BYTES)
    if len(raw) > MAX_BYTES:
        raise ValueError("handoff_size_limit")
    data = json.loads(raw, object_pairs_hook=_object,
                      parse_constant=lambda _: _invalid_json())
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA:
        raise ValueError("handoff_schema_invalid")
    rows = data.get("files")
    if not isinstance(rows, list) or len(rows) > MAX_FILES:
        raise ValueError("handoff_files_invalid")
    sources = {value["source_path"]: (key, value) for key, value in ctx.evidence_sources.items()}
    bound, seen, unloaded = {}, set(), []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("handoff_file_invalid")
        name, digest, size = row.get("path"), row.get("sha256"), row.get("size")
        if (not isinstance(name, str) or not name or "\\" in name or "#" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or PurePosixPath(name).is_absolute() or ":" in name
                or name in seen or not isinstance(digest, str) or not _SHA.fullmatch(digest)
                or type(size) is not int or size < 0):
            raise ValueError("handoff_file_identity_invalid")
        seen.add(name)
        _capture(row.get("capture"))
        if not isinstance(row.get("source"), dict):
            raise ValueError("handoff_source_invalid")
        entries = row.get("entries", [])
        if not isinstance(entries, list) or len(entries) > 1000:
            raise ValueError("handoff_entries_invalid")
        pointers = set()
        for entry in entries:
            pointer = entry.get("pointer") if isinstance(entry, dict) else None
            if (not isinstance(pointer, str) or not _POINTER.fullmatch(pointer)
                    or pointer in pointers or not isinstance(entry.get("source"), dict)):
                raise ValueError("handoff_entry_invalid")
            pointers.add(pointer)
            _capture(entry.get("capture"))
        if name not in sources:
            unloaded.append(name)
            continue
        key, actual = sources[name]
        if digest != actual["source_sha256"] or size != actual["source_size"]:
            raise ValueError("handoff_content_mismatch")
        bound[key] = row
    if sources.keys() - seen:
        raise ValueError("handoff_unlisted_input")
    coverage = data.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("handoff_coverage_invalid")
    ctx.evidence_handoff = bound
    ctx.handoff_receipt = {
        "schema_version": SCHEMA, "sha256": hashlib.sha256(raw).hexdigest(),
        "bound_files": len(bound), "unloaded_files": unloaded,
        "upstream_coverage": coverage, "authenticity_verified": False,
        "target_app_attribution_verified": False,
    }


def coverage_summary(ctx: Any) -> dict:
    receipt = getattr(ctx, "handoff_receipt", {})
    if not receipt:
        return {}
    rows = list(ctx.evidence_handoff.values())
    return {
        "status": "partial", "handoff_sha256": receipt["sha256"],
        "bound_files": receipt["bound_files"],
        "truncated_files": sum(row["capture"].get("complete") is False for row in rows),
        "unloaded_files": len(receipt["unloaded_files"]),
        "upstream_coverage": copy.deepcopy(receipt["upstream_coverage"]),
        "blocked_claims": ["web_capture_exhaustive", "target_app_runtime_attribution"],
    }


def _invalid_json() -> None:
    raise ValueError("handoff_nonfinite_json")


def _suspicions(capture: dict) -> list[dict]:
    reasons = []
    if capture.get("complete") is False:
        reasons.append("capture_truncated")
    if capture.get("tls_verification") == "ignored":
        reasons.append("capture_tls_unverified")
    if capture.get("request_association", "unknown") != "known":
        reasons.append("capture_request_association_unknown")
    if capture.get("representation") == "browser_rendered_dom":
        reasons.append("capture_rendered_dom")
    return [{"kind": reason} for reason in reasons]


def bind_evidence(ctx: Any, evidence: Evidence) -> None:
    path, _, fragment = evidence.location.partition("#")
    facts = getattr(ctx, "evidence_sources", {}).get(path)
    if facts is None:
        return
    evidence.provenance = {**evidence.provenance, **copy.deepcopy(facts)}
    handoff = getattr(ctx, "evidence_handoff", {}).get(path)
    if handoff is None:
        return
    binding = {"handoff_sha256": ctx.handoff_receipt["sha256"],
               "source": copy.deepcopy(handoff["source"]),
               "capture": copy.deepcopy(handoff["capture"]),
               "authenticity_verified": False, "target_app_attribution_verified": False}
    for entry in handoff.get("entries", []):
        if fragment == entry["pointer"] or fragment.startswith(entry["pointer"] + "/"):
            binding["entry"] = copy.deepcopy(entry)
            binding["capture"] = copy.deepcopy(entry["capture"])
            break
    evidence.provenance["capture_handoff"] = binding
    for suspicion in _suspicions(binding["capture"]):
        if suspicion not in evidence.suspicions:
            evidence.suspicions.append(suspicion)


def bind_result(ctx: Any, result: AnalyzerResult) -> None:
    def bind(evidence: Evidence) -> None:
        bind_evidence(ctx, evidence)
        facts = result.evidence_inputs.get(evidence.location)
        if facts:
            evidence.provenance.update(copy.deepcopy(facts))
            if evidence.locator:
                evidence.locator["offset_scope"] = "decoded-har-body"
                evidence.locator["json_pointer"] = facts["entry_ref"].split("#", 1)[1] + "/response/content/text"
            if facts.get("body_truncated") is True:
                marker = {"kind": "capture_truncated"}
                if marker not in evidence.suspicions:
                    evidence.suspicions.append(marker)

    for endpoint in result.endpoints:
        for evidence in endpoint.evidences:
            bind(evidence)
    for finding in result.findings:
        for evidence in finding.evidences:
            bind(evidence)
    for lead in result.leads:
        for evidence in lead.source_refs:
            bind(evidence)
