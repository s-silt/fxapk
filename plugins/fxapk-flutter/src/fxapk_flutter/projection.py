"""Static-only report projection, exact APK identity, immutable attachment output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

from apkscan.core.models import Endpoint, Evidence
from apkscan.core.report_schema import report_schema_info
from apkscan.report.json import _to_jsonable

from .evidence import FlutterError, contained, digest, read, reject_overlapping_paths, save, validate_bundle
from .index import url_candidates


def project(bundle: Path, relative: str) -> dict:
    manifest = validate_bundle(bundle)
    source = manifest["source"]
    items: dict[str, Endpoint] = {}
    for row in url_candidates(bundle):
        evidence = Evidence(
            source="derived-native", location=f"{relative}/{row['source']}:{row['line']}",
            snippet=row["value"], provenance={"producer": "fxapk-flutter", "apk_sha256": source["apk_sha256"],
                                            "binary_sha256": source["libapp"]["sha256"]},
            locator={"function_address": row["function"], "instruction_address": row["address"]},
            structure_status="parsed", reference_status="static_literal", reachability="unknown",
        )
        item = items.setdefault(row["value"], Endpoint(value=row["value"], kind="url"))
        if len(item.evidences) < 20:
            item.evidences.append(evidence)
    return {
        "metadata": {"schema_version": manifest["schema_version"], "status": "ok", "reason": "",
                     "source": source, "compatibility": manifest["compatibility"], "cache_hit": manifest["cache_hit"],
                     "coverage": manifest["coverage"], "bundle": relative, "manifest_sha256": digest(bundle / "manifest.json"),
                     "endpoint_candidates": len(items), "runtime_observed": False},
        "endpoints": list(items.values()),
    }


def attach(bundle: Path, report: Path, out: Path) -> dict:
    reject_overlapping_paths(bundle, out)
    manifest = validate_bundle(bundle)
    raw = read(report, 32 * 1024 * 1024)
    try:
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FlutterError("invalid_report") from exc
    if not isinstance(data, dict) or not report_schema_info(data).supported:
        raise FlutterError("unsupported_report_schema")
    meta = data.get("meta")
    if not isinstance(meta, dict) or meta.get("sample_sha256") != manifest["source"]["apk_sha256"]:
        raise FlutterError("report_apk_mismatch")
    if not isinstance(data.get("endpoints"), list) or not all(isinstance(item, dict) for item in data["endpoints"]):
        raise FlutterError("invalid_report")
    out.mkdir(parents=True, exist_ok=False)
    relative = "flutter/" + manifest["cache_key"]
    destination = contained(out, relative)
    shutil.copytree(bundle, destination)
    result = project(destination, relative)
    result["metadata"]["source_report"] = {"path": "source-report.json", "sha256": hashlib.sha256(raw).hexdigest(),
                                           "source_artifact_base": str(report.parent.resolve())}
    # Preserve historical projections and their original artifact base explicitly.
    if "flutter_analysis" in meta:
        result["metadata"]["previous"] = meta["flutter_analysis"]
    meta["flutter_analysis"] = result["metadata"]
    for endpoint in result["endpoints"]:
        projected = _to_jsonable(endpoint)
        old = next((x for x in data["endpoints"] if x.get("kind") == endpoint.kind and x.get("value") == endpoint.value), None)
        if old is None:
            data["endpoints"].append(projected)
        else:
            for evidence in projected["evidences"]:
                if evidence not in old.setdefault("evidences", []):
                    old["evidences"].append(evidence)
    (out / "source-report.json").write_bytes(raw)
    save(out / "report.json", data)
    return {"status": "ok", "source_apk_sha256": manifest["source"]["apk_sha256"],
            "endpoints": len(result["endpoints"]), "runtime_observed": False, "closure_evaluated": False}
