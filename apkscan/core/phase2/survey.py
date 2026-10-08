"""Bounded survey input; negative evidence needs a complete, verified capture scope.

Legacy pcap_survey endpoint lists remain useful positive observations. Only the
phase2-survey/1.0 envelope binds absence to the current immutable Phase1 packages.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Mapping

from apkscan.core.case_package import verify_case_package
from apkscan.core.integrity import sha256_hex
from apkscan.core.json_io import read_json_bounded
from apkscan.core.phase2.chain import is_sha256
from apkscan.core.phase2.inventory import InventoryLimits, Phase1EvidenceInventory

SURVEY_SCHEMA_VERSION = "phase2-survey/1.0"
# These are the legacy states with an established meaning in this repository.
# New state vocabulary requires an explicit contract change, never silent omission.
_OBSERVATION_STATES = frozenset({"established", "established_then_reset", "syn_only"})
_SURVEY_STATUSES = frozenset({"complete", "partial", "unassessed"})


class SurveyError(ValueError):
    """Invalid survey material; messages contain no input values or OS details."""


@dataclass(frozen=True)
class SurveyLimits:
    max_bytes: int = 8 * 1024 * 1024
    max_json_depth: int = 32
    max_endpoints: int = 100_000
    max_observations_per_endpoint: int = 10_000
    max_total_observations: int = 250_000
    max_capture_bindings: int = 100_000


@dataclass(frozen=True)
class SurveyAssessment:
    established_hosts: frozenset[str]
    assessment: str
    raw: bytes

    @property
    def complete(self) -> bool:
        return self.assessment == "complete"

    @property
    def sha256(self) -> str:
        return sha256_hex(self.raw)


def _ip_host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or "%" in value:
        raise SurveyError("survey endpoint has an invalid IP")
    host = value
    port = None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise SurveyError("survey endpoint has an invalid IP")
        host = value[1:end]
        suffix = value[end + 1:]
        if suffix:
            if not suffix.startswith(":"):
                raise SurveyError("survey endpoint has an invalid IP")
            port = suffix[1:]
    elif value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    if port is not None and (
        not port or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535
    ):
        raise SurveyError("survey endpoint has an invalid port")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError as exc:
        raise SurveyError("survey endpoint has an invalid IP") from exc
    if value.startswith("[") and parsed.version != 6:
        raise SurveyError("survey endpoint has an invalid IP")
    return str(parsed)


def validate_established_hosts(
    payload: object, *, limits: SurveyLimits | None = None,
    allow_unknown_states: bool = False,
) -> set[str]:
    """Validate endpoint/state shapes before extracting any positive observations."""
    bounds = limits or SurveyLimits()
    if not isinstance(payload, Mapping) or not isinstance(payload.get("endpoints"), list):
        raise SurveyError("survey must contain an endpoints array")
    endpoints = payload["endpoints"]
    if len(endpoints) > bounds.max_endpoints:
        raise SurveyError("survey endpoint limit exceeded")
    hosts = set()
    total = 0
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            raise SurveyError("survey endpoint must be an object")
        host = _ip_host(endpoint.get("ip"))
        observations = endpoint.get("observations")
        if not isinstance(observations, list) or not observations:
            raise SurveyError("survey endpoint must contain observations")
        total += len(observations)
        if len(observations) > bounds.max_observations_per_endpoint or total > bounds.max_total_observations:
            raise SurveyError("survey observation limit exceeded")
        for observation in observations:
            if not isinstance(observation, Mapping):
                raise SurveyError("survey observation must be an object")
            state = observation.get("state")
            if (not isinstance(state, str) or not state or len(state) > 128
                    or state.strip() != state or any(ord(char) < 32 or ord(char) > 126 for char in state)):
                raise SurveyError("survey observation has an invalid state")
            if not allow_unknown_states and state not in _OBSERVATION_STATES:
                raise SurveyError("survey observation has an unsupported state")
            if state.startswith("established"):
                hosts.add(host)
    return hosts


def _registered_captures(
    inventory: Phase1EvidenceInventory, case_dir: Path,
) -> tuple[dict[tuple[str, str], tuple[str, str]], set[str]]:
    """Revalidate the inventory's exact manifests; never follow a survey path."""
    expected = {}
    captured_packages = set()
    bounds = InventoryLimits()
    if inventory.issues:
        raise SurveyError("survey requires a verified Phase1 inventory")
    root = case_dir.resolve()
    for package in inventory.packages:
        package_dir = case_dir / package.directory_name
        if package_dir.is_symlink() or not package_dir.resolve().is_relative_to(root):
            raise SurveyError("survey package location is unsafe")
        manifest_path = package_dir / "case-package.json"
        try:
            manifest, raw = read_json_bounded(
                manifest_path, bounds.max_manifest_bytes, bounds.max_json_depth,
            )
            if sha256_hex(raw) != package.manifest_sha256:
                raise SurveyError("survey package changed after inventory")
            checked = verify_case_package(manifest_path)
            _, current_raw = read_json_bounded(
                manifest_path, bounds.max_manifest_bytes, bounds.max_json_depth,
            )
        except SurveyError:
            raise
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError) as exc:
            raise SurveyError("survey package cannot be verified") from exc
        if (checked.get("status") != "verified" or checked.get("package_id") != package.package_id
                or sha256_hex(current_raw) != package.manifest_sha256
                or not isinstance(manifest, Mapping)
                or manifest.get("package_id") != package.package_id
                or manifest.get("case_id") != inventory.case_id):
            raise SurveyError("survey package verification failed")
        sample = manifest.get("sample_sha256")
        if not is_sha256(sample):
            raise SurveyError("survey package has no sample identity")
        for artifact in manifest.get("artifacts", []):
            if (isinstance(artifact, Mapping) and artifact.get("scope") == "case_evidence"
                    and isinstance(artifact.get("path"), str)
                    and Path(artifact["path"]).suffix.lower() in {".pcap", ".pcapng"}):
                expected[(package.package_id, artifact["path"])] = (str(sample), str(artifact["sha256"]))
                captured_packages.add(package.package_id)
    return expected, captured_packages


def load_survey(
    path: Path, *, inventory: Phase1EvidenceInventory, case_dir: Path,
    limits: SurveyLimits | None = None,
) -> SurveyAssessment:
    bounds = limits or SurveyLimits()
    try:
        payload, raw = read_json_bounded(path, bounds.max_bytes, bounds.max_json_depth)
    except (OSError, UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise SurveyError("survey is unreadable or exceeds the JSON limits") from exc
    hosts = validate_established_hosts(
        payload, limits=bounds,
        allow_unknown_states=isinstance(payload, Mapping) and "schema_version" not in payload,
    )
    if "schema_version" not in payload:
        return SurveyAssessment(frozenset(hosts), "unassessed", raw)
    if payload.get("schema_version") != SURVEY_SCHEMA_VERSION:
        raise SurveyError("survey has an unsupported schema")
    if payload.get("case_id") != inventory.case_id:
        raise SurveyError("survey belongs to a different case")
    if payload.get("inventory_fingerprint") != inventory.fingerprint:
        raise SurveyError("survey belongs to a different inventory")
    status = payload.get("status")
    if not isinstance(status, str) or status not in _SURVEY_STATUSES:
        raise SurveyError("survey has an unsupported completeness status")
    if not isinstance(payload.get("truncated"), bool):
        raise SurveyError("survey must declare truncation")
    bindings = payload.get("capture_bindings")
    if not isinstance(bindings, list):
        raise SurveyError("survey must contain capture bindings")
    if len(bindings) > bounds.max_capture_bindings:
        raise SurveyError("survey capture binding limit exceeded")
    expected, captured_packages = _registered_captures(inventory, case_dir)
    observed = set()
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise SurveyError("survey capture binding must be an object")
        package_id = binding.get("package_id")
        sample = binding.get("sample_sha256")
        digest = binding.get("sha256")
        artifact_path = binding.get("artifact_path")
        if not all(is_sha256(value) for value in (package_id, sample, digest)) or not isinstance(artifact_path, str):
            raise SurveyError("survey capture binding is malformed")
        key = (str(package_id), artifact_path)
        if key in observed or expected.get(key) != (sample, digest):
            raise SurveyError("survey capture binding does not match a registered capture")
        observed.add(key)
    complete = status == "complete" and not payload["truncated"]
    if complete and (not inventory.packages or observed != set(expected)
                     or captured_packages != {package.package_id for package in inventory.packages}):
        raise SurveyError("complete survey must cover every registered capture and package")
    assessment = "complete" if complete else ("unassessed" if status == "unassessed" else "partial")
    return SurveyAssessment(frozenset(hosts), assessment, raw)
