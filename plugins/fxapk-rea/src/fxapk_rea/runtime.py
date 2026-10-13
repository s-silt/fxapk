"""Local REA subprocess adapter; no downloads, navigation or browser lifecycle."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import shutil
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from apkscan.core.proctree import run_owned

from .evidence import EvidenceError, MAX_INPUT_BYTES, origin_of, read_bounded
from .rea_compat import provenance

SUPPORTED_REA = frozenset({"6.4.0"})


def validate_endpoint(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        address = ipaddress.ip_address(parsed.hostname or "")
        if (
            parsed.scheme != "http"
            or not address.is_loopback
            or not parsed.port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or any(ord(c) < 33 for c in endpoint)
        ):
            raise ValueError
    except ValueError:
        raise EvidenceError("cdp_endpoint_requires_numeric_loopback_http") from None
    return endpoint.rstrip("/")


def validate_scope(endpoint: str, target: str, origin: str) -> str:
    endpoint = validate_endpoint(endpoint)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target):
        raise EvidenceError("invalid_target_id")
    if origin_of(origin) != origin:
        raise EvidenceError("exact_origin_required")
    return endpoint


def run_bounded(
    argv: list[str],
    out: Path,
    *,
    timeout: float,
    max_stdout: int = MAX_INPUT_BYTES,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    if (
        type(max_stdout) is not int
        or not 1 <= max_stdout <= MAX_INPUT_BYTES
        or not math.isfinite(timeout)
        or not 0 < timeout <= 180
    ):
        raise EvidenceError("invalid_execution_budget")
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    helper = Path(__file__).with_name("runner.py")
    command = [sys.executable, str(helper), str(out), str(max_stdout), json.dumps(argv)]
    if env is not None:
        command.append(json.dumps(env))
    result = run_owned(command, timeout=timeout)
    tree = {key: value for key, value in asdict(result).items() if key not in ("stdout", "stderr")}
    metadata: dict[str, Any] = {
        "exit_code": None,
        "streams": {},
        "errors": ["runner_result_unavailable"],
    }
    try:
        if len(result.stdout) <= 8192:
            value = json.loads(result.stdout)
            if isinstance(value, dict):
                metadata = value
    except (ValueError, RecursionError):
        pass
    streams = metadata.get("streams", {})
    ok = (
        result.returncode == 0
        and not result.timed_out
        and result.ownership_complete
        and result.termination_complete
        and not result.forced_tree_kill
        and metadata.get("exit_code") == 0
        and not metadata.get("errors")
        and set(streams) == {"stdout", "stderr"}
        and not any(s.get("truncated") for s in streams.values())
    )
    return {**metadata, "ok": ok, "process_tree": tree}


class ReaRuntime:
    def __init__(self, executable: str | None = None, node: str | None = None):
        self.executable = executable or shutil.which("rea")
        self.node = node or shutil.which("node")

    def command(self) -> list[str]:
        if not self.executable or not Path(self.executable).is_file():
            raise EvidenceError("rea_missing")
        path = Path(self.executable).resolve()
        if path.suffix.lower() in (".cmd", ".bat"):
            raise EvidenceError("use_rea_javascript_launcher")
        if path.suffix.lower() in (".mjs", ".js", ".cjs"):
            if not self.node or not Path(self.node).is_file():
                raise EvidenceError("node_missing")
            return [str(Path(self.node).resolve()), str(path)]
        return [str(path)]

    def capabilities(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "status": "unavailable",
            "reason": "",
            "rea_version": None,
            "supported_rea_versions": sorted(SUPPORTED_REA),
            "browser": "not_probed",
            "compatibility_patch": provenance(self.executable),
            "capabilities": {"import": "available", "inspect": "unavailable"},
        }
        try:
            command = self.command()
            with tempfile.TemporaryDirectory(prefix="fxapk-rea-version-") as directory:
                out = Path(directory) / "version"
                probe = run_bounded([*command, "--version"], out, timeout=15, max_stdout=4096)
                if not probe["ok"]:
                    raise EvidenceError("rea_version_probe_failed")
                version = read_bounded(out / "stdout.bin", 4096).decode("utf-8").strip()
            if version not in SUPPORTED_REA:
                raise EvidenceError("unsupported_rea_version")
            info.update(status="ok", rea_version=version)
            info["capabilities"]["inspect"] = "available"
        except (EvidenceError, OSError, UnicodeError) as exc:
            info["reason"] = str(exc) if isinstance(exc, EvidenceError) else "runtime_probe_failed"
        return info

    def inspect(
        self,
        endpoint: str,
        target: str,
        origin: str,
        out: Path,
        *,
        observation_ms: int,
        console_text: bool = False,
    ) -> dict[str, Any]:
        endpoint = validate_scope(endpoint, target, origin)
        if type(observation_ms) is not int or not 0 <= observation_ms <= 60000:
            raise EvidenceError("invalid_observation_budget")
        args = [
            *self.command(),
            "inspect-web-page",
            endpoint,
            target,
            "--allowed-origins",
            origin,
            "--observation-ms",
            str(observation_ms),
            "--include-script-sources",
            "--include-json-body-shapes",
            "--format",
            "json",
            "--full-output",
        ]
        if console_text:
            args.append("--include-console-text")
        result = run_bounded(args, out, timeout=observation_ms / 1000 + 30)
        result["compatibility_patch"] = provenance(self.executable)
        tree = result.get("process_tree", {})
        retry_safe = (
            tree.get("ownership_complete") is True
            and tree.get("termination_complete") is True
            and not tree.get("timed_out")
            and not tree.get("forced_tree_kill")
            and not result.get("errors")
            and not any(s.get("truncated") for s in result.get("streams", {}).values())
        )
        if retry_safe and _navigation_changed(out):
            # REA intentionally refuses mixed-document inventories. Start exactly
            # one NEW window with the same target/origin; never clear its guard or
            # combine the two documents. Retain the first attempt byte for byte.
            retry = run_bounded(args, out / "after-navigation", timeout=observation_ms / 1000 + 30)
            retry["compatibility_patch"] = result["compatibility_patch"]
            retry["navigation_retry"] = {
                "reason": "target_changed",
                "scope": "new_observation_window_after_navigation",
                "previous_execution": result,
                "previous_stdout_ref": "execution/stdout.bin",
            }
            return retry
        return result


def _navigation_changed(out: Path) -> bool:
    try:
        value = json.loads(read_bounded(out / "stdout.bin"))
        data = value.get("data") if isinstance(value, dict) else None
        details = data.get("details") if isinstance(data, dict) else None
        return (
            isinstance(details, dict)
            and isinstance(data, dict)
            and data.get("code") == "target_unavailable"
            and details.get("operation") == "inspect_web_page"
            and details.get("reason") == "target_changed"
        )
    except (OSError, ValueError, EvidenceError):
        return False
