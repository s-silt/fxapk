"""Versioned contracts for optional fxapk plugins.

The core package owns these small data contracts; optional plugins must not reach
into dynamic capture internals or expose arbitrary device commands.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

PLUGIN_API_VERSION = "1"


@dataclass(frozen=True)
class CaptureRoundContext:
    serial: str
    package_name: str
    round_id: str
    round_kind: str
    out_dir: Path
    sample_sha256: str | None = None
    capture_mode: str = ""
    runtime_variant: str | None = None
    deadline_monotonic: float | None = None


@dataclass(frozen=True)
class PluginResult:
    status: Literal["ok", "partial", "failed", "unavailable"]
    reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExternalEvidenceAttachment:
    producer: str
    schema_version: str
    relative_path: str
    kind: str
    size: int
    sha256: str
    scope: str = "case_evidence"
    round_id: str | None = None
    sample_sha256: str | None = None
    runtime_report_sha256: str | None = None
    status: Literal["complete", "partial", "failed"] = "complete"


class FxapkPlugin(Protocol):
    name: str
    api_version: str

    def register_cli(self, app: Any) -> None: ...

    def capabilities(self) -> dict[str, Any]: ...


class AndroidUiPlugin(FxapkPlugin, Protocol):
    name: str
    api_version: str

    def run_round(self, context: CaptureRoundContext) -> dict[str, Any]: ...
