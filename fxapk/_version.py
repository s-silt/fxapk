"""Version provenance shared by package initialization, diagnostics and new reports.

The source declaration travels inside wheels too; it is not a source hash or proof
of a clean checkout. Never use the current runtime to backfill historical reports.
"""
from __future__ import annotations

import importlib.metadata as metadata
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VersionProvenance:
    effective_version: str
    source_version: str | None
    distribution_version: str | None
    distribution_status: str
    selected_source: str
    consistency: str
    distribution_location: str = ""

    def report_record(self) -> dict[str, str | None]:
        """Stable, path-free observation; missing evidence is explicit."""
        return {
            "effective_version": self.effective_version,
            "source_version": self.source_version,
            "distribution_version": self.distribution_version,
            "distribution_status": self.distribution_status,
            "selected_source": self.selected_source,
            "consistency": self.consistency,
        }


def resolve_version(
    source_version: str | None, *, effective_version: str | None = None,
) -> VersionProvenance:
    """Keep distribution-first selection, distinguish absence from read failure.

    An existing effective version can be supplied for diagnostics of an already
    imported package, preserving the legacy report identity even if it conflicts.
    """
    source = source_version or None
    dist_version = None
    location = ""
    try:
        dist = metadata.distribution("fxapk")
        dist_version = dist.version or None
        status = "available" if dist_version else "invalid"
    except metadata.PackageNotFoundError:
        status = "missing"
    except Exception:  # noqa: BLE001 — diagnostics must not break report generation
        logger.debug("Unable to read fxapk distribution version", exc_info=True)
        status = "error"
    else:
        try:
            location = str(getattr(dist, "_path", None) or dist.locate_file(""))
        except Exception:  # noqa: BLE001 — location is optional diagnostic information
            logger.debug("Unable to locate fxapk distribution", exc_info=True)

    selected = dist_version or source or "unknown"
    origin = "distribution" if dist_version else "source" if source else "unknown"
    effective = selected if effective_version is None else effective_version
    if effective != selected:
        origin = "unknown"
    observed = {v for v in (source, dist_version, effective) if v and v != "unknown"}
    consistency = (
        "conflict" if len(observed) > 1 else
        "consistent" if source and dist_version and effective == selected else
        "unverifiable"
    )
    return VersionProvenance(effective, source, dist_version, status, origin, consistency, location)
