"""Compress only newly generated output; retain staging on any storage failure."""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from types import TracebackType
from typing import Callable, Self

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.evidence_archive import ArchiveError, pack, remove_owned_staging


class EvidenceOutput:
    def __init__(self, out: Path | None, archive_out: Path | None,
                 progress: Callable[[dict], None] | None = None, *, compression: str = "zstd") -> None:
        if (out is None) == (archive_out is None):
            raise ArchiveError("choose_output_directory_or_archive")
        self.archive_out = archive_out
        self.progress = progress
        self.compression = compression
        self.staging: Path | None = None
        self.storage: dict | None = None
        if archive_out is None:
            assert out is not None
            self.path = out
            self.receipt_path = None
        else:
            self.archive_out = archive_out.absolute()
            self.receipt_path = Path(str(self.archive_out) + ".receipt.json")
            if self.archive_out.exists() or self.receipt_path.exists():
                raise ArchiveError("archive_output_exists")
            self.archive_out.parent.mkdir(parents=True, exist_ok=True)
            self.staging = Path(tempfile.mkdtemp(prefix=".fxapk-evidence-", dir=self.archive_out.parent))
            self.path = self.staging / "data"

    def __enter__(self) -> Self:
        return self

    def _receipt(self) -> None:
        if self.receipt_path is not None and self.storage is not None:
            raw = json.dumps(self.storage, ensure_ascii=False, allow_nan=False, indent=2).encode()
            if not atomic_create_bytes(self.receipt_path, raw):
                raise ArchiveError("archive_receipt_exists")

    def __exit__(self, exc_type: type[BaseException] | None, error: BaseException | None,
                 traceback: TracebackType | None) -> bool:
        if self.archive_out is None:
            return False
        assert self.staging is not None
        if error is not None:
            code = str(error) if isinstance(error, ValueError) and re.fullmatch("[a-z_]{1,80}", str(error)) else "archive_generation_failed"
            self.storage = {"state": "failed", "phase": "generation",
                            "reason_codes": sorted({"archive_generation_failed", code}),
                            "exception_type": type(error).__name__, "archive_published": False,
                            "retained_staging": str(self.staging)}
            self._receipt()
            return False  # Preserve the original exception for the public entry point.
        try:
            self.storage = pack(self.path, self.archive_out, progress=self.progress, compression=self.compression)
            self.storage["staging_cleanup"] = "pending"
            try:
                remove_owned_staging(self.staging, self.archive_out.parent)
                self.storage["staging_cleanup"] = "complete"
            except (OSError, ValueError):
                self.storage.update(state="partial", staging_cleanup="failed",
                                    reason_codes=["archive_cleanup_failed"], retained_staging=str(self.staging))
            self._receipt()
            if self.progress:
                self.progress({"id": "archive_output", "state": self.storage["state"],
                               "staging_cleanup": self.storage["staging_cleanup"]})
        except Exception as failure:
            code = str(failure) if isinstance(failure, ValueError) and re.fullmatch("[a-z_]{1,80}", str(failure)) else "archive_storage_failed"
            self.storage = {"state": "failed", "phase": "storage", "reason_codes": [code],
                            "exception_type": type(failure).__name__,
                            "retained_staging": str(self.staging) if self.staging.exists() else None,
                            "archive_published": self.archive_out.is_file()}
            self._receipt()
            raise ArchiveError(code) from failure
        return False

    def reference(self, member: str) -> str:
        return f"{self.archive_out}::{member}" if self.archive_out is not None else str(self.path / member)

    def display(self, value: object) -> object:
        """Keep original receipts unchanged; console paths point to the archive."""
        if isinstance(value, dict):
            return {k: self.display(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.display(v) for v in value]
        if isinstance(value, str) and self.archive_out is not None:
            for prefix in sorted({str(self.path.absolute()), str(self.path.resolve())}, key=len, reverse=True):
                if value.startswith(prefix + "/") or value.startswith(prefix + "\\"):
                    return self.reference(value[len(prefix) + 1:].replace("\\", "/"))
        return value
