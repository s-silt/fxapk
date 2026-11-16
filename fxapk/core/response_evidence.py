"""Opt-in local retention of bounded HTTP entity bytes, without request secrets."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit
from uuid import uuid4

_SINK: ContextVar[tuple[Path, list[dict[str, Any]]] | None] = ContextVar("response_evidence", default=None)


@contextmanager
def capture_responses(root: Path | None) -> Iterator[list[dict[str, Any]]]:
    artifacts: list[dict[str, Any]] = []
    token = _SINK.set((root, artifacts) if root is not None else None)
    try:
        yield artifacts
    finally:
        _SINK.reset(token)


def retain_response(response: Any) -> None:
    sink = _SINK.get()
    if sink is None:
        return
    root, artifacts = sink
    body = response.content
    if not isinstance(body, bytes):
        return
    entry: dict[str, Any] = {"observed_at": datetime.now(timezone.utc).isoformat(),
                             "http_status": response.status_code,
                             "body_encoding": "decoded_http_entity", "bytes": len(body),
                             "sha256": hashlib.sha256(body).hexdigest()}
    parsed = urlsplit(str(getattr(response, "url", "")))
    # Paths, query strings, userinfo and headers can contain credentials.
    entry["source_origin"] = f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else ""
    try:
        root.mkdir(parents=True, exist_ok=True)
        name = f"{entry['sha256']}-{uuid4().hex}.body"
        with (root / name).open("xb") as stream:
            stream.write(body)
        entry.update(status="retained", relpath=f"raw-responses/{name}")
    except OSError:
        entry.update(status="failed", reason="response_evidence_write_failed")
    artifacts.append(entry)


def verify_retention(evidence: object, directory: Path) -> bool:
    """Validate stored bytes on every receipt; never trust a prior retained flag."""
    if not isinstance(evidence, dict) or evidence.get("status") != "retained":
        return False
    artifacts = evidence.get("artifacts")
    valid = isinstance(artifacts, list) and bool(artifacts)
    if isinstance(artifacts, list) and artifacts:
        for item in artifacts:
            try:
                if not isinstance(item, dict) or item.get("status") != "retained":
                    valid = False
                    break
                relative = Path(item["relpath"])
                path = (directory / relative).resolve()
                if relative.is_absolute() or not path.is_relative_to(directory.resolve()):
                    valid = False
                    break
                with path.open("rb") as stream:
                    size = path.stat().st_size
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if size != item["bytes"] or digest != item["sha256"]:
                    valid = False
                    break
            except (OSError, ValueError, TypeError, KeyError):
                valid = False
                break
    if not valid:
        evidence.update(status="invalid", reason="response_evidence_missing_or_corrupt")
    return valid
