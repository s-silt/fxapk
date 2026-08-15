"""Non-derived corpus catalog for case bindings and record lifecycle state.

``manifest.jsonl`` remains a rebuildable index of report content.  Human
facts that cannot be reconstructed from a report -- which cases a report is
linked to and whether an obsolete record is quarantined -- live here instead
of being smuggled into that derived index.
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Iterable, Iterator, Mapping, Sequence

from apkscan.core.atomic import atomic_write_text
from apkscan.core.case_identity import normalize_case_id
from apkscan.core.json_contract import (
    parse_finite_json_float as _parse_finite_float,
    reject_nonfinite_json_constant as _reject_json_constant,
)

logger = logging.getLogger(__name__)

CATALOG_NAME = "catalog.jsonl"
CATALOG_LOCK_NAME = ".catalog.lock"
KEY_FIELDS: tuple[str, ...] = (
    "sample_sha256",
    "tool_version",
    "ruleset_digest",
    "evidence_surface",
)
RECORD_ACTIVE = "active"
RECORD_QUARANTINED = "quarantined"
RECORD_STATES = frozenset({RECORD_ACTIVE, RECORD_QUARANTINED})
INGEST_SEQUENCE_FIELD = "ingest_sequence"


class CatalogCorruptError(RuntimeError):
    """Raised before a catalog mutation when its current bytes are invalid."""

    def __init__(self, path: Path, diagnostics: list[dict[str, object]]) -> None:
        self.path = path
        self.diagnostics = diagnostics
        details = "; ".join(
            f"line {item.get('line', 0)}: {item.get('reason', 'invalid')}"
            for item in diagnostics
        )
        super().__init__(f"corpus catalog 损坏，拒绝写入 {path}: {details}")


class CatalogStaleError(RuntimeError):
    """Raised when a caller tries to replace a newer catalog snapshot."""


class CatalogFactRegressionError(RuntimeError):
    """Raised when generic CAS replacement would erase non-derived facts."""


class CatalogBindingError(RuntimeError):
    """Raised when a direct case bind lacks an intact stored-report anchor."""


def catalog_path(corpus_dir: str | Path) -> Path:
    return Path(corpus_dir) / CATALOG_NAME


@contextmanager
def catalog_write_lock(corpus_dir: str | Path) -> Iterator[None]:
    """Serialize catalog + derived-manifest mutations across processes."""
    root = Path(corpus_dir)
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / CATALOG_LOCK_NAME
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            deadline = time.monotonic() + 30.0
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"等待 corpus catalog 锁超时：{lock_path}") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            deadline = time.monotonic() + 30.0
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"等待 corpus catalog 锁超时：{lock_path}") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def key_of(value: Mapping[str, object] | Sequence[object]) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        return tuple(
            str(
                (value.get(field) or "static")
                if field == "evidence_surface"
                else (value.get(field) or "")
            )
            for field in KEY_FIELDS
        )
    items = tuple(str(item or "") for item in value)
    if len(items) != len(KEY_FIELDS):
        raise ValueError(f"corpus key 必须有 {len(KEY_FIELDS)} 段")
    return items[:-1] + (items[-1] or "static",)


def _base_entry(key: Sequence[object]) -> dict[str, object]:
    normalized = key_of(key)
    return {
        **dict(zip(KEY_FIELDS, normalized, strict=True)),
        "case_ids": [],
        "record_state": RECORD_ACTIVE,
        "record_state_reason": None,
        INGEST_SEQUENCE_FIELD: None,
    }


def _validate_row(row: object) -> str | None:
    if not isinstance(row, dict):
        return "catalog 行必须是 JSON 对象"
    for field in KEY_FIELDS[:3]:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            return f"catalog {field} 必须是非空字符串"
    surface = row.get("evidence_surface", "static")
    if surface not in {"static", "unpacked"}:
        return "catalog evidence_surface 必须是 static 或 unpacked"
    raw_case_ids = row.get("case_ids")
    if not isinstance(raw_case_ids, list):
        return "case_ids 必须是数组"
    for case_id in raw_case_ids:
        if not isinstance(case_id, str):
            return "case_ids 只能包含字符串"
        try:
            normalized = normalize_case_id(case_id)
        except ValueError as exc:
            return str(exc)
        if normalized != case_id:
            return "case_id 必须已按 NFC/首尾空白规则规范化"
    state = row.get("record_state", RECORD_ACTIVE)
    if state not in RECORD_STATES:
        return f"record_state 必须是 {sorted(RECORD_STATES)}"
    state_reason = row.get("record_state_reason")
    if state_reason is not None and not isinstance(state_reason, str):
        return "record_state_reason 必须是字符串或 null"
    if state == RECORD_QUARANTINED and not (state_reason or "").strip():
        return "quarantined 记录必须有 record_state_reason"
    sequence = row.get(INGEST_SEQUENCE_FIELD)
    if sequence is not None and (
        not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1
    ):
        return "ingest_sequence 必须是正整数或 null"
    return None


def read_catalog(
    corpus_dir: str | Path,
) -> tuple[list[dict], list[dict[str, object]]]:
    """Read valid rows plus diagnostics without mutating the source bytes."""
    path = catalog_path(corpus_dir)
    if not path.exists():
        return [], []
    rows: list[dict] = []
    diagnostics: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [], [{"line": 0, "reason": f"{type(exc).__name__}: {exc}"}]
    seen_keys: set[tuple[str, ...]] = set()
    seen_sequences: set[int] = set()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(
                line,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
        except (ValueError, RecursionError) as exc:
            diagnostics.append({"line": number, "reason": f"不是合法 JSON: {exc}"})
            continue
        reason = _validate_row(row)
        if reason is not None:
            diagnostics.append({"line": number, "reason": reason})
            continue
        assert isinstance(row, dict)
        key = key_of(row)
        if key in seen_keys:
            diagnostics.append({"line": number, "reason": "catalog 主键重复"})
            continue
        sequence = row.get(INGEST_SEQUENCE_FIELD)
        if isinstance(sequence, int) and sequence in seen_sequences:
            diagnostics.append({"line": number, "reason": "catalog ingest_sequence 重复"})
            continue
        seen_keys.add(key)
        if isinstance(sequence, int) and not isinstance(sequence, bool):
            seen_sequences.add(sequence)
        rows.append(row)
    return rows, diagnostics


def _log_diagnostics(path: Path, diagnostics: list[dict[str, object]]) -> None:
    for item in diagnostics:
        logger.warning(
            "corpus catalog 第 %s 行损坏：%s",
            item.get("line", 0),
            item.get("reason", "invalid"),
        )


def load_catalog(corpus_dir: str | Path) -> list[dict]:
    """Tolerant read for audit: return valid rows and log every bad line."""
    rows, diagnostics = read_catalog(corpus_dir)
    _log_diagnostics(catalog_path(corpus_dir), diagnostics)
    return rows


def load_catalog_strict(corpus_dir: str | Path) -> list[dict]:
    """Read for mutation; any diagnostic rejects the entire write."""
    rows, diagnostics = read_catalog(corpus_dir)
    if diagnostics:
        path = catalog_path(corpus_dir)
        _log_diagnostics(path, diagnostics)
        raise CatalogCorruptError(path, diagnostics)
    return rows


def _save_catalog_unlocked(
    corpus_dir: str | Path, entries: Iterable[Mapping[str, object]]
) -> None:
    rows = sorted((dict(entry) for entry in entries), key=key_of)
    diagnostics: list[dict[str, object]] = []
    seen_keys: set[tuple[str, ...]] = set()
    seen_sequences: set[int] = set()
    for number, row in enumerate(rows, 1):
        reason = _validate_row(row)
        key = key_of(row)
        if reason is None and key in seen_keys:
            reason = "catalog 主键重复"
        sequence = row.get(INGEST_SEQUENCE_FIELD)
        if reason is None and isinstance(sequence, int) and sequence in seen_sequences:
            reason = "catalog ingest_sequence 重复"
        if reason is not None:
            diagnostics.append({"line": number, "reason": reason})
        seen_keys.add(key)
        if isinstance(sequence, int) and not isinstance(sequence, bool):
            seen_sequences.add(sequence)
    if diagnostics:
        raise CatalogCorruptError(catalog_path(corpus_dir), diagnostics)
    payload = "".join(
        json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
        for row in rows
    )
    atomic_write_text(catalog_path(corpus_dir), payload)


def catalog_revision(corpus_dir: str | Path) -> str:
    """Hash the current catalog bytes, or return ``missing`` without creating it."""
    path = catalog_path(corpus_dir)
    if not path.exists():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_catalog_snapshot(corpus_dir: str | Path) -> tuple[list[dict], str]:
    """Return strict rows plus a CAS revision for an intentional replacement."""
    with catalog_write_lock(corpus_dir):
        rows = load_catalog_strict(corpus_dir)
        from apkscan.core import corpus

        assert_manifest_catalog_coverage(
            corpus.load_manifest_strict(corpus_dir), rows, corpus_dir
        )
        return rows, catalog_revision(corpus_dir)


def save_catalog(
    corpus_dir: str | Path,
    entries: Iterable[Mapping[str, object]],
    *,
    expected_revision: str | None = None,
) -> None:
    """CAS-replace a healthy catalog; stale lock-external rows are rejected."""
    with catalog_write_lock(corpus_dir):
        current_rows = load_catalog_strict(corpus_dir)
        from apkscan.core import corpus

        manifest_rows = corpus.load_manifest_strict(corpus_dir)
        assert_manifest_catalog_coverage(manifest_rows, current_rows, corpus_dir)
        current_revision = catalog_revision(corpus_dir)
        if not expected_revision:
            raise CatalogStaleError("save_catalog requires expected_revision from load_catalog_snapshot")
        if current_revision != expected_revision:
            raise CatalogStaleError(
                f"catalog changed since snapshot: expected {expected_revision}, got {current_revision}"
            )
        proposed = [dict(entry) for entry in entries]
        _assert_catalog_facts_monotonic(current_rows, proposed)
        assert_manifest_catalog_coverage(manifest_rows, proposed, corpus_dir)
        _save_catalog_unlocked(corpus_dir, proposed)


def _assert_catalog_facts_monotonic(
    current_rows: list[dict], proposed_rows: list[dict]
) -> None:
    current = {key_of(row): row for row in current_rows}
    proposed = {key_of(row): row for row in proposed_rows}
    missing = sorted(set(current) - set(proposed))
    if missing:
        raise CatalogFactRegressionError(
            f"save_catalog 不得删除既有 catalog 主键：{missing}"
        )
    added = sorted(set(proposed) - set(current))
    if added:
        raise CatalogFactRegressionError(
            f"save_catalog 不得预埋不存在的 catalog 主键；请走 add_report：{added}"
        )
    for key, before in current.items():
        after = proposed[key]
        before_cases = {
            value for value in before.get("case_ids", []) if isinstance(value, str)
        }
        after_cases = {
            value for value in after.get("case_ids", []) if isinstance(value, str)
        }
        if before_cases != after_cases:
            raise CatalogFactRegressionError(
                f"save_catalog 不得改变案件关联；请使用 bind_case：{key}"
            )
        if before.get("record_state", RECORD_ACTIVE) != after.get(
            "record_state", RECORD_ACTIVE
        ) or before.get("record_state_reason") != after.get("record_state_reason"):
            raise CatalogFactRegressionError(
                f"save_catalog 不得隐式改变隔离状态；请使用 set_record_state：{key}"
            )
        if before.get(INGEST_SEQUENCE_FIELD) != after.get(INGEST_SEQUENCE_FIELD):
            raise CatalogFactRegressionError(
                f"save_catalog 不得改写 ingest_sequence：{key}"
            )


def _find(entries: list[dict], key: Sequence[object]) -> dict | None:
    wanted = key_of(key)
    return next((entry for entry in entries if key_of(entry) == wanted), None)


def has_catalog_era_projection(entry: Mapping[str, object]) -> bool:
    """该 manifest 记录是否带着**只可能来自 catalog** 的投影事实。

    真正的 legacy 行只有 ``case_id``；非空 ``case_ids``、隔离态、入库顺序与物化标记
    都是 catalog 时代的产物。

    ★单独成谓词是为了让「跨 catalog 边界」这件事在别处也判得出来：``corpus restore``
    要据此判断一份 catalog 之前的旧快照能不能真正回滚（答案是不能——catalog 才是真源，
    manifest 是派生索引，恢复出的旧 manifest 会被立刻重新物化）。判据只此一处，
    别在调用方另写一份形态相近的。
    """
    raw_case_ids = entry.get("case_ids")
    has_projected_cases = isinstance(raw_case_ids, list) and bool(raw_case_ids)
    raw_sequence = entry.get(INGEST_SEQUENCE_FIELD)
    has_projected_sequence = (
        isinstance(raw_sequence, int)
        and not isinstance(raw_sequence, bool)
        and raw_sequence > 0
    )
    state = str(entry.get("record_state") or RECORD_ACTIVE)
    return (
        has_projected_cases
        or has_projected_sequence
        or state == RECORD_QUARANTINED
        or bool(entry.get("record_state_reason"))
        or entry.get("catalog_authority_materialized") is True
    )


def assert_manifest_catalog_coverage(
    manifest_entries: Iterable[Mapping[str, object]],
    catalog_entries: list[dict],
    corpus_dir: str | Path,
) -> None:
    """Reject a missing catalog row when the derived manifest proves it existed.

    A true legacy row may have only ``case_id``.  In contrast, non-empty
    ``case_ids``, a quarantined state, or the materialization marker are
    catalog-era projections.  Treating a missing annotation as an empty one
    would erase case bindings or re-activate quarantined evidence.
    """
    catalog_keys = {key_of(entry) for entry in catalog_entries}
    diagnostics: list[dict[str, object]] = []
    for number, entry in enumerate(manifest_entries, 1):
        if has_catalog_era_projection(entry) and key_of(entry) not in catalog_keys:
            diagnostics.append(
                {
                    "line": number,
                    "reason": (
                        "manifest 含 catalog-era 案件/隔离/入库顺序事实，"
                        "但对应 catalog 主键缺失"
                    ),
                }
            )
    if diagnostics:
        raise CatalogCorruptError(catalog_path(corpus_dir), diagnostics)


def bind_case_in_memory(
    entries: list[dict], key: Sequence[object], case_id: object
) -> tuple[list[dict], bool]:
    cid = normalize_case_id(case_id)
    rows = [dict(entry) for entry in entries]
    target = _find(rows, key)
    if target is None:
        target = _base_entry(key)
        rows.append(target)
    existing = target.get("case_ids")
    raw_case_ids = existing if isinstance(existing, list) else []
    case_ids = {
        normalize_case_id(item)
        for item in raw_case_ids
        if isinstance(item, str) and item.strip()
    }
    changed = cid not in case_ids
    case_ids.add(cid)
    target["case_ids"] = sorted(case_ids)
    target.setdefault("record_state", RECORD_ACTIVE)
    target.setdefault("record_state_reason", None)
    return rows, changed


def _preserve_legacy_case_in_memory(
    entries: list[dict], manifest_entry: Mapping[str, object]
) -> tuple[list[dict], bool]:
    """Promote a true legacy alias before creating catalog authority."""
    key = key_of(manifest_entry)
    if _find(entries, key) is not None:
        return [dict(entry) for entry in entries], False
    legacy = manifest_entry.get("case_id")
    if not isinstance(legacy, str) or not legacy.strip():
        return [dict(entry) for entry in entries], False
    return bind_case_in_memory(entries, key, legacy)


def ensure_ingest_sequence_in_memory(
    entries: list[dict], key: Sequence[object]
) -> tuple[list[dict], bool]:
    """Assign the next lock-serialized sequence to a genuinely new record."""
    rows = [dict(entry) for entry in entries]
    target = _find(rows, key)
    if target is None:
        target = _base_entry(key)
        rows.append(target)
    current = target.get(INGEST_SEQUENCE_FIELD)
    if isinstance(current, int) and not isinstance(current, bool) and current > 0:
        return rows, False
    sequences = [
        value
        for entry in rows
        if isinstance((value := entry.get(INGEST_SEQUENCE_FIELD)), int)
        and not isinstance(value, bool)
        and value > 0
    ]
    target[INGEST_SEQUENCE_FIELD] = max(sequences, default=0) + 1
    return rows, True


def bind_case(corpus_dir: str | Path, key: Sequence[object], case_id: object) -> bool:
    root = Path(corpus_dir)
    with catalog_write_lock(root):
        rows = load_catalog_strict(root)
        from apkscan.core import corpus

        manifest_rows = corpus.load_manifest_strict(root)
        assert_manifest_catalog_coverage(manifest_rows, rows, root)
        wanted = key_of(key)
        stored_entry = next(
            (entry for entry in manifest_rows if key_of(entry) == wanted),
            None,
        )
        if stored_entry is None:
            raise CatalogBindingError("案件绑定被拒：catalog 主键在 manifest 中不存在")
        report_file = corpus.resolve_report_file(
            root, str(stored_entry.get("report_path") or "")
        )
        recorded = str(stored_entry.get("report_bytes_sha256") or "").strip().lower()
        if report_file is None or not recorded:
            raise CatalogBindingError("案件绑定被拒：库内报告或记录哈希缺失")
        try:
            actual = hashlib.sha256(report_file.read_bytes()).hexdigest()
        except OSError as exc:
            raise CatalogBindingError(f"案件绑定被拒：库内报告不可读：{exc}") from exc
        if actual != recorded:
            raise CatalogBindingError("案件绑定被拒：库内报告与记录哈希不一致")
        rows, legacy_migrated = _preserve_legacy_case_in_memory(rows, stored_entry)
        rows, changed = bind_case_in_memory(rows, key, case_id)
        if changed or legacy_migrated:
            _save_catalog_unlocked(root, rows)
    if changed or legacy_migrated:
        from apkscan.core import corpus

        corpus.refresh_catalog_fields(root)
    return changed


def set_record_state(
    corpus_dir: str | Path,
    key: Sequence[object],
    *,
    state: str,
    reason: str = "",
) -> bool:
    if state not in RECORD_STATES:
        raise ValueError(f"record_state 必须是 {sorted(RECORD_STATES)}")
    clean_reason = reason.strip()
    if not clean_reason:
        raise ValueError("状态变更必须说明 reason")
    root = Path(corpus_dir)
    with catalog_write_lock(root):
        rows = [dict(entry) for entry in load_catalog_strict(root)]
        from apkscan.core import corpus

        manifest_rows = corpus.load_manifest_strict(root)
        assert_manifest_catalog_coverage(manifest_rows, rows, root)
        wanted = key_of(key)
        if not any(key_of(entry) == wanted for entry in manifest_rows):
            raise CatalogBindingError("状态变更被拒：catalog 主键在 manifest 中不存在")
        manifest_entry = next(entry for entry in manifest_rows if key_of(entry) == wanted)
        if state == RECORD_ACTIVE:
            report_file = corpus.resolve_report_file(
                root, str(manifest_entry.get("report_path") or "")
            )
            recorded = str(
                manifest_entry.get("report_bytes_sha256") or ""
            ).strip().lower()
            if report_file is None or not recorded:
                raise CatalogBindingError("恢复 active 被拒：库内报告或记录哈希缺失")
            try:
                actual = hashlib.sha256(report_file.read_bytes()).hexdigest()
            except OSError as exc:
                raise CatalogBindingError(f"恢复 active 被拒：库内报告不可读：{exc}") from exc
            if actual != recorded:
                raise CatalogBindingError("恢复 active 被拒：库内报告与记录哈希不一致")
        rows, legacy_migrated = _preserve_legacy_case_in_memory(rows, manifest_entry)
        target = _find(rows, key)
        if target is None:
            target = _base_entry(key)
            rows.append(target)
        changed = (
            target.get("record_state") != state
            or (target.get("record_state_reason") or "") != clean_reason
        )
        target["record_state"] = state
        target["record_state_reason"] = clean_reason
        if changed or legacy_migrated:
            _save_catalog_unlocked(root, rows)
    if changed or legacy_migrated:
        from apkscan.core import corpus

        corpus.refresh_catalog_fields(root)
    return changed


def _set_state_in_memory(
    entries: list[dict], key: Sequence[object], *, state: str, reason: str
) -> tuple[list[dict], bool]:
    rows = [dict(entry) for entry in entries]
    target = _find(rows, key)
    if target is None:
        target = _base_entry(key)
        rows.append(target)
    changed = (
        target.get("record_state") != state
        or (target.get("record_state_reason") or "") != reason
    )
    target["record_state"] = state
    target["record_state_reason"] = reason or None
    return rows, changed


def quarantine_tool_versions(
    corpus_dir: str | Path,
    tool_versions: Iterable[str],
    *,
    reason: str,
    apply: bool = False,
) -> dict[str, object]:
    """Plan or apply lifecycle quarantine by exact tool version; never delete."""
    versions = {str(version).strip() for version in tool_versions if str(version).strip()}
    clean_reason = reason.strip()
    if not versions:
        raise ValueError("至少指定一个 tool_version")
    if not clean_reason:
        raise ValueError("隔离版本必须说明 reason")
    from apkscan.core import corpus

    matched = changed = 0
    catalog_changed = False
    lock = catalog_write_lock(corpus_dir) if apply else nullcontext()
    with lock:
        rows = load_catalog_strict(corpus_dir)
        manifest_rows = corpus.load_manifest_strict(corpus_dir)
        assert_manifest_catalog_coverage(manifest_rows, rows, corpus_dir)
        for entry in manifest_rows:
            if str(entry.get("tool_version") or "") not in versions:
                continue
            matched += 1
            rows, legacy_migrated = _preserve_legacy_case_in_memory(rows, entry)
            rows, did_change = _set_state_in_memory(
                rows,
                key_of(entry),
                state=RECORD_QUARANTINED,
                reason=clean_reason,
            )
            changed += int(did_change)
            catalog_changed = catalog_changed or legacy_migrated or did_change
        if apply and catalog_changed:
            _save_catalog_unlocked(corpus_dir, rows)
    if apply and catalog_changed:
        corpus.refresh_catalog_fields(corpus_dir)
    return {
        "tool_versions": sorted(versions),
        "matched": matched,
        "would_quarantine": changed,
        "quarantined": changed if apply else 0,
        "applied": apply,
        "deleted": 0,
    }


def materialize(entry: Mapping[str, object], catalog_entries: list[dict]) -> dict:
    row = dict(entry)
    annotation = _find(catalog_entries, key_of(row))
    legacy = row.get("case_id")
    case_ids: set[str] = set()
    # Once a catalog row exists it is authoritative.  The legacy alias is
    # consulted only for records that have not yet been migrated.
    if annotation is None and isinstance(legacy, str) and legacy.strip():
        case_ids.add(normalize_case_id(legacy))
    if annotation is not None:
        raw_case_ids = annotation.get("case_ids")
        if isinstance(raw_case_ids, list):
            for item in raw_case_ids:
                if isinstance(item, str) and item.strip():
                    case_ids.add(normalize_case_id(item))
        state = str(annotation.get("record_state") or RECORD_ACTIVE)
        reason = annotation.get("record_state_reason")
    else:
        state = RECORD_ACTIVE
        reason = None
    row["case_ids"] = sorted(case_ids)
    # Compatibility for older consumers.  It is only an alias for the sole
    # binding; multi-case records must consume case_ids explicitly.
    row["case_id"] = next(iter(case_ids)) if len(case_ids) == 1 else None
    row["record_state"] = state if state in RECORD_STATES else RECORD_ACTIVE
    row["record_state_reason"] = str(reason) if reason else None
    sequence = annotation.get(INGEST_SEQUENCE_FIELD) if annotation is not None else None
    row[INGEST_SEQUENCE_FIELD] = (
        sequence
        if isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > 0
        else None
    )
    row["catalog_authority_materialized"] = annotation is not None
    return row


def migrate_legacy_case_ids(corpus_dir: str | Path, *, apply: bool = False) -> dict[str, object]:
    # Local import avoids a corpus <-> catalog import cycle.
    from apkscan.core import corpus

    planned = 0
    invalid = 0
    lock = catalog_write_lock(corpus_dir) if apply else nullcontext()
    with lock:
        catalog_rows = load_catalog_strict(corpus_dir)
        manifest_rows = corpus.load_manifest_strict(corpus_dir)
        assert_manifest_catalog_coverage(manifest_rows, catalog_rows, corpus_dir)
        for entry in manifest_rows:
            legacy = entry.get("case_id")
            if not isinstance(legacy, str) or not legacy.strip():
                continue
            try:
                updated, changed = bind_case_in_memory(catalog_rows, key_of(entry), legacy)
            except ValueError:
                invalid += 1
                continue
            if changed:
                planned += 1
                catalog_rows = updated
        if apply and planned:
            _save_catalog_unlocked(corpus_dir, catalog_rows)
    if apply and planned:
        corpus.refresh_catalog_fields(corpus_dir)
    return {
        "would_migrate": planned,
        "migrated": planned if apply else 0,
        "invalid": invalid,
        "applied": apply,
    }


__all__ = [
    "CATALOG_LOCK_NAME",
    "CATALOG_NAME",
    "CatalogCorruptError",
    "CatalogBindingError",
    "CatalogFactRegressionError",
    "CatalogStaleError",
    "INGEST_SEQUENCE_FIELD",
    "KEY_FIELDS",
    "RECORD_ACTIVE",
    "RECORD_QUARANTINED",
    "assert_manifest_catalog_coverage",
    "bind_case",
    "bind_case_in_memory",
    "ensure_ingest_sequence_in_memory",
    "catalog_path",
    "catalog_revision",
    "catalog_write_lock",
    "has_catalog_era_projection",
    "key_of",
    "load_catalog",
    "load_catalog_snapshot",
    "load_catalog_strict",
    "materialize",
    "migrate_legacy_case_ids",
    "normalize_case_id",
    "quarantine_tool_versions",
    "read_catalog",
    "save_catalog",
    "set_record_state",
]
