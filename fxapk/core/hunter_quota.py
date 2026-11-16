"""Durable, account-scoped free-credit budget for Hunter searches.

All local callers use one store, independent of case, output directory and API key.
Only account fingerprints and counters are stored, never credentials or targets.
The platform's live balance is authoritative; local reservations cover crashes.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Iterator

DAILY_LIMIT = 500
PAGE_SIZE = 10
CHINA_TIME = timezone(timedelta(hours=8))


class HunterQuotaError(RuntimeError):
    def __init__(self, category: str, *, skipped: bool = False):
        self.category = category
        self.skipped = skipped
        super().__init__(category)


def quota_path() -> Path:
    configured = os.environ.get("FXAPK_HUNTER_QUOTA_DB")
    path = Path(configured) if configured else Path.home() / ".fxapk" / "hunter-quota.sqlite3"
    if not path.is_absolute():
        raise HunterQuotaError("hunter_quota_store_invalid")
    return path.resolve()


def local_day() -> str:
    return datetime.now(CHINA_TIME).date().isoformat()


def account_balance(payload: Any) -> tuple[str, int, int]:
    """Use the documented personal account identity, not a rotatable API key."""
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise HunterQuotaError("hunter_account_balance_unknown")
    remaining, limit = data.get("rest_free_point"), data.get("day_free_point")
    if (type(remaining) is not int or type(limit) is not int
            or not 0 <= remaining <= limit or limit <= 0):
        # -1 / absent means unrestricted in the API, not a known free balance.
        raise HunterQuotaError("hunter_account_balance_unknown")
    personal = data.get("personal_info")
    phone = personal.get("phone") if isinstance(personal, dict) else None
    if not isinstance(phone, str) or not re.fullmatch(r"\+?[0-9]{7,15}", phone.strip()):
        raise HunterQuotaError("hunter_account_identity_unknown")
    account = hashlib.sha256(("hunter-personal:" + phone.strip()).encode()).hexdigest()
    return account, remaining, limit


def consumed_points(payload: Any) -> int | None:
    data = payload.get("data") if isinstance(payload, dict) else None
    raw = data.get("consume_quota") if isinstance(data, dict) else None
    if type(raw) is int:
        return raw if raw >= 0 else None
    if isinstance(raw, str):
        match = re.fullmatch(r"(?:消耗积分\s*[:：]\s*)?([0-9]+)", raw.strip())
        if match:
            return int(match[1])
    return None


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    """OS lock is released on process death; the reservation is already durable."""
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        deadline = time.monotonic() + 30
        if os.name == "nt":
            import msvcrt

            def acquire() -> None:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

            def release() -> None:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def acquire() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            def release() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        while True:
            try:
                acquire()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise HunterQuotaError("hunter_quota_lock_timeout") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            release()


class QuotaStore:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def reserve(self, account: str, remaining: int, limit: int, day: str) -> dict[str, Any]:
        db = self.connection
        latest = db.execute("SELECT max(day) FROM budget WHERE account=?", (account,)).fetchone()[0]
        if latest and day < latest:
            raise HunterQuotaError("hunter_quota_clock_rollback")
        row = db.execute("SELECT used, blocked FROM budget WHERE account=? AND day=?", (account, day)).fetchone()
        used, blocked = row if row else (0, "")
        if type(used) is not int or used < 0 or not isinstance(blocked, str):
            raise HunterQuotaError("hunter_quota_store_invalid")
        # Include spending by the web UI/other tools already visible at preflight.
        used = max(used, limit - remaining)
        db.execute("INSERT OR REPLACE INTO budget VALUES (?, ?, ?, ?)", (account, day, used, blocked))
        db.commit()
        if blocked:
            raise HunterQuotaError(blocked, skipped=True)
        # Fixed 10-row page costs at most 10 points under the documented basic
        # search contract. Never spend the last partial page via paid fallback.
        if min(DAILY_LIMIT - used, remaining) < PAGE_SIZE:
            raise HunterQuotaError("hunter_daily_free_limit", skipped=True)
        db.execute("UPDATE budget SET used=? WHERE account=? AND day=?", (used + PAGE_SIZE, account, day))
        db.commit()  # Commit BEFORE sending the billable request.
        return {"day": day, "daily_limit": DAILY_LIMIT, "free_remaining_before": remaining,
                "reserved_points": PAGE_SIZE, "accounted_points": used + PAGE_SIZE,
                "status": "reserved", "scope": "account_shared_local_store"}

    def settle(self, account: str, receipt: dict[str, Any], payload: Any) -> None:
        consumed = consumed_points(payload)
        # A missing/invalid receipt or timeout keeps the full reservation.
        if consumed is None:
            receipt["status"] = "reserved_cost_unknown"
            return
        db = self.connection
        day = receipt["day"]
        if consumed > PAGE_SIZE:
            db.execute("UPDATE budget SET used=used+?, blocked=? WHERE account=? AND day=?",
                       (consumed - PAGE_SIZE, "hunter_cost_contract_changed", account, day))
            db.commit()
            receipt.update(status="blocked_cost_contract_changed", consumed_points=consumed,
                           accounted_points=db.execute("SELECT used FROM budget WHERE account=? AND day=?", (account, day)).fetchone()[0])
            return
        db.execute("UPDATE budget SET used=used-? WHERE account=? AND day=?",
                   (PAGE_SIZE - consumed, account, day))
        db.commit()
        receipt.update(status="settled", consumed_points=consumed,
                       accounted_points=db.execute("SELECT used FROM budget WHERE account=? AND day=?", (account, day)).fetchone()[0])


@contextmanager
def quota_store() -> Iterator[QuotaStore]:
    """Lock spans preflight, durable reservation, HTTP request and settlement."""
    body_error = False
    try:
        path = quota_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock(path.with_suffix(".lock")):
            db = sqlite3.connect(path, timeout=5)
            try:
                db.execute("PRAGMA synchronous=FULL")
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise HunterQuotaError("hunter_quota_store_invalid")
                if version == 0:
                    db.execute("CREATE TABLE budget (account TEXT NOT NULL, day TEXT NOT NULL, used INTEGER NOT NULL CHECK(used>=0), blocked TEXT NOT NULL, PRIMARY KEY(account, day))")
                    db.execute("PRAGMA user_version=1")
                    db.commit()
                try:
                    yield QuotaStore(db)
                except BaseException:
                    body_error = True
                    raise
            finally:
                db.close()
    except (OSError, sqlite3.Error) as exc:
        if body_error and not isinstance(exc, sqlite3.Error):
            raise
        raise HunterQuotaError("hunter_quota_store_unavailable") from exc
