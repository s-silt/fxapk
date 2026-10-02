"""Opt-in process-wide HTTP admission, shared by explicitly grouped origins.

Configuration is local FXAPK_HTTP_RATE_LIMITS JSON. No credentials are read or
stored. This bounds request starts and in-flight requests in this process only;
it cannot account for another process, account user, provider credits or money.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Iterator
from urllib.parse import urlsplit

import requests


class RequestThrottled(requests.RequestException):
    """Stable local admission failure; no target, config or secret in the message."""


@dataclass(frozen=True)
class RatePolicy:
    requests: int
    period_seconds: float
    max_concurrency: int = 1
    max_wait_seconds: float = 30

    def __post_init__(self) -> None:
        if type(self.requests) is not int or not 1 <= self.requests <= 10000:
            raise ValueError("invalid_request_rate")
        if type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 64:
            raise ValueError("invalid_rate_concurrency")
        for value, maximum in ((self.period_seconds, 86400), (self.max_wait_seconds, 60)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
                raise ValueError("invalid_rate_window")


class RateController:
    def __init__(self, policy: RatePolicy, *, clock=time.monotonic, wall_clock=time.time, sleep=time.sleep):
        self.policy = policy
        self.clock, self.wall_clock, self.sleep = clock, wall_clock, sleep
        self._starts: deque[float] = deque()
        self._active = 0
        self._cooldown = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        deadline = self.clock() + self.policy.max_wait_seconds
        while True:
            with self._lock:
                now = self.clock()
                while self._starts and self._starts[0] <= now - self.policy.period_seconds:
                    self._starts.popleft()
                delay = max(0.0, self._cooldown - now)
                if len(self._starts) >= self.policy.requests:
                    delay = max(delay, self._starts[0] + self.policy.period_seconds - now)
                if self._active >= self.policy.max_concurrency:
                    delay = max(delay, .01)
                if delay <= 0:
                    self._starts.append(now)
                    self._active += 1
                    return
                if now + delay > deadline:
                    raise RequestThrottled("local_rate_limit_wait_exceeded")
            # Sleep outside the lock: completions and 429 feedback must progress.
            self.sleep(min(delay, .25))

    def release(self) -> None:
        with self._lock:
            self._active -= 1

    def observe(self, response: Any) -> None:
        if getattr(response, "status_code", None) != 429:
            return
        headers = getattr(response, "headers", {})
        raw = headers.get("Retry-After") if hasattr(headers, "get") else None
        seconds = self.policy.period_seconds
        if isinstance(raw, str) and len(raw) <= 128:
            try:
                value = float(raw)
                if math.isfinite(value) and value >= 0:
                    seconds = max(seconds, value)
            except ValueError:
                try:
                    seconds = max(seconds, parsedate_to_datetime(raw).timestamp() - self.wall_clock())
                except (ValueError, TypeError, OverflowError):
                    pass  # Invalid header retains the conservative local window.
        with self._lock:
            self._cooldown = max(self._cooldown, self.clock() + seconds)


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid_rate_origin")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    return f"{parsed.scheme}://{host}" + (f":{port}" if port is not None and port != (443 if parsed.scheme == "https" else 80) else "")


_controllers: dict[tuple[str, RatePolicy], RateController] = {}
_registry_lock = threading.Lock()


def controller_for(url: str | bytes) -> RateController | None:
    raw = os.environ.get("FXAPK_HTTP_RATE_LIMITS", "").strip()
    if not raw:
        return None  # Preserve existing provider-specific throttles and behavior.
    if len(raw) > 65536:
        raise RequestThrottled("invalid_rate_configuration")
    try:
        entries = json.loads(raw)
        if not isinstance(entries, dict) or len(entries) > 128:
            raise ValueError("invalid_rate_configuration")
        groups: dict[str, RatePolicy] = {}
        origins: dict[str, str] = {}
        for origin, item in entries.items():
            if not isinstance(origin, str) or not isinstance(item, dict):
                raise ValueError("invalid_rate_configuration")
            normalized = _origin(origin)
            if origin != normalized or normalized in origins:
                raise ValueError("rate_origin_must_be_canonical")
            if set(item) - {"requests", "period_seconds", "max_concurrency", "max_wait_seconds", "group"}:
                raise ValueError("unknown_rate_setting")
            group = item.get("group", normalized)
            if "group" in item and (not isinstance(group, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", group)):
                raise ValueError("invalid_rate_group")
            policy = RatePolicy(**{k: v for k, v in item.items() if k != "group"})
            if group in groups and groups[group] != policy:
                raise ValueError("conflicting_shared_rate_policy")
            origins[normalized] = group
            groups[group] = policy
        wanted = _origin(url.decode("ascii") if isinstance(url, bytes) else url)
        group = origins.get(wanted)
        if group is None:
            return None
        key = (group, groups[group])
    except (ValueError, TypeError, UnicodeError, KeyError) as exc:
        raise RequestThrottled("invalid_rate_configuration") from exc
    with _registry_lock:
        if key not in _controllers:
            if len(_controllers) >= 256:
                raise RequestThrottled("rate_registry_capacity_exceeded")
            _controllers[key] = RateController(key[1])
        return _controllers[key]


@contextmanager
def request_slot(url: str | bytes, *, allow_redirects: bool) -> Iterator[RateController | None]:
    controller = controller_for(url)
    if controller is None:
        yield None
        return
    if allow_redirects:
        raise RequestThrottled("rate_limited_request_requires_explicit_redirect_handling")
    controller.acquire()
    try:
        yield controller
    finally:
        controller.release()
