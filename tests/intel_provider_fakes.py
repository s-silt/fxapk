"""Reusable fakes + fixtures for the PR6 intel-provider adapter tests.

``FakeSession`` records every ``get`` call and raises ``AssertionError`` on a
second one, so the "exactly one upstream request" invariant is a tripwire in
every test, not a claim a single test must remember to assert. ``FakeResponse``
mirrors the small slice of ``requests`` semantics the transport uses:
``status_code`` / ``headers`` (case-insensitive) / ``iter_content`` (chunked,
counting emitted bytes) / ``close`` (sets ``closed``). No network, no real key.

The ``scrub_intel_env`` autouse fixture deletes every intel env var so the dev
machine's real ``.env`` can never enable a provider or leak a real key into a
test. Import it into each intel test module (an imported autouse fixture applies
to that module).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import requests
from requests.structures import CaseInsensitiveDict

#: sentinel credential used everywhere a key must be present; never a real key.
SECRET = "sekret-key-123"

#: every env var any intel adapter reads (primary + legacy aliases + optional).
INTEL_ENV_VARS = (
    "FXAPK_FOFA_KEY",
    "FXAPK_FOFA_URL",
    "FXAPK_HUNTER_KEY",
    "FXAPK_SHODAN_KEY",
    "SHODAN_API_KEY",
    "FXAPK_CENSYS_TOKEN",
    "CENSYS_API_TOKEN",
    "FXAPK_CENSYS_ORG_ID",
)


class _SecondRequestError(BaseException):
    """Raised by FakeSession on an unexpected second get.

    A BaseException (not Exception) subclass so the PR5 base's `except Exception`
    in _dispatch cannot launder a chained-request regression into a FAILURE — the
    tripwire propagates out and fails the test loudly.
    """


class FakeResponse:
    """A minimal stand-in for ``requests.Response`` (streamed read path only)."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        raise_on_iter: bool = False,
    ) -> None:
        self.status_code = status_code
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict(headers or {})
        self._body = body
        self._raise_on_iter = raise_on_iter
        self.closed = False
        self.iter_called = False
        self.chunks_yielded = 0

    def iter_content(self, chunk_size: int = 1):
        self.iter_called = True
        if self._raise_on_iter:
            raise AssertionError("body must not be read on this path")
        for start in range(0, len(self._body), max(1, chunk_size)):
            self.chunks_yielded += 1
            yield self._body[start : start + chunk_size]

    @property
    def content(self) -> bytes:
        # Booby-trap: the transport MUST stream via iter_content and stop early on
        # the byte cap / wall deadline; a rewrite that buffers the whole body via
        # .content (defeating the gzip-bomb / slow-drip bounds) trips here.
        raise AssertionError("transport must stream via iter_content, not buffer .content")

    def json(self) -> Any:
        return json.loads(self._body)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)  # pragma: no cover - unused by transport

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeResponse:  # pragma: no cover - unused by transport
        return self

    def __exit__(self, *_exc: object) -> None:  # pragma: no cover - unused by transport
        self.close()


def json_response(
    obj: Any,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    content_length: int | None = None,
) -> FakeResponse:
    """A ``FakeResponse`` whose body is ``json.dumps(obj)``."""
    hdrs = dict(headers or {})
    if content_length is not None:
        hdrs["Content-Length"] = str(content_length)
    return FakeResponse(
        status_code=status_code, headers=hdrs, body=json.dumps(obj).encode("utf-8")
    )


class FakeSession:
    """Records ``get`` calls; a second ``get`` is a hard failure."""

    def __init__(self, *outcomes: FakeResponse | BaseException) -> None:
        self._outcomes: list[FakeResponse | BaseException] = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: Any = None,
        allow_redirects: Any = None,
        stream: Any = None,
        **_extra: Any,
    ) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "params": dict(params or {}),
                "headers": dict(headers or {}),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
                "stream": stream,
            }
        )
        if not self._outcomes:
            raise _SecondRequestError("unexpected second upstream request")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture(autouse=True)
def scrub_intel_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Delete every intel env var before each test (hard isolation from .env)."""
    for name in INTEL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def set_credential(
    monkeypatch: pytest.MonkeyPatch, provider_cls: type, value: str = SECRET
) -> None:
    """Enable ``provider_cls`` by setting its first ``required_env`` var."""
    monkeypatch.setenv(provider_cls.required_env[0], value)


def assert_secret_absent(secret: str, result: Any, caplog: Any) -> None:
    """The secret must be nowhere in the result, its JSON, or captured logs."""
    serialized = json.dumps(result.to_dict())
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in serialized
    assert secret not in logs
    if result.reason is not None:
        assert secret not in result.reason
    for evidence in result.evidence:
        assert evidence.raw_reference is None or secret not in evidence.raw_reference
