from __future__ import annotations

import logging

from apkscan.core.redact import (
    redact_url,
    safe_exception_text,
    scrub_urls,
)


_SECRET_PARTS = (
    "alice",
    "correct-horse",
    "api_key=top-secret",
    "private-section",
)


def test_redact_url_removes_userinfo_query_and_fragment() -> None:
    raw = (
        "https://alice:correct-horse@example.com:8443/config/app.json"
        "?api_key=top-secret&mode=prod#private-section"
    )

    rendered = redact_url(raw)

    assert rendered.startswith(
        "https://example.com:8443/config/app.json?***#*** [url:"
    )
    assert rendered.endswith("]")
    assert all(secret not in rendered for secret in _SECRET_PARTS)


def test_redact_url_fingerprint_is_stable_and_tracks_full_input() -> None:
    first = redact_url("https://example.com/a?token=first")
    repeated = redact_url("https://example.com/a?token=first")
    changed = redact_url("https://example.com/a?token=second")

    assert first == repeated
    assert first != changed
    assert "first" not in first
    assert "second" not in changed


def test_redact_url_never_returns_malformed_input() -> None:
    raw = "https://alice:secret@example.com:invalid/path?token=value"

    rendered = redact_url(raw)

    assert rendered.startswith("<redacted-url> [url:")
    assert raw not in rendered
    assert "secret" not in rendered
    assert "token=value" not in rendered


def test_scrub_urls_redacts_url_inside_exception_text() -> None:
    raw_url = (
        "https://alice:correct-horse@example.com/api"
        "?api_key=top-secret#private-section"
    )
    text = f"request failed for {raw_url}"

    scrubbed, changed = scrub_urls(text)

    assert changed is True
    assert "request failed for https://example.com/api?***#*** [url:" in scrubbed
    assert all(secret not in scrubbed for secret in _SECRET_PARTS)


def test_safe_exception_text_defaults_to_type_only() -> None:
    raw_url = (
        "https://alice:correct-horse@example.com/api"
        "?api_key=top-secret#private-section"
    )
    exc = RuntimeError(f"request failed for {raw_url}")

    rendered = safe_exception_text(exc)

    assert rendered == "RuntimeError"
    assert raw_url not in rendered
    assert all(secret not in rendered for secret in _SECRET_PARTS)


def test_safe_exception_text_can_include_redacted_message() -> None:
    raw_url = (
        "https://alice:correct-horse@example.com/api"
        "?api_key=top-secret#private-section"
    )
    exc = RuntimeError(f"request failed for {raw_url}")

    rendered = safe_exception_text(exc, include_message=True)

    assert rendered.startswith(
        "RuntimeError: request failed for https://example.com/api?***#*** [url:"
    )
    assert all(secret not in rendered for secret in _SECRET_PARTS)


def _raise_url_exception(raw_url: str) -> None:
    raise RuntimeError(f"request failed for {raw_url}")


def test_exc_info_traceback_demonstrates_why_it_must_not_be_forwarded(
    caplog,
) -> None:
    """Mutation guard: changing exc_info=False to True must expose the secret."""
    logger = logging.getLogger("tests.url-redaction")
    raw_url = (
        "https://alice:correct-horse@example.com/api"
        "?api_key=top-secret#private-section"
    )

    with caplog.at_level(logging.WARNING, logger=logger.name):
        try:
            _raise_url_exception(raw_url)
        except RuntimeError as exc:
            logger.warning(
                "download failed: %s (%s)",
                redact_url(raw_url),
                safe_exception_text(exc),
                exc_info=False,
            )

    output = caplog.text
    assert "https://example.com/api?***#*** [url:" in output
    assert "RuntimeError" in output
    assert all(secret not in output for secret in _SECRET_PARTS)
