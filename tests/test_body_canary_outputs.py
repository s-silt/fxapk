"""Regression tests for keeping captured HTTP bodies out of derived reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core.models import Report
from apkscan.dynamic.merge import load_runtime_endpoints, merge_and_rerender


BODY_CANARY = "APKS_CANARY_RUNTIME_HTTP_BODY_7f9d4c2a"


@pytest.fixture
def runtime_report_with_body_canary(tmp_path: Path) -> Path:
    """Create a valid runtime report with a marker only in captured bodies."""
    path = tmp_path / "runtime_report.json"
    payload = {
        "endpoints": [
            {
                "value": "https://api.example.com/login",
                "kind": "url",
                "evidences": [
                    {
                        "source": "runtime",
                        "location": "synthetic",
                        "snippet": "POST https://api.example.com/login",
                    }
                ],
                "is_cleartext": False,
                "is_private": False,
                "is_suspicious": False,
                "enrichment": {},
            }
        ],
        "sessions": [
            {
                "url": "https://api.example.com/login",
                "method": "POST",
                "request": {
                    "headers": {"content-type": "application/json"},
                    "body": BODY_CANARY,
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": BODY_CANARY,
                },
                "request_body": BODY_CANARY,
                "response_body": BODY_CANARY,
            }
        ],
        "messages": [
            {
                "url": "https://api.example.com/login",
                "method": "POST",
                "request_body": BODY_CANARY,
                "response_body": BODY_CANARY,
            }
        ],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def test_runtime_body_canary_is_absent_from_derived_outputs(
    tmp_path: Path,
    runtime_report_with_body_canary: Path,
) -> None:
    report = Report(
        package_name="com.example.bodycanary",
        meta={},
        leads=[],
        endpoints=[],
        findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )

    runtime_endpoints = load_runtime_endpoints(
        str(runtime_report_with_body_canary)
    )
    assert len(runtime_endpoints) == 1
    assert runtime_endpoints[0].value == "https://api.example.com/login"

    out_dir = tmp_path / "derived"
    stats = merge_and_rerender(
        report,
        runtime_endpoints,
        str(out_dir),
        base="body-canary",
        formats=["json", "html"],
        runtime_report_path=str(runtime_report_with_body_canary),
    )

    json_path = out_dir / "body-canary.json"
    html_path = out_dir / "body-canary.html"

    runtime_text = runtime_report_with_body_canary.read_text(encoding="utf-8")
    assert BODY_CANARY in runtime_text

    assert json_path.exists()
    assert html_path.exists()
    assert {str(json_path), str(html_path)} <= set(stats["report_paths"])

    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")

    assert BODY_CANARY not in json_text
    assert BODY_CANARY not in html_text

    payload = json.loads(json_text)
    assert runtime_endpoints[0].value in {
        endpoint["value"] for endpoint in payload["endpoints"]
    }
