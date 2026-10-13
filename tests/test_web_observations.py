"""核心 web_observations 安全投影：不依赖可选插件，畸形输入不升 complete。"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.report_io import report_from_dict
from apkscan.report.digest import build_digest
from apkscan.report.html import render_to_string

_SAMPLE = "ab" * 32


def _report(meta: dict | None = None) -> dict:
    payload = {
        "schema_version": "1.2",
        "package_name": "example.app",
        "meta": {
            "sample_sha256": _SAMPLE,
            "package_name": "example.app",
            "closure": {"status": "partial", "gaps": ["keep-gap"], "targets": []},
        },
        "leads": [
            {
                "category": "DOMAIN",
                "value": "keep.example",
                "advice": "待核",
                "notes": "same-note",
            }
        ],
        "endpoints": [{"value": "keep.example", "kind": "domain"}],
        "findings": [],
        "analyzer_status": [],
        "mystery_top": {"token": "preserve-me"},
    }
    if meta:
        payload["meta"].update(meta)
    return payload


def test_missing_meta_does_not_add_digest_fields() -> None:
    from apkscan.core.web_observations import digest_web_observations

    base = _report()
    digest = build_digest(base)
    assert "web_observations" not in digest
    assert digest["sha256"] == _SAMPLE
    assert digest["leads"][0]["value"] == "keep.example"
    assert digest["closure"]["status"] == "partial"
    assert digest_web_observations(None)["status"] == "unknown"
    assert digest_web_observations(None)["coverage_status"] != "complete"


def test_malformed_observation_stays_unknown_and_does_not_leak() -> None:
    secret = "https://evil.example/secret-path"
    script = "<script>alert(1)</script>"
    payload = _report(
        {
            "web_observations": [
                {
                    "coverage_status": "complete",
                    "provider": "rea",
                    "source_sha256": "cd" * 32,
                    "bundle_relative_path": "external_observations/" + ("cd" * 32) + "/",
                    "notes": secret,
                    "gaps": [script, "click_attribution_unverified", "not a fixed gap !!!"],
                    "request_count": 2,
                    "script_count": 1,
                    "identity": "declared",
                    "provenance_authenticated": True,
                    "closure_evaluated": True,
                    "target_app_attribution_verified": True,
                    "click_attribution_verified": True,
                }
            ]
        }
    )
    digest = build_digest(payload)
    view = digest["web_observations"]
    encoded = json.dumps(view, ensure_ascii=False)
    assert view["status"] == "unknown"
    assert view["coverage_status"] != "complete"
    assert view["authenticated"] is False
    assert view["closure_evaluated"] is False
    assert view["provenance_authenticated"] is False
    assert secret not in encoded
    assert "alert" not in encoded
    assert "not a fixed gap" not in encoded
    report = report_from_dict(payload)
    html = render_to_string(report)
    assert "外部网页观察" in html
    assert "https://evil.example" not in html
    assert "<script>alert" not in html
    assert 'href="http' not in html
    assert "href='http" not in html


def test_unknown_fields_are_dropped_and_bad_schema_stays_unknown(caplog) -> None:
    import logging

    from apkscan.core.web_observations import digest_web_observations

    secret = "free-text-must-not-surface"
    sha = "ef" * 32

    class Explosive(dict):
        def keys(self):  # type: ignore[no-untyped-def]
            raise RuntimeError(secret)

    caplog.set_level(logging.ERROR)
    exploded = digest_web_observations([Explosive()])
    assert exploded["status"] == "unknown"
    assert secret not in caplog.text
    view = digest_web_observations(
        [
            {
                "schema_version": "fxapk-web-observation-attachment/1",
                "provider": "rea",
                "identity": "unknown",
                "source_sha256": sha,
                "bundle_relative_path": f"external_observations/{sha}/",
                "request_count": 1,
                "script_count": 0,
                "async_count": 0,
                "action_count": 0,
                "coverage_status": "partial",
                "gaps": ["partial_coverage"],
                "bundle_integrity_checked": True,
                "provenance_authenticated": False,
                "target_app_attribution_verified": False,
                "click_attribution_verified": False,
                "closure_evaluated": False,
                "notes": {secret: {"nested": secret}},
            },
            {"schema_version": "other", "provider": "rea", "notes": secret},
        ]
    )
    encoded = json.dumps(view, ensure_ascii=False)
    assert view["observations"][0]["status"] == "partial"
    assert view["observations"][1]["status"] == "unknown"
    assert secret not in encoded
    assert view["status"] == "unknown"


def test_plugin_module_is_not_imported_by_core(monkeypatch) -> None:
    import sys

    monkeypatch.delitem(sys.modules, "fxapk_rea", raising=False)
    monkeypatch.delitem(sys.modules, "fxapk_rea.evidence", raising=False)
    monkeypatch.delitem(sys.modules, "fxapk_rea.trace", raising=False)
    source = Path("apkscan/core/web_observations.py").read_text(encoding="utf-8")
    digest_source = Path("apkscan/report/digest.py").read_text(encoding="utf-8")
    html_source = Path("apkscan/report/html.py").read_text(encoding="utf-8")
    assert "fxapk_rea" not in source
    assert "fxapk_rea" not in digest_source
    assert "fxapk_rea" not in html_source
    html = render_to_string(report_from_dict(_report()))
    assert "外部网页观察" not in html
    assert "fxapk_rea" not in sys.modules
