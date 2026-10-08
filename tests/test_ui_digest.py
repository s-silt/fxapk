from __future__ import annotations

import json

import pytest

from apkscan.report.digest import build_digest


def test_digest_projects_ui_observation_statuses() -> None:
    digest = build_digest({
        "leads": [],
        "meta": {
            "ui_observations": [
                {"status": "complete", "receipt_path": "ui/one/observation.json"},
                {"status": "partial", "receipt_path": "ui/two/observation.json"},
            ],
        },
    })

    assert digest["ui"] == {"observation_count": 2, "statuses": ["complete", "partial"]}


@pytest.mark.parametrize("status", [None, 1, {"private": "synthetic-secret"}, "synthetic-secret", "complete\nsynthetic-secret"])
def test_ui_digest_maps_unrecognized_status_to_unknown(status):
    digest = build_digest({"leads": [], "meta": {"ui_observations": [{"status": status}]}})

    assert digest["ui"] == {"observation_count": 1, "statuses": ["unknown"]}
    assert "synthetic-secret" not in json.dumps(digest)


@pytest.mark.parametrize("status", ["complete", "partial", "failed", "unavailable", "skipped", "unknown"])
def test_ui_digest_preserves_supported_status(status):
    digest = build_digest({"leads": [], "meta": {"ui_observations": [{"status": status}]}})

    assert digest["ui"]["statuses"] == [status]
