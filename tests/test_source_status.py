from __future__ import annotations

import pytest

from apkscan.core.source_status import (
    SOURCE_STATUS_FAILED,
    SOURCE_STATUS_HIT,
    SOURCE_STATUS_NO_RECORD,
    SOURCE_STATUS_SKIPPED,
    canonicalize_source_status_tree,
    is_answered_source_status,
    normalize_source_status,
    normalize_source_status_map,
    provider_payload_if_hit,
    source_status_value,
)


def test_normalize_accepts_legacy_string_status() -> None:
    assert normalize_source_status("hit") == {"status": SOURCE_STATUS_HIT}
    assert normalize_source_status("no_record") == {"status": SOURCE_STATUS_NO_RECORD}


def test_normalize_maps_private_failure_detail_to_public_contract() -> None:
    assert normalize_source_status("timeout") == {
        "status": SOURCE_STATUS_FAILED,
        "error_type": "timeout",
    }
    assert normalize_source_status({"status": "quota_insufficient", "detail": "credits"}) == {
        "status": SOURCE_STATUS_FAILED,
        "error_type": "quota_insufficient",
    }


def test_normalize_maps_not_applicable_to_skipped_reason() -> None:
    assert normalize_source_status("not_applicable") == {
        "status": SOURCE_STATUS_SKIPPED,
        "reason": "not_applicable",
    }


def test_normalize_preserves_only_contract_metadata() -> None:
    raw = {
        "status": "failed",
        "error_type": "provider_error",
        "reason": "upstream rejected request",
        "attempts": 2,
    }
    assert normalize_source_status(raw) == {
        "status": "failed",
        "error_type": "provider_error",
        "reason": "upstream rejected request",
    }


def test_normalize_drops_non_string_optional_metadata() -> None:
    assert normalize_source_status(
        {"status": "failed", "error_type": 429, "reason": ["timeout"]}
    ) == {"status": "failed"}


def test_normalize_invalid_status_fails_closed() -> None:
    assert normalize_source_status("made_up") == {
        "status": SOURCE_STATUS_FAILED,
        "error_type": "invalid_status",
        "reason": "legacy_status:made_up",
    }


def test_normalize_map_accepts_mixed_legacy_and_object_entries() -> None:
    assert normalize_source_status_map(
        {
            "rdap": "hit",
            "fofa": {"status": "rate_limited", "detail": "429"},
        }
    ) == {
        "fofa": {
            "status": "failed",
            "error_type": "rate_limited",
        },
        "rdap": {"status": "hit"},
    }


def test_status_helpers_accept_legacy_and_canonical_shapes() -> None:
    assert source_status_value("hit") == "hit"
    assert source_status_value({"status": "no_record"}) == "no_record"
    assert source_status_value("timeout") == "failed"
    assert is_answered_source_status("hit") is True
    assert is_answered_source_status({"status": "no_record"}) is True
    assert is_answered_source_status("timeout") is False


@pytest.mark.parametrize("status", ["failed", "no_record", "skipped", "disabled", "made_up"])
def test_provider_payload_rejects_every_non_hit_status(status: str) -> None:
    enrichment = {
        "source_status": {"dns": {"status": status}},
        "dns": {"ips": ["198.51.100.10"]},
    }

    assert provider_payload_if_hit(enrichment, "dns") == {}


def test_provider_payload_requires_entry_when_status_map_is_present() -> None:
    enrichment = {
        "source_status": {"certs": {"status": "hit"}},
        "dns": {"ips": ["198.51.100.10"]},
    }

    assert provider_payload_if_hit(enrichment, "dns") == {}


def test_provider_payload_accepts_canonical_or_legacy_hit_entry() -> None:
    payload = {"ips": ["198.51.100.10"]}

    assert provider_payload_if_hit(
        {"source_status": {"dns": {"status": "hit"}}, "dns": payload}, "dns"
    ) == payload
    assert provider_payload_if_hit(
        {"source_status": {"dns": "hit"}, "dns": payload}, "dns"
    ) == payload


def test_provider_payload_preserves_reports_without_any_source_status_key() -> None:
    payload = {"ips": ["198.51.100.10"]}

    assert provider_payload_if_hit({"dns": payload}, "dns") == payload


def test_canonicalization_migrates_legacy_provider_payloads_at_nested_enrichment_nodes() -> None:
    tree = {
        "dns": {"ips": ["198.51.100.10"]},
        "resolved_ip_enrichment": {
            "198.51.100.10": {
                "ip_rdap": {"netname": "EXAMPLE-NET"},
                "asn": {"error": "timeout: synthetic"},
                "certs": {"note": "查询无结果"},
            }
        },
    }

    canonicalize_source_status_tree(tree)

    assert tree["source_status"] == {"dns": {"status": "hit"}}
    child = tree["resolved_ip_enrichment"]["198.51.100.10"]
    assert child["source_status"] == {
        "asn": {"status": "failed", "error_type": "timeout"},
        "certs": {"status": "no_record"},
        "ip_rdap": {"status": "hit"},
    }


def test_canonicalization_never_fills_provider_missing_from_explicit_status_map() -> None:
    tree = {
        "source_status": {"certs": {"status": "hit"}},
        "dns": {"ips": ["198.51.100.10"]},
    }

    canonicalize_source_status_tree(tree)

    assert tree["source_status"] == {"certs": {"status": "hit"}}
    assert provider_payload_if_hit(tree, "dns") == {}


def test_canonicalization_malformed_legacy_marker_fails_closed() -> None:
    tree = {"dns": {"_source_status": {"unexpected": True}, "ips": ["198.51.100.10"]}}

    canonicalize_source_status_tree(tree)

    assert tree["source_status"] == {
        "dns": {"status": "failed", "error_type": "invalid_source_status"}
    }


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("failed", {"status": "failed"}),
        ("no_record", {"status": "no_record"}),
        ("timeout", {"status": "failed", "error_type": "timeout"}),
        (
            "made_up",
            {
                "status": "failed",
                "error_type": "invalid_status",
                "reason": "legacy_status:made_up",
            },
        ),
    ],
)
def test_canonicalization_honours_legacy_private_status_marker(
    marker: str, expected: dict[str, str]
) -> None:
    tree = {"dns": {"_status": marker, "ips": ["198.51.100.10"]}}

    canonicalize_source_status_tree(tree)

    assert tree["source_status"] == {"dns": expected}
    assert provider_payload_if_hit(tree, "dns") == {}


def test_legacy_source_status_marker_takes_priority_over_private_status() -> None:
    tree = {
        "dns": {
            "_source_status": "hit",
            "_status": "failed",
            "ips": ["198.51.100.10"],
        }
    }

    canonicalize_source_status_tree(tree)

    assert tree["source_status"] == {"dns": {"status": "hit"}}
    assert provider_payload_if_hit(tree, "dns")["ips"] == ["198.51.100.10"]


@pytest.mark.parametrize(
    ("field", "marker"),
    [
        ("_status", "failed"),
        ("_status", "no_record"),
        ("_status", "timeout"),
        ("_status", "made_up"),
        ("_source_status", "failed"),
    ],
)
def test_direct_legacy_provider_helper_rejects_non_hit_markers(
    field: str, marker: str
) -> None:
    enrichment = {
        "dns": {field: marker, "ips": ["198.51.100.10"]},
    }

    assert provider_payload_if_hit(enrichment, "dns") == {}


def test_direct_legacy_provider_helper_accepts_hit_and_strips_controls() -> None:
    enrichment = {
        "dns": {
            "_source_status": "hit",
            "_status": "failed",
            "_via": "legacy",
            "ips": ["198.51.100.10"],
        },
    }

    assert provider_payload_if_hit(enrichment, "dns") == {
        "ips": ["198.51.100.10"]
    }
