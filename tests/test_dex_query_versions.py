"""Pinned provider upgrades preserve old receipts and exact MUTF-8 xrefs."""
from __future__ import annotations

import importlib.metadata
import sys

import pytest

from apkscan.core import dex_query as dq
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, zip_bytes


def test_provider_identity_rejects_mixed_release_and_hash() -> None:
    old_revision, old_hash = dq.SUPPORTED_IDENTITIES["0.1.1.post5"]
    payload = {"provider_version": dq.PINNED_VERSION,
               "provider_revision": old_revision, "findrefs_sha256": old_hash}
    assert not dq._supported_identity(payload)
    payload["provider_revision"] = dq.PINNED_REVISION
    assert not dq._supported_identity(payload)
    payload["findrefs_sha256"] = dq.PINNED_FINDREFS_SHA256
    assert dq._supported_identity(payload)
    payload["provider_revision"] = old_revision
    assert not dq._supported_identity(payload)
    assert not dq._supported_identity(payload, source_hash=False)
    payload["provider_version"] = []
    assert not dq._supported_identity(payload)


@pytest.mark.skipif(sys.platform == "darwin", reason="Worker memory enforcement unavailable")
def test_legacy_receipt_keeps_actual_provider_identity(tmp_path) -> None:
    apk = tmp_path / "legacy.apk"
    apk.write_bytes(zip_bytes([("classes.dex", build_dex(sample_classes()).data)]))
    result = dq.query_apk(apk, ["xref-token-example"],
                          worker_argv=[sys.executable, "tests/fixtures/dex_query/fake_worker.py"])
    assert result["provider_version"] == "0.1.1.post5"
    assert result["provider_revision"] == dq.SUPPORTED_IDENTITIES["0.1.1.post5"][0]
    dq._validate_receipt(result)


@pytest.mark.skipif(sys.platform == "darwin", reason="Worker memory enforcement unavailable")
@pytest.mark.parametrize("value", ["xref-token-example", "emoji-\U0001f600", "nul-\0-value"])
def test_real_isolated_provider_matches_dex_gold_offsets(tmp_path, value) -> None:
    try:
        version = importlib.metadata.version("droidasc")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("Optional ASC provider not installed")
    if dq.resolve_worker_argv() is None or version not in dq.SUPPORTED_IDENTITIES:
        pytest.skip("Optional pinned ASC worker not installed")
    built = build_dex(sample_classes(value))
    apk = tmp_path / "mutf8.apk"
    apk.write_bytes(zip_bytes([("classes.dex", built.data)]))
    result = dq.query_apk(apk, [value])
    assert result["provider_version"] == version
    row = result["members"][0]
    assert row["status"] == "hit"
    assert {(h["descriptor"], h["file_offset"], h["offset"]) for h in row["hits"]} == {
        (h.descriptor, h.file_offset, h.code_unit_offset) for h in built.hits
    }
