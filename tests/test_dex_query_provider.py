"""核心查询回执绑定每个 DEX 成员。替身 worker 不是 ASC。"""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

import apkscan.core.dex_query as dex_query
from apkscan.core.dex_query import DexQueryError, DexQueryLimits, capabilities, query_apk
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, wide_classes, zip_bytes

_WORKER = [
    sys.executable,
    "tests/fixtures/dex_query/fake_worker.py",
]
_LIMITS = DexQueryLimits(timeout_sec=20, memory_bytes=256 * 1024 * 1024)


def test_query_receipt_binds_each_member_including_duplicate_bytes(tmp_path) -> None:
    sample = build_dex(sample_classes())
    wide = build_dex(wide_classes())
    unsupported = build_dex(sample_classes(), version="041")
    apk = tmp_path / "members.apk"
    apk.write_bytes(zip_bytes([
        ("classes.dex", sample.data),
        ("classes2.dex", sample.data),
        ("extra.dex", wide.data),
        ("assets/payload.dex", wide.data),
        ("broken.dex", b"not-a-dex"),
        ("future.dex", unsupported.data),
    ]))
    token = "xref-token-example"
    receipt = query_apk(
        apk,
        [token, "missing-token-example"],
        worker_argv=_WORKER,
        limits=_LIMITS,
    )
    assert receipt["engine_executed"] is True
    assert receipt["consumption"]["memory_limit_enforced"] is True
    assert receipt["apk_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    by_name = {item["name"]: item for item in receipt["members"]}
    assert list(by_name) == [
        "classes.dex",
        "classes2.dex",
        "extra.dex",
        "assets/payload.dex",
        "broken.dex",
        "future.dex",
    ]
    for name in ("classes.dex", "classes2.dex"):
        row = by_name[name]
        assert row["sha256"] == sample.sha256
        assert row["status"] == "hit"
        assert row["precision"] == "exact"
        assert [(hit["descriptor"], hit["file_offset"], hit["offset_unit"]) for hit in row["hits"]] == [
            (hit.descriptor, hit.file_offset, "code_units") for hit in sample.hits
        ]
    assert by_name["extra.dex"]["sha256"] == wide.sha256
    assert by_name["extra.dex"]["hits"] == []
    assert by_name["extra.dex"]["status"] == "no_match"
    assert by_name["assets/payload.dex"]["status"] == "no_match"
    assert by_name["broken.dex"]["status"] == "failed"
    assert by_name["broken.dex"]["reason"] == "input_rejected"
    assert by_name["broken.dex"]["hits"] == []
    assert by_name["future.dex"]["status"] == "unsupported"
    assert by_name["future.dex"]["reason"] == "dex_unsupported"
    assert by_name["future.dex"]["precision"] == "unsupported"
    assert by_name["future.dex"]["hits"] == []
    projected = json.dumps({key: value for key, value in receipt.items() if key != "query_values"})
    assert token not in projected


def test_capabilities_probe_does_not_mark_the_engine_executed() -> None:
    payload = capabilities(worker_argv=_WORKER, limits=_LIMITS)
    assert payload["available"] is True
    assert payload["engine_executed"] is False
    assert payload["memory_limit_enforced"] is True
    assert payload["reason"] is None


def test_forced_tree_kill_result_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from apkscan.core.proctree import OwnedRun

    def fake_run(*_args: object, **_kwargs: object) -> OwnedRun:
        return OwnedRun(
            returncode=0,
            stdout=json.dumps({"schema_version": "asc-worker-result/1", "op": "query"}),
            stderr="",
            timed_out=False,
            ownership_complete=True,
            termination_complete=True,
            forced_tree_kill=True,
            reason_codes=(),
            memory_limit_enforced=True,
            process_limit_enforced=True,
        )

    monkeypatch.setattr(dex_query, "run_owned", fake_run)
    apk = tmp_path / "app.apk"
    apk.write_bytes(zip_bytes([("classes.dex", build_dex(sample_classes()).data)]))
    with pytest.raises(DexQueryError) as caught:
        query_apk(apk, ["token.example.invalid"], worker_argv=["fake-worker"], limits=_LIMITS)
    assert caught.value.reason == "worker_tree_killed"
