"""用隔离 venv 里的真实 ASC 跑合成 DEX。没有该 venv 时跳过，不把替身当成 ASC。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from apkscan.core.dex_query import DexQueryLimits, query_apk
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, wide_classes, zip_bytes

_VENV = Path(os.environ.get("FXAPK_ASC_TEST_PYTHON", sys.executable))


def _require_worker() -> list[str]:
    if not _VENV.exists():
        pytest.skip("隔离 ASC venv 不存在")
    probe = subprocess.run(
        [str(_VENV), "-I", "-c", "import droidasc, fxapk_asc.worker"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip("隔离 venv 里没有 droidasc 或 fxapk-asc")
    return [str(_VENV), "-I", "-m", "fxapk_asc.worker"]


def _apk_handler_names(apk: Path) -> list[str]:
    script = (
        "import json, mmap, sys\n"
        "from droidasc.asc_client.apk_handler import _parse_cd_dex_entries\n"
        "with open(sys.argv[1], 'rb') as handle:\n"
        "    mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)\n"
        "    print(json.dumps([item[0] for item in _parse_cd_dex_entries(mapped)]))\n"
    )
    result = subprocess.run(
        [str(_VENV), "-I", "-c", script, str(apk)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _asc_on_041(directory: Path) -> dict[str, object]:
    dex = build_dex(sample_classes(), version="041").data
    script = (
        "import json, sys\n"
        "from droidasc.asc_core.findrefs.findrefs_manager import FindRefManager\n"
        "from droidasc.asc_core.utils.tinydex import DEX\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "try:\n"
        "    dex = DEX(data)\n"
        "    FindRefManager(dex).find_ref({'string': 'xref-token-example'})\n"
        "    print(json.dumps({'raised': False}))\n"
        "except Exception as exc:\n"
        "    print(json.dumps({'raised': True, 'type': type(exc).__name__}))\n"
    )
    path = directory / "a0-dex041.bin"
    path.write_bytes(dex)
    result = subprocess.run(
        [str(_VENV), "-I", "-c", script, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(result.stdout) if result.stdout else {"raised": True, "type": "no-stdout"}
    payload["returncode"] = result.returncode
    return payload


def test_live_asc_matches_independent_offsets_for_every_zip_location(tmp_path: Path) -> None:
    worker = _require_worker()
    sample = build_dex(sample_classes())
    wide = build_dex(wide_classes())
    unsupported = build_dex(sample_classes(), version="041")
    apk = tmp_path / "members.apk"
    apk.write_bytes(zip_bytes([
        ("classes.dex", sample.data),
        ("classes2.dex", sample.data),
        ("extra.dex", wide.data),
        ("assets/payload.dex", wide.data),
        ("future.dex", unsupported.data),
        ("broken.dex", b"not-a-dex"),
    ]))
    upstream = _apk_handler_names(apk)
    assert "classes.dex" in upstream
    assert "classes2.dex" in upstream
    assert "extra.dex" not in upstream
    assert "assets/payload.dex" not in upstream
    started = time.perf_counter()
    receipt = query_apk(
        apk,
        ["xref-token-example", "xref-token-\U0001F4A1", "missing-token-example"],
        worker_argv=worker,
        limits=DexQueryLimits(timeout_sec=60),
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    by_name = {item["name"]: item for item in receipt["members"]}
    for name in ("classes.dex", "classes2.dex"):
        row = by_name[name]
        assert row["status"] == "hit"
        assert [(hit["descriptor"], hit["file_offset"], hit["offset"]) for hit in row["hits"]] == [
            (hit.descriptor, hit.file_offset, hit.code_unit_offset) for hit in sample.hits
        ]
    for name in ("extra.dex", "assets/payload.dex"):
        row = by_name[name]
        assert row["status"] == "hit"
        assert [(hit["descriptor"], hit["file_offset"], hit["offset"]) for hit in row["hits"]] == [
            (hit.descriptor, hit.file_offset, hit.code_unit_offset) for hit in wide.hits
        ]
    assert by_name["future.dex"]["status"] == "unsupported"
    assert by_name["future.dex"]["hits"] == []
    assert by_name["broken.dex"]["status"] == "failed"
    assert by_name["broken.dex"]["hits"] == []
    assert receipt["consumption"]["memory_limit_enforced"] is True
    evidence = {
        "provider_version": receipt["provider_version"],
        "provider_revision": receipt["provider_revision"],
        "elapsed_ms": round(elapsed_ms, 3),
        "peak_job_memory_bytes": receipt["consumption"]["peak_memory_bytes"],
        "memory_limit_enforced": True,
        "process_limit_enforced": receipt["consumption"]["process_limit_enforced"],
        "platform": sys.platform,
        "apk_handler_names": upstream,
        "dex041_asc_attempt": _asc_on_041(tmp_path),
        "jadx": "not available",
        "members": {
            name: {
                "status": row["status"],
                "reason": row["reason"],
                "precision": row["precision"],
                "hits": row["hits"],
            }
            for name, row in by_name.items()
        },
    }
    (tmp_path / "a0-members.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
