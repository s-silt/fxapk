"""Pinned provider upgrades preserve old receipts and exact MUTF-8 xrefs."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import sys
import tomllib
from pathlib import Path

import pytest

from apkscan.core import dex_query as dq
from tests.fixtures.dex_query.dexgen import build_dex, sample_classes, zip_bytes

# 值来自官方 PyPI 轮子，独立计算，不得从生产常量反算。
# findrefs_sha256 是轮子内 droidasc/asc_core/findrefs/findrefs_manager.py 的原始字节摘要；
# wheel_sha256 是 wheel 文件摘要。
# revision 是上游 git commit，轮子里不含、无法从发布物机器核验
# （来源是 plugins/fxapk-asc/README.md），此处不声称已核验。
_ASC_RELEASES = {
    "0.1.2.post2": {
        "wheel_sha256": "5adf6681e6d6eeefe685045115f0db9c63ad2e5c126ff8bbb3fd1f2b76e3e324",
        "findrefs_sha256": "19bab436bf154df6ca1da9cbede95e004de8260a6b22a5d2231862f94efde503",
        "revision": "b93cbd0798131312b6dc083198e6decbca28a12e",
    },
    "0.1.1.post5": {
        "wheel_sha256": "fea2a6fb8bcfcd007f091c3e2a9204a6367250083a2f11d4a7709aac3f36e94b",
        "findrefs_sha256": "99f170737a2a9fb67e4a7a681b98fbc0f56d9e53601cb33f3125b37fd6487b7c",
        "revision": "d3d75ab7a3c092345102d2ec66ab614ad4a6cc75",
    },
}


def _missing_asc_live(detail: str) -> None:
    """缺 ASC 真跑件时 skip；FXAPK_REQUIRE_ASC_LIVE=1 时 fail。"""
    if os.environ.get("FXAPK_REQUIRE_ASC_LIVE") == "1":
        pytest.fail(f"{detail}——本环境声明必须真跑、缺件是 CI 配置错误")
    pytest.skip(detail)


def _droidasc_pins(lines: list[str]) -> list[str]:
    pins: list[str] = []
    for line in lines:
        text = line.strip()
        if text.startswith("droidasc=="):
            pins.append(text.split("==", 1)[1].split(";", 1)[0].strip())
    return pins


def test_identity_tables_match_independent_release_manifest() -> None:
    expected = {
        version: (item["revision"], item["findrefs_sha256"])
        for version, item in _ASC_RELEASES.items()
    }
    assert dq.SUPPORTED_IDENTITIES == expected

    root = Path(__file__).parents[1]
    # 顶层只导入标准库，按路径加载即可，不需要安装 droidasc。
    worker_path = root / "plugins/fxapk-asc/src/fxapk_asc/worker.py"
    spec = importlib.util.spec_from_file_location("fxapk_asc_worker_manifest", worker_path)
    assert spec is not None and spec.loader is not None
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    assert worker.SUPPORTED_IDENTITIES == dq.SUPPORTED_IDENTITIES
    assert worker.PINNED_VERSION == dq.PINNED_VERSION
    assert worker.PINNED_REVISION == dq.PINNED_REVISION
    assert worker.PINNED_FINDREFS_SHA256 == dq.PINNED_FINDREFS_SHA256

    lock_path = root / "plugins/fxapk-asc/requirements.lock"
    assert _droidasc_pins(lock_path.read_text(encoding="utf-8").splitlines()) == [dq.PINNED_VERSION]
    project = tomllib.loads((root / "plugins/fxapk-asc/pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    assert _droidasc_pins([dep for dep in dependencies if isinstance(dep, str)]) == [dq.PINNED_VERSION]


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
        _missing_asc_live("Optional ASC provider not installed")
    if dq.resolve_worker_argv() is None or version not in dq.SUPPORTED_IDENTITIES:
        _missing_asc_live("Optional pinned ASC worker not installed")
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
