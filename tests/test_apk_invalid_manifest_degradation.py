from __future__ import annotations

import struct
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from apkscan.core import apk as apk_mod
from apkscan.core import visibility
from apkscan.core.models import AnalysisConfig
from tests.conftest import FakeContext


class _InvalidManifestApk:
    def __init__(self, _path: str) -> None:
        self.dex_batches_consumed = 0

    def is_valid_APK(self) -> bool:  # noqa: N802 - androguard API spelling
        return False

    def get_all_dex(self):  # noqa: ANN201 - mirrors androguard generator
        self.dex_batches_consumed += 1
        yield b"not-a-valid-dex"


class _BudgetExtractingApk:
    """Drive apkInspector's extraction shim from the real ``load_apk`` lifecycle."""

    barrier: threading.Barrier | None = None

    def __init__(self, path: str) -> None:
        self.path = path

    def is_valid_APK(self) -> bool:  # noqa: N802 - androguard API spelling
        return True

    def get_all_dex(self):  # noqa: ANN201 - mirrors androguard generator
        with zipfile.ZipFile(self.path) as archive, open(self.path, "rb") as apk_file:
            for info in archive.infolist():
                apk_file.seek(info.header_offset)
                header = apk_file.read(30)
                (
                    signature,
                    _version,
                    _flags,
                    method,
                    _mtime,
                    _mdate,
                    _crc,
                    compressed_size,
                    uncompressed_size,
                    filename_length,
                    extra_length,
                ) = struct.unpack("<IHHHHHIIIHH", header)
                assert signature == 0x04034B50
                if self.barrier is not None:
                    self.barrier.wait(timeout=5)
                extracted, _indicator = apk_mod._bounded_extract_file_based_on_header_info(
                    apk_file,
                    {
                        "file_name_length": filename_length,
                        "extra_field_length": extra_length,
                        "compressed_size": compressed_size,
                        "uncompressed_size": uncompressed_size,
                        "compression_method": method,
                    },
                    {
                        "filename": info.filename,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                        "relative_offset_of_local_file_header": info.header_offset,
                    },
                )
                yield extracted


def _underdeclared_dex_apk(path: Path, *, count: int) -> None:
    payload = b"\x00" * 10_000
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for ordinal in range(count):
            name = "classes.dex" if ordinal == 0 else f"classes{ordinal + 1}.dex"
            archive.writestr(name, payload)

    raw = bytearray(path.read_bytes())
    cursor = 0
    patched = 0
    while True:
        cursor = raw.find(b"PK\x01\x02", cursor)
        if cursor < 0:
            break
        raw[cursor + 24:cursor + 28] = (8).to_bytes(4, "little")
        patched += 1
        cursor += 4
    assert patched == count
    path.write_bytes(raw)


def test_invalid_manifest_degrades_but_keeps_dex_jadx_analysis_available(
    tmp_path: Path, monkeypatch,
) -> None:
    """Manifest anti-analysis corruption must not suppress a readable APK's DEX/JADX path."""
    import androguard.core.apk as androguard_apk

    sample = tmp_path / "manifest-poisoned.apk"
    sample.write_bytes(b"not-a-real-zip; fake APK object owns the control-flow fixture")
    monkeypatch.setattr(androguard_apk, "APK", _InvalidManifestApk)

    ctx = apk_mod.load_apk(str(sample), AnalysisConfig(online=False))

    assert ctx.apk_validation_ok is False
    assert ctx._apk is not None
    assert ctx.apk_path == str(sample.resolve())
    # DEX 观察路径必须真的被走到（get_all_dex 被消费、坏 DEX 单条跳过而非整体压掉），
    # 而不是靠「降级」名义静默短路（codex 复审 P2：测试要锁真实调用链）。
    assert ctx._apk.dex_batches_consumed == 1


def test_dex_aggregate_budget_rejects_before_androguard(tmp_path: Path) -> None:
    """单条不超 zip-bomb/单文件上限、总量超聚合预算的 DEX 矩阵在 androguard 解压前被拒。

    用字节级放大 central directory 声明构造（不占实际磁盘），走真实常量路径、
    不 monkeypatch——改小源码常量或拆掉预算闸时本测试必须变红（突变验证过）。
    """
    import zipfile

    per_dex_declared = 256 * 1024 * 1024  # 恰不超单文件上限，也不超 zip-bomb 的 500MB
    sample = tmp_path / "dex-matrix.apk"
    with zipfile.ZipFile(sample, "w") as zf:
        for i in range(5):  # 5 × 256MB = 1.25GB > 1GiB 总预算
            zf.writestr(f"classes{i + 1}.dex" if i else "classes.dex", b"x")

    raw = bytearray(sample.read_bytes())
    marker = 0
    patched = 0
    while True:
        marker = raw.find(b"PK\x01\x02", marker)
        if marker == -1:
            break
        raw[marker + 20:marker + 24] = per_dex_declared.to_bytes(4, "little")  # compressed
        raw[marker + 24:marker + 28] = per_dex_declared.to_bytes(4, "little")  # uncompressed
        patched += 1
        marker += 4
    assert patched == 5, patched
    sample.write_bytes(bytes(raw))

    with pytest.raises(apk_mod.ApkParseError, match="聚合预算"):
        apk_mod.load_apk(str(sample), AnalysisConfig(online=False))


def test_invalid_manifest_state_is_machine_checkable_in_report_outputs() -> None:
    """Manifest 盲区只阻断相关主张，并在 closure 重算后保留。"""
    complete_meta = {
        "jadx_receipt": {"status": "ok", "complete": True},
        "resource_files_scanned": 1,
        "runtime_merged": True,
        "capture_quality": {"dynamic_status": "complete"},
    }
    degraded_meta = {**complete_meta, "apk_validation_ok": False}
    assessment = visibility.assess({"meta": degraded_meta})
    assert assessment["sources"]["manifest"]["visibility"] == "unavailable"
    assert assessment["sources"]["manifest"]["inputs_seen"] == ["apk_validation_ok"]
    assert any(
        note.startswith("[manifest]") and "apk_validation_ok=False" in note
        for note in assessment["notes"]
    ), assessment["notes"]
    assert assessment["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert assessment["degraded"] is True

    reassessed = visibility.reassess_derived(assessment, {"apk_validation_ok": False})
    assert reassessed["sources"]["manifest"]["visibility"] == "unavailable"
    assert any(note.startswith("[manifest]") for note in reassessed["notes"])

    # closure 刷新遇到裁剪掉 apk_validation_ok 的报告时，必须沿用旧确证盲区。
    from apkscan.core.closure import _preserve_confirmed_gaps

    fresh = visibility.assess({"meta": complete_meta})
    preserved = _preserve_confirmed_gaps(assessment, fresh, complete_meta)
    assert preserved["sources"]["manifest"]["visibility"] == "unavailable"
    assert any("沿用先前快照" in why for why in preserved["sources"]["manifest"]["why"])

    clean = visibility.assess({"meta": complete_meta})
    assert clean["sources"]["manifest"]["visibility"] == "complete"
    assert not any(note.startswith("[manifest]") for note in clean["notes"])
    assert clean["blocked_claims"] == []
    assert clean["degraded"] is False


def test_pipeline_run_projects_apk_validation_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """真入口锁：context False 必须经 pipeline.run 落到 meta 与 visibility。"""
    from apkscan.core import pipeline

    monkeypatch.setattr(pipeline, "discover_analyzers", lambda: [])
    monkeypatch.setattr(pipeline, "discover_enrichers", lambda: [])
    ctx = FakeContext()
    ctx.apk_validation_ok = False
    ctx.dex_available = True
    ctx.extra_dex_report = {}

    report = pipeline.run(ctx, AnalysisConfig(online=False))

    assert report.meta["apk_validation_ok"] is False
    assert "apk_validation_warning" in report.meta
    assert report.meta["visibility"]["sources"]["manifest"]["visibility"] == "unavailable"


def test_dex_budget_constants_stay_in_sync_with_jadx_materialization() -> None:
    """apk.py 与 jadx.py 的 DEX 预算常量必须同步（codex 二轮 P2：重复定义漂移风险）。"""
    from apkscan.analyzers import jadx

    assert (
        apk_mod._DEX_SINGLE_LIMIT_BYTES,
        apk_mod._DEX_TOTAL_LIMIT_BYTES,
        apk_mod._DEX_COUNT_LIMIT,
    ) == (
        jadx._MAX_MATERIALIZE_DEX_BYTES,
        jadx._MAX_MATERIALIZE_TOTAL_BYTES,
        jadx._MAX_MATERIALIZE_DEX_COUNT,
    )


def test_dex_extract_accumulating_budget_enforced_on_actual_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """低报声明绕过 Level 1 后，shim 的实际解压**累计**闸仍拦（codex 二轮 P1）。

    直驱 shim：两条 DEFLATE classes*.dex 各实际膨胀 10000 字节（central 低报为 8），
    单条远低于 500MB 单条上限，累计 20000 超过 monkeypatch 的 15000 总量 → 第二条拒绝。
    """
    monkeypatch.setattr(apk_mod, "_DEX_TOTAL_LIMIT_BYTES", 15000)
    import androguard.core.apk as androguard_apk

    monkeypatch.setattr(androguard_apk, "APK", _BudgetExtractingApk)
    sample = tmp_path / "underdeclared.apk"
    _underdeclared_dex_apk(sample, count=2)

    with pytest.raises(apk_mod.ApkParseError, match="实际解压超 15000"):
        apk_mod.load_apk(str(sample), AnalysisConfig(online=False))


def test_dex_actual_budget_isolated_between_concurrent_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """并发 load_apk 各有独立实际预算，不能把两个样本的 DEX 字节相加。"""
    import androguard.core.apk as androguard_apk

    monkeypatch.setattr(apk_mod, "_DEX_TOTAL_LIMIT_BYTES", 15_000)
    monkeypatch.setattr(androguard_apk, "APK", _BudgetExtractingApk)
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    _underdeclared_dex_apk(first, count=1)
    _underdeclared_dex_apk(second, count=1)
    _BudgetExtractingApk.barrier = threading.Barrier(2)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda path: apk_mod.load_apk(
                        str(path), AnalysisConfig(online=False)
                    ),
                    (first, second),
                )
            )
    finally:
        _BudgetExtractingApk.barrier = None

    assert len(results) == 2


def test_dex_actual_budget_resets_after_failed_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一次聚合拒绝结束后，下一样本从零计数。"""
    import androguard.core.apk as androguard_apk

    monkeypatch.setattr(apk_mod, "_DEX_TOTAL_LIMIT_BYTES", 15_000)
    monkeypatch.setattr(androguard_apk, "APK", _BudgetExtractingApk)
    rejected = tmp_path / "rejected.apk"
    accepted = tmp_path / "accepted.apk"
    _underdeclared_dex_apk(rejected, count=2)
    _underdeclared_dex_apk(accepted, count=1)

    with pytest.raises(apk_mod.ApkParseError, match="实际解压超 15000"):
        apk_mod.load_apk(str(rejected), AnalysisConfig(online=False))
    assert apk_mod._dex_extract_total_bytes.get() is None
    ctx = apk_mod.load_apk(str(accepted), AnalysisConfig(online=False))
    assert ctx.apk_path == str(accepted.resolve())
    assert apk_mod._dex_extract_total_bytes.get() is None
