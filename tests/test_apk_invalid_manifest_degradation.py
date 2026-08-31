from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.core import apk as apk_mod
from apkscan.core import visibility
from apkscan.core.models import AnalysisConfig


class _InvalidManifestApk:
    def __init__(self, _path: str) -> None:
        self.dex_batches_consumed = 0

    def is_valid_APK(self) -> bool:  # noqa: N802 - androguard API spelling
        return False

    def get_all_dex(self):  # noqa: ANN201 - mirrors androguard generator
        self.dex_batches_consumed += 1
        yield b"not-a-valid-dex"


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


def test_dex_aggregate_budget_rejects_before_androguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """单条不超 zip-bomb 上限、总量超聚合预算的 DEX 矩阵在 androguard 解压前被拒。"""
    import zipfile

    sample = tmp_path / "dex-matrix.apk"
    with zipfile.ZipFile(sample, "w") as zf:
        zf.writestr(zipfile.ZipInfo("classes.dex"), b"dex\n035\x00" + b"\x00" * 64)

    monkeypatch.setattr(apk_mod, "_DEX_TOTAL_LIMIT_BYTES", 16)
    with pytest.raises(apk_mod.ApkParseError, match="聚合预算"):
        apk_mod.load_apk(str(sample), AnalysisConfig(online=False))


def test_invalid_manifest_state_is_machine_checkable_in_report_outputs() -> None:
    """apk_validation_ok=False 必须在 meta 布尔键与 visibility notes 里机器可读（codex 复审 P1）。"""
    assessment = visibility.assess({"meta": {"apk_validation_ok": False}})
    assert any(
        note.startswith("[manifest]") and "apk_validation_ok=False" in note
        for note in assessment["notes"]
    ), assessment["notes"]
    # 缺失 = 无事件契约：校验通过的报告不得出现该降级行。
    clean = visibility.assess({"meta": {}})
    assert not any(note.startswith("[manifest]") for note in clean["notes"])
