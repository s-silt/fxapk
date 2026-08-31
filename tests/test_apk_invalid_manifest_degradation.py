from __future__ import annotations

from pathlib import Path

from apkscan.core import apk as apk_mod
from apkscan.core.models import AnalysisConfig


class _InvalidManifestApk:
    def __init__(self, _path: str) -> None:
        pass

    def is_valid_APK(self) -> bool:  # noqa: N802 - androguard API spelling
        return False

    def get_all_dex(self):  # noqa: ANN201 - mirrors androguard generator
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
