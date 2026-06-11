"""文件夹批量分析引擎（apkscan.dynamic.batch.run_folder）测试。

引擎只编排：扫文件夹 → sha256 去重 → 逐个调 auto.run（launch-only）→ 有设备则卸载 →
记台账 → 汇总。device/auto/provision 全部 monkeypatch 掉，不碰真机、不读报告文件。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.dynamic import batch
from apkscan.dynamic.ledger import AnalyzedLedger, apk_sha256


def _make_apk(folder: Path, name: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_bytes(b"PK\x03\x04" + name.encode())  # 内容含名字 → 各 apk sha 不同
    return p


def _ok_result(out_dir: str, pkg: str = "com.evil.app") -> dict:
    return {
        "steps": [],
        "report_paths": [f"{out_dir}/report.html"],
        "package_name": pkg,
        "out_dir": out_dir,
    }


@pytest.fixture
def no_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(batch.device, "has_device", lambda: False)
    monkeypatch.setattr(
        batch.provision, "uninstall_app", lambda *a, **k: {"ok": True, "detail": ""}
    )


def test_run_folder_analyzes_each_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")
    _make_apk(folder, "b.apk")
    calls: list[str] = []

    def _run(apk_path: str, **kwargs: object) -> dict:
        calls.append(apk_path)
        return _ok_result(str(kwargs["out_dir"]))

    monkeypatch.setattr(batch.auto, "run", _run)
    res = batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert len(res["analyzed"]) == 2
    assert len(calls) == 2


def test_run_folder_skips_already_analyzed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    a = _make_apk(folder, "a.apk")
    _make_apk(folder, "b.apk")
    ledger_path = tmp_path / "led.json"
    AnalyzedLedger(ledger_path).record(
        apk_sha256(str(a)), apk_name="a.apk", report_dir="x", status="done"
    )
    runs: list[str] = []

    def _run(apk_path: str, **kwargs: object) -> dict:
        runs.append(apk_path)
        return _ok_result(str(kwargs["out_dir"]))

    monkeypatch.setattr(batch.auto, "run", _run)
    res = batch.run_folder(
        str(folder), out_dir=str(tmp_path / "out"), ledger_path=str(ledger_path)
    )
    assert len(res["skipped"]) == 1
    assert len(res["analyzed"]) == 1
    assert len(runs) == 1  # 只跑没分析过的那个


def test_run_folder_force_reanalyzes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    a = _make_apk(folder, "a.apk")
    ledger_path = tmp_path / "led.json"
    AnalyzedLedger(ledger_path).record(
        apk_sha256(str(a)), apk_name="a.apk", report_dir="x", status="done"
    )
    monkeypatch.setattr(batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"])))
    res = batch.run_folder(
        str(folder), out_dir=str(tmp_path / "out"), ledger_path=str(ledger_path), force=True
    )
    assert len(res["analyzed"]) == 1
    assert len(res["skipped"]) == 0


def test_run_folder_records_success_to_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    a = _make_apk(folder, "a.apk")
    ledger_path = tmp_path / "led.json"
    monkeypatch.setattr(batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"])))
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"), ledger_path=str(ledger_path))
    assert AnalyzedLedger(ledger_path).is_analyzed(apk_sha256(str(a))) is True


def test_run_folder_uninstalls_when_device_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")
    monkeypatch.setattr(batch.device, "has_device", lambda: True)
    monkeypatch.setattr(
        batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"]), pkg="com.evil.app")
    )
    uninstalled: list[str] = []

    def _uninstall(pkg: str, *a: object, **k: object) -> dict:
        uninstalled.append(pkg)
        return {"ok": True, "detail": ""}

    monkeypatch.setattr(batch.provision, "uninstall_app", _uninstall)
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert uninstalled == ["com.evil.app"]


def test_run_folder_no_uninstall_without_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")
    monkeypatch.setattr(batch.device, "has_device", lambda: False)
    monkeypatch.setattr(
        batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"]), pkg="com.evil.app")
    )
    called: list[str] = []
    monkeypatch.setattr(batch.provision, "uninstall_app", lambda pkg, *a, **k: called.append(pkg))
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert called == []


def test_run_folder_per_app_outdir_has_stem_and_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    a = _make_apk(folder, "evilbank.apk")
    seen: dict[str, str] = {}

    def _run(apk_path: str, **kwargs: object) -> dict:
        seen["out_dir"] = str(kwargs["out_dir"])
        return _ok_result(str(kwargs["out_dir"]))

    monkeypatch.setattr(batch.auto, "run", _run)
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert "evilbank" in seen["out_dir"]
    assert apk_sha256(str(a))[:8] in seen["out_dir"]


def test_run_folder_passes_launch_only_and_duration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")
    seen: dict[str, object] = {}

    def _run(apk_path: str, **kwargs: object) -> dict:
        seen.update(kwargs)
        return _ok_result(str(kwargs["out_dir"]))

    monkeypatch.setattr(batch.auto, "run", _run)
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"), capture_duration=30)
    assert seen["capture_duration"] == 30
    assert seen["confirm"] is None  # launch-only：不等人操作 app


def test_run_folder_failure_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")  # sorted：a 先于 b
    _make_apk(folder, "b.apk")

    def _run(apk_path: str, **kwargs: object) -> dict:
        if apk_path.endswith("a.apk"):
            raise RuntimeError("boom")
        return _ok_result(str(kwargs["out_dir"]))

    monkeypatch.setattr(batch.auto, "run", _run)
    res = batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert len(res["failed"]) == 1
    assert len(res["analyzed"]) == 1  # b 仍成功，单个失败不中断整批


def test_run_folder_failed_app_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "samples"
    a = _make_apk(folder, "a.apk")
    ledger_path = tmp_path / "led.json"

    def _boom(apk_path: str, **kwargs: object) -> dict:
        raise RuntimeError("boom")

    monkeypatch.setattr(batch.auto, "run", _boom)
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"), ledger_path=str(ledger_path))
    # 失败的不入台账 → 下次还会重试（不被永久跳过）
    assert AnalyzedLedger(ledger_path).is_analyzed(apk_sha256(str(a))) is False


def test_run_folder_empty_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "empty"
    folder.mkdir()
    monkeypatch.setattr(batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"])))
    res = batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert res["analyzed"] == []
    assert res["skipped"] == []
    assert res["failed"] == []
