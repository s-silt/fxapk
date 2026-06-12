"""文件夹批量分析引擎（apkscan.dynamic.batch.run_folder）测试。

引擎只编排：扫文件夹 → sha256 去重 → 逐个调 auto.run（launch-only）→ 有设备则卸载 →
记台账 → 汇总。device/auto/provision 全部 monkeypatch 掉，不碰真机、不读报告文件。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.dynamic import batch
from apkscan.dynamic.ledger import AnalyzedLedger, apk_sha256

runner = CliRunner()


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
    monkeypatch.setattr(batch.device, "select_target_serial", lambda: None)
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
    monkeypatch.setattr(batch.device, "select_target_serial", lambda: "emulator-5554")
    monkeypatch.setattr(
        batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"]), pkg="com.evil.app")
    )
    uninstalled: list[tuple[str, object]] = []

    def _uninstall(pkg: str, serial: object = None, **k: object) -> dict:
        uninstalled.append((pkg, serial))
        return {"ok": True, "detail": ""}

    monkeypatch.setattr(batch.provision, "uninstall_app", _uninstall)
    batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    # 卸载钉定选中设备的 serial（多设备/一机多 transport 不再 more than one）。
    assert uninstalled == [("com.evil.app", "emulator-5554")]


def test_run_folder_no_uninstall_without_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "samples"
    _make_apk(folder, "a.apk")
    monkeypatch.setattr(batch.device, "select_target_serial", lambda: None)
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


# ---------------------------------------------------------------------------
# 跨样本团伙聚类接线（读各包主报告 → correlate → 写 case_correlation.json）
# ---------------------------------------------------------------------------


def _write_report(d: Path, c2: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.json").write_text(
        json.dumps({"meta": {"sign_subject": "CN=X"}, "leads": [{"value": c2, "is_c2": True}]}),
        encoding="utf-8",
    )


def test_run_correlation_clusters_shared_c2(tmp_path: Path) -> None:
    out = tmp_path / "out"
    a, b = out / "a__1111", out / "b__2222"
    _write_report(a, "evil.com")
    _write_report(b, "evil.com")
    analyzed = [
        {"apk": "a.apk", "sha256": "sha_a", "report_paths": [str(a / "report.json")], "out_dir": str(a)},
        {"apk": "b.apk", "sha256": "sha_b", "report_paths": [str(b / "report.json")], "out_dir": str(b)},
    ]
    clusters = batch._run_correlation(analyzed, str(out))
    assert len(clusters) == 1
    assert set(clusters[0]["members"]) == {"sha_a", "sha_b"}
    assert (out / "case_correlation.json").is_file()


def test_run_correlation_missing_report_is_safe(tmp_path: Path) -> None:
    # 主报告文件不存在（如静态都失败）→ 不崩，无簇。
    analyzed = [
        {"apk": "a.apk", "sha256": "sha_a", "report_paths": [str(tmp_path / "nope.json")], "out_dir": "x"},
    ]
    assert batch._run_correlation(analyzed, str(tmp_path / "out")) == []


def test_run_folder_includes_clusters_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_device: None
) -> None:
    folder = tmp_path / "empty"
    folder.mkdir()
    monkeypatch.setattr(batch.auto, "run", lambda apk_path, **k: _ok_result(str(k["out_dir"])))
    res = batch.run_folder(str(folder), out_dir=str(tmp_path / "out"))
    assert "clusters" in res
    assert res["summary"]["clusters"] == 0


# ---------------------------------------------------------------------------
# CLI：fxapk batch <folder>（薄包装，把参数透传引擎 + 打印汇总）
# ---------------------------------------------------------------------------


def _patch_run_folder(monkeypatch: pytest.MonkeyPatch, result: dict) -> dict:
    calls: dict = {"called": False, "kwargs": None}

    def _fake(folder: str, **kwargs: object) -> dict:
        calls["called"] = True
        calls["folder"] = folder
        calls["kwargs"] = kwargs
        cb = kwargs.get("on_progress")
        if callable(cb):
            cb("扫描中")  # 确认 cli 进度回调可安全调用
        return result

    monkeypatch.setattr(batch, "run_folder", _fake)
    return calls


def test_cli_batch_passes_args_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = {
        "analyzed": [{"apk": "a.apk", "sha256": "x", "package_name": "com.x",
                      "report_paths": ["r"], "out_dir": "o", "status": "done"}],
        "skipped": [],
        "failed": [],
        "summary": {"total": 1, "analyzed": 1, "skipped": 0, "failed": 0, "had_device": False},
        "out_dir": "out_batch",
        "ledger_path": "x",
    }
    calls = _patch_run_folder(monkeypatch, result)
    res = runner.invoke(
        cli.app,
        ["batch", str(tmp_path), "--out", "myout", "--offline",
         "--duration", "30", "--fmt", "json", "--force"],
    )
    assert res.exit_code == 0
    assert calls["called"] is True
    kw = calls["kwargs"]
    assert kw["out_dir"] == "myout"
    assert kw["online"] is False
    assert kw["capture_duration"] == 30
    assert kw["formats"] == ["json"]
    assert kw["force"] is True
    assert callable(kw["on_progress"])
    assert "a.apk" in res.output


def test_cli_batch_prints_clusters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = {
        "analyzed": [],
        "skipped": [],
        "failed": [],
        "clusters": [
            {
                "cluster_id": 1,
                "members": ["sha_a", "sha_b"],
                "shared": [{"kind": "c2", "value": "evil.com"}],
            }
        ],
        "summary": {"total": 2, "analyzed": 2, "skipped": 0, "failed": 0, "had_device": False, "clusters": 1},
        "out_dir": "out_batch",
        "ledger_path": "x",
    }
    _patch_run_folder(monkeypatch, result)
    res = runner.invoke(cli.app, ["batch", str(tmp_path)])
    assert res.exit_code == 0
    assert "团伙簇" in res.output
    assert "evil.com" in res.output  # 并案依据（共享 C2）


def test_cli_batch_prints_summary_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = {
        "analyzed": [],
        "skipped": [{"apk": "old.apk", "sha256": "y"}],
        "failed": [{"apk": "bad.apk", "sha256": "z", "detail": "处理异常"}],
        "summary": {"total": 2, "analyzed": 0, "skipped": 1, "failed": 1, "had_device": True},
        "out_dir": "out_batch",
        "ledger_path": "x",
    }
    _patch_run_folder(monkeypatch, result)
    res = runner.invoke(cli.app, ["batch", str(tmp_path)])
    assert res.exit_code == 0
    assert "跳过 1" in res.output
    assert "失败 1" in res.output
    assert "old.apk" in res.output
    assert "bad.apk" in res.output
