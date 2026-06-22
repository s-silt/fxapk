"""阶段3：自动入账 + 喂图谱 + track ingest 命令集成测试。

铁律呼应：入账/喂图谱是 best-effort 旁路——绝不抛、绝不影响报告产出；kuzu 缺失静默跳过。
全 mock：不联网、不开真浏览器、不碰真机、不依赖真 kuzu。

覆盖（spec §8）：
- analyze/auto 静态步骤后台账有该 APK + leads。
- --no-track 关闭生效（台账不写、图谱不喂）。
- 入账失败不影响报告产出。
- kuzu 缺失时图谱喂入静默跳过（ImportError 被吞，台账仍正常）。
- kuzu 可用时 ingest_report 被调用（mock graph）。
- track ingest 把历史 report.json 回填进台账（+图谱）。
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.models import (
    Confidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.track import autoingest
from apkscan.track.ledger import TrackingLedger

runner = CliRunner()


# ---------------------------------------------------------------------------
# 构造助手
# ---------------------------------------------------------------------------


def _make_report(
    *,
    sha256: str = "a" * 64,
    package_name: str = "com.fraud.app",
    label: str = "杀猪盘",
    leads: list[Lead] | None = None,
) -> Report:
    return Report(
        package_name=package_name,
        meta={"sample_sha256": sha256, "app_label": label},
        leads=leads if leads is not None else [_lead(LeadCategory.DOMAIN, "c2.x.com", "X 公司")],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _lead(category: LeadCategory, value: str, subject: str | None = None) -> Lead:
    return Lead(category=category, value=value, subject=subject, confidence=Confidence.HIGH)


def _use_tmp_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """把默认台账路径指到 tmp（autoingest 用 TrackingLedger() 无参构造，走 env 覆盖）。"""
    p = tmp_path / "tracking.json"
    from apkscan.track.ledger import ENV_TRACKING_DB

    monkeypatch.setenv(ENV_TRACKING_DB, str(p))
    return p


def _patch_graph_ingest(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """打桩 graph：GraphStore（no-op close）+ ingest_report（记录被调），不碰真 kuzu。"""
    import apkscan.graph as graph_mod

    calls: dict[str, Any] = {"ingest_called": False, "sha256": None, "report_path": None}

    class _FakeStore:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def close(self) -> None:
            pass

    def _fake_ingest(report_dict: dict, store: Any, *, report_path: str = "", sha256: str = "") -> bool:
        calls["ingest_called"] = True
        calls["sha256"] = sha256
        calls["report_path"] = report_path
        return True

    monkeypatch.setattr(graph_mod, "GraphStore", _FakeStore)
    monkeypatch.setattr(graph_mod, "ingest_report", _fake_ingest)
    return calls


# ---------------------------------------------------------------------------
# autoingest 单元：入账 + 喂图谱
# ---------------------------------------------------------------------------


def test_auto_track_writes_ledger_and_feeds_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    calls = _patch_graph_ingest(monkeypatch)

    autoingest.auto_track_and_ingest(_make_report(), "/r/report.json", track=True)

    # 台账有该 APK + lead
    data = json.loads(led_path.read_text(encoding="utf-8"))
    apk = data["apks"]["a" * 64]
    assert apk["package"] == "com.fraud.app"
    assert "DOMAIN:c2.x.com" in apk["leads"]
    # 图谱被喂（kuzu 可用 mock）
    assert calls["ingest_called"] is True
    assert calls["sha256"] == "a" * 64
    assert calls["report_path"] == "/r/report.json"


def test_no_track_skips_both(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    calls = _patch_graph_ingest(monkeypatch)

    autoingest.auto_track_and_ingest(_make_report(), "/r/report.json", track=False)

    assert not led_path.exists()  # 台账没写
    assert calls["ingest_called"] is False  # 图谱没喂


def test_kuzu_missing_silently_skips_graph_but_ledger_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    # reset 一次性 warned 标志，确保 ImportError 分支被走
    monkeypatch.setattr(autoingest, "_kuzu_missing_warned", False)

    real_import = builtins.__import__

    def _fake_import(name: str, *a: Any, **k: Any) -> Any:
        if name == "apkscan.graph" or name.startswith("apkscan.graph"):
            raise ImportError("No module named 'kuzu'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    # 不抛
    autoingest.auto_track_and_ingest(_make_report(), "/r/report.json", track=True)

    # 台账照样写入（图谱缺失不连累入账）
    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert "a" * 64 in data["apks"]


def test_ledger_failure_does_not_raise_and_graph_still_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_tmp_ledger(monkeypatch, tmp_path)
    calls = _patch_graph_ingest(monkeypatch)

    # 让 TrackingLedger 构造即炸（模拟入账层意外）。
    import apkscan.track.autoingest as ai_mod

    def _boom_ledger(*a: Any, **k: Any) -> Any:
        raise RuntimeError("ledger boom")

    monkeypatch.setattr("apkscan.track.ledger.TrackingLedger", _boom_ledger)

    # 不抛；入账失败不阻断图谱喂入（两旁路独立）。
    ai_mod.auto_track_and_ingest(_make_report(), "/r/report.json", track=True)
    assert calls["ingest_called"] is True


def test_graph_failure_does_not_raise_and_ledger_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)

    import apkscan.graph as graph_mod

    class _FakeStore:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def close(self) -> None:
            pass

    def _boom_ingest(*a: Any, **k: Any) -> bool:
        raise RuntimeError("graph boom")

    monkeypatch.setattr(graph_mod, "GraphStore", _FakeStore)
    monkeypatch.setattr(graph_mod, "ingest_report", _boom_ingest)

    # 不抛；图谱失败不连累入账。
    autoingest.auto_track_and_ingest(_make_report(), "/r/report.json", track=True)
    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert "a" * 64 in data["apks"]


# ---------------------------------------------------------------------------
# auto.analyze_static 集成：静态步骤后入账
# ---------------------------------------------------------------------------


class _FakeCtx:
    def __init__(self, package_name: str = "com.fraud.app") -> None:
        self.package_name = package_name


def _patch_static(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    """打桩 auto 静态：load_apk / pipeline.run / 写报告 no-op。"""
    import apkscan.core.apk as apk_mod
    import apkscan.core.pipeline as pipeline_mod
    from apkscan.dynamic import auto

    monkeypatch.setattr(apk_mod, "load_apk", lambda *a, **k: _FakeCtx(report.package_name))
    monkeypatch.setattr(pipeline_mod, "run", lambda ctx, config: report)
    monkeypatch.setattr(
        auto, "_write_reports", lambda report, *, out_dir, formats, base: [f"{out_dir}/{base}.json"]
    )


def test_analyze_static_writes_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    _patch_graph_ingest(monkeypatch)
    from apkscan.dynamic import auto

    report = _make_report(sha256="d" * 64)
    _patch_static(monkeypatch, report)

    result = auto.analyze_static("x.apk", out_dir=str(tmp_path / "out"), track=True)
    assert result["steps"][0]["status"] == "done"

    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert "d" * 64 in data["apks"]


def test_analyze_static_no_track(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    _patch_graph_ingest(monkeypatch)
    from apkscan.dynamic import auto

    _patch_static(monkeypatch, _make_report(sha256="e" * 64))

    auto.analyze_static("x.apk", out_dir=str(tmp_path / "out"), track=False)
    assert not led_path.exists()


def test_analyze_static_ingest_failure_does_not_break_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_tmp_ledger(monkeypatch, tmp_path)
    from apkscan.dynamic import auto

    _patch_static(monkeypatch, _make_report(sha256="f" * 64))

    # 让 autoingest 整体炸（模拟入账层意外），静态步骤仍须 done。
    def _boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(autoingest, "auto_track_and_ingest", _boom)

    result = auto.analyze_static("x.apk", out_dir=str(tmp_path / "out"), track=True)
    assert result["steps"][0]["status"] == "done"  # 报告产出不受影响
    assert result["report_paths"]  # 仍有报告路径


# ---------------------------------------------------------------------------
# cli.analyze 集成：写报告后入账 / --no-track
# ---------------------------------------------------------------------------


def _patch_cli_analyze(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    """打桩 cli.analyze 链路：load_app / pipeline.run / 写报告 / 设备探测，全 no-op。"""
    import apkscan.core.pipeline as pipeline_mod

    # cli.py 顶层 `from apkscan.core.loader import load_app`，名字绑定在 cli 命名空间 → 在此打桩。
    monkeypatch.setattr(cli, "load_app", lambda *a, **k: _FakeCtx(report.package_name))
    monkeypatch.setattr(pipeline_mod, "run", lambda ctx, config: report)
    monkeypatch.setattr(cli, "_write_reports", lambda *a, **k: None)
    monkeypatch.setattr(cli.device, "has_device", lambda *a, **k: False)
    # sample_fingerprint 会真算 sha；这里让 meta 已有的 sample_sha256 不被覆盖坏，
    # 直接 mock 成返回固定指纹（避免读真文件）。
    import apkscan.core.integrity as integrity_mod

    monkeypatch.setattr(
        integrity_mod, "sample_fingerprint", lambda *a, **k: {"sha256": report.meta["sample_sha256"]}
    )


def test_cli_analyze_writes_ledger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    _patch_graph_ingest(monkeypatch)

    report = _make_report(sha256="1" * 64)
    _patch_cli_analyze(monkeypatch, report)

    apk_file = tmp_path / "sample.apk"
    apk_file.write_bytes(b"PK\x03\x04 fake apk")

    res = runner.invoke(
        cli.app, ["analyze", str(apk_file), "--offline", "--out", str(tmp_path / "out")]
    )
    assert res.exit_code == 0, res.output

    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert "1" * 64 in data["apks"]


def test_cli_analyze_no_track(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    led_path = _use_tmp_ledger(monkeypatch, tmp_path)
    _patch_graph_ingest(monkeypatch)

    report = _make_report(sha256="2" * 64)
    _patch_cli_analyze(monkeypatch, report)

    apk_file = tmp_path / "sample.apk"
    apk_file.write_bytes(b"PK\x03\x04 fake apk")

    res = runner.invoke(
        cli.app,
        ["analyze", str(apk_file), "--offline", "--no-track", "--out", str(tmp_path / "out")],
    )
    assert res.exit_code == 0, res.output
    assert not led_path.exists()


def test_cli_analyze_ingest_failure_does_not_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_tmp_ledger(monkeypatch, tmp_path)
    report = _make_report(sha256="3" * 64)
    _patch_cli_analyze(monkeypatch, report)

    # 让 autoingest 整体炸：analyze 仍须 exit 0（报告已产出）。
    def _boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("apkscan.track.autoingest.auto_track_and_ingest", _boom)

    apk_file = tmp_path / "sample.apk"
    apk_file.write_bytes(b"PK\x03\x04 fake apk")

    res = runner.invoke(
        cli.app, ["analyze", str(apk_file), "--offline", "--out", str(tmp_path / "out")]
    )
    assert res.exit_code == 0, res.output


# ---------------------------------------------------------------------------
# track ingest 命令：历史报告回填
# ---------------------------------------------------------------------------


def _write_report_json(path: Path, sha256: str, package: str = "com.fraud.app") -> None:
    payload = {
        "package_name": package,
        "meta": {"sample_sha256": sha256, "app_label": "杀猪盘"},
        "leads": [
            {"category": "DOMAIN", "value": "c2.x.com", "subject": "X 公司"},
            {"category": "IP", "value": "1.2.3.4", "subject": None},
        ],
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_track_ingest_backfills_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = tmp_path / "tracking.json"
    calls = _patch_graph_ingest(monkeypatch)

    r1 = tmp_path / "r1.json"
    r2 = tmp_path / "r2.json"
    _write_report_json(r1, "a1" + "0" * 62)
    _write_report_json(r2, "b2" + "0" * 62)

    res = runner.invoke(
        cli.app, ["track", "ingest", str(r1), str(r2), "--ledger", str(led_path)]
    )
    assert res.exit_code == 0, res.output

    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert ("a1" + "0" * 62) in data["apks"]
    assert ("b2" + "0" * 62) in data["apks"]
    apk = data["apks"]["a1" + "0" * 62]
    assert "DOMAIN:c2.x.com" in apk["leads"]
    assert "IP:1.2.3.4" in apk["leads"]
    # 图谱也被喂（两份）
    assert calls["ingest_called"] is True


def test_track_ingest_no_graph_skips_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = tmp_path / "tracking.json"
    calls = _patch_graph_ingest(monkeypatch)

    r1 = tmp_path / "r1.json"
    _write_report_json(r1, "c3" + "0" * 62)

    res = runner.invoke(
        cli.app, ["track", "ingest", str(r1), "--ledger", str(led_path), "--no-graph"]
    )
    assert res.exit_code == 0, res.output
    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert ("c3" + "0" * 62) in data["apks"]
    assert calls["ingest_called"] is False  # --no-graph 不喂图谱


def test_track_ingest_bad_json_skips_without_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = tmp_path / "tracking.json"
    _patch_graph_ingest(monkeypatch)

    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    _write_report_json(good, "d4" + "0" * 62)
    bad.write_text("{ not valid json", encoding="utf-8")

    res = runner.invoke(
        cli.app, ["track", "ingest", str(good), str(bad), "--ledger", str(led_path)]
    )
    # 坏报告跳过，好报告仍入账；命令不崩。
    assert res.exit_code == 0, res.output
    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert ("d4" + "0" * 62) in data["apks"]


def test_track_ingest_kuzu_missing_silent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    led_path = tmp_path / "tracking.json"

    real_import = builtins.__import__

    def _fake_import(name: str, *a: Any, **k: Any) -> Any:
        if name.startswith("apkscan.graph"):
            raise ImportError("No module named 'kuzu'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    r1 = tmp_path / "r1.json"
    _write_report_json(r1, "e5" + "0" * 62)

    res = runner.invoke(
        cli.app, ["track", "ingest", str(r1), "--ledger", str(led_path)]
    )
    assert res.exit_code == 0, res.output  # kuzu 缺失不崩
    data = json.loads(led_path.read_text(encoding="utf-8"))
    assert ("e5" + "0" * 62) in data["apks"]  # 台账照样回填
