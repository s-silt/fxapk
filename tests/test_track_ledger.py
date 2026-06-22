"""TrackingLedger（线索追踪台账）单测。

覆盖：合并保留人工改 / 新线索默认待办 / 旧线索不删 / lead_key 稳定 /
坏文件当空不抛 / 原子写 / env 与构造参数覆盖路径。

铁律：不联网、不开真浏览器、不碰真机；用 pytest + monkeypatch + tmp_path。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkscan.core.models import (
    Confidence,
    Lead,
    LeadCategory,
    Report,
)
from apkscan.track.ledger import (
    ENV_TRACKING_DB,
    TrackingLedger,
    default_ledger_path,
    make_lead_key,
)


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
        leads=leads or [],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


def _lead(category: LeadCategory, value: str, subject: str | None = None) -> Lead:
    return Lead(
        category=category,
        value=value,
        subject=subject,
        confidence=Confidence.HIGH,
    )


# ---------------------------------------------------------------------------
# lead_key 稳定
# ---------------------------------------------------------------------------


def test_lead_key_stable() -> None:
    assert make_lead_key("DOMAIN", "*.x.com") == "DOMAIN:*.x.com"
    # 同一线索跨多次分析归一：相同 category/value → 相同 key。
    assert make_lead_key("IP", "1.2.3.4") == make_lead_key("IP", "1.2.3.4")


def test_upsert_preserves_first_seen(tmp_path: Path) -> None:
    """二次 upsert（重分析）保留 APK 与线索的首见时间 first_seen，仅刷新派生字段。"""
    led = TrackingLedger(tmp_path / "t.json")
    rep = _make_report(leads=[_lead(LeadCategory.DOMAIN, "*.x.com")])
    led.upsert_report(rep, "r1.json")
    apk1 = led.all()["apks"]["a" * 64]
    key = make_lead_key("DOMAIN", "*.x.com")
    apk_first = apk1["first_seen"]
    lead_first = apk1["leads"][key]["first_seen"]

    led.upsert_report(rep, "r2.json")  # 二次分析（同一 APK/线索）
    apk2 = led.all()["apks"]["a" * 64]
    assert apk2["first_seen"] == apk_first  # 首见不变
    assert apk2["leads"][key]["first_seen"] == lead_first
    assert apk2["report_path"] == "r2.json"  # 派生字段照常刷新


def test_upsert_uses_category_value_as_lead_key(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    rep = _make_report(leads=[_lead(LeadCategory.DOMAIN, "pay.x.com", "X 公司")])
    ledger.upsert_report(rep, "/r/report.json")

    data = ledger.all()
    apk = data["apks"]["a" * 64]
    assert "DOMAIN:pay.x.com" in apk["leads"]
    lead = apk["leads"]["DOMAIN:pay.x.com"]
    assert lead["category"] == "DOMAIN"
    assert lead["value"] == "pay.x.com"
    assert lead["subject"] == "X 公司"


# ---------------------------------------------------------------------------
# 新线索默认待办 / APK 默认待处理
# ---------------------------------------------------------------------------


def test_new_lead_defaults_pending(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    rep = _make_report(leads=[_lead(LeadCategory.IP, "1.2.3.4")])
    ledger.upsert_report(rep, "/r/report.json")

    apk = ledger.all()["apks"]["a" * 64]
    assert apk["apk_status"] == "待处理"
    assert apk["leads"]["IP:1.2.3.4"]["status"] == "待办"
    assert apk["leads"]["IP:1.2.3.4"]["history"] == []


# ---------------------------------------------------------------------------
# 合并保留人工改的 status/notes/history
# ---------------------------------------------------------------------------


def test_upsert_preserves_manual_edits(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    ledger = TrackingLedger(path)
    sha = "b" * 64
    rep = _make_report(sha256=sha, leads=[_lead(LeadCategory.DOMAIN, "c2.x.com", "旧主体")])
    ledger.upsert_report(rep, "/r/v1.json")

    # 人工改 APK 与线索的进度 + 加一条进展。
    assert ledger.set_apk(sha, status="调查中", notes="重点案")
    assert ledger.set_lead(sha, "DOMAIN:c2.x.com", status="已出函", notes="函号 123")
    assert ledger.add_history(sha, "DOMAIN:c2.x.com", "已出函至注册商")

    # 二次分析：subject 变了、report_path 变了，但人工字段必须保留。
    rep2 = _make_report(
        sha256=sha, leads=[_lead(LeadCategory.DOMAIN, "c2.x.com", "新主体")]
    )
    ledger.upsert_report(rep2, "/r/v2.json")

    apk = ledger.all()["apks"][sha]
    # 人工字段保留
    assert apk["apk_status"] == "调查中"
    assert apk["apk_notes"] == "重点案"
    lead = apk["leads"]["DOMAIN:c2.x.com"]
    assert lead["status"] == "已出函"
    assert lead["notes"] == "函号 123"
    assert len(lead["history"]) == 1
    assert lead["history"][0]["text"] == "已出函至注册商"
    # 派生字段刷新
    assert lead["subject"] == "新主体"
    assert apk["report_path"] == "/r/v2.json"


# ---------------------------------------------------------------------------
# 旧线索不删
# ---------------------------------------------------------------------------


def test_upsert_does_not_delete_vanished_leads(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    sha = "c" * 64
    rep = _make_report(
        sha256=sha,
        leads=[
            _lead(LeadCategory.DOMAIN, "a.x.com"),
            _lead(LeadCategory.DOMAIN, "b.x.com"),
        ],
    )
    ledger.upsert_report(rep, "/r/v1.json")

    # 二次分析里 b.x.com 消失，只剩 a.x.com。
    rep2 = _make_report(sha256=sha, leads=[_lead(LeadCategory.DOMAIN, "a.x.com")])
    ledger.upsert_report(rep2, "/r/v2.json")

    leads = ledger.all()["apks"][sha]["leads"]
    assert "DOMAIN:a.x.com" in leads
    assert "DOMAIN:b.x.com" in leads  # 旧线索保留办案痕迹，不删


# ---------------------------------------------------------------------------
# 坏文件当空不抛
# ---------------------------------------------------------------------------


def test_corrupt_file_treated_as_empty(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text("{ this is not valid json", encoding="utf-8")
    ledger = TrackingLedger(path)  # 不抛
    assert ledger.all()["apks"] == {}
    # 仍可正常写入
    ledger.upsert_report(_make_report(), "/r/report.json")
    assert "a" * 64 in ledger.all()["apks"]


def test_non_dict_top_level_treated_as_empty(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    ledger = TrackingLedger(path)
    assert ledger.all()["apks"] == {}


def test_apks_field_non_dict_treated_as_empty(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "apks": "oops"}), encoding="utf-8")
    ledger = TrackingLedger(path)
    assert ledger.all()["apks"] == {}


def test_missing_sha256_skips_without_raising(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    rep = Report(
        package_name="com.x",
        meta={},  # 无 sample_sha256
        leads=[_lead(LeadCategory.IP, "1.2.3.4")],
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )
    ledger.upsert_report(rep, "/r/report.json")  # 不抛
    assert ledger.all()["apks"] == {}


# ---------------------------------------------------------------------------
# 原子写：临时文件 + os.replace，磁盘上是合法 JSON
# ---------------------------------------------------------------------------


def test_atomic_write_persists_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "t.json"  # 父目录不存在 → mkdir
    ledger = TrackingLedger(path)
    ledger.upsert_report(_make_report(), "/r/report.json")

    assert path.is_file()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["version"] == 1
    assert "a" * 64 in on_disk["apks"]
    # 不留 .tmp 半截文件
    assert not (path.parent / "t.json.tmp").exists()


def test_write_failure_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", _boom)
    # 落盘失败被吞，不抛、不破坏调用方流程。
    ledger.upsert_report(_make_report(), "/r/report.json")


# ---------------------------------------------------------------------------
# env 与构造参数覆盖路径
# ---------------------------------------------------------------------------


def test_path_from_constructor_arg(tmp_path: Path) -> None:
    p = tmp_path / "custom.json"
    ledger = TrackingLedger(p)
    assert ledger.path == p


def test_path_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "env.json"
    monkeypatch.setenv(ENV_TRACKING_DB, str(p))
    ledger = TrackingLedger()
    assert ledger.path == p
    assert default_ledger_path() == p


def test_constructor_arg_overrides_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_TRACKING_DB, str(tmp_path / "env.json"))
    arg = tmp_path / "arg.json"
    ledger = TrackingLedger(arg)
    assert ledger.path == arg  # 构造参数优先于 env


def test_default_path_is_home_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_TRACKING_DB, raising=False)
    expected = Path.home() / ".apkscan" / "tracking.json"
    assert default_ledger_path() == expected


# ---------------------------------------------------------------------------
# 包名校验（样本不可信）
# ---------------------------------------------------------------------------


def test_invalid_package_blanked_but_ingested(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    rep = _make_report(package_name="com.x; rm -rf /")
    ledger.upsert_report(rep, "/r/report.json")
    apk = ledger.all()["apks"]["a" * 64]
    assert apk["package"] == ""  # 形态非法置空，但 APK 仍入账（sha256 主键）


# ---------------------------------------------------------------------------
# 手动改：未找到目标返回 False 不抛
# ---------------------------------------------------------------------------


def test_set_apk_missing_returns_false(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    assert ledger.set_apk("nope", status="x") is False


def test_set_lead_missing_returns_false(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    ledger.upsert_report(_make_report(), "/r/report.json")
    assert ledger.set_lead("a" * 64, "DOMAIN:nope", status="x") is False
    assert ledger.add_history("a" * 64, "DOMAIN:nope", "x") is False


# ---------------------------------------------------------------------------
# add_lead：手动加线索（标 manual / 建壳 / 重复返 False / 不破坏 upsert 合并）
# ---------------------------------------------------------------------------


def test_add_lead_creates_manual_lead(tmp_path: Path) -> None:
    """手动加线索：新建并标 manual:true，first_seen/updated_at 置当前。"""
    ledger = TrackingLedger(tmp_path / "t.json")
    ledger.upsert_report(_make_report(), "/r/report.json")  # APK 已在台账
    sha = "a" * 64

    assert (
        ledger.add_lead(sha, "DOMAIN", "manual.x.com", subject="人工", notes="举报来的")
        is True
    )

    lead = ledger.all()["apks"][sha]["leads"]["DOMAIN:manual.x.com"]
    assert lead["manual"] is True
    assert lead["category"] == "DOMAIN"
    assert lead["value"] == "manual.x.com"
    assert lead["subject"] == "人工"
    assert lead["notes"] == "举报来的"
    assert lead["status"] == "待办"  # 默认状态
    assert lead["history"] == []
    assert lead["first_seen"] == lead["updated_at"]


def test_add_lead_custom_status(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    ledger.upsert_report(_make_report(), "/r/report.json")
    assert ledger.add_lead("a" * 64, "IP", "9.9.9.9", status="调查中") is True
    lead = ledger.all()["apks"]["a" * 64]["leads"]["IP:9.9.9.9"]
    assert lead["status"] == "调查中"


def test_add_lead_creates_apk_shell_when_absent(tmp_path: Path) -> None:
    """APK 不在台账 → 建最小壳（package/label 空、默认 apk_status），线索照常入。"""
    ledger = TrackingLedger(tmp_path / "t.json")
    sha = "d" * 64
    assert ledger.add_lead(sha, "DOMAIN", "new.x.com") is True

    apk = ledger.all()["apks"][sha]
    assert apk["package"] == ""
    assert apk["label"] == ""
    assert apk["report_path"] == ""
    assert apk["apk_status"] == "待处理"
    assert "DOMAIN:new.x.com" in apk["leads"]
    assert apk["leads"]["DOMAIN:new.x.com"]["manual"] is True


def test_add_lead_duplicate_key_returns_false(tmp_path: Path) -> None:
    """同 lead_key 已存在（无论自动或手动）→ 返回 False，不覆盖既有线索。"""
    ledger = TrackingLedger(tmp_path / "t.json")
    sha = "e" * 64
    # 先自动入账一条 DOMAIN:dup.x.com
    rep = _make_report(sha256=sha, leads=[_lead(LeadCategory.DOMAIN, "dup.x.com")])
    ledger.upsert_report(rep, "/r/report.json")

    # 手动加同 key → False，不覆盖原线索（仍非 manual）。
    assert ledger.add_lead(sha, "DOMAIN", "dup.x.com", notes="试图覆盖") is False
    lead = ledger.all()["apks"][sha]["leads"]["DOMAIN:dup.x.com"]
    assert lead["notes"] == ""  # 未被覆盖
    assert "manual" not in lead  # 原自动线索未被改写

    # 手动加一条后再加同 key → 第二次 False。
    assert ledger.add_lead(sha, "IP", "8.8.8.8") is True
    assert ledger.add_lead(sha, "IP", "8.8.8.8") is False


def test_add_lead_missing_sha256_returns_false(tmp_path: Path) -> None:
    ledger = TrackingLedger(tmp_path / "t.json")
    assert ledger.add_lead("", "DOMAIN", "x.com") is False
    assert ledger.add_lead("   ", "DOMAIN", "x.com") is False


def test_add_lead_survives_subsequent_upsert_merge(tmp_path: Path) -> None:
    """手动线索被后续同 key 的 upsert 命中 → 走既有合并，保留人工 status/notes/history。"""
    ledger = TrackingLedger(tmp_path / "t.json")
    sha = "f" * 64
    # 手动加一条线索，再人工改状态/备注/进展。
    assert ledger.add_lead(sha, "DOMAIN", "c2.x.com", subject="人工主体") is True
    key = "DOMAIN:c2.x.com"
    assert ledger.set_lead(sha, key, status="已出函", notes="函号 123")
    assert ledger.add_history(sha, key, "已出函至注册商")

    # 后续分析命中同 key（subject 不同）→ 合并刷新派生字段，保留人工字段。
    rep = _make_report(
        sha256=sha, leads=[_lead(LeadCategory.DOMAIN, "c2.x.com", "分析主体")]
    )
    ledger.upsert_report(rep, "/r/v2.json")

    lead = ledger.all()["apks"][sha]["leads"][key]
    assert lead["status"] == "已出函"  # 人工状态保留
    assert lead["notes"] == "函号 123"  # 人工备注保留
    assert len(lead["history"]) == 1  # 人工进展保留
    assert lead["history"][0]["text"] == "已出函至注册商"
    assert lead["subject"] == "分析主体"  # 派生字段照常刷新
    assert lead["manual"] is True  # manual 标记不被 upsert 抹掉


def test_load_reloads_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    ledger = TrackingLedger(path)
    ledger.upsert_report(_make_report(), "/r/report.json")
    # 外部改盘后 load() 重读
    fresh = TrackingLedger(path)
    assert "a" * 64 in fresh.load()["apks"]
