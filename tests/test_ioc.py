"""apkscan.report.ioc 单测 + fxapk export CLI 薄包装测试。

ioc 纯函数层把 report.json 的 leads 扁平成 IOC 行（给 MISP/i2/Maltego 跨案碰撞），
铁律：纯函数禁 print/typer、对坏输入容错返回空、绝不抛；CLI 命令包 try/except、坏输入
友好提示 + 退出码 1。本测试逐项锁定。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.report import ioc

runner = CliRunner()


# ---------------------------------------------------------------------------
# 测试夹具：构造一份含多条 lead 的 report dict（report.json 解析结果的形状）
# ---------------------------------------------------------------------------


def _make_report() -> dict:
    """一份含 4 条 lead 的 report dict：覆盖 is_c2、advice 分级、source 拼接、缺字段容错。"""
    return {
        "package_name": "com.fraud.app",
        "meta": {"sample_sha256": "abc123def456"},
        "leads": [
            {
                # C2 域名：建议调证、is_c2=True、有 source_refs
                "category": "DOMAIN",
                "value": "pay.evil.com",
                "subject": "某科技有限公司",
                "where_to_request": "阿里云",
                "advice": "建议调证",
                "confidence": "HIGH",
                "is_c2": True,
                "source_refs": [
                    {"source": "dex", "location": "com/x/Api.java", "snippet": "..."},
                    {"source": "manifest", "location": "AndroidManifest.xml"},
                ],
            },
            {
                # 支付线索：建议调证、非 C2、单 source_ref
                "category": "PAYMENT",
                "value": "支付宝 2088xxx",
                "subject": "张三",
                "where_to_request": "支付宝",
                "advice": "建议调证",
                "confidence": "MEDIUM",
                "is_c2": False,
                "source_refs": [{"source": "resource", "location": "strings.xml"}],
            },
            {
                # 配置键：无需调证、无 source_refs（source 应为空）
                "category": "CONFIG_KEY",
                "value": "GETUI_APPID=xxxx",
                "subject": None,
                "where_to_request": None,
                "advice": "无需调证",
                "confidence": "LOW",
                "is_c2": False,
                "source_refs": [],
            },
            {
                # 待核联系方式：缺 source_refs 键 + 缺若干字段（容错应留空）
                "category": "CONTACT",
                "value": "telegram @scammer",
                "advice": "待核",
                "confidence": "LOW",
            },
        ],
    }


# ---------------------------------------------------------------------------
# leads_to_ioc_rows —— 行数 / 字段映射
# ---------------------------------------------------------------------------


def test_rows_count_and_basic_fields() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    assert len(rows) == 4
    # 列齐全
    expected_cols = {
        "type",
        "value",
        "subject",
        "where_to_request",
        "advice",
        "confidence",
        "is_c2",
        "sample_sha256",
        "source",
    }
    assert set(rows[0].keys()) == expected_cols


def test_type_is_category() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    assert rows[0]["type"] == "DOMAIN"
    assert rows[1]["type"] == "PAYMENT"
    assert rows[2]["type"] == "CONFIG_KEY"
    assert rows[3]["type"] == "CONTACT"


def test_value_subject_advice_confidence_mapping() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    assert rows[0]["value"] == "pay.evil.com"
    assert rows[0]["subject"] == "某科技有限公司"
    assert rows[0]["where_to_request"] == "阿里云"
    assert rows[0]["advice"] == "建议调证"
    assert rows[0]["confidence"] == "HIGH"
    # subject 为 None → 空串
    assert rows[2]["subject"] == ""
    assert rows[2]["where_to_request"] == ""


def test_is_c2_flag() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    assert rows[0]["is_c2"] is True
    assert rows[1]["is_c2"] is False
    # 缺 is_c2 键 → 容错 False
    assert rows[3]["is_c2"] is False


def test_sample_sha256_from_meta() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    assert rows[0]["sample_sha256"] == "abc123def456"


def test_sample_sha256_missing_meta_is_empty() -> None:
    report = _make_report()
    report["meta"] = {}  # 暂无 sample_sha256（取证完整性功能将来才写）
    rows = ioc.leads_to_ioc_rows(report)
    assert all(r["sample_sha256"] == "" for r in rows)
    # 连 meta 键都没有也容错
    del report["meta"]
    rows2 = ioc.leads_to_ioc_rows(report)
    assert all(r["sample_sha256"] == "" for r in rows2)


def test_source_joins_first_evidence() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    # source = 第一个 Evidence 的 source:location
    assert rows[0]["source"] == "dex:com/x/Api.java"
    assert rows[1]["source"] == "resource:strings.xml"
    # 空 source_refs → 空串
    assert rows[2]["source"] == ""
    # 缺 source_refs 键 → 空串
    assert rows[3]["source"] == ""


# ---------------------------------------------------------------------------
# only_investigate 语义
# ---------------------------------------------------------------------------


def test_only_investigate_filters_to_advice() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report(), only_investigate=True)
    # 只剩 advice=建议调证 的 2 条
    assert len(rows) == 2
    assert all(r["advice"] == "建议调证" for r in rows)
    assert {r["value"] for r in rows} == {"pay.evil.com", "支付宝 2088xxx"}


def test_default_exports_all_with_advice_column() -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())  # 默认 only_investigate=False
    assert len(rows) == 4
    advices = {r["advice"] for r in rows}
    assert "无需调证" in advices  # 全导，但带 advice 列让下游自行过滤
    assert "待核" in advices


# ---------------------------------------------------------------------------
# 坏 report —— 容错返回空、绝不抛
# ---------------------------------------------------------------------------


def test_missing_leads_key_returns_empty() -> None:
    assert ioc.leads_to_ioc_rows({"meta": {}}) == []


def test_leads_not_a_list_returns_empty() -> None:
    assert ioc.leads_to_ioc_rows({"leads": "oops"}) == []
    assert ioc.leads_to_ioc_rows({"leads": None}) == []


def test_non_dict_lead_skipped() -> None:
    report = {"leads": [{"category": "DOMAIN", "value": "x.com"}, "not-a-dict", 42, None]}
    rows = ioc.leads_to_ioc_rows(report)
    assert len(rows) == 1
    assert rows[0]["value"] == "x.com"


def test_report_not_a_dict_returns_empty() -> None:
    assert ioc.leads_to_ioc_rows("not-a-dict") == []  # type: ignore[arg-type]
    assert ioc.leads_to_ioc_rows(None) == []  # type: ignore[arg-type]


def test_bad_source_refs_does_not_raise() -> None:
    report = {
        "leads": [
            {"category": "DOMAIN", "value": "a.com", "source_refs": "bad"},
            {"category": "DOMAIN", "value": "b.com", "source_refs": ["not-evidence"]},
            {"category": "DOMAIN", "value": "c.com", "source_refs": [{"no_source": 1}]},
        ]
    }
    rows = ioc.leads_to_ioc_rows(report)
    assert len(rows) == 3
    assert all(r["source"] == "" for r in rows)


# ---------------------------------------------------------------------------
# write_csv —— 写文件后读回、表头正确、中文不乱码
# ---------------------------------------------------------------------------


def test_write_csv_roundtrip(tmp_path: Path) -> None:
    rows = ioc.leads_to_ioc_rows(_make_report())
    out = tmp_path / "case.ioc.csv"
    ioc.write_csv(rows, str(out))
    assert out.is_file()

    # 用 utf-8-sig 读回（write_csv 写 UTF-8 with BOM 便于 Excel）
    with out.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "type",
            "value",
            "subject",
            "where_to_request",
            "advice",
            "confidence",
            "is_c2",
            "sample_sha256",
            "source",
        ]
        read = list(reader)
    assert len(read) == 4
    # 中文不乱码
    assert read[0]["subject"] == "某科技有限公司"
    assert read[1]["value"] == "支付宝 2088xxx"


def test_write_csv_empty_rows_writes_header_only(tmp_path: Path) -> None:
    out = tmp_path / "empty.ioc.csv"
    ioc.write_csv([], str(out))
    assert out.is_file()
    with out.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    # 仅表头一行
    assert len(rows) == 1
    assert rows[0][0] == "type"


# ---------------------------------------------------------------------------
# CLI：fxapk export
# ---------------------------------------------------------------------------


def _write_report_json(path: Path) -> None:
    path.write_text(json.dumps(_make_report(), ensure_ascii=False), encoding="utf-8")


def test_cli_export_happy_path(tmp_path: Path) -> None:
    report_json = tmp_path / "case.json"
    _write_report_json(report_json)
    out_csv = tmp_path / "case.ioc.csv"

    res = runner.invoke(cli.app, ["export", str(report_json), "--out", str(out_csv)])
    assert res.exit_code == 0
    assert out_csv.is_file()
    # 打印导出行数
    assert "4" in res.output

    with out_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 4


def test_cli_export_default_out_path(tmp_path: Path) -> None:
    report_json = tmp_path / "mycase.json"
    _write_report_json(report_json)

    res = runner.invoke(cli.app, ["export", str(report_json)])
    assert res.exit_code == 0
    # 默认 out = 与 report.json 同目录的 <base>.ioc.csv
    default_csv = tmp_path / "mycase.ioc.csv"
    assert default_csv.is_file()


def test_cli_export_only_investigate(tmp_path: Path) -> None:
    report_json = tmp_path / "case.json"
    _write_report_json(report_json)
    out_csv = tmp_path / "case.ioc.csv"

    res = runner.invoke(
        cli.app,
        ["export", str(report_json), "--out", str(out_csv), "--only-investigate"],
    )
    assert res.exit_code == 0
    with out_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2  # 只剩 advice=建议调证


def test_cli_export_missing_file(tmp_path: Path) -> None:
    res = runner.invoke(cli.app, ["export", str(tmp_path / "nope.json")])
    assert res.exit_code == 1
    # 友好提示，不抛 traceback
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "错误" in res.output or "找不到" in res.output or "不存在" in res.output


def test_cli_export_bad_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    res = runner.invoke(cli.app, ["export", str(bad)])
    assert res.exit_code == 1
    assert res.exception is None or isinstance(res.exception, SystemExit)
    assert "错误" in res.output or "解析" in res.output or "JSON" in res.output
