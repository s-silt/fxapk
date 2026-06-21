"""紧凑调证摘要（Codex 友好）测试：build_digest 优先级排序 / 压缩字段 / 计数 + CLI stdout JSON。"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from apkscan import cli
from apkscan.report.digest import build_digest

runner = CliRunner()


def test_build_digest_sorts_and_summarizes() -> None:
    report = {
        "meta": {"package_name": "com.x", "sample_sha256": "AB12", "comm_sessions": [{}, {}]},
        "leads": [
            {"category": "DOMAIN", "value": "infra.com", "advice": "无需调证", "confidence": "LOW"},
            {"category": "WALLET_SECRET", "value": "seed", "advice": "建议调证", "confidence": "HIGH",
             "source_refs": [{"x": 1}]},
            {"category": "ADMIN_PANEL", "value": "a.com", "advice": "待核", "confidence": "MEDIUM"},
        ],
    }
    d = build_digest(report)
    assert d["package"] == "com.x"
    assert d["sha256"] == "AB12"
    assert d["summary"]["total_leads"] == 3
    assert d["summary"]["comm_sessions"] == 2
    # 优先级排序：建议调证 > 待核 > 无需调证
    assert [lead["advice"] for lead in d["leads"]] == ["建议调证", "待核", "无需调证"]
    assert d["leads"][0]["category"] == "WALLET_SECRET"
    # 压缩：去掉 source_refs 等冗长内部结构
    assert "source_refs" not in d["leads"][0]
    assert d["summary"]["by_advice"]["建议调证"] == 1


def test_build_digest_bad_input_never_throws() -> None:
    assert build_digest(["not a dict"])["leads"] == []
    assert build_digest(None)["leads"] == []
    assert build_digest({})["leads"] == []


def test_cli_digest_emits_json_stdout(tmp_path) -> None:
    rep = tmp_path / "report.json"
    rep.write_text(
        json.dumps(
            {
                "meta": {"package_name": "com.evil"},
                "leads": [
                    {"category": "DOMAIN", "value": "c2.evil.com", "advice": "建议调证",
                     "confidence": "HIGH", "is_c2": True, "evidence_to_obtain": ["x"]}
                ],
            }
        ),
        encoding="utf-8",
    )
    res = runner.invoke(cli.app, ["digest", str(rep)])
    assert res.exit_code == 0
    assert '"c2.evil.com"' in res.output
    assert '"leads"' in res.output


def test_cli_digest_bad_path_exits_1() -> None:
    res = runner.invoke(cli.app, ["digest", "/no/such/report.json"])
    assert res.exit_code == 1
