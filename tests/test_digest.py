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


def test_build_digest_redacts_remote_control_value() -> None:
    """★回归（codex 全库审计 P1）：REMOTE_CONTROL 被动态侧标为高敏（含被害人关联），`digest --redact` 须脱敏
    其 value（与脱敏表同步）；非高敏类（IP）仍明文。"""
    report = {
        "leads": [
            {"category": "REMOTE_CONTROL", "value": "com.icbc.bank 被害人账户 6222abcd", "advice": "建议调证", "confidence": "HIGH"},
            {"category": "IP", "value": "1.2.3.4", "advice": "建议调证", "confidence": "HIGH"},
        ],
    }
    d = build_digest(report, redact=True)
    by_cat = {lead["category"]: lead["value"] for lead in d["leads"]}
    assert "6222" not in by_cat["REMOTE_CONTROL"] and "已脱敏" in by_cat["REMOTE_CONTROL"]
    assert by_cat["IP"] == "1.2.3.4"  # 非高敏类不脱敏


def test_redact_scrubs_pii_from_freetext_fields() -> None:
    """★codex C1：redact 时 subject/notes/where_to_request/evidence_to_obtain 自由文本里的结构化 PII
    （手机号/证件号/邮箱/卡号）被抹除，不再绕过脱敏进云端摘要；并置 redaction_warning 告警。"""
    report = {
        "leads": [{
            "category": "VICTIM_DATA",
            "value": "受害人物证",
            "subject": "受害人 张三 手机 13800138000",
            "notes": "身份证 11010119900307391X，邮箱 victim@example.com",
            "where_to_request": "向 6222021234567890123 开户行调证",
            "evidence_to_obtain": ["联系电话 13900139000 的通话记录"],
            "advice": "建议调证", "confidence": "HIGH",
        }],
    }
    d = build_digest(report, redact=True)
    lead = d["leads"][0]
    blob = f"{lead['subject']} {lead['notes']} {lead['where_to_request']} {lead['evidence_to_obtain']}"
    assert "13800138000" not in blob and "13900139000" not in blob  # 手机号
    assert "11010119900307391X" not in blob                          # 身份证
    assert "victim@example.com" not in blob                          # 邮箱
    assert "6222021234567890123" not in blob                         # 卡号
    assert "PII已脱敏" in blob                                        # 有替换标记
    assert "张三" in lead["subject"]  # 非结构化姓名保留（如实局限）：仅证明结构化 PII 被抹
    assert d.get("redaction_warning")  # 告警不静默


def test_no_redact_keeps_freetext_plaintext() -> None:
    """默认（redact=False）自由文本原样，取证查看需要看到实际值；无告警。"""
    report = {"leads": [{"category": "VICTIM_DATA", "value": "x",
                         "notes": "手机 13800138000", "advice": "待核", "confidence": "LOW"}]}
    d = build_digest(report)
    assert d["leads"][0]["notes"] == "手机 13800138000"
    assert "redaction_warning" not in d


def test_integrity_flags_low_completeness_and_enrichment() -> None:
    """★codex #4：分析完整度/富化命中率低 + 关键分析器失败 → integrity.reliable=False + warnings。"""
    report = {
        "leads": [],
        "analysis_status": "partial",
        "completeness": 0.5,
        "critical_failures": ["endpoints"],
        "enricher_status": [
            {"provider": "asn", "attempted": 10, "ok": 2, "failed": 8},
            {"provider": "rdap", "attempted": 4, "ok": 1, "failed": 3},
        ],
    }
    d = build_digest(report)
    integ = d["integrity"]
    assert integ["reliable"] is False
    assert integ["enrichment_ok_rate"] == round(3 / 14, 4)
    assert any("完整度" in w for w in integ["warnings"])
    assert any("关键分析器失败" in w for w in integ["warnings"])
    assert any("富化命中率" in w for w in integ["warnings"])


def test_integrity_reliable_when_healthy() -> None:
    """完整度高 + 富化命中率高 + 无关键失败 → reliable=True、无 warnings。"""
    report = {
        "leads": [], "analysis_status": "complete", "completeness": 1.0,
        "critical_failures": [],
        "enricher_status": [{"provider": "asn", "attempted": 10, "ok": 9, "failed": 1}],
    }
    integ = build_digest(report)["integrity"]
    assert integ["reliable"] is True
    assert integ["warnings"] == []


def test_integrity_dirty_counts_never_throw() -> None:
    """★codex P0：脏 enricher_status（attempted="bad"/列表/负数）→ 不抛，跳过并降可靠性告警。"""
    report = {
        "leads": [], "analysis_status": "partial", "completeness": 1.0, "critical_failures": [],
        "enricher_status": [
            {"provider": "asn", "attempted": "bad", "ok": 1},        # 脏字符串
            {"provider": "rdap", "attempted": [1, 2], "ok": 0},       # 脏列表
            {"provider": "x", "attempted": 3, "ok": 5},               # ok>attempted
            {"provider": "y", "attempted": 10, "ok": 9},              # 正常
        ],
    }
    d = build_digest(report)  # 绝不抛
    integ = d["integrity"]
    assert integ["enrichment_ok_rate"] == round(9 / 10, 4)  # 仅正常条目
    assert any("异常条目" in w for w in integ["warnings"])


def test_integrity_nan_completeness_not_reliable() -> None:
    """★codex P1：NaN/越界 completeness 不得绕过阈值伪装 reliable=True。"""
    d1 = build_digest({"leads": [], "completeness": float("nan"), "enricher_status": []})
    assert d1["integrity"]["reliable"] is False
    d2 = build_digest({"leads": [], "completeness": 1.5, "enricher_status": []})
    assert d2["integrity"]["reliable"] is False
    d3 = build_digest({"leads": [], "completeness": -0.1, "enricher_status": []})
    assert d3["integrity"]["reliable"] is False


def test_integrity_no_enrichment_attempts_not_flagged() -> None:
    """零富化尝试（离线/无端点）→ enrichment_ok_rate=None，不因此告警（不是失败）。"""
    report = {"leads": [], "analysis_status": "complete", "completeness": 1.0,
              "critical_failures": [], "enricher_status": []}
    integ = build_digest(report)["integrity"]
    assert integ["enrichment_ok_rate"] is None
    assert integ["reliable"] is True


def test_build_digest_bad_input_never_throws() -> None:
    assert build_digest(["not a dict"])["leads"] == []
    assert build_digest(None)["leads"] == []
    assert build_digest({})["leads"] == []


def test_build_digest_exposes_compact_closure_without_raw_targets() -> None:
    report = {
        "meta": {
            "closure": {
                "status": "partial",
                "targets": [{"value": "198.51.100.10", "raw": {"large": "payload"}}],
                "gaps": ["Origin is missing"],
                "next_actions": ["request edge origin logs"],
                "source_summary": {"hit": 3, "failed": 1},
            }
        },
        "leads": [],
    }

    digest = build_digest(report)

    assert digest["closure"]["status"] == "partial"
    assert digest["closure"]["target_count"] == 1
    assert digest["closure"]["gaps"] == ["Origin is missing"]
    assert "targets" not in digest["closure"]
    assert "large" not in str(digest["closure"])


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
