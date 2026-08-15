"""人工恢复凭据（墓碑）：放行一条被抑制的线索，且**重跑之后仍然放行**。

**要锁的根因**：抑制是自动的，每次分析都会重新压。人工核实放行之后若只改这一份报告，
下次重跑（换版本、补证据——常态）同一条线索又被压回去，上一次的核实白做。

本文件的断言分三层：
- 墓碑本身的读写与归一化（core/restore.py）；
- 两处复压路径都认墓碑：静态隔离入口 + 运行时回灌的 dict 合并；
- CLI 端到端：restore 写凭据 → 新报告 replay 放回，且**重跑产出的新报告**不再被压。
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.commands import lead as lead_cmd
from apkscan.core import infra
from apkscan.core.leads import apply_repack_quarantine
from apkscan.core.models import (
    DOWNGRADE_EVIDENCE_SCOPE,
    DOWNGRADE_REPACK_IDENTITY,
    DOWNGRADE_SNI_MASQUERADE,
    Endpoint,
    Evidence,
    Lead,
    LeadCategory,
    Report,
    merge_runtime_into_lead_dict,
)
from apkscan.core.report_io import load_report, write_report
from apkscan.core.restore import (
    MANUAL_RESTORES_KEY,
    is_restored,
    record_restore,
    restore_index,
)

runner = CliRunner()

_VALUE = "api.example.com"
_REPACK_META = {"repack_identity": {"verdict": "repack_suspected"}}


def _net_lead(value: str = _VALUE, advice: str = infra.ADVICE_INVESTIGATE) -> Lead:
    return Lead(
        category=LeadCategory.DOMAIN, value=value, advice=advice, base_advice=advice,
        where_to_request="域名注册商", evidence_to_obtain=["注册人实名"],
        source_refs=[Evidence(source="dex", location="classes.dex")],
    )


# ---------------------------------------------------------------------------
# 墓碑本身
# ---------------------------------------------------------------------------


def test_restore_index_is_case_insensitive_and_skips_bad_shapes() -> None:
    """凭据按 (类别, 值, 来源) 三段归一化匹配；坏形状跳过而不是抛。

    三元组而非二元组：同一条线索可能同时被多个来源压着，放行的是**其中一条**——按来源精确
    匹配，才不会因为放行了一条就把其余的也一起挡住复压。
    """
    meta = {MANUAL_RESTORES_KEY: [
        {"category": "DOMAIN", "value": "API.Example.COM", "source": "repack_identity"},
        {"category": "DOMAIN", "value": "no-source.example.com"},   # 缺字段
        "不是对象",
        {"category": "", "value": "x", "source": "y"},              # 空字段
    ]}
    index = restore_index(meta)
    assert len(index) == 1, "只有第一条是完整的"
    assert is_restored(index, "domain", "api.example.com", "REPACK_IDENTITY"), "三段都不区分大小写"
    assert not is_restored(index, "IP", _VALUE, DOWNGRADE_REPACK_IDENTITY), "类别不同不算"
    assert not is_restored(index, "DOMAIN", _VALUE, DOWNGRADE_SNI_MASQUERADE), "来源不同不算"


def test_restore_index_tolerates_missing_and_broken_meta() -> None:
    for meta in (None, {}, {MANUAL_RESTORES_KEY: "不是列表"}, {MANUAL_RESTORES_KEY: None}):
        assert restore_index(meta) == set()  # type: ignore[arg-type]


def test_record_restore_updates_in_place_on_same_key() -> None:
    """同 (类别,值,来源) 再放行一次是**更新**而不是追加——否则重复放行会把墓碑堆成流水账。"""
    meta: dict = {}
    record_restore(meta, category="DOMAIN", value=_VALUE, source=DOWNGRADE_REPACK_IDENTITY,
                   note="第一次", at="2026-08-01T10:00:00+08:00",
                   prior_advice=infra.ADVICE_REVIEW, new_advice=infra.ADVICE_INVESTIGATE)
    record_restore(meta, category="DOMAIN", value=_VALUE, source=DOWNGRADE_REPACK_IDENTITY,
                   note="第二次（补充依据）", at="2026-08-01T11:00:00+08:00",
                   prior_advice=infra.ADVICE_REVIEW, new_advice=infra.ADVICE_INVESTIGATE)
    entries = meta[MANUAL_RESTORES_KEY]
    assert len(entries) == 1
    assert entries[0]["note"] == "第二次（补充依据）"


# ---------------------------------------------------------------------------
# 两处复压路径都必须认墓碑
# ---------------------------------------------------------------------------


def test_quarantine_skips_manually_restored_lead() -> None:
    """★复压路径一（静态隔离）：已人工放行的不再压。

    这是「经常重跑」场景的核心——没有这道门，重跑一次就把人工核实抹掉。
    去掉 apply_repack_quarantine 里的墓碑判断，本测试即红。
    """
    restored, other = _net_lead(), _net_lead("other.example.com")
    meta = dict(_REPACK_META)
    record_restore(meta, category="DOMAIN", value=_VALUE, source=DOWNGRADE_REPACK_IDENTITY,
                   note="已与官方同版本包差分核实", at="2026-08-01T10:00:00+08:00",
                   prior_advice=infra.ADVICE_REVIEW, new_advice=infra.ADVICE_INVESTIGATE)

    quarantined = apply_repack_quarantine([restored, other], meta)

    assert restored.advice == infra.ADVICE_INVESTIGATE, "已放行的不得被复压"
    assert not restored.downgrades, "也不该重新记账"
    assert _VALUE not in quarantined
    assert other.advice == infra.ADVICE_REVIEW, "没放行的照压不误"
    assert "other.example.com" in quarantined


def test_quarantine_restore_is_scoped_to_the_named_source() -> None:
    """墓碑只放行它指名的那条来源；同一线索上别的来源该压照压。"""
    lead = _net_lead()
    meta = dict(_REPACK_META)
    # 放行的是伪装 SNI 那条，不是重打包。
    record_restore(meta, category="DOMAIN", value=_VALUE, source=DOWNGRADE_SNI_MASQUERADE,
                   note="已核实证书与 Host 一致", at="2026-08-01T10:00:00+08:00",
                   prior_advice=infra.ADVICE_REVIEW, new_advice=infra.ADVICE_INVESTIGATE)

    apply_repack_quarantine([lead], meta)

    assert DOWNGRADE_REPACK_IDENTITY in lead.downgrades, "放行别的来源不影响本来源"
    assert lead.advice == infra.ADVICE_REVIEW


def test_runtime_merge_skips_manually_restored_source() -> None:
    """★复压路径二（运行时回灌的 dict 合并）：已放行的来源不再并进账本。

    回灌是重跑之外的第二条复压路径——只堵静态那条，pcap 一并就把人工放行冲掉了。
    """
    index = restore_index({MANUAL_RESTORES_KEY: [
        {"category": "DOMAIN", "value": _VALUE, "source": DOWNGRADE_SNI_MASQUERADE},
    ]})
    existing = {
        "category": "DOMAIN", "value": _VALUE, "advice": infra.ADVICE_INVESTIGATE,
        "base_advice": infra.ADVICE_INVESTIGATE, "downgrades": {}, "source_refs": [],
    }
    runtime = {
        "category": "DOMAIN", "value": _VALUE,
        "downgrades": {DOWNGRADE_SNI_MASQUERADE: "只在非标准 TLS 端口作 SNI 出现"},
        "source_refs": [{
            "source": "runtime-pcap",
            "location": "pcap",
            "snippet": "x",
            "scope": "case_evidence",
        }],
    }

    ev_merged, ledger_changed = merge_runtime_into_lead_dict(existing, runtime, restored=index)

    assert ev_merged is True, "证据照并——放行的是档位判断，不是证据"
    assert ledger_changed is False, "账本不该被改"
    assert existing["advice"] == infra.ADVICE_INVESTIGATE, "已放行的不得被回灌复压"
    assert not existing.get("downgrades")

    # 对照：没有墓碑时同一份输入必须压下去（否则上面的断言可能是假绿）。
    plain = dict(existing, advice=infra.ADVICE_INVESTIGATE, downgrades={}, source_refs=[])
    merge_runtime_into_lead_dict(plain, runtime, restored=None)
    assert plain["advice"] == infra.ADVICE_REVIEW
    assert DOWNGRADE_SNI_MASQUERADE in plain["downgrades"]


# ---------------------------------------------------------------------------
# closure 一致性守卫
# ---------------------------------------------------------------------------


def test_closure_excludes_hand_edited_advice_and_counts_it() -> None:
    """★手改 advice 绕过 lift_downgrade → 闭环 fail-closed 且计数（不静默）。

    这种报告处于矛盾态：档位说可查、账本却还压着，而下一次任何重算都会把它压回去。
    放行必须走 `fxapk lead restore`，手改的不认。
    """
    from apkscan.core.closure.targets import _select_targets_with_stats

    hand_edited = _net_lead()
    hand_edited.downgrades[DOWNGRADE_REPACK_IDENTITY] = "还压着"
    hand_edited.advice = infra.ADVICE_INVESTIGATE   # 手改：与账本矛盾

    report = Report(
        package_name="com.example.app", meta={}, leads=[hand_edited],
        endpoints=[], findings=[], analyzer_status=[],
    )
    _selected, stats = _select_targets_with_stats(report, 6)

    assert stats.get("inconsistent_excluded") == 1, "矛盾态必须被挡下并计数"


def test_closure_counts_manually_restored_leads() -> None:
    """★墓碑放行必须**可见**：闭环结果要计数「这条是被人放行的，不是判据说它干净」。

    这是墓碑机制唯一站得住的保证。手改 advice 会被上面的一致性守卫挡下，而手塞一条墓碑不会
    （跳过抑制后档位与空账本自洽）——不计数就等于给绕过守卫留了一条**更安静**的路。
    墓碑不做真伪校验，可见性就是全部。
    """
    from apkscan.core.closure.targets import _select_targets_with_stats

    restored_lead = _net_lead()          # 因墓碑而未被抑制，档位是最高档
    meta = dict(_REPACK_META)
    record_restore(meta, category="DOMAIN", value=_VALUE, source=DOWNGRADE_REPACK_IDENTITY,
                   note="已差分核实", at="2026-08-01T10:00:00+08:00",
                   prior_advice=infra.ADVICE_REVIEW, new_advice=infra.ADVICE_INVESTIGATE)
    apply_repack_quarantine([restored_lead], meta)
    assert restored_lead.advice == infra.ADVICE_INVESTIGATE, "前提：墓碑让它没被压"

    report = Report(
        package_name="com.example.app", meta=meta, leads=[restored_lead],
        endpoints=[Endpoint(kind="domain", value=_VALUE)], findings=[], analyzer_status=[],
    )
    _selected, stats = _select_targets_with_stats(report, 6)

    assert stats.get("manually_restored") == 1, (
        "被人工放行的线索进了闭环却不计数——绕过守卫的那条安静路径就是这么留下的"
    )


def test_letters_marks_a_manually_restored_target() -> None:
    """★最危险的消费面：文书正文必须写明「本条系人工放行」。

    这条线索本已被自动判据压住、不该套打，是人放回来的。正文不写这一句，产出的就是一份外观
    完全正常的函——读的人无从知道机器本来拦下了它，也就不会去追放行依据。
    """
    from apkscan.report import letters as letters_mod

    report = {
        "meta": {MANUAL_RESTORES_KEY: [
            {"category": "DOMAIN", "value": _VALUE, "source": DOWNGRADE_REPACK_IDENTITY,
             "note": "已与官方同版本包差分核实"},
        ]},
        "leads": [{
            "category": "DOMAIN", "value": _VALUE, "advice": infra.ADVICE_INVESTIGATE,
            "where_to_request": "域名注册商", "evidence_to_obtain": ["注册人实名"],
            "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}],
        }],
    }
    drafted = letters_mod.build_letters(report)

    assert len(drafted) == 1
    assert "人工放行" in drafted[0]["body_md"], "文书正文没有放行标记"
    assert drafted[0]["manually_restored"] == [DOWNGRADE_REPACK_IDENTITY], "结构化字段也要回带"

    # 对照：judged-clean 的线索不该被标成人工放行（否则警示会贬值成噪音）。
    plain = dict(report, meta={})
    assert "人工放行" not in letters_mod.build_letters(plain)[0]["body_md"]


def test_html_marks_a_manually_restored_lead() -> None:
    """★HTML 出口：人工放行的线索不能以普通最高档线索的外观混在红标区里。"""
    from apkscan.report import html as report_html

    lead = _net_lead()
    meta = {MANUAL_RESTORES_KEY: [
        {"category": "DOMAIN", "value": _VALUE, "source": DOWNGRADE_REPACK_IDENTITY, "note": "已核实"},
    ]}
    rep = Report(package_name="com.example.app", meta=meta, leads=[lead],
                 endpoints=[], findings=[], analyzer_status=[])

    rendered = report_html.render_to_string(rep)

    assert "人工放行" in rendered, "HTML 没标出人工放行，它与判据确认的线索长得一样"
    assert DOWNGRADE_REPACK_IDENTITY in rendered, "要标明放行的是哪条来源"

    # 对照：没有墓碑时不该出现这句（否则警示贬值成噪音）。
    plain = Report(package_name="com.example.app", meta={}, leads=[_net_lead()],
                   endpoints=[], findings=[], analyzer_status=[])
    assert "人工放行" not in report_html.render_to_string(plain)


def test_ioc_export_carries_manual_restore_provenance() -> None:
    """★IOC 出口：人工放行必须随行导出——机器消费方（情报平台）看不到就等于没有。"""
    from apkscan.report import ioc

    report = {
        "meta": {MANUAL_RESTORES_KEY: [
            {"category": "DOMAIN", "value": _VALUE, "source": DOWNGRADE_REPACK_IDENTITY},
        ]},
        "leads": [
            {"category": "DOMAIN", "value": _VALUE, "advice": infra.ADVICE_INVESTIGATE,
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
            {"category": "DOMAIN", "value": "clean.example.com", "advice": infra.ADVICE_INVESTIGATE,
             "source_refs": [{"source": "dex", "location": "classes.dex", "scope": "case_evidence"}]},
        ],
    }
    rows = ioc.leads_to_ioc_rows(report, only_investigate=True)
    by_val = {r["value"]: r for r in rows}

    assert by_val[_VALUE]["manually_restored"] == DOWNGRADE_REPACK_IDENTITY
    assert by_val["clean.example.com"]["manually_restored"] == "", "判据确认的行该列为空"


def test_replay_ambiguous_keeps_each_match_status(tmp_path: Path) -> None:
    """★歧义时不合并成单一状态：一条成功、一条 source_absent，两者都要如实保留。

    合并的话（比如统一报 "lifted"）会掩盖其中一条其实没放行成功——消费方据此以为都放回来了。
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    from apkscan.core.models import apply_downgrade

    pressed = _net_lead()                        # 被压着 → 能 lift
    apply_downgrade(pressed, DOWNGRADE_REPACK_IDENTITY, "隔离")
    free = Lead(category=LeadCategory.IP, value=_VALUE,    # 同值不同类别 → 本轮没被压
                advice=infra.ADVICE_INVESTIGATE, base_advice=infra.ADVICE_INVESTIGATE)
    rep = Report(package_name="com.example.app", meta={"sample_sha256": "7" * 64},
                 leads=[pressed, free], endpoints=[], findings=[], analyzer_status=[])
    report = tmp_path / "report.json"
    write_report(rep, report, render_existing_html=False)
    # 凭据不写 category → 同值跨类别命中两条。
    lead_cmd.save_restores(corpus_dir, [{
        "sample_sha256": "7" * 64, "category": "", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "x", "at": "t",
    }])

    res = runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)])

    assert res.exit_code == 0, res.output
    out = json.loads(res.stdout)
    assert len(out["results"]) == out["candidates"] == 1, "一条凭据恰好一条顶层结果"
    row = out["results"][0]
    assert row["status"] == "ambiguous_multiple_leads"
    assert {m["status"] for m in row["matches"]} == {"lifted_fully_restored", "source_absent"}


def test_closure_keeps_properly_restored_lead() -> None:
    """走 helper 撤销的（档位与账本自洽）照常进闭环——守卫不能把正常放行也挡了。"""
    from apkscan.core.closure.targets import _select_targets_with_stats
    from apkscan.core.models import apply_downgrade, lift_downgrade

    lead = _net_lead()
    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "隔离")
    assert lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY) is True

    report = Report(
        package_name="com.example.app", meta={}, leads=[lead],
        endpoints=[Endpoint(kind="domain", value=_VALUE)], findings=[], analyzer_status=[],
    )
    selected, stats = _select_targets_with_stats(report, 6)

    assert not stats.get("inconsistent_excluded")
    assert [ep.value for ep in selected] == [_VALUE]


# ---------------------------------------------------------------------------
# CLI 端到端
# ---------------------------------------------------------------------------


def _write_pressed_report(path: Path) -> None:
    """写一份「被重打包隔离压过」的报告到 path。"""
    lead = _net_lead()
    report = Report(
        package_name="com.example.app", meta=dict(_REPACK_META),
        leads=[lead], endpoints=[], findings=[], analyzer_status=[],
    )
    apply_repack_quarantine(report.leads, report.meta)
    assert lead.advice == infra.ADVICE_REVIEW, "前提：这条确实被压着"
    write_report(report, path, render_existing_html=False)


def test_cli_show_lists_suppression_sources(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_pressed_report(report)

    res = runner.invoke(cli.app, ["lead", "show", str(report)])

    assert res.exit_code == 0, res.output
    out = json.loads(res.stdout)
    row = next(r for r in out["leads"] if r["value"] == _VALUE)
    assert row["advice"] == infra.ADVICE_REVIEW
    assert DOWNGRADE_REPACK_IDENTITY in row["downgrades"]
    assert row["revocable"] is True, "有判据链锚点，撤得动"


def test_cli_restore_lifts_and_leaves_a_tombstone(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_pressed_report(report)

    res = runner.invoke(cli.app, [
        "lead", "restore", str(report), "--value", _VALUE.upper(),   # 大小写不敏感
        "--source", DOWNGRADE_REPACK_IDENTITY, "--note", "已与官方同版本包差分核实",
    ])

    assert res.exit_code == 0, res.output
    revived = load_report(report)
    lead = revived.leads[0]
    assert lead.advice == infra.ADVICE_INVESTIGATE, "撤销后回到判据链结论"
    assert not lead.downgrades
    tomb = revived.meta[MANUAL_RESTORES_KEY]
    assert len(tomb) == 1 and tomb[0]["note"] == "已与官方同版本包差分核实"
    assert tomb[0]["prior_advice"] == infra.ADVICE_REVIEW


def test_cli_restore_refuses_without_anchor(tmp_path: Path) -> None:
    """两个锚点都不可考的旧报告：拒绝撤销并说清原因，绝不猜一个档位写回去。"""
    report = tmp_path / "report.json"
    legacy = {"leads": [{
        "category": "DOMAIN", "value": _VALUE, "advice": infra.ADVICE_REVIEW,
        "downgrades": {DOWNGRADE_REPACK_IDENTITY: "隔离"},
    }], "meta": {}}
    report.write_text(json.dumps(legacy, ensure_ascii=False), encoding="utf-8")

    res = runner.invoke(cli.app, [
        "lead", "restore", str(report), "--value", _VALUE,
        "--source", DOWNGRADE_REPACK_IDENTITY, "--note", "x",
    ])

    assert res.exit_code == 1
    assert "锚点" in res.stderr
    after = json.loads(report.read_text(encoding="utf-8"))
    assert after["leads"][0]["advice"] == infra.ADVICE_REVIEW, "拒绝时不得改动报告"


def _write_scope_downgraded_report(path: Path, *, with_old_tombstone: bool = False) -> None:
    meta: dict = {"sample_sha256": "a" * 64}
    if with_old_tombstone:
        meta[MANUAL_RESTORES_KEY] = [
            {
                "category": "DOMAIN",
                "value": _VALUE,
                "source": DOWNGRADE_EVIDENCE_SCOPE,
                "note": "历史错误放行凭据",
            }
        ]
    payload = {
        "schema_version": "1.2",
        "package_name": "com.example.app",
        "meta": meta,
        "leads": [
            {
                "category": "DOMAIN",
                "value": _VALUE,
                "advice": infra.ADVICE_REVIEW,
                "base_advice": infra.ADVICE_INVESTIGATE,
                "downgrades": {DOWNGRADE_EVIDENCE_SCOPE: "无当前案件直接证据"},
                "source_refs": [
                    {
                        "source": "batch",
                        "location": "batch.csv",
                        "scope": "batch_reference",
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_cli_restore_refuses_to_lift_evidence_scope_fact(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_scope_downgraded_report(report)
    before = report.read_bytes()

    res = runner.invoke(
        cli.app,
        [
            "lead",
            "restore",
            str(report),
            "--value",
            _VALUE,
            "--source",
            DOWNGRADE_EVIDENCE_SCOPE,
            "--note",
            "人工认为可信",
        ],
    )

    assert res.exit_code != 0
    assert "不可撤销" in res.stderr
    assert report.read_bytes() == before


def test_cli_replay_refuses_historical_evidence_scope_credential(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    lead_cmd.save_restores(
        corpus_dir,
        [
            {
                "sample_sha256": "a" * 64,
                "category": "DOMAIN",
                "value": _VALUE,
                "source": DOWNGRADE_EVIDENCE_SCOPE,
                "note": "历史错误放行凭据",
                "at": "2026-08-01T10:00:00+08:00",
            }
        ],
    )
    report = tmp_path / "report.json"
    _write_scope_downgraded_report(report, with_old_tombstone=True)
    before = report.read_bytes()

    res = runner.invoke(
        cli.app,
        ["lead", "replay", str(report), "--corpus", str(corpus_dir)],
    )

    assert res.exit_code == 0, res.output
    output = json.loads(res.stdout)
    assert output["lifted"] == 0
    assert output["results"][0]["status"] == "non_revocable_scope"
    assert report.read_bytes() == before
    loaded = load_report(report)
    assert DOWNGRADE_EVIDENCE_SCOPE in loaded.leads[0].downgrades
    assert loaded.leads[0].advice == infra.ADVICE_REVIEW


def test_restore_index_ignores_historical_evidence_scope_tombstone() -> None:
    index = restore_index(
        {
            MANUAL_RESTORES_KEY: [
                {
                    "category": "DOMAIN",
                    "value": _VALUE,
                    "source": DOWNGRADE_EVIDENCE_SCOPE,
                }
            ]
        }
    )

    assert not is_restored(index, "DOMAIN", _VALUE, DOWNGRADE_EVIDENCE_SCOPE)


def test_cli_restore_then_replay_survives_a_rerun(tmp_path: Path) -> None:
    """★端到端、也是这一刀存在的理由：放行 → **重跑产出全新报告** → replay 放回。

    「同一份 APK 经常重跑」是常态。凭据只钉在旧报告里的话，重跑出的新报告又是被压的状态，
    人工核实等于每次都要重做。凭据存进样本库、按样本哈希索引，才跨得过重跑。
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    first = tmp_path / "run1" / "report.json"
    first.parent.mkdir()
    _write_pressed_report(first)
    # 样本身份靠 meta.sample_sha256 索引——两次运行是同一个 APK。
    payload = json.loads(first.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "a" * 64
    first.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    res = runner.invoke(cli.app, [
        "lead", "restore", str(first), "--value", _VALUE,
        "--source", DOWNGRADE_REPACK_IDENTITY, "--note", "已差分核实",
        "--corpus", str(corpus_dir),
    ])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["stored_in_corpus"] == 1

    # 重跑：全新的报告，同一个样本哈希，那条线索又被压上了。
    second = tmp_path / "run2" / "report.json"
    second.parent.mkdir()
    _write_pressed_report(second)
    payload2 = json.loads(second.read_text(encoding="utf-8"))
    payload2["meta"]["sample_sha256"] = "a" * 64
    second.write_text(json.dumps(payload2, ensure_ascii=False), encoding="utf-8")
    assert load_report(second).leads[0].advice == infra.ADVICE_REVIEW, "前提：重跑后又被压着"

    res2 = runner.invoke(cli.app, ["lead", "replay", str(second), "--corpus", str(corpus_dir)])

    assert res2.exit_code == 0, res2.output
    out = json.loads(res2.stdout)
    assert out["candidates"] == 1 and out["lifted"] == 1
    assert [r["status"] for r in out["results"]] == ["lifted_fully_restored"], (
        "该来源撤掉后没有别的来源压着，状态应是「已完全恢复」"
    )
    revived = load_report(second)
    assert revived.leads[0].advice == infra.ADVICE_INVESTIGATE, "重跑后的新报告也放回来了"
    assert revived.meta[MANUAL_RESTORES_KEY], "新报告也留下墓碑——后续回灌不会再压它"


def test_cli_replay_is_scoped_to_the_sample(tmp_path: Path) -> None:
    """凭据不跨样本生效：不同样本上的同名域名来源可能完全不同，一次放行就放行所有样本是越界。"""
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    lead_cmd.save_restores(corpus_dir, [{
        "sample_sha256": "b" * 64, "category": "DOMAIN", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "别的样本上的放行", "at": "2026-08-01T10:00:00+08:00",
    }])
    report = tmp_path / "report.json"
    _write_pressed_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "c" * 64       # 另一个样本
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    res = runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)])

    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["candidates"] == 0
    assert load_report(report).leads[0].advice == infra.ADVICE_REVIEW, "别的样本的凭据不得生效"


def test_cli_replay_output_shape_is_identical_across_branches(tmp_path: Path) -> None:
    """``replay`` 的每个出口给出**同一套键、同样的类型**——分支形状漂移是机器契约最伤下游的一种。

    ★这条走 CLI 真入口而不是只调 ``_replay_payload``：形状要一致靠的是「每个出口都真的走了
      那个构造器」，只测构造器本身测不到有人在某个分支里另拼一个字典（那正是修掉的原样）。
      「库里没有该样本的凭据」还是最常走到的分支——新样本第一次重放时库里当然是空的。
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    report = tmp_path / "report.json"
    _write_pressed_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "e" * 64
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    # 分支一：库里没有这个样本的任何凭据（早退出口）。
    empty = json.loads(
        runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)]).stdout
    )

    # 分支二：有凭据、正常走完（主出口）。
    lead_cmd.save_restores(corpus_dir, [{
        "sample_sha256": "e" * 64, "category": "DOMAIN", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "x", "at": "2026-08-01T10:00:00+08:00",
    }])
    full = json.loads(
        runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)]).stdout
    )

    contract = {"sample_sha256", "candidates", "lifted", "results", "written", "dry_run"}
    assert contract <= set(empty), f"早退出口缺键：{sorted(contract - set(empty))}"
    assert contract <= set(full), f"主出口缺键：{sorted(contract - set(full))}"
    for key in contract:
        assert type(empty[key]) is type(full[key]), (
            f"键 {key!r} 在两个出口类型不同："
            f"{type(empty[key]).__name__} vs {type(full[key]).__name__}"
        )
    # note 只在有话要说时出现，是给人看的补充，不进消费方该依赖的那套键。
    assert set(empty) - contract == {"note"} and set(full) == contract


def test_cli_replay_dry_run_does_not_write(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    report = tmp_path / "report.json"
    _write_pressed_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "d" * 64
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    lead_cmd.save_restores(corpus_dir, [{
        "sample_sha256": "d" * 64, "category": "DOMAIN", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "x", "at": "2026-08-01T10:00:00+08:00",
    }])

    res = runner.invoke(cli.app, [
        "lead", "replay", str(report), "--corpus", str(corpus_dir), "--dry-run",
    ])

    assert res.exit_code == 0, res.output
    out = json.loads(res.stdout)
    assert out["lifted"] == 1 and out["written"] == [] and out["dry_run"] is True
    assert load_report(report).leads[0].advice == infra.ADVICE_REVIEW, "dry-run 不得写盘"


def test_runtime_first_seen_lead_also_respects_the_tombstone() -> None:
    """★复压路径三（回灌**首次**引入该值）：append 的新 lead 同样要摘掉已放行的来源。

    合并分支已按墓碑过滤，但首次引入走的是直接 append 一个**已经带着抑制账本**的 dict。
    真实序列：新报告 replay 放行 → 本轮静态侧没产出该值 → pcap 首次发现它 → 带抑制入库 →
    人工核实被抹掉。去掉 append 前的 strip_restored_downgrades，本测试即红。
    """
    from apkscan.core.restore import strip_restored_downgrades

    index = restore_index({MANUAL_RESTORES_KEY: [
        {"category": "DOMAIN", "value": _VALUE, "source": DOWNGRADE_SNI_MASQUERADE},
    ]})
    fresh = {
        "category": "DOMAIN", "value": _VALUE,
        "advice": infra.ADVICE_REVIEW, "base_advice": infra.ADVICE_INVESTIGATE,
        "downgrades": {DOWNGRADE_SNI_MASQUERADE: "只在非标准 TLS 端口作 SNI 出现"},
    }

    assert strip_restored_downgrades(fresh, index) is True
    assert not fresh["downgrades"], "已放行的来源要摘掉"
    assert fresh["advice"] == infra.ADVICE_INVESTIGATE, "并按剩余账本重算档位，不是直接写"

    # 对照：别的来源不受影响，档位仍压着。
    other = {
        "category": "DOMAIN", "value": _VALUE,
        "advice": infra.ADVICE_REVIEW, "base_advice": infra.ADVICE_INVESTIGATE,
        "downgrades": {DOWNGRADE_REPACK_IDENTITY: "隔离"},
    }
    assert strip_restored_downgrades(other, index) is False
    assert other["advice"] == infra.ADVICE_REVIEW


def test_probe_ingest_first_seen_lead_respects_tombstone_via_real_entry(tmp_path: Path) -> None:
    """★接线锁：走**真入口** `probe_ingest.merge_into_report_json`，验 append 分支认墓碑。

    上一条只调 helper 本身——删掉 append 分支的调用、传错索引、把调用挪到 append 之后，
    那条测试照样绿。接线必须由走真入口的用例来锁（本项目实证过「函数写了但没人调」）。
    """
    from apkscan.dynamic import probe_ingest

    report = tmp_path / "report.json"
    # 报告里**没有**这条线索（模拟 replay 放行后、本轮静态侧未产出），但带着放行墓碑。
    report.write_text(json.dumps({
        "leads": [],
        "endpoints": [],
        "meta": {MANUAL_RESTORES_KEY: [
            {"category": "IP", "value": "203.0.113.9:8443", "source": DOWNGRADE_REPACK_IDENTITY},
        ]},
    }, ensure_ascii=False), encoding="utf-8")

    # 构造一条带抑制账本的 runtime lead，走真入口首次并入。
    pressed = Lead(
        category=LeadCategory.IP, value="203.0.113.9:8443",
        advice=infra.ADVICE_REVIEW, base_advice=infra.ADVICE_INVESTIGATE,
        downgrades={DOWNGRADE_REPACK_IDENTITY: "隔离"},
    )
    monkeyed = probe_ingest.to_report_leads
    try:
        probe_ingest.to_report_leads = lambda _leads: [pressed]   # type: ignore[assignment]
        probe_ingest.merge_into_report_json(str(report), [])
    finally:
        probe_ingest.to_report_leads = monkeyed  # type: ignore[assignment]

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["leads"], "前提：这条 lead 确实是首次被并入（走 append 分支）"
    merged = payload["leads"][0]
    assert not merged.get("downgrades"), "首次并入也要摘掉已放行的来源"
    assert merged["advice"] == infra.ADVICE_INVESTIGATE, "并按剩余账本重算档位"


def test_replay_reports_a_status_for_every_credential(tmp_path: Path) -> None:
    """★每条凭据恰好一条结果：线索不存在 / 本轮没被该来源压着，都要有明确状态。

    只给 lifted 列表的话，「凭据对应的线索本轮根本不存在」会静默落进列表之外——
    消费方（工作流里是 AI）看到 candidates>0 却什么都没有，无从判断是成功还是没匹配上。
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    report = tmp_path / "report.json"
    _write_pressed_report(report)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["meta"]["sample_sha256"] = "f" * 64
    report.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    lead_cmd.save_restores(corpus_dir, [
        {"sample_sha256": "f" * 64, "category": "DOMAIN", "value": "gone.example.com",
         "source": DOWNGRADE_REPACK_IDENTITY, "note": "线索本轮不存在", "at": "t"},
        {"sample_sha256": "f" * 64, "category": "DOMAIN", "value": _VALUE,
         "source": DOWNGRADE_SNI_MASQUERADE, "note": "本轮没被这条来源压着", "at": "t"},
    ])

    res = runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)])

    assert res.exit_code == 0, res.output
    out = json.loads(res.stdout)
    assert out["candidates"] == 2 and out["lifted"] == 0
    assert {r["status"] for r in out["results"]} == {"lead_missing", "source_absent"}
    assert len(out["results"]) == 2, "每条凭据恰好一条结果"


def test_replay_distinguishes_partial_restore(tmp_path: Path) -> None:
    """撤掉一条但仍被别的来源压着 → 状态是 lifted_still_suppressed，且带出剩余来源。

    「已完全恢复」与「只撤了一个、还压着」在 advice 上都可能不是最高档，靠状态区分。
    """
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    from apkscan.core.models import apply_downgrade

    lead = _net_lead()
    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "隔离")
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "伪装 SNI")
    rep = Report(package_name="com.example.app", meta={"sample_sha256": "9" * 64},
                 leads=[lead], endpoints=[], findings=[], analyzer_status=[])
    report = tmp_path / "report.json"
    write_report(rep, report, render_existing_html=False)
    lead_cmd.save_restores(corpus_dir, [{
        "sample_sha256": "9" * 64, "category": "DOMAIN", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "只放行重打包这条", "at": "t",
    }])

    res = runner.invoke(cli.app, ["lead", "replay", str(report), "--corpus", str(corpus_dir)])

    assert res.exit_code == 0, res.output
    row = json.loads(res.stdout)["results"][0]
    assert row["status"] == "lifted_still_suppressed"
    assert row["remaining_downgrades"] == [DOWNGRADE_SNI_MASQUERADE]
    assert row["advice"] == infra.ADVICE_REVIEW, "另一条来源还压着，档位不回升"


def test_corpus_path_inside_git_worktree_is_refused(tmp_path: Path) -> None:
    """★凭据含真实线索值与核实说明——落在 git 工作树内一律拒跑。

    这道防线在 corpus 命令上早就有；`lead` 各写一份解析就等于把它绕过去了，故共用同一入口。
    """
    fake_repo = tmp_path / "repo"
    (fake_repo / ".git").mkdir(parents=True)
    report = fake_repo / "report.json"
    _write_pressed_report(report)

    # ★必须在**任何**调用之前取基线：放到调用之后取，等于拿被改坏的内容当基线，
    #   原子性断言就恒真了（假绿）。
    before = report.read_bytes()

    res = runner.invoke(cli.app, [
        "lead", "restore", str(report), "--value", _VALUE,
        "--source", DOWNGRADE_REPACK_IDENTITY, "--note", "x",
        "--corpus", str(fake_repo / "corpus"),
    ])

    assert res.exit_code == 2, res.output
    assert "git 工作树" in res.stderr
    assert not (fake_repo / "corpus" / lead_cmd.RESTORES_NAME).exists(), "拒跑就不该落盘"
    # ★原子性：拒跑必须发生在**任何**报告改动之前。校验落在写盘之后的话，报告已经被改写、
    #   甚至连带刷新了 HTML——那是「一半生效」，比直接失败更难收拾。
    assert report.read_bytes() == before, "拒跑时报告必须逐字节不变"


def test_both_normalizers_share_one_contract() -> None:
    """★两处三元组匹配必须同口径：models 的比对与 restore 的建索引共用同一个归一化函数。

    这是**安全键的匹配规则**——分叉会让「已放行」在一处成立、另一处不成立，人工核实在某条
    路径上被静默抹掉。此处直接对两者施加同一组混合大小写/空白/None 输入。
    """
    from apkscan.core.models import _is_restored_triplet
    from apkscan.core.restore import norm_component

    cases = ["  DOMAIN ", "domain", "Api.Example.COM", None, "", "  "]
    for raw in cases:
        index = {(norm_component("DOMAIN"), norm_component(raw), norm_component("SRC"))}
        assert _is_restored_triplet(index, " domain ", raw, " src "), f"输入 {raw!r} 两处口径不一致"
        assert is_restored(index, "DOMAIN", raw, "SRC"), f"输入 {raw!r} restore 侧不一致"


def test_restores_file_roundtrip_and_upsert(tmp_path: Path) -> None:
    """凭据文件的往返与去重：同 (样本,类别,值,来源) 覆盖而非堆积；坏行跳过不抛。"""
    entries = lead_cmd.upsert_restore([], {
        "sample_sha256": "e" * 64, "category": "DOMAIN", "value": _VALUE,
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "第一次", "at": "t1",
    })
    entries = lead_cmd.upsert_restore(entries, {
        "sample_sha256": "e" * 64, "category": "DOMAIN", "value": _VALUE.upper(),
        "source": DOWNGRADE_REPACK_IDENTITY, "note": "第二次", "at": "t2",
    })
    assert len(entries) == 1 and entries[0]["note"] == "第二次"

    lead_cmd.save_restores(tmp_path, entries)
    # 混入一行坏数据，读取必须跳过而不是崩。
    with lead_cmd.restores_path(tmp_path).open("a", encoding="utf-8") as fh:
        fh.write("{不是 json\n")
    assert len(lead_cmd.load_restores(tmp_path)) == 1
