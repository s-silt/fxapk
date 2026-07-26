"""跨版本回归对比（corpus regress）：真样本换版后检出变好还是变坏。零真实数据，合成报告。"""
from __future__ import annotations

import json

from apkscan.core import corpus, regress


def _report(sha: str, version: str, *, status="complete", hardened=False,
            findings=(), leads=(), closure=None, pkg="com.x", ruleset="dd") -> dict:
    return {
        "schema_version": "1.0",
        "analysis_status": status,
        "completeness": 1.0,
        "package_name": pkg,
        "meta": {
            "sample_sha256": sha, "tool_version": version, "ruleset_digest": ruleset,
            "is_hardened": hardened,
            **({"closure": {"status": closure}} if closure else {}),
        },
        "findings": [{"id": f} for f in findings],
        "leads": [{"category": "DOMAIN", "value": f"d{i}.test", "advice": a}
                  for i, a in enumerate(leads)],
        "endpoints": [],
    }


def _seed(tmp_path, reports: list[dict]):
    """把报告入库（走真实 corpus.add_report，保证与生产同路径）。"""
    root = tmp_path / "corpus"
    for r in reports:
        raw = json.dumps(r, ensure_ascii=False)
        corpus.add_report(root, r, raw, case_id="c1")
    return root


def test_detects_became_analyzable(tmp_path):
    """★方向明确的改善：由分析失败转为可分析（实测两个样本正是从整包被拒变为可分析）。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", status="failed"),
        _report("s1", "1.1.0", status="complete"),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["became_analyzable"] == 1
    assert any("由分析失败转为可分析" in n for n in diffs[0].notes)


def test_detects_hardening_newly_detected(tmp_path):
    """★加固漏判 → 检出（今天新增 stub-dex 结构判据正是这个效果）。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", hardened=False),
        _report("s1", "1.1.0", hardened=True, findings=["PACK-UNIDENTIFIED-STUB-DEX"]),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["hardening_newly_detected"] == 1
    assert diffs[0].findings_added == ["PACK-UNIDENTIFIED-STUB-DEX"]


def test_advice_investigate_change_tracked(tmp_path):
    """★核心指标：建议调证条数变化必须被捕捉。

    实测一次降噪把它从 89 压到 24，而线索**总数**只从 107 降到 87——只看总数完全看不出来，
    故必须按 advice 分档统计（manifest 只存总数，需回读报告全文）。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", leads=["建议调证"] * 8 + ["待核"] * 2),
        _report("s1", "1.1.0", leads=["建议调证"] * 2 + ["无需调证"] * 6 + ["待核"] * 2),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["advice_investigate_from"] == 8
    assert summary["advice_investigate_to"] == 2
    assert any("建议调证 8 → 2" in n and "降噪" in n for n in diffs[0].notes)
    # 线索总数没变，只看 counts 会漏
    assert diffs[0].counts_from["leads"] == diffs[0].counts_to["leads"] == 10


def test_closure_downgrade_flagged_for_human_review(tmp_path):
    """★闭环 complete → partial 必须标出并要求人核：可能是正确降级，也可能是误伤。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", closure="complete"),
        _report("s1", "1.1.0", closure="partial"),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["closure_downgraded"] == 1
    assert any("须人核" in n for n in diffs[0].notes)


def test_no_overall_verdict_given(tmp_path):
    """★绝不给"优化/劣化"总评分：检出变多可能是误报涨了，变少可能是降噪，方向要人判。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", findings=["A"]),
        _report("s1", "1.1.0", findings=["A", "B"]),
    ])
    _diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    for banned in ("verdict", "score", "improved", "regressed", "better", "worse"):
        assert banned not in summary, f"汇总不得含总评分字段：{banned}"


def test_only_in_one_version_not_counted_as_change(tmp_path):
    """仅单版有的样本（新入库/旧版未跑）单列，不当成检出变化。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0"),
        _report("s1", "1.1.0"),
        _report("s2", "1.1.0"),          # 只有新版
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["compared"] == 1
    assert summary["only_in_to"] == 1
    assert len(diffs) == 1


def test_available_versions_and_missing_report_tolerated(tmp_path):
    root = _seed(tmp_path, [_report("s1", "1.0.0"), _report("s1", "1.1.0")])
    entries = corpus.load_manifest(root)
    assert regress.available_versions(entries) == ["1.0.0@dd", "1.1.0@dd"]
    # 报告文件被删 → advice 统计退化为空，但不抛
    for f in (root / "reports").rglob("*.json"):
        f.unlink()
    diffs, _summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].advice_from == {} and diffs[0].advice_to == {}


def test_same_tool_version_different_ruleset_is_comparable(tmp_path):
    """★真实迭代形态：版本号不动、规则集在动。

    实测语料库 14 个样本里被重跑过的三个**全部**是同 tool_version 不同 ruleset_digest；
    若版本坐标只取 tool_version，一整轮规则改动的效果会被量成 0（两版零重叠）。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.2.0", ruleset="aaaaaaaa11", findings=["A"]),
        _report("s1", "1.2.0", ruleset="bbbbbbbb22", findings=["A", "B"]),
    ])
    entries = corpus.load_manifest(root)
    revs = regress.available_versions(entries)
    assert revs == ["1.2.0@aaaaaaaa", "1.2.0@bbbbbbbb"]
    diffs, summary = regress.load_and_diff(root, revs[0], revs[1])
    assert summary["compared"] == 1, "同版本不同规则集必须能对上，否则本轮改动量不出来"
    assert diffs[0].findings_added == ["B"]


def test_resolve_revision_refuses_ambiguous_version():
    """★版本号下有多个规则集时拒绝猜：猜错会把两次不同规则集的结果错当同一版对比。"""
    revs = ["1.1.0@aaaa1111", "1.2.0@bbbb2222", "1.2.0@cccc3333"]
    assert regress.resolve_revision("1.2.0@bbbb2222", revs)[0] == "1.2.0@bbbb2222"
    assert regress.resolve_revision("1.1.0", revs)[0] == "1.1.0@aaaa1111"  # 唯一前缀可省
    got, err = regress.resolve_revision("1.2.0", revs)
    assert got is None and "多个规则集" in err
    got, err = regress.resolve_revision("9.9.9", revs)
    assert got is None and "不在库内" in err


def test_cli_regress_requires_two_versions(tmp_path):
    """★库内只有一版时明确拒跑（exit 2），不静默给空对比。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _seed(tmp_path, [_report("s1", "1.0.0")])
    r = CliRunner().invoke(cli.app, ["corpus", "regress", "--corpus", str(root)])
    assert r.exit_code == 2
    assert "无法跨版本对比" in r.stdout + str(r.stderr or "")


def test_cli_regress_json_output(tmp_path):
    from typer.testing import CliRunner

    from apkscan import cli

    root = _seed(tmp_path, [
        _report("s1", "1.0.0", status="failed"),
        _report("s1", "1.1.0", status="complete", findings=["X"]),
    ])
    r = CliRunner().invoke(cli.app, ["corpus", "regress", "--corpus", str(root), "--json"])
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["summary"]["became_analyzable"] == 1
    assert payload["diffs"][0]["findings_added"] == ["X"]
