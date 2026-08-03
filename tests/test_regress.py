"""跨版本回归对比（corpus regress）：真样本换版后检出变好还是变坏。零真实数据，合成报告。"""
from __future__ import annotations

import json

from apkscan.core import corpus, regress


def _report(sha: str, version: str, *, status="complete", hardened=False,
            findings=(), leads=(), closure=None, pkg="com.x", ruleset="dd",
            visibility=None) -> dict:
    return {
        "schema_version": "1.0",
        "analysis_status": status,
        "completeness": 1.0,
        "package_name": pkg,
        "meta": {
            "sample_sha256": sha, "tool_version": version, "ruleset_digest": ruleset,
            "is_hardened": hardened,
            **({"closure": {"status": closure}} if closure else {}),
            **({"visibility": visibility} if visibility is not None else {}),
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


def test_available_versions_follows_insertion_order(tmp_path):
    """★修订版按**入库顺序**返回，不是字典序。

    字典序里 "1.10.0" 排在 "1.9.0" 前面，取最后一个当「最新版」会拿到 1.9——方向直接反了。
    manifest 没有任何时间戳字段，而 corpus.upsert 是纯追加，行序即入库顺序，这是唯一能代表新旧的信号。
    """
    root = _seed(tmp_path, [_report("s1", "1.9.0"), _report("s1", "1.10.0")])
    entries = corpus.load_manifest(root)
    revs = regress.available_versions(entries)
    assert revs == ["1.9.0@dd", "1.10.0@dd"], "修订版顺序必须跟入库顺序，不能按字符串排"
    assert revs[-1].startswith("1.10.0"), "后入库的才是最新版"


def test_missing_report_never_reads_as_zero_leads(tmp_path):
    """★报告读不到 ≠ 零线索——这正是本模块存在的理由，不能在它内部先犯这个错。

    曾把「读不到」和「读到了但零线索」都折叠成 {}，于是一份报告文件缺失就会渲染出
    「建议调证 8 → 0（降噪）」和「闭环 complete → None（降级）」，凭空捏造并不存在的改进。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", leads=["建议调证"] * 8, closure="complete"),
        _report("s1", "1.1.0", leads=["建议调证"] * 8, closure="complete"),
    ])
    # 只删新版那份报告全文（manifest 记录仍在）
    victim = next(p for p in (root / "reports").rglob("*.json") if "1.1.0" in p.name)
    victim.unlink()

    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    d = diffs[0]
    assert d.advice_to is None, "读不到必须是 None，不能是 {}（那等于断言零线索）"
    assert d.advice_from is not None
    assert any("读不到" in n for n in d.notes)
    assert not any("降噪" in n for n in d.notes), "不得凭空断言降噪"
    assert not any("→" in n for n in d.notes), f"读不到时不得给出任何 A→B 结论：{d.notes}"
    # 汇总不得把读不到的样本算成 0 条
    assert summary["advice_investigate_from"] == 0, "该样本不可比，不该进合计"
    assert summary["advice_comparable"] == 0
    assert summary["advice_unreadable"] == 1
    assert summary["closure_downgraded"] == 0


def test_empty_leads_distinguished_from_unreadable(tmp_path):
    """对照：报告读得到、leads 确实为空 → {} 而非 None，降噪结论正常产出。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", leads=["建议调证"] * 3),
        _report("s1", "1.1.0", leads=[]),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].advice_to == {}
    assert summary["advice_comparable"] == 1 and summary["advice_unreadable"] == 0
    assert any("建议调证 3 → 0" in n for n in diffs[0].notes)


def test_malformed_manifest_does_not_raise(tmp_path):
    """★「绝不抛」要对畸形 manifest 也成立：手编/旧 schema 的坏值不得炸到调用方。"""
    root = _seed(tmp_path, [_report("s1", "1.0.0"), _report("s1", "1.1.0")])
    mpath = next((root).rglob("manifest.jsonl"))
    rows = [json.loads(x) for x in mpath.read_text(encoding="utf-8").splitlines() if x.strip()]
    rows[0]["counts"] = "not-a-dict"
    rows[1]["finding_ids"] = [{"nested": "dict"}, "OK-ID"]
    mpath.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")

    diffs, _summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].counts_from == {}
    assert diffs[0].findings_added == ["OK-ID"]  # 畸形元素跳过，合法的仍算


def test_same_tool_version_different_ruleset_is_comparable(tmp_path):
    """★真实迭代形态：版本号不动、规则集在动。

    实测语料库 多个样本里被重跑过的三个**全部**是同 tool_version 不同 ruleset_digest；
    若版本坐标只取 tool_version，一整轮规则改动的效果会被量成 0（两版零重叠）。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.2.0", ruleset="aaaaaaaa11", findings=["A"]),
        _report("s1", "1.2.0", ruleset="bbbbbbbb22", findings=["A", "B"]),
    ])
    entries = corpus.load_manifest(root)
    revs = regress.available_versions(entries)
    assert revs == ["1.2.0@aaaaaaaa11", "1.2.0@bbbbbbbb22"]
    diffs, summary = regress.load_and_diff(root, revs[0], revs[1])
    assert summary["compared"] == 1, "同版本不同规则集必须能对上，否则本轮改动量不出来"
    assert diffs[0].findings_added == ["B"]


def test_resolve_revision_refuses_ambiguous_version():
    """★版本号下有多个规则集时拒绝猜：猜错会把两次不同规则集的结果错当同一版对比。"""
    revs = ["1.1.0@aaaa1111", "1.2.0@bbbb2222", "1.2.0@cccc3333"]
    assert regress.resolve_revision("1.2.0@bbbb2222", revs)[0] == "1.2.0@bbbb2222"
    assert regress.resolve_revision("1.1.0", revs)[0] == "1.1.0@aaaa1111"  # 该版唯一，可省摘要
    assert regress.resolve_revision("1.2.0@bbbb", revs)[0] == "1.2.0@bbbb2222"  # 摘要可写前缀
    got, err = regress.resolve_revision("1.2.0", revs)
    assert got is None and "多个规则集" in err
    got, err = regress.resolve_revision("9.9.9", revs)
    assert got is None and "不在库内" in err


def test_resolve_revision_does_not_cross_version_boundary():
    """★版本段要**精确相等**，不能整串前缀匹配：否则 "1.1.0" 会静默解析成 "1.1.0-rc"。"""
    got, err = regress.resolve_revision("1.1.0", ["1.1.0-rc@abcd1234"])
    assert got is None, f"稳定版输入被解析成了预发布版：{got}"
    assert "不在库内" in err
    # 两者并存时也不得把稳定版输入配到 rc
    revs = ["1.1.0@aaaa1111", "1.1.0-rc@bbbb2222"]
    assert regress.resolve_revision("1.1.0", revs)[0] == "1.1.0@aaaa1111"
    assert regress.resolve_revision("1.1.0-rc", revs)[0] == "1.1.0-rc@bbbb2222"


def test_revision_uses_full_digest_not_prefix(tmp_path):
    """★修订版键用**完整** ruleset_digest。

    corpus 主键用的是完整 digest，两份「完整值不同、前 8 位相同」的报告是合法共存的两条记录；
    若按前 8 位切版，它们会被压成同一版——两套不同规则集的结果被当成同一版互相对比。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.2.0", ruleset="abcdef1200000000", findings=["A"]),
        _report("s1", "1.2.0", ruleset="abcdef1299999999", findings=["A", "B"]),
    ])
    revs = regress.available_versions(corpus.load_manifest(root))
    assert len(revs) == 2, f"前 8 位相同的两套规则集被压成了同一版：{revs}"
    # 人读形态仍截断显示
    assert regress.short_revision(revs[0]) == "1.2.0@abcdef12"
    diffs, summary = regress.load_and_diff(root, revs[0], revs[1])
    assert summary["compared"] == 1 and diffs[0].findings_added == ["B"]


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


# ---------------------------------------------------------------------------
# 证据可见性维度：警示消失 = 漏报放大器，必须被回归护网抓住
# ---------------------------------------------------------------------------


def _vis(*, blocked=("static_endpoint_exhaustive",), dex="stub_only", actions=1,
         degraded=True, remediation="not_attempted", notes=("原文案",)) -> dict:
    """合成一份 meta.visibility（形状照 visibility.assess 的返回值）。"""
    return {
        "schema_version": "1.0",
        "sources": {
            "dex": {"visibility": dex, "why": ["合成"]},
            "native": {"visibility": "complete", "why": []},
            "resource": {"visibility": "complete", "why": []},
            "runtime": {"visibility": "unavailable", "why": []},
        },
        "claims": {c: {"eligible": False} for c in blocked},
        "blocked_claims": sorted(blocked),
        "remediation": remediation,
        "notes": list(notes),
        "next_actions": [f"补法{i}" for i in range(actions)],
        "degraded": degraded,
    }


def test_visibility_blocked_cleared_flagged_for_human_review(tmp_path):
    """★核心回归锁：受限主张凭空解除必须标「须人核」，哪怕线索/检出/闭环全都没变。

    这是漏报放大器的形态——办案人看到「未发现远程配置」会当成已穷尽，而真相可能只是
    可见性求值退化把警示弄丢了。两版 closure 同为 partial（复刻「闭环早已因截断降级」的
    盲区前提：closure 维度看不出任何变化）。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", closure="partial", leads=["建议调证"] * 3,
                visibility=_vis(blocked=("static_endpoint_exhaustive",), dex="stub_only")),
        _report("s1", "1.1.0", closure="partial", leads=["建议调证"] * 3,
                visibility=_vis(blocked=(), dex="complete", actions=0, degraded=False)),
        # 对照样本：两版可见性完全相同 → 不得被标为有变化（防「恒 True」的退化实现）
        _report("s2", "1.0.0", closure="partial", visibility=_vis()),
        _report("s2", "1.1.0", closure="partial", visibility=_vis()),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    by_sha = {d.sample_sha256[:2]: d for d in diffs}
    changed = next(d for d in diffs if d.visibility_from != d.visibility_to)
    assert changed.changed is True
    assert summary["changed"] == 1, "只有 s1 该被标为有变化"
    assert summary["visibility_blocked_cleared"] == 1
    assert summary["visibility_comparable"] == 2
    assert any("受限主张解除" in n and "须人核" in n for n in changed.notes), changed.notes
    unchanged = next(d for d in diffs if d is not changed)
    assert unchanged.changed is False, "可见性完全相同的样本不得被标为有变化"
    assert by_sha  # 库内两个样本都在


def test_visibility_next_actions_zeroed_while_still_blind(tmp_path):
    """★历史缺陷形态锁：仍有受限主张、补法建议却清零（当年可见性求值排在补法预案之前）。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis(actions=16)),
        _report("s1", "1.1.0", visibility=_vis(actions=0)),
    ])
    diffs, _summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].changed is True
    assert any("补法建议清零" in n for n in diffs[0].notes), diffs[0].notes


def test_visibility_assessment_lost_is_not_silence(tmp_path):
    """★求值整体丢失锁（兼 None-vs-{} 纪律）：新版报告读得到、却没有可见性求值。

    若把「缺失」折叠成 {}（重犯 advice_counts 当年的错），两侧就都是 {} → changed=False，
    「pipeline 把整个可见性阶段丢了」这种退化又回到不可见。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis()),
        _report("s1", "1.1.0"),  # 新版无 meta.visibility
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].visibility_to is None, "缺失必须是 None，不能折叠成 {}"
    assert diffs[0].changed is True
    assert summary["visibility_assessment_lost"] == 1
    assert any("求值阶段丢失" in n for n in diffs[0].notes), diffs[0].notes


def test_visibility_added_blocked_is_neutral_not_alarming(tmp_path):
    """新增受限主张多半是新约束正确降级：记中性备注、不标 ⚠（取证代价不对称）。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis(blocked=())),
        _report("s1", "1.1.0", visibility=_vis(blocked=("no_remote_config",))),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["visibility_blocked_added"] == 1
    assert summary["visibility_blocked_cleared"] == 0
    vis_notes = [n for n in diffs[0].notes if "可见性" in n]
    assert vis_notes and all("⚠" not in n for n in vis_notes), vis_notes


def test_visibility_change_without_any_note_still_counts_as_changed(tmp_path):
    """★指纹变化本身就是变化，不能只靠「有没有产生 ⚠ 备注」来决定是否列出。

    只有告警形态的变化才进 notes（受限主张增减、补法建议清零）；补法建议条数普通增减、
    某一源的档位挪动都不告警。若 changed 只看 notes，这类变化在默认 --changed-only 下
    整个消失——回归护网看不见的东西等于没护。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis(actions=1)),
        _report("s1", "1.1.0", visibility=_vis(actions=5)),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].notes == [], "本例不该触发任何告警备注"
    assert diffs[0].changed is True, "notes 为空，但指纹变了 → 仍须列出"
    assert summary["changed"] == 1


def test_visibility_prose_changes_do_not_count_as_regression(tmp_path):
    """★指纹边界锁：人读文案（notes）不入指纹。

    收录文案 = 每次措辞微调全库样本都被标「有变化」，人很快不看 regress 输出，真退化反被淹没。
    """
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis(notes=("旧措辞",))),
        _report("s1", "1.1.0", visibility=_vis(notes=("新措辞，完全改写了这句话",))),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].changed is False, "只改文案不算回归"
    assert summary["changed"] == 0


def test_both_versions_without_visibility_is_not_a_change(tmp_path):
    """两版都没有可见性求值（旧库）→ 无变化：锁「缺失返回 None 而非空 dict」。"""
    root = _seed(tmp_path, [_report("s1", "1.0.0"), _report("s1", "1.1.0")])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert diffs[0].visibility_from is None and diffs[0].visibility_to is None
    assert diffs[0].changed is False
    assert summary["visibility_comparable"] == 0
    assert summary["visibility_assessment_lost"] == 0


def test_legacy_to_new_schema_is_neutral_not_lost(tmp_path):
    """旧版无求值 → 新版有：一次性的 schema 升级，中性备注，绝不计入「求值丢失」。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0"),
        _report("s1", "1.1.0", visibility=_vis()),
    ])
    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    assert summary["visibility_assessment_lost"] == 0
    assert any("旧版本产物" in n for n in diffs[0].notes), diffs[0].notes
    assert not any("⚠" in n for n in diffs[0].notes if "可见性" in n)


def test_unreadable_report_suppresses_visibility_conclusions(tmp_path):
    """★读不到时的早退优先级不被破坏：可见性 notes 必须排在 unreadable 早退之后。"""
    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis()),
        _report("s1", "1.1.0", visibility=_vis(blocked=())),
    ])
    victim = next(p for p in (root / "reports").rglob("*.json") if "1.1.0" in p.name)
    victim.unlink()

    diffs, summary = regress.load_and_diff(root, "1.0.0@dd", "1.1.0@dd")
    d = diffs[0]
    assert d.visibility_to is None
    assert any("读不到" in n for n in d.notes)
    assert not any("受限主张解除" in n for n in d.notes), f"读不到时不得下可见性结论：{d.notes}"
    assert summary["visibility_blocked_cleared"] == 0
    # 报告读不到 → 走 advice_unreadable 口径，不折进「求值丢失」
    assert summary["visibility_assessment_lost"] == 0


def test_cli_regress_renders_visibility(tmp_path):
    """★CLI 接线锁：--json 与文本两路都要把可见性变化渲染到人眼前。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _seed(tmp_path, [
        _report("s1", "1.0.0", visibility=_vis()),
        _report("s1", "1.1.0", visibility=_vis(blocked=(), actions=0, degraded=False)),
    ])
    r = CliRunner().invoke(cli.app, ["corpus", "regress", "--corpus", str(root), "--json"])
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["diffs"], "仅可见性变化的样本必须出现在默认 --changed-only 输出里"
    assert payload["diffs"][0]["visibility"][0]["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert payload["diffs"][0]["visibility"][1]["blocked_claims"] == []
    assert payload["summary"]["visibility_blocked_cleared"] == 1

    r2 = CliRunner().invoke(cli.app, ["corpus", "regress", "--corpus", str(root)])
    assert r2.exit_code == 0, r2.stdout
    assert "可见性受限解除 1" in r2.stdout
    assert "受限主张解除" in r2.stdout
