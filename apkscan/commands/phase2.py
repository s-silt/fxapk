# -*- coding: utf-8 -*-
"""Phase2 复核命令（``fxapk phase2 <子命令>``）：消费 Phase1 不可变包，产判决、覆盖与门禁。"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import typer
from typer.core import TyperGroup

from apkscan.core.phase2.inventory import (
    audit_coverage,
    build_coverage_skeleton,
    build_inventory,
    load_clue_records,
    load_coverage_snapshot,
)
from apkscan.core.phase2.link import build_gate_receipt, write_gate_receipt
from apkscan.core.phase2.triage import build_triage, render_queue_md
from apkscan.core.phase2.decision import (
    DecisionError,
    append_decision,
    append_decisions,
    build_batch_decisions,
    build_decision,
    build_decisions_from_intents,
    classify_replay_change,
    extract_established_hosts,
    load_decisions,
    materialize_case,
    members_hash,
    resolve_unique_prefix,
    signals_hash,
    run_gate,
    show_parent_members,
)


def _coverage_decisions_sha256(coverage: object) -> str | None:
    """coverage 钉过的判决账本字节。旧 coverage 没有这个字段时返回 None。"""
    if not isinstance(coverage, dict):
        return None
    recorded = coverage.get("decisions_sha256")
    return recorded if isinstance(recorded, str) else None


def _inventory_previous_sha256(case_dir: Path, inventory: object) -> str:
    """上一环是已验包 manifest 的当前字节。

    单包就是那份 ``case-package.json``。多包按目录名排序后拼接各文件字节再哈希，
    不是另一套规范 JSON 指纹。缺文件抛 ``OSError``，由命令转成非零退出。
    """
    from apkscan.core.phase2.chain import bytes_sha256, file_sha256

    packages = tuple(getattr(inventory, "packages", ()))
    if not packages:
        raise OSError("清单没有已验包，不能声明上一环")
    ordered = sorted(packages, key=lambda item: str(item.directory_name))
    if len(ordered) == 1:
        return file_sha256(case_dir / ordered[0].directory_name / "case-package.json")
    chunks = [
        (case_dir / item.directory_name / "case-package.json").read_bytes()
        for item in ordered
    ]
    return bytes_sha256(b"".join(chunks))


def _inventory_file_matches(path: Path, case_dir: Path, inventory: object) -> bool:
    """已有清单必须解析成与本次清单相同的对象。半份文件解析失败，不能钉成上一环。"""
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return recorded == _inventory_envelope(case_dir, inventory)


def _inventory_envelope(case_dir: Path, inventory: object) -> dict:
    """落盘清单补上一环。内存 to_dict 不加这个字段。"""
    from apkscan.core.phase2.chain import chain_link

    body = inventory.to_dict()  # type: ignore[attr-defined]
    return chain_link(
        "inventory",
        body,
        previous_sha256=_inventory_previous_sha256(case_dir, inventory),
    )


def _cmd_inventory_phase1(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    text = json.dumps(_inventory_envelope(case_dir, inventory), ensure_ascii=False, indent=1) + "\n"
    if args.out:
        out = Path(args.out)
        if out.exists():
            print(f"拒绝覆盖已有文件：{out}", file=sys.stderr)
            return 2
        out.write_text(text, encoding="utf-8")
        print(f"Phase1 清单 → {out}")
    else:
        print(text, end="")
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    """Phase2 只读分层：把候选全集分层收敛，产 phase2/triage.json 与人读 queue.md。"""
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    # inventory 有阻断（坏包/缺 manifest/超限等）时默认拒绝运行：坏包会污染分层判据，
    # 不可信的 triage 绝不能以退出码 0 写出去、被自动化当成成功。
    if inventory.issues and not args.allow_inventory_issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题，triage 拒绝运行"
              "（坏包会污染判据）。确需诊断产出请加 --allow-inventory-issues。", file=sys.stderr)
        for issue in inventory.issues[:10]:
            print(f"  ✗ {issue.code}: {issue.detail}", file=sys.stderr)
        return 1
    try:
        triage = build_triage(inventory, case_dir)
    except ValueError as exc:  # 覆盖守恒等契约失败即非零退出
        print(f"分层失败：{exc}", file=sys.stderr)
        return 3
    out_dir = case_dir / "phase2"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        from apkscan.core.phase2.chain import chain_link, file_sha256

        inventory_path = out_dir / "inventory.json"
        if inventory_path.exists() and not _inventory_file_matches(inventory_path, case_dir, inventory):
            raise OSError("已有 inventory.json 与本次清单不一致，拒绝把它钉成上一环")
        if not inventory_path.is_file():
            inventory_text = (
                json.dumps(_inventory_envelope(case_dir, inventory), ensure_ascii=False, indent=1)
                + "\n"
            )
            inventory_path.write_text(inventory_text, encoding="utf-8")
        triage_body = chain_link(
            "triage",
            triage.to_dict(),
            previous_sha256=file_sha256(inventory_path),
        )
        triage_json = (
            json.dumps(triage_body, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        )
        queue_md = render_queue_md(triage)
        # 先写临时文件、两个都成功后再 replace，避免第二个写失败留下新旧混合产物。
        tmp_json = out_dir / "triage.json.tmp"
        tmp_md = out_dir / "queue.md.tmp"
        tmp_json.write_text(triage_json, encoding="utf-8")
        tmp_md.write_text(queue_md, encoding="utf-8")
        tmp_json.replace(out_dir / "triage.json")
        tmp_md.replace(out_dir / "queue.md")
    except OSError as exc:
        print(f"写产物失败：{exc}", file=sys.stderr)
        return 4
    t = triage.totals
    print(f"Phase2 triage → {out_dir}")
    print(f"  候选 {t['candidates']} / case-parent {t['parents']} / "
          f"自动 {t['auto']} / 人判 {t['human']}（T1={t['t1']} T2组={t['t2_groups']}）")
    return 0


def _finish_decision(args, case_dir, inventory, parent_members, decision) -> int:
    """decide/decide-member 共用收尾：dry-run 打印，否则原子追加。"""
    # clue 默认路径与 materialize 对齐（复审 P1#4）：不给 --clues 时读 <case>/clue_records.jsonl。
    clue_file = Path(args.clues) if args.clues else case_dir / "clue_records.jsonl"
    try:
        clue_records = load_clue_records(clue_file) if clue_file.exists() else []
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"clue 台账读取失败：{exc}", file=sys.stderr)
        return 2
    known = {str(cid) for c in clue_records if isinstance((cid := c.get("clue_id")), str)}
    if args.dry_run:
        print(json.dumps(decision, ensure_ascii=False, indent=1))
        return 0
    decisions_path = case_dir / "phase2" / "decisions.jsonl"
    try:
        append_decision(
            decisions_path, decision, members_by_parent=parent_members,
            inventory_candidate_ids={c.candidate_id for c in inventory.candidates},
            known_clue_ids=known, case_id=inventory.case_id,
        )
    except DecisionError as exc:
        print(f"判决被拒：{exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"写判决失败：{exc}", file=sys.stderr)
        return 4
    print(f"已记录判决 {decision['decision_id']} → {decisions_path}")
    return 0


def _cmd_decide(args: argparse.Namespace) -> int:
    """记录一条 parent-scope 判决；--show-members 只打印成员不判决。"""
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    triage = build_triage(inventory, case_dir)
    parent_members = {p.parent_id: p.member_candidate_ids for p in triage.parents}
    proposals = {p.parent_id: p for p in triage.parents}
    if args.show_members:
        try:
            rows = show_parent_members(inventory, triage, args.parent)
        except DecisionError as exc:
            print(f"解析失败：{exc}", file=sys.stderr)
            return 2
        for row in rows:
            print(f"  {row['candidate_id']}  pkg={row['package_id']}  "
                  f"evidence={row['evidence_id']}  scope={row['scope']}")
        return 0
    try:
        resolved = resolve_unique_prefix(args.parent, parent_members, label="parent")
    except DecisionError as exc:
        print(f"解析失败：{exc}", file=sys.stderr)
        return 2
    proposal = proposals[resolved]
    decided_by = args.decided_by or os.environ.get("FXAPK_ACTOR", "")
    if not decided_by:
        print("缺少判决人：给 --decided-by 或设 FXAPK_ACTOR", file=sys.stderr)
        return 2
    accepts: list[dict[str, str]] = []
    for spec in args.accept or []:
        cand_prefix, sep, clue = spec.partition("=")
        if not sep or not clue:
            print(f"--accept 格式应为 candidate=clue_id：{spec!r}", file=sys.stderr)
            return 2
        try:
            cand = resolve_unique_prefix(cand_prefix, proposal.member_candidate_ids, label="candidate")
        except DecisionError as exc:
            print(f"解析失败：{exc}", file=sys.stderr)
            return 2
        accepts.append({"candidate_id": cand, "clue_id": clue})
    decision = build_decision(
        case_id=inventory.case_id, decided_by=decided_by, scope="parent",
        parent_id=resolved, candidate_id=None, disposition=args.disposition,
        reason=args.reason, next_action=args.next_action, accepts=accepts, clue_id=None,
        supersedes=args.supersedes or [],
        members_hash_value=members_hash(proposal.member_candidate_ids),
        decided_against={
            "inventory_fingerprint": inventory.fingerprint,
            "triage_bucket": proposal.bucket, "triage_tier": proposal.tier,
            "signals_hash": signals_hash(proposal.signals),
        },
    )
    return _finish_decision(args, case_dir, inventory, parent_members, decision)


def _cmd_decide_member(args: argparse.Namespace) -> int:
    """记录一条 member-scope 例外判决。"""
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    triage = build_triage(inventory, case_dir)
    parent_members = {p.parent_id: p.member_candidate_ids for p in triage.parents}
    cand_to_parent = {cid: p.parent_id for p in triage.parents for cid in p.member_candidate_ids}
    try:
        cand = resolve_unique_prefix(args.candidate, list(cand_to_parent), label="candidate")
    except DecisionError as exc:
        print(f"解析失败：{exc}", file=sys.stderr)
        return 2
    parent_id = cand_to_parent[cand]
    proposal = {p.parent_id: p for p in triage.parents}[parent_id]
    decided_by = args.decided_by or os.environ.get("FXAPK_ACTOR", "")
    if not decided_by:
        print("缺少判决人：给 --decided-by 或设 FXAPK_ACTOR", file=sys.stderr)
        return 2
    decision = build_decision(
        case_id=inventory.case_id, decided_by=decided_by, scope="member",
        parent_id=parent_id, candidate_id=cand, disposition=args.disposition,
        reason=args.reason, next_action=args.next_action, accepts=[], clue_id=args.clue_id,
        supersedes=args.supersedes or [], members_hash_value=members_hash([cand]),
        decided_against={
            "inventory_fingerprint": inventory.fingerprint,
            "triage_bucket": proposal.bucket, "triage_tier": proposal.tier,
            "signals_hash": signals_hash(proposal.signals),
        },
    )
    return _finish_decision(args, case_dir, inventory, parent_members, decision)


def _cmd_materialize(args: argparse.Namespace) -> int:
    """把 decisions + auto 提议物化成 candidate 级 coverage.json。"""
    from collections import Counter
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    triage = build_triage(inventory, case_dir)
    clue_path = Path(args.clues) if args.clues else None
    try:
        result = materialize_case(
            case_dir, inventory=inventory, triage=triage,
            clue_records_path=clue_path, dry_run=args.dry_run,
        )
    except DecisionError as exc:
        print(f"物化失败：{exc}", file=sys.stderr)
        return 3
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"物化 I/O 失败：{exc}", file=sys.stderr)
        return 4
    dist = Counter(e["disposition"] for e in result.coverage["entries"])
    where = "（dry-run 未写盘）" if args.dry_run else f"→ {case_dir / 'phase2' / 'coverage.json'}"
    print(f"物化 {where}")
    print(f"  entries {len(result.coverage['entries'])} / {dict(dist)}")
    if result.report["warning_count"]:
        print(f"  ⚠ stale 判决 {result.report['warning_count']} 条（Phase1 补包后跑 replay）",
              file=sys.stderr)
    return 0


def _cmd_gate(args: argparse.Namespace) -> int:
    """发布门禁：G1-G10 全跑，有 blocker 即非零退出。"""
    case_dir = Path(args.case_dir)
    coverage_path = case_dir / "phase2" / "coverage.json"
    if not coverage_path.is_file():
        print("缺 coverage.json，请先 materialize", file=sys.stderr)
        return 2
    if args.clues and not Path(args.clues).exists():  # 显式指定却不存在 → 材料错误（复审 P2#6）
        print(f"指定的 clue 台账不存在：{args.clues}", file=sys.stderr)
        return 2
    if args.survey and not Path(args.survey).exists():
        print(f"指定的 survey 文件不存在：{args.survey}", file=sys.stderr)
        return 2
    # build_inventory/triage/run_gate 全包进错误边界（复审 P2#6）：坏 inventory 也应转稳定退出码而非 traceback。
    try:
        inventory = build_inventory(case_dir, case_id=args.case_id)
        triage = build_triage(inventory, case_dir)
        parent_members = {p.parent_id: p.member_candidate_ids for p in triage.parents}
        coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
        clue_file = Path(args.clues) if args.clues else case_dir / "clue_records.jsonl"
        clue_records = load_clue_records(clue_file) if clue_file.exists() else []
        known = {str(cid) for c in clue_records if isinstance((cid := c.get("clue_id")), str)}
        decisions_path = case_dir / "phase2" / "decisions.jsonl"
        pinned = _coverage_decisions_sha256(coverage)
        if not decisions_path.is_file():
            raise DecisionError(
                "decisions.jsonl 缺失，不能把已删除的判决账本读成空账本；请重跑 materialize"
            )
        from apkscan.core.phase2.chain import file_sha256

        current_decisions_sha256 = file_sha256(decisions_path)
        if pinned is not None and pinned != current_decisions_sha256:
            raise DecisionError(
                "decisions.jsonl 与 coverage 钉住的字节不一致，不能把另一份账本当成当时物化的账本"
            )
        decisions = load_decisions(
            decisions_path, members_by_parent=parent_members,
            known_clue_ids=known, expected_case_id=inventory.case_id)
        survey_hosts = None
        if args.survey:  # 期3：pcap_survey 端点全集 → G9 包外 established 硬门、G10 声明消失
            survey_hosts = extract_established_hosts(
                json.loads(Path(args.survey).read_text(encoding="utf-8")))
        report = run_gate(inventory, triage, decisions, clue_records, coverage,
                          case_id=inventory.case_id, survey_established_hosts=survey_hosts,
                          allow_pending=args.allow_pending)
    except (OSError, UnicodeError, ValueError, DecisionError) as exc:
        print(f"gate 执行失败：{exc}", file=sys.stderr)
        return 2
    receipt_path = case_dir / "phase2" / "gate-receipt.json"
    try:
        write_gate_receipt(receipt_path, build_gate_receipt(
            inventory, report, coverage_path=coverage_path,
            decisions_path=decisions_path,
            decisions_ledger="present",
        ))
    except OSError as exc:
        print(f"写 gate 回执失败：{exc}", file=sys.stderr)
        return 4
    print(f"Phase2 gate: {'PASS' if report.ok else 'BLOCKED'}")
    print(f"  回执 → {receipt_path}")
    for line in report.declarations:
        print(f"  ℹ {line}")
    for line in report.warnings:
        print(f"  ⚠ {line}")
    for line in report.blockers:
        print(f"  ✗ {line}", file=sys.stderr)
    return 0 if report.ok else 1


def _cmd_decide_batch(args: argparse.Namespace) -> int:
    """T2 组批：对 tier 前缀匹配的 human parent 批量判决（--expect 硬门）。"""
    case_dir = Path(args.case_dir)
    inventory = build_inventory(case_dir, case_id=args.case_id)
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    triage = build_triage(inventory, case_dir)
    decided_by = args.decided_by or os.environ.get("FXAPK_ACTOR", "")
    if not decided_by:
        print("缺少判决人：给 --decided-by 或设 FXAPK_ACTOR", file=sys.stderr)
        return 2
    parent_members = {p.parent_id: p.member_candidate_ids for p in triage.parents}
    known: set[str] = set()
    try:
        existing = load_decisions(
            case_dir / "phase2" / "decisions.jsonl", members_by_parent=parent_members,
            expected_case_id=inventory.case_id)
        decisions = build_batch_decisions(
            triage, tier_prefix=args.tier_prefix, disposition=args.disposition,
            reason=args.reason, decided_by=decided_by, expect=args.expect,
            existing_decisions=existing, skip_decided=args.skip_decided,
            inventory_fingerprint=inventory.fingerprint)
    except DecisionError as exc:
        print(f"组批被拒：{exc}", file=sys.stderr)
        return 3
    if args.dry_run:
        print(f"[dry-run] 将写入 {len(decisions)} 条判决")
        return 0
    decisions_path = case_dir / "phase2" / "decisions.jsonl"
    cand_ids = {c.candidate_id for c in inventory.candidates}
    try:  # 整批原子写入（复审 P2#5），杜绝半批
        append_decisions(decisions_path, decisions, members_by_parent=parent_members,
                         inventory_candidate_ids=cand_ids, known_clue_ids=known,
                         case_id=inventory.case_id)
    except DecisionError as exc:
        print(f"组批写入被拒：{exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"组批写入失败：{exc}", file=sys.stderr)
        return 4
    print(f"已记录 {len(decisions)} 条组批判决 → {decisions_path}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    """诊断 Phase1 补包后判决迁移状态，产 replay_report.json + stale.md。有 blocked_stale → 退 1。"""
    case_dir = Path(args.case_dir)
    if args.clues and not Path(args.clues).exists():
        print(f"指定的 clue 台账不存在：{args.clues}", file=sys.stderr)
        return 2
    out_dir = case_dir / "phase2"
    try:
        inventory = build_inventory(case_dir, case_id=args.case_id)
        triage = build_triage(inventory, case_dir)
        clue_file = Path(args.clues) if args.clues else case_dir / "clue_records.jsonl"
        clue_records = load_clue_records(clue_file) if clue_file.exists() else []
        known = {str(cid) for c in clue_records if isinstance((cid := c.get("clue_id")), str)}
        # ★不传 members_by_parent（复审 P1#1）：replay 要诊断的正是旧 accepts 与新成员集不匹配；
        # 传当前成员集会让 load_decisions 的 accepts 校验提前拒、点名消失无法分类。图/schema 仍由 classify 内 validate 全校验。
        decisions = load_decisions(
            case_dir / "phase2" / "decisions.jsonl",
            known_clue_ids=known, expected_case_id=inventory.case_id)
        report = classify_replay_change(inventory, triage, decisions)
        from apkscan.core.phase2.chain import replay_stale

        by_id = {str(record.get("decision_id")): record for record in decisions}
        payload = {
            "schema_version": "phase2-replay/1.0", "case_id": inventory.case_id,
            "old_fingerprint": report.old_fingerprint, "new_fingerprint": report.new_fingerprint,
            "summary": report.summary,
            "items": [{"decision_id": item.decision_id, "scope": item.scope, "key": item.key,
                       "classification": item.classification, "detail": item.detail,
                       "next_action": item.next_action,
                       "stale": replay_stale(by_id[item.decision_id], inventory.fingerprint)}
                      for item in report.items]}
        lines = ["# Phase2 replay（补包后判决迁移）", "",
                 f"- 旧 inventory fingerprint：`{report.old_fingerprint}`",
                 f"- 新：`{report.new_fingerprint}`", f"- 汇总：{report.summary}", ""]
        for item in report.items:
            lines += [f"## {item.classification}｜{item.scope}:{item.key}",
                      f"- {item.detail}", f"- 下一步：{item.next_action}", ""]
        # 两个产物先写 tmp、都成功后 replace（复审 P2#4）：避免半套报告
        out_dir.mkdir(parents=True, exist_ok=True)
        tmp_json = out_dir / "replay_report.json.tmp"
        tmp_md = out_dir / "stale.md.tmp"
        tmp_json.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tmp_json.replace(out_dir / "replay_report.json")
        tmp_md.replace(out_dir / "stale.md")
    except (OSError, UnicodeError, ValueError, DecisionError) as exc:
        print(f"replay 执行失败：{exc}", file=sys.stderr)
        return 2
    print(f"Phase2 replay：{report.summary}")
    print(f"  → {out_dir / 'replay_report.json'} + stale.md")
    return 1 if report.summary.get("blocked_stale", 0) else 0


def _cmd_decide_file(args: argparse.Namespace) -> int:
    """从 jsonl 批量判决：★只 build 一次 inventory/triage，杜绝逐条 decide 的 296×0.7s 重算（耗时优化）。"""
    case_dir = Path(args.case_dir)
    intents_path = Path(args.intents)
    if not intents_path.exists():
        print(f"判决意图文件不存在：{args.intents}", file=sys.stderr)
        return 2
    if args.clues and not Path(args.clues).exists():
        print(f"指定的 clue 台账不存在：{args.clues}", file=sys.stderr)
        return 2
    decided_by = args.decided_by or os.environ.get("FXAPK_ACTOR", "")
    if not decided_by:
        print("缺少判决人：给 --decided-by 或设 FXAPK_ACTOR", file=sys.stderr)
        return 2
    inventory = build_inventory(case_dir, case_id=args.case_id)
    if inventory.issues:
        print(f"BLOCKED：{len(inventory.issues)} 个 Phase1 包问题", file=sys.stderr)
        return 1
    triage = build_triage(inventory, case_dir)
    # ★解析意图 / 构造判决 / 载 clue 台账全纳入一个 try（复审 P2#2/#6）：坏输入——非对象行、
    #   accepts 非数组、clue 台账坏 JSON 或记录非对象——一律转成退出码 2，绝不漏成 traceback。
    try:
        intents = [json.loads(line) for line in
                   intents_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        decisions = build_decisions_from_intents(
            inventory, triage, intents, case_id=inventory.case_id, decided_by=decided_by)
        clue_records = load_clue_records(Path(args.clues)) if args.clues else []
        known = {str(cid) for c in clue_records if isinstance((cid := c.get("clue_id")), str)}
    except (DecisionError, KeyError, ValueError, TypeError, AttributeError, OSError, UnicodeError) as exc:
        print(f"判决意图/线索台账解析失败：{exc}", file=sys.stderr)
        return 2
    if not decisions:
        print("没有判决意图（文件为空），未改动台账")
        return 0
    parent_members = {p.parent_id: p.member_candidate_ids for p in triage.parents}
    cand_ids = {c.candidate_id for c in inventory.candidates}
    decisions_path = case_dir / "phase2" / "decisions.jsonl"
    if args.dry_run:
        # ★dry-run 走与真写**完全相同**的累积校验（读台账 + 逐条 validate_new_decision +
        #   known-clue），只是不落盘：预检说「可提交」就必须真能提交（复审 P2#3）。
        try:
            append_decisions(decisions_path, decisions,
                             members_by_parent=parent_members, inventory_candidate_ids=cand_ids,
                             known_clue_ids=known, case_id=inventory.case_id, dry_run=True)
        except DecisionError as exc:
            print(f"[dry-run] 校验不通过（真跑会被拒）：{exc}", file=sys.stderr)
            return 3
        except OSError as exc:
            print(f"[dry-run] 读台账失败：{exc}", file=sys.stderr)
            return 4
        print(f"[dry-run] {len(decisions)} 条判决已过完整校验，可提交")
        return 0
    try:
        append_decisions(decisions_path, decisions,
                         members_by_parent=parent_members, inventory_candidate_ids=cand_ids,
                         known_clue_ids=known, case_id=inventory.case_id)
    except DecisionError as exc:
        print(f"批量写入被拒：{exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"批量写入失败：{exc}", file=sys.stderr)
        return 4
    print(f"已批量记录 {len(decisions)} 条判决（1 次 build）→ {decisions_path}")
    return 0


def _cmd_init_coverage(args: argparse.Namespace) -> int:
    inventory = build_inventory(Path(args.case_dir), case_id=args.case_id)
    if inventory.issues:
        print("Phase1 清单有阻断，不能生成审核工作队列：", file=sys.stderr)
        for issue in inventory.issues:
            print(f"  ✗ {issue.code}: {issue.detail}", file=sys.stderr)
        return 1
    out = Path(args.out)
    if out.exists():
        print(f"拒绝覆盖已有覆盖快照：{out}", file=sys.stderr)
        return 2
    payload = build_coverage_skeleton(inventory)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(f"审核工作队列 → {out}（{len(inventory.candidates)} 个候选，全部待处理）")
    print("下一步：逐项改为接受/排除/合并/仅入报告等最终处置，再运行 audit-coverage。")
    return 0


def _run_coverage_audit(args: argparse.Namespace):
    inventory = build_inventory(Path(args.case_dir), case_id=args.case_id)
    try:
        snapshot = load_coverage_snapshot(Path(args.coverage))
        clues = load_clue_records(Path(args.clues))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"覆盖材料无法读取：{exc}", file=sys.stderr)
        return None
    return audit_coverage(inventory, snapshot, clues)


def _print_coverage_audit(audit, *, status_only: bool = False) -> int:
    state = "PASS" if audit.ok else "BLOCKED"
    print(f"Phase2 coverage: {state}")
    print(
        f"  Phase1 候选 {audit.candidate_count} / 已处置 {audit.covered_count} / "
        f"接受线索 {audit.accepted_clue_count}"
    )
    pending = audit.disposition_counts.get("pending_with_action", 0)
    if pending:
        print(f"  待补证/待审核 {pending}")
    if audit.blockers:
        print("BLOCKERS")
        for issue in audit.blockers:
            target = issue.candidate_id or issue.clue_id or "-"
            print(f"  ✗ {issue.code} [{target}] {issue.detail}")
            print(f"    下一步：{issue.next_action}")
    if audit.blockers:
        print(f"NEXT ACTION：先解决 {len(audit.blockers)} 个阻断，再重新审计。")
        return 1
    if pending:
        print("NEXT ACTION：继续处理 pending_with_action；正式发布门禁仍会阻断。")
        if status_only:
            return 1
    elif not status_only:
        print("覆盖结构与线索 provenance 一致；可进入正式 release gate。")
    return 0


def _cmd_audit_coverage(args: argparse.Namespace) -> int:
    audit = _run_coverage_audit(args)
    return 2 if audit is None else _print_coverage_audit(audit)


def _cmd_status(args: argparse.Namespace) -> int:
    """打印 Phase2 覆盖审计的阻断和下一步。

    这是 coverage 审计：Phase1 候选有没有处置。
    :func:`apkscan.core.case_package.project_case_status` 投影的是包完整性、分析、
    闭环、复核四个正交状态，输入是 manifest 或裸报告。两套状态各看各的材料，
    本命令不调用那个投影。
    """
    audit = _run_coverage_audit(args)
    return 2 if audit is None else _print_coverage_audit(audit, status_only=True)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="fxapk phase2", description="Phase2 独立复核：清单→分层→判决→物化→门禁")
    sub = ap.add_subparsers(dest="command", required=True)
    inv = sub.add_parser("inventory-phase1", help="枚举全部 Phase1 审核候选（独立分母）")
    inv.add_argument("--case-dir", required=True)
    inv.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    inv.add_argument("--out", default="", help="可选 JSON 输出；拒绝覆盖已有文件")
    inv.set_defaults(func=_cmd_inventory_phase1)

    tr = sub.add_parser("triage", help="Phase2 只读分层：产 phase2/triage.json 与 queue.md")
    tr.add_argument("--case-dir", required=True)
    tr.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    tr.add_argument("--allow-inventory-issues", action="store_true",
                    help="Phase1 包有阻断问题时仍产出诊断 triage（默认拒绝，坏包会污染判据）")
    tr.set_defaults(func=_cmd_triage)

    de = sub.add_parser("decide", help="记录一条 parent-scope 判决（--show-members 只看成员）")
    de.add_argument("--case-dir", required=True)
    de.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    de.add_argument("--parent", required=True, help="parent_id 或唯一前缀")
    de.add_argument("--disposition", default="", help="6 个 disposition 之一")
    de.add_argument("--reason", default=None)
    de.add_argument("--next-action", default=None)
    de.add_argument("--accept", action="append", default=[], help="candidate前缀=clue_id，可重复")
    de.add_argument("--supersedes", action="append", default=[], help="被更正的 decision_id，可重复")
    de.add_argument("--decided-by", default=None)
    de.add_argument("--clues", default=None, help="clue_records.jsonl 路径")
    de.add_argument("--show-members", action="store_true", help="只打印该 parent 成员，不判决")
    de.add_argument("--dry-run", action="store_true")
    de.set_defaults(func=_cmd_decide)

    dm = sub.add_parser("decide-member", help="记录一条 member-scope 例外判决")
    dm.add_argument("--case-dir", required=True)
    dm.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    dm.add_argument("--candidate", required=True, help="candidate_id 或唯一前缀")
    dm.add_argument("--disposition", required=True)
    dm.add_argument("--reason", default=None)
    dm.add_argument("--next-action", default=None)
    dm.add_argument("--clue-id", default=None)
    dm.add_argument("--supersedes", action="append", default=[])
    dm.add_argument("--decided-by", default=None)
    dm.add_argument("--clues", default=None)
    dm.add_argument("--dry-run", action="store_true")
    dm.set_defaults(func=_cmd_decide_member)

    ma = sub.add_parser("materialize", help="物化 decisions+auto 为 candidate 级 coverage.json")
    ma.add_argument("--case-dir", required=True)
    ma.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    ma.add_argument("--clues", default=None, help="clue_records.jsonl 路径")
    ma.add_argument("--dry-run", action="store_true")
    ma.set_defaults(func=_cmd_materialize)

    ga = sub.add_parser("gate", help="发布门禁 G1-G10（有 blocker 即非零退出）")
    ga.add_argument("--case-dir", required=True)
    ga.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    ga.add_argument("--clues", default=None, help="clue_records.jsonl 路径")
    ga.add_argument("--allow-pending", action="store_true", help="pending>0 降为 warning")
    ga.add_argument("--survey", default=None,
                    help="pcap_survey to_dict JSON：接入 G9 包外 established 硬门（不给则 G10 声明未设防）")
    ga.set_defaults(func=_cmd_gate)

    db = sub.add_parser("decide-batch", help="T2 组批判决（tier 前缀 + --expect 硬门）")
    db.add_argument("--case-dir", required=True)
    db.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    db.add_argument("--tier-prefix", required=True)
    db.add_argument("--disposition", required=True)
    db.add_argument("--reason", required=True)
    db.add_argument("--expect", type=int, required=True)
    db.add_argument("--decided-by", default=None)
    db.add_argument("--skip-decided", action="store_true")
    db.add_argument("--dry-run", action="store_true")
    db.set_defaults(func=_cmd_decide_batch)

    rp = sub.add_parser("replay", help="诊断 Phase1 补包后判决迁移（产 replay_report.json + stale.md）")
    rp.add_argument("--case-dir", required=True)
    rp.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    rp.add_argument("--clues", default=None, help="clue_records.jsonl 路径")
    rp.set_defaults(func=_cmd_replay)

    dfp = sub.add_parser("decide-file", help="从 jsonl 批量判决（一次 build，杜绝逐条重算的耗时）")
    dfp.add_argument("--case-dir", required=True)
    dfp.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    dfp.add_argument("--intents", required=True, help="判决意图 jsonl 路径")
    dfp.add_argument("--clues", default=None, help="clue_records.jsonl 路径")
    dfp.add_argument("--decided-by", default=None)
    dfp.add_argument("--dry-run", action="store_true")
    dfp.set_defaults(func=_cmd_decide_file)

    init = sub.add_parser("init-coverage", help="为全部 Phase1 候选生成待审核工作队列")
    init.add_argument("--case-dir", required=True)
    init.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    init.add_argument("--out", required=True, help="新建 review-coverage.json")
    init.set_defaults(func=_cmd_init_coverage)

    audit = sub.add_parser("audit-coverage", help="核对 Phase1 候选、处置与线索的双向覆盖")
    audit.add_argument("--case-dir", required=True)
    audit.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    audit.add_argument("--coverage", required=True)
    audit.add_argument("--clues", required=True)
    audit.set_defaults(func=_cmd_audit_coverage)

    status = sub.add_parser("status", help="显示第二阶段阻断与下一步（无需配置机器环境变量）")
    status.add_argument("--case-dir", required=True)
    status.add_argument("--case-id", default=None, help="显式 case_id；缺省取 manifest，与之冲突即阻断（绝不取目录名）")
    status.add_argument("--coverage", required=True)
    status.add_argument("--clues", required=True)
    status.set_defaults(func=_cmd_status)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


def _dispatch_phase2(argv: list[str]) -> None:
    """把参数原样交给 argparse。无参数和 ``--help`` 都走它，退出码与旧入口相同。"""
    raise typer.Exit(code=main(argv or ["--help"]))


def _phase2_group_args(ctx: typer.Context) -> list[str]:
    """组级帮助不能留给 typer：嵌套组会把 ``--help`` 当成未知子命令并以 2 退出。"""
    args = list(ctx.args)
    if "--help" in args or "-h" in args:
        return ["--help"]
    return args


class _Phase2Group(TyperGroup):
    """组级 ``--help`` / ``-h`` 在 Click 报未知命令前交给 argparse。"""

    def parse_args(self, ctx, args):  # type: ignore[no-untyped-def]
        if args and args[0] in {"--help", "-h"}:
            _dispatch_phase2(["--help"])
        return super().parse_args(ctx, args)


def build_phase2_typer(*, deprecated_alias: bool) -> typer.Typer:
    """Phase2 子命令组。``fxapk case`` 是正名；``fxapk phase2`` 是一版别名。

    子命令名不是 typer 参数。若把它做成带默认值的参数，typer 会把它暴露成
    ``--command-name``，调用方就能改派到另一个子命令。
    """
    help_text = (
        "Phase2 独立复核：inventory-phase1 / triage / decide / materialize / gate / replay。"
        if not deprecated_alias
        else "已并入 fxapk case 的别名，本版仍可用；下一版删除。参数与退出码不变。"
    )
    group = typer.Typer(
        cls=_Phase2Group,
        add_completion=False,
        help=help_text,
        invoke_without_command=True,
        no_args_is_help=False,
        context_settings={
            "allow_extra_args": True,
            "ignore_unknown_options": True,
            "help_option_names": [],
        },
    )

    @group.callback()
    def _group_callback(ctx: typer.Context) -> None:
        if ctx.invoked_subcommand is not None:
            return
        _dispatch_phase2(_phase2_group_args(ctx))

    def _register(name: str, help_line: str) -> None:
        @group.command(
            name,
            context_settings={
                "allow_extra_args": True,
                "ignore_unknown_options": True,
                "help_option_names": [],
            },
            add_help_option=False,
        )
        def _command(ctx: typer.Context) -> None:
            _dispatch_phase2([name, *list(ctx.args)])

        _command.__doc__ = help_line

    for command_name, command_help in (
        ("inventory-phase1", "枚举全部 Phase1 审核候选（独立分母）。"),
        ("triage", "Phase2 只读分层：产 phase2/triage.json 与 queue.md。"),
        ("decide", "记录一条 parent-scope 判决。"),
        ("decide-member", "记录一条 member-scope 例外判决。"),
        ("materialize", "物化 decisions+auto 为 candidate 级 coverage.json。"),
        ("gate", "发布门禁 G1-G10（有 blocker 即非零退出）。"),
        ("decide-batch", "T2 组批判决（tier 前缀 + --expect 硬门）。"),
        ("replay", "诊断 Phase1 补包后判决迁移。"),
        ("decide-file", "从 jsonl 批量判决。"),
        ("init-coverage", "为全部 Phase1 候选生成待审核工作队列。"),
        ("audit-coverage", "核对 Phase1 候选、处置与线索的双向覆盖。"),
        ("status", "显示第二阶段覆盖审计的阻断和下一步；不是 case status 的四态投影。"),
    ):
        _register(command_name, command_help)
    return group


if __name__ == "__main__":
    raise SystemExit(main())
