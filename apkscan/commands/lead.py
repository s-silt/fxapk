"""线索档位的人工恢复 CLI（``lead_app``）：看谁压着、放行、跨重跑重放。

``lead_app`` 由 cli.py ``app.add_typer(lead_app, name="lead")`` 挂到主 app。

**这个命令组解决什么**：抑制是自动的，每次分析都会重新压。人工核实放行之后，只要重跑一次
分析（换版本、补证据——常态），同一条线索又被压回去。于是放行这件事必须留下**跨运行**的
凭据：写进报告自身的 ``meta.manual_restores``（本次报告立即生效），并可选地存进样本库
（按样本哈希索引，重跑出新报告后用 ``replay`` 一次性放回）。

★与核心层的边界：核心层只认 ``report.meta`` 里的墓碑，不知道样本库存在。样本库的读写全在
  本模块——所以核心层可以在没有样本库的环境里照常跑。
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import typer

from apkscan.commands.corpus import ENV_CORPUS, resolve_corpus
from apkscan.core import corpus as _corpus
from apkscan.core import report_io
from apkscan.core.models import Lead, lift_downgrade
from apkscan.core.restore import MANUAL_RESTORES_KEY, record_restore

logger = logging.getLogger(__name__)

lead_app = typer.Typer(
    help="线索档位的人工恢复：查看抑制来源 / 放行 / 跨重跑重放。",
    no_args_is_help=True,
)

#: 样本库里存放恢复凭据的文件名（与 manifest.jsonl 并列）。
RESTORES_NAME = "restores.jsonl"


def _fail(message: str, code: int = 2) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _load_report_payload(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"错误：报告不存在：{path}", 1)
    except (OSError, ValueError) as exc:
        _fail(f"错误：报告读取/解析失败：{exc}", 1)
    if not isinstance(payload, dict):  # type: ignore[possibly-unbound]
        _fail("错误：报告顶层不是对象。", 1)
    return payload  # type: ignore[return-value]


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now().astimezone().isoformat(timespec="seconds")


def restores_path(corpus_dir: str | Path) -> Path:
    """样本库里恢复凭据文件的完整路径。"""
    return Path(corpus_dir) / RESTORES_NAME


def load_restores(corpus_dir: str | Path) -> list[dict]:
    """读 restores.jsonl → 记录列表。文件不存在 → 空列表；坏行跳过并 warning，绝不抛。"""
    path = restores_path(corpus_dir)
    if not path.exists():
        return []
    out: list[dict] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except ValueError:
            logger.warning("恢复凭据第 %d 行不是合法 JSON，跳过", lineno)
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def save_restores(corpus_dir: str | Path, entries: list[dict]) -> None:
    """原子全量重写 restores.jsonl（与 manifest 同策略：要么旧内容完整、要么新内容完整）。"""
    from apkscan.core.atomic import atomic_write_text

    body = "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in entries)
    atomic_write_text(str(restores_path(corpus_dir)), body)


def upsert_restore(entries: list[dict], record: dict) -> list[dict]:
    """按 ``(sample_sha256, category, value, source)`` 去重写入；同键覆盖。

    键里带 ``sample_sha256``：凭据是对**某个样本**的判断，不能跨样本生效——不同样本上的同名
    域名可能来源完全不同，一次放行就放行所有样本是越界。
    """
    def _key(item: dict) -> tuple[str, ...]:
        return tuple(
            str(item.get(k, "")).strip().lower()
            for k in ("sample_sha256", "category", "value", "source")
        )

    key = _key(record)
    out = [e for e in entries if _key(e) != key]
    out.append(record)
    return out


def _match(lead: Lead, value: str, category: str | None) -> bool:
    if category and lead.category.value.lower() != category.strip().lower():
        return False
    return lead.value.strip().lower() == value.strip().lower()


@lead_app.command("show")
def lead_show(
    report: str = typer.Argument(..., help="report.json 路径。"),
    suppressed_only: bool = typer.Option(
        True, "--suppressed-only/--all", help="只列被抑制的线索（默认）。"
    ),
) -> None:
    """列出线索的档位与**抑制来源**：谁压着它、为什么、还能不能撤。"""
    rep = report_io.load_report(Path(report))
    restored_raw = rep.meta.get(MANUAL_RESTORES_KEY)
    restored_n = len(restored_raw) if isinstance(restored_raw, list) else 0
    rows: list[dict[str, Any]] = []
    for lead in rep.leads:
        if suppressed_only and not lead.downgrades:
            continue
        rows.append({
            "category": lead.category.value,
            "value": lead.value,
            "advice": lead.advice,
            "base_advice": lead.base_advice,
            "legacy_effective_advice": lead.legacy_effective_advice,
            # 有锚点才撤得动；两个锚点都没有的（从未被本机制碰过的旧数据）撤销会被拒。
            "revocable": bool(lead.base_advice or lead.legacy_effective_advice),
            "downgrades": dict(lead.downgrades),
        })
    typer.echo(json.dumps(
        {"leads": rows, "manual_restores": restored_n}, ensure_ascii=False, indent=2
    ))


@lead_app.command("restore")
def lead_restore(
    report: str = typer.Argument(..., help="report.json 路径（**原地**改写）。"),
    value: str = typer.Option(..., "--value", help="线索值（大小写不敏感）。"),
    source: str = typer.Option(..., "--source", help="要撤销的抑制来源 id，如 repack_identity。"),
    note: str = typer.Option(..., "--note", help="放行依据，必填——留痕给复核的人看。"),
    category: str = typer.Option("", "--category", help="限定类别（DOMAIN/IP…），默认匹配全部类别。"),
    corpus: str = typer.Option("", "--corpus", help=f"同时把凭据存进样本库（重跑后可 replay）；默认取环境变量 {ENV_CORPUS}。"),
) -> None:
    """撤销一条抑制来源并留下凭据：本报告立即生效，可选同时存进样本库供重跑重放。"""
    # ★corpus 的解析必须赶在**任何**报告改动之前：解析会因「落在 git 工作树内」而 exit 2，
    #   若排在写盘之后，拒跑时报告已经被改写（甚至连带刷新了 HTML）——那不是原子失败，
    #   而是"一半生效"。另：与 replay 同口径地认 FXAPK_CORPUS，否则两个命令行为不一致。
    want_corpus = bool(corpus.strip() or os.environ.get(ENV_CORPUS, "").strip())
    corpus_root = resolve_corpus(corpus) if want_corpus else None

    path = Path(report)
    rep = report_io.load_report(path)
    hits = [ld for ld in rep.leads if _match(ld, value, category or None)]
    if not hits:
        _fail(f"错误：报告里没有值为 {value!r} 的线索（--category={category or '不限'}）。", 1)

    lifted: list[Lead] = []
    refused: list[Lead] = []
    for lead in hits:
        if source not in lead.downgrades:
            continue
        prior = lead.advice
        if lift_downgrade(lead, source):
            lifted.append(lead)
            record_restore(
                rep.meta,
                category=lead.category.value,
                value=lead.value,
                source=source,
                note=note,
                at=_now_iso(),
                prior_advice=prior,
                new_advice=lead.advice,
            )
        else:
            refused.append(lead)

    if not lifted and not refused:
        _fail(f"错误：这些线索上没有 {source!r} 这条抑制来源。可先用 `fxapk lead show` 看有哪些。", 1)
    if refused and not lifted:
        _fail(
            f"错误：{len(refused)} 条无法撤销——两个档位锚点都不可考（第一刀之前的旧报告，"
            f"算不出该恢复到哪一档）。这类只能重新分析一次，让判据链给出结论。",
            1,
        )

    written = report_io.write_report(rep, path, render_existing_html=True)

    stored = 0
    if corpus_root is not None:
        raw = _load_report_payload(path)
        sha, synthetic = _corpus.sample_identity(raw)
        entries = load_restores(corpus_root)
        for lead in lifted:
            entries = upsert_restore(entries, {
                "sample_sha256": sha,
                "sample_sha256_synthetic": synthetic,
                "category": lead.category.value,
                "value": lead.value,
                "source": source,
                "note": note,
                "at": _now_iso(),
            })
            stored += 1
        save_restores(corpus_root, entries)

    typer.echo(json.dumps({
        "lifted": [
            {"category": ld.category.value, "value": ld.value, "advice": ld.advice,
             "remaining_downgrades": sorted(ld.downgrades)}
            for ld in lifted
        ],
        "refused_no_anchor": [ld.value for ld in refused],
        "written": written,
        "stored_in_corpus": stored,
    }, ensure_ascii=False, indent=2))


@lead_app.command("replay")
def lead_replay(
    report: str = typer.Argument(..., help="report.json 路径（**原地**改写）。"),
    corpus: str = typer.Option("", "--corpus", help=f"样本库根目录（读恢复凭据）；默认取环境变量 {ENV_CORPUS}。"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只报会做什么，不写盘。"),
) -> None:
    """把样本库里该样本的历史放行凭据重放到这份新报告上。

    ★重放的是**放行这个动作**，不是当时的档位：逐条走 lift_downgrade 重新算，所以判据链结论
      变了的新报告不会被旧档位覆盖。
    """
    corpus_root = resolve_corpus(corpus)   # 同上：统一走 corpus 的 PII 硬防线
    path = Path(report)
    raw = _load_report_payload(path)
    sha, _synthetic = _corpus.sample_identity(raw)
    entries = [e for e in load_restores(corpus_root)
               if str(e.get("sample_sha256", "")).strip().lower() == sha.lower()]
    if not entries:
        typer.echo(json.dumps(
            {"sample_sha256": sha, "candidates": 0, "lifted": [], "note": "样本库里没有该样本的凭据"},
            ensure_ascii=False, indent=2))
        return

    rep = report_io.load_report(path)
    # ★每条凭据**恰好**产出一条结果，状态显式区分。消费方按工作流是 AI：只给 lifted/skipped
    #   两个列表的话，「凭据对应的线索本轮根本不存在」会落进两个列表之外（candidates>0 却
    #   两列表皆空），而「撤了一条但仍被别的来源压着」与「已完全恢复」在输出上分不开。
    results: list[dict[str, Any]] = []
    changed = 0
    for entry in entries:
        value = str(entry.get("value", ""))
        source = str(entry.get("source", ""))
        category = str(entry.get("category", "")) or None
        note = str(entry.get("note", ""))
        row: dict[str, Any] = {"category": category, "value": value, "source": source}
        matched = [ld for ld in rep.leads if _match(ld, value, category)]
        if not matched:
            row["status"] = "lead_missing"          # 本轮报告里没有这条线索（判据/样本变了）
            results.append(row)
            continue

        # ★一条凭据**恰好**一条结果：同值可能命中多条 lead（凭据没写 category 时跨类别匹配、
        #   报告里存在重复条目）。逐条 append 会让 len(results) > candidates，消费方（AI）
        #   没法把结果与凭据一一对上。故此处逐条处理、最后**聚合**成一条。
        per_lead: list[dict[str, Any]] = []
        for lead in matched:
            one: dict[str, Any] = {"category": lead.category.value, "value": lead.value}
            prior = lead.advice                     # 必须在 lift 之前取：之后 advice 已经变了
            if source not in lead.downgrades:
                one["status"] = "source_absent"     # 本轮没被该来源压着，无需放行
            elif not lift_downgrade(lead, source):
                one["status"] = "no_anchor"         # 两个锚点都不可考，算不出恢复到哪一档
            else:
                record_restore(
                    rep.meta, category=lead.category.value, value=lead.value, source=source,
                    note=note, at=_now_iso(), prior_advice=prior, new_advice=lead.advice,
                )
                changed += 1
                one["remaining_downgrades"] = sorted(lead.downgrades)
                # 撤掉一条 ≠ 档位回升：其余来源还压着时 advice 不动，这两种必须分得开。
                one["status"] = (
                    "lifted_still_suppressed" if lead.downgrades else "lifted_fully_restored"
                )
            one["advice"] = lead.advice
            per_lead.append(one)

        if len(per_lead) == 1:
            row.update(per_lead[0])
        else:
            # 歧义：一条凭据命中多条 lead。不合并成单一状态（那会掩盖其中一条没放行成功），
            # 而是给出显式的歧义状态 + 每条的明细，让消费方知道这条凭据需要人再看一眼。
            row["status"] = "ambiguous_multiple_leads"
            row["matches"] = per_lead
        results.append(row)

    written: list[str] = []
    if changed and not dry_run:
        written = report_io.write_report(rep, path, render_existing_html=True)
    typer.echo(json.dumps({
        "sample_sha256": sha, "candidates": len(entries), "lifted": changed,
        "results": results, "written": written, "dry_run": dry_run,
    }, ensure_ascii=False, indent=2))


__all__ = ["RESTORES_NAME", "lead_app", "load_restores", "restores_path", "save_restores", "upsert_restore"]
