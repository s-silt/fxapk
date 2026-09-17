"""批量富化 CLI 子命令（``enrich_app``）：目标清单 → 被动富化 → CSV 回灌 + NDJSON 明细。

``enrich_app`` 由 cli.py ``app.add_typer(enrich_app, name="enrich")`` 挂到主 app（add_typer 留
cli.py 以引用主 app、避免本模块反向 import cli 造成循环）。纯逻辑在 core/batch_enrich.py，
本层只做 IO / 打印 / 退出码。

★配额闸门：``--dry-run``（**默认开**）只静态估算、代码路径上不碰富化调度，必须显式
``--no-dry-run`` 才真发请求。宁可让人多敲一个参数，也不让"手一抖烧掉整天配额"发生。

★本命令只用 ``active=False`` 的富化器，不直接连接目标业务服务；查询会把目标标识提交给第三方
数据源，DNS 查询还可能被解析服务或权威 DNS 观察。
"""

from __future__ import annotations

import csv
import json as _json
import logging
import os
from pathlib import Path
from uuid import uuid4

import typer

from apkscan.core import batch_enrich as _batch
from apkscan.core.models import ANALYSIS_MODE_PASSIVE

logger = logging.getLogger(__name__)


enrich_app = typer.Typer(
    add_completion=False,
    help="批量被动富化：目标清单（每行一个 IP/域名）→ 各源查询 → CSV 回灌 + NDJSON 明细。",
)


def _print(obj: object) -> None:
    """统一打印稳定 JSON（UTF-8、缩进 2）。"""
    typer.echo(_json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False))


def _write_csv(rows: list[dict[str, str]], columns: list[str], path: Path) -> None:
    """原子写 CSV：同目录临时文件写完 → ``os.replace`` 替换。

    编码 utf-8-sig：Excel 默认按本地代码页解，无 BOM 的中文会乱码（同 report/ioc.py）。

    ★为什么必须原子：这份 CSV 是**每轮全量重建**的人工台账快照（不是 append），直接
    ``open(path,"w")`` 一旦在写中途失败（磁盘满 / 进程被杀），上一轮完整的快照就被截成半截，
    而它的重建源（NDJSON 账本）里那些 ``failed`` 记录会在下一轮**重新花配额查**。
    同目录 tmp + ``os.replace`` 保证：要么旧快照完整、要么新快照完整，绝不留半截。
    与 :mod:`apkscan.core.atomic` 同一不变式（此处自持一份是因为要走 csv.DictWriter 的
    文件句柄 + utf-8-sig，不是文本整体写入）。
    """
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            logger.debug("[enrich] 清理 CSV 临时文件失败：%s", tmp, exc_info=True)
        raise


def _note_ledger_limits(summary: dict[str, object], warnings: "tuple[str, ...]") -> None:
    """把账本读取的超限告警放进摘要。

    ★为什么必须出现在摘要里：超限意味着账本没被完整读回，续跑判据不完整、本轮会**重查**
    一部分已完成来源（花配额）。只体现在"怎么又查了一遍"里是看不见的。
    """
    if warnings:
        summary["ledger_limit_warnings"] = list(warnings)


def _rebuild_csv_from_ledger(
    ndjson_path: Path, csv_path: Path, warnings_out: list[str] | None = None
) -> int | None:
    """从 NDJSON 账本全量重建 CSV 快照，返回跳过的坏行数；账本不存在 → ``None``（不建空表）。

    ★为什么"没有待处理目标"也要重建：NDJSON 是 append-only 事件账本，CSV 是它的当前快照。
    两者会失同步——上一轮写 CSV 时磁盘满、或人只拿到 NDJSON 而 CSV 丢了。此时若因
    ``capped`` 为空就直接返回，账本里明明有数据，CSV 却缺失/过期，而重跑又会被续跑逻辑
    判为"都已完成"从而永远不再重建。这一支不发任何请求，纯本地重建，没有配额代价。

    ``warnings_out``：账本读取的超限告警回填口。★重建 CSV 时超限尤其要说：快照会**少**
    那部分目标，而少了的行与"这个目标从没查过"在表里长得一模一样。
    """
    if not ndjson_path.exists():
        return None
    scan = _batch.scan_ledger(ndjson_path)
    if warnings_out is not None:
        warnings_out.extend(scan.limit_warnings)
    _write_csv(
        _batch.records_to_csv_rows(scan.records), _batch.csv_columns(scan.records), csv_path
    )
    return scan.bad_lines


def _append_ndjson(records: list[dict[str, object]], path: Path) -> None:
    """明细按行 append（**不覆盖**）——它同时是续跑账本，覆盖等于把已完成记录丢掉。"""
    with open(path, "ab+") as handle:
        # A killed process may leave a partial final JSON/UTF-8 line. Preserve it
        # as a bad line, but never concatenate the next valid record onto it.
        handle.seek(0, os.SEEK_END)
        if handle.tell():
            handle.seek(-1, os.SEEK_END)
            if handle.read(1) != b"\n":
                handle.write(b"\n")
        for record in records:
            handle.write(
                _json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                ).encode("utf-8")
                + b"\n"
            )


def _has_coverage_gaps(value: object) -> bool:
    if isinstance(value, dict):
        if "coverage_complete" in value and value["coverage_complete"] is not True:
            return True
        if any((key.endswith("_status") and isinstance(item, str) and item.startswith("failed"))
               or ((key == "truncated" or key.endswith("_truncated")) and item is True)
               for key, item in value.items()):
            return True
        return any(_has_coverage_gaps(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_coverage_gaps(item) for item in value)
    return False


@enrich_app.command(name="batch")
def batch(
    targets_file: str = typer.Option(..., "--targets", "-t", help="目标清单文件，每行一个 IP 或域名（# / // 开头为注释）。"),
    out_dir: str = typer.Option(".", "--out", "-o", help="输出目录（写 enrich.csv 与 enrich.ndjson）。"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="默认只估算配额、不发任何请求；确认后加 --no-dry-run 才真跑。"),
    max_targets: int = typer.Option(
        _batch.DEFAULT_MAX_TARGETS,
        "--max-targets",
        min=1,
        max=_batch.MAX_BATCH_TARGETS,
        help="单次运行目标上限；不得超过内置硬顶，因该入口会执行 Shodan 等额度型来源。",
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="续跑：跳过明细 NDJSON 里已完成的目标（默认开）。"),
    stage: str = typer.Option("all", "--stage", help="baseline=免 Key 基础核验；api=按配置补充；all=两类来源。"),
    providers: str = typer.Option("", "--providers", help="可选，逗号分隔的精确源名；显式选择产品源表示已核本次查询范围。"),
    credential_slot: int = typer.Option(0, "--credential-slot", min=0, max=2, help="Quake/DayDayMap 凭据槽：0=首个已配置；1/2=明确选择。不会因限频自动换账户。"),
) -> None:
    """批量富化一份目标清单。

    退出码：0 正常；2 输入/输出不可用（清单缺失、无可用目标、目录不可写）。
    """
    if max_targets > _batch.MAX_BATCH_TARGETS:
        typer.echo(
            f"--max-targets 不得超过批量富化硬顶 {_batch.MAX_BATCH_TARGETS}。",
            err=True,
        )
        raise typer.Exit(2)
    source = Path(targets_file)
    try:
        raw = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        typer.echo(f"读不了目标清单 {targets_file}：{type(exc).__name__}", err=True)
        raise typer.Exit(2)

    targets, skipped = _batch.parse_targets(raw)
    if not targets:
        typer.echo("目标清单里没有可识别的 IP / 域名（每行一个；# 开头为注释）。", err=True)
        raise typer.Exit(2)

    destination = Path(out_dir)
    csv_path = destination / "enrich.csv"
    ndjson_path = destination / "enrich.ndjson"

    from apkscan.core.registry import discover_enrichers

    enrichers = [e for e in discover_enrichers() if getattr(e, "active", False) is False]
    from apkscan.core.enrichment_profiles import configuration_issues, select_enrichers

    try:
        enrichers = select_enrichers(enrichers, stage, providers)
        for enricher in enrichers:
            if enricher.name in {"quake", "daydaymap", "daydaymap_profile"}:
                enricher.credential_slot = credential_slot
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    import os

    config_issues = configuration_issues(enrichers, os.environ)
    completed: dict[str, set[str]] = {}
    ledger_warnings: tuple[str, ...] = ()
    resume_incomplete = False
    resume_complete = True
    resume_bad_lines = 0
    if resume:
        # 只扫一遍账本：同时拿到续跑判据与超限告警（分两次读会白读一遍大文件）。
        scan = _batch.scan_ledger(ndjson_path)
        resume_bad_lines = scan.bad_lines
        completed = _batch.completed_from_records(scan.records)
        ledger_warnings = scan.limit_warnings
        resume_incomplete = scan.resume_incomplete
        resume_complete = scan.resume_complete

    eligible = [
        target
        for target in targets
        if _batch.pending_enrichers(target, enrichers, os.environ)
    ]
    pending = [
        target
        for target in eligible
        if _batch.pending_enrichers(target, enrichers, os.environ, completed)
    ]
    capped = pending[:max_targets]
    over_cap = len(pending) - len(capped)

    # 预算使用完整输入，保留 disabled / already_done / not_applicable 的区别。
    #   ``completed`` 一并传进去，``estimate_budget`` 内部会把已完成的从 ``matched`` 里扣掉，
    #   所以 ``estimated_requests`` 不受影响；差别只在**逐源状态说得对不对**：
    #   若只喂 ``capped``，全部源都已完成时 ``capped`` 为空，于是每个源都被算成
    #   ``not_applicable``——一个只吃 ip 的源、目标就是 IP、上轮刚查成功，却报"不吃这种目标"。
    #   不能预先过滤未配置的目标，否则 disabled 会错报为 not_applicable。
    #   ★被 ``--max-targets`` 截掉的那部分仍如实计入预算行（它们确实还要查），
    #     顶层的 ``over_max_targets`` 单独说明本次只处理前 N 个。
    budget = _batch.estimate_budget(targets, enrichers, os.environ, completed)
    summary: dict[str, object] = {
        "targets_in_list": len(targets),
        "skipped_unparseable": skipped,
        "no_configured_provider_skipped": len(targets) - len(eligible),
        "already_done_skipped": len(eligible) - len(pending),
        "will_process": len(capped),
        "over_max_targets": over_cap,
        "estimated_requests": _batch.budget_total(budget),
        "stage": stage,
        "selected_providers": [e.name for e in enrichers],
        "request_estimate_note": "含已建模辅助调用的请求预算上界；DNS按8次、RIPEstat按5次、VT/OTX按2次、Shodan域名按2次及IP按1次；不是计费次数，其他旧适配器的内部请求仍可能增加。",
        "resume_complete": resume_complete,
        "ledger_bad_lines_skipped": resume_bad_lines,
        "safe_to_execute": resume_complete and not config_issues,
        "configuration_issues": config_issues,
        "budget_reliable": resume_complete,
        "budget": [
            {
                "provider": line.provider,
                "status": line.status,
                "targets": line.targets,
                "request_units_per_target": line.request_units,
                "estimated_requests": line.requests if line.requests is not None else line.targets * line.request_units,
                **({"reason": line.reason} if line.reason else {}),
            }
            for line in budget
        ],
    }
    _note_ledger_limits(summary, ledger_warnings)

    if dry_run:
        # ★这一支**绝不**调 enrich_targets——dry-run 是防误烧配额的闸门，不是提示。
        summary["dry_run"] = True
        if resume_incomplete:
            # dry-run 可以照常报告，但**不许**声称这份预算是可信的：账本没读全，
            # "已完成"集合就是残缺的，估算出的请求数只会偏低（真跑会多花）。
            summary["resume_incomplete"] = True
            summary["note"] = (
                "未发任何请求。★账本未被完整读回（见 ledger_limit_warnings），"
                "本预算不可信、真实请求数会更多；真跑会被拒绝，请先按告警处理账本。"
            )
        else:
            summary["note"] = "未发任何请求。确认预算后加 --no-dry-run 真跑。"
        _print(summary)
        return

    if config_issues:
        summary["error"] = "配置校验未通过，未发送请求；只输出变量名，不回显配置值。"
        _print(summary)
        raise typer.Exit(2)

    if resume_incomplete:
        # ★fail closed：账本没被完整读回 → "哪些已经查过"这个判据是残缺的。
        #   此处若只告警后继续（旧行为），后果不是一次性的：本轮会重查账本里看不见的那批
        #   provider（真金白银的配额），而新记录仍 append 到同一份账本尾部 —— 账本越长、
        #   越早触发上限、每轮重查得越多，形成永久性的重复烧钱循环。
        #   故在**任何网络调用之前**退出；账本一个字节都不追加。
        summary["dry_run"] = False
        summary["resume_incomplete"] = True
        summary["error"] = "账本未被完整读回，已在联网前中止（拒绝重复消耗配额）。"
        summary["recovery"] = [
            f"账本：{ndjson_path}",
            "1) 先备份该文件；",
            "2) 用 --dry-run 查看 ledger_limit_warnings 判断是哪一维超限；",
            "3) 不要直接归档或删除旧记录：这会让其中的完成状态不可见，后续可能重新查询并消耗额度；",
            "4) 安全恢复：离线压缩为新的 enrich.ndjson，"
            "对每个 (target, provider) 保留最新终态记录；",
            "5) 先用 --dry-run 确认 resume_complete=true，再执行真跑；",
            "6) 或加 --no-resume 明确接受「不跳过已完成目标」（会重新查询并重花配额）。",
        ]
        _print(summary)
        raise typer.Exit(2)

    if not capped:
        # ★没有待查目标 ≠ 无事可做：账本在、CSV 缺失或过期时必须重建快照（纯本地、零配额）。
        #   否则续跑逻辑会永久判定"都已完成"，CSV 再也不会被生成。
        summary["dry_run"] = False
        summary["note"] = "没有待处理目标（可能都已在明细账本里）。"
        rebuild_warnings: list[str] = []
        try:
            bad_ledger_lines = _rebuild_csv_from_ledger(
                ndjson_path, csv_path, rebuild_warnings
            )
        except OSError as exc:
            typer.echo(f"重建 CSV 失败：{type(exc).__name__}", err=True)
            raise typer.Exit(2)
        _note_ledger_limits(summary, (*ledger_warnings, *rebuild_warnings))
        if bad_ledger_lines is None:
            summary["csv_rebuilt"] = False
        else:
            summary["csv_rebuilt"] = True
            summary["ledger_bad_lines_skipped"] = bad_ledger_lines
            summary["csv"] = str(csv_path)
            summary["ndjson"] = str(ndjson_path)
        _print(summary)
        return

    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        typer.echo(f"输出目录不可用 {out_dir}：{type(exc).__name__}", err=True)
        raise typer.Exit(2)

    rebuild_warnings = []
    try:
        records = _batch.enrich_targets(
            capped, enrichers, mode=ANALYSIS_MODE_PASSIVE, env=os.environ,
            completed=completed, on_record=lambda record: _append_ndjson([record], ndjson_path),
        )
        # CSV 从账本全量重建（不是只写本轮记录）：账本是 append-only 事件流，CSV 是当前快照。
        bad_ledger_lines = _rebuild_csv_from_ledger(
            ndjson_path, csv_path, rebuild_warnings
        )
    except OSError as exc:
        typer.echo(f"写输出失败：{type(exc).__name__}", err=True)
        raise typer.Exit(2)

    summary["dry_run"] = False
    summary["processed"] = len(records)
    from collections import Counter

    outcomes: dict[str, Counter] = {}
    for record in records:
        for provider, status in record.get("source_status", {}).items():
            outcomes.setdefault(provider, Counter())[status["status"]] += 1
    summary["source_outcomes"] = {p: dict(c) for p, c in sorted(outcomes.items())}
    # DNS 命中仍可能截断或拒收部分记录；不能仅凭 hit 判定覆盖完整。
    summary["completed_with_gaps"] = any(
        any(status in c for status in ("failed", "skipped", "disabled")) for c in outcomes.values()
    ) or any(
        _has_coverage_gaps(data)
        for r in records for data in r.get("enrichment", {}).values()
    )
    summary["ledger_bad_lines_skipped"] = bad_ledger_lines or 0
    _note_ledger_limits(summary, (*ledger_warnings, *rebuild_warnings))
    summary["csv"] = str(csv_path)
    summary["ndjson"] = str(ndjson_path)
    _print(summary)


@enrich_app.command(name="inventory")
def inventory() -> None:
    """零联网盘点已实现来源和凭据配置状态，不输出任何值。"""
    import os
    from apkscan.core.enrichment_profiles import api_inventory
    from apkscan.core.registry import discover_enrichers

    _print(api_inventory(discover_enrichers(), os.environ))
