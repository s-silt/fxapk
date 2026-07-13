"""样本库 CLI 子命令（``corpus_app``）：累积 report.json → 查询 / 见过没 / 重建 / 喂 agent。

``corpus_app`` 由 cli.py ``app.add_typer(corpus_app, name="corpus")`` 挂到主 app（add_typer 留 cli.py
以引用主 app、避免本模块反向 import cli 造成循环，沿 graph/track 先例）。纯逻辑在 core/corpus.py，
本层只做 IO / 打印 / 退出码。

★PII 硬防线：语料库含真实案件数据（IOC/案件号），路径**必须**由用户经 --corpus 或环境变量
FXAPK_CORPUS 显式指向库外（OneDrive），二者皆缺即拒跑——绝不默认 ./corpus 免得把案件数据误落进
当前目录 / git 工作树。
"""

from __future__ import annotations

import json as _json
import logging
import os
from pathlib import Path

import typer

from apkscan.core import corpus as _corpus

logger = logging.getLogger(__name__)


corpus_app = typer.Typer(
    add_completion=False,
    help="样本库：累积历次 report.json → 见过没 / 过滤列举 / 自愈重建 / 吐 JSONL 喂 agent。",
)

#: 语料库根目录的环境变量名（未给 --corpus 时的来源）。
ENV_CORPUS = "FXAPK_CORPUS"


def _print(obj: object) -> None:
    """统一打印稳定 JSON（UTF-8、缩进 2）。"""
    typer.echo(_json.dumps(obj, ensure_ascii=False, indent=2))


def _inside_git_worktree(path: Path) -> bool:
    """path 或其任一祖先是否含 .git（即落在某个 git 工作树内）。解析失败保守按"在库内"处理。"""
    try:
        resolved = path.resolve()
    except OSError:
        return True  # 无法解析 → 保守拒跑，不冒 PII 误落 git 的险
    for d in (resolved, *resolved.parents):
        if (d / ".git").exists():
            return True
    return False


def _resolve_corpus(corpus: str) -> Path:
    """定位语料库根目录：--corpus 优先，其次环境变量 FXAPK_CORPUS；皆缺 → 拒跑（exit 2）。

    ★PII 硬防线：解析出的目录若落在 git 工作树内一律拒跑——语料含真实案件数据，必须放库外
    （OneDrive），绝不让它随 ``git add`` 混进公开仓库（本仓库有过 PII 泄入 git 历史的前科）。
    """
    root = (corpus or os.environ.get(ENV_CORPUS, "")).strip()
    if not root:
        typer.echo(
            f"错误：未指定语料库目录。请用 --corpus DIR 或设置环境变量 {ENV_CORPUS}（指向库外/OneDrive）。",
            err=True,
        )
        raise typer.Exit(code=2)
    path = Path(root)
    if _inside_git_worktree(path):
        typer.echo(
            f"错误：语料库目录 {root} 位于 git 工作树内。语料含真实案件数据（IOC/案件号），"
            f"必须放库外（如 OneDrive），绝不入 git。",
            err=True,
        )
        raise typer.Exit(code=2)
    return path


@corpus_app.command("add")
def corpus_add(
    reports: list[Path] = typer.Argument(..., exists=True, help="一个或多个 report.json 文件。"),
    case: str = typer.Option("", "--case", help="案件归属（唯一人工字段；不给则打警告继续）。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把一份/多份 report.json 入库（原样存证 + 登记索引，按样本×版本×规则幂等去重）。"""
    root = _resolve_corpus(corpus)
    if not case:
        typer.echo(
            "警告：未指定 --case，本次入库无案件归属（串案维度将退化为纯样本维度）。", err=True
        )

    added = skipped = failed = 0
    for rp in reports:
        try:
            # read_bytes().decode 而非 read_text：后者会把 CRLF 归一为 LF，破坏原样存证的字节保真。
            raw = rp.read_bytes().decode("utf-8")
            # parse_constant：NaN/Infinity（json 默认接受、但非 RFC-8259 合法）归一化为 None，
            # 否则会随 manifest_entry 的数值字段写进 manifest.jsonl，破坏"每行严格合法 JSON"。
            # 报告原文 raw 仍原样存证、不受影响（见下方 add_report(..., raw, ...)）。
            report = _json.loads(raw, parse_constant=lambda _c: None)
        except (OSError, ValueError, RecursionError) as exc:
            # ValueError 含 JSONDecodeError + UnicodeDecodeError（非 UTF-8 文件）。
            logger.warning("跳过无法读取/解析的报告 %s：%s", rp, exc)
            typer.echo(f"跳过（读取/解析失败）：{rp}", err=True)
            failed += 1
            continue
        if not isinstance(report, dict):
            typer.echo(f"跳过（报告顶层非对象）：{rp}", err=True)
            failed += 1
            continue
        try:
            result = _corpus.add_report(root, report, raw, case_id=case or None)
        except OSError as exc:
            # 写盘失败（如畸形/超长文件名触发 OSError）不得中止整批入库。
            logger.warning("写入失败，跳过 %s：%s", rp, exc)
            typer.echo(f"跳过（写入失败）：{rp}：{exc}", err=True)
            failed += 1
            continue
        if result.get("collision"):
            typer.echo(
                f"跳过（路径碰撞：与已入库不同主键的证据同路径，拒绝覆盖）：{rp}", err=True
            )
            failed += 1
            continue
        if result["synthetic"]:
            typer.echo(
                f"注意：{rp} 缺 sample_sha256（旧报告），按内容派生占位身份 {result['key'][0]}。",
                err=True,
            )
        if result["added"]:
            added += 1
        else:
            skipped += 1

    _print({"added": added, "skipped": skipped, "failed": failed, "corpus": str(root)})


@corpus_app.command("ls")
def corpus_ls(
    package: str = typer.Option("", "--package", help="按包名过滤。"),
    case: str = typer.Option("", "--case", help="按案件过滤。"),
    packer: str = typer.Option("", "--packer", help="按加固厂商过滤。"),
    app_type: str = typer.Option("", "--type", help="按分类过滤（如 fraud）。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """按条件列举库内样本（稳定 JSON）。"""
    root = _resolve_corpus(corpus)
    entries = _corpus.load_manifest(root)
    rows = _corpus.query(
        entries, package_name=package, case_id=case, packer=packer, app_type=app_type
    )
    _print({"count": len(rows), "samples": rows})


@corpus_app.command("seen")
def corpus_seen(
    value: str = typer.Argument(..., help="要反查的值（样本哈希 / 包名 / 签名证书摘要）。"),
    by: str = typer.Option(
        "sample_sha256", "--by", help="按哪个字段查：sample_sha256 | package_name | sign_sha256。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """见过没？按样本哈希 / 包名 / 共享签名证书一击反查库内记录。"""
    root = _resolve_corpus(corpus)
    # 拼错 --by 不能静默返回 seen=false（那是权威口吻的假阴性，取证致命）——直接拒跑。
    if by not in _corpus.SEEN_FIELDS:
        typer.echo(
            f"错误：--by 不支持的字段 {by!r}（支持：{' | '.join(_corpus.SEEN_FIELDS)}）。", err=True
        )
        raise typer.Exit(code=2)
    hits = _corpus.find_by(_corpus.load_manifest(root), value, by=by)
    _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})


@corpus_app.command("reindex")
def corpus_reindex(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """扫 reports/ 全量重建 manifest（自愈索引；只从旧 manifest 继承人工 case_id）。"""
    root = _resolve_corpus(corpus)
    entries = _corpus.reindex(root)
    _print({"reindexed": len(entries), "corpus": str(root)})


@corpus_app.command("events")
def corpus_events(
    sha256: str = typer.Argument(..., help="样本哈希（sample_sha256，支持库内 nosha- 占位）。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把库内该样本的报告吐成 JSONL 事件流（复用 report_to_events，喂 agent）。多版本取最近入库的一份。"""
    from apkscan.core.jsonl import report_to_events

    root = _resolve_corpus(corpus)
    hits = _corpus.find_by(_corpus.load_manifest(root), sha256, by="sample_sha256")
    if not hits:
        typer.echo(f"库内无此样本：{sha256}", err=True)
        raise typer.Exit(code=1)

    # 多版本取**最近入库**的一份：不能用 hits[-1]（reindex 会把 manifest 按报告路径字典序重排，
    # append 序失效），改按报告文件 mtime 取最大——P0 无时间戳设计下 mtime 是唯一 reindex 后仍成立的
    # "入库新旧"载体（入库经 atomic 落盘、reindex 只重写 manifest 不动报告文件）。
    def _mtime(e: dict) -> float:
        try:
            return (root / str(e.get("report_path") or "")).stat().st_mtime
        except OSError:
            return 0.0

    entry = max(hits, key=_mtime) if len(hits) > 1 else hits[0]
    if len(hits) > 1:
        typer.echo(
            f"注意：{sha256} 有 {len(hits)} 个版本，取最近入库的 "
            f"tool_version={entry.get('tool_version')} ruleset_digest={entry.get('ruleset_digest')}。",
            err=True,
        )

    # manifest 是可重建的派生缓存、非路径权威：report_path 缺失/绝对/含 .. 都可能越出语料库根读到
    # 任意文件 → 缺键或越界即拒（可 reindex 自愈），绝不据此读库外文件。
    rel = str(entry.get("report_path") or "")
    report_file = (root / rel).resolve()
    root_resolved = root.resolve()
    if not rel or not report_file.is_relative_to(root_resolved):
        typer.echo(
            f"错误：manifest 的 report_path 缺失或越出语料库根：{rel!r}（可 fxapk corpus reindex 自愈）。",
            err=True,
        )
        raise typer.Exit(code=1)
    try:
        # parse_constant：NaN/Infinity → None，保证吐出的每行事件严格合法 JSON（与 cli.py 的
        # jsonl 命令同一守卫；库内报告原文按 fxapk dump 格式可能含字面 NaN）。
        report = _json.loads(report_file.read_text(encoding="utf-8"), parse_constant=lambda _c: None)
    except (OSError, ValueError, RecursionError) as exc:
        typer.echo(f"错误：读取库内报告失败：{report_file}：{exc}", err=True)
        raise typer.Exit(code=1) from exc

    for event in report_to_events(report):
        typer.echo(_json.dumps(event, ensure_ascii=False))
