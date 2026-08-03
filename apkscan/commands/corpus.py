"""样本库 CLI 子命令（``corpus_app``）：累积 report.json → 查询 / 见过没 / 重建 / 喂 agent。

``corpus_app`` 由 cli.py ``app.add_typer(corpus_app, name="corpus")`` 挂到主 app（add_typer 留 cli.py
以引用主 app、避免本模块反向 import cli 造成循环）。纯逻辑在 core/corpus.py，
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
from apkscan.core.redact import warn_unredacted_agent_output

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


def resolve_corpus(corpus: str) -> Path:
    """定位语料库根目录：--corpus 优先，其次环境变量 FXAPK_CORPUS；皆缺 → 拒跑（exit 2）。

    ★PII 硬防线：解析出的目录若落在 git 工作树内一律拒跑——语料含真实案件数据，必须放库外
    （OneDrive），绝不让它随 ``git add`` 混进公开仓库（本仓库有过 PII 泄入 git 历史的前科）。

    ★**公开**（非下划线）是有意的：凡是往语料库读写的命令都必须走这道门。``fxapk lead`` 的
      恢复凭据同样含真实线索值与核实说明，一开始各写各的解析就等于把这道防线绕过去了——
      共用同一个入口，防线才不会随着新命令增加而漏。
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
    root = resolve_corpus(corpus)
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
    warn_unredacted_agent_output("corpus ls")
    root = resolve_corpus(corpus)
    entries = _corpus.load_manifest(root)
    rows = _corpus.query(
        entries, package_name=package, case_id=case, packer=packer, app_type=app_type
    )
    _print({"count": len(rows), "samples": rows})


#: seen --by 的列表维度取值（非标量 SEEN_FIELDS，走专用列表反查）。
_CONFIG_OBJECT_BY = "config-object"
_SO_SHA256_BY = "so_sha256"
#: 自建构建环境标识。★比 .so 哈希更耐用：同族样本的 .so 名与 sha256 逐份随机化，
#: 而构建路径是编译器写进 __FILE__ 的，改名/重打包/重签名都动不了它。
_BUILD_ENV_BY = "build-env"


@corpus_app.command("seen")
def corpus_seen(
    value: str = typer.Argument(
        ...,
        help="要反查的值（样本哈希 / 包名 / 签名证书摘要 / 配置对象 url|sha256 / .so sha256 / 构建环境标识）。",
    ),
    by: str = typer.Option(
        "sample_sha256", "--by",
        help="按哪个字段查：sample_sha256 | package_name | sign_sha256 | config-object | so_sha256 | build-env。",
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """见过没？按样本哈希 / 包名 / 共享签名证书 / 共享远程配置对象 / 共享 .so 家族指纹 / **自建构建环境** 一击反查库内记录。"""
    warn_unredacted_agent_output("corpus seen")
    root = resolve_corpus(corpus)
    if by == _CONFIG_OBJECT_BY:
        # 远程配置对象是列表维度（一样本可引用多个）：按 url 或 sha256 反查引用它的样本。
        hits = _corpus.find_by_config_object(_corpus.load_manifest(root), value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _SO_SHA256_BY:
        # .so 家族硬指纹是列表维度（一样本多 .so）：按 sha256/name 反查同族样本（A1 家族反查基石）。
        hits = _corpus.find_by_native_lib(_corpus.load_manifest(root), value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _BUILD_ENV_BY:
        # 构建环境标识是列表维度（一样本可含多个自建根）：按标识反查同一构建环境打出的样本。
        # ★它比「共用同一台服务器」耐用（同机不代表同源），但只说明构建环境相同，
        #   定性仍须结合其它独立证据。
        hits = _corpus.find_by_build_env(_corpus.load_manifest(root), value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    # 拼错 --by 不能静默返回 seen=false（那是权威口吻的假阴性，取证致命）——直接拒跑。
    if by not in _corpus.SEEN_FIELDS:
        typer.echo(
            f"错误：--by 不支持的字段 {by!r}"
            f"（支持：{' | '.join(_corpus.SEEN_FIELDS)} | {_CONFIG_OBJECT_BY} "
            f"| {_SO_SHA256_BY} | {_BUILD_ENV_BY}）。",
            err=True,
        )
        raise typer.Exit(code=2)
    hits = _corpus.find_by(_corpus.load_manifest(root), value, by=by)
    _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})


@corpus_app.command("shared-config")
def corpus_shared_config(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """跨样本共享的远程配置对象簇：同一 OSS 对象(url) 或同一配置内容(sha256) 被 ≥2 样本引用——串案强锚。"""
    warn_unredacted_agent_output("corpus shared-config")
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_config_objects(_corpus.load_manifest(root))
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("shared-native")
def corpus_shared_native(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """跨样本共享同一 .so（sha256 逐字节相同）被 ≥2 样本引用——家族串案锚点候选。

    ★不是每个簇都是强锚：加固壳运行时库与第三方 SDK/引擎库逐字节相同，凡用同款组件的
    样本全都共享它，**共享它只说明用了同一个第三方组件、不说明同一开发主体**。这类簇带
    ``weak_anchor=true`` 与 ``weak_anchor_reason``（壳产品名 / third-party-sdk），并排在结果末尾。
    只标注不删除：共享事实仍要看得见，静默丢弃会让人以为压根没这回事。
    """
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_native_libs(_corpus.load_manifest(root))
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("shared-build-env")
def corpus_shared_build_env(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """跨样本共享的**自建构建环境**簇：同一构建标识被 ≥2 个样本使用。

    ★这是几种关联锚里最耐用的一条：文件名与哈希可以逐份不同、域名与服务器随时可换，
    而构建路径是编译器写进 ``__FILE__`` 的，对**已编译产物**做改名、重打包、重签名
    都动不了它。

    ★但它只说明"构建环境相同"，**不足以直接得出同一主体**：重新编译（换机器、
    换 CI 工作区、换项目根目录）就会改写它。相同标识须结合其它独立证据才能定性；
    反向的"标识不同"同理——足以排除同一次构建环境，不足以单独排除同一主体。
    """
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_build_environments(_corpus.load_manifest(root))
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("reindex")
def corpus_reindex(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """扫 reports/ 全量重建 manifest（自愈索引；只从旧 manifest 继承人工 case_id）。"""
    root = resolve_corpus(corpus)
    entries = _corpus.reindex(root)
    _print({"reindexed": len(entries), "corpus": str(root)})


@corpus_app.command("events")
def corpus_events(
    sha256: str = typer.Argument(..., help="样本哈希（sample_sha256，支持库内 nosha- 占位）。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把库内该样本的报告吐成 JSONL 事件流（复用 report_to_events，喂 agent）。多版本取最近入库的一份。

    ★★**本命令不脱敏，原样输出**——与 ``fxapk jsonl`` 共用同一条转换路径，同样不受 ``digest``
      默认脱敏的保护。
    """
    from apkscan.core.jsonl import report_to_events

    warn_unredacted_agent_output("corpus events")

    root = resolve_corpus(corpus)
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


def _vis_brief(vis: dict | None) -> str:
    """可见性指纹的一行人读形态；``None``（该版无求值）显式说出来，不渲染成「无受限」。"""
    if vis is None:
        return "（无求值）"
    blocked = vis.get("blocked_claims") or []
    return f"[{'、'.join(blocked) if blocked else '无'}] 补法建议 {vis.get('next_actions', 0)} 条"


@corpus_app.command("regress")
def corpus_regress_cmd(
    version_from: str = typer.Option(
        "", "--from", help="旧修订版 版本@规则摘要（如 1.1.0@fdd06596）；留空取倒数第二个。"),
    version_to: str = typer.Option(
        "", "--to", help="新修订版；留空取最新一个。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
    changed_only: bool = typer.Option(True, "--changed-only/--all", help="只列有变化的样本。"),
    as_json: bool = typer.Option(False, "--json", help="输出结构化 JSON 而非人读表。"),
) -> None:
    """跨版本回归对比：同一批**真实样本**换版后检出到底变好还是变坏。

    合成基线（tests/synthetic）防的是"改坏"、进 CI；**发现问题**靠真样本——实测六个真缺陷
    没有一个是合成测试发现的。corpus 主键含 (样本, 版本, 规则集)，重跑自动并存多份报告，
    本命令把这批数据用起来，不必每次手写一次性脚本。

    版本坐标是「``tool_version@ruleset前8位``」而非光是版本号：实测库里被重跑过的样本**全部**
    是同版本号、不同规则集，只按版本号切版会把一整轮规则改动的效果量成 0。

    ★只忠实呈现 + 对**方向明确**的变化加注（载入失败↔可分析、加固漏判↔检出、闭环降级、
    建议调证增减），**绝不给"优化/劣化"总评分**——检出变多可能是误报涨了，变少可能是降噪。
    """
    from apkscan.core import regress as _regress

    root = resolve_corpus(corpus)
    entries = _corpus.load_manifest(root)
    versions = _regress.available_versions(entries)
    if len(versions) < 2:
        typer.echo(
            f"错误：库内只有 {len(versions)} 个修订版（{versions}），无法跨版本对比。"
            "请用新版 fxapk 重跑同批样本并 corpus add 后再试。",
            err=True,
        )
        raise typer.Exit(code=2)

    v_from, v_to = versions[-2], versions[-1]
    for spec, label in ((version_from, "--from"), (version_to, "--to")):
        if not spec:
            continue
        resolved, err = _regress.resolve_revision(spec, versions)
        if resolved is None:
            typer.echo(f"错误：{label} {err}", err=True)
            raise typer.Exit(code=2)
        if label == "--from":
            v_from = resolved
        else:
            v_to = resolved

    diffs, summary = _regress.load_and_diff(root, v_from, v_to)

    if as_json:
        payload = {
            "summary": summary,
            "diffs": [
                {
                    "sample_sha256": d.sample_sha256, "package_name": d.package_name,
                    "case_id": d.case_id,
                    "status": [d.status_from, d.status_to],
                    "closure": [d.closure_from, d.closure_to],
                    "is_hardened": [d.hardened_from, d.hardened_to],
                    "counts": [d.counts_from, d.counts_to],
                    "advice": [d.advice_from, d.advice_to],
                    "visibility": [d.visibility_from, d.visibility_to],
                    "findings_added": d.findings_added,
                    "findings_removed": d.findings_removed,
                    "notes": d.notes,
                }
                for d in diffs if (d.changed or not changed_only)
            ],
        }
        typer.echo(_json.dumps(payload, ensure_ascii=False, indent=2))
        return

    s = summary
    typer.echo(f"跨版本回归：{s['version_from_short']} → {s['version_to_short']}")
    typer.echo(
        f"  两版都有的样本 {s['compared']} 个，其中有变化 {s['changed']} 个；"
        f"仅旧版有 {s['only_in_from']}、仅新版有 {s['only_in_to']}"
    )
    for label, key in (("仅旧版有", "only_in_from_samples"), ("仅新版有", "only_in_to_samples")):
        if s[key]:
            typer.echo(f"    {label}（未参与对比）：{', '.join(x[:12] for x in s[key])}")
    typer.echo(
        f"  ★由失败转为可分析 {s['became_analyzable']}；由可分析转为失败 {s['became_unanalyzable']}；"
        f"加固新检出 {s['hardening_newly_detected']}；闭环降级 {s['closure_downgraded']}"
    )
    typer.echo(
        f"  可见性受限解除 {s['visibility_blocked_cleared']}（须人核）；"
        f"新增受限 {s['visibility_blocked_added']}；求值丢失 {s['visibility_assessment_lost']}"
        f"（基于两版都有可见性求值的 {s['visibility_comparable']} 个样本）"
    )
    typer.echo(
        f"  建议调证线索合计 {s['advice_investigate_from']} → {s['advice_investigate_to']}"
        f"（基于两版报告都读得到的 {s['advice_comparable']} 个样本）"
    )
    if s["advice_unreadable"]:
        # 读不到的样本不参与任何线索/闭环结论——不说出来，用户会以为合计覆盖了全部样本。
        typer.echo(
            f"  ⚠ 另有 {s['advice_unreadable']} 个样本至少一版报告读不到，未计入上面的合计"
        )
    if s["findings_added_total"]:
        typer.echo(f"  新增检出（按 id）：{s['findings_added_total']}")
    if s["findings_removed_total"]:
        typer.echo(f"  消失检出（按 id）：{s['findings_removed_total']}")

    shown = [d for d in diffs if (d.changed or not changed_only)]
    hidden = len(diffs) - len(shown)
    tail = f"，另有 {hidden} 个无变化未列出（--all 全列）" if hidden else ""
    typer.echo(f"\n逐样本（{len(shown)} 个{tail}）：")
    for d in shown:
        typer.echo(f"\n  [{d.sample_sha256[:12]}] {d.package_name or '?'}  案={d.case_id or '—'}")
        if d.status_from != d.status_to:
            typer.echo(f"    状态 {d.status_from} → {d.status_to}")
        if d.counts_from != d.counts_to:
            typer.echo(f"    计数 {d.counts_from} → {d.counts_to}")
        if d.advice_from != d.advice_to:
            typer.echo(f"    线索分档 {d.advice_from} → {d.advice_to}")
        if d.hardened_from != d.hardened_to:
            typer.echo(f"    加固判定 {d.hardened_from} → {d.hardened_to}")
        if d.visibility_from != d.visibility_to:
            typer.echo(f"    可见性受限主张 {_vis_brief(d.visibility_from)} → {_vis_brief(d.visibility_to)}")
        if d.findings_added:
            typer.echo(f"    + {', '.join(d.findings_added)}")
        if d.findings_removed:
            typer.echo(f"    - {', '.join(d.findings_removed)}")
        for n in d.notes:
            typer.echo(f"    {n}")
