"""样本库 CLI 子命令（``corpus_app``）：累积 report.json → 查询 / 见过没 / 重建 / 快照回滚 / 喂 agent。

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
from apkscan.core import corpus_catalog as _catalog
from apkscan.core import linkage as _linkage
from apkscan.core import linkage_discovery as _linkage_discovery
from apkscan.core import linkage_evaluation as _linkage_evaluation
from apkscan.core import linkage_labels as _linkage_labels
from apkscan.core import linkage_ml as _linkage_ml
from apkscan.core import linkage_review as _linkage_review
from apkscan.core import linkage_training as _linkage_training
from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.json_contract import (
    parse_finite_json_float as _parse_finite_float,
    reject_nonfinite_json_constant as _reject_json_constant,
)
from apkscan.core.redact import safe_exception_diagnostic, safe_exception_text, warn_unredacted_agent_output

logger = logging.getLogger(__name__)


corpus_app = typer.Typer(
    add_completion=False,
    help="样本库：累积历次 report.json → 见过没 / 过滤列举 / 自愈重建 / 吐 JSONL 喂 agent。",
)

#: 语料库根目录的环境变量名（未给 --corpus 时的来源）。
ENV_CORPUS = "FXAPK_CORPUS"


def _print(obj: object) -> None:
    """统一打印稳定 JSON（UTF-8、缩进 2）。"""
    typer.echo(_json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False))


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


def resolve_corpus(corpus: str, *, safe_errors: bool = False) -> Path:
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
        if safe_errors:
            typer.echo("错误：语料库目录未通过安全位置校验。", err=True)
        else:
            typer.echo(
                f"错误：语料库目录 {root} 位于 git 工作树内。语料含真实案件数据（IOC/案件号），"
                f"必须放库外（如 OneDrive），绝不入 git。",
                err=True,
            )
        raise typer.Exit(code=2)
    return path


def _query_entries(
    root: Path, *, include_quarantined: bool, safe_errors: bool = False
) -> list[dict]:
    try:
        entries = _corpus.load_materialized_manifest(root)
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
    ) as exc:
        # 两个分支共用同一句文案，只在非 safe_errors 时追加**异常类型名**（不含消息），
        # 避免两串各自漂移。
        message = "错误：无法读取或校验语料库索引"
        if not safe_errors:
            message += f"（{safe_exception_text(exc)}）"
        typer.echo(message, err=True)
        raise typer.Exit(code=1) from exc
    return _corpus.visible_entries(entries, include_quarantined=include_quarantined)


@corpus_app.command("add")
def corpus_add(
    reports: list[Path] = typer.Argument(..., exists=True, help="一个或多个 report.json 文件。"),
    case: str = typer.Option("", "--case", help="显式案件关联；同一报告可重复入库绑定多个案件。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把一份/多份 report.json 入库（原样存证 + 登记索引，按样本×版本×规则幂等去重）。"""
    root = resolve_corpus(corpus)
    if not case:
        typer.echo(
            "警告：未指定 --case，本次入库无案件归属（串案维度将退化为纯样本维度）。", err=True
        )

    added = case_bound = skipped = conflicts = failed = 0
    for rp in reports:
        try:
            # read_bytes().decode 而非 read_text：后者会把 CRLF 归一为 LF，破坏原样存证的字节保真。
            raw = rp.read_bytes().decode("utf-8")
            # NaN/Infinity 不是 RFC-8259 JSON；入库必须拒绝，不能归一成 None 后继续存证。
            report = _json.loads(
                raw,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
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
        except (
            OSError,
            TimeoutError,
            ValueError,
            _catalog.CatalogCorruptError,
            _corpus.ManifestCorruptError,
            _corpus.ManifestShrinkError,
        ) as exc:
            # 写盘/锁/catalog 完整性失败不得伪装成幂等跳过，也不应中止整批其余输入。
            logger.warning("写入失败，跳过 %s：%s", rp, safe_exception_diagnostic(exc))
            typer.echo(f"跳过（写入失败）：{rp}：{safe_exception_text(exc)}", err=True)
            failed += 1
            continue
        if result.get("collision"):
            typer.echo(
                f"跳过（路径碰撞：与已入库不同主键的证据同路径，拒绝覆盖）：{rp}", err=True
            )
            failed += 1
            continue
        if result.get("content_conflict"):
            reason = result.get("conflict_reason") or "incoming report bytes differ"
            typer.echo(
                f"跳过（同主键内容冲突，拒绝覆盖或新增案件关联）：{rp}：{reason}",
                err=True,
            )
            conflicts += 1
            failed += 1
            continue
        if result["synthetic"]:
            typer.echo(
                f"注意：{rp} 缺 sample_sha256（旧报告），按内容派生占位身份 {result['key'][0]}。",
                err=True,
            )
        if result["added"]:
            added += 1
        if result.get("case_bound"):
            case_bound += 1
        if not result["added"] and not result.get("case_bound"):
            skipped += 1

    _print(
        {
            "added": added,
            "case_bound": case_bound,
            "skipped": skipped,
            "conflicts": conflicts,
            "failed": failed,
            "corpus": str(root),
        }
    )
    if failed:
        raise typer.Exit(code=1)


@corpus_app.command("ls")
def corpus_ls(
    package: str = typer.Option("", "--package", help="按包名过滤。"),
    case: str = typer.Option("", "--case", help="按案件过滤。"),
    packer: str = typer.Option("", "--packer", help="按加固厂商过滤。"),
    app_type: str = typer.Option("", "--type", help="按分类过滤（如 fraud）。"),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="同时显示已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """按条件列举库内样本（稳定 JSON）。"""
    warn_unredacted_agent_output("corpus ls")
    root = resolve_corpus(corpus)
    entries = _query_entries(root, include_quarantined=include_quarantined)
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
_DOMAIN_BY = "domain"
_CNAME_BY = "cname"


@corpus_app.command("seen")
def corpus_seen(
    value: str = typer.Argument(
        ...,
        help="要反查的值（样本哈希 / 包名 / 签名证书摘要 / 域名 / CNAME边 / 配置对象 / .so / 构建环境）。",
    ),
    by: str = typer.Option(
        "sample_sha256", "--by",
        help="按哪个字段查：sample_sha256 | package_name | sign_sha256 | domain | cname | config-object | so_sha256 | build-env。",
    ),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="同时反查已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """见过没？按样本哈希 / 包名 / 共享签名证书 / 共享远程配置对象 / 共享 .so 家族指纹 / **自建构建环境** 一击反查库内记录。"""
    warn_unredacted_agent_output("corpus seen")
    root = resolve_corpus(corpus)
    entries = _query_entries(root, include_quarantined=include_quarantined)
    if by == _CONFIG_OBJECT_BY:
        # 远程配置对象是列表维度（一样本可引用多个）：按 url 或 sha256 反查引用它的样本。
        hits = _corpus.find_by_config_object(entries, value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _SO_SHA256_BY:
        # .so 家族硬指纹是列表维度（一样本多 .so）：按 sha256/name 反查同族样本（A1 家族反查基石）。
        hits = _corpus.find_by_native_lib(entries, value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _BUILD_ENV_BY:
        # 构建环境标识是列表维度（一样本可含多个自建根）：按标识反查同一构建环境打出的样本。
        # ★它比「共用同一台服务器」耐用（同机不代表同源），但只说明构建环境相同，
        #   定性仍须结合其它独立证据。
        hits = _corpus.find_by_build_env(entries, value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _DOMAIN_BY:
        hits = _corpus.find_by_domain(entries, value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    if by == _CNAME_BY:
        hits = _corpus.find_by_cname(entries, value)
        _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})
        return
    # 拼错 --by 不能静默返回 seen=false（那是权威口吻的假阴性，取证致命）——直接拒跑。
    if by not in _corpus.SEEN_FIELDS:
        typer.echo(
            f"错误：--by 不支持的字段 {by!r}"
            f"（支持：{' | '.join(_corpus.SEEN_FIELDS)} | {_CONFIG_OBJECT_BY} "
            f"| {_SO_SHA256_BY} | {_BUILD_ENV_BY} | {_DOMAIN_BY} | {_CNAME_BY}）。",
            err=True,
        )
        raise typer.Exit(code=2)
    hits = _corpus.find_by(entries, value, by=by)
    _print({"seen": bool(hits), "by": by, "value": value, "count": len(hits), "hits": hits})


@corpus_app.command("shared-config")
def corpus_shared_config(
    include_quarantined: bool = typer.Option(False, "--include-quarantined"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """跨样本共享的远程配置对象簇：同一 OSS 对象(url) 或同一配置内容(sha256) 被 ≥2 样本引用——串案强锚。"""
    warn_unredacted_agent_output("corpus shared-config")
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_config_objects(
        _query_entries(root, include_quarantined=include_quarantined)
    )
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("shared-native")
def corpus_shared_native(
    include_quarantined: bool = typer.Option(False, "--include-quarantined"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """跨样本共享同一 .so（sha256 逐字节相同）被 ≥2 样本引用——家族串案锚点候选。

    ★不是每个簇都是强锚：加固壳运行时库与第三方 SDK/引擎库逐字节相同，凡用同款组件的
    样本全都共享它，**共享它只说明用了同一个第三方组件、不说明同一开发主体**。这类簇带
    ``weak_anchor=true`` 与 ``weak_anchor_reason``（壳产品名 / third-party-sdk），并排在结果末尾。
    只标注不删除：共享事实仍要看得见，静默丢弃会让人以为压根没这回事。
    """
    warn_unredacted_agent_output("corpus shared-native")
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_native_libs(
        _query_entries(root, include_quarantined=include_quarantined)
    )
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("shared-build-env")
def corpus_shared_build_env(
    include_quarantined: bool = typer.Option(False, "--include-quarantined"),
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
    warn_unredacted_agent_output("corpus shared-build-env")
    root = resolve_corpus(corpus)
    clusters = _corpus.shared_build_environments(
        _query_entries(root, include_quarantined=include_quarantined)
    )
    _print({"count": len(clusters), "clusters": clusters})


@corpus_app.command("link-candidates")
def corpus_link_candidates(
    case: str = typer.Option("", "--case", help="只保留至少一侧绑定到该案件的候选。"),
    limit: int = typer.Option(20, "--limit", min=1, help="最多输出多少个样本对候选。"),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="同时使用已隔离的旧版/开发版记录。"
    ),
    model: Path | None = typer.Option(
        None,
        "--model",
        help="工作树外的实验模型 JSON；仅重排规则已召回候选。",
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """按可解释技术锚生成串案候选；分数是复核优先级，不是同主体概率。"""
    # ★纯空白的 --case 是输入错误：静默退化成无过滤会让人把全量结果当成过滤后的结果。
    if case and not case.strip():
        raise typer.BadParameter("不能是纯空白", param_hint="--case")
    warn_unredacted_agent_output("corpus link-candidates")
    root = resolve_corpus(corpus)
    entries = _query_entries(root, include_quarantined=include_quarantined)
    artifact = _load_private_linkage_model(model) if model is not None else None
    result = _linkage.rank_link_candidates(
        entries,
        case_id=case,
        # 模型必须看到规则召回全集后再截最终展示；先截 rules Top-N 会把第 N+1 名永久挡在外面。
        limit=None if artifact is not None else limit,
    )
    if artifact is not None:
        try:
            result = _linkage_ml.rerank_rule_candidates(result, artifact)
        except (_linkage_ml.ArtifactValidationError, _linkage_ml.PairFeatureError) as exc:
            typer.echo(f"错误：实验模型无法应用：{safe_exception_text(exc)}", err=True)
            raise typer.Exit(code=1) from exc
        result["candidates"] = result["candidates"][:limit]
        result["count"] = len(result["candidates"])
    _print(result)


def _load_private_linkage_labels(path: Path) -> _linkage_labels.LinkageLabelSet:
    """Load labels outside a git worktree and map safe failures to CLI exits."""
    if _inside_git_worktree(path):
        typer.echo("错误：标签文件必须位于 git 工作树外，避免私有标签被误提交。", err=True)
        raise typer.Exit(code=2)
    try:
        return _linkage_labels.load_linkage_labels(path)
    except _linkage_labels.LabelValidationError as exc:
        unreadable = isinstance(exc.__cause__, OSError)
        typer.echo(
            "错误：无法读取私有标签文件。"
            if unreadable
            else "错误：私有标签文件未通过严格 schema 校验。",
            err=True,
        )
        code = 1 if unreadable else 2
        raise typer.Exit(code=code) from exc


def _load_private_linkage_model(path: Path) -> _linkage_ml.LinkageModelArtifact:
    """Load a strict aggregate-only challenger artifact outside the worktree."""
    if _inside_git_worktree(path):
        typer.echo("错误：实验模型文件必须位于 git 工作树外，避免被误提交。", err=True)
        raise typer.Exit(code=2)
    try:
        if path.stat().st_size > 1024 * 1024:
            raise _linkage_ml.ArtifactValidationError("artifact exceeds the 1 MiB limit")
        return _linkage_ml.load_linkage_model_artifact_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        typer.echo("错误：无法读取实验模型文件。", err=True)
        raise typer.Exit(code=1) from exc
    except _linkage_ml.ArtifactValidationError as exc:
        typer.echo(f"错误：实验模型文件无效：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc


@corpus_app.command("link-labels-validate")
def corpus_link_labels_validate(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="工作树外的私有 JSONL 标签文件。",
    ),
) -> None:
    """严格校验私有串案标签；只输出聚合计数，不回显任何标签值。"""
    validated = _load_private_linkage_labels(labels)
    try:
        _linkage_labels.build_linkage_ground_truth(validated)
    except _linkage_labels.LabelValidationError as exc:
        typer.echo("错误：私有标签存在语义冲突。", err=True)
        raise typer.Exit(code=2) from exc
    kind_counts = {"family_membership": 0, "pair_judgment": 0}
    for record in validated.records:
        kind = (
            "family_membership"
            if isinstance(record, _linkage_labels.FamilyMembership)
            else "pair_judgment"
        )
        kind_counts[kind] += 1
    _print(
        {
            "schema_version": _linkage_labels.LABEL_SCHEMA_VERSION,
            "valid": True,
            "record_count": validated.record_count,
            "effective_record_count": len(validated.effective_records),
            "kind_counts": kind_counts,
            "status_counts": dict(validated.status_counts),
            "privacy": {
                "aggregate_only": True,
                "contains_raw_identifiers": False,
            },
        }
    )


@corpus_app.command("link-evaluate")
def corpus_link_evaluate(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="工作树外的私有 JSONL 标签文件。",
    ),
    engine: str = typer.Option("rules-v2", "--engine", help="评测引擎；当前仅支持 rules-v2。"),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="评测时同时使用已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """用私有标签离线评测串案候选；stdout 只含聚合指标。"""
    if engine != "rules-v2":
        raise typer.BadParameter("当前仅支持 rules-v2", param_hint="--engine")
    validated = _load_private_linkage_labels(labels)
    root = resolve_corpus(corpus, safe_errors=True)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=True
    )
    try:
        result = _linkage_evaluation.evaluate_linkage_rules(entries, validated)
    except _linkage_labels.LabelValidationError as exc:
        typer.echo(f"错误：标签真值冲突：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    except _linkage_evaluation.LinkageEvaluationError as exc:
        typer.echo(f"错误：串案评测失败：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=1) from exc
    result["input_options"] = {
        "engine": engine,
        "include_quarantined": include_quarantined,
    }
    _print(result)


@corpus_app.command("link-discover")
def corpus_link_discover(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="工作树外的私有 JSONL 标签文件。",
    ),
    evidence_values: str = typer.Option(
        "omit",
        "--evidence-values",
        help="证据值输出：omit（默认，仅聚合）| raw（原始家族标识和锚值）。",
    ),
    min_member_count: int = typer.Option(
        2, "--min-member-count", min=2, help="候选锚至少覆盖的组内样本数。"
    ),
    min_member_fraction: float = typer.Option(
        0.25,
        "--min-member-fraction",
        min=0.0,
        max=1.0,
        help="候选锚至少覆盖的组内样本比例（0, 1]。",
    ),
    limit: int = typer.Option(200, "--limit", min=1, help="最多输出多少个候选锚。"),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="发现时同时使用已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """从已确认关系组中发现重复技术锚；只供人工复核，不自动改规则或并案。"""
    if evidence_values not in {"omit", "raw"}:
        raise typer.BadParameter("仅支持 omit 或 raw", param_hint="--evidence-values")
    if min_member_fraction <= 0.0:
        raise typer.BadParameter("必须在 (0, 1] 范围内", param_hint="--min-member-fraction")
    if evidence_values == "raw":
        warn_unredacted_agent_output(
            "corpus link-discover --evidence-values raw",
            safe_alternative="fxapk corpus link-discover --evidence-values omit ...",
        )
    validated = _load_private_linkage_labels(labels)
    safe_errors = evidence_values == "omit"
    root = resolve_corpus(corpus, safe_errors=safe_errors)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=safe_errors
    )
    try:
        result = _linkage_discovery.discover_linkage_anchors(
            entries,
            validated,
            min_member_count=min_member_count,
            min_member_fraction=min_member_fraction,
            evidence_values=evidence_values,
            limit=limit,
        )
    except _linkage_labels.LabelValidationError as exc:
        typer.echo("错误：私有标签存在语义冲突。", err=True)
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        typer.echo(f"错误：串案锚发现参数无效：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    result["input_options"] = {
        "include_quarantined": include_quarantined,
        "evidence_values": evidence_values,
    }
    _print(result)


def _validate_evidence_values(value: str) -> None:
    if value not in {"omit", "raw"}:
        raise typer.BadParameter("仅支持 omit 或 raw", param_hint="--evidence-values")


@corpus_app.command("link-explain")
def corpus_link_explain(
    left_sha256: str = typer.Argument(..., help="候选左侧真实 APK SHA-256。"),
    right_sha256: str = typer.Argument(..., help="候选右侧真实 APK SHA-256。"),
    evidence_values: str = typer.Option(
        "omit",
        "--evidence-values",
        help="证据值输出：omit（默认，第三方复核视图）| raw（原始证据）。",
    ),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="解释时同时使用已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """解释一个规则候选的支持、排除、覆盖缺口和 caps；默认不输出原始标识符。"""
    _validate_evidence_values(evidence_values)
    if evidence_values == "raw":
        warn_unredacted_agent_output(
            "corpus link-explain --evidence-values raw",
            safe_alternative="fxapk corpus link-explain --evidence-values omit ...",
        )
    safe_errors = evidence_values == "omit"
    root = resolve_corpus(corpus, safe_errors=safe_errors)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=safe_errors
    )
    try:
        result = _linkage_review.explain_link_candidate(
            entries,
            left_sha256,
            right_sha256,
            evidence_values=evidence_values,
        )
    except _linkage_review.LinkageReviewError as exc:
        typer.echo(f"错误：候选解释失败：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    result["input_options"] = {"include_quarantined": include_quarantined}
    _print(result)


@corpus_app.command("link-groups")
def corpus_link_groups(
    min_score: float = typer.Option(
        50.0,
        "--min-score",
        min=0.0,
        max=100.0,
        help="进入复核关系图的最低规则复核优先级。",
    ),
    evidence_values: str = typer.Option(
        "omit",
        "--evidence-values",
        help="证据值输出：omit（默认，第三方复核视图）| raw（原始证据）。",
    ),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="分组时同时使用已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """按真实候选边生成 review_groups；传递相连不会被伪造成直接关联。"""
    _validate_evidence_values(evidence_values)
    if evidence_values == "raw":
        warn_unredacted_agent_output(
            "corpus link-groups --evidence-values raw",
            safe_alternative="fxapk corpus link-groups --evidence-values omit ...",
        )
    safe_errors = evidence_values == "omit"
    root = resolve_corpus(corpus, safe_errors=safe_errors)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=safe_errors
    )
    try:
        result = _linkage_review.build_review_groups(
            entries,
            min_score=min_score,
            evidence_values=evidence_values,
        )
    except _linkage_review.LinkageReviewError as exc:
        typer.echo(f"错误：复核关系图生成失败：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    result["input_options"] = {"include_quarantined": include_quarantined}
    _print(result)


@corpus_app.command("link-readiness")
def corpus_link_readiness(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="工作树外的私有 JSONL 标签文件。",
    ),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="检查时同时使用已隔离的旧版/开发版记录。"
    ),
    test_fraction: float = typer.Option(
        0.2,
        "--test-fraction",
        min=0.0,
        max=1.0,
        help="按完整关系组切出的测试比例（0, 1）。",
    ),
    seed: int = typer.Option(0, "--seed", help="确定性分组种子。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """检查两档门槛：生产训练档（顶层，原样 fail-closed）与 rules-v2 封顶回归档（只 gate 规则封顶声明）。"""
    if not 0.0 < test_fraction < 1.0:
        raise typer.BadParameter("必须在 (0, 1) 范围内", param_hint="--test-fraction")
    if not 0 <= seed <= 2**32 - 1:
        raise typer.BadParameter("必须在 0..2**32-1 范围内", param_hint="--seed")
    validated = _load_private_linkage_labels(labels)
    root = resolve_corpus(corpus, safe_errors=True)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=True
    )
    try:
        result = _linkage_training.assess_training_readiness(
            entries,
            validated,
            test_fraction=test_fraction,
            seed=seed,
        )
        # ★拆档不动生产档：顶层 status/reason 仍只描述生产训练门槛。回归档是平行的一档，
        #   挂在独立键下、自带 disclaimer 与 model_training.unlocked_by_this_tier=false——
        #   它 ready 与否对 link-train 没有任何影响（训练侧只认生产门槛 + 政策下限）。
        result["rules_cap_regression"] = (
            _linkage_evaluation.assess_rules_regression_readiness(entries, validated)
        )
    except _linkage_labels.LabelValidationError as exc:
        typer.echo("错误：私有标签存在语义冲突。", err=True)
        raise typer.Exit(code=2) from exc
    except (
        _linkage_training.TrainingDataError,
        _linkage_ml.PairFeatureError,
        _linkage_evaluation.LinkageEvaluationError,
    ) as exc:
        typer.echo(f"错误：训练就绪检查失败：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=1) from exc
    result["experimental"] = True
    result["privacy"] = {
        "aggregate_only": True,
        "contains_raw_identifiers": False,
    }
    result["input_options"] = {
        "include_quarantined": include_quarantined,
        "test_fraction": test_fraction,
        "seed": seed,
    }
    _print(result)


@corpus_app.command("link-train")
def corpus_link_train(
    labels: Path = typer.Option(
        ...,
        "--labels",
        help="工作树外的私有 JSONL 标签文件。",
    ),
    model_out: Path = typer.Option(
        ...,
        "--model-out",
        help="工作树外的新模型 JSON；已存在时拒绝覆盖。",
    ),
    test_fraction: float = typer.Option(
        0.2,
        "--test-fraction",
        min=0.0,
        max=1.0,
        help="按完整关系组切出的测试比例（0, 1）。",
    ),
    seed: int = typer.Option(0, "--seed", help="确定性分组种子。"),
    include_quarantined: bool = typer.Option(
        False, "--include-quarantined", help="训练时同时使用已隔离的旧版/开发版记录。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """在默认数据门槛和组隔离门通过后训练实验 challenger；当前数据不足会明确阻断。"""
    if _inside_git_worktree(model_out):
        typer.echo("错误：实验模型输出必须位于 git 工作树外，避免被误提交。", err=True)
        raise typer.Exit(code=2)
    if not 0.0 < test_fraction < 1.0:
        raise typer.BadParameter("必须在 (0, 1) 范围内", param_hint="--test-fraction")
    if not 0 <= seed <= 2**32 - 1:
        raise typer.BadParameter("必须在 0..2**32-1 范围内", param_hint="--seed")
    validated = _load_private_linkage_labels(labels)
    root = resolve_corpus(corpus, safe_errors=True)
    entries = _query_entries(
        root, include_quarantined=include_quarantined, safe_errors=True
    )
    try:
        result = _linkage_training.train_linkage_challenger(
            entries,
            validated,
            test_fraction=test_fraction,
            seed=seed,
        )
    except _linkage_labels.LabelValidationError as exc:
        typer.echo("错误：私有标签存在语义冲突。", err=True)
        raise typer.Exit(code=2) from exc
    except (
        _linkage_training.TrainingDataError,
        _linkage_ml.ArtifactValidationError,
        _linkage_ml.PairFeatureError,
        ValueError,
    ) as exc:
        typer.echo(f"错误：实验模型训练失败：{safe_exception_text(exc)}", err=True)
        raise typer.Exit(code=1) from exc

    artifact = result.pop("artifact", None)
    result["privacy"] = {
        "aggregate_only": True,
        "contains_raw_identifiers": False,
    }
    result["input_options"] = {
        "include_quarantined": include_quarantined,
        "test_fraction": test_fraction,
        "seed": seed,
    }
    if result.get("status") != "trained":
        result["artifact_written"] = False
        _print(result)
        return
    if not isinstance(artifact, dict):
        typer.echo("错误：训练器未返回有效模型产物。", err=True)
        raise typer.Exit(code=1)
    try:
        artifact_bytes = (
            _json.dumps(
                artifact,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        if not atomic_create_bytes(model_out, artifact_bytes):
            typer.echo("错误：模型输出文件已存在，拒绝覆盖。", err=True)
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        typer.echo("错误：无法原子写入实验模型。", err=True)
        raise typer.Exit(code=1) from exc
    result["artifact_written"] = True
    result["model"] = {
        "model_id": artifact.get("model_id"),
        "feature_schema_version": artifact.get("feature_schema_version"),
        "rule_engine": artifact.get("rule_engine"),
        "artifact_digest": artifact.get("artifact_digest"),
        "score_semantics": artifact.get("score_semantics"),
    }
    _print(result)


@corpus_app.command("reindex")
def corpus_reindex(
    allow_shrink: bool = typer.Option(
        False, "--allow-shrink",
        help="允许重建条数少于现有 manifest（仅当报告文件确已删除时用；默认拒绝，防 OneDrive "
             "占位符/读失败把样本静默丢出索引）。",
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """扫 reports/ 全量重建 manifest（案件关联/隔离状态从独立 catalog 恢复）。

    ★重建条数**变少**默认拒绝：报告读不出来（OneDrive 未按需下载/同步中断）时 reindex 会把
    这些样本静默丢出索引。确认报告文件是**有意删除**
    后才加 ``--allow-shrink``。
    """
    root = resolve_corpus(corpus)
    try:
        entries = _corpus.reindex(root, allow_shrink=allow_shrink)
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
        _corpus.ManifestShrinkError,
    ) as exc:
        typer.echo(f"错误：重建索引失败：{root}（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=1) from exc
    _print({"reindexed": len(entries), "corpus": str(root)})


@corpus_app.command("reconcile")
def corpus_reconcile(
    inventory: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Phase-1 case-package.json，或显式 inventory JSONL（每行 case_id + report_path）。",
    ),
    apply: bool = typer.Option(
        False,
        "--apply/--dry-run",
        help="默认只对账；显式 --apply 才新增报告或案件绑定，绝不覆盖/删除。",
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """校验并对账 Phase-1 package/inventory；不从目录名或列表位置推断案件。"""
    root = resolve_corpus(corpus)
    try:
        result = _corpus.reconcile_inventory(root, inventory, apply=apply)
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
    ) as exc:
        typer.echo(f"错误：对账失败：{root}（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=1) from exc
    _print(result)
    counts = result.get("counts")
    if isinstance(counts, dict):
        rejected = int(counts.get("invalid_report") or 0) + int(
            counts.get("content_conflict") or 0
        )
        if apply:
            rejected += int(counts.get("quarantined") or 0)
            rejected += int(counts.get("missing_record") or 0)
            rejected += int(counts.get("case_unbound") or 0)
        if rejected:
            typer.echo(f"错误：corpus reconcile 有 {rejected} 项未被安全接收。", err=True)
            raise typer.Exit(code=1)


@corpus_app.command("versions")
def corpus_versions(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """只读审计库内工具版本与 active/quarantined 分档，不自动隔离。"""
    root = resolve_corpus(corpus)
    entries = _query_entries(root, include_quarantined=True)
    versions = _corpus.audit_versions(entries)
    _print(
        {
            "count": len(versions),
            "version_state_basis": "highest_stable_release_in_corpus",
            "current_releases": [
                version
                for version, row in versions.items()
                if row.get("version_state") == "current_release"
            ],
            "versions": versions,
        }
    )


@corpus_app.command("quarantine-version")
def corpus_quarantine_version(
    tool_versions: list[str] = typer.Argument(..., help="要隔离的精确 tool_version，可给多个。"),
    reason: str = typer.Option(..., "--reason", help="隔离原因（必填，写入 catalog）。"),
    apply: bool = typer.Option(False, "--apply/--dry-run", help="默认只预览；--apply 才写 catalog。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """显式隔离旧版/开发版记录；不删除报告，普通查询默认不再使用。"""
    root = resolve_corpus(corpus)
    try:
        result = _catalog.quarantine_tool_versions(
            root, tool_versions, reason=reason, apply=apply
        )
    except ValueError as exc:
        typer.echo(f"错误：隔离参数无效（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=2) from exc
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
    ) as exc:
        typer.echo(f"错误：按工具版本隔离失败：{root}（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=1) from exc
    _print(result)


#: catalog 迁移的**可逆性**边界声明。与 :data:`_BACKFILL_BOUNDARY` 同一条纪律：写进 dry-run 与
#: 真写两处输出，不许只在文档里活着——决定要不要 ``--apply`` 的人，必须在同一屏看到它撤不回来。
#:
#: ★实测（2026-08-12，在语料库副本上演练）：迁移后跑 ``corpus restore <迁移前快照> --apply``，
#: 命令照常回 ``applied: true`` 与 ``restored_entries``、**看起来成功了**；但 catalog 才是案件
#: 绑定的真源、manifest 只是可重建的派生索引，恢复出来的旧 manifest 会被 catalog 立刻重新物化回
#: 迁移后的形态。而手工删掉 ``catalog.jsonl`` 想补全回滚，会让整库 fail-closed（manifest 残留
#: catalog-era 事实、对应主键却没了），``ls`` / ``verify`` 全部拒绝执行。两条路都不通，只剩目录级还原。
_CATALOG_MIGRATION_IRREVERSIBLE = (
    "★本操作不可用 corpus restore 撤销：catalog 是案件绑定真源、manifest 只是派生索引，"
    "恢复旧 manifest 快照会被 catalog 重新物化；删掉 catalog.jsonl 则整库拒绝读写。"
    "唯一有效的回滚是对语料库做**整目录备份**——请在 --apply 之前完成"
)


@corpus_app.command("migrate-catalog")
def corpus_migrate_catalog(
    apply: bool = typer.Option(False, "--apply/--dry-run", help="默认只预览 legacy case_id 迁移。"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把旧 manifest.case_id 安全迁入 catalog.case_ids；不改库内报告。

    ★不可逆：``corpus restore`` 撤不掉它，只有整目录备份能回滚（见
    :data:`_CATALOG_MIGRATION_IRREVERSIBLE`）。
    """
    root = resolve_corpus(corpus)
    try:
        result = _catalog.migrate_legacy_case_ids(root, apply=apply)
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
    ) as exc:
        typer.echo(f"错误：目录迁移失败：{root}（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=1) from exc
    _print({**result, "reversibility": _CATALOG_MIGRATION_IRREVERSIBLE})


#: 补录哈希的证据边界声明。写进每一处补录相关输出（dry-run 与真写），不许只在文档里活着：
#: 读输出的人（含后续接手的 AI）必须在拿到哈希的同一屏看到它证明不了什么。
_BACKFILL_BOUNDARY = (
    "补录哈希只证明「从补录这一刻起」文件未被改动，不能追溯证明补录之前没被改过"
    "（manifest 里恒带 origin=backfill，与入库哈希 origin=ingest 严格分开）"
)


def _verify_or_exit(root: Path) -> dict:
    try:
        return _corpus.verify_reports(root)
    except (
        OSError,
        TimeoutError,
        _catalog.CatalogCorruptError,
        _corpus.ManifestCorruptError,
    ) as exc:
        corruption_key = (
            "catalog_corrupt"
            if isinstance(exc, _catalog.CatalogCorruptError)
            else "manifest_corrupt"
            if isinstance(exc, _corpus.ManifestCorruptError)
            else "integrity_read_failed"
        )
        _print(
            {
                "counts": {
                    _corpus.VERIFY_OK: 0,
                    _corpus.VERIFY_MISMATCH: 0,
                    _corpus.VERIFY_UNVERIFIABLE: 0,
                    _corpus.VERIFY_MISSING: 0,
                    _corpus.VERIFY_ORPHAN: 0,
                    corruption_key: 1,
                },
                "error": safe_exception_text(exc),
            }
        )
        typer.echo(f"错误：语料库校验失败：{root}（{safe_exception_text(exc)}）", err=True)
        raise typer.Exit(code=1) from exc


@corpus_app.command("verify")
def corpus_verify(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """逐条校验存证未被篡改：文件在吗？当前字节哈希与 manifest 入库记录一致吗？（只读命令）

    分档严格分开（★「没法验」不等于「验过没问题」）：

      ok（有哈希且相符）/ mismatch（有哈希但对不上 = 文件被改过，报警）/
      unverifiable（存量记录无哈希，没法验）/ missing（有记录、文件取不到）/
      orphan（reports/ 有文件、manifest 无记录）。

    退出码：mismatch 或 missing > 0 → 1（存证出了要人处理的事）；仅 unverifiable / orphan
    → 0，但往 stderr 醒目提示还有多少条没法验。
    """
    root = resolve_corpus(corpus)
    res = _verify_or_exit(root)
    counts = res["counts"]
    # ok 行不逐条列（没有待办动作，逐条列只会淹没要人看的行）；其余四类给足坐标。
    _print({
        "counts": counts,
        "ok_by_origin": res["ok_by_origin"],
        "mismatch": [r for r in res["entries"] if r["status"] == _corpus.VERIFY_MISMATCH],
        "missing": [r for r in res["entries"] if r["status"] == _corpus.VERIFY_MISSING],
        "unverifiable": [
            {"sample_sha256": r["sample_sha256"], "report_path": r["report_path"]}
            for r in res["entries"] if r["status"] == _corpus.VERIFY_UNVERIFIABLE
        ],
        "orphans": res["orphans"],
    })
    if counts[_corpus.VERIFY_MISMATCH]:
        typer.echo(
            f"警告：{counts[_corpus.VERIFY_MISMATCH]} 条存证与记录的内容哈希不符——文件在库内被"
            "改过。先别写库（reindex 会按被改后的内容重算索引），去 .snapshots/ 与备份比对定位改动。",
            err=True,
        )
    if counts[_corpus.VERIFY_MISSING]:
        typer.echo(
            f"警告：{counts[_corpus.VERIFY_MISSING]} 条记录的报告文件取不到"
            "（被删/路径越界/OneDrive 未按需下载）。",
            err=True,
        )
    if counts[_corpus.VERIFY_UNVERIFIABLE]:
        typer.echo(
            f"注意：{counts[_corpus.VERIFY_UNVERIFIABLE]} 条存量记录没有内容哈希，本次没法验"
            f"（≠ 验过没问题）。可 fxapk corpus backfill-hash 补录；{_BACKFILL_BOUNDARY}。",
            err=True,
        )
    if counts[_corpus.VERIFY_ORPHAN]:
        typer.echo(
            f"注意：reports/ 下有 {counts[_corpus.VERIFY_ORPHAN]} 个 manifest 之外的报告文件"
            "（orphan）——绕库写入的产物或索引丢条，请核查来历（确认合法后 corpus reindex 可纳入索引）。",
            err=True,
        )
    if counts[_corpus.VERIFY_MISMATCH] or counts[_corpus.VERIFY_MISSING]:
        raise typer.Exit(code=1)


@corpus_app.command("backfill-hash")
def corpus_backfill_hash(
    apply: bool = typer.Option(
        False, "--apply", help="真写入。默认 dry-run：只列出将补录哪些记录，不动磁盘。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """给没有内容哈希的存量记录补录报告文件哈希（默认 dry-run，--apply 才写）。

    ★证据边界：补录按文件**当前**内容计算，只证明「从补录这一刻起」未被改动，**不能**追溯
    证明补录之前没被改过——若文件此前已被篡改，补录会把篡改后的内容钉成基准。因此补录哈希
    恒带 ``origin=backfill``，在 manifest 与 verify 输出里与入库哈希（ingest）严格分开；
    已有哈希的记录绝不重算覆盖。真写前自动给 manifest 拍快照。
    """
    root = resolve_corpus(corpus)
    if not apply:
        res = _verify_or_exit(root)
        todo = [
            {"sample_sha256": r["sample_sha256"], "report_path": r["report_path"]}
            for r in res["entries"] if r["status"] == _corpus.VERIFY_UNVERIFIABLE
        ]
        _print({
            "dry_run": True,
            "would_backfill": len(todo),
            "targets": todo,
            "evidence_boundary": _BACKFILL_BOUNDARY,
            "hint": "加 --apply 才真写；真写前会自动给 manifest 拍快照。",
        })
        return
    result = _corpus.backfill_report_hashes(root)
    if result.get("error"):
        typer.echo(f"错误：{result['error']}", err=True)
        raise typer.Exit(code=1)
    _print({
        "backfilled": result["backfilled"],
        "already_hashed": result["already_hashed"],
        "unreadable": result["unreadable"],
        "total": result["total"],
        "evidence_boundary": _BACKFILL_BOUNDARY,
    })
    if result["unreadable"]:
        typer.echo(
            f"注意：{len(result['unreadable'])} 条记录的文件取不到，未补录（verify 中仍为"
            " missing/unverifiable）。",
            err=True,
        )


@corpus_app.command("snapshot")
def corpus_snapshot(
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """手动给 manifest.jsonl 打一份快照（落 <corpus>/.snapshots/，可 corpus restore 回滚）。

    save_manifest 每次真写前也会自动打（写前快照）；本命令给"接下来要做危险操作"的人一个
    显式的落点——比如跑一次性脚本前先拍一份。内容与最新快照相同时复用既有快照、不新建。
    """
    root = resolve_corpus(corpus)
    if not _corpus.manifest_path(root).exists():
        typer.echo(f"错误：{root} 下没有 manifest.jsonl，无可快照。", err=True)
        raise typer.Exit(code=1)
    snap = _corpus.snapshot_manifest(root)
    if snap is None:
        typer.echo("错误：快照失败（原因见日志 warning）。", err=True)
        raise typer.Exit(code=1)
    _print({
        "snapshot": str(snap),
        "entries": len(_corpus.load_manifest(root)),
        "snapshots_kept": len(_corpus.list_snapshots(root)),
    })


#: 跨 catalog 边界回滚的警告。命中条件：当前 manifest 已带 catalog-era 投影、目标快照没有。
#:
#: ★为什么非提示不可：restore 在这种情形下会照常回 ``applied: true`` 与 ``restored_entries``，
#: 读的人据此认定已退回旧状态；而 catalog 仍在且是真源，manifest 转头就被重新物化回去，库其实没变。
#: **一个报成功却没生效的回滚，比明确失败危险得多**——失败会让人再想办法，假成功不会。
_CATALOG_CROSSING_WARNING = (
    "★该快照拍摄于 catalog 建立之前，恢复它**不会**把库退回那个时代："
    "catalog.jsonl 仍在且是案件绑定真源，manifest 会被立刻重新物化回当前形态；"
    "删掉 catalog.jsonl 则整库拒绝读写。要真正回到 catalog 之前，只能整目录还原备份"
)


def _crosses_catalog_boundary(current_entries: list[dict], target: Path) -> bool:
    """当前 manifest 已是 catalog 时代，而目标快照仍停在 catalog 之前的形态。

    判据复用 :func:`apkscan.core.corpus_catalog.has_catalog_era_projection`——别在这里
    另写一份形态相近的，两处判据一旦漂移，警告就会在最该出现的时候不出现。
    """
    if not any(_catalog.has_catalog_era_projection(entry) for entry in current_entries):
        return False  # 当前就没跨过 catalog 边界，这次恢复不涉及该问题
    try:
        snapshot_entries = _corpus.load_manifest_file(target)
    except (OSError, _corpus.ManifestCorruptError):
        return False  # 快照读不出来时交由后续正常流程报错，不在这里抢先下判断
    return not any(_catalog.has_catalog_era_projection(entry) for entry in snapshot_entries)


@corpus_app.command("restore")
def corpus_restore(
    snapshot: str = typer.Argument("", help="要恢复的快照文件名（留空则列出可用快照）。"),
    apply: bool = typer.Option(
        False, "--apply", help="真写入。默认 dry-run：只打印将恢复几条/现有几条，不动磁盘。"
    ),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """列出可用快照 / 把 manifest.jsonl 恢复到某份快照。

    ★破坏性操作：恢复是对 manifest 的全量覆盖，故默认 dry-run、``--apply`` 才真写；
    真写前会先给**当前**状态打一份快照（否则恢复本身又成了一次不可逆覆盖，恢复错了没法反悔）。
    只回滚 manifest 索引，不动 reports/ 下的报告文件。

    ★**回滚不过 catalog 这道边界**：manifest 是 catalog 的派生索引，恢复一份 catalog 建立之前的
    旧快照并不会把库退回那个时代——见 :data:`_CATALOG_CROSSING_WARNING`，命中时输出会带上它。
    """
    root = resolve_corpus(corpus)
    current_entries = _corpus.load_manifest(root)
    current = len(current_entries)

    if not snapshot:
        if apply:
            typer.echo("错误：--apply 需要指定要恢复的快照文件名（先不带参数列出可用快照）。", err=True)
            raise typer.Exit(code=2)
        _print({
            "current_entries": current,
            "snapshots": [
                {"name": p.name, "entries": len(_corpus.load_manifest_file(p))}
                for p in _corpus.list_snapshots(root)
            ],
        })
        return

    target = _corpus.resolve_snapshot(root, snapshot)
    if target is None:
        # 不存在与路径穿越同一出口：绝不据用户输入读快照目录之外的文件。
        typer.echo(f"错误：快照不存在或名字越出快照目录：{snapshot!r}", err=True)
        raise typer.Exit(code=1)

    crosses_catalog = _crosses_catalog_boundary(current_entries, target)

    if not apply:
        preview: dict[str, object] = {
            "dry_run": True,
            "snapshot": target.name,
            "would_restore_entries": len(_corpus.load_manifest_file(target)),
            "current_entries": current,
            "hint": "加 --apply 才真写；真写前会先给当前状态打快照。",
        }
        if crosses_catalog:
            preview["catalog_boundary"] = _CATALOG_CROSSING_WARNING
        _print(preview)
        return

    result = _corpus.restore_manifest(root, snapshot)
    if result.get("error"):
        typer.echo(f"错误：{result['error']}", err=True)
        raise typer.Exit(code=1)
    applied_payload: dict[str, object] = {
        "applied": True,
        "snapshot": target.name,
        "restored_entries": result["restored_entries"],
        "previous_entries": current,
        "pre_restore_snapshot": result["pre_restore_snapshot"],
    }
    if crosses_catalog:
        applied_payload["catalog_boundary"] = _CATALOG_CROSSING_WARNING
    _print(applied_payload)


@corpus_app.command("events")
def corpus_events(
    sha256: str = typer.Argument(..., help="样本哈希（sample_sha256，支持库内 nosha- 占位）。"),
    revision: str = typer.Option(
        "",
        "--revision",
        help="显式选择 tool_version@ruleset_digest；旧库多版本缺入库序列时必须提供。",
    ),
    include_quarantined: bool = typer.Option(False, "--include-quarantined"),
    corpus: str = typer.Option("", "--corpus", help=f"语料库根目录（默认取环境变量 {ENV_CORPUS}）。"),
) -> None:
    """把库内该样本的报告吐成 JSONL 事件流（复用 report_to_events，喂 agent）。多版本取最近入库的一份。

    ★★**本命令不脱敏，原样输出**——与 ``fxapk jsonl`` 共用同一条转换路径，同样不受 ``digest``
      默认脱敏的保护。
    """
    from apkscan.core.jsonl import report_to_events

    warn_unredacted_agent_output("corpus events")

    root = resolve_corpus(corpus)
    hits = _corpus.find_by(
        _query_entries(root, include_quarantined=include_quarantined),
        sha256,
        by="sample_sha256",
    )
    if not hits:
        typer.echo(f"库内无此样本：{sha256}", err=True)
        raise typer.Exit(code=1)

    from apkscan.core import regress as _regress

    candidates = hits
    if revision:
        revisions = _regress.available_versions(hits)
        resolved, error = _regress.resolve_revision(revision, revisions)
        if resolved is None:
            typer.echo(f"错误：--revision {error}", err=True)
            raise typer.Exit(code=2)
        candidates = [entry for entry in hits if _regress.revision_of(entry) == resolved]

    if len(candidates) > 1:
        sequences = [entry.get("ingest_sequence") for entry in candidates]
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in sequences
        ):
            typer.echo(
                "错误：该样本有多个候选记录但存量 corpus 缺少权威 ingest_sequence，"
                "不能按 manifest 行序或文件 mtime 猜测。请用 --revision 显式选择；"
                "若同一 revision 仍有多个证据面，请先逐条显式 add 完成 catalog adoption。",
                err=True,
            )
            raise typer.Exit(code=2)
        entry = max(candidates, key=lambda item: int(item["ingest_sequence"]))
    else:
        entry = candidates[0]
    if len(hits) > 1:
        typer.echo(
            f"注意：{sha256} 有 {len(hits)} 个版本，取最近入库的 "
            f"tool_version={entry.get('tool_version')} ruleset_digest={entry.get('ruleset_digest')}。",
            err=True,
        )

    # The manifest path is derived, and the evidence bytes may have been
    # modified out of band.  The shared reader enforces reports/ confinement,
    # strict JSON, top-level object shape, and the recorded ingest digest.
    report, error = _corpus.load_stored_report_checked(root, entry)
    if report is None:
        typer.echo(f"错误：读取库内报告失败：{error}", err=True)
        raise typer.Exit(code=1)

    for event in report_to_events(report):
        typer.echo(_json.dumps(event, ensure_ascii=False, allow_nan=False))


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
    include_quarantined: bool = typer.Option(False, "--include-quarantined"),
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
    entries = _query_entries(root, include_quarantined=include_quarantined)
    versions, order_is_authoritative = _regress.available_versions_with_order(entries)
    if len(versions) < 2:
        typer.echo(
            f"错误：库内只有 {len(versions)} 个修订版（{versions}），无法跨版本对比。"
            "请用新版 fxapk 重跑同批样本并 corpus add 后再试。",
            err=True,
        )
        raise typer.Exit(code=2)

    if not order_is_authoritative and (not version_from or not version_to):
        typer.echo(
            "错误：存量 corpus 缺少 catalog 权威 ingest_sequence，manifest 行序可能已被 "
            "reindex 改写，不能据此猜测旧版/新版方向。请同时显式给出 --from 与 --to；"
            "后续新入库记录会自动登记稳定顺序。",
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

    diffs, summary = _regress.diff_versions(root, entries, v_from, v_to)

    if as_json:
        payload = {
            "summary": summary,
            "diffs": [
                {
                    "sample_sha256": d.sample_sha256, "package_name": d.package_name,
                    "case_ids": d.case_ids,
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
        case_label = "、".join(d.case_ids) if d.case_ids else "—"
        typer.echo(f"\n  [{d.sample_sha256[:12]}] {d.package_name or '?'}  案={case_label}")
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
