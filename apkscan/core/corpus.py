"""样本库：把历次分析的 report.json 累积成可查询、可回归、可重建的语料库（纯逻辑层）。

设计地基（资产沉淀主线 P0）：**report.json 语料本身就是唯一事实源**，本模块只在其上加一层
「可全量重建的派生索引（manifest.jsonl）+ 薄查询函数」——零新存储引擎、零新依赖，不复活已弃用的
图谱 / SQLite 台账。任何索引损坏 :func:`reindex` 即可从报告全量重建，report.json 永远是 source
of truth，这是与中央台账的本质区别。

库布局（根目录经 CLI 的 --corpus 或环境变量 FXAPK_CORPUS 注入，指向 OneDrive，含案件数据不入 git）::

    <corpus>/
      reports/<sample_sha256>/<tool_version>_<ruleset_digest>.report.json   ← 报告原样字节入库
      manifest.jsonl                                                        ← 派生索引，一报告一行

记录单元 = 一份 report.json 原样（schema_version 已版本化、meta 已带 sample_sha256/tool_version/
ruleset_digest 三可复现锚点、finding 已带 analyzer/confidence/kind 溯源）。入库 = 复制 + 登记，无
转换层。库内主键 = ``(sample_sha256, tool_version, ruleset_digest)``：同一样本用同一版 fxapk + 同一
套规则重复入库幂等跳过；换版本 / 换规则则并存一份新报告，天然支撑跨版本回归对比。

★铁律（与 report/json.py、core/diff.py 一致）：纯函数层**禁** print/typer，对坏输入容错返回空/
留空、**绝不抛**；打印与退出码只在 commands/corpus.py。

★P0 有意不带时间戳（added_at/analyzed_at）：让 :func:`manifest_entry` 是报告内容的**纯函数**，
reindex 全量重建后逐字节可复现、幂等易测。若后续需要入库时序，再以文件 mtime 回填（P0 不做）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from apkscan.core.atomic import atomic_write_text

logger = logging.getLogger(__name__)

#: 语料库内报告子目录名。
REPORTS_DIR = "reports"
#: 派生索引文件名（JSONL，一报告一行）。
MANIFEST_NAME = "manifest.jsonl"

#: 库内主键字段：唯一标识"某样本 × 某版 fxapk × 某套规则"的一次分析。
KEY_FIELDS: tuple[str, ...] = ("sample_sha256", "tool_version", "ruleset_digest")

#: manifest 里能被 ``corpus seen --by`` 反查的字段（值 → 命中记录）。
SEEN_FIELDS: tuple[str, ...] = ("sample_sha256", "package_name", "sign_sha256")

#: key_iocs 每条报告最多摘取的高价值线索值数（供快速 grep，非全量）。
_MAX_KEY_IOCS = 8
#: 代表"应进情报平台当 IOC"的研判建议取值（与 report/ioc.py 对齐）。
_ADVICE_INVESTIGATE = "建议调证"
#: 文件名安全化：路径组件里非 [A-Za-z0-9._-] 的字符统一替换为下划线。
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]")
#: 单个路径组件最大长度（真 sha256 恒 64 hex、tool_version/digest 都远短，仅防畸形超长 meta）。
_MAX_COMPONENT = 120
#: Windows 保留设备名（作为文件名 stem 会导致创建失败）——命中则加前缀规避。
_WIN_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)
#: 派生占位身份的保留前缀（见 sample_identity）；真 sha256 是纯 hex，不可能以此开头。
_NOSHA_PREFIX = "nosha-"


def _s(value: Any) -> str:
    """转字符串；None → 空串（用于路径/键，不留 None）。"""
    return "" if value is None else str(value)


def _safe_component(value: str, fallback: str) -> str:
    """把一个值净化成单个安全的路径组件：过滤非法字符 + 限长 + 规避 Windows 保留设备名（空 → fallback）。

    ★注意：本函数是**有损**映射（如 ``abc?123``/``abc*123`` 都 → ``abc_123``）；库内主键用的是**原始
    值**（见 _key_of），二者可能对不上 → 不同主键落同一路径。故 :func:`add_report` 写盘前有碰撞守卫，
    绝不静默覆写已入库的取证字节。
    """
    cleaned = (_UNSAFE_RE.sub("_", value).strip("._") or fallback)[:_MAX_COMPONENT]
    if cleaned.split(".", 1)[0].upper() in _WIN_RESERVED:
        cleaned = f"_{cleaned}"
    return cleaned


def _meta(report: dict) -> dict:
    """取 report 的 meta 子 dict（非 dict / 缺失 → 空 dict）。"""
    m = report.get("meta")
    return m if isinstance(m, dict) else {}


def sample_identity(report: dict) -> tuple[str, bool]:
    """求样本身份哈希：优先 ``meta.sample_sha256``；缺失（旧报告）→ 按报告内容派生占位哈希。

    Returns:
        (sample_sha256, synthetic)。synthetic=True 表示原报告无 sample_sha256（取证完整性功能
        之前产出的旧报告），此处按报告规范化内容算 ``nosha-<16hex>`` 占位——身份不确定但仍可入库、
        不塌缩、不谎报真实样本哈希。
    """
    real = _s(_meta(report).get("sample_sha256")).strip()
    # 拒绝把伪造的保留前缀当真实身份：否则一份 meta.sample_sha256="nosha-XXXX" 的报告能抢占某旧报告
    # 将来派生的占位身份、使真报告入库被幂等跳过、证据永不落盘（synthetic 命名空间必须保留）。
    if real and not real.startswith(_NOSHA_PREFIX):
        return real, False
    try:
        canonical = json.dumps(report, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        logger.warning("样本身份：报告无法规范化序列化，退回空占位")
        canonical = repr(report)
    digest = hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{_NOSHA_PREFIX}{digest}", True


def _key_of(entry: dict) -> tuple[str, ...]:
    """从一条 manifest 记录取库内主键元组。"""
    return tuple(_s(entry.get(f)) for f in KEY_FIELDS)


def report_relpath(report: dict) -> str:
    """报告在库内的相对路径：``reports/<sha>/<tool_version>_<ruleset_digest>.report.json``。"""
    meta = _meta(report)
    sha, _synthetic = sample_identity(report)
    sha_dir = _safe_component(sha, "unknown")
    tv = _safe_component(_s(meta.get("tool_version")) or "unknown", "unknown")
    digest = _safe_component(_s(meta.get("ruleset_digest")) or "unknown", "unknown")
    return f"{REPORTS_DIR}/{sha_dir}/{tv}_{digest}.report.json"


def _key_iocs(report: dict) -> list[str]:
    """从 leads 摘取高价值线索值（is_c2 或 advice=建议调证）供快速 grep，去重、限量。"""
    leads = report.get("leads")
    if not isinstance(leads, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        if not (lead.get("is_c2") or lead.get("advice") == _ADVICE_INVESTIGATE):
            continue
        value = _s(lead.get("value")).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= _MAX_KEY_IOCS:
            break
    return out


def _finding_ids(report: dict) -> list[str]:
    """报告命中的规则 id 去重排序（供规则库命中反查，Finding.id 即规则 id）。"""
    findings = report.get("findings")
    if not isinstance(findings, list):
        return []
    ids = {
        _s(f.get("id")).strip()
        for f in findings
        if isinstance(f, dict) and _s(f.get("id")).strip()
    }
    return sorted(ids)


def _count(report: dict, key: str) -> int:
    """report 顶层某列表字段的长度（非 list → 0）。"""
    v = report.get(key)
    return len(v) if isinstance(v, list) else 0


def manifest_entry(report: dict, case_id: str | None = None) -> dict:
    """把一份 report dict 提炼成一条 manifest 记录（纯函数，坏输入容错，绝不抛）。

    只提取索引/研判/可复现所需字段；报告全文另存于 :func:`report_relpath`。``case_id`` 是唯一
    非派生的人工字段（入库时标注案件归属），其余全部由报告内容决定 → reindex 可全量重建。
    """
    if not isinstance(report, dict):
        report = {}
    meta = _meta(report)
    sha, synthetic = sample_identity(report)
    classification = meta.get("app_classification")
    classification = classification if isinstance(classification, dict) else {}
    return {
        # ---- 库内主键 ----
        "sample_sha256": sha,
        "sample_sha256_synthetic": synthetic,
        "tool_version": _s(meta.get("tool_version")) or None,
        "ruleset_digest": _s(meta.get("ruleset_digest")) or None,
        # ---- 身份 / 版本 ----
        "package_name": _s(report.get("package_name") or meta.get("package_name")) or None,
        "version_name": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        "sign_sha256": meta.get("sign_sha256"),  # 签名证书摘要 = 共享证书串案强锚
        # ---- 加固 / 分类 ----
        "packer": meta.get("packer"),
        "is_hardened": bool(meta.get("is_hardened", False)),
        "app_type": classification.get("type"),
        "app_score": classification.get("score"),
        # ---- 可信度 / 可复现 ----
        "mode": meta.get("mode"),
        "analysis_status": report.get("analysis_status"),
        "completeness": report.get("completeness"),
        "schema_version": report.get("schema_version"),
        # ---- 归属（唯一人工字段）+ 定位 ----
        "case_id": case_id or None,
        "report_path": report_relpath(report),
        # ---- 计数 / 反查料 ----
        "counts": {
            "leads": _count(report, "leads"),
            "endpoints": _count(report, "endpoints"),
            "findings": _count(report, "findings"),
        },
        "finding_ids": _finding_ids(report),
        "key_iocs": _key_iocs(report),
    }


# ---------------------------------------------------------------------------
# manifest 读写（JSONL；写走原子全量重写，非 append）
# ---------------------------------------------------------------------------


def manifest_path(corpus_dir: str | Path) -> Path:
    """语料库 manifest.jsonl 的完整路径。"""
    return Path(corpus_dir) / MANIFEST_NAME


def load_manifest(corpus_dir: str | Path) -> list[dict]:
    """读 manifest.jsonl → 记录列表。文件不存在 → 空列表；坏行记 warning 跳过、绝不抛。"""
    path = manifest_path(corpus_dir)
    if not path.exists():
        return []
    entries: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError, RecursionError):
        # ValueError 覆盖 UnicodeDecodeError（非 UTF-8 的 manifest）；RecursionError 覆盖畸形深嵌套。
        logger.exception("读取 manifest 失败：%s", path)
        return []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("manifest 第 %d 行非法 JSON，跳过：%s", lineno, path)
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries


def save_manifest(corpus_dir: str | Path, entries: list[dict]) -> None:
    """把记录列表原子全量重写进 manifest.jsonl（keyed 语义由调用方保证，本函数只落盘）。

    ``atomic_write_text`` 无 append，故写入恒为"内存 merge 后整文件原子替换"——百级样本无碍，且
    保证 manifest 要么旧内容完整、要么新内容完整，绝不留半截坏索引。
    """
    payload = "\n".join(
        json.dumps(e, ensure_ascii=False, sort_keys=True) for e in entries
    )
    if payload:
        payload += "\n"
    atomic_write_text(manifest_path(corpus_dir), payload)


def upsert(entries: list[dict], entry: dict) -> tuple[list[dict], bool]:
    """按库内主键把 entry 并入 entries（纯函数，不落盘）。

    主键已存在 → **幂等跳过**（保留原记录，含其人工 case_id），返回 added=False；不存在 → 追加，
    返回 added=True。返回新列表（不原地改入参）。
    """
    key = _key_of(entry)
    existing = {_key_of(e) for e in entries}
    if key in existing:
        return list(entries), False
    return [*entries, entry], True


# ---------------------------------------------------------------------------
# 入库 / 重建 / 查询
# ---------------------------------------------------------------------------


def add_report(
    corpus_dir: str | Path,
    report: dict,
    raw_text: str,
    case_id: str | None = None,
) -> dict:
    """把一份报告入库：原样字节存进 reports/、登记进 manifest（幂等）。

    Args:
        corpus_dir: 语料库根目录。
        report: 已解析的 report dict（供 manifest_entry 提取索引字段）。
        raw_text: 报告原始文本（原样存盘，不改一字节；取证链要求）。
        case_id: 案件归属（唯一人工字段），可空。

    Returns:
        ``{"added": bool, "report_path": str, "key": [...], "synthetic": bool}``。
        added=False 表示该 (样本, 版本, 规则) 已在库，幂等跳过（报告文件与 manifest 均不改）。
    """
    root = Path(corpus_dir)
    entry = manifest_entry(report, case_id=case_id)
    entries = load_manifest(root)
    new_entries, added = upsert(entries, entry)
    report_path = entry["report_path"]
    base = {
        "report_path": report_path,
        "key": list(_key_of(entry)),
        "synthetic": entry.get("sample_sha256_synthetic", False),
    }

    if added:
        report_file = root / report_path
        # ★碰撞守卫：本主键是"新"的（不在 manifest），却已有同名文件 → 是**另一个**主键净化后落到
        #   同路径（如 sha 含非法字符、或大小写不敏感文件系统上 hex 大小写不同）。若字节还不同，直接
        #   覆写就会静默销毁已入库的取证原字节 → 拒绝，交由调用方报冲突。字节相同则是崩溃残留的孤儿
        #   文件（同内容），可安全续写。
        if report_file.exists():
            try:
                on_disk = report_file.read_bytes()
            except OSError:
                on_disk = None
            if on_disk is not None and on_disk != raw_text.encode("utf-8"):
                logger.warning(
                    "路径碰撞：%s 已存在且字节不同（不同主键净化后同路径），拒绝覆盖已入库证据", report_path
                )
                return {**base, "added": False, "collision": True}
        # 报告原样落盘（原子），再更新索引——先证据后索引，索引损坏可 reindex 重建。
        atomic_write_text(report_file, raw_text)
        save_manifest(root, new_entries)
        logger.info("入库：%s（case=%s）", report_path, case_id or "-")
    else:
        logger.info("已在库，幂等跳过：%s", report_path)

    return {**base, "added": added, "collision": False}


def reindex(corpus_dir: str | Path) -> list[dict]:
    """扫 reports/ 下全部 *.report.json 全量重建 manifest，并写回。

    manifest 是缓存不是事实源：本函数从报告重算每条记录，只从**旧 manifest 继承人工 case_id**
    （按主键匹配）——其余字段全由报告内容决定。坏报告（无法解析）记 warning 跳过。返回新记录列表。
    """
    root = Path(corpus_dir)
    reports_root = root / REPORTS_DIR

    # 旧 manifest 的 case_id 表：主键 → case_id（人工标注不能因重建而丢）。
    old_case: dict[tuple[str, ...], str] = {}
    for e in load_manifest(root):
        cid = e.get("case_id")
        if cid:
            old_case[_key_of(e)] = cid

    entries: list[dict] = []
    if reports_root.exists():
        for report_file in sorted(reports_root.rglob("*.report.json")):
            try:
                report = json.loads(report_file.read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError):
                # ValueError 含 JSONDecodeError + UnicodeDecodeError；一个坏文件不得让自愈工具崩。
                logger.warning("reindex 跳过无法解析的报告：%s", report_file)
                continue
            if not isinstance(report, dict):
                logger.warning("reindex 跳过非 dict 报告：%s", report_file)
                continue
            entry = manifest_entry(report)
            carried = old_case.get(_key_of(entry))
            if carried:
                entry["case_id"] = carried
            entries.append(entry)

    save_manifest(root, entries)
    logger.info("reindex 完成：%d 条记录", len(entries))
    return entries


def query(entries: list[dict], **filters: str) -> list[dict]:
    """按字段等值过滤 manifest 记录（空值过滤项忽略）。字段名见 manifest_entry。"""
    active = {k: v for k, v in filters.items() if v}
    if not active:
        return list(entries)
    out: list[dict] = []
    for e in entries:
        if all(_s(e.get(k)) == v for k, v in active.items()):
            out.append(e)
    return out


def find_by(entries: list[dict], value: str, by: str = "sample_sha256") -> list[dict]:
    """反查："这个值见过没"。按 ``by`` 字段等值匹配（支持 sample_sha256/package_name/sign_sha256）。"""
    if by not in SEEN_FIELDS:
        logger.warning("find_by 不支持的字段：%s（支持 %s）", by, SEEN_FIELDS)
        return []
    target = _s(value).strip()
    if not target:
        return []
    return [e for e in entries if _s(e.get(by)).strip() == target]
