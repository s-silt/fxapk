"""样本库：把历次分析的 report.json 累积成可查询、可回归、可重建的语料库（纯逻辑层）。

设计地基（资产沉淀主线 P0/P1）：report.json 是报告内容的事实源；无法从报告重建的显式案件关联与
生命周期隔离状态由 ``catalog.jsonl`` 保存。``manifest.jsonl`` 仍是两者合成的可重建派生索引——
零数据库、零外部 workflow 依赖。任何索引损坏 :func:`reindex` 即可从报告 + catalog 全量重建。

库布局（根目录经 CLI 的 --corpus 或环境变量 FXAPK_CORPUS 注入，必须位于工作树外，案件数据不入 git）::

    <corpus>/
      reports/<sample_sha256>/<tool_version>_<ruleset_digest>[_<证据面>].report.json  ← 报告原样字节入库
      catalog.jsonl                                                         ← case_ids / 隔离状态（非派生）
      .catalog.lock                                                         ← 跨进程写事务锁
      manifest.jsonl                                                        ← 派生索引，一报告一行
      .snapshots/manifest-<UTC时间戳>-<pid>-<seq>.jsonl                     ← manifest 写前快照（可 restore 回滚）

记录单元 = 一份 report.json 原样（schema_version 已版本化、meta 已带 sample_sha256/tool_version/
ruleset_digest 三可复现锚点、finding 已带 analyzer/confidence/kind 溯源）。入库 = 复制 + 登记，无
转换层。库内主键 = ``(sample_sha256, tool_version, ruleset_digest, evidence_surface)``：同一样本用
同一版 fxapk + 同一套规则、且看的是同一个证据面时，重复入库幂等跳过；换版本 / 换规则 / 换证据面
则并存一份新报告，天然支撑跨版本回归对比。

★证据面（evidence_surface）为什么必须入主键：同一样本、同一版本、同一套规则，**脱壳前后看到的
不是同一批内容**——脱壳后能读到壳内 dex，端点与线索通常显著更多。此前它不在主键里，两份报告
主键完全相同，后入库的被幂等跳过，于是**更完整的那份被静默丢弃**。
static 不加路径后缀，故该维度引入后存量记录的路径与主键一字不变。

★存证自证未被篡改（完整性三件套）：入库时对**存盘原样字节**计 sha256 记进 manifest
（``report_bytes_sha256`` + origin="ingest"，与样本 APK 的 ``sample_sha256`` 是两回事）；
``fxapk corpus verify`` 逐条校验并把 ok / mismatch / unverifiable 严格分开——「没法验」绝不能
呈现成「验过没问题」；``fxapk corpus backfill-hash`` 给存量记录补录哈希（origin="backfill"），
补录哈希只证明「从补录起」未改、**不追溯**证明此前历史。绕过 API 直接改 reports/ 文件的脚本
永远防不住，但从此**可检测**——2026-07-28 那次 28 份存证被一次性脚本覆盖，事后定位靠的是
「文件名里编的版本号 vs 内容里的 meta.tool_version 对不上」这种巧合，这里把巧合变成机制。

★铁律（与 report/json.py、core/diff.py 一致）：纯函数层**禁** print/typer；普通缺失可结构化返回，
catalog/manifest 损坏与证据冲突则 fail closed 抛命名异常；打印与退出码只在 commands/corpus.py。

★入库顺序不是报告内容的派生值：新主键首次由 ``add_report`` 建索引时，catalog 锁内分配单调
``ingest_sequence``；reindex 只重建 manifest 并从 catalog 恢复它。旧库/孤儿一旦失去原顺序就保持
``None``，消费方必须要求显式版本，绝不能拿 manifest 行序或文件 mtime 猜“最新”。
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import json
import logging
import os
import posixpath
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, Mapping

from apkscan.core.atomic import atomic_create_bytes, atomic_write_bytes, atomic_write_text
from apkscan.core import corpus_catalog
from apkscan.core.evidence_scope import (
    project_serialized_leads,
    serialized_has_case_evidence,
)
from apkscan.core.json_contract import (
    parse_finite_json_float as _parse_finite_float,
    reject_nonfinite_json_constant as _reject_json_constant,
)
from apkscan.core.source_status import provider_payload_if_hit

logger = logging.getLogger(__name__)


def _strict_json_object(raw_text: str) -> dict:
    parsed = json.loads(
        raw_text,
        parse_constant=_reject_json_constant,
        parse_float=_parse_finite_float,
    )
    if not isinstance(parsed, dict):
        raise ValueError("report 原文顶层必须是 JSON 对象")
    return parsed


def _same_json_value(parsed: object, supplied: object) -> bool:
    """Type-strict semantic equality for a parsed JSON value.

    Python considers ``True == 1`` and ``1 == 1.0``.  Those are distinct JSON
    representations and must not let a caller index one object while storing
    another object's bytes.
    """
    if isinstance(parsed, dict):
        return (
            isinstance(supplied, dict)
            and parsed.keys() == supplied.keys()
            and all(_same_json_value(value, supplied[key]) for key, value in parsed.items())
        )
    if isinstance(parsed, list):
        return (
            isinstance(supplied, list)
            and len(parsed) == len(supplied)
            and all(_same_json_value(left, right) for left, right in zip(parsed, supplied))
        )
    if parsed is None or isinstance(parsed, (str, bool, int, float)):
        return type(parsed) is type(supplied) and parsed == supplied
    return False

#: 语料库内报告子目录名。
REPORTS_DIR = "reports"
#: 派生索引文件名（JSONL，一报告一行）。
MANIFEST_NAME = "manifest.jsonl"

#: 证据面：同一样本 × 同一版本 × 同一套规则，**脱壳前后看到的不是同一批内容**——
#: 脱壳后能读到壳内的 dex，端点与线索通常显著更多（实测某样本：静态 100 端点、脱壳后 239）。
#: 若不入主键，两份报告主键完全相同，后入库的那份被幂等跳过，
#: 结果是**更完整的那份被静默丢弃**——正是取证上最不该发生的一类损失。
_SURFACE_STATIC = "static"
_SURFACE_UNPACKED = "unpacked"


def evidence_surface(report: dict) -> str:
    """本次分析看到的证据面：脱壳产物 or 原始包。

    判据是脱壳路径写下的 ``meta.unpacked`` 标记，不靠端点数量之类的启发式——
    数量会随规则变化，标记不会。
    """
    return _SURFACE_UNPACKED if _meta(report).get("unpacked") else _SURFACE_STATIC


#: 库内主键字段：唯一标识"某样本 × 某版 fxapk × 某套规则 × 某个证据面"的一次分析。
KEY_FIELDS: tuple[str, ...] = (
    "sample_sha256", "tool_version", "ruleset_digest", "evidence_surface",
)

#: 主键字段的缺省值。``evidence_surface`` 是后加的一维，**存量 manifest 行没有这个字段**；
#: 不给缺省值的话，同一份存量报告在 reindex 前算出 ""、reindex 后算出 "static"，
#: 主键对不上、会被当成两条记录。缺省对齐到 static 后，存量记录的主键与路径都一字不变。
_KEY_DEFAULTS: dict[str, str] = {"evidence_surface": _SURFACE_STATIC}

#: manifest 里能被 ``corpus seen --by`` 反查的字段（值 → 命中记录）。
SEEN_FIELDS: tuple[str, ...] = ("sample_sha256", "package_name", "sign_sha256")
#: 其中**哈希类**字段（十六进制、大小写等价）——find_by 比对前两侧归一小写，避免传大写 SHA256 假阴性；
#: package_name 大小写敏感（com.Foo ≠ com.foo），**不归一**。
_HASH_SEEN_FIELDS: frozenset[str] = frozenset({"sample_sha256", "sign_sha256"})

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

#: 报告内容哈希（manifest 字段 ``report_bytes_sha256``）的来源标记。
#:
#: ★与 ``sample_sha256`` 是两回事，混同会出大事：sample_sha256 是**样本 APK 检材**的身份哈希
#:   （定"分析的是哪个检材"）；report_bytes_sha256 是**入库报告文件存盘原样字节**的哈希
#:   （定"这份存证自哈希钉下起有没有被改过一字节"）。字段名带 ``bytes`` 就是为了把两者拉开。
#:
#: 两个来源值的证据强度不同，绝不能在任何输出里长得一样：
#:   · ``ingest``   —— :func:`add_report` 在落盘同一时刻对即将写盘的字节计算，
#:     覆盖该存证的整个库内生命期；
#:   · ``backfill`` —— 事后按文件**当时**的内容补算，只证明「从补录那一刻起」未被改动，
#:     **不能**追溯证明补录之前没被改过。若补录前文件已被篡改，补录会把篡改后的内容钉成
#:     基准、verify 从此恒 ok——这正是补录必须打独立标记的原因：不打标记，就是在给一批
#:     来历不明的哈希发"入库即验"的合格证。
HASH_ORIGIN_INGEST = "ingest"
HASH_ORIGIN_BACKFILL = "backfill"

#: :func:`verify_reports` 的分档。★前三档都是"manifest 有记录"的情形，必须严格分开——
#: 把 unverifiable 折进 ok，等于替一批无从验证的文件背书（本项目最忌讳的一类塌缩）。
VERIFY_OK = "ok"  # 有记录哈希，且文件当前字节与之相符（origin 决定这句话覆盖多长的历史）
VERIFY_MISMATCH = "mismatch"  # 有记录哈希但对不上——文件在库内被改过，要报警
VERIFY_UNVERIFIABLE = "unverifiable"  # 没有记录哈希（存量记录）——是「没法验」，不是「验过没问题」
VERIFY_MISSING = "missing"  # manifest 有记录但文件取不到（不存在/路径越界/读失败）
VERIFY_ORPHAN = "orphan"  # reports/ 下有报告文件但 manifest 无对应记录


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
    """从一条 manifest 记录取库内主键元组。

    缺字段取 ``_KEY_DEFAULTS`` 的缺省值——后加的主键维度在存量行里不存在，
    不归一就会让同一份报告在 reindex 前后算出两个不同主键。
    """
    return tuple(_s(entry.get(f)) or _KEY_DEFAULTS.get(f, "") for f in KEY_FIELDS)


def manifest_key(entry: Mapping[str, object]) -> tuple[str, ...]:
    """Return the stable four-part key of a manifest/catalog record."""
    return _key_of(dict(entry))


def visible_entries(entries: list[dict], *, include_quarantined: bool = False) -> list[dict]:
    """Hide explicitly quarantined records from normal queries by default."""
    if include_quarantined:
        return list(entries)
    return [
        entry
        for entry in entries
        if entry.get("record_state", corpus_catalog.RECORD_ACTIVE)
        != corpus_catalog.RECORD_QUARANTINED
    ]


_CASE_IOC_FIELDS: tuple[str, ...] = (
    "key_iocs",
    "domains",
    "cname_edges",
    "remote_config_objects",
)


def _sanitize_case_ioc_projection(entry: dict) -> dict:
    """Fail closed for legacy/unmarked case-level IOC projections."""
    row = dict(entry)
    # The marker means the projection was computed by the current
    # scope-aware extractor.  It is sufficient even when the source report is
    # an older schema: producer-owned remote_config_artifacts remain valid,
    # while Lead/Endpoint-derived values were gated during this reindex/add.
    # Pre-marker manifest rows still fail closed regardless of schema label.
    if row.get("case_ioc_scope_indexed") is not True:
        for field in _CASE_IOC_FIELDS:
            row[field] = []
    return row


def load_materialized_manifest(corpus_dir: str | Path) -> list[dict]:
    """Strictly join catalog authority into the derived manifest for queries.

    The revision checks avoid observing an old active catalog immediately
    before a concurrent quarantine commit.  Catalog corruption is never
    tolerated on a query path because skipping a bad quarantine row would
    re-expose the record.
    """
    root = Path(corpus_dir)
    for _attempt in range(5):
        catalog_before = corpus_catalog.catalog_revision(root)
        manifest_before = manifest_revision(root)
        catalog_rows = corpus_catalog.load_catalog_strict(root)
        manifest_entries = load_manifest_strict(root)
        if (
            corpus_catalog.catalog_revision(root) != catalog_before
            or manifest_revision(root) != manifest_before
        ):
            continue
        corpus_catalog.assert_manifest_catalog_coverage(
            manifest_entries, catalog_rows, root
        )
        materialized = [
            _sanitize_case_ioc_projection(corpus_catalog.materialize(entry, catalog_rows))
            for entry in manifest_entries
        ]
        if (
            corpus_catalog.catalog_revision(root) == catalog_before
            and manifest_revision(root) == manifest_before
        ):
            return materialized
    raise TimeoutError("corpus catalog/manifest 在查询期间持续变化，拒绝返回可能过期的结果")


_DEVELOPMENT_VERSION_RE = re.compile(
    r"(?:^|[.\-_]|\d)(?:dev|alpha|beta|rc|pre|preview|a\d|b\d)(?:[.\-_\d]|$)",
    re.I,
)
_STABLE_RELEASE_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*)$")


def _stable_release(value: str) -> tuple[int, ...] | None:
    match = _STABLE_RELEASE_RE.fullmatch(value.strip())
    if match is None:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def audit_versions(entries: list[dict]) -> dict[str, dict[str, object]]:
    """Read-only version/lifecycle census; it never quarantines automatically."""
    out: dict[str, dict[str, object]] = {}
    for entry in entries:
        version = _s(entry.get("tool_version")).strip() or "unknown"
        row = out.setdefault(
            version,
            {"records": 0, "active": 0, "quarantined": 0, "development": False},
        )
        record_count = row.get("records")
        row["records"] = (record_count if isinstance(record_count, int) else 0) + 1
        state = _s(entry.get("record_state")) or corpus_catalog.RECORD_ACTIVE
        bucket = "quarantined" if state == corpus_catalog.RECORD_QUARANTINED else "active"
        bucket_count = row.get(bucket)
        row[bucket] = (bucket_count if isinstance(bucket_count, int) else 0) + 1
        row["development"] = bool(_DEVELOPMENT_VERSION_RE.search(version))
    stable = {
        version: parsed
        for version in out
        if not bool(out[version]["development"])
        and (parsed := _stable_release(version)) is not None
    }
    current_release = max(stable.values(), default=None)
    for version, row in out.items():
        if bool(row["development"]):
            state = "development"
        elif (parsed := stable.get(version)) is None:
            state = "unknown"
        elif parsed == current_release:
            state = "current_release"
        else:
            state = "legacy_release"
        row["version_state"] = state
        row["version_state_basis"] = "highest_stable_release_in_corpus"
    return dict(sorted(out.items()))


def report_relpath(report: dict) -> str:
    """报告在库内的相对路径。

    ``reports/<sha>/<tool_version>_<ruleset_digest>[_<证据面>].report.json``

    ★证据面后缀**只在非 static 时才加**：静态分析的路径与后缀引入前完全一致，
    存量记录不需要搬家，reindex 也不会把它们算成新记录。
    """
    meta = _meta(report)
    sha, _synthetic = sample_identity(report)
    sha_dir = _safe_component(sha, "unknown")
    tv = _safe_component(_s(meta.get("tool_version")) or "unknown", "unknown")
    digest = _safe_component(_s(meta.get("ruleset_digest")) or "unknown", "unknown")
    surface = evidence_surface(report)
    suffix = "" if surface == _SURFACE_STATIC else f"_{_safe_component(surface, 'unknown')}"
    return f"{REPORTS_DIR}/{sha_dir}/{tv}_{digest}{suffix}.report.json"


def _key_iocs(report: dict) -> list[str]:
    """从 leads 摘取高价值线索值（is_c2 或 advice=建议调证）供快速 grep，去重、限量。

    ★``shape_uncertain`` 的值不收：它们的地址性尚未确证（形态与版本号无法区分）。串案时
    两个毫不相干的样本恰好含同一个版本号字面，会被呈现成「共享基础设施」——那是凭空造出
    一条串案信号，方向上正是本项目最重的那类错误。要串案，先把它确证成地址。
    """
    out: list[str] = []
    seen: set[str] = set()
    for lead in project_serialized_leads(report):
        if not (lead.get("is_c2") or lead.get("advice") == _ADVICE_INVESTIGATE):
            continue
        if lead.get("shape_uncertain"):
            continue
        value = _s(lead.get("value")).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= _MAX_KEY_IOCS:
            break
    return out


def _remote_config_objects(report: dict) -> list[dict]:
    """报告引用的远程配置对象，供跨样本串联「同一 OSS 对象 / 同一份配置」。

    取下载解码产物的 ``(source_url, sha256)``（producer 写入的
    meta["remote_config_artifacts"]）并上**显式 case_evidence** 的 ``REMOTE_CONFIG`` 线索 URL。
    artifact 是报告生产阶段的逐案事实，暂不套用 Lead scope；Lead 缺/坏 scope 一律不索引。
    """
    objects: dict[str, dict] = {}
    for art in _meta(report).get("remote_config_artifacts") or []:
        if not isinstance(art, dict):
            continue
        url = _s(art.get("source_url")).strip()
        if url:
            objects.setdefault(url, {"url": url, "sha256": _s(art.get("sha256")).strip().lower() or None})
    for lead in project_serialized_leads(report):
        if (
            lead.get("category") == "REMOTE_CONFIG"
            and serialized_has_case_evidence(lead, "source_refs")
        ):
            url = _s(lead.get("value")).strip()
            if url:
                objects.setdefault(url, {"url": url, "sha256": None})
    return [objects[url] for url in sorted(objects)]


def _normalize_domain(value: object) -> str:
    """用于串案索引的域名规范化（大小写不敏感、DNS 末点等价）。"""
    return _s(value).strip().lower().rstrip(".")


def _has_case_runtime_dns_evidence(endpoint: Mapping[str, object]) -> bool:
    evidences = endpoint.get("evidences")
    if not isinstance(evidences, list):
        return False
    return any(
        isinstance(evidence, Mapping)
        and _s(evidence.get("scope")) == "case_evidence"
        and _s(evidence.get("source")) == "runtime-pcap"
        and _s(evidence.get("location")) == "pcap-dns"
        for evidence in evidences
    )


def _domain_control_iocs(report: dict) -> tuple[list[str], list[dict[str, str]]]:
    """提取逐案报告内的域名及**明确观测** CNAME 边。

    只收报告自身的 endpoints/leads，不读取同目录批次附件，避免批次汇总被误算成每案命中。
    ``dns`` 仅在 provider 状态为 hit（或报告完全没有 source_status 的真正旧格式）时可用；失败/
    无记录/跳过后的残留 payload 不得进索引。``dns_runtime`` 是逐案运行时观测，不受被动 DNS
    provider 状态抑制。旧版 ``dns.cname`` 没有 RR owner，只能补域名集合，不能臆造边；带 from/to
    的 ``cname_edges`` 才进入边索引。
    """
    domains: set[str] = set()
    edges: set[tuple[str, str]] = set()
    for lead in project_serialized_leads(report):
        if (
            serialized_has_case_evidence(lead, "source_refs")
            and _s(lead.get("category")).upper() == "DOMAIN"
        ):
            value = _normalize_domain(lead.get("value"))
            if value:
                domains.add(value)
    for endpoint in report.get("endpoints") or []:
        if (
            not isinstance(endpoint, dict)
            or not serialized_has_case_evidence(endpoint, "evidences")
            or _s(endpoint.get("kind")).lower() != "domain"
        ):
            continue
        value = _normalize_domain(endpoint.get("value"))
        if value:
            domains.add(value)
        enrichment = endpoint.get("enrichment")
        if not isinstance(enrichment, dict):
            continue
        dns_runtime = enrichment.get("dns_runtime")
        runtime_block = (
            dns_runtime
            if isinstance(dns_runtime, dict) and _has_case_runtime_dns_evidence(endpoint)
            else {}
        )
        for block in (provider_payload_if_hit(enrichment, "dns"), runtime_block):
            for cname in block.get("cname") or []:
                target = _normalize_domain(cname)
                if target:
                    domains.add(target)
            for edge in block.get("cname_edges") or []:
                if not isinstance(edge, dict):
                    continue
                src = _normalize_domain(edge.get("from"))
                dst = _normalize_domain(edge.get("to"))
                if src and dst:
                    domains.update((src, dst))
                    edges.add((src, dst))
    return sorted(domains), [
        {"from": src, "to": dst} for src, dst in sorted(edges)
    ]


#: 构建标识的合法形态：编译器写进 ``__FILE__`` 的路径段，长度与字符集都有限。
#: 过长/含路径分隔符的一律丢——那是提取没切干净，不是标识。
_MAX_BUILD_ID = 80
_BUILD_ID_BAD = frozenset("/\\\n\r\t")

#: 进**串案维度**所需的最少残留路径数。
#:
#: 真实的构建环境会在几十个源文件里留下痕迹；只留下一两条路径的，分不清是构建环境
#: 还是「恰好被引用的某个文件」——而串案对假阳性最敏感：一条噪音就能把两个互不相干的
#: 案件聚成一簇，读的人会当成并案依据。
#:
#: 阈值经真实检材实测标定，两侧分得很开、中间是空的：
#:   · 已核实的真构建环境 —— 路径数为**两位数**；
#:   · 实测噪音 3 个 —— 路径数 **1 – 2**：
#:       ``c:/content/test-UHD-HEVC_01_FMV_Med_track1.hvc``（HEVC 测试码流）、
#:       ``z:/jc/units/javascript.jc``（JavaCC 语法文件）、
#:       ``e:/tingyunandroid-oom/koom-*``（第三方 APM/OOM 监控库）。
#: 取 3 而非贴着 26，是给「路径少但真实」的环境留余量：宁可放进来几条弱证据，
#: 也不要把真环境挡在门外——门槛是为了挡噪音，不是为了挑最强的。
#:
#: ★只作用于串案维度：分析器的 ``meta.build_provenance`` 仍**全量如实**记录，
#:   人核报告看得到全部，这里只决定「哪些够格拿去跨案聚簇」。
_MIN_BUILD_PATHS = 3


def _build_environments(report: dict) -> list[dict]:
    """报告登记的**自建构建环境标识**（meta["build_provenance"]，由 build_provenance 分析器产）。

    ★为什么这比 .so 哈希更耐用：同源库的文件名与 sha256 可以逐份不同，文件名锚与
    :func:`_native_lib_hashes` 反查因此双双失效；而构建路径是编译器写进 ``__FILE__`` 的，
    对**已编译产物**做改名、重打包、重签名都动不了它。

    ★但它不是终审，别当成并案依据：重新编译（换机器、换 CI 工作区、换项目根目录）就会改写它；
    相同标识只说明构建环境相同，是否同一主体须另有独立证据。反向的"标识不同"同理——
    足以排除"同一次构建环境"，不足以单独排除同一主体。

    ★只收 ``self_hosted`` 那层：第三方 SDK 的构建路径会随源码继承进来（如某开源客户端作者的
    开发机目录出现在 多个样本里），拿它串案会把互不相干的样本串成一团，还会把无关的开源作者
    卷进来。分层由分析器负责，这里只信它的 self_hosted 分类。
    """
    out: dict[str, dict] = {}
    prov = _meta(report).get("build_provenance")
    if not isinstance(prov, dict):
        return []
    for item in prov.get("self_hosted") or []:
        if isinstance(item, dict):
            ident = _s(item.get("identifier") or item.get("root")).strip()
            root = _s(item.get("root")).strip() or None
            count = item.get("count")
        else:
            ident, root, count = _s(item).strip(), None, None
        if not ident or len(ident) > _MAX_BUILD_ID or any(c in _BUILD_ID_BAD for c in ident):
            continue
        # 残留路径太少 → 不够格进串案维度（见 _MIN_BUILD_PATHS）。
        # count 缺失（旧报告没这个字段）时**放行**：不因少个字段就丢掉已有数据。
        if isinstance(count, int) and count < _MIN_BUILD_PATHS:
            continue
        out.setdefault(ident, {"identifier": ident, "root": root})
    return [out[k] for k in sorted(out)]


def find_by_build_env(entries: list[dict], value: str) -> list[dict]:
    """反查用同一构建环境打出来的样本（列表维度，故不走 :func:`find_by`）。

    大小写敏感：构建标识是开发方自己写的字面量，``Env0000-Aaaa`` 与 ``env0000-aaaa`` 不应等同。
    空值 → 空列表。绝不抛。
    """
    target = _s(value).strip()
    if not target:
        return []
    return [
        e for e in entries
        if any(_s(b.get("identifier")).strip() == target
               for b in (e.get("build_environments") or []) if isinstance(b, dict))
    ]


def shared_build_environments(entries: list[dict]) -> list[dict]:
    """跨样本共享的构建环境簇：同一标识被 **≥2 个不同样本** 使用。

    返回按样本数降序的 ``[{identifier, root, samples: [...]}]``。绝不抛。
    """
    groups: dict[str, set[str]] = {}
    roots: dict[str, str | None] = {}
    for entry in entries:
        sample = _s(entry.get("sample_sha256")).strip().lower()
        if not sample:
            continue
        for b in entry.get("build_environments") or []:
            if not isinstance(b, dict):
                continue
            ident = _s(b.get("identifier")).strip()
            if ident:
                groups.setdefault(ident, set()).add(sample)
                roots.setdefault(ident, b.get("root"))
    out = [
        {"identifier": k, "root": roots.get(k), "samples": sorted(v)}
        for k, v in groups.items() if len(v) >= 2
    ]
    out.sort(key=lambda c: (-len(c["samples"]), c["identifier"]))
    return out


def _native_lib_hashes(report: dict) -> list[dict]:
    """报告登记的 App .so 指纹（meta["native_lib_hashes"]，由 native_fingerprint 分析器产）。

    每项 ``{name, sha256, size}``——同族样本核心 .so 常逐字节相同，其 sha256 是家族级硬指纹，供
    ``corpus seen <sha> --by so_sha256`` 一击反查全家族。按 sha256 去重排序确定；空/坏 → 空列表。绝不抛。
    """
    objects: dict[str, dict] = {}
    for h in _meta(report).get("native_lib_hashes") or []:
        if not isinstance(h, dict):
            continue
        sha = _s(h.get("sha256")).strip().lower()
        # ★形状校验：sha256 须 64 位十六进制——否则坏/导入的旧报告能凭任意串（截断哈希 / 占位符 / 路径）
        #   造出假家族簇。size 须非负 int，否则记 None。不合形状即丢，绝不索引。
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            continue
        size = h.get("size")
        objects.setdefault(sha, {
            "name": _s(h.get("name")).strip() or None,
            "sha256": sha,
            "size": size if isinstance(size, int) and size >= 0 else None,
        })
    return [objects[sha] for sha in sorted(objects)]


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


def visibility_summary(report: Any) -> dict | None:
    """``meta.visibility`` 的可比结构化指纹；**无求值（旧版报告）→ None**，与「求过值但全空」严格区分。

    给 ``corpus regress`` 用：换版后「受限主张凭空消失」是漏报放大器——办案人会把一句「未发现远程
    配置」当成已穷尽，而真相可能只是求值退化把警示弄丢了。这类退化此前完全在回归护网之外。

    ★只收**方向可判的结构化字段**。``notes``/``why``/``next_actions`` 的文案不入指纹：措辞一改
    全库样本都会被标「有变化」，人很快就不看 regress 输出了，真退化反被淹没。``next_actions``
    只记条数，因为「仍有受限主张、补法建议却归零」是有过先例的缺陷形态（见 pipeline 里可见性
    求值排序那段注释），值得单独看得见。

    ★字段缺失 / None 不得被读成「无受限主张」——那正是本函数要防的误读（同 :func:`advice_counts`
    的 None-vs-{} 教训）。畸形值一律折到 None，表现同「求值丢失」、会被标出而非静默吞掉。
    """
    if not isinstance(report, dict):
        return None
    vis = _meta(report).get("visibility")
    if not isinstance(vis, dict):
        return None
    raw_sources = vis.get("sources")
    sources = raw_sources if isinstance(raw_sources, dict) else {}
    raw_claims = vis.get("claims")
    claims = raw_claims if isinstance(raw_claims, dict) else {}
    blocked = vis.get("blocked_claims")
    actions = vis.get("next_actions")
    return {
        "blocked_claims": sorted(str(b) for b in blocked) if isinstance(blocked, list) else [],
        "sources": {
            str(k): _s(v.get("visibility")) for k, v in sources.items() if isinstance(v, dict)
        },
        # ★「确证盲区」与「未评估」之分也要收：同一条主张从 missing 退成 unassessed 时，
        #   blocked_claims、各源档位、degraded、补法条数可以逐字不变，而 closure 的封顶语义
        #   已经从「记 gap 封顶 partial」松成「只 warn」——办案人那边看到的警示悄悄少了一条。
        #   这两个列表是 sources（已在指纹里）+ 分档语义的派生值，只在该变的时候变，不会刷屏。
        "claims": {
            str(c): {
                "missing_sources": sorted(str(s) for s in (v.get("missing_sources") or [])),
                "unassessed_sources": sorted(str(s) for s in (v.get("unassessed_sources") or [])),
            }
            for c, v in claims.items() if isinstance(v, dict)
        },
        "degraded": bool(vis.get("degraded")),
        "remediation": _s(vis.get("remediation")) or None,
        "next_actions": len(actions) if isinstance(actions, list) else 0,
    }


_REPACK_IDENTITY_VERDICTS = frozenset({"self_built", "repack_suspected", "unknown"})


def _repack_identity_verdict(report: dict) -> str | None:
    """Project only the bounded ownership verdict, never analyzer detail.

    ``meta.repack_identity`` also contains certificate and content-profile
    material.  Linkage needs only the ownership uncertainty gate; copying the
    full object would widen the corpus index and could turn unrelated report
    detail into an accidental feature.
    """
    raw = _meta(report).get("repack_identity")
    if not isinstance(raw, dict):
        return None
    verdict = raw.get("verdict")
    return verdict if isinstance(verdict, str) and verdict in _REPACK_IDENTITY_VERDICTS else None


def manifest_entry(report: dict, case_id: str | None = None) -> dict:
    """把一份 report dict 提炼成一条 manifest 记录（纯函数，坏输入容错，绝不抛）。

    只提取索引/研判/可复现所需字段；报告全文另存于 :func:`report_relpath`。``case_id`` 仅供
    旧 manifest 调用方兼容；新写入以独立 catalog 的 ``case_ids`` 多对多关联为准。另有一对
    非派生的**机器**字段不在本函数里产：
    ``report_bytes_sha256`` / ``report_bytes_sha256_origin`` 由 :func:`add_report`（入库时）或
    :func:`backfill_report_hashes`（事后补录）追加在条目上、:func:`reindex` 按主键照抄继承——
    它们记录的是「哈希是什么时候钉下的」这一历史事实，从报告内容重算不出来（重算得到的是
    "此刻的哈希"，不是"当时的哈希"）。其余字段全部由报告内容决定 → reindex 可全量重建。
    """
    if not isinstance(report, dict):
        report = {}
    meta = _meta(report)
    sha, synthetic = sample_identity(report)
    classification = meta.get("app_classification")
    classification = classification if isinstance(classification, dict) else {}
    domains, cname_edges = _domain_control_iocs(report)
    entry = {
        # ---- 库内主键 ----
        "sample_sha256": sha,
        "sample_sha256_synthetic": synthetic,
        "tool_version": _s(meta.get("tool_version")) or None,
        "ruleset_digest": _s(meta.get("ruleset_digest")) or None,
        # 证据面（static / unpacked）：脱壳前后看到的不是同一批内容，不入主键会丢掉更完整的那份。
        "evidence_surface": evidence_surface(report),
        # ---- 身份 / 版本 ----
        "package_name": _s(report.get("package_name") or meta.get("package_name")) or None,
        "version_name": meta.get("version_name"),
        "version_code": meta.get("version_code"),
        # 依赖版本（androguard 等）复现锚点：不入主键（避免改 corpus 路径 schema 冲击既有证据库），
        # 但登记于此，供 upsert 检出「同主键不同依赖版本」时告警（codex P1，不静默丢 dep 变体报告）。
        "dependency_versions": meta.get("dependency_versions")
        if isinstance(meta.get("dependency_versions"), dict) else None,
        # App .so 家族级硬指纹（列表维度）：供 corpus seen --by so_sha256 一击反查全家族。
        "native_lib_hashes": _native_lib_hashes(report),
        # 自建构建环境标识（列表维度）：.so 名与 sha256 都随机化时仍能串案的锚，见 _build_environments。
        "build_environments": _build_environments(report),
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
        # 证据可见性指纹（None = 该报告没做可见性求值，★不等于「没有受限主张」）。纯追加字段：
        # upsert 按主键幂等跳过，存量行须经 corpus reindex 全量重建才补齐，消费方须把缺字段当未知。
        "visibility": visibility_summary(report),
        # Scope-aware case-level IOC projection marker.  Query paths clear
        # these fields on legacy/unmarked rows until an explicit reindex.
        "case_ioc_scope_indexed": True,
        # ---- 旧单案兼容别名 + 定位 ----
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
        # 域名控制面反查：完整域名与明确观测的 CNAME 边。共享 NS 不在此处自动升级为同控锚点。
        "domains": domains,
        "cname_edges": cname_edges,
        # ---- config-chain 跨样本串联维度（同 OSS 对象 / 同配置内容）----
        "remote_config_objects": _remote_config_objects(report),
    }
    # Omit the field when the analyzer did not produce a bounded verdict.
    # ``unknown`` is an explicit assessed verdict; missing means unassessed and
    # must keep linkage generation partial until the report is re-analysed.
    repack_verdict = _repack_identity_verdict(report)
    if repack_verdict is not None:
        entry["repack_identity_verdict"] = repack_verdict
    return entry


# Public generic manifest replacement may carry caller-owned extension fields,
# but every field emitted by manifest_entry is a projection of immutable report
# bytes and can only be refreshed by add/reindex after digest/scope checks.
_REPORT_DERIVED_MANIFEST_FIELDS = (
    frozenset(manifest_entry({})) | {"repack_identity_verdict"}
) - {
    "case_id",  # legacy/catalog authority has a more specific guard below
    "report_path",  # immutable evidence locator has a specific guard below
}


# ---------------------------------------------------------------------------
# manifest 读写（JSONL；写走原子全量重写，非 append）
# ---------------------------------------------------------------------------


def manifest_path(corpus_dir: str | Path) -> Path:
    """语料库 manifest.jsonl 的完整路径。"""
    return Path(corpus_dir) / MANIFEST_NAME


class ManifestCorruptError(RuntimeError):
    """Raised when a mutation/query would discard malformed manifest facts."""

    def __init__(self, path: Path, diagnostics: list[dict[str, object]]) -> None:
        self.path = path
        self.diagnostics = diagnostics
        details = "; ".join(
            f"line {item.get('line', 0)}: {item.get('reason', 'invalid')}"
            for item in diagnostics
        )
        super().__init__(f"corpus manifest 损坏，拒绝继续 {path}: {details}")


class ManifestStaleError(RuntimeError):
    """Raised when a public manifest CAS would overwrite newer bytes."""


class ManifestIntegrityMutationError(RuntimeError):
    """Raised when generic manifest replacement would rewrite evidence anchors."""


class ManifestAuthorityMutationError(RuntimeError):
    """Raised when generic manifest replacement contradicts catalog authority."""


def _manifest_row_reason(entry: Mapping[str, object]) -> str | None:
    for field in ("sample_sha256", "tool_version", "ruleset_digest"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            return f"manifest {field} 必须是非空字符串"
    raw_path = entry.get("report_path")
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        return "manifest report_path 必须是非空相对路径"
    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ".." in posix_path.parts
        or ".." in windows_path.parts
    ):
        return "manifest report_path 必须留在 corpus 根内"
    path_parts = (
        posix_path.parts
        if posix_path.parts and posix_path.parts[0] == REPORTS_DIR
        else windows_path.parts
    )
    if (
        not path_parts
        or path_parts[0] != REPORTS_DIR
        or not path_parts[-1].endswith(".report.json")
    ):
        return "manifest report_path 必须位于 reports/ 且以 .report.json 结尾"
    if "evidence_surface" in entry and entry.get("evidence_surface") not in {
        _SURFACE_STATIC,
        _SURFACE_UNPACKED,
    }:
        return "manifest evidence_surface 非法"
    legacy_case = entry.get("case_id")
    if legacy_case is not None:
        if not isinstance(legacy_case, str):
            return "manifest case_id 必须是字符串或 null"
        try:
            normalized = corpus_catalog.normalize_case_id(legacy_case)
        except ValueError as exc:
            return f"manifest case_id 非法：{exc}"
        if normalized != legacy_case:
            return "manifest case_id 必须已按 NFC/首尾空白规则规范化"
    if "case_ids" in entry:
        case_ids = entry.get("case_ids")
        if not isinstance(case_ids, list):
            return "manifest case_ids 必须是数组"
        for case_id in case_ids:
            if not isinstance(case_id, str):
                return "manifest case_ids 只能包含字符串"
            try:
                normalized = corpus_catalog.normalize_case_id(case_id)
            except ValueError as exc:
                return f"manifest case_ids 非法：{exc}"
            if normalized != case_id:
                return "manifest case_ids 必须已规范化"
    return None


def _read_manifest_file(path: Path) -> tuple[list[dict], list[dict[str, object]]]:
    if not path.exists():
        return [], []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [], [{"line": 0, "reason": f"{type(exc).__name__}: {exc}"}]
    entries: list[dict] = []
    diagnostics: list[dict[str, object]] = []
    seen_keys: set[tuple[str, ...]] = set()
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(
                line,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
        except (ValueError, RecursionError) as exc:
            diagnostics.append({"line": lineno, "reason": f"不是合法 JSON: {exc}"})
            continue
        if not isinstance(obj, dict):
            diagnostics.append({"line": lineno, "reason": "manifest 行必须是 JSON 对象"})
            continue
        reason = _manifest_row_reason(obj)
        if reason is not None:
            diagnostics.append({"line": lineno, "reason": reason})
            continue
        key = _key_of(obj)
        if key in seen_keys:
            diagnostics.append({"line": lineno, "reason": "manifest 主键重复"})
            continue
        seen_keys.add(key)
        entries.append(obj)
    return entries, diagnostics


def _log_manifest_diagnostics(path: Path, diagnostics: list[dict[str, object]]) -> None:
    for item in diagnostics:
        logger.warning(
            "manifest 第 %s 行损坏：%s：%s",
            item.get("line", 0),
            item.get("reason", "invalid"),
            path,
        )


def load_manifest(corpus_dir: str | Path) -> list[dict]:
    """读 manifest.jsonl → 记录列表。文件不存在 → 空列表；坏行记 warning 跳过、绝不抛。"""
    return load_manifest_file(manifest_path(corpus_dir))


def load_manifest_strict(corpus_dir: str | Path) -> list[dict]:
    """Read the whole derived index or fail; mutations must never skip rows."""
    path = manifest_path(corpus_dir)
    entries, diagnostics = _read_manifest_file(path)
    if diagnostics:
        _log_manifest_diagnostics(path, diagnostics)
        raise ManifestCorruptError(path, diagnostics)
    return entries


def load_manifest_file(path: str | Path) -> list[dict]:
    """按文件路径读一份 JSONL manifest（当前 manifest 或某份快照）→ 记录列表。

    容错语义同 :func:`load_manifest`：不存在 → 空列表；坏行记 warning 跳过、绝不抛。
    独立成函数是为了让快照（.snapshots/ 下的历史 manifest）能用同一套解析口径计数/预览——
    缩减护栏与 restore 的条数比对必须与 load_manifest 同基准，否则「磁盘上有坏行」会被误判成缩减。
    """
    path = Path(path)
    entries, diagnostics = _read_manifest_file(path)
    _log_manifest_diagnostics(path, diagnostics)
    return entries


def manifest_revision(corpus_dir: str | Path) -> str:
    """Hash current manifest bytes, or return ``missing`` without writing."""
    path = manifest_path(corpus_dir)
    if not path.exists():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest_snapshot(corpus_dir: str | Path) -> tuple[list[dict], str]:
    """Return a strict manifest plus the revision required by public save."""
    root = Path(corpus_dir)
    with corpus_catalog.catalog_write_lock(root):
        return load_manifest_strict(root), manifest_revision(root)


# ---------------------------------------------------------------------------
# 写前快照 + 缩减护栏
#
# ★事故形态（2026-07-28，这两道门的存在理由）：一个一次性脚本的替换判据写成「某字段有差异就
#   替换」，而旧版本记录压根没有那个字段——条件恒真；glob 又扫了全部版本而非当前那份。结果
#   28 份跨 4 个工具版本的历史存证被本机一份产物覆盖。语料库在库外（OneDrive）、没有版本控制，
#   事后只能靠「文件名里编的版本号 vs 内容里的 meta.tool_version」比对才定位出污染面。
#   save_manifest 的原子写保证的是「要么旧内容完整、要么新内容完整」，保证不了「新内容是对的」：
#   调用方把 entries 算错，一次调用就抹掉整库。下面把这类不可逆损失变成可逆：
#   ① 缩减护栏——正常操作只增不减，条数变少默认拒写（见 save_manifest / ManifestShrinkError）；
#   ② 写前快照——真写之前把现状逐字节复制进 .snapshots/，可 `fxapk corpus restore` 回滚。
# ---------------------------------------------------------------------------

#: 写前快照目录名（位于语料库根下）。reindex 只扫 reports/、load_manifest 只读 manifest.jsonl，
#: 都不受本目录影响。
SNAPSHOT_DIR = ".snapshots"

#: 快照保留份数。取 50 的理由：
#: · 一次批量 ``corpus add`` 会连环触发写入（每份报告一次 save = 一次快照），历史最大一批是
#:   几十份报告——窗口必须大于常见批量规模，批量结束后「批前状态」才仍在窗口内、没被中间态挤掉；
#: · manifest 目前百级样本、单文件几百 KB，50 份合计不过几十 MB，对 OneDrive 无压力；
#: · 同内容不重复建快照（见 :func:`snapshot_manifest` 去重），窗口不会被无变化的重写刷穿。
SNAPSHOT_KEEP = 50

#: 进程内快照序号：快照文件名的时间戳部分在 Windows 上挂钟粒度约 15.6ms，批量入库连环快照
#: 大概率同刻——若光用时间戳，后一份会**覆盖**前一份、写前状态白拍。名字里再编入 pid + 进程内
#: 递增序号：绝不覆盖已有快照，且同进程内文件名字典序 == 时间序（列表/去重/淘汰都按名字排）。
_SNAPSHOT_SEQ = itertools.count()


class ManifestShrinkError(RuntimeError):
    """save_manifest 缩减护栏：新列表比磁盘现有条数少、且调用方未显式声明 ``allow_shrink``。

    抛出时磁盘分毫未动。错误信息自带现有几条/本次几条/怎么显式缩减。
    """


def snapshot_dir(corpus_dir: str | Path) -> Path:
    """语料库快照目录的完整路径。"""
    return Path(corpus_dir) / SNAPSHOT_DIR


def list_snapshots(corpus_dir: str | Path) -> list[Path]:
    """现有快照文件，新 → 旧。目录不存在/读失败 → 空列表，绝不抛。

    排序按文件名：时间戳定宽 + pid + 进程内序号定宽，字典序即时间序（见 ``_SNAPSHOT_SEQ`` 注释）。
    """
    d = snapshot_dir(corpus_dir)
    try:
        if not d.is_dir():
            return []
        return sorted(
            (p for p in d.glob("manifest-*.jsonl") if p.is_file()),
            key=lambda p: p.name,
            reverse=True,
        )
    except OSError:
        logger.warning("列举快照失败：%s", d, exc_info=True)
        return []


def snapshot_manifest(corpus_dir: str | Path) -> Path | None:
    """把当前 manifest.jsonl 逐字节复制进 ``.snapshots/``，返回代表当前内容的快照路径。

    · manifest 尚不存在（首写）→ None（无可快照，不是失败）。
    · 内容与最新快照逐字节相同 → 不新建，直接返回既有最新快照——防同内容重写把保留窗口
      刷穿、挤掉真正不同的旧状态。
    · 新建后按文件名时间序淘汰到 :data:`SNAPSHOT_KEEP` 份。
    · ★任何失败 → warning + 返回 None，**绝不抛**：快照是保险，保险坏了不该让正事（主写入）
      停下；但必须出声——沉默降级会让人以为有保险，等真出事才发现快照区早就是空的。
      调用方若把快照当前置条件（如 restore 恢复前拍现状），须自查返回值。
    """
    root = Path(corpus_dir)
    src = manifest_path(root)
    try:
        if not src.exists():
            return None
        data = src.read_bytes()
        snaps = list_snapshots(root)
        if snaps:
            try:
                if snaps[0].read_bytes() == data:
                    return snaps[0]  # 内容未变：复用最新快照，不占保留窗口
            except OSError:
                pass  # 最新快照读不出来 → 照常新建，不因保险的保险坏了就不投保
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%f")
        dest = snapshot_dir(root) / (
            f"manifest-{ts}Z-{os.getpid():08d}-{next(_SNAPSHOT_SEQ):06d}.jsonl"
        )
        atomic_write_bytes(dest, data)
        for stale in list_snapshots(root)[SNAPSHOT_KEEP:]:
            try:
                stale.unlink()
            except OSError:
                logger.warning("淘汰过期快照失败（不阻断）：%s", stale, exc_info=True)
        return dest
    except Exception:
        logger.warning(
            "manifest 写前快照失败（主写入继续，但此刻没有保险，请尽快排查）：%s", src, exc_info=True
        )
        return None


def resolve_snapshot(corpus_dir: str | Path, name: str) -> Path | None:
    """按文件名定位一份快照；不存在或名字越出快照目录（路径穿越）→ None。

    ``name`` 来自 CLI 用户输入——与 commands/corpus.py events 对 report_path 的防线同一思路：
    绝不据外部输入读快照目录之外的文件。
    """
    raw = _s(name).strip()
    if not raw:
        return None
    d = snapshot_dir(corpus_dir)
    candidate = d / raw
    try:
        if not candidate.resolve().is_relative_to(d.resolve()):
            return None
    except OSError:
        return None
    return candidate if candidate.is_file() else None


def restore_manifest(corpus_dir: str | Path, snapshot_name: str) -> dict:
    """Restore a manifest snapshot without rolling back catalog annotations."""
    root = Path(corpus_dir)
    try:
        with corpus_catalog.catalog_write_lock(root):
            catalog_rows = corpus_catalog.load_catalog_strict(root)
            return _restore_manifest_locked(root, snapshot_name, catalog_rows)
    except (
        OSError,
        TimeoutError,
        corpus_catalog.CatalogCorruptError,
        ManifestCorruptError,
    ) as exc:
        return {
            "applied": False,
            "error": str(exc),
            "restored_entries": None,
            "current_entries": len(load_manifest(root)),
            "pre_restore_snapshot": None,
        }


def _restore_manifest_locked(
    corpus_dir: str | Path,
    snapshot_name: str,
    catalog_rows: list[dict],
) -> dict:
    """把指定快照恢复为当前 manifest.jsonl，并重新合入 catalog 权威注解。

    dry-run 与 ``--apply`` 确认在 commands 层做；本函数的不变式是**真写之前必给当前状态打快照**——
    否则「恢复」本身就是又一次不可逆的全量覆盖，正是本模块要消灭的那类操作。与
    :func:`snapshot_manifest` 在 save_manifest 里的角色（保险，失败不阻断）不同，这里快照失败
    必须**中止恢复**：恢复是显式的破坏性写入，保险装不上就不该动手。

    Returns:
        ``{"applied": bool, "error": str | None, "restored_entries": int | None,
        "current_entries": int, "pre_restore_snapshot": str | None}``。失败不抛（错误进 error）。
    """
    root = Path(corpus_dir)
    current_rows = load_manifest_strict(root)
    corpus_catalog.assert_manifest_catalog_coverage(
        current_rows, catalog_rows, root
    )
    base: dict = {
        "applied": False,
        "error": None,
        "restored_entries": None,
        "current_entries": len(current_rows),
        "pre_restore_snapshot": None,
    }
    target = resolve_snapshot(root, snapshot_name)
    if target is None:
        return {**base, "error": f"快照不存在或名字越出快照目录：{snapshot_name!r}"}
    try:
        data = target.read_bytes()
    except OSError as exc:
        return {**base, "error": f"读取快照失败：{target}：{exc}"}
    try:
        raw_restored_rows: list[dict] = []
        for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(
                line,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
            if not isinstance(row, dict):
                raise ValueError(f"第 {number} 行不是对象")
            raw_restored_rows.append(row)
        _validate_manifest_entries(raw_restored_rows)
        corpus_catalog.assert_manifest_catalog_coverage(
            raw_restored_rows, catalog_rows, root
        )
        restored_rows = [
            corpus_catalog.materialize(row, catalog_rows)
            for row in raw_restored_rows
        ]
    except (UnicodeError, ValueError, RecursionError, ManifestCorruptError) as exc:
        return {**base, "error": f"快照 manifest 无法解析：{exc}"}
    payload = "\n".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, allow_nan=False)
        for row in restored_rows
    )
    data = (payload + "\n").encode("utf-8") if payload else b""
    pre: Path | None = None
    if manifest_path(root).exists():
        pre = snapshot_manifest(root)
        if pre is None:
            return {**base, "error": "恢复前给当前状态打快照失败，中止恢复（保险装不上就不动手）"}
    try:
        atomic_write_bytes(manifest_path(root), data)
    except OSError as exc:
        return {
            **base,
            "error": f"写入 manifest 失败：{exc}",
            "pre_restore_snapshot": str(pre) if pre else None,
        }
    return {
        **base,
        "applied": True,
        "restored_entries": len(restored_rows),
        "pre_restore_snapshot": str(pre) if pre else None,
    }


def _validate_manifest_entries(entries: list[dict]) -> None:
    diagnostics: list[dict[str, object]] = []
    seen: set[tuple[str, ...]] = set()
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            diagnostics.append({"line": number, "reason": "manifest 行必须是 JSON 对象"})
            continue
        reason = _manifest_row_reason(entry)
        if reason is not None:
            diagnostics.append({"line": number, "reason": reason})
            continue
        key = _key_of(entry)
        if key in seen:
            diagnostics.append({"line": number, "reason": "manifest 主键重复"})
        seen.add(key)
    if diagnostics:
        raise ManifestCorruptError(Path(MANIFEST_NAME), diagnostics)


def _save_manifest_unlocked(
    corpus_dir: str | Path,
    entries: list[dict],
    *,
    catalog_rows: list[dict],
    allow_shrink: bool = False,
) -> None:
    """Lock-internal atomic rewrite; callers already own ``.catalog.lock``."""
    root = Path(corpus_dir)
    current = load_manifest_strict(root)
    corpus_catalog.assert_manifest_catalog_coverage(current, catalog_rows, root)
    catalog_keys = {corpus_catalog.key_of(row) for row in catalog_rows}
    canonical_entries: list[dict] = []
    for entry in entries:
        if _key_of(entry) in catalog_keys:
            canonical_entries.append(corpus_catalog.materialize(entry, catalog_rows))
            continue
        # A genuinely unannotated legacy/orphan row stays legacy.  Writing
        # catalog-era projection fields without a catalog row would make a
        # later catalog loss indistinguishable from intentional absence.
        legacy = dict(entry)
        for field in (
            "case_ids",
            "record_state",
            "record_state_reason",
            corpus_catalog.INGEST_SEQUENCE_FIELD,
            "catalog_authority_materialized",
        ):
            legacy.pop(field, None)
        canonical_entries.append(legacy)
    entries = canonical_entries
    _validate_manifest_entries(entries)
    existing = len(current)
    missing_keys = {_key_of(entry) for entry in current} - {
        _key_of(entry) for entry in entries
    }
    if missing_keys and not allow_shrink:
        raise ManifestShrinkError(
            f"manifest 缩减被拒：本次写入 {len(entries)} 条，磁盘现有 {existing} 条，"
            f"但将丢失 {len(missing_keys)} 个既有主键。正常入库/重建只能保留全部既有主键；"
            f"即使总条数相同，以新记录替换坏/缺旧记录也属于缩减。确认要缩减"
            f"（如删除报告文件后重建索引）：save_manifest(..., allow_shrink=True)，"
            f"CLI 用 fxapk corpus reindex --allow-shrink。"
        )
    payload = "\n".join(
        json.dumps(e, ensure_ascii=False, sort_keys=True, allow_nan=False)
        for e in entries
    )
    if payload:
        payload += "\n"
    # Serialize before making a snapshot: a non-JSON value must be a pure
    # rejection, not a failed mutation that still writes an operational file.
    snapshot_manifest(root)
    atomic_write_text(manifest_path(root), payload)


def save_manifest(
    corpus_dir: str | Path,
    entries: list[dict],
    *,
    allow_shrink: bool = False,
    expected_revision: str | None = None,
) -> None:
    """CAS-rewrite derived fields of the exact current manifest key set.

    Callers first obtain ``(rows, revision)`` from
    :func:`load_manifest_snapshot`.  Generic replacement cannot add/delete
    keys, rewrite report path/digest/origin, alter a legacy ``case_id``, or
    contradict catalog-projected case/state/sequence facts.  Named locked
    workflows own those mutations: :func:`add_report`, :func:`reindex`,
    :func:`backfill_report_hashes`, and catalog state/bind APIs.

    Serialization is validated before the recovery snapshot, then the whole
    JSONL is atomically replaced.  ``allow_shrink`` is retained for internal
    compatibility but does not weaken the public exact-key-set guard.
    """
    if expected_revision is None:
        raise ManifestStaleError(
            "save_manifest requires expected_revision from load_manifest_snapshot"
        )
    root = Path(corpus_dir)
    with corpus_catalog.catalog_write_lock(root):
        current = load_manifest_strict(root)
        current_revision = manifest_revision(root)
        if current_revision != expected_revision:
            raise ManifestStaleError(
                "manifest changed since snapshot: "
                f"expected {expected_revision}, got {current_revision}"
            )
        catalog_rows = corpus_catalog.load_catalog_strict(root)
        corpus_catalog.assert_manifest_catalog_coverage(current, catalog_rows, root)
        _validate_manifest_entries(entries)
        current_by_key = {_key_of(entry): entry for entry in current}
        proposed_by_key = {_key_of(entry): entry for entry in entries}
        if set(current_by_key) != set(proposed_by_key):
            raise ManifestShrinkError(
                "save_manifest 只能替换现有派生字段，不能新增/删除主键；"
                "新增走 add_report，重建/删除走 reindex 的显式路径"
            )
        for key, before in current_by_key.items():
            after = proposed_by_key[key]
            for field in (
                "report_path",
                "report_bytes_sha256",
                "report_bytes_sha256_origin",
            ):
                if before.get(field) != after.get(field):
                    raise ManifestIntegrityMutationError(
                        f"save_manifest 不得改写 {field}；请走命名完整性流程：{key}"
                    )
            for field in _REPORT_DERIVED_MANIFEST_FIELDS:
                if (field in before) != (field in after) or before.get(
                    field
                ) != after.get(field):
                    raise ManifestAuthorityMutationError(
                        "save_manifest 不得改写报告派生索引字段 "
                        f"{field}；请从已核哈希报告走 reindex：{key}"
                    )
            annotation = next(
                (
                    row
                    for row in catalog_rows
                    if corpus_catalog.key_of(row) == key
                ),
                None,
            )
            if annotation is not None:
                expected = corpus_catalog.materialize(after, catalog_rows)
                for field in (
                    "case_ids",
                    "case_id",
                    "record_state",
                    "record_state_reason",
                    corpus_catalog.INGEST_SEQUENCE_FIELD,
                    "catalog_authority_materialized",
                ):
                    if after.get(field) != expected.get(field):
                        raise ManifestAuthorityMutationError(
                            f"save_manifest 的 {field} 与 catalog 权威事实不一致：{key}"
                        )
            elif before.get("case_id") != after.get("case_id"):
                raise ManifestAuthorityMutationError(
                    f"save_manifest 不得改写 legacy case_id；请先走显式迁移/绑定：{key}"
                )
        _save_manifest_unlocked(
            root,
            entries,
            catalog_rows=catalog_rows,
            allow_shrink=allow_shrink,
        )


def upsert(entries: list[dict], entry: dict) -> tuple[list[dict], bool]:
    """按库内主键把 entry 并入 entries（纯函数，不落盘）。

    主键已存在 → **幂等跳过**（保留原记录），返回 added=False；不存在 → 追加，
    返回 added=True。返回新列表（不原地改入参）。
    """
    key = _key_of(entry)
    for e in entries:
        if _key_of(e) == key:
            # ★同主键不同依赖版本（codex P1）：主键 (样本,版本,规则) 不含依赖版本，androguard 小版本变更
            #   可能产出不同报告，幂等跳过会静默丢这份 dep 变体。主键不变（不冲击 corpus 路径 schema），
            #   但此处告警让操作者知悉——需保留变体则手工换 tool_version/另库入库。
            old_dep = e.get("dependency_versions")
            new_dep = entry.get("dependency_versions")
            if old_dep != new_dep:
                logger.warning(
                    "corpus 幂等跳过：同主键 %s 但依赖版本不同（库内 %s / 本次 %s）——"
                    "该依赖变体报告未入库", key, old_dep, new_dep,
                )
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
    """Store immutable report bytes and atomically union explicit case bindings.

    A corpus-wide catalog lock serializes the report -> catalog -> derived
    manifest write order.  It prevents two processes binding different cases
    (or ingesting different reports) from losing one another's updates.
    """
    # Validate every value that would enter the key/catalog before the lock
    # creates even its operational sidecar, and before any evidence path can
    # be created.  Legacy reports may use a synthetic sample id, but a corpus
    # revision without tool/rules anchors is not reproducible.
    if case_id is not None:
        corpus_catalog.normalize_case_id(case_id)
    raw_text.encode("utf-8")
    parsed_report = _strict_json_object(raw_text)
    if not _same_json_value(parsed_report, report):
        raise ValueError("report 参数与 raw_text 解析结果不一致，拒绝存证")
    preview = manifest_entry(parsed_report)
    key = _key_of(preview)
    if not key[1] or not key[2]:
        raise ValueError("report 缺少 tool_version/ruleset_digest，拒绝入库")
    for component in key:
        component.encode("utf-8")
    with corpus_catalog.catalog_write_lock(corpus_dir):
        return _add_report_locked(corpus_dir, parsed_report, raw_text, case_id=case_id)


def _create_report_exclusive(path: Path, data: bytes) -> bool:
    """Create evidence bytes only if the target does not already exist.

    Returns ``False`` on an existence race so the caller can re-read and
    compare.  Complete bytes are fsynced under a unique same-directory name
    before an atomic no-replace publication; the canonical path is never
    streamed into and therefore cannot become a permanent crash remnant.
    """
    return atomic_create_bytes(path, data)


def _add_report_locked(
    corpus_dir: str | Path,
    report: dict,
    raw_text: str,
    *,
    case_id: str | None,
) -> dict:
    """Implementation of :func:`add_report`; caller holds catalog lock."""
    root = Path(corpus_dir)
    normalized_case = corpus_catalog.normalize_case_id(case_id) if case_id is not None else None
    entry = manifest_entry(report)
    incoming_bytes = raw_text.encode("utf-8")
    incoming_hash = hashlib.sha256(incoming_bytes).hexdigest()
    entry["report_bytes_sha256"] = incoming_hash
    entry["report_bytes_sha256_origin"] = HASH_ORIGIN_INGEST
    catalog_rows = corpus_catalog.load_catalog_strict(root)
    manifest_entries = load_manifest_strict(root)
    corpus_catalog.assert_manifest_catalog_coverage(
        manifest_entries, catalog_rows, root
    )
    entries = [
        corpus_catalog.materialize(item, catalog_rows) for item in manifest_entries
    ]
    manifest_needs_refresh = entries != manifest_entries
    key = _key_of(entry)
    existing = next((item for item in entries if _key_of(item) == key), None)
    raw_existing = next(
        (item for item in manifest_entries if _key_of(item) == key),
        None,
    )
    catalog_has_key = any(corpus_catalog.key_of(item) == key for item in catalog_rows)

    # A duplicate key is idempotent only when the immutable report bytes are
    # identical.  Do not silently bind a changed report to another case.
    if existing is not None:
        conflict_reason = _stored_report_conflict(root, existing, incoming_bytes)
        if conflict_reason == "stored_report_hash_missing" and not catalog_has_key:
            # Explicitly adopting a true pre-catalog/reindex orphan is the one
            # safe exception to the three-way recorded-hash rule: compare the
            # actual immutable bytes to the caller's strict raw JSON, then pin
            # a backfill baseline now.  A managed catalog row with a missing
            # hash remains a hard conflict (it may have been tampered with).
            stored_path = resolve_report_file(root, _s(existing.get("report_path")))
            try:
                stored_bytes = stored_path.read_bytes() if stored_path is not None else None
            except OSError:
                stored_bytes = None
            if stored_bytes == incoming_bytes:
                conflict_reason = None
                refreshed_entries: list[dict] = []
                for candidate in entries:
                    updated = dict(candidate)
                    if _key_of(updated) == key:
                        updated["report_bytes_sha256"] = incoming_hash
                        updated["report_bytes_sha256_origin"] = HASH_ORIGIN_BACKFILL
                        existing = updated
                    refreshed_entries.append(updated)
                entries = refreshed_entries
                manifest_needs_refresh = True
        if conflict_reason is not None:
            return {
                "added": False,
                "report_path": existing.get("report_path") or entry["report_path"],
                "key": list(key),
                "synthetic": entry.get("sample_sha256_synthetic", False),
                "collision": False,
                "content_conflict": True,
                "conflict_reason": conflict_reason,
                "case_bound": False,
            }

    catalog_changed = False
    if existing is not None and not catalog_has_key and raw_existing is not None:
        # Compatibility migration: before adding a second case, preserve any
        # true pre-catalog single ``case_id``.  Catalog-era ``case_ids`` are a
        # derived projection and must never be promoted after catalog loss or
        # manifest tampering.
        legacy_case = raw_existing.get("case_id")
        if "case_ids" not in raw_existing and isinstance(legacy_case, str) and legacy_case.strip():
            try:
                catalog_rows, migrated = corpus_catalog.bind_case_in_memory(
                    catalog_rows, key, legacy_case
                )
            except ValueError:
                logger.warning("忽略 manifest 中无效的 legacy case_id：%r", legacy_case)
            else:
                catalog_changed = catalog_changed or migrated
    # Only a key first indexed by this transaction gets an ingest sequence.
    # A legacy/reindexed row has already lost its original order; assigning
    # max+1 during a later bind/adoption would falsely call it the newest run.
    if existing is None:
        catalog_rows, sequence_added = corpus_catalog.ensure_ingest_sequence_in_memory(
            catalog_rows, key
        )
        catalog_changed = catalog_changed or sequence_added
    case_bound = False
    if normalized_case is not None:
        catalog_rows, case_bound = corpus_catalog.bind_case_in_memory(
            catalog_rows, key, normalized_case
        )
        catalog_changed = catalog_changed or case_bound
    entry = corpus_catalog.materialize(entry, catalog_rows)
    new_entries, added = upsert(entries, entry)
    report_path = entry["report_path"]
    base = {
        "report_path": report_path,
        "key": list(key),
        "synthetic": entry.get("sample_sha256_synthetic", False),
    }

    if added:
        report_file = resolve_report_file(root, report_path)
        if report_file is None:
            return {
                **base,
                "added": False,
                "collision": True,
                "content_conflict": True,
                "conflict_reason": "target_report_path_outside_corpus",
                "case_bound": False,
            }
        if report_file.exists():
            try:
                on_disk = report_file.read_bytes()
            except OSError as exc:
                logger.warning("路径碰撞目标无法读取，拒绝覆盖：%s：%s", report_path, exc)
                return {
                    **base,
                    "added": False,
                    "collision": True,
                    "content_conflict": True,
                    "conflict_reason": "target_report_unreadable",
                    "case_bound": False,
                }
            if on_disk != incoming_bytes:
                logger.warning(
                    "路径碰撞：%s 已存在且字节不同（不同主键净化后同路径），拒绝覆盖已入库证据", report_path
                )
                return {
                    **base,
                    "added": False,
                    "collision": True,
                    "content_conflict": True,
                    "conflict_reason": "target_report_bytes_differ",
                    "case_bound": False,
                }
        else:
            created = _create_report_exclusive(report_file, incoming_bytes)
            if not created:
                # Another process outside the corpus lock created this exact
                # target after exists().  Never overwrite it; re-read and only
                # adopt identical bytes.
                try:
                    raced_bytes = report_file.read_bytes()
                except OSError:
                    return {
                        **base,
                        "added": False,
                        "collision": True,
                        "content_conflict": True,
                        "conflict_reason": "target_report_unreadable",
                        "case_bound": False,
                    }
                if raced_bytes != incoming_bytes:
                    return {
                        **base,
                        "added": False,
                        "collision": True,
                        "content_conflict": True,
                        "conflict_reason": "target_report_bytes_differ",
                        "case_bound": False,
                    }
        # Evidence bytes now exist unchanged.  Re-resolve immediately before
        # indexing: if a parent link changed after the pre-check, the manifest
        # must not certify a different path.  Writes use the first resolved
        # absolute target, so a link swap cannot redirect the write outside.
        final_report_file = resolve_report_file(root, report_path)
        if final_report_file != report_file:
            return {
                **base,
                "added": False,
                "collision": True,
                "content_conflict": True,
                "conflict_reason": "target_report_path_changed_before_index",
                "case_bound": False,
            }
        try:
            if report_file.read_bytes() != incoming_bytes:
                return {
                    **base,
                    "added": False,
                    "collision": True,
                    "content_conflict": True,
                    "conflict_reason": "target_report_changed_before_index",
                    "case_bound": False,
                }
        except OSError:
            return {
                **base,
                "added": False,
                "collision": True,
                "content_conflict": True,
                "conflict_reason": "target_report_unreadable",
                "case_bound": False,
            }
        # Evidence first, then the non-derived catalog, then the rebuildable
        # manifest.  A crash can leave an orphan report, never a false index.
        if catalog_changed:
            corpus_catalog._save_catalog_unlocked(root, catalog_rows)
        _save_manifest_unlocked(root, new_entries, catalog_rows=catalog_rows)
        logger.info("入库：%s（case=%s）", report_path, normalized_case or "-")
    else:
        if catalog_changed:
            corpus_catalog._save_catalog_unlocked(root, catalog_rows)
        if catalog_changed or manifest_needs_refresh:
            refreshed = [corpus_catalog.materialize(item, catalog_rows) for item in entries]
            _save_manifest_unlocked(root, refreshed, catalog_rows=catalog_rows)
        logger.info("已在库，幂等跳过：%s", report_path)

    return {
        **base,
        "added": added,
        "collision": False,
        "content_conflict": False,
        "case_bound": case_bound,
    }


def reindex(corpus_dir: str | Path, *, allow_shrink: bool = False) -> list[dict]:
    """Rebuild the derived manifest under the catalog mutation lock."""
    with corpus_catalog.catalog_write_lock(corpus_dir):
        return _reindex_locked(corpus_dir, allow_shrink=allow_shrink)


def _reindex_locked(corpus_dir: str | Path, *, allow_shrink: bool = False) -> list[dict]:
    """扫 reports/ 下全部 *.report.json 全量重建 manifest，并写回。

    manifest 是缓存不是事实源：本函数从报告重算每条记录，案件关联/隔离状态从独立 catalog
    合入；旧 manifest 的单值 case_id 只作迁移兼容。完整性哈希
    （report_bytes_sha256/…origin）仍按主键继承。坏报告（无法解析）记 warning 跳过；路径越界、
    重复主键或已有入库哈希不符则拒绝整个重建。

    ★完整性哈希必须**照抄**、绝不按当前文件字节重算：重算 = 把此刻的内容重新钉成基准——若
    文件在重建前已被篡改，重算会把篡改「洗白」。同主键已有哈希时，本函数先比当前真实字节；
    不符即拒绝重建，因此也不会拿篡改内容刷新 ``key_iocs/domains`` 等派生索引。篡改若改变主键，
    默认 key-set 单调门同样拒绝旧主键消失。旧记录没有哈希则保持 unverifiable，不发明历史基准。

    ★缩减语义：重建条数少于现有 manifest 时，默认被 save_manifest 的缩减护栏拒绝
    （抛 :class:`ManifestShrinkError`，manifest 分毫未动）。条数变少只有两种可能：报告文件真被
    删了（合法，显式传 ``allow_shrink=True`` / CLI ``--allow-shrink`` 自证故意），或**报告读不
    出来**——语料库在 OneDrive 上，文件未按需下载（占位符）/同步中断时读取会失败，上面那句
    「坏报告记 warning 跳过」就会把这些样本静默丢出索引。默认拒绝防的正是这后一种：
    warning 会刷屏而过，条数护栏会硬停。

    Raises:
        ManifestShrinkError: 重建条数少于现有 manifest 且未显式 ``allow_shrink=True``。
    """
    root = Path(corpus_dir)
    reports_root = root / REPORTS_DIR
    catalog_rows = corpus_catalog.load_catalog_strict(root)

    # 旧单值 case_id 仅作迁移兼容；完整性哈希仍是不能由当前报告重算的历史事实。
    old_case: dict[tuple[str, ...], str] = {}
    old_hash: dict[tuple[str, ...], tuple[str, str | None]] = {}
    old_hash_by_path: dict[Path, str] = {}
    current_manifest = load_manifest_strict(root)
    corpus_catalog.assert_manifest_catalog_coverage(
        current_manifest, catalog_rows, root
    )
    for e in current_manifest:
        key = _key_of(e)
        cid = e.get("case_id")
        if cid:
            old_case[key] = cid
        recorded = _s(e.get("report_bytes_sha256")).strip()
        if recorded:
            old_hash[key] = (recorded, _s(e.get("report_bytes_sha256_origin")).strip() or None)
            resolved_old_path = resolve_report_file(
                root, _s(e.get("report_path")).strip()
            )
            if resolved_old_path is not None:
                old_hash_by_path[resolved_old_path] = recorded

    entries: list[dict] = []
    seen_report_keys: dict[tuple[str, ...], Path] = {}
    if reports_root.exists():
        for report_file in sorted(reports_root.rglob("*.report.json")):
            rel = report_file.relative_to(root).as_posix()
            safe_report_file = resolve_report_file(root, rel)
            if safe_report_file is None:
                raise ManifestCorruptError(
                    manifest_path(root),
                    [{"line": 0, "reason": f"reports/ 候选路径越出 corpus：{rel}"}],
                )
            try:
                report_bytes = safe_report_file.read_bytes()
                path_recorded = old_hash_by_path.get(safe_report_file)
                if (
                    path_recorded is not None
                    and hashlib.sha256(report_bytes).hexdigest() != path_recorded
                ):
                    raise ManifestCorruptError(
                        manifest_path(root),
                        [
                            {
                                "line": 0,
                                "reason": (
                                    "reindex 拒绝消费与该路径既有入库哈希不符的报告："
                                    f"{rel}"
                                ),
                            }
                        ],
                    )
                report = json.loads(
                    report_bytes.decode("utf-8"),
                    parse_constant=_reject_json_constant,
                    parse_float=_parse_finite_float,
                )
            except ManifestCorruptError:
                raise
            except (OSError, UnicodeError, ValueError, RecursionError):
                # ValueError 含 JSONDecodeError + UnicodeDecodeError；一个坏文件不得让自愈工具崩。
                logger.warning("reindex 跳过无法解析的报告：%s", report_file)
                continue
            if not isinstance(report, dict):
                logger.warning("reindex 跳过非 dict 报告：%s", report_file)
                continue
            entry = manifest_entry(report)
            entry_key = _key_of(entry)
            previous_path = seen_report_keys.get(entry_key)
            if previous_path is not None:
                raise ManifestCorruptError(
                    manifest_path(root),
                    [
                        {
                            "line": 0,
                            "reason": (
                                "reports/ 中多个文件声明同一 manifest 主键："
                                f"{previous_path} / {report_file}"
                            ),
                        }
                    ],
                )
            seen_report_keys[entry_key] = report_file
            # reindex 的路径事实来自本次实际扫描到的库内文件；旧版可能把 unpacked 内容写进
            # 无 ``_unpacked`` 后缀的文件名，按元数据重新推导会制造 missing + orphan 假象。
            entry["report_path"] = rel
            carried = old_case.get(entry_key)
            if carried:
                entry["case_id"] = carried
            # ★哈希照抄不重算（洗白风险见函数 docstring）；旧记录没有哈希则新记录也没有——
            #   reindex 不发明完整性基准，补录是 backfill_report_hashes 的显式职责。
            carried_hash = old_hash.get(entry_key)
            if carried_hash:
                actual_hash = hashlib.sha256(report_bytes).hexdigest()
                if actual_hash != carried_hash[0]:
                    raise ManifestCorruptError(
                        manifest_path(root),
                        [
                            {
                                "line": 0,
                                "reason": (
                                    "reindex 拒绝消费与既有入库哈希不符的报告："
                                    f"{rel}"
                                ),
                            }
                        ],
                    )
                entry["report_bytes_sha256"] = carried_hash[0]
                entry["report_bytes_sha256_origin"] = carried_hash[1]
            entries.append(corpus_catalog.materialize(entry, catalog_rows))

    _save_manifest_unlocked(
        root,
        entries,
        catalog_rows=catalog_rows,
        allow_shrink=allow_shrink,
    )
    logger.info("reindex 完成：%d 条记录", len(entries))
    return entries


# ---------------------------------------------------------------------------
# 完整性自证：verify（只读校验）+ backfill（存量补录）
#
# 防的不是"绕过 API 直接写文件"本身——语料库就是一个普通目录，那永远防不住——而是让这种
# 篡改**可检测**：manifest（及其 .snapshots/ 历史）记着每份存证入库那一刻的字节哈希，改过
# 就对不上。走 API 的路径本已安全（add_report 幂等 + 碰撞守卫，库内报告没有合法改写路径），
# 这两个函数补的是 API 之外那条路的检测面。
# ---------------------------------------------------------------------------


def resolve_report_file(root: str | Path, rel: str) -> Path | None:
    """按 manifest 的 report_path 定位 ``reports/`` 内文件；越界 → None。

    manifest 是可重建的派生缓存、非路径权威（与 commands 层 events 命令的防线同一思路）：
    绝不据一条可能被编辑过的记录读语料库之外的文件。返回解析后的绝对路径，避免校验后
    又用未解析路径读取而被可替换的符号链接带出根目录。
    """
    rel = _s(rel).strip()
    if not rel:
        return None
    posix_path = PurePosixPath(rel)
    windows_path = PureWindowsPath(rel)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ".." in posix_path.parts
        or ".." in windows_path.parts
    ):
        return None
    parts = (
        posix_path.parts
        if posix_path.parts and posix_path.parts[0] == REPORTS_DIR
        else windows_path.parts
    )
    if (
        not parts
        or parts[0] != REPORTS_DIR
        or not parts[-1].endswith(".report.json")
    ):
        return None
    root_path = Path(root)
    candidate = root_path / rel
    try:
        root_resolved = root_path.resolve()
        reports_resolved = (root_resolved / REPORTS_DIR).resolve()
        resolved = candidate.resolve()
        if (
            not reports_resolved.is_relative_to(root_resolved)
            or not resolved.is_relative_to(reports_resolved)
        ):
            return None
    except OSError:
        return None
    return resolved


def load_stored_report_checked(
    root: str | Path, entry: Mapping[str, object]
) -> tuple[dict | None, str]:
    """Read one indexed report with path, digest and strict-JSON checks.

    Modern rows with ``report_bytes_sha256`` fail closed on a byte mismatch.
    A true legacy row without a recorded digest remains readable for backward
    compatibility, but callers must not describe that row as integrity-verified.
    """
    report_file = resolve_report_file(root, _s(entry.get("report_path")))
    if report_file is None or not report_file.is_file():
        return None, "report_path missing or outside corpus reports root"
    try:
        data = report_file.read_bytes()
    except OSError as exc:
        return None, f"cannot read stored report: {exc}"
    recorded = _s(entry.get("report_bytes_sha256")).strip().lower()
    if recorded and hashlib.sha256(data).hexdigest() != recorded:
        return None, "stored report bytes do not match report_bytes_sha256"
    try:
        decoded = data.decode("utf-8")
        report = json.loads(
            decoded,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        return None, f"stored report is not strict JSON: {exc}"
    if not isinstance(report, dict):
        return None, "stored report top level must be an object"
    return report, ""


def _stored_report_conflict(root: Path, entry: Mapping[str, object], incoming: bytes) -> str | None:
    """Validate manifest hash, actual stored bytes, and incoming bytes together."""
    report_file = resolve_report_file(root, _s(entry.get("report_path")))
    if report_file is None or not report_file.is_file():
        return "stored_report_missing_or_unreadable"
    try:
        stored = report_file.read_bytes()
    except OSError:
        return "stored_report_missing_or_unreadable"
    stored_hash = hashlib.sha256(stored).hexdigest()
    recorded = _s(entry.get("report_bytes_sha256")).strip()
    if not recorded:
        return "stored_report_hash_missing"
    if stored_hash != recorded:
        return "stored_report_hash_mismatch"
    if stored != incoming:
        return "incoming_report_bytes_differ"
    return None


def verify_reports(corpus_dir: str | Path) -> dict:
    """逐条校验存证完整性（只读，不写任何文件）。

    损坏的 manifest/catalog 会 fail closed 抛出明确的 corrupt 异常；CLI 将其转换为结构化非零
    结果。只有一条合法索引对应的报告缺失/不可读时才进入下列逐条状态，而不是跳过坏索引伪装全绿。

    每条 manifest 记录归入且仅归入一档。★"文件读得到"的三种情形必须严格分开——把
    unverifiable 折进 ok，等于替一批无从验证的文件背书；把读失败折进 ok 同理：

      · ``ok``           —— 有记录哈希，且文件当前字节与之相符。origin 决定这句话覆盖多长的
                            历史：ingest 覆盖整个库内生命期，backfill 只覆盖补录之后。
      · ``mismatch``     —— 有记录哈希但对不上：文件在库内被改过，要报警。
      · ``unverifiable`` —— 没有记录哈希（完整性功能之前的存量记录）：无从验起，
                            **不等于验过没问题**。
      · ``missing``      —— 文件取不到：不存在 / report_path 越出库根 / 读失败。OneDrive 未按
                            需下载也落这档——宁可误报，也不把「读不到」静默当「没问题」。

    另扫 reports/ 下全部 ``*.report.json`` 找 ``orphan``（有文件、manifest 无记录）：那是绕过
    add_report 直接落盘的产物或索引丢条，两种都该有人看。范围与 :func:`reindex` 的扫描口径
    一致，故 reports/ 下的其它制品（如 remote_config/ 落盘的配置对象）不会被误报成 orphan。

    Returns:
        ``{"counts": {ok, mismatch, unverifiable, missing, orphan}, "ok_by_origin": {...},
        "entries": [每条 manifest 记录一行], "orphans": [库内相对路径]}``。
    """
    root = Path(corpus_dir)
    counts = {VERIFY_OK: 0, VERIFY_MISMATCH: 0, VERIFY_UNVERIFIABLE: 0, VERIFY_MISSING: 0}
    ok_by_origin: dict[str, int] = {}
    rows: list[dict] = []
    referenced: set[Path] = set()
    # Integrity verification includes the non-derived catalog.  A missing or
    # corrupt case/quarantine/ingest-order row is itself an integrity failure;
    # verifying only report bytes would otherwise return a misleading green.
    for e in load_materialized_manifest(root):
        rel = _s(e.get("report_path")).strip()
        recorded = _s(e.get("report_bytes_sha256")).strip().lower() or None
        # origin 只在有哈希时才有意义；有哈希却没标来源（手编 manifest）→ "unknown"，不猜。
        origin = (_s(e.get("report_bytes_sha256_origin")).strip() or "unknown") if recorded else None
        row: dict[str, Any] = {
            "sample_sha256": _s(e.get("sample_sha256")) or None,
            "report_path": rel or None,
            "origin": origin,
            "recorded_sha256": recorded,
        }
        target = resolve_report_file(root, rel)
        if target is not None:
            try:
                referenced.add(target.resolve())
            except OSError:
                pass
        data: bytes | None = None
        if target is None:
            row |= {
                "status": VERIFY_MISSING,
                "reason": "report_path 缺失或越出语料库根（索引坏条可 corpus reindex 自愈）",
            }
        elif not target.is_file():
            row |= {"status": VERIFY_MISSING, "reason": "manifest 有记录但文件不在"}
        else:
            try:
                data = target.read_bytes()
            except OSError as exc:
                row |= {"status": VERIFY_MISSING, "reason": f"文件读取失败（OneDrive 未下载/权限？）：{exc}"}
        if data is not None:
            if recorded is None:
                row |= {
                    "status": VERIFY_UNVERIFIABLE,
                    "reason": "manifest 未记录内容哈希（存量记录）——没法验，不等于验过没问题；"
                              "corpus backfill-hash 可补录（只证明补录起点之后）",
                }
            else:
                actual = hashlib.sha256(data).hexdigest()
                if actual == recorded:
                    row["status"] = VERIFY_OK
                    ok_by_origin[origin or "unknown"] = ok_by_origin.get(origin or "unknown", 0) + 1
                else:
                    row |= {"status": VERIFY_MISMATCH, "actual_sha256": actual}
        counts[row["status"]] += 1
        rows.append(row)

    orphans: list[str] = []
    reports_root = root / REPORTS_DIR
    try:
        if reports_root.is_dir():
            for f in sorted(reports_root.rglob("*.report.json")):
                try:
                    if f.is_file() and f.resolve() not in referenced:
                        orphans.append(f.relative_to(root).as_posix())
                except OSError:
                    logger.warning("orphan 扫描无法处理文件，跳过：%s", f, exc_info=True)
    except OSError:
        logger.warning("orphan 扫描失败：%s", reports_root, exc_info=True)

    return {
        "counts": {**counts, VERIFY_ORPHAN: len(orphans)},
        "ok_by_origin": ok_by_origin,
        "entries": rows,
        "orphans": orphans,
    }


def backfill_report_hashes(corpus_dir: str | Path) -> dict:
    """Backfill under the catalog lock so derived annotations cannot regress."""
    root = Path(corpus_dir)
    try:
        with corpus_catalog.catalog_write_lock(root):
            return _backfill_report_hashes_locked(root)
    except (
        OSError,
        TimeoutError,
        corpus_catalog.CatalogCorruptError,
        ManifestCorruptError,
    ) as exc:
        return {
            "total": len(load_manifest(root)),
            "already_hashed": 0,
            "backfilled": 0,
            "unreadable": [],
            "written": False,
            "error": f"写入 manifest 失败：{exc}",
        }


def _backfill_report_hashes_locked(corpus_dir: str | Path) -> dict:
    """给没有内容哈希的存量记录按**当前**文件字节补算哈希并回填 manifest。执行层：被调用即真写
    （dry-run 与 ``--apply`` 确认在 commands 层做，同 :func:`restore_manifest` 的分工）。

    ★★证据边界（本函数最重要的一条）：补录哈希以补录那一刻的文件内容为基准，只能证明
    「从补录起」未被改动，**不能**追溯证明补录之前没被改过——若文件在补录前已被篡改，
    补录会把篡改后的内容钉成基准、verify 从此恒 ok。因此：

      ① 回填一律打 ``origin="backfill"``，与入库哈希（ingest）在 manifest 与 verify 输出里
         都不同貌——不打标记，就是在给一批来历不明的哈希发"入库即验"的合格证；
      ② 已有哈希的记录（无论 ingest 还是 backfill）**绝不重算覆盖**：覆盖 = 销毁旧基准，
         恰好抹掉 mismatch 本可揭发的篡改。

    文件取不到的记录原样保留（仍 unverifiable），逐条列入返回值——补不上要说出来，
    静默跳过会让人以为补齐了。

    写 manifest 条数不变：缩减护栏放行、写前快照照常触发（补录前的 manifest 状态可回滚，
    快照文件名的时间戳顺带钉住了"补录发生在何时"）。

    Returns:
        ``{"total": int, "already_hashed": int, "backfilled": int, "unreadable": [...],
        "written": bool, "error": str | None}``。绝不抛（写失败进 error）。
    """
    root = Path(corpus_dir)
    catalog_rows = corpus_catalog.load_catalog_strict(root)
    current_manifest = load_manifest_strict(root)
    corpus_catalog.assert_manifest_catalog_coverage(
        current_manifest, catalog_rows, root
    )
    entries = [
        corpus_catalog.materialize(entry, catalog_rows) for entry in current_manifest
    ]
    new_entries: list[dict] = []
    backfilled = 0
    already = 0
    unreadable: list[dict] = []
    for e in entries:
        if _s(e.get("report_bytes_sha256")).strip():
            already += 1
            new_entries.append(e)
            continue
        target = resolve_report_file(root, _s(e.get("report_path")))
        data: bytes | None = None
        if target is not None and target.is_file():
            try:
                data = target.read_bytes()
            except OSError:
                data = None
        if data is None:
            unreadable.append({
                "sample_sha256": _s(e.get("sample_sha256")) or None,
                "report_path": _s(e.get("report_path")) or None,
            })
            new_entries.append(e)
            continue
        new_entries.append({
            **e,
            "report_bytes_sha256": hashlib.sha256(data).hexdigest(),
            "report_bytes_sha256_origin": HASH_ORIGIN_BACKFILL,
        })
        backfilled += 1

    base = {
        "total": len(entries),
        "already_hashed": already,
        "unreadable": unreadable,
        "written": False,
        "error": None,
    }
    if not backfilled:
        return {**base, "backfilled": 0}
    try:
        # 条数不变 → 缩减护栏放行；真写前自动拍快照（补录前状态可回滚）。
        _save_manifest_unlocked(root, new_entries, catalog_rows=catalog_rows)
    except (OSError, ManifestShrinkError) as exc:
        return {**base, "backfilled": 0, "error": f"写入 manifest 失败：{exc}"}
    return {**base, "backfilled": backfilled, "written": True}


_RECONCILE_STATUSES: tuple[str, ...] = (
    "in_sync",
    "missing_record",
    "case_unbound",
    "content_conflict",
    "quarantined",
    "invalid_report",
)


def _reconcile_record_status(
    root: Path,
    entries: list[dict],
    key: tuple[str, ...],
    case_id: str,
    incoming_bytes: bytes,
) -> tuple[str, str | None]:
    existing = next((candidate for candidate in entries if _key_of(candidate) == key), None)
    if existing is None:
        return "missing_record", None
    conflict_reason = _stored_report_conflict(root, existing, incoming_bytes)
    if conflict_reason is not None:
        return "content_conflict", conflict_reason
    if existing.get("record_state") == corpus_catalog.RECORD_QUARANTINED:
        return "quarantined", None
    case_ids = existing.get("case_ids")
    bound_cases = (
        {_s(value) for value in case_ids}
        if isinstance(case_ids, list)
        else {_s(existing.get("case_id"))}
    )
    if case_id not in bound_cases:
        return "case_unbound", None
    return "in_sync", None


def _case_package_inventory_row(package_path: Path) -> tuple[dict[str, object] | None, str]:
    """Verify a Phase-1 package and project its sole hashed report artifact."""
    from apkscan.core.case_package import verify_case_package

    try:
        before = package_path.read_bytes()
    except OSError as exc:
        return None, f"cannot read case package: {type(exc).__name__}"
    checked = verify_case_package(package_path)
    try:
        after = package_path.read_bytes()
    except OSError as exc:
        return None, f"cannot reread case package: {type(exc).__name__}"
    if before != after:
        return None, "case package changed during verification"
    if checked.get("status") != "verified":
        issues = checked.get("issues")
        details = "; ".join(str(item) for item in issues) if isinstance(issues, list) else ""
        return None, details or "case package integrity verification failed"
    try:
        payload = json.loads(
            after.decode("utf-8"),
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
        if not isinstance(payload, dict):
            raise ValueError("case package root must be an object")
        raw_case_id = payload.get("case_id")
        if not isinstance(raw_case_id, str):
            raise ValueError("case package case_id must be a string")
        case_id = corpus_catalog.normalize_case_id(raw_case_id)
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("case package artifacts must be an array")
        reports = [
            item
            for item in artifacts
            if isinstance(item, dict) and item.get("kind") == "report"
        ]
        if len(reports) != 1:
            raise ValueError(f"case package must contain one report artifact, found {len(reports)}")
        artifact = reports[0]
        rel = artifact.get("path")
        if not isinstance(rel, str) or not rel:
            raise ValueError("case package report artifact path is missing")
        candidate = Path(rel)
        if candidate.is_absolute():
            raise ValueError("case package report artifact path is absolute")
        package_root = package_path.parent.resolve()
        report_path = (package_root / candidate).resolve()
        if not report_path.is_relative_to(package_root):
            raise ValueError("case package report artifact escapes package root")
        expected_hash = artifact.get("sha256")
        expected_size = artifact.get("size")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ValueError("case package report artifact sha256 is invalid")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            raise ValueError("case package report artifact size is invalid")
        report_bytes = report_path.read_bytes()
        if len(report_bytes) != expected_size:
            raise ValueError("case package report artifact size changed after verification")
        if hashlib.sha256(report_bytes).hexdigest() != expected_hash:
            raise ValueError("case package report artifact hash changed after verification")
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        return None, str(exc) or type(exc).__name__
    return {
        "case_id": case_id,
        "report_path": str(report_path),
        "_artifact_sha256": expected_hash,
        "_artifact_size": expected_size,
        "package_id": checked.get("package_id"),
    }, ""


def reconcile_inventory(
    corpus_dir: str | Path,
    inventory_path: str | Path,
    *,
    apply: bool = False,
) -> dict:
    """Compare an explicit Phase-1 JSONL inventory with the external corpus.

    Each line is ``{"case_id": "...", "report_path": "..."}``.  Relative
    report paths are resolved beside the inventory.  Missing case ids are
    invalid; directory names and list positions are never used as fallbacks.
    The default is a read-only plan.  ``apply=True`` may add immutable reports
    or add a case binding, but never overwrites, unquarantines, or deletes.
    """
    root = Path(corpus_dir)
    inventory = Path(inventory_path)
    counts = {status: 0 for status in _RECONCILE_STATUSES}
    items: list[dict[str, object]] = []
    added = bound = 0
    input_kind = "inventory_jsonl"
    try:
        input_text = inventory.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {
            "input_kind": input_kind,
            "applied": apply,
            "added": 0,
            "case_bound": 0,
            "counts": {**counts, "invalid_report": 1},
            "items": [{"line": 0, "status": "invalid_report", "reason": type(exc).__name__}],
        }
    package_like = False
    try:
        whole = json.loads(
            input_text,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
        package_like = isinstance(whole, dict) and (
            whole.get("phase") == "phase1"
            or "package_id" in whole
            or "artifacts" in whole
        )
    except (ValueError, RecursionError):
        pass
    if package_like:
        input_kind = "case_package"
        package_row, package_error = _case_package_inventory_row(inventory)
        if package_row is None:
            counts["invalid_report"] = 1
            return {
                "input_kind": input_kind,
                "applied": apply,
                "added": 0,
                "case_bound": 0,
                "counts": counts,
                "items": [
                    {"line": 1, "status": "invalid_report", "reason": package_error}
                ],
            }
        lines = [json.dumps(package_row, ensure_ascii=False, allow_nan=False)]
    else:
        lines = input_text.splitlines()

    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        item: dict[str, object] = {"line": line_number}
        try:
            row = json.loads(
                line,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
            if not isinstance(row, dict):
                raise ValueError("inventory 行必须是对象")
            raw_case_id = row.get("case_id")
            if not isinstance(raw_case_id, str):
                raise ValueError("case_id 必须是字符串")
            case_id = corpus_catalog.normalize_case_id(raw_case_id)
            raw_path = row.get("report_path")
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ValueError("report_path 不能为空")
            report_file = Path(raw_path.strip())
            if not report_file.is_absolute():
                report_file = inventory.parent / report_file
            raw_bytes = report_file.read_bytes()
            expected_size = row.get("_artifact_size")
            expected_hash = row.get("_artifact_sha256")
            if isinstance(expected_size, int) and len(raw_bytes) != expected_size:
                raise ValueError("case package report artifact size changed before reconcile")
            if isinstance(expected_hash, str) and hashlib.sha256(raw_bytes).hexdigest() != expected_hash:
                raise ValueError("case package report artifact hash changed before reconcile")
            raw_text = raw_bytes.decode("utf-8")
            report = json.loads(
                raw_text,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_float,
            )
            if not isinstance(report, dict):
                raise ValueError("report 顶层必须是对象")
            entry = manifest_entry(report)
            key = _key_of(entry)
            if entry.get("sample_sha256_synthetic"):
                raise ValueError("report 缺少 sample_sha256")
            if not entry.get("tool_version") or not entry.get("ruleset_digest"):
                raise ValueError("report 缺少 tool_version/ruleset_digest")
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            item.update({"status": "invalid_report", "reason": str(exc) or type(exc).__name__})
            counts["invalid_report"] += 1
            items.append(item)
            continue

        item.update({"case_id": case_id, "report_path": str(report_file), "key": list(key)})
        package_id = row.get("package_id")
        if isinstance(package_id, str) and package_id:
            item["package_id"] = package_id
        entries = load_materialized_manifest(root)
        status, reason = _reconcile_record_status(
            root, entries, key, case_id, raw_bytes
        )
        if reason:
            item["reason"] = reason
        mutation_conflict: str | None = None
        if apply and status in {"missing_record", "case_unbound"}:
            result = add_report(root, report, raw_text, case_id=case_id)
            added += int(bool(result.get("added")))
            bound += int(bool(result.get("case_bound")))
            if result.get("content_conflict") or result.get("collision"):
                mutation_conflict = _s(result.get("conflict_reason")).strip() or (
                    "report path/content conflict"
                )

        if apply:
            # Re-read the authoritative joined view even for an apparent
            # no-write state.  This gives each final status a post-action
            # snapshot and prevents a concurrent quarantine/bind from being
            # reported from a stale hand-joined catalog/manifest pair.
            entries = load_materialized_manifest(root)
            status, reason = _reconcile_record_status(
                root, entries, key, case_id, raw_bytes
            )
            # A path collision can leave the incoming key absent from the
            # final view.  Preserve the named mutation failure instead of
            # incorrectly reporting the rejected item as merely missing.
            if mutation_conflict is not None and status in {
                "missing_record",
                "case_unbound",
            }:
                status, reason = "content_conflict", mutation_conflict
            if reason:
                item["reason"] = reason
            else:
                item.pop("reason", None)
        item["status"] = status
        counts[status] += 1
        items.append(item)

    return {
        "input_kind": input_kind,
        "applied": apply,
        "added": added,
        "case_bound": bound,
        "counts": counts,
        "items": items,
    }


def query(entries: list[dict], **filters: str) -> list[dict]:
    """按字段等值过滤 manifest 记录（空值过滤项忽略）。字段名见 manifest_entry。"""
    active = {k: v for k, v in filters.items() if v}
    if not active:
        return list(entries)
    out: list[dict] = []
    for e in entries:
        def matches(field: str, wanted: str) -> bool:
            if field == "case_id" and isinstance(e.get("case_ids"), list):
                return wanted in {_s(item) for item in e["case_ids"]}
            return _s(e.get(field)) == wanted

        if all(matches(k, v) for k, v in active.items()):
            out.append(e)
    return out


def refresh_catalog_fields(corpus_dir: str | Path) -> list[dict]:
    """Join the non-derived catalog into manifest and persist the derived view."""
    root = Path(corpus_dir)
    with corpus_catalog.catalog_write_lock(root):
        catalog_rows = corpus_catalog.load_catalog_strict(root)
        current_manifest = load_manifest_strict(root)
        corpus_catalog.assert_manifest_catalog_coverage(
            current_manifest, catalog_rows, root
        )
        entries = [
            corpus_catalog.materialize(entry, catalog_rows) for entry in current_manifest
        ]
        _save_manifest_unlocked(root, entries, catalog_rows=catalog_rows)
        return entries


def find_by(entries: list[dict], value: str, by: str = "sample_sha256") -> list[dict]:
    """反查："这个值见过没"。按 ``by`` 字段等值匹配（支持 sample_sha256/package_name/sign_sha256）。"""
    if by not in SEEN_FIELDS:
        logger.warning("find_by 不支持的字段：%s（支持 %s）", by, SEEN_FIELDS)
        return []
    target = _s(value).strip()
    if not target:
        return []
    if by in _HASH_SEEN_FIELDS:
        # ★哈希是十六进制、大小写等价：两侧归一小写再比，避免传大写 SHA256（或库内大写）漏报——
        # seen 是权威口吻，假阴性取证致命。package_name 不归一（大小写敏感）。
        target = target.lower()
        return [e for e in entries if _s(e.get(by)).strip().lower() == target]
    return [e for e in entries if _s(e.get(by)).strip() == target]


def find_by_config_object(entries: list[dict], value: str) -> list[dict]:
    """反查引用了某远程配置对象的样本：``value`` 匹配任一对象的 url（精确）或 sha256（大小写归一）。

    config-chain 层⑧ 的列表维度反查（``remote_config_objects`` 是列表，非 :func:`find_by` 的标量字段）。
    空值 → 空列表。绝不抛。
    """
    target = _s(value).strip()
    if not target:
        return []
    target_lower = target.lower()
    out: list[dict] = []
    for entry in entries:
        for obj in entry.get("remote_config_objects") or []:
            if not isinstance(obj, dict):
                continue
            sha = _s(obj.get("sha256")).strip().lower()
            if _s(obj.get("url")).strip() == target or (sha and sha == target_lower):
                out.append(entry)
                break
    return out


def find_by_domain(entries: list[dict], value: str) -> list[dict]:
    """按规范化完整域名反查；大小写和 DNS 末点等价。"""
    target = _normalize_domain(value)
    if not target:
        return []
    return [
        entry for entry in entries
        if target in {_normalize_domain(v) for v in entry.get("domains") or []}
    ]


def find_by_cname(entries: list[dict], value: str) -> list[dict]:
    """按 ``source->target`` 精确反查明确观测的 CNAME 边。"""
    raw = _s(value)
    if "->" not in raw:
        return []
    src, dst = (_normalize_domain(part) for part in raw.split("->", 1))
    if not src or not dst:
        return []
    out: list[dict] = []
    for entry in entries:
        for edge in entry.get("cname_edges") or []:
            if not isinstance(edge, dict):
                continue
            if (_normalize_domain(edge.get("from")), _normalize_domain(edge.get("to"))) == (src, dst):
                out.append(entry)
                break
    return out


def shared_config_objects(entries: list[dict]) -> list[dict]:
    """跨样本共享的远程配置对象簇：同一 url（同一 OSS 对象）或同一 sha256（配置内容字节相同）被 **≥2 个
    不同样本** 引用——串案强锚（"样本 A 与 B 拉同一 bucket/config.dat" 或 "配置内容完全一致"）。

    返回按样本数降序的簇 ``[{key_type: url|sha256, key, samples: [sample_sha256...]}]``（url 与 sha256 各成
    簇：内容一致的 sha256 簇是比 url 更强的佐证）。绝不抛。
    """
    groups: dict[tuple[str, str], set[str]] = {}
    for entry in entries:
        sample = _s(entry.get("sample_sha256")).strip().lower()
        if not sample:
            continue
        for obj in entry.get("remote_config_objects") or []:
            if not isinstance(obj, dict):
                continue
            url = _s(obj.get("url")).strip()
            sha = _s(obj.get("sha256")).strip().lower()
            if url:
                groups.setdefault(("url", url), set()).add(sample)
            if sha:
                groups.setdefault(("sha256", sha), set()).add(sample)
    clusters = [
        {"key_type": key_type, "key": key, "samples": sorted(samples)}
        for (key_type, key), samples in groups.items()
        if len(samples) >= 2
    ]
    clusters.sort(key=lambda c: (-len(c["samples"]), c["key_type"], c["key"]))
    return clusters


def find_by_native_lib(entries: list[dict], value: str) -> list[dict]:
    """按 .so 家族硬指纹反查样本：``value`` 匹配任一 native lib 的 sha256（大小写归一）或精确 name。

    A1 家族配方库的反查基石——核心业务 .so 逐字节相同即同族，一击拉出全家族样本。列表维度
    （``native_lib_hashes`` 是列表，非 :func:`find_by` 的标量字段）。空值 → 空列表。绝不抛。
    """
    target = _s(value).strip()
    if not target:
        return []
    target_lower = target.lower()
    out: list[dict] = []
    for entry in entries:
        for h in entry.get("native_lib_hashes") or []:
            if not isinstance(h, dict):
                continue
            sha = _s(h.get("sha256")).strip().lower()
            if (sha and sha == target_lower) or _s(h.get("name")).strip() == target:
                out.append(entry)
                break
    return out


_PACKER_SO_POLICY_COMPLETE: bool | None = None


@functools.lru_cache(maxsize=1)
def _packer_so_names() -> Mapping[str, str]:
    """``{小写 .so 库名: 加固产品名}``，取自 ``rules/packers.yaml`` 的 ``so_names``。

    复用现成规则而非新建壳指纹库：判据必须**可命名、可解释**，且与 ``analyzers/packing.py``
    共用同一份真源，避免两处「什么算加固壳」的口径漂移。加载失败 → 空 mapping（静默降级为
    不降噪，宁可少标注也不误标）。

    ★缓存 + 返回只读视图：``load_rules`` 每次都重读并解析 YAML，而本函数会被每个候选簇调用
    （原实现是 O(簇数) 次文件读）。``MappingProxyType`` 保证调用方拿不到可变的缓存对象——
    否则任何一处就地修改都会污染后续全部调用。
    """
    global _PACKER_SO_POLICY_COMPLETE
    out: dict[str, str] = {}
    try:
        from apkscan.core.registry import load_rules

        raw = load_rules("packers")
        packers = raw.get("packers") if isinstance(raw, dict) else None
        if not isinstance(packers, list):
            _PACKER_SO_POLICY_COMPLETE = False
            return MappingProxyType({})
        for entry in packers:
            if not isinstance(entry, dict):
                continue
            product = _s(entry.get("name")).strip()
            so_names = entry.get("so_names")
            if not product or not isinstance(so_names, list):
                continue
            for so in so_names:
                key = _s(so).strip().lower()
                if key:
                    out.setdefault(key, product)
    except Exception:
        _PACKER_SO_POLICY_COMPLETE = False
        logger.exception("加载加固壳 so 名单失败，本次不做共享 .so 降噪标注")
        return MappingProxyType({})
    _PACKER_SO_POLICY_COMPLETE = True
    return MappingProxyType(out)


def native_anchor_policy_snapshot() -> dict[str, object]:
    """Return the exact native weak-anchor inputs and whether all loaded safely."""
    packers = _packer_so_names()
    complete = _PACKER_SO_POLICY_COMPLETE is True
    own_code_libs: list[str] = []
    benign_substrings: list[str] = []
    try:
        from apkscan.core.appframework import APP_OWN_CODE_LIBS

        own_code_libs = sorted(APP_OWN_CODE_LIBS)
    except Exception:
        complete = False
        logger.exception("加载 App 自有 native 库名单失败")
    try:
        from apkscan.analyzers._common import NATIVE_LIB_BENIGN_SUBSTR

        benign_substrings = sorted(NATIVE_LIB_BENIGN_SUBSTR)
    except Exception:
        complete = False
        logger.exception("加载第三方 native 库名单失败")
    return {
        "version": "1.0",
        "status": "complete" if complete else "partial",
        "packer_so_names": [list(item) for item in sorted(packers.items())],
        "app_own_code_libs": own_code_libs,
        "benign_substrings": benign_substrings,
    }


def native_anchor_weakness(name: str) -> str | None:
    """该 ``.so`` 库名是否属**非单一主体独有**（共享它不足以并簇）→ 返回理由；否则 None。

    ★为什么必须降噪：``shared_native_libs`` 原先把「被 ≥2 样本共享的 .so」一律当强锚，
    而实测有两类共享**与主体归属无关**：

    1. **加固壳运行时库** —— 同一款商用加固的壳 so 逐字节相同，凡用该加固的样本全都共享它。
       实测一个加固壳 so 让 多个样本聚成一簇，其中多数互不相干。
    2. **第三方 SDK / 引擎库** —— RN/Flutter/FFmpeg/播放器等预编译库随 SDK 继承进任何接入方。

    两类的共同点是：**共享它只说明「用了同一个第三方组件」**，不说明同一开发主体。
    与 :mod:`apkscan.analyzers.build_provenance` 对第三方 SDK 构建路径的处置同一思路。

    ★判据只用**可命名、可解释**的名单（壳产品名 / 已知 SDK 库名），**绝不用统计阈值**：
    「被很多样本共享」也完全可能是真的强关联（同族核心业务库正是如此），按频次降噪会把
    最有价值的锚点误杀。
    """
    base = posixpath.basename(_s(name).strip().replace("\\", "/")).lower()
    if not base:
        return None

    packers = _packer_so_names()
    product = packers.get(base)
    if product:
        return f"packer:{product}"
    # 规则容忍不带 .so 后缀 / 前缀写法（如 libnllvm* / libsgmainso*），与 packing.py 同款语义。
    for key, prod in packers.items():
        if not key.endswith(".so") and base.startswith(key):
            return f"packer:{prod}"

    # ★先问「这是不是本应用自己的业务代码容器」。Flutter 的 libapp.so、Unity 的
    #   libil2cpp.so 装的是这个 App 自己的全部业务逻辑——两份样本共享同一份**逐字节相同**的
    #   业务代码容器，是最强的同族证据，恰恰不能当第三方降噪掉。
    #   而第三方名单是按子串匹配的，"libil2cpp" 就在里面（它服务于另一个用途：给扫描器
    #   划定输入范围）。同一张表被两处消费、目的相反，这里按用途取自己的口径。
    try:
        from apkscan.core.appframework import is_app_own_code

        if is_app_own_code(base):
            return None
    except Exception:
        logger.exception("加载 App 自有 native 库名单失败，本次不做共享 .so 降噪标注")
        return None

    try:
        from apkscan.analyzers._common import NATIVE_LIB_BENIGN_SUBSTR

        for substr in NATIVE_LIB_BENIGN_SUBSTR:
            if substr in base:
                return "third-party-sdk"
    except Exception:
        logger.exception("加载第三方库名单失败，本次不做第三方 SDK 降噪标注")
    return None


def shared_native_libs(entries: list[dict]) -> list[dict]:
    """跨样本共享同一 .so（sha256 逐字节相同）被 **≥2 个不同样本** 引用——家族串案锚点候选。

    返回 ``[{sha256, name, samples, weak_anchor, weak_anchor_reason}]``。绝不抛。

    ★ ``weak_anchor=True`` 的簇是**加固壳/第三方 SDK 撞出来的假聚簇**，不足以并案
    （见 :func:`native_anchor_weakness`）。**标注而非删除**：读结果的人需要看见
    「这簇是加固壳撞的」，静默丢弃会让人以为压根没有这个共享事实。
    排序把强锚放前面（弱锚沉底），同强弱内仍按样本数降序。
    """
    groups: dict[str, set[str]] = {}
    names: dict[str, set[str]] = {}
    for entry in entries:
        sample = _s(entry.get("sample_sha256")).strip().lower()
        if not sample:
            continue
        for h in entry.get("native_lib_hashes") or []:
            if not isinstance(h, dict):
                continue
            sha = _s(h.get("sha256")).strip().lower()
            if not sha:
                continue
            groups.setdefault(sha, set()).add(sample)
            name = _s(h.get("name")).strip()
            if name:
                names.setdefault(sha, set()).add(name)
    clusters: list[dict] = []
    for sha, samples in groups.items():
        if len(samples) < 2:
            continue
        observed_names = sorted(names.get(sha) or [])
        classified = [
            (0 if reason.startswith("packer:") else 1, name, reason)
            for name in observed_names
            if (reason := native_anchor_weakness(name)) is not None
        ]
        if classified:
            _rank, name, reason = min(classified)
        else:
            name = observed_names[0] if observed_names else None
            reason = None
        clusters.append(
            {
                "sha256": sha,
                "name": name,
                "samples": sorted(samples),
                "weak_anchor": reason is not None,
                "weak_anchor_reason": reason,
            }
        )
    clusters.sort(key=lambda c: (bool(c["weak_anchor"]), -len(c["samples"]), c["sha256"]))
    return clusters
