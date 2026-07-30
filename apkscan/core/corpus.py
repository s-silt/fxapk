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

import functools
import hashlib
import json
import logging
import posixpath
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

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
    """从 leads 摘取高价值线索值（is_c2 或 advice=建议调证）供快速 grep，去重、限量。

    ★``shape_uncertain`` 的值不收：它们的地址性尚未确证（形态与版本号无法区分）。串案时
    两个毫不相干的样本恰好含同一个版本号字面，会被呈现成「共享基础设施」——那是凭空造出
    一条串案信号，方向上正是本项目最重的那类错误。要串案，先把它确证成地址。
    """
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

    取下载解码产物的 ``(source_url, sha256)``（meta["remote_config_artifacts"]，authorized-active 才有 sha）
    并上 ``REMOTE_CONFIG`` 候选线索的 url（passive 也有）。按 url 去重（下载产物优先保留其 sha256），按 url
    排序确定。空/无则空列表。绝不抛。
    """
    objects: dict[str, dict] = {}
    for art in _meta(report).get("remote_config_artifacts") or []:
        if not isinstance(art, dict):
            continue
        url = _s(art.get("source_url")).strip()
        if url:
            objects.setdefault(url, {"url": url, "sha256": _s(art.get("sha256")).strip().lower() or None})
    for lead in report.get("leads") or []:
        if isinstance(lead, dict) and lead.get("category") == "REMOTE_CONFIG":
            url = _s(lead.get("value")).strip()
            if url:
                objects.setdefault(url, {"url": url, "sha256": None})
    return [objects[url] for url in sorted(objects)]


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
#: 阈值由 32 份真实检材实测标定，两侧分得很开、中间是空的：
#:   · 已核实的真构建环境 14 个（``/opt/work/<批次>-<代号>-<业务>/`` 与 ``d:/buildroot``）
#:     —— 路径数 **26 – 32**；
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

    ★为什么这是比 .so 哈希更耐用的串案锚：同族样本的 ``.so`` 文件名逐份随机、sha256 逐份不同
    （实测 11 份同源库无一重复），文件名锚与 :func:`_native_lib_hashes` 家族反查**双双失效**；
    而构建路径是编译器写进 ``__FILE__`` 的，改文件名、重打包、重签名都动不了它。实测一个构建
    环境标识横跨 3 个不同案件——同标识即同一下游客户，是并案依据。

    ★只收 ``self_hosted`` 那层：第三方 SDK 的构建路径会随源码继承进来（如某开源客户端作者的
    开发机目录出现在 13 个样本里），拿它串案会把互不相干的样本串成一团，还会把无关的开源作者
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
    """跨样本共享的构建环境簇：同一标识被 **≥2 个不同样本** 使用 —— 同一打包方/同一下游客户。

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
        # ---- config-chain 跨样本串联维度（同 OSS 对象 / 同配置内容）----
        "remote_config_objects": _remote_config_objects(report),
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
    out: dict[str, str] = {}
    try:
        from apkscan.core.registry import load_rules

        raw = load_rules("packers")
        packers = raw.get("packers") if isinstance(raw, dict) else None
        if not isinstance(packers, list):
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
        logger.exception("加载加固壳 so 名单失败，本次不做共享 .so 降噪标注")
        return MappingProxyType({})
    return MappingProxyType(out)


def native_anchor_weakness(name: str) -> str | None:
    """该 ``.so`` 库名是否属**非单一主体独有**（共享它不足以并簇）→ 返回理由；否则 None。

    ★为什么必须降噪：``shared_native_libs`` 原先把「被 ≥2 样本共享的 .so」一律当强锚，
    而实测有两类共享**与主体归属无关**：

    1. **加固壳运行时库** —— 同一款商用加固的壳 so 逐字节相同，凡用该加固的样本全都共享它。
       实测一个加固壳 so 让 13 个样本聚成一簇，其中多数互不相干。
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
