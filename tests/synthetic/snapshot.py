"""案例级语义回归基准的共享 runner 与投影层。

★为什么单独成模块：快照测试（``tests/test_synthetic_snapshots.py``）与基线更新脚本
（``tools/update_synthetic_baseline.py``）必须用**同一份** FakeContext 构造与投影逻辑——
两边各写一份就会漂移，"测试重算的投影"对不上"脚本写进基线的投影"，基线机制整个失效。

三件事：
1. :func:`build_context` —— 把 SyntheticSample 变成可跑真 pipeline 的 FakeContext。
   最小 manifest 与 DEX 填充串加在**这里**、不进 ``samples.py`` 的样本声明：样本保持
   「最小触发内容」语义，夹具缺陷（空 manifest → critical_failures、串太少 → 误判 stub）
   由 runner 统一补齐。
2. :func:`run_samples` / :func:`run_all` —— 跑真 pipeline + ``close_report``（锁 analyze+close
   态，closure 语义一并入锁），产出各维度投影的原料。
3. :func:`project` —— 六个维度各自的稳定投影：锁结构与语义字段，不锁措辞与 volatile 字段
   （全局剔除清单见 :data:`EXCLUDED_FIELDS`）。
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from apkscan.analyzers.packing import _STUB_MAX_DEX_STRINGS
from apkscan.core import corpus, pipeline
from apkscan.core.closure import ClosureConfig, close_report
from apkscan.core.models import AnalysisConfig, Report
from apkscan.report.digest import build_digest
from apkscan.report.json import to_dict
from tests.conftest import FakeContext
from tests.synthetic.samples import SAMPLES, SyntheticSample

#: 基线目录与维度全集（一维度一文件：``tests/synthetic/baselines/<dimension>.json``）。
BASELINE_DIR = Path(__file__).resolve().parent / "baselines"
DIMENSIONS: tuple[str, ...] = ("report", "visibility", "attribution", "closure", "digest", "corpus")

#: 最小可解析 manifest。★``package`` 必须与 FakeContext 默认 ``package_name``（com.test.app）
#: 一致：manifest 分析器会把解析出的 package 写进 meta，而 pipeline 已按 ctx.package_name 播种了
#: 同名键——两者不一致时 pipeline.py 的防静默覆盖告警（"meta key 冲突"）每跑一次刷一条。
#: 为什么必须有它：manifest_xml 为空串时 manifest 分析器解析失败 → critical_failures=['manifest']，
#: 快照锁到的是"夹具残破"而非样本语义。
_MIN_MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.test.app"><application/></manifest>'
)

#: DEX 填充目标 = stub 阈值 + 余量。★禁止写死绝对数（如 1200）：阈值将来一旦调过写死值，
#: 8 个正常样本会集体翻回 stub_only、快照全红且红得莫名其妙——跟着阈值走才把这条路锁死。
_DEX_PAD_MARGIN = 200
_PAD_TARGET = _STUB_MAX_DEX_STRINGS + _DEX_PAD_MARGIN

#: 全局剔除清单（文档化，供更新脚本随 diff 打印）：这些字段**有意**不进任何快照投影。
EXCLUDED_FIELDS: tuple[str, ...] = (
    "meta.analysis_started_at —— 唯一 volatile（秒精度时间戳，偶发 flaky）",
    "meta.{tool_version,dependency_versions,analysis_environment,ruleset_digest} —— 复现锚点，随环境/版本漂移",
    "根 completeness / analyzer_status / analysis_status、meta.stage_status、skipped_analyzers"
    " —— jadx 等外部工具在场与否会改变（本机有、CI 无），环境相关",
    "visibility 的 why/notes/next_actions 文案 —— 锁结构不锁措辞；dex_string_pool 统计 —— 是填充串的形状",
    "closure checks 的 reason 文案 —— 同上锁结构不锁措辞（其语义在 visibility 维度已按结构入锁）",
    "corpus 条目的 sample_sha256 / report_path —— nosha 派生、run 级不稳；tool_version / ruleset_digest"
    " / dependency_versions —— 同上复现锚点",
    "digest.findings 的 items/note —— 标题与提示是措辞，只锁 counts；HTML 全文 —— 只测渲染成功与标题",
)


def build_context(sample: SyntheticSample) -> FakeContext:
    """按样本声明构造 FakeContext（最小 manifest + 按需填充 DEX 串到 stub 阈值之上）。

    填充串刻意用可读长句式（低不透明度、无 URL/关键词/中文黑话）：既不被 dex_string_pool
    的混淆判据盯上，也不触发任何检出类别（8 样本填充前后检出集 0 变化，已实测）。
    """
    dex = list(sample.dex_strings)
    if sample.pad_dex_strings:
        i = 0
        while len(dex) < _PAD_TARGET:
            dex.append(f"synthetic filler string number {i:04d} keeps the dex pool realistic")
            i += 1
    return FakeContext(manifest_xml=_MIN_MANIFEST, dex_strings=dex, files=dict(sample.files))


@dataclass
class SampleRun:
    """一个样本跑完 analyze+close 后的全部快照原料。"""

    report: Report  # 供 HTML 渲染冒烟（render_to_string 吃 Report 对象，不原地改，已实测）
    raw: dict       # to_dict 序列化面（close_report 之后取，锁 analyze+close 态）
    digest: dict    # build_digest(raw) 摘要面


def run_samples(samples: tuple[SyntheticSample, ...]) -> dict[str, SampleRun]:
    """跑真 pipeline + close_report，返回 {样本名: SampleRun}。

    ★钉死能力探测（detect_capabilities → 空集）：jadx 这类外部工具"本机有、CI 无"。有 jadx 时
    该分析器会真跑并因 FakeContext 无 apk_path 报 error → analysis_status=partial → closure 的
    static_health=warn、gaps 多一条；无 jadx 则 skipped → complete/pass（两种形态都已实测）。
    基线必须跨机一致，故快照 runner 统一按「无外部工具」的形态跑。这不 mock 任何判据、只钉
    环境探测，与 conftest ``_no_real_adb`` 同一哲学：环境巧合不得进语义基线。
    检出回归测试（test_synthetic_regression）不钉，保持其原有断言语义。
    用 mock.patch.object 而非手写全局赋值 + finally：恢复语义交给标准库（嵌套/重入时各层
    各自恢复到进入前的值，不会互相踩），也少一条"赋值行本身抛异常导致漏恢复"的路。
    """
    with mock.patch.object(pipeline, "detect_capabilities", lambda online=True: set()):
        return {s.name: _run_one(s) for s in samples}


def run_all() -> dict[str, SampleRun]:
    """全样本跑一遍（快照测试的 module fixture 与更新脚本共用入口）。"""
    return run_samples(SAMPLES)


def _run_one(sample: SyntheticSample) -> SampleRun:
    report = pipeline.run(build_context(sample), AnalysisConfig(online=False))
    # ★close_report 是唯一原地改（只加 $.meta.closure，二次调用幂等，均已实测）——必须在取
    #   raw/digest 快照**之前**、且只跑一次：快照锁的是「analyze+close 态」，closure 语义一并入锁。
    close_report(report, ClosureConfig(online=False))
    raw = to_dict(report)
    return SampleRun(report=report, raw=raw, digest=build_digest(raw))


# ---------------------------------------------------------------------------
# 各维度投影：只挑稳定语义字段。凡返回值都经 JSON 往返（见 project），与基线同构、无共享容器。
# ---------------------------------------------------------------------------

#: 缺键哨兵：投影里「键不存在」与「值恰为 null/False/[]」必须可区分——否则"字段被整个删掉"
#: 与"字段还在、值为空"在基线上同形，schema 破坏会被放过（实测例：manifest_entry 若删掉
#: ``packer`` 键，旧投影 ``entry.get(k)`` 得 None，与基线里的 null 全等、照样绿）。
#: 同理各投影**不做 bool()/str() 归一**：类型漂移（如 True 变字符串 "true"）也要现形。
_ABSENT = "<缺键>"

#: 报告核心维度锁的 Lead 字段：类别/值/档位判定链/置信度与结构化警示位。
#: ★刻意不含 where_to_request / evidence_to_obtain / notes / source_refs——那些是措辞或证据
#:   排版，锁了会把"改一句话"变成基线更新，人很快就不看 diff 了（锁结构不锁措辞）。
_LEAD_FIELDS: tuple[str, ...] = (
    "category", "value", "subject", "advice", "base_advice", "confidence",
    "shape_uncertain", "sni_masquerade", "is_c2", "is_runtime_seen",
    "is_runtime_contact", "downgrades",
)

#: corpus 维度锁的 manifest_entry 字段（定案清单）。★不含 sample_sha256/report_path（nosha 从
#: 报告内容派生，含 volatile 时间戳 → run 级不稳）与 tool_version/ruleset_digest/dependency_versions。
_CORPUS_FIELDS: tuple[str, ...] = (
    "counts", "finding_ids", "key_iocs", "domains", "cname_edges", "remote_config_objects",
    "package_name", "app_type", "app_score", "evidence_surface", "is_hardened", "packer",
    "mode", "schema_version", "native_lib_hashes", "build_environments", "sign_sha256",
    "version_name", "version_code", "visibility",
)


def _project_report(run: SampleRun) -> dict:
    """报告核心：schema_version + leads 的稳定语义字段（按类别/值/档位排序，与产出顺序解耦）。"""
    leads = [
        {k: lead.get(k, _ABSENT) for k in _LEAD_FIELDS}
        for lead in run.raw.get("leads", [])
        if isinstance(lead, dict)
    ]
    leads.sort(key=lambda d: (str(d.get("category")), str(d.get("value")), str(d.get("advice"))))
    return {"schema_version": run.raw.get("schema_version"), "leads": leads}


def _project_visibility(run: SampleRun) -> dict:
    """可见性：各源档位、阻断清单、claims 键集+eligible、补救档、degraded、加固位、crit==[]。

    ★排除 why/notes/next_actions 文案与 dex_string_pool 统计（后者就是填充串的形状）。
    critical_failures 以整列表入锁（基线值为 []），等价于"必须为空"且新出现的项直接可见。
    值一律取原样（缺键给 :data:`_ABSENT` 哨兵、不做 bool() 归一）：投影只搬运、不修补。
    """
    meta = run.raw.get("meta") or {}
    vis = meta.get("visibility") or {}
    sources = vis.get("sources") or {}
    claims = vis.get("claims") or {}
    grades: dict[str, Any] = {}
    for name in ("dex", "java", "native", "resource", "runtime"):
        src = sources.get(name, _ABSENT)
        # 源整个缺席 → 哨兵；源在但形状不是 dict（schema 破坏）→ 原值直接现形。
        grades[name] = src.get("visibility", _ABSENT) if isinstance(src, dict) else src
    blocked = vis.get("blocked_claims", _ABSENT)
    return {
        "sources": grades,
        # 排序是有意归一（该列表无顺序契约）；非列表（缺键/类型漂移）原样入投影、直接变红。
        "blocked_claims": sorted(str(c) for c in blocked) if isinstance(blocked, list) else blocked,
        "claims_eligible": {
            str(c): (v.get("eligible", _ABSENT) if isinstance(v, dict) else v)
            for c, v in claims.items()
        },
        "remediation": vis.get("remediation", _ABSENT),
        "degraded": vis.get("degraded", _ABSENT),
        "is_hardened": meta.get("is_hardened", _ABSENT),
        "critical_failures": run.raw.get("critical_failures", _ABSENT),
    }


def _project_attribution(run: SampleRun) -> dict:
    """network_attribution：锁「meta 键缺席 + 角色候选 0」。★缺席就是缺席（显式布尔），不把
    缺席序列化成 {}——否则"将来某天键出现了"与"键一直是空对象"在基线上不可区分。"""
    meta = run.raw.get("meta") or {}
    return {
        "network_attribution_present": "network_attribution" in meta,
        "attributed_role_candidates": (run.digest.get("summary") or {}).get(
            "attributed_role_candidates"
        ),
    }


def _project_closure(run: SampleRun) -> dict:
    """closure：status/checks/targets/target_selection/gaps（source_summary/next_actions 由
    digest 维度的 compact closure 覆盖，不重复锁）。

    checks 只锁 {id, status, evidence_refs}，剔除 reason 文案（锁结构不锁措辞，与 visibility
    的 why/notes 同理；reason 携带的语义——哪个源没评估——在 visibility 维度已按结构入锁）。
    gaps 保留原文：gap 字符串没有独立 id，原文就是它的身份标识。"""
    cl = (run.raw.get("meta") or {}).get("closure") or {}
    projected = {k: cl.get(k, _ABSENT) for k in ("status", "targets", "target_selection", "gaps")}
    checks = cl.get("checks", _ABSENT)
    projected["checks"] = (
        [
            {k: c.get(k, _ABSENT) for k in ("id", "status", "evidence_refs")}
            if isinstance(c, dict) else c
            for c in checks
        ]
        if isinstance(checks, list) else checks
    )
    return projected


def _project_digest(run: SampleRun) -> dict:
    """报告数字：digest 的 summary / findings.counts / app_classification / closure。
    findings 只锁 counts——items 的标题与 note 是措辞。"""
    d = run.digest
    findings = d.get("findings", _ABSENT)
    return {
        "summary": d.get("summary", _ABSENT),
        "findings_counts": findings.get("counts", _ABSENT) if isinstance(findings, dict) else findings,
        "app_classification": d.get("app_classification", _ABSENT),
        "closure": d.get("closure", _ABSENT),
    }


def _project_corpus(run: SampleRun) -> dict:
    """corpus：manifest_entry 纯函数投影（不建库）。

    ★必须喂 deepcopy：manifest_entry 的返回值与入参 report **共享 meta.dependency_versions
    容器**（corpus.py:734 直引用），拿共享容器去比对/落盘等于给基线埋了个远程可变引用。
    """
    entry = corpus.manifest_entry(copy.deepcopy(run.raw))
    # ★缺键必须给哨兵：_CORPUS_FIELDS 里 4 个字段基线值恰为 null（packer/sign_sha256/
    #   version_name/version_code），.get(k) 的 None 会让"键被删"与"值为 null"同形假绿
    #   （突变实测：pop("packer") 后旧投影 10 passed、哨兵投影 9 failed）。
    return {k: entry.get(k, _ABSENT) for k in _CORPUS_FIELDS}


_PROJECTORS: dict[str, Callable[[SampleRun], dict]] = {
    "report": _project_report,
    "visibility": _project_visibility,
    "attribution": _project_attribution,
    "closure": _project_closure,
    "digest": _project_digest,
    "corpus": _project_corpus,
}


def project(dimension: str, run: SampleRun) -> dict:
    """算一个样本在某维度的投影，并做 JSON 往返归一。

    往返有两个作用：① 与基线文件同构（tuple→list、键序无关）；② 兜底断掉与 run.raw 的一切
    容器共享（"fixture 按维度发 deepcopy"的双保险）。allow_nan=False 顺带把 NaN 拦在入锁之前。
    """
    projected = _PROJECTORS[dimension](run)
    return json.loads(json.dumps(projected, ensure_ascii=False, sort_keys=True, allow_nan=False))


# ---------------------------------------------------------------------------
# 基线文件 IO 与结构化 diff
# ---------------------------------------------------------------------------


def baseline_path(dimension: str) -> Path:
    return BASELINE_DIR / f"{dimension}.json"


def load_baseline(dimension: str) -> dict:
    """读一个维度的基线（缺文件 → 空 dict，由测试报"无基线"而非 IO 崩）。"""
    path = baseline_path(dimension)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def dump_baseline(data: dict) -> str:
    """基线的规范序列化：ensure_ascii=False / sort_keys / indent=2 / allow_nan=False / 末尾换行。"""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def flat_diff(expected: Any, actual: Any, prefix: str = "") -> list[str]:
    """递归比出结构化 diff 行，形如 ``a.b[2].c: expected 3, actual 4``。相等 → []。

    dict 比键并集（单侧缺键显式标出）；list 先比长度再逐位；其余按标量比。
    """
    diffs: list[str] = []
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            p = f"{prefix}.{key}" if prefix else str(key)
            if key not in expected:
                diffs.append(f"{p}: expected <基线无此键>, actual {actual[key]!r}")
            elif key not in actual:
                diffs.append(f"{p}: expected {expected[key]!r}, actual <实际无此键>")
            else:
                diffs.extend(flat_diff(expected[key], actual[key], p))
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            diffs.append(f"{prefix}: expected 长度 {len(expected)}, actual 长度 {len(actual)}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            diffs.extend(flat_diff(e, a, f"{prefix}[{i}]"))
    elif expected != actual or type(expected) is not type(actual):
        diffs.append(f"{prefix}: expected {expected!r}, actual {actual!r}")
    return diffs
