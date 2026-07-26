"""证据可见性求值：这份报告**看到了什么、没看到什么**，因而哪些「未发现」不可解读为「不存在」。

## 为什么需要这一层

各分析器已经各自记录了自己的可见性事实——``dex_available``（DEX 能否解析）、``is_hardened`` /
``hardening_structural``（加壳）、``dex_string_pool``（字符串池不透明度）、``native_obfuscation``
（原生层混淆）、``artifact_lineage``（脱壳结果是否已回灌）——但**没有任何下游消费它们**。
于是一份「壳桩样本」的报告会平静地写着「未发现网络端点」，读的人（尤其是 AI）无从知道那是
「扫过了确实没有」还是「压根看不见」。

本模块把这些散落事实归一成一个可消费的视图，回答一个问题：
**基于本次实际看到的输入，哪些结论有资格下、哪些没有。**

## 三条设计纪律

1. **不重载 ``analysis_status`` / ``completeness``**。那两个字段的既定语义是「分析器执行健康度」
   （成功数 ÷ 成功+报错数），``--strict`` 的退出码依赖它。样本加固是**样本**的属性，不是
   工具跑挂了；混进去会让正常跑完的加固样本表现成「分析失败」，并冲击既有指标基线。
   可见性是**正交的第三个维度**。

2. **落到「主张」而非「分析器」**。``endpoints`` 同时扫 DEX、manifest、资源、native——DEX 不可见时
   不能把它的全部产出标成不可信：manifest 里声明的域名照样可用，运行时 pcap 实测的连接照样是硬证据。
   不可下的只是「端点已穷尽」这类**需要完整可见性**的主张。

3. **只标注，不封顶**。本模块不改 closure、不改退出码，只提供求值结果；由消费方按自己的主张
   相关性决定要不要被某条 blocker 影响。全局一刀切封顶会把真实可办案的动态证据一起降级掉。

纯函数、可离线、绝不联网、绝不抛。
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# --- 来源可见性取值 -------------------------------------------------------
VIS_COMPLETE = "complete"        # 该来源完整可见
VIS_PARTIAL = "partial"          # 可见但有截断/部分不可读
VIS_STUB_ONLY = "stub_only"      # 只看得到壳桩，真实内容被加密/隐藏
VIS_OPAQUE = "opaque"            # 可读到字节，但内容被混淆/加密（如字符串池不透明）
VIS_UNAVAILABLE = "unavailable"  # 完全不可见（解析失败 / 缺失）
VIS_UNKNOWN = "unknown"          # 无从判断

#: 补救状态：脱壳这类动作**做成功**与**结果已成为当前报告的输入**是两回事，必须分开。
REM_NOT_ATTEMPTED = "not_attempted"
REM_FAILED = "failed"
REM_REANALYZED = "reanalyzed_with_extra_dex"

#: 需要「该来源完整可见」才有资格下的主张 → 依赖的来源。
#: ★只列**穷尽性/否定性**主张。肯定性主张（"发现了 X"）不受可见性影响——看见了就是看见了。
_CLAIM_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "static_endpoint_exhaustive": ("dex", "native", "resource"),
    "no_contact_harvesting": ("dex",),
    "no_sms_interception": ("dex",),
    "no_remote_config": ("dex", "resource"),
    "config_chain_complete": ("dex", "resource"),
    "no_hardcoded_credential": ("dex", "native", "resource"),
}

#: 主张的人读名（进报告/digest 给人看）。
_CLAIM_LABELS: dict[str, str] = {
    "static_endpoint_exhaustive": "静态端点已穷尽",
    "no_contact_harvesting": "未发现通讯录窃取",
    "no_sms_interception": "未发现短信拦截/转发",
    "no_remote_config": "未发现远程配置下发",
    "config_chain_complete": "配置链已追全",
    "no_hardcoded_credential": "未发现硬编码凭据",
}

#: 视为「不足以支撑穷尽性主张」的可见性取值。
_INSUFFICIENT = frozenset({VIS_STUB_ONLY, VIS_OPAQUE, VIS_UNAVAILABLE})


def _meta(report: Any) -> dict:
    if not isinstance(report, dict):
        return {}
    m = report.get("meta")
    return m if isinstance(m, dict) else {}


def _dex_visibility(meta: dict) -> tuple[str, list[str]]:
    """DEX 层可见性 + 判定依据。

    ★``packed`` 为空**不等于**未加固：结构性判据（stub-dex 等）命中时 ``packed`` 仍是 None 而
    ``is_hardened`` 为 True——以 ``packed`` 是否有值来判加固会漏掉全部未识别厂商的壳。
    """
    why: list[str] = []
    if meta.get("dex_available") is False:
        why.append("DEX 解析失败（dex_available=False）")
        return VIS_UNAVAILABLE, why

    structural = meta.get("hardening_structural")
    if isinstance(structural, dict) and structural.get("reason"):
        why.append(f"结构判据命中加固：{structural.get('reason')}")
        return VIS_STUB_ONLY, why
    if meta.get("is_hardened"):
        why.append(f"加固判定 is_hardened=True（厂商：{meta.get('packed') or '未识别'}）")
        return VIS_STUB_ONLY, why

    pool = meta.get("dex_string_pool")
    if isinstance(pool, dict) and pool.get("suspicious"):
        why.append("字符串池不透明度超阈（编译期字符串混淆）")
        return VIS_OPAQUE, why
    return VIS_COMPLETE, why


def _native_visibility(meta: dict) -> tuple[str, list[str]]:
    why: list[str] = []
    obf = meta.get("native_obfuscation")
    if isinstance(obf, dict):
        libs = obf.get("suspected") or obf.get("libraries") or []
        if libs:
            why.append(f"{len(libs)} 个 .so 疑加密/虚拟化，其中字符串不可读")
            return VIS_OPAQUE, why
    return VIS_COMPLETE, why


def _remediation(meta: dict) -> tuple[str, list[str]]:
    """脱壳补救到了哪一步。

    ★区分「脱壳成功」与「脱壳结果已成为当前报告的输入」：前者只说 DEX dump 出来了，后者才说明
    这份报告看到了那些 DEX。二者混同时，「步骤显示脱壳成功、报告却还是壳桩」从数据上看不出来。
    """
    lineage = meta.get("artifact_lineage")
    if isinstance(lineage, dict) and lineage.get("active_input") == "unpacked":
        n = lineage.get("unpacked_dex_count") or 0
        return REM_REANALYZED, [f"脱壳回灌已生效（{n} 个 DEX 进入本次分析）"]
    if meta.get("unpacked"):
        return REM_REANALYZED, ["报告自身即脱壳回灌产物"]
    return REM_NOT_ATTEMPTED, []


def assess(report: Any) -> dict[str, Any]:
    """求值一份报告的证据可见性与主张资格。绝不抛；坏输入 → 全 unknown 的保守结果。

    Returns:
        ``{"sources": {...}, "claims": {...}, "blocked_claims": [...], "remediation": ...,
        "notes": [...], "degraded": bool}``
    """
    try:
        meta = _meta(report)
        dex_vis, dex_why = _dex_visibility(meta)
        nat_vis, nat_why = _native_visibility(meta)
        rem, rem_why = _remediation(meta)

        # 脱壳回灌已生效 → DEX 重新可见（此时的 is_hardened 描述的是**原包**，不是当前输入）
        if rem == REM_REANALYZED and dex_vis == VIS_STUB_ONLY:
            dex_vis = VIS_COMPLETE
            dex_why.append("★上述加固结论属被取代的原包；当前输入为脱壳回灌产物")

        sources = {
            "dex": {"visibility": dex_vis, "why": dex_why},
            "native": {"visibility": nat_vis, "why": nat_why},
            # 资源层目前无专门的不可见信号；显式记 unknown 而非默认 complete——
            # 「没有信号」不等于「已确认完整」，这正是本模块要防的那类误读。
            "resource": {"visibility": VIS_UNKNOWN, "why": []},
        }

        claims: dict[str, dict] = {}
        blocked: list[str] = []
        for claim, needs in _CLAIM_REQUIREMENTS.items():
            missing = [s for s in needs
                       if sources.get(s, {}).get("visibility") in _INSUFFICIENT]
            eligible = not missing
            claims[claim] = {
                "label": _CLAIM_LABELS.get(claim, claim),
                "eligible": eligible,
                "missing_sources": missing,
            }
            if not eligible:
                blocked.append(claim)

        notes: list[str] = []
        for src, info in sources.items():
            for w in info["why"]:
                notes.append(f"[{src}] {w}")
        notes.extend(rem_why)
        if blocked:
            labels = "、".join(_CLAIM_LABELS.get(c, c) for c in blocked)
            notes.append(
                f"★以下结论**无资格下**（相关输入不可见）：{labels}。"
                "此处的「未发现」只说明本次没看到，不能解读为不存在。"
            )

        return {
            "schema_version": "1.0",
            "sources": sources,
            "claims": claims,
            "blocked_claims": sorted(blocked),
            "remediation": rem,
            "notes": notes,
            "degraded": bool(blocked),
        }
    except Exception:  # noqa: BLE001 — 求值失败不得影响主流程；返回保守的"全未知"
        logger.exception("[visibility] 可见性求值异常，返回保守结果")
        return {
            "schema_version": "1.0",
            "sources": {k: {"visibility": VIS_UNKNOWN, "why": []}
                        for k in ("dex", "native", "resource")},
            "claims": {}, "blocked_claims": sorted(_CLAIM_REQUIREMENTS),
            "remediation": REM_NOT_ATTEMPTED,
            "notes": ["可见性求值异常，全部穷尽性结论按无资格处理"],
            "degraded": True,
        }


def blocks_claim(assessment: Any, claim: str) -> bool:
    """某条主张是否被可见性阻断。消费方（closure/digest/preflight）用这个问，而不是自己读一堆 meta 键。

    ★这是"按主张相关性"消费的入口：与当前结论无关的 blocker 不该影响它。例如 DEX 不可见时，
    「pcap 实测连接过某 IP」照样成立——那条主张不依赖 DEX。
    """
    if not isinstance(assessment, dict):
        return False
    return claim in (assessment.get("blocked_claims") or [])


__all__ = [
    "REM_FAILED",
    "REM_NOT_ATTEMPTED",
    "REM_REANALYZED",
    "VIS_COMPLETE",
    "VIS_OPAQUE",
    "VIS_PARTIAL",
    "VIS_STUB_ONLY",
    "VIS_UNAVAILABLE",
    "VIS_UNKNOWN",
    "assess",
    "blocks_claim",
]
