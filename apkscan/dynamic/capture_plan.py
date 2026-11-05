"""Bounded acquisition suggestions, not authorization or evidence-closure decisions.

Static hints select questions to verify. Recipe presence, empty endpoints and
early exits do not establish plaintext recovery, protocol implementation or cause.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, is_dataclass
from typing import Any

logger = logging.getLogger(__name__)

# 结构化决策的硬约束常量（把 capture_plan 的铁律落到引擎可读的字段）。
_TOTAL_BUDGET_SEC = 3600  # 单轮资源上限，不是案件闭环条件。
_RETREAT_THRESHOLD_DEFAULT = 3  # 同条件重复失败的资源上限，不诊断退出原因。
_RETREAT_THRESHOLD_PACKED = 2

# 铁律永远第一条——这是治"几小时零产出"的行为约束。
_DIRECTIVES = (
    "【铁律·先读】仅在本次授权范围内执行；工具建议不增加授权。floor 优先：先保存无探针原包基线，再观察。"
    "单轮时间盒 ≤60min；同条件秒退无进展即停止重试，累计上限 2~3 次仅限制资源。"
    "零流量、未触发、归因不足、failed/partial 分别保留。时间耗尽或已有线索均不表示案件闭环。"
)
_BASELINE = (
    "【第0步·原包基线·≤15min】按现有设备与网络条件保存带外 pcap、原 APK 哈希、操作窗口和 UID/socket 归因。"
    "PCAPdroid 的 VpnService 与网关 tcpdump 各有覆盖限制，按实际采集方式记录。"
    "接入节点 IP:port、SNI、DNS 是待核基础设施线索，不能直接认定源站或运营者；"
    "不能保证取得流量。核同一目标双向载荷、业务触发和时间对应，不以节点数量替代取证质量。"
)
_PINNING = (
    "【TLS 诊断·≤20min】证书告警或代理零流量不独立证明 pinning。先核路由、代理、CA 信任、"
    "目标业务是否触发、实际 TLS 库与现有日志。只读观察按已定位层选择；"
    "重签、去 pin、替换返回值等行为修改须核已有专项授权并另记 modified-runtime，与原包基线分开。"
)
_STOP = (
    "【停止门·资源与证据分开】本轮问题已有对应原始证据时停止该项；相同错误无新线索或预算耗尽时停止重试并交付缺口。"
    "配方仅为候选，须绑定当前样本和报文、核参数/认证/负例并逐字节对照；资源或配置解密不等于业务回传。"
    "案件是否闭环按实际范围与证据合同复核，不由预算、退出次数、明文可读性或接入节点数量决定。"
)
_MERGE = (
    "【回灌串案】核输入哈希、窗口与来源后回灌可写工作报告；冻结包保留原字节，新证据创建新 revision。"
    "`fxapk probe-leads probe.log --into report.json "
    "--sample-sha <样本sha256>`（探针；日志无样本标识，须显式声明并与报告 meta.sample_sha256 相符）/ "
    "`fxapk pcap-leads capture.pcap --into report.json`（pcap），合并进同一 report.leads 串案，"
    "未归因和覆盖缺口继续保留，不因合并成功升级证据状态。"
)


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    if isinstance(v, dict):
        return v
    # Report 等 dataclass:用报告的 JSON 序列化口径(Enum→值、逐字段递归)转 dict,否则
    # fxapk auto 传入的 Report dataclass 会被当成 {} → 规避信号全 False、决策静默退默认(接线空转)。
    if is_dataclass(v) and not isinstance(v, type):
        try:
            # 复用报告序列化器的底层转换(Enum→值、逐字段递归),吃任意 dataclass。
            from apkscan.report.json import _to_jsonable

            d = _to_jsonable(v)
            return d if isinstance(d, dict) else {}
        except Exception:
            logger.debug("Report→dict 转换失败,退化为空信号", exc_info=True)
            return {}
    return {}


def _is_packed(findings: list, leads: list) -> bool:
    for f in findings:
        if isinstance(f, dict) and str(f.get("id")) == "PACK-DETECTED":
            return True
    for lead in leads:
        if isinstance(lead, dict) and str(lead.get("category")) == "PACKER":
            return True
    return False


def _has_lead_category(leads: list, category: str) -> bool:
    return any(isinstance(lead, dict) and str(lead.get("category")) == category for lead in leads)


def _telegram_hint(leads: list, findings: list) -> bool:
    needles = ("telegram", "mtproto", "tgnet", "tlrpc")
    for item in (*leads, *findings):
        if not isinstance(item, dict):
            continue
        blob = " ".join(
            str(item.get(k, "")) for k in ("value", "notes", "title", "description", "subject")
        ).lower()
        if any(n in blob for n in needles):
            return True
    return False


@dataclass(frozen=True)
class _Signals:
    """从 report 抠出的规避信号（plan_capture 文本与 decide_capture 决策共用，杜绝漂移）。"""

    packed: bool = False
    zero_endpoints: bool = False
    has_crypto_recipe: bool = False
    self_hosted_im: bool = False
    anti_frida: bool = False  # 静态反分析候选，不是当前退出原因证明。
    endpoint_count: int = 0


def _extract_signals(report: Any) -> _Signals:
    """从 report 提取规避信号，绝不抛（坏输入退化为全 False）。"""
    try:
        rep = _as_dict(report)
        findings = _as_list(rep.get("findings"))
        leads = _as_list(rep.get("leads"))
        endpoints = _as_list(rep.get("endpoints"))
        meta = _as_dict(rep.get("meta"))
        ep_count = sum(1 for e in endpoints if isinstance(e, dict))
        return _Signals(
            packed=_is_packed(findings, leads),
            zero_endpoints=isinstance(rep.get("endpoints"), list) and not endpoints,
            has_crypto_recipe=any(
                isinstance(meta.get(key), dict) and bool(meta[key])
                for key in ("crypto_recipe", "runtime_crypto_recipe")
            ),
            self_hosted_im=(
                _telegram_hint(leads, findings) or _has_lead_category(leads, "SELF_HOSTED_IM")
            ),
            anti_frida=bool(meta.get("anti_frida")),
            endpoint_count=ep_count,
        )
    except Exception:  # noqa: BLE001 - 信号提取不该抛，坏 report 退化为全 False
        logger.exception("[capture-plan] 信号提取异常，退化为全 False")
        return _Signals()


@dataclass(frozen=True)
class CaptureDecision:
    """抓包引擎可消费的结构化决策（与 plan_capture 文本同源，见 _extract_signals）。

    保留现有字段兼容调用者。静态报告不能单独决定跳过明文观察或确定 native 实现；
    对这两项返回 False（证据不足），不表示必须注入或已证明非 native。
    """

    floor_first: bool  # 先保存原包带外基线，结果可能 partial/failed。
    prefer_offline_decrypt: bool  # 有候选配方 → 优先离线验证，尚未证实解密成功。
    skip_frida_plaintext: bool  # 静态信号不能自动跳过观察，也不授权注入。
    expect_native_protocol: bool  # 静态端点数量/IM 名称不能证明 native 实现。
    frida_retreat_threshold: int  # frida 秒退累计达此数即弃明文、退 floor。
    total_budget_sec: int  # 抓包总预算（铁律 ≤60min）。
    signals: dict[str, bool]  # 原始信号，供上层透明展示 / 调试。
    reasons: tuple[str, ...]  # 决策依据（人读）。
    evidence_readiness: dict[str, Any] = field(default_factory=dict)


def decide_capture(report: Any) -> CaptureDecision:
    """据 report 规避信号产出结构化抓包决策（供引擎读），绝不抛。

    与 plan_capture 共用 _extract_signals，保证『机器决策』与『人读打法』永不漂移。
    """
    s = _extract_signals(report)
    reasons: list[str] = ["floor 优先：保存原包基线；预算/重试上限不代表取证完成"]
    if s.has_crypto_recipe:
        reasons.append("候选配方 → 优先离线验证当前样本与报文，不能仅据字段存在跳过明文观察")
    if s.zero_endpoints:
        reasons.append("endpoint=0 → 静态可见性缺口，不能推断协议或实现层")
    if s.self_hosted_im:
        reasons.append("自建 IM / Telegram 候选 → 核实际调用和协议，名称不证明 native 实现")
    if s.packed:
        reasons.append("加固候选 → 同条件重试资源上限下调至 2，不据此诊断秒退原因")
    if s.anti_frida:
        reasons.append(
            "静态反 frida 候选 → 对照无探针/启动注入/延后观察窗口，先核 API/bridge/ABI 与日志；"
            "重试上限下调，未命中不表示不存在"
        )
    return CaptureDecision(
        floor_first=True,
        prefer_offline_decrypt=s.has_crypto_recipe,
        skip_frida_plaintext=False,
        expect_native_protocol=False,
        frida_retreat_threshold=(
            _RETREAT_THRESHOLD_PACKED
            if (s.packed or s.anti_frida)
            else _RETREAT_THRESHOLD_DEFAULT
        ),
        total_budget_sec=_TOTAL_BUDGET_SEC,
        signals={
            "packed": s.packed,
            "zero_endpoints": s.zero_endpoints,
            "has_crypto_recipe": s.has_crypto_recipe,
            "self_hosted_im": s.self_hosted_im,
            "anti_frida": s.anti_frida,
        },
        reasons=tuple(reasons),
        evidence_readiness=capture_evidence_readiness(report),
    )



def capture_evidence_readiness(report: Any) -> dict[str, Any]:
    """Make acquisition gaps machine-readable without claiming capture success."""
    from apkscan.core.closure.gates import evaluate_capture_quality
    rep = _as_dict(report)
    meta = _as_dict(rep.get("meta"))
    quality = meta.get("capture_quality", meta.get("runtime_capture_quality"))
    if not isinstance(quality, dict) or not quality:
        return {"status": "not_supplied", "gaps": ["capture_quality_missing"],
                "operator_identity_verified": False}
    try:
        result = evaluate_capture_quality(quality)
    except (TypeError, ValueError, OverflowError):
        return {"status": "invalid_quality", "gaps": ["capture_quality_invalid"],
                "operator_identity_verified": False}
    gaps = []
    if not result["target_attributed_count"]:
        gaps.append("target_app_attribution_missing")
    if not result["bidirectional_target_count"]:
        gaps.append("same_target_bidirectional_payload_missing")
    if result["runtime_variant"] == "modified-runtime":
        gaps.append("behavior_modified_observation_not_independent")
    if quality.get("capture_apk_identity_which") in (None, "", "unknown"):
        gaps.append("running_apk_identity_requires_confirmation")
    if result["floor_parse_status"] not in ("ok", "absent", ""):
        gaps.append("packet_capture_parse_incomplete")
    return {"status": "needs_review" if gaps else "quality_checks_satisfied",
            "dynamic_quality_status": result["dynamic_status"], "gaps": gaps,
            "operator_identity_verified": False}


def plan_capture(report: Any) -> list[str]:
    """据 report（dict）规避信号产出抓包打法步骤（有序、带时间盒/停止门）。

    绝不抛；坏输入也至少给『铁律 + 起手式』。第一条恒为铁律、第二条恒为带外 pcap 保底。
    """
    steps: list[str] = [_DIRECTIVES, _BASELINE]
    try:
        s = _extract_signals(report)
        has_recipe, packed, zero_ep, telegram = (
            s.has_crypto_recipe,
            s.packed,
            s.zero_endpoints,
            s.self_hosted_im,
        )

        # 优先复核已有材料，不把配方存在写成已成功解密。
        if has_recipe:
            steps.append(
                "【候选配方·优先离线验证】核 crypto_recipe/runtime_crypto_recipe 的算法、参数来源和当前样本绑定。"
                "对已保存密文独立解密，与捕获输出逐字节比较，认证算法增加篡改负例；"
                "验证失败保留原因，不因配方存在而跳过所需观察。"
            )
        if packed:
            steps.append(
                "【加固候选·≤20min】先核原包结构、实际加载模块、已有恢复 DEX 和目标类覆盖。"
                "恢复物绑定来源并检查头部、解析和语义覆盖；不能以可打开代替完整脱壳。"
                "启动注入退出时核 Frida/API/Java bridge/ABI，比较无探针与延后只读观察；"
                "相同条件无进展即停，重试上限 2 次，不自动重打包或改变反检测行为。"
            )
        if s.anti_frida:
            steps.append(
                "【反 frida 候选·≤10min】静态工具特征不证明本次检测执行或退出原因。"
                "核进程、加载时机、脚本实际加载/错误/事件计数，按证据选择最小观察点。"
                "未命中保留覆盖未知；恢复阶段保持已有可用网络与原始日志。"
            )
        if zero_ep:
            steps.append(
                "【endpoint=0·≤20min】只说明报告未列出静态端点；先核分析器状态、DEX/资源/JNI 覆盖和业务触发。"
                "不能据此判断 native、自建协议或无网络行为；按原包 PCAP 与具体调用路径选择补证。"
            )
        if telegram:
            steps.append(
                "【自建 IM / Telegram 候选】先查具体类/函数与调用路径；确认匹配后才选择 telegram-mtproto-hook、"
                "netstat-hook 或 native-ssl 的只读观察面。名称不证明 native 协议或运营者；登录等业务操作按本次授权。"
            )

        steps.append(_PINNING)
        steps.append(_STOP)
        steps.append(_MERGE)
    except Exception:  # noqa: BLE001 - 出打法不该抛，坏 report 也至少给铁律 + 起手式
        logger.exception("[capture-plan] 生成打法异常，仅返回铁律 + 起手式")
    return steps
