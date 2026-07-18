"""第一方资产评分：给每个后端域名/IP 打一个加权 ``asset_score`` + reason，供报告/线索排序。

解密远程配置后往往一次冒出几十个后端域名，需按可信度排序，让办案人先看最像**App 自有后端**的那几个。
加权信号（纯从端点已有事实派生，不联网）：
- APK 代码/资源里硬编码引用（dex/resource/native/manifest）→ +30（自有后端强信号）
- 运行时实际访问（runtime*）→ +20
- 出现在解密的远程配置里（remote-config）→ +15
- 观测到业务/登录路径（runtime 业务/登录 API）→ +10
- 疑似自有后端（infra 判"建议调证"）→ +10；命中公共 SDK/CDN/云基础设施（"无需调证"）→ **-40**（沉底）

复用 ``core.infra.classify_domain`` 作公共域判据（单一事实源），IP 的公共边缘用五层归因的 edge_provider 判。
纯函数、绝不抛。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apkscan.core import infra

#: 静态引用来源（端点值硬编码在 APK 内）——见 analyzers/endpoints.py 的四路数据源。
_STATIC_SOURCES = frozenset({"dex", "resource", "native", "manifest"})

_W_STATIC = 30
_W_RUNTIME = 20
_W_CONFIG = 15
_W_OWN_BACKEND = 10
_W_BUSINESS = 10
_W_PUBLIC_INFRA = -40


@dataclass(frozen=True)
class AssetScore:
    """一个后端资产（域名/IP）的加权可信度评分 + 命中理由（每条带权重，便于报告解释排序）。"""

    value: str
    kind: str
    score: int
    reasons: tuple[str, ...]


def rank_assets(endpoints: list[Any]) -> list[AssetScore]:
    """给所有域名/IP 端点打分并按分**降序**排（同分按 value 升序，确定）。url 端点由其 host 覆盖，跳过。"""
    scores = [score_asset(ep) for ep in endpoints if getattr(ep, "kind", None) in ("domain", "ip")]
    scores.sort(key=lambda s: (-s.score, s.value))
    return scores


def score_asset(endpoint: Any) -> AssetScore:
    """给单个端点打加权 asset_score。绝不抛：缺字段按信号缺失处理。"""
    value = str(getattr(endpoint, "value", "") or "")
    kind = str(getattr(endpoint, "kind", "") or "")
    sources = {
        str(getattr(ev, "source", "")) for ev in (getattr(endpoint, "evidences", None) or [])
    }
    score = 0
    reasons: list[str] = []

    if sources & _STATIC_SOURCES:
        score += _W_STATIC
        reasons.append(f"apk-code-ref+{_W_STATIC}")
    if any(s.startswith("runtime") for s in sources):
        score += _W_RUNTIME
        reasons.append(f"runtime-access+{_W_RUNTIME}")
    if "remote-config" in sources:
        score += _W_CONFIG
        reasons.append(f"config-appearance+{_W_CONFIG}")
    if _has_business_path(endpoint):
        score += _W_BUSINESS
        reasons.append(f"business-path+{_W_BUSINESS}")

    delta, reason = _infra_signal(value, kind, endpoint)
    if delta:
        score += delta
        reasons.append(reason)

    return AssetScore(value=value, kind=kind, score=score, reasons=tuple(reasons))


def _has_business_path(endpoint: Any) -> bool:
    """端点是否被观测服务业务/登录 API 路径（runtime 累积的 business_api_paths / login_paths）。"""
    enrichment = getattr(endpoint, "enrichment", None)
    runtime = enrichment.get("runtime") if isinstance(enrichment, dict) else None
    if not isinstance(runtime, dict):
        return False
    for key in ("business_api_paths", "login_paths"):
        values = runtime.get(key)
        if isinstance(values, list) and any(isinstance(p, str) and p for p in values):
            return True
    return False


def _infra_signal(value: str, kind: str, endpoint: Any) -> tuple[int, str]:
    """公共基础设施判据：域名走 infra.classify_domain；IP 看五层归因 edge_provider。返回 (加减分, reason)。"""
    if kind == "domain" and value:
        advice, _reason = infra.classify_domain(value)
        if advice == infra.ADVICE_SKIP:
            return _W_PUBLIC_INFRA, f"public-infra{_W_PUBLIC_INFRA}"
        if advice == infra.ADVICE_INVESTIGATE:
            return _W_OWN_BACKEND, f"own-backend+{_W_OWN_BACKEND}"
        return 0, ""  # 待核 → 中性
    if kind == "ip" and _is_public_edge_ip(endpoint):
        return _W_PUBLIC_INFRA, f"public-edge{_W_PUBLIC_INFRA}"
    return 0, ""


def _is_public_edge_ip(endpoint: Any) -> bool:
    """IP 的五层归因里是否带 edge_provider（公共 CDN/防红边缘，非自有源站）→ 视作公共基础设施。"""
    enrichment = getattr(endpoint, "enrichment", None)
    attribution = enrichment.get("attribution") if isinstance(enrichment, dict) else None
    if not isinstance(attribution, dict):
        return False
    for record in attribution.get("ips") or []:
        if isinstance(record, dict):
            edge = record.get("edge_provider")
            if isinstance(edge, dict) and (edge.get("tier") or edge.get("name")):
                return True
    return False


__all__ = ["AssetScore", "rank_assets", "score_asset"]
