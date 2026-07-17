"""远程配置对象分析器 —— 从 App 静态字符串里发现疑似运行时拉取的**远程配置对象**（OSS/COS/CDN 上的
配置文件），产 ``LeadCategory.REMOTE_CONFIG`` 候选线索。

涉诈 App 常把加密配置托管在对象存储/CDN，运行时下载后解密出**动态域名/IP 池**——这条链是"APK→控制面→
业务基础设施"的关键一跳。本分析器是该链的**被动发现半**：纯离线、零网络，只按 ``rules/remote_config.yaml``
的对象存储家族 + 配置类后缀/路径识别候选。下载 + 多层解码在授权档另行执行（复刻 pipeline 主被动硬隔离门）。

数据源（slice-1a）：``ctx.dex_strings()``（硬编码 URL 的最高产源）。资源/native 源作后续扩展，当前 scope
记入 meta（不静默截断）。

约束：只依赖 AnalysisContext 公开接口；逐源 try/except + logging，单源失败不拖垮其余；无候选 → 干净返回
error=None；全程 type hints。
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from apkscan.config.discover import DiscoveryRules, classify_config_url
from apkscan.config.models import RemoteConfigCandidate
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.textutil import strip_url_tail as _strip_url_tail

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# 仅 http/https 的对象 URL 可下载（ws/mqtt 等非配置对象通道由 endpoints 覆盖，此处不收）。
_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""", re.IGNORECASE)

# dex 字符串扫描上限（与 endpoints 一致，防加固样本超大字符串池扫过久）。
_MAX_DEX_STRINGS = 200_000

_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "向对象存储/CDN 厂商调取该 bucket/对象的上传主体实名、访问日志与对象历史版本",
)


class RemoteConfigAnalyzer(BaseAnalyzer):
    """发现远程配置对象候选（被动）。"""

    name = "remote_config"

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        rules = DiscoveryRules.load()
        candidates: dict[str, RemoteConfigCandidate] = {}

        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning(
                        "[remote_config] dex 字符串超上限 %d，其余未扫（大型/加固样本）", _MAX_DEX_STRINGS
                    )
                    break
                if not isinstance(s, str) or "://" not in s:
                    continue
                for match in _URL_RE.finditer(s):
                    url = _strip_url_tail(match.group(0))
                    if url in candidates:
                        continue
                    cand = classify_config_url(url, f"dex-string[{idx}]", rules)
                    if cand is not None:
                        candidates[url] = cand
        except Exception:
            logger.exception("[remote_config] 扫描 dex 字符串失败")
            return AnalyzerResult(analyzer=self.name, error="dex 字符串扫描失败")

        leads = [self._to_lead(c) for c in candidates.values()]
        return AnalyzerResult(
            analyzer=self.name,
            leads=leads,
            meta={
                "remote_config_candidate_count": len(leads),
                "remote_config_source_scope": "dex-strings",  # 显式声明已扫范围（非静默截断）
            },
        )

    def _to_lead(self, cand: RemoteConfigCandidate) -> Lead:
        notes = (
            f"远程配置对象候选（{cand.store_kind}）；命中：{', '.join(cand.reasons)}。"
            "授权档可下载 + 多层解码，取其中的动态域名/IP 池。"
        )
        return Lead(
            category=LeadCategory.REMOTE_CONFIG,
            value=cand.url,
            where_to_request=cand.store_kind if cand.store_kind != "http" else None,
            evidence_to_obtain=list(_EVIDENCE_TO_OBTAIN),
            confidence=Confidence.MEDIUM,
            source_refs=[Evidence(source="dex", location=cand.source_ref, snippet=cand.url[:200])],
            notes=notes,
            advice="待核",  # 静态候选、未下载解码，不下"建议调证"结论
        )
