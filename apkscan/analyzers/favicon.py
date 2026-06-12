"""favicon / 应用图标 mmh3 指纹分析器 —— 产测绘引擎 pivot 锚点线索。

杀猪盘换皮但复用同一套后台前端 / 图标。一个 favicon hash 能把单包后端扩成同团伙站群：
办案人把 hash 丢 FOFA/Quake/ZoomEye/Shodan/Censys 反查同 hash 的全部公网 IP/域名（后台
面板与钓鱼站群），再向机房/IDC 调服务器租用主体。也是团伙聚类的强连边键。

职责：
- 从 ctx.list_files() 定位图标：res/mipmap*/、res/drawable* 下 ic_launcher*.png|.webp；
  assets/**/favicon.ico、static/favicon.*、www/**/favicon.*。
- ctx.read_file() 读字节 → favicon_hash（Shodan/FOFA 口径 = mmh3(base64.encodebytes(raw))）。
- denylist（命中即跳过、不产线索）：常见/空白/通用模板图标的 hash + 显然的空白占位
  内容（空字节 / 全透明纯色占位）。否则通用图标撞库产海量噪音。
- 命中（非 denylist）→ Lead(category=CONFIG_KEY)：value=favicon_mmh3=<hash>，
  notes 带 FOFA/Shodan/ZoomEye 一键查询串；并写 result.meta["favicon_mmh3"]=<int> 供团伙聚类。
- 本期不主动发测绘查询（只产查询串 Lead）。

约束：
- 只依赖 AnalysisContext 公开接口（list_files / read_file），禁止 import androguard。
- 每图标读取/哈希 try/except，单个坏图标不炸 analyze；顶层数据源失败记 error 而非抛。
- 绝不 print，全程 type hints。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Lead,
    LeadCategory,
)
from apkscan.core.registry import BaseAnalyzer
from apkscan.dynamic.fingerprint import favicon_hash

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_META_KEY = "favicon_mmh3"

# 候选图标文件 basename / 路径特征（小写匹配）。
# - Android 启动图标：res/mipmap*/、res/drawable* 下 ic_launcher*.png|.webp
# - Web/混合前端 favicon：assets/**/favicon.*、static/favicon.*、www/**/favicon.*
_LAUNCHER_DIR_HINTS: tuple[str, ...] = ("res/mipmap", "res/drawable")
_LAUNCHER_NAME_PREFIX = "ic_launcher"
_FAVICON_DIR_HINTS: tuple[str, ...] = ("assets/", "static/", "www/")
_FAVICON_BASENAME = "favicon."
_ICON_EXTS: tuple[str, ...] = (".png", ".webp", ".ico", ".jpg", ".jpeg")

# ---------------------------------------------------------------------------
# denylist —— 常见 / 空白 / 通用模板图标，命中即跳过、不产线索。
#
# ★ 扩充方式：拿一批正常 App（市场 Top 应用、开源样板工程、各框架默认脚手架图标）
#   批量跑本分析器，把高频复现、明显非专属的 favicon hash 收进 _DENY_HASHES。
#   先放显然的排除项（空字节 / 全透明纯色占位），避免通用图标撞库产海量噪音。
# ---------------------------------------------------------------------------
_DENY_HASHES: frozenset[int] = frozenset(
    {
        0,  # 空字节（encodebytes(b"")==b"" → mmh3("")==0）
        540142872,  # 1KB 全 0x00 占位（典型空白/全透明纯色模板）
        # TODO: 用一批正常 App 跑出的通用模板图标 hash 在此扩充。
    }
)


class FaviconAnalyzer(BaseAnalyzer):
    """从应用图标 / favicon 抽 mmh3 指纹，产测绘 pivot 锚点线索。"""

    name: str = "favicon"
    requires: list[str] = []  # 纯文件读取，APK/IPA 通用，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        try:
            paths = ctx.list_files()
        except Exception:  # 顶层数据源失败：记 error 而非抛
            logger.exception("[%s] 读取文件列表失败", self.name)
            result.error = "读取文件列表失败"
            return result

        candidates = [p for p in paths if isinstance(p, str) and self._is_icon_path(p)]
        if not candidates:
            logger.info("[%s] 未发现候选图标 / favicon 文件", self.name)
            return result

        # 同一 hash 只产一条线索（多分辨率图标内容常一致）；记录首个命中路径作证据。
        emitted: set[int] = set()
        for path in candidates:
            try:
                self._process_icon(ctx, path, result, emitted)
            except Exception:
                # 单个坏图标不应炸掉整个 analyze；记录后继续。
                logger.exception("[%s] 处理图标失败，跳过：%s", self.name, path)

        return result

    # ------------------------------------------------------------------
    # 单图标处理
    # ------------------------------------------------------------------

    def _process_icon(
        self,
        ctx: "AnalysisContext",
        path: str,
        result: AnalyzerResult,
        emitted: set[int],
    ) -> None:
        raw = ctx.read_file(path)
        if not raw:  # None（读不到）/ 空字节 → 跳过（空字节亦属显然排除项）
            return

        if _is_blank_placeholder(raw):
            logger.debug("[%s] 跳过空白/纯色占位图标：%s", self.name, path)
            return

        h = favicon_hash(raw)

        if h in _DENY_HASHES:
            logger.debug("[%s] 跳过 denylist 通用模板图标（hash=%s）：%s", self.name, h, path)
            return

        if h in emitted:
            return
        emitted.add(h)

        # meta 并簇键（首个非 denylist 命中即写；供 dynamic/correlate 当强连边）。
        if _META_KEY not in result.meta:
            result.meta[_META_KEY] = h

        result.leads.append(self._build_lead(h, path))

    def _build_lead(self, h: int, path: str) -> Lead:
        return Lead(
            category=LeadCategory.CONFIG_KEY,
            value=f"favicon_mmh3={h}",
            subject="待核（测绘 pivot 锚点）",
            where_to_request="FOFA / Quake / ZoomEye / Shodan / Censys 测绘平台",
            evidence_to_obtain=[
                "同 favicon hash 的全部公网 IP/域名（后台面板与钓鱼站群）",
                "据此向机房/IDC 调服务器租用主体",
            ],
            confidence=Confidence.HIGH,
            source_refs=[
                Evidence(
                    source="resource",
                    location=path,
                    snippet=f"favicon_mmh3={h}",
                )
            ],
            notes=_query_strings(h),
            advice="建议调证",
        )

    # ------------------------------------------------------------------
    # 图标路径识别
    # ------------------------------------------------------------------

    @staticmethod
    def _is_icon_path(path: str) -> bool:
        low = path.lower().replace("\\", "/")
        if not low.endswith(_ICON_EXTS):
            return False
        base = low.rsplit("/", 1)[-1]

        # Android 启动图标：res/mipmap*/ 或 res/drawable* 下的 ic_launcher*。
        if base.startswith(_LAUNCHER_NAME_PREFIX) and any(
            hint in low for hint in _LAUNCHER_DIR_HINTS
        ):
            return True

        # Web/混合前端 favicon.*（assets/ static/ www/ 下任意层级）。
        if base.startswith(_FAVICON_BASENAME) and any(
            hint in low for hint in _FAVICON_DIR_HINTS
        ):
            return True

        return False


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _query_strings(h: int) -> str:
    """三家测绘平台一键复制查询串（FOFA / Shodan / ZoomEye）。"""
    return (
        f'icon_hash="{h}" (FOFA)；'
        f"http.favicon.hash:{h} (Shodan)；"
        f'iconhash:"{h}" (ZoomEye)'
    )


def _is_blank_placeholder(raw: bytes) -> bool:
    """是否为显然的空白占位（空字节 / 单一字节重复，如全 0x00 全透明纯色模板）。

    只排除“没有任何图形信息”的字节流——单字节重复（含空字节）即视为空白占位，
    不会误伤真实图标（真实 PNG/WebP 含文件头/IDAT，字节必然多样）。
    """
    if not raw:
        return True
    first = raw[0]
    return all(b == first for b in raw)
