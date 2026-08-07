"""应用框架识别分析器：把「这份样本用什么框架写的、业务代码在哪」写进 ``report.meta``。

判据实现在 :mod:`apkscan.core.appframework`（纯函数、可单测）；本分析器只负责取 native
库清单、调用它、落 meta。

为什么要有这一层
----------------
判据里散着大量「这个 .so 是不是第三方的」判断，而答案取决于框架——Flutter/Unity 把整份
业务代码编译进单个 .so，那个文件与并列的引擎库性质完全相反。此前没有统一结论可查，
各处只能各自打补丁；一处漏判就会把本应用的真后端当成第三方常量降档。

本分析器不产 Lead / Finding：框架是**背景事实**，不是可发函的线索，也不是缺陷。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkscan.core.appframework import META_KEY, detect_framework
from apkscan.core.models import AnalyzerResult
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

__all__ = ["META_KEY", "AppFrameworkAnalyzer"]


class AppFrameworkAnalyzer(BaseAnalyzer):
    """识别 Flutter / Unity / React Native 等框架，并定位其业务代码容器。"""

    name: str = "app_framework"
    meta_key_categories = {META_KEY: "record"}
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = ["apk"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        # 失败安全：任何一步塌了都留一份「未识别」的完整结构，
        # 下游读到 identified=False 会保持原有行为，而不是把缺数据当成「原生应用」。
        meta: dict = {
            "identified": False,
            "name": "",
            "own_code_libs": [],
            "runtime_libs": [],
            "evidence": [],
        }
        result.meta[META_KEY] = meta
        try:
            libs = list(ctx.native_libs() or [])
        except Exception:  # noqa: BLE001 - 单源失败不炸整个分析
            logger.exception("[%s] 取 native 库清单失败", self.name)
            return result

        fw = detect_framework(libs)
        meta.update(
            identified=fw.identified,
            name=fw.name,
            own_code_libs=list(fw.own_code_libs),
            runtime_libs=list(fw.runtime_libs),
            evidence=list(fw.evidence),
        )
        return result
