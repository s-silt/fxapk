"""统一加载入口：按文件类型（APK / IPA）分流到对应的 AnalysisContext 构造器。

放在独立模块（而非 apk.py 或 ipa.py 内）以避免 apk.py↔ipa.py 互相 import；二者各自隔离其
平台依赖（apk→androguard，ipa→zipfile/plistlib），loader 只做薄分流。
"""

from __future__ import annotations

import logging

from apkscan.core.models import AnalysisConfig

logger = logging.getLogger(__name__)


def load_app(path: str, config: AnalysisConfig, extra_dex: list[str] | None = None):
    """按文件类型加载：``.ipa`` / 含 Payload/ 的 ZIP → IpaContext；否则 → ApkContext。

    返回实现 ``AnalysisContext`` 协议的上下文。解析失败抛 ApkParseError 的子类
    （ApkParseError / IpaParseError），CLI 的 ``except ApkParseError`` 统一兜住、exit 2。

    extra_dex 仅对 APK 有意义（脱壳 dump 的 .dex）；IPA 无 DEX，忽略并记日志。
    """
    from apkscan.core.ipa import is_ipa

    if is_ipa(path):
        if extra_dex:
            logger.info("[loader] IPA 无 DEX，忽略 extra_dex：%s", extra_dex)
        from apkscan.core.ipa import load_ipa

        return load_ipa(path, config)

    from apkscan.core.apk import load_apk

    return load_apk(path, config, extra_dex)


__all__ = ["load_app"]
