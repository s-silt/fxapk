"""fxapk — APK 调证分析 CLI。"""

from __future__ import annotations

from fxapk._version import resolve_version

# 版本号优先取已安装包元数据（pyproject 的 version，pip 安装后自动正确）；源码树 / 冻结
# exe 无 dist-info 时回退到下面的保底串。保底串发版时与 pyproject 同步（_FALLBACK_VERSION）。
_FALLBACK_VERSION = "2.0.2"

__version__ = resolve_version(_FALLBACK_VERSION).effective_version

__all__ = ["__version__"]
