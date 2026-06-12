"""apkscan — 涉诈 APK / iOS IPA 调证分析 CLI。"""

from __future__ import annotations

# 版本号优先取已安装包元数据（pyproject 的 version，pip 安装后自动正确）；源码树 / 冻结
# exe 无 dist-info 时回退到下面的保底串。保底串发版时与 pyproject 同步（_FALLBACK_VERSION）。
_FALLBACK_VERSION = "0.6.3"
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    try:
        __version__ = _pkg_version("fxapk")
    except PackageNotFoundError:  # 未安装（直接跑源码树 / 冻结 exe 未带元数据）
        __version__ = _FALLBACK_VERSION
except Exception:  # pragma: no cover - importlib.metadata 理论上恒在；兜底不让 import 失败
    __version__ = _FALLBACK_VERSION

__all__ = ["__version__"]
