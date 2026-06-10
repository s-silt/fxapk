"""IPA（iOS 应用包）静态分析的 AnalysisContext 实现。

iOS 涉诈软件多是套了个 H5（WKWebView 加载打包/远程的 H5），真东西在 H5/JS 里。IPA 本质是
ZIP，结构 ``Payload/<App>.app/``。本模块用**标准库** zipfile + plistlib 解 IPA，把 ``.app``
文件树喂进现有的字符串/JS 型 analyzer（js_bundle/crypto_recipe/endpoints/config_keys…），
这些 analyzer 认 ``/www/`` 路径，而 iOS H5 壳恰好把 H5 放在 ``.app/.../www/`` 下。

★ 接口契约（对标 core/apk.py）：
- 实现 ``AnalysisContext`` 协议；``platform="ios"``、``dex_available=False``。
- Android 专属成员（manifest_xml/permissions/components/certificates）给空，pipeline 据
  ``platform`` 注入 ``ipa`` 能力，让 requires=["apk"] 的 Android analyzer 自动 skipped。
- ``dex_strings()`` 复用 ``core.macho`` 从主二进制抽可读 ASCII 串（弥补 IPA 无 DEX 字符串池；
  FairPlay 加密则优雅返空）。
- zipfile/plistlib 的 import 只允许出现在本文件（对标 androguard 隔离原则）。
- 全程 try/except + logging，绝不把异常抛给调用方（除构造期 IpaParseError）。
"""

from __future__ import annotations

import logging
import posixpath
import zipfile
from functools import cached_property
from io import BytesIO
from pathlib import Path
from typing import Any

from apkscan.core import macho
from apkscan.core.apk import ApkParseError
from apkscan.core.models import AnalysisConfig, CertInfo, ComponentSet

logger = logging.getLogger(__name__)


class IpaParseError(ApkParseError):
    """IPA 无法解析（损坏 / 非 IPA / 缺 Payload·Info.plist）。

    继承 ApkParseError：CLI 的 ``except ApkParseError`` 同样 catch，exit 2 契约不变。
    """


def is_ipa(path: str) -> bool:
    """判定一个文件是否为 IPA：``.ipa`` 后缀优先；否则看 ZIP 内是否有 ``Payload/`` 条目。

    后缀短路（毫秒级）；无 ``.ipa``/``.apk`` 后缀时才打开 ZIP 看中央目录（只读目录、不解压）。
    任何异常 → False（不抛）。
    """
    try:
        suffix = Path(path).suffix.lower()
    except Exception:  # noqa: BLE001
        return False
    if suffix == ".ipa":
        return True
    if suffix == ".apk":
        return False  # 明确是 APK，不必开 ZIP
    # 无后缀/其它后缀：看是不是含 Payload/ 的 ZIP。
    try:
        with zipfile.ZipFile(path) as zf:
            return any(n.startswith("Payload/") for n in zf.namelist())
    except Exception:  # noqa: BLE001 — 非 ZIP / 打不开 → 不是 IPA
        return False


class IpaContext:
    """AnalysisContext 的 IPA 实现（zipfile + plistlib 驱动）。通过 load_ipa() 构造。"""

    platform: str = "ios"

    def __init__(
        self,
        zf: zipfile.ZipFile,
        app_root: str,
        plist: dict[str, Any],
        config: AnalysisConfig,
        *,
        apk_path: str = "",
    ) -> None:
        self._zf = zf
        self._app_root = app_root  # 形如 "Payload/Demo.app/"
        self._plist = plist
        self.config = config
        self.apk_path = apk_path  # IPA 原始文件路径（保持协议字段名）
        # iOS 无 DEX：显式降级标志（pipeline 据此不把"无 DEX"当成加固告警）。
        self.dex_available = False
        self.apk_validation_ok = True
        self._read_cache: dict[str, bytes | None] = {}

    # ---- 标量属性 -------------------------------------------------------

    @cached_property
    def package_name(self) -> str:
        """iOS 用 CFBundleIdentifier 作包标识（供 report.meta / 报告命名）。"""
        return str(self._plist.get("CFBundleIdentifier") or "")

    @property
    def manifest_xml(self) -> str:
        """iOS 无 AndroidManifest → 空串（吃 manifest 的 analyzer 自然降级/被门控跳过）。"""
        return ""

    # ---- 协议方法 -------------------------------------------------------

    def permissions(self) -> list[str]:
        return []  # iOS 无 Android 权限声明（权限用途在 Info.plist，由 ios_plist analyzer 出）

    def components(self) -> ComponentSet:
        return ComponentSet()  # iOS 无四大组件

    def dex_strings(self):  # -> Iterator[str]
        """把主二进制（Mach-O）的可读 ASCII 串当"字符串池"产出（弥补无 DEX）。

        FairPlay 加密 / 读不到主二进制 → 空（core.macho 已优雅降级）。H5 端点本就在 www JS 里
        由 list_files/read_file 通道命中，主二进制串是对"远程 H5 壳"入口 URL 的补充。
        """
        return iter(self._macho_strings)

    @cached_property
    def _macho_strings(self) -> tuple[str, ...]:
        exe = str(self._plist.get("CFBundleExecutable") or "")
        if not exe:
            return ()
        data = self.read_file(self._app_root + exe)
        if not data:
            return ()
        return tuple(macho.scan_ascii_strings(data))

    def list_files(self) -> list[str]:
        """``.app`` 内全部文件路径（路径分隔归一为 ``/``，与 js_bundle/endpoints 口径一致）。"""
        try:
            return [
                n.replace("\\", "/")
                for n in self._zf.namelist()
                if n.startswith(self._app_root) and not n.endswith("/")
            ]
        except Exception:  # noqa: BLE001
            logger.exception("[ipa] 列文件失败")
            return []

    def read_file(self, path: str) -> bytes | None:
        if path in self._read_cache:
            return self._read_cache[path]
        data: bytes | None
        try:
            data = self._zf.read(path)
        except Exception:  # noqa: BLE001 — 缺失/读失败视为正常未命中
            logger.debug("[ipa] read_file 未命中：%s", path, exc_info=True)
            data = None
        self._read_cache[path] = data
        return data

    def native_libs(self) -> list[str]:
        """对标 .so：iOS 的 .dylib / .framework 二进制（packing/sdk_fingerprint 已门控跳过，
        此处仅为协议完整；endpoints 的 native_libs 通道用得上，无害）。"""
        return [
            f for f in self.list_files()
            if f.endswith(".dylib") or "/Frameworks/" in f
        ]

    def certificates(self) -> list[CertInfo]:
        return []  # iOS 代码签名非 APK 证书结构；certificate analyzer 已门控跳过


# ---------------------------------------------------------------------------
# 加载
# ---------------------------------------------------------------------------


def _find_app_root(names: list[str]) -> str:
    """从 ZIP 条目名定位 ``Payload/<App>.app/`` 前缀。取首个匹配；找不到 → 空串。"""
    for n in names:
        norm = n.replace("\\", "/")
        idx = norm.find(".app/")
        if norm.startswith("Payload/") and idx != -1:
            return norm[: idx + len(".app/")]
    return ""


def load_ipa(path: str, config: AnalysisConfig) -> IpaContext:
    """加载 IPA 并构造 IpaContext。无法解析 → IpaParseError（fail fast）。

    流程：开 ZIP → 定位 ``Payload/<App>.app/`` → plistlib 解 Info.plist（支持 binary plist）。
    """
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[ipa] 打开 IPA(ZIP) 失败：%s", path)
        raise IpaParseError(f"无法打开 IPA（非法 ZIP？）：{path}（{exc}）") from exc

    try:
        names = zf.namelist()
    except Exception as exc:  # noqa: BLE001
        zf.close()
        raise IpaParseError(f"无法读取 IPA 目录：{path}（{exc}）") from exc

    app_root = _find_app_root(names)
    if not app_root:
        zf.close()
        raise IpaParseError(f"非法 IPA（缺 Payload/<App>.app/）：{path}")

    plist_name = app_root + "Info.plist"
    try:
        raw = zf.read(plist_name)
    except Exception as exc:  # noqa: BLE001
        zf.close()
        raise IpaParseError(f"非法 IPA（缺 Info.plist）：{path}（{exc}）") from exc

    plist = _parse_plist(raw)
    if plist is None:
        zf.close()
        raise IpaParseError(f"非法 IPA（Info.plist 解析失败）：{path}")

    try:
        ipa_path = str(Path(path).resolve())
    except Exception:  # noqa: BLE001
        ipa_path = path

    logger.info(
        "[ipa] 加载 IPA：%s bundleID=%s app=%s",
        path,
        plist.get("CFBundleIdentifier", "?"),
        posixpath.basename(app_root.rstrip("/")),
    )
    return IpaContext(zf=zf, app_root=app_root, plist=plist, config=config, apk_path=ipa_path)


def _parse_plist(raw: bytes) -> dict[str, Any] | None:
    """plistlib 解析（自动识别 binary / xml plist）；失败或非 dict → None。"""
    import plistlib

    try:
        obj = plistlib.load(BytesIO(raw))
    except Exception:  # noqa: BLE001
        logger.exception("[ipa] plistlib 解析 Info.plist 失败")
        return None
    return obj if isinstance(obj, dict) else None


__all__ = ["IpaContext", "IpaParseError", "is_ipa", "load_ipa"]
