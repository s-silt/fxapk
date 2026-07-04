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

#: 单文件解压后大小硬上限：防 zip 炸弹（声明的解压体积可与压缩体积严重不成比例）。与
#: apk.py 的 _MAX_DECOMPRESSED_FILE_BYTES 同口径 500MB，理由同（远超合法单文件、拦住典型
#: zip 炸弹）；IPA 侧独立定义，避免跨模块耦合私有常量。
_MAX_DECOMPRESSED_FILE_BYTES = 500 * 1024 * 1024

#: read_file 缓存的单文件上限：超过此值的文件（大 framework 二进制 / 大资源）读到后不进
#: _read_cache，避免巨型二进制随分析常驻内存（缓存本意是让多个分析器重复读小文本资源命中，
#: 大文件重复读罕见，收益远不抵内存代价）。与 apk.py 的 _MAX_READ_CACHE_BYTES 同口径 32MB，
#: 保持 APK/IPA 缓存行为对称；IPA 侧独立定义，避免跨模块耦合私有常量。正确性不受影响——未
#: 缓存只是每次重读，read_file 返回的字节完全一致。
_MAX_READ_CACHE_BYTES = 32 * 1024 * 1024

#: 单实例生命周期内 _read_cache 累计缓存总量上限：防"许多个体各自都在 _MAX_READ_CACHE_BYTES
#: 以下"的文件累加撑爆内存——zip 炸弹的另一变体，不是单文件超大，是数量多（如几千个刚好卡在
#: 32MB 以下的伪装文本资源）。单文件上限挡不住这种累加。与 apk.py 的 _MAX_TOTAL_CACHE_BYTES
#: 同口径 256MB，保持 APK/IPA 对称；256MB 远超正常样本全部文本资源实测量级，只挡病态累加，
#: 不误伤真实场景。
_MAX_TOTAL_CACHE_BYTES = 256 * 1024 * 1024


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
        # _read_cache 累计已缓存字节数（防病态多文件累加撑爆内存，见 _MAX_TOTAL_CACHE_BYTES）。
        self._cached_bytes = 0

    # ---- 资源生命周期 ---------------------------------------------------
    # IpaContext 持有一个打开的 ZipFile（ApkContext 用 androguard 已读进内存、无句柄）。成功路径
    # 必须显式关闭，否则每分析一个 IPA 泄漏一个文件句柄，且 Windows 下会锁住 IPA 文件导致后续
    # 删除/移动失败。CLI 在 finally 里调 close()；亦支持 `with load_app(...) as ctx`。

    def close(self) -> None:
        """关闭底层 ZipFile（幂等、绝不抛）。"""
        try:
            self._zf.close()
        except Exception:  # noqa: BLE001 - 关闭失败无需炸主流程
            logger.exception("[ipa] 关闭 IPA ZipFile 失败（已忽略）")

    def __enter__(self) -> "IpaContext":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

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
        cache = self._read_cache
        if path in cache:
            return cache[path]
        data: bytes | None
        try:
            info = self._zf.getinfo(path)
            if info.file_size > _MAX_DECOMPRESSED_FILE_BYTES:
                logger.warning(
                    "[ipa] read_file 跳过（声明解压后 %d 字节超过 %d 上限，疑 zip 炸弹）：%s",
                    info.file_size,
                    _MAX_DECOMPRESSED_FILE_BYTES,
                    path,
                )
                data = None
            else:
                data = self._zf.read(path)
        except Exception:  # noqa: BLE001 — 缺失/读失败视为正常未命中
            logger.debug("[ipa] read_file 未命中：%s", path, exc_info=True)
            data = None
        # 超大文件（大 framework 二进制/大资源）不进缓存，避免常驻内存。None（未命中/被拦）仍缓存
        # 以避免重复未命中查询；小文件照常缓存供多分析器重复读命中。未缓存的文件（无论何种原因）
        # 仍返回完整字节，只是每次重读——不缓存只影响性能，不影响正确性。口径对齐 apk.py。
        if data is None:
            cache[path] = data
        elif len(data) > _MAX_READ_CACHE_BYTES:
            logger.debug(
                "[ipa] read_file 跳过缓存（超 %d 字节，避免常驻内存）：%s（%d 字节）",
                _MAX_READ_CACHE_BYTES,
                path,
                len(data),
            )
        elif self._cached_bytes + len(data) > _MAX_TOTAL_CACHE_BYTES:
            # 单文件不大，但累计缓存量将超总量上限——防"许多个体都在阈值以下"的病态累加。
            logger.debug(
                "[ipa] read_file 跳过缓存（累计缓存量将超总量上限 %d 字节）：%s（%d 字节，当前已缓存 %d 字节）",
                _MAX_TOTAL_CACHE_BYTES,
                path,
                len(data),
                self._cached_bytes,
            )
        else:
            cache[path] = data
            self._cached_bytes += len(data)
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
