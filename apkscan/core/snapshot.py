"""可 pickle 的分析上下文快照（供分析器进程池并行）。

★ 动机：分析器串行跑（~11 个对 12 万 dex 字符串各自正则扫描）是全链 CPU 地板。要并行只能走
**进程池**（Python GIL 使线程对纯正则无效；re2 与项目 lookbehind/lookahead 正则不兼容、取证准确性
不可冒险）。本模块把真实 ApkContext 物化成**可 pickle、满足 AnalysisContext 协议**的快照，发给 worker
进程，使分析器在多核上真并行。

可 pickle 的小快照（实测 HuaCai ~12MB）：
- dex_strings（tuple，4.1MB）+ manifest/components/permissions/certs/native_libs/config/list_files（小）；
- **文本资源 dict**（.js/.json/.xml/… 共 ~8MB；59.5MB 的大头是图片/字体/.so 等分析器不读的二进制，不收）。

read_file 正确性保证：命中文本 dict 直接返回；未命中（罕见二进制读）→ **惰性重开 APK 兜底**（worker 内
按 apk_path 建 androguard APK，仅在真发生非文本读时才付这份开销；多数分析器只读文本→永不触发）。
worker 内的 APK 句柄不 pickle（``__getstate__`` 排除），每 worker 惰性建一次。

仅 **android（APK）** 走并行快照；IPA / 无 apk_path 由 pipeline 回退串行（其 read_file 语义不同）。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: 预读进快照的文本资源后缀（分析器实际扫描的；二进制不收以控快照体积）。
_TEXT_SUFFIXES: tuple[str, ...] = (
    ".js", ".json", ".xml", ".html", ".htm", ".txt", ".css", ".properties",
    ".yaml", ".yml", ".ini", ".cfg", ".conf", ".smali", ".java", ".kt", ".vue",
    ".ts", ".map", ".md", ".csv", ".sql", ".plist", ".pem", ".crt", ".key",
)


class SnapshotContext:
    """可 pickle 的 AnalysisContext 快照（满足同一协议；read_file 走预读 dict + 惰性 APK 兜底）。"""

    def __init__(
        self,
        *,
        package_name: str,
        manifest_xml: str,
        platform: str,
        config: Any,
        apk_path: str,
        permissions: list[str],
        components: Any,
        dex_strings: tuple[str, ...],
        file_list: list[str],
        native_libs: list[str],
        certificates: list,
        files: dict[str, bytes],
        dex_available: bool = True,
        apk_validation_ok: bool = True,
    ) -> None:
        # AnalysisContext 协议的 property/属性。
        self.package_name = package_name
        self.manifest_xml = manifest_xml
        self.platform = platform
        self.config = config
        self.apk_path = apk_path
        self.dex_available = dex_available
        self.apk_validation_ok = apk_validation_ok
        # 方法返回的数据。
        self._permissions = permissions
        self._components = components
        self._dex_strings = dex_strings
        self._file_list = file_list
        self._native_libs = native_libs
        self._certificates = certificates
        self._files = files  # 预读文本资源 path→bytes
        # worker 内惰性 APK 句柄（不 pickle）：None=未建，False=建过但失败，否则为 APK 实例。
        self._worker_apk: Any = None

    # ---- pickle：排除 worker APK 句柄（androguard 对象不可 pickle 且应每 worker 重建）----
    def __getstate__(self) -> dict:
        state = self.__dict__.copy()
        state["_worker_apk"] = None
        return state

    # ---- AnalysisContext 协议方法 ----
    def permissions(self) -> list[str]:
        return self._permissions

    def components(self) -> Any:
        return self._components

    def dex_strings(self):
        return iter(self._dex_strings)

    def list_files(self) -> list[str]:
        return self._file_list

    def native_libs(self) -> list[str]:
        return self._native_libs

    def certificates(self) -> list:
        return self._certificates

    def read_file(self, path: str) -> bytes | None:
        """命中预读文本 dict 直接返回；未命中惰性重开 APK 兜底（保证永远返回正确字节）。绝不抛。"""
        if path in self._files:
            return self._files[path]
        return self._lazy_read(path)

    def _lazy_read(self, path: str) -> bytes | None:
        apk = self._ensure_worker_apk()
        if apk is None:
            return None
        try:
            return apk.get_file(path)
        except Exception:  # noqa: BLE001 — 缺失/读取失败按 None（与 ApkContext.read_file 一致）
            logger.debug("snapshot 惰性 read_file 未命中：%s", path, exc_info=True)
            return None

    def _ensure_worker_apk(self) -> Any:
        """worker 内惰性建 androguard APK（按 apk_path），缓存；失败标 False 不再重试。"""
        if self._worker_apk is not None:
            return self._worker_apk or None
        if not self.apk_path:
            self._worker_apk = False
            return None
        try:
            from androguard.core.apk import APK

            self._worker_apk = APK(self.apk_path)
        except Exception:  # noqa: BLE001 — worker 内重开失败兜底为 None（极罕见非文本读才走到）
            logger.warning("snapshot worker 重开 APK 失败，非文本 read_file 将返 None", exc_info=True)
            self._worker_apk = False
        return self._worker_apk or None


def build_snapshot(ctx: Any) -> SnapshotContext:
    """把真实 ApkContext 物化成可 pickle 的 SnapshotContext（仅 android/APK 用；预读文本资源）。绝不抛。"""
    files: dict[str, bytes] = {}
    try:
        for path in ctx.list_files():
            if not isinstance(path, str):
                continue
            low = path.lower()
            if low.endswith(".dex") or not low.endswith(_TEXT_SUFFIXES):
                continue
            try:
                data = ctx.read_file(path)
            except Exception:  # noqa: BLE001 — 单文件预读失败跳过，worker 内惰性兜底仍可读
                continue
            if data is not None:
                files[path] = data
    except Exception:  # noqa: BLE001 — 预读整体失败不致命（worker 惰性兜底）
        logger.warning("snapshot 预读文本资源失败，依赖 worker 惰性 read_file 兜底", exc_info=True)

    return SnapshotContext(
        package_name=getattr(ctx, "package_name", "") or "",
        manifest_xml=getattr(ctx, "manifest_xml", "") or "",
        platform=getattr(ctx, "platform", "android"),
        config=ctx.config,
        apk_path=getattr(ctx, "apk_path", "") or "",
        permissions=list(ctx.permissions()),
        components=ctx.components(),
        dex_strings=tuple(ctx.dex_strings()),
        file_list=list(ctx.list_files()),
        native_libs=list(ctx.native_libs()),
        certificates=list(ctx.certificates()),
        files=files,
        dex_available=getattr(ctx, "dex_available", True),
        apk_validation_ok=getattr(ctx, "apk_validation_ok", True),
    )
