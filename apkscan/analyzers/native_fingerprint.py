"""native 库指纹：对 App 自有 .so 逐个算 sha256 写进 report.meta，供跨样本候选召回。

相同 sha256 只证明所取字节相同，不能单独证明样本属于同一家族，也不能证明开发、运营或控制主体相同；
第三方组件、加固壳、公开构建产物与重打包继承都可能产生相同字节。corpus 还保留按精确库名查询的兼容入口，
但同名比同哈希更弱，只能召回待复核记录。是否形成家族或主体结论须结合独立锚点与原始证据复核。

纯静态、有界读、绝不抛：单 .so 超上限或读失败即跳过；结果按 sha256 去重、稳定排序（可复现）。
不做任何配方存储/重放（那是案件数据，靠智能体首次破解）。
"""
from __future__ import annotations

import hashlib
import logging
import posixpath
from typing import TYPE_CHECKING

from apkscan.analyzers._common import collect_so_paths
from apkscan.core.models import AnalyzerResult
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

#: 单个 .so 读入上限（字节）：超此跳过（防超大/zip-bomb .so 撑爆内存；对齐 native_obfuscation 上限）。
_MAX_LIB_BYTES = 64 * 1024 * 1024
#: 最多指纹化的 .so 数（防极端多库样本）。
_MAX_LIBS = 40


class NativeFingerprintAnalyzer(BaseAnalyzer):
    """对 App .so 逐个算 sha256 → meta["native_lib_hashes"]，仅供候选召回。"""

    name: str = "native_fingerprint"
    meta_key_categories = {
        'native_lib_hashes': 'record',
    }
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = ["apk"]  # Android 专属

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        hashes: list[dict[str, object]] = []
        seen: set[str] = set()

        # 全 .so 完整路径（**不按 basename 塌缩**：同名多 ABI 变体字节不同、须各自哈希）。稳定排序、确定性。
        for path in collect_so_paths(ctx, self.name):
            if len(hashes) >= _MAX_LIBS:
                break
            # ★P0-5：read_file 前先查 zip 声明的解压后大小——超阈值直接跳过、绝不 read。read_file 自身
            #   上限是 500MB（远高于本 64MB 阈值），若不前置拦截，一个「小压缩、巨解压」的 .so 会被
            #   androguard 全量膨胀进内存后才被判超限。declared_size 返回 None（无法判断）时保守放行、退回读后判长。
            try:
                declared = ctx.declared_size(path)
            except Exception:  # noqa: BLE001 — 访问器异常不阻断，退回读后判长
                logger.debug("[%s] 查 .so 声明大小失败：%s", self.name, path, exc_info=True)
                declared = None
            if declared is not None and declared > _MAX_LIB_BYTES:
                logger.debug("[%s] 跳过超大 .so（声明 %d 字节 > %d 上限，不读）：%s",
                             self.name, declared, _MAX_LIB_BYTES, path)
                continue
            try:
                data = ctx.read_file(path)
            except Exception:  # noqa: BLE001 — 单库读失败不影响其余
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, path, exc_info=True)
                continue
            if not data or len(data) > _MAX_LIB_BYTES:  # 声明大小不可得时的兜底
                continue
            sha = hashlib.sha256(data).hexdigest()
            if sha in seen:
                continue
            seen.add(sha)
            hashes.append({
                "name": posixpath.basename(path.replace("\\", "/")),
                "sha256": sha,
                "size": len(data),
            })

        # 按 sha256 稳定排序（可复现，与采集顺序无关）。
        hashes.sort(key=lambda h: str(h["sha256"]))
        result.meta["native_lib_hashes"] = hashes
        logger.info("[%s] 指纹化 .so %d 个", self.name, len(hashes))
        return result
