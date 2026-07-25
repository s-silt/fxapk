"""native 库指纹：对 App 自有 .so 逐个算 sha256 写进 report.meta，作**家族级硬指纹**。

依据（家族取证经验）：同族样本的核心业务 .so 常**逐字节相同**（同一构建），其 sha256 是比签名证书更硬的
家族锚点——解密配方、下发通道格式都随该 .so 走。把哈希登记进报告后，corpus 可 ``--by so_sha256`` 一击
反查全家族样本（见 core/corpus 的 native_lib 列表维度）。

纯静态、有界读、绝不抛：单 .so 超上限或读失败即跳过；结果按 sha256 去重、稳定排序（可复现）。
不做任何配方存储/重放（那是案件数据，靠智能体首次破解）。
"""
from __future__ import annotations

import hashlib
import logging
import posixpath
from typing import TYPE_CHECKING

from apkscan.analyzers._common import collect_so_basenames
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
    """对 App .so 逐个算 sha256 → meta["native_lib_hashes"]（家族级硬指纹，供 corpus --by so_sha256 反查）。"""

    name: str = "native_fingerprint"
    requires: list[str] = ["apk"]  # Android 专属

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        hashes: list[dict[str, object]] = []
        seen: set[str] = set()

        # {basename: path}；按 basename 稳定排序，确定性。
        by_base = collect_so_basenames(ctx, self.name)
        for base in sorted(by_base):
            if len(hashes) >= _MAX_LIBS:
                break
            path = by_base[base]
            try:
                data = ctx.read_file(path)
            except Exception:  # noqa: BLE001 — 单库读失败不影响其余
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, path, exc_info=True)
                continue
            if not data or len(data) > _MAX_LIB_BYTES:
                continue
            sha = hashlib.sha256(data).hexdigest()
            if sha in seen:
                continue
            seen.add(sha)
            hashes.append({
                "name": posixpath.basename(str(path).replace("\\", "/")),
                "sha256": sha,
                "size": len(data),
            })

        # 按 sha256 稳定排序（可复现，与采集顺序无关）。
        hashes.sort(key=lambda h: str(h["sha256"]))
        result.meta["native_lib_hashes"] = hashes
        logger.info("[%s] 指纹化 .so %d 个", self.name, len(hashes))
        return result
