"""疑 native 混淆/虚拟化启发式识别（熵 + 可提取字符串密度，不反汇编）。

定位（务必守住边界）：这是**启发式信号**，不是线索抠取器，也不是精确加壳判定。
- 目标：对 App 自有 native ``.so`` 做轻量统计画像，标出「原生逻辑疑被加密 / 虚拟化 / 段加密」
  的库——提示分析人**静态别在它上面费劲**（若 C2/加密逻辑在 native，转动态 cryptohook 抓运行时明文），
  并作团伙技术画像 / 串案佐证（同款重混淆疑同团伙）。
- 能抓：VMP（虚拟化）、加密壳、段加密（如 dpt-shell 的 SO RC4）——特征是**高熵 + 几乎无可读串**。
- **抓不到纯 OLLVM 控制流平坦化**：它保留字符串、熵也不高，须反汇编做 CFG 分析（重依赖，不做）。
- 天然有噪：合法 App（金融 / 游戏 DRM 防盗版）也用 VMP/OLLVM → 只报 MEDIUM，须结合其它信号。

不产 Lead（不产调证目标），只产 Finding + ``meta["native_obfuscation"]`` 供 digest / 串案。

约束：只依赖 AnalysisContext 公开接口（native_libs / list_files / read_file）；单库评估异常
try/except + logging，不炸整个 analyze；全程 type hints。
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from apkscan.core.models import AnalyzerResult, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# --- 启发式阈值（可调；注释说明标定依据）---------------------------------
# 普通 native 代码窗口熵约 6.0~6.7；加密 / VM 字节码 / 压缩 ≈ 7.8~8.0。取 7.5 为"高熵"分界（干净分离）。
_HIGH_ENTROPY = 7.5
# 「≥4 连续可打印」密度：普通 .so（符号名/格式串）通常 >10%；加密/VM 段仅随机噪声 ≈ 5%（真随机地板）。
# 取 0.08 为界——需高于加密噪声地板(~5.5%)、低于正常代码(>10%)，否则会漏判真加密 .so。
_LOW_STRING_DENSITY = 0.08
# 太小的 .so（stub / 桩）统计噪声大，跳过。
_MIN_SIZE = 64 * 1024
# 采样窗口：只对 head/mid/tail 各一窗计算，避免对超大 .so 全量扫描。
_WINDOW = 256 * 1024
# 单样本最多评估的 .so 数（防极端多库样本拖慢）。
_MAX_LIBS = 60
# 可提取字符串：≥4 连续可打印 ASCII。
_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

# 常见合法 / 引擎 / 系统库白名单（子串小写匹配）——这些体积大或偶有高熵资源但属正常，降 FP。
_BENIGN_SUBSTR: frozenset[str] = frozenset(
    {
        "libc++_shared", "libc++.", "libc.so", "libm.so", "libz.so", "libdl.",
        "liblog.so", "libjsc", "libhermes", "libv8", "libflutter", "libmonosgen",
        "libmono", "libunity", "libil2cpp", "libreactnativejni", "libfbjni",
        "libfolly", "libskia", "libavcodec", "libavformat", "libavutil",
        "libcrypto", "libssl", "libopus", "libwebp", "libjpeg", "libpng",
        "libtensorflow", "libpytorch", "libtorch", "libglog", "libmarsxlog",
        "libwcdb", "libsqlite", "libcronet", "libmmkv",
    }
)


class NativeObfuscationAnalyzer(BaseAnalyzer):
    """启发式标出疑加密 / 虚拟化的 App 自有 native .so（信号，非精确判定）。"""

    name: str = "native_obfuscation"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        result.meta["native_obfuscation"] = []

        try:
            so_paths = self._app_so_paths(ctx)
        except Exception:
            logger.exception("[%s] 枚举 .so 失败，跳过", self.name)
            return result

        suspects: list[dict[str, Any]] = []
        for path in so_paths[:_MAX_LIBS]:
            try:
                info = self._assess_lib(ctx, path)
            except Exception:
                logger.exception("[%s] 评估失败，跳过：%s", self.name, path)
                continue
            if info is not None:
                suspects.append(info)

        if not suspects:
            return result

        result.meta["native_obfuscation"] = suspects
        result.findings.append(self._build_finding(suspects))
        return result

    # ------------------------------------------------------------------
    # 枚举 App 自有 .so（排除白名单）
    # ------------------------------------------------------------------

    def _app_so_paths(self, ctx: "AnalysisContext") -> list[str]:
        seen: dict[str, None] = {}
        for source in (ctx.native_libs() or []), (ctx.list_files() or []):
            for p in source:
                if isinstance(p, str) and p.lower().endswith(".so"):
                    seen.setdefault(p, None)
        out: list[str] = []
        for p in seen:
            base = p.rsplit("/", 1)[-1].lower()
            if any(b in base for b in _BENIGN_SUBSTR):
                continue
            out.append(p)
        return out

    # ------------------------------------------------------------------
    # 单库统计画像
    # ------------------------------------------------------------------

    def _assess_lib(self, ctx: "AnalysisContext", path: str) -> dict[str, Any] | None:
        data = ctx.read_file(path)
        if not data or len(data) < _MIN_SIZE:
            return None
        sample = self._sample(data)
        entropy = self._max_window_entropy(sample)
        density = self._string_density(sample)
        if entropy >= _HIGH_ENTROPY and density < _LOW_STRING_DENSITY:
            return {
                "lib": path,
                "entropy": round(entropy, 3),
                "string_density": round(density, 4),
                "size": len(data),
            }
        return None

    @staticmethod
    def _sample(data: bytes) -> bytes:
        """取 head/mid/tail 三窗（超大 .so 不全量扫）。"""
        n = len(data)
        if n <= 3 * _WINDOW:
            return data
        mid = n // 2
        return data[:_WINDOW] + data[mid : mid + _WINDOW] + data[-_WINDOW:]

    @classmethod
    def _max_window_entropy(cls, data: bytes) -> float:
        """按窗口算熵取最大——局部加密 / VM 段即便被低熵头稀释也能浮现。"""
        best = 0.0
        for i in range(0, len(data), _WINDOW):
            chunk = data[i : i + _WINDOW]
            if len(chunk) < 4096:
                continue
            e = cls._entropy(chunk)
            if e > best:
                best = e
        return best if best else cls._entropy(data)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())

    @staticmethod
    def _string_density(data: bytes) -> float:
        if not data:
            return 0.0
        total = sum(len(m) for m in _STRING_RE.findall(data))
        return total / len(data)

    # ------------------------------------------------------------------
    # Finding 组装
    # ------------------------------------------------------------------

    def _build_finding(self, suspects: list[dict[str, Any]]) -> Finding:
        lines = [
            f"  · {s['lib']}（熵 {s['entropy']} / 可读串占比 {s['string_density']:.1%} / {s['size'] // 1024}KB）"
            for s in suspects
        ]
        return Finding(
            id="NATIVE-OBFUSCATION-SUSPECTED",
            title="native .so 疑加密 / 虚拟化（VMP / 加密壳启发式，非精确判定）",
            severity=Severity.MEDIUM,
            category="anti_analysis",
            description=(
                "以下 App 自有 native 库呈现【高熵 + 几乎无可读字符串】特征，疑原生逻辑被"
                "虚拟化（VMP）/ 加密壳 / 段加密（如 dpt-shell SO RC4）保护：\n"
                + "\n".join(lines)
                + "。★ 启发式信号，非精确判定——合法 App（金融 / 游戏 DRM）亦可能如此；"
                "且本法抓不到纯 OLLVM 控制流平坦化（须反汇编）。"
            ),
            recommendation=(
                "该 .so 的原生逻辑静态不可得：若 C2 / 加密逻辑在 native，转动态用 cryptohook "
                "hook Cipher / 抓运行时明文；把「native 重混淆」作为团伙技术画像并簇串案。"
            ),
            evidences=[
                Evidence(source="native", location=s["lib"], snippet=f"entropy={s['entropy']}")
                for s in suspects
            ],
            references=["https://developer.android.com/topic/security"],
        )
