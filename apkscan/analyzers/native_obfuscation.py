"""native 混淆/虚拟化启发式识别（熵 + 可提取字符串密度，不反汇编）。

定位（务必守住边界）：这是**启发式信号**，不是精确加壳判定。
- 目标：对 App 自有 native ``.so`` 做轻量统计画像，标出「原生逻辑疑被加密 / 虚拟化 / 段加密」
  的库——提示**静态分析在该库上不完整**（若关键 / 加密逻辑在 native，宜转运行时观测抓明文），
  并作技术画像用于跨样本关联（同款重混淆特征可关联样本）。
- 能抓：VMP（虚拟化，含**选择性函数虚拟化**——局部高熵 VM 块）、加密壳、段加密（SO 段被加密）
  ——特征是**高熵 + 几乎无可读串**（整库或局部窗）；以及 **ELF PT_NOTE 段被劫持**（可执行/异常大，
  VMPacker 类用它承载解释器 stub）这一结构化低 FP 信号。
- **抓不到纯控制流平坦化混淆**：它保留字符串、熵也不高，须反汇编做 CFG 分析（重依赖，不做）。
- 天然有噪：合法 App（金融 / 游戏 DRM 防盗版）也会混淆 native → 只报 MEDIUM，须结合其它信号。

不产 Lead，只产 Finding + ``meta["native_obfuscation"]`` 供 digest / 关联消费。

约束：只依赖 AnalysisContext 公开接口（native_libs / list_files / read_file）；单库评估异常
try/except + logging，不炸整个 analyze；全程 type hints。
"""

from __future__ import annotations

import logging
import math
import re
import struct
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

# --- 结构/局部块签名（补整库启发式漏判的选择性虚拟化）------------------------
# 局部窗高熵界：比整库 7.5 更严（压 FP），VM 字节码/加密块窗内熵≈7.8~8.0。
_LOCAL_ENTROPY = 7.8
# 局部窗内可读串密度界：须**高于**真随机地板(~5.5%)、低于正常代码(>10%)——取 0.07
# （0.05 会低于随机地板导致纯 VM/加密块窗永远不触发；这是与整库 0.08 门配套的更严局部门）。
_LOCAL_DENSITY = 0.07
# 局部块分窗扫描的窗数上限（步进覆盖全文件、有界防超大 .so 拖慢）。
_MAX_LOCAL_WINDOWS = 64
# PT_NOTE 段合法大小上界：正规 note（build-id/android-ident/gnu-property）仅几十~几百字节；
# 超此（或带可执行标志）疑被 native VMP/注入壳劫持承载解释器 stub。
_PT_NOTE_MAX_FILESZ = 4096
_PT_NOTE = 4  # ELF p_type == PT_NOTE
_PF_X = 0x1   # ELF p_flags 可执行位

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
        signals: list[str] = []

        # (1) ELF 结构签名：PT_NOTE 段被劫持（可执行 / 异常大）——主签名，低 FP。
        note = self._pt_note_anomaly(data)
        if note:
            signals.append(note)

        # (2) 熵/串密度：整库高熵（原判定）或内嵌局部高熵块（补选择性虚拟化漏判）。
        sample = self._sample(data)
        entropy = self._max_window_entropy(sample)
        density = self._string_density(sample)
        if entropy >= _HIGH_ENTROPY and density < _LOW_STRING_DENSITY:
            signals.append("整库高熵 + 低可读串（疑加密壳 / 整库虚拟化）")
        elif self._has_local_high_entropy_block(data):
            # 整库判定未触发但存在局部近随机高熵块 = 选择性虚拟化（核心函数进 VM、全局 .rodata 仍正常）。
            signals.append("内嵌局部高熵块（疑选择性虚拟化 / 加密 VM 字节码段）")

        if not signals:
            return None
        return {
            "lib": path,
            "entropy": round(entropy, 3),
            "string_density": round(density, 4),
            "size": len(data),
            "signals": signals,
        }

    # ------------------------------------------------------------------
    # ELF PT_NOTE 结构签名（stdlib 解析，兼容 ELF32/64，非 ELF/解析异常静默跳过）
    # ------------------------------------------------------------------

    @staticmethod
    def _pt_note_anomaly(data: bytes) -> str | None:
        """查 ELF program header 的 PT_NOTE 段异常（PF_X 可执行 / p_filesz 超 4KB）→ 疑 VMP/注入壳劫持。

        合法 note 段绝不可执行、且仅几十~几百字节；VMPacker 类会劫持它承载解释器 stub。
        非 ELF、解析越界或字段异常一律返回 None（绝不抛）。
        """
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None
        ei_class = data[4]  # 1=ELF32, 2=ELF64
        if data[5] not in (1, 2):  # EI_DATA 非 1(LE)/2(BE) = 非法头,拒
            return None
        endian = "<" if data[5] == 1 else ">"
        try:
            if ei_class == 2:  # ELF64: p_type@0 p_flags@4 p_filesz@32
                e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
                flags_off, filesz_off = 4, 32
            elif ei_class == 1:  # ELF32: p_type@0 p_filesz@16 p_flags@24
                e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
                flags_off, filesz_off = 24, 16
            else:
                return None
            if e_phentsize < 8 or e_phoff <= 0:
                return None
            for i in range(min(e_phnum, 128)):  # 上限防损坏头无限循环
                base = e_phoff + i * e_phentsize
                p_type = struct.unpack_from(endian + "I", data, base)[0]
                if p_type != _PT_NOTE:
                    continue
                p_flags = struct.unpack_from(endian + "I", data, base + flags_off)[0]
                p_filesz = struct.unpack_from(
                    endian + ("Q" if ei_class == 2 else "I"), data, base + filesz_off
                )[0]
                if p_flags & _PF_X:
                    return "PT_NOTE 段可执行（PF_X，正规 note 段绝不可执行）"
                if p_filesz > _PT_NOTE_MAX_FILESZ:
                    return f"PT_NOTE 段异常大（{p_filesz}B，正规 note 仅几十~几百字节）"
        except (struct.error, IndexError):
            return None
        return None

    def _has_local_high_entropy_block(self, data: bytes) -> bool:
        """全量分窗（有界 ≤_MAX_LOCAL_WINDOWS）：任一窗高熵（≥7.8）且窗内局部可读串密度<0.07
        → 内嵌加密/VM 字节码块（选择性虚拟化：只核心函数进 VM，全局 .rodata 串密度仍正常）。
        注：统计信号，内嵌大块压缩资产（zip/图片等）同样高熵低串、会命中，故须结合其它信号研判。"""
        n = len(data)
        step = max(_WINDOW, -(-n // _MAX_LOCAL_WINDOWS))  # 窗数超上限则步进跨采,保证覆盖有界
        for i in range(0, n, step):
            chunk = data[i : i + _WINDOW]
            if len(chunk) < 4096:
                continue
            if self._entropy(chunk) >= _LOCAL_ENTROPY and self._string_density(chunk) < _LOCAL_DENSITY:
                return True
        return False

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
            f"  · {s['lib']}（{'；'.join(s.get('signals') or ['高熵/低串'])}"
            f"；熵 {s['entropy']} / 可读串占比 {s['string_density']:.1%} / {s['size'] // 1024}KB）"
            for s in suspects
        ]
        return Finding(
            id="NATIVE-OBFUSCATION-SUSPECTED",
            title="native .so 疑加密 / 虚拟化（VMP / 加密壳 / PT_NOTE 劫持启发式，非精确判定）",
            severity=Severity.MEDIUM,
            category="anti_analysis",
            description=(
                "以下 App 自有 native 库呈现【高熵 + 几乎无可读串】/【局部高熵 VM 块】/【PT_NOTE 段被劫持】"
                "等特征，疑原生逻辑被虚拟化（VMP，含选择性函数虚拟化）/ 加密壳 / 段加密保护：\n"
                + "\n".join(lines)
                + "。★ 启发式信号，非精确判定——合法 App（金融 / 游戏 DRM）亦可能高熵；"
                "PT_NOTE 段异常是结构化低 FP 信号；局部高熵块是统计信号，内嵌大块压缩资产"
                "（zip/图片等）亦会命中，须结合其它信号研判；本法抓不到纯控制流平坦化混淆（须反汇编）。"
            ),
            recommendation=(
                "该 .so 的原生逻辑静态不完整：若关键 / 加密逻辑在 native，宜转运行时观测 "
                "hook Cipher / 抓运行时明文；把「native 重混淆」作为技术画像用于跨样本关联。"
            ),
            evidences=[
                Evidence(source="native", location=s["lib"], snippet=f"entropy={s['entropy']}")
                for s in suspects
            ],
            references=["https://developer.android.com/topic/security"],
        )
