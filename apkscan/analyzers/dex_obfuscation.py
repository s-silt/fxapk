"""DEX 字符串池不透明度（可信度信号，非工具指纹）：回答「本次静态抽取是不是瞎了」。

为什么需要：编译期**字符串混淆器**（把 dex 里的字符串常量整体加密、运行时再解密）一旦用上，
`endpoints` / `contacts` / `config_keys` 这些**全部依赖 dex 字符串池**的分析器会集体抽不到东西，
报告于是干干净净地写着「未发现网络端点」——而真相是我们看不见。这类**静默失明**比漏检更危险：
它把「没看到」渲染成「不存在」，办案人据此判该样本干净。

本模块**不指名任何工具、不产任何端点/线索**，只度量字符串池本身的不透明程度，命中即在报告里明说
「静态抽取可能不完整，`未发现` 不可解读为 `不存在`」。与 `native_obfuscation`（度量 .so 熵/串密度）
是同一思路在 DEX 侧的对应物。

★ 头号假阳陷阱：**中文（及任何非拉丁语系）App 的字符串大量非 ASCII，但完全可读**——绝不能把
「非 ASCII」当混淆。判据只认**结构性不可读**：控制字符、私用区、代理码位残片、以及码位分布近随机。
CJK / 西里尔 / 阿拉伯 / 假名一律算**可读内容**。

纯静态、有界、绝不抛。
"""
from __future__ import annotations

import logging
import math
import re
import unicodedata
from collections import Counter
from typing import TYPE_CHECKING, Any

from apkscan.analyzers._common import collect_dex_strings
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

#: 采样上限（与其它 dex 分析器同口径）。
_MAX_DEX_STRINGS = 200_000

#: 参与统计的最短串长：过短的串（单字符、两字符标识符）判不出可读性，一律不计。
_MIN_LEN = 4

#: 判定所需的最少**有效样本**数：样本太少任何比例都不稳，宁可不报。
_MIN_SAMPLE = 300

#: 参与统计的总字符量上限：条数上限管不住"少量超长串"的对抗构造，而逐字符分析的开销与
#: 总字符量成正比，故按字符量另设硬顶。触顶会 warning（截断必须可见，不静默）。
_MAX_TOTAL_CHARS = 20_000_000

#: 不透明串占比阈值：超过即认为池中存在成规模的加密串。
_OPAQUE_RATIO = 0.15

#: 可读串占比下限：低于此说明池里几乎没有人类可读内容。
_READABLE_RATIO_FLOOR = 0.10

#: 单串「不可读字符」占比阈值：超过即判该串不透明。
_UNREADABLE_CHAR_RATIO = 0.30

#: 单串近随机判据：字符熵 ≥ 此值且长度足够 → 近随机（正常文本远低于此）。
_RANDOM_ENTROPY = 4.2
_RANDOM_MIN_LEN = 16

#: 证据里展示的样本条数与单条截断长度。
_EVIDENCE_SAMPLES = 3
_SNIPPET_LEN = 40

#: JVM/DEX 类型描述符与方法签名——它们恒存在于字符串池（不随字符串混淆消失），计入统计会稀释比例、
#: 掩盖失明，故排除。★须按**完整语法**匹配：仅"首字符 L/[/( + 含分号"会把普通业务文案误当描述符。
#:   单类型：``[`` * n + （基元 BCDFIJSZV | ``L``包名/类名``;``）
#:   方法签名：``(`` 参数* ``)`` 返回型（返回型另可为 ``V``）
#: 不计入「不可读」的格式字符：排版空白，以及 emoji 合成部件——ZWJ(U+200D) 与变体选择符
#: (U+FE0E/U+FE0F)。它们类别虽是 Cf，却是正常文本的构成部件，计入会把 emoji 多的 App 判成混淆。
_TEXT_FORMAT_EXEMPT = frozenset("\t\n\r‍︎️")

_TYPE_DESC = r"\[*(?:[BCDFIJSZV]|L[A-Za-z0-9_$/]+;)"
_DESCRIPTOR_RE = re.compile(rf"(?:{_TYPE_DESC}|\((?:{_TYPE_DESC})*\)(?:{_TYPE_DESC}|V))")


def _is_descriptor(s: str) -> bool:
    """判类型描述符 / 方法签名（``Landroid/app/Activity;`` / ``()V`` / ``[B``）。

    ★按 JVM 描述符**语法**判，不能只看首字符 + 含分号（复审 P2）：那样会把
    ``Login failed; retry later`` / ``(optional) phone number`` / ``(点击重试)`` 这类**普通业务文案**
    当描述符排除掉——被排除的串不进分母，反而抬高不透明占比、把正常 App 推向误报。
    """
    if not s:
        return False
    return bool(_DESCRIPTOR_RE.fullmatch(s))


def _unreadable_char_ratio(s: str) -> float:
    """结构性不可读字符占比：控制字符(Cc)、格式字符(Cf)、私用区(Co)、代理码位(Cs)、未分配(Cn)。

    ★ 只认这几类。CJK / 西里尔 / 阿拉伯 / 假名等**有语义的文字**属 Lo/Ll/Lu 等类别，不在此列
    ——中文 App 的字符串因此不会被误判。

    ★ emoji 例外（复审 P1）：合成 emoji 用 **ZWJ（U+200D）** 连接，其类别正是 ``Cf``。实测
    「👨‍👩‍👧‍👦」ZWJ 占比达 43%、「👩‍💻」达 33%，都会越过不可读阈值——于是一个 emoji 用得多的
    正常 App 会被判成"字符串池整体混淆"。故 ZWJ 与变体选择符（U+FE0E/U+FE0F）不计入不可读：
    它们是**正常文本的构成部件**，不是加密痕迹。
    """
    if not s:
        return 0.0
    bad = 0
    for ch in s:
        if ch in _TEXT_FORMAT_EXEMPT:  # 排版空白 + emoji 组合部件：正常内容里合法
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs", "Cn"):
            bad += 1
    return bad / len(s)


def _char_entropy(s: str) -> float:
    """按字符算香农熵（bit/字符）。正常自然语言/标识符远低于随机串。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_opaque(s: str) -> bool:
    """该串是否「结构性不可读」= 疑加密载荷。

    两条独立判据（任一成立即算）：
      1. 控制/私用/代理/未分配字符占比超阈值——加密后按字节映射码位常落进这些区间；
      2. 足够长且字符熵近随机——密文按码位展开后分布近均匀，正常文本/标识符不会。
    """
    if _unreadable_char_ratio(s) >= _UNREADABLE_CHAR_RATIO:
        return True
    return len(s) >= _RANDOM_MIN_LEN and _char_entropy(s) >= _RANDOM_ENTROPY


def _is_readable(s: str) -> bool:
    """该串是否含人类可读内容：≥3 个连续「文字类」字符（任何语系），或含 emoji / 图形符号。

    用 unicodedata 的字母类判定而非 ASCII 白名单——中文/日文/俄文内容同样算可读。
    ★ emoji（类别 So）与肤色修饰符（Sk）也算**可读内容**（复审 P1）：贴纸描述、聊天模板、
    无障碍标签这类正常字符串常以 emoji 为主、字母很少，若不算可读，它们会同时踩中
    「不透明占比高 + 可读占比低」两条，把正常 App 判成整体混淆。
    """
    run = 0
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("So", "Sk"):  # emoji / 图形符号 / 修饰符：有语义的内容
            return True
        if cat.startswith("L"):
            run += 1
            if run >= 3:
                return True
        else:
            run = 0
    return False


def assess_string_pool(strings: list[str]) -> dict[str, Any]:
    """对字符串池做不透明度画像（纯函数，便于单测）。

    Returns:
        ``{sampled, opaque, readable, opaque_ratio, readable_ratio, suspicious, samples}``。
        ``suspicious`` 仅在样本量达标 **且** 「不透明占比高」与「可读占比低」**同时**成立时为 True——
        单边条件极易误报（小 App 串少、资源类 App 串多但短），故取双边。
    """
    considered: list[str] = []
    budget = _MAX_TOTAL_CHARS
    truncated = False
    for s in strings:
        if not isinstance(s, str) or len(s) < _MIN_LEN or _is_descriptor(s):
            continue
        # ★总字符量上限（复审 P2）：条数上限约束不住"少量超长串"的对抗构造；逐字符跑
        # unicodedata.category + Counter 的开销与总字符量成正比，故按字符量硬封顶。
        if budget <= 0:
            truncated = True
            break
        budget -= len(s)
        considered.append(s)
    if truncated:
        logger.warning(
            "[dex_obfuscation] 字符串总量超 %d 字符上限，仅据前 %d 条统计——比例可能不代表全池",
            _MAX_TOTAL_CHARS, len(considered),
        )

    sampled = len(considered)
    opaque_list = [s for s in considered if _is_opaque(s)]
    readable = sum(1 for s in considered if _is_readable(s))
    opaque = len(opaque_list)
    opaque_ratio = (opaque / sampled) if sampled else 0.0
    readable_ratio = (readable / sampled) if sampled else 0.0

    suspicious = (
        sampled >= _MIN_SAMPLE
        and opaque_ratio >= _OPAQUE_RATIO
        and readable_ratio <= _READABLE_RATIO_FLOOR
    )
    return {
        "sampled": sampled,
        "opaque": opaque,
        "readable": readable,
        "opaque_ratio": round(opaque_ratio, 4),
        "readable_ratio": round(readable_ratio, 4),
        "suspicious": suspicious,
        "samples": [s[:_SNIPPET_LEN] for s in opaque_list[:_EVIDENCE_SAMPLES]],
    }


class DexObfuscationAnalyzer(BaseAnalyzer):
    """度量 DEX 字符串池不透明度 → 报告里明示「静态抽取可能失明」（可信度信号，非工具指纹）。"""

    name: str = "dex_obfuscation"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        ok, strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)
        if not ok and not strings:
            logger.info("[%s] 无 dex 字符串可评估，跳过", self.name)
            return result

        stats = assess_string_pool(strings)
        result.meta["dex_string_pool"] = stats
        logger.info(
            "[%s] 字符串池：样本 %d、不透明 %.1f%%、可读 %.1f%%",
            self.name, stats["sampled"], stats["opaque_ratio"] * 100, stats["readable_ratio"] * 100,
        )
        if stats["suspicious"]:
            result.findings.append(self._build_finding(stats))
        return result

    def _build_finding(self, stats: dict[str, Any]) -> Finding:
        return Finding(
            id="DEX-STRING-POOL-OPAQUE",
            title="DEX 字符串池疑被整体混淆（静态抽取可能不完整）",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,  # 统计信号：重资源/重加密的合法 App 亦可能命中
            category="anti_analysis",
            description=(
                f"字符串池中 {stats['opaque_ratio']:.1%} 的串结构性不可读（控制字符 / 私用区 / 近随机码位），"
                f"而仅 {stats['readable_ratio']:.1%} 含人类可读内容（样本 {stats['sampled']} 条）。"
                "这符合**编译期字符串混淆**的形态：字面量在打包时被整体加密、运行时才解密。\n"
                "★ 直接后果：`endpoints` / `contacts` / `config_keys` 等**全部依赖 dex 字符串池**的分析器"
                "会集体抽不到内容——本报告里这些项的「未发现」**不可解读为「不存在」**。\n"
                "★ 统计信号非精确判定：重度加密资源 / 内嵌二进制载荷的合法 App 亦可能命中。"
            ),
            recommendation=(
                "别据本次静态结果判该样本「无网络行为 / 无联系方式」。真实端点须转**运行时观测**取："
                "floor PCAP 抓实际连接的 IP:端口、socket 归因落到进程，或运行时 hook 解密后的字符串；"
                "另可把「字符串池整体混淆」作为技术画像用于跨样本家族关联。"
            ),
            evidences=[
                Evidence(source="dex", location="string-pool", snippet=repr(s))
                for s in stats.get("samples", [])
            ],
        )
