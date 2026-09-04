"""逆向 / Hook / 反检测工具链识别分析器 —— 识别样本内置的 RE/hook/反分析能力。

职责：
- 用 ctx.native_libs() + ctx.list_files() + ctx.dex_strings() 三路匹配 hook 框架 / 反检测工具特征。
- 规则来自 apkscan/rules/re_toolkit.yaml（ShadowHook/ByteHook/GlossHook/LSPlant/pine/xDL/Dobby、
  LibcoreSyscall/HiddenApiBypass/Frida Gadget 等），每条含 so 名 / 特征文件 / dex 包前缀 + category + anti_frida。
- 命中产出：
    * Finding(category="anti_analysis", id="RE-TOOLKIT-DETECTED")——列出识别到的工具与能力；
    * meta["re_toolkit"] = [{name, category, capability, strong}]（供 digest/串案）；
    * meta["hook_frameworks"] = [名]（结合无障碍权限研判运行时劫持）；
    * meta["anti_frida"] = bool（命中 anti_frida 工具 → 供 capture_plan 预判 frida 抓包会被击败、换打法）。

★ 定位与边界：本分析器是**防御性威胁情报**——识别样本内置了哪些 hook/反检测工具以研判其能力、
  预判动态抓包可行性、并作团伙工具链指纹串案。只识别、不利用。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    as_str_list as _as_str_list,
)
from apkscan.analyzers._common import (
    collect_app_so_string_blobs as _collect_app_so_string_blobs,
)
from apkscan.analyzers._common import (
    collect_dex_strings as _collect_dex_strings_shared,
)
from apkscan.analyzers._common import (
    collect_file_paths as _collect_file_paths_shared,
)
from apkscan.analyzers._common import (
    collect_so_basenames as _collect_so_basenames_shared,
)
from apkscan.analyzers._common import (
    str_or_empty as _str_or_empty,
)
from apkscan.analyzers._common import (
    truncate as _truncate_shared,
)
from apkscan.core.models import (
    AnalyzerResult,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "re_toolkit"

# DEX 字符串扫描上限（与 packing 一致，避免极端样本扫描过久）。
_MAX_DEX_STRINGS = 200_000
_SNIPPET_MAX = 200

# --- 内嵌 syscall 机器码结构检测（抗 fork）的常量 -------------------------------
#: 候选 base64 串最短字符数：真实 shellcode 载荷是数千字符；下限压掉海量短 base64（token/ID/短密钥）。
_MIN_STUB_B64_CHARS = 512
#: 解码后最小字节数：太短不足以是一段可用的 syscall 桩。
_MIN_STUB_BYTES = 128
#: ★单个载荷解码上限：实测真实 syscall 桩仅 1.8~3.4KB，取 64KB 已是 20 倍余量。作用有二——
#:   ① 硬性封住单候选的内存/CPU 峰值（**解码前**按 base64 长度预估即跳过，不先分配再判）；
#:   ② 把每候选的扫描位置从百万级压到万级，使「随机数据撞上 syscall 编码」的概率保持在可忽略量级
#:      （扫描位置越多，随机碰撞机会线性增长——这是原注释只写 1/2³² 的疏漏）。
_MAX_STUB_PAYLOAD_BYTES = 64 * 1024
#: 超过此大小的载荷已远大于任何真实 syscall 桩，要求更多命中数以抵消其扫描位置增多带来的碰撞概率。
_LARGE_STUB_BYTES = 8 * 1024
#: 候选数与累计解码量上限。累计量是**硬上限**（解码前预估、超了就停），候选数是兜底。
#: 触顶会 logger.warning——截断必须可见，不能静默漏检（本项目硬规则）。
_MAX_STUB_CANDIDATES = 2000
_MAX_STUB_DECODE_BYTES = 8 * 1024 * 1024
#: 需要的对齐 syscall 指令数下限：小载荷（≤_LARGE_STUB_BYTES，覆盖全部真实样本）取 1——实测
#: arm64 全部 syscall 走同一 stub、仅 1 处；大载荷取 2，抵消扫描位置增多的碰撞概率。
_MIN_SYSCALL_INSN = 1
_MIN_SYSCALL_INSN_LARGE = 2
#: 仅纯 base64 字符（已去空白）才尝试解码。
_B64_ONLY_RE = re.compile(r"[A-Za-z0-9+/=]+")
#: 已知容器格式魔数：解码结果是这些即正常内嵌资源（证书/图片/压缩包/动态库），不是裸机器码。
_CONTAINER_MAGICS: tuple[bytes, ...] = (
    b"\x7fELF", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"\x1f\x8b",
    b"%PDF", b"BM", b"RIFF", b"dex\n", b"\x30\x82", b"OggS", b"\x00\x00\x01\x00",
)
#: 定长 4 字节指令集的 syscall 编码（小端）+ 指令对齐。**只用这些**——x86 的 0f 05 / cd 80 仅 1~2 字节，
#: 在随机噪声里常见，单独作判据会误报，故不列入。
_SYSCALL_INSNS: dict[str, tuple[bytes, int]] = {
    "arm64": (b"\x01\x00\x00\xd4", 4),      # svc #0
    "arm32": (b"\x00\x00\x00\xef", 4),      # svc #0（ARM 模式）
    "riscv64": (b"\x73\x00\x00\x00", 2),    # ecall（含压缩指令 → 2 字节对齐）
    "mips": (b"\x0c\x00\x00\x00", 4),       # syscall
}
# ★已知局限（有意为之）：**仅 x86/x86_64 载荷的样本检不出**——其 syscall 编码是 0f 05 / cd 80，
#   仅 1~2 字节，在任意随机数据里都常见，单独作判据必误报。真实移动样本压倒性是 arm；上游库亦
#   七架构全带（arm64 必在），故该局限在实务上影响极小。宁可漏，不可造。

# category → 人读分组名。
_CATEGORY_LABELS: dict[str, str] = {
    "hook_framework": "Hook 框架（运行时劫持能力）",
    "evasion": "反检测 / 反分析",
    "instrumentation": "插桩 / 注入",
}


@dataclass
class _ToolRule:
    """单条工具指纹规则（从 YAML 规整而来）。"""

    name: str
    category: str
    capability: str = ""
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    dex_prefixes: list[str] = field(default_factory=list)
    # .so 内符号/字符串子串（大小写不敏感）→ 强证据；识别以静态库编入宿主 .so、无独立 so 名/
    # dex 包名的工具（ArtHook），或抗改名的反检测特征串（SignCheck/InjectDetect）。
    so_strings: list[str] = field(default_factory=list)
    # true = 要求 so_strings 列全部在同一 .so 内共现（如 SignCheck 的 IPackageManager+IServiceManager）；
    # false = 任一命中即可（默认）。
    so_strings_all: bool = False
    # DEX 字符串**内容**子串（★大小写敏感——base64 载荷区分大小写）→ 强证据。
    # 与 dex_prefixes 的区别：后者匹的是包名（R8 改名即失效），本字段匹的是**字面量内容**——
    # R8/ProGuard 只重命名符号、从不改字符串内容，故可扛住改名与重打包。
    # 只放「删了工具就不能工作」或「本项目独有措辞」的串；技术级通用串（框架类名、syscall 号）绝不入此列。
    dex_strings: list[str] = field(default_factory=list)
    anti_frida: bool = False
    note: str = ""


@dataclass
class _Hit:
    """一条规则的命中证据集合。

    strong：so 名 / 特征文件 / .so 内符号·字符串命中（工具运行时实证）；否则仅 dex 包名命中（中证据）。
    """

    rule: _ToolRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    strong: bool = False


class ReToolkitAnalyzer(BaseAnalyzer):
    """识别样本内置的 hook 框架 / 反检测工具，产 anti_analysis Finding + 抓包预判 meta。"""

    name: str = "re_toolkit"
    meta_key_categories = {
        'anti_frida': 'signal',
        'dex_strings_truncated': 'coverage',
        'hook_frameworks': 'record',
        're_toolkit': 'signal',
    }
    meta_keys = frozenset(meta_key_categories)
    # 待定：聚合画像可能仅供人工查看，也可能应进入 visibility；先按信号报警。
    meta_category_pending = frozenset({'re_toolkit'})
    requires: list[str] = ["apk"]  # Android 专属

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用工具指纹规则，跳过识别", self.name)
            self._set_empty_meta(result)
            return result

        # 四路数据源各自 try/except，单源失败不影响其余。
        so_basenames = _collect_so_basenames_shared(ctx, self.name)
        file_paths = _collect_file_paths_shared(ctx, self.name)
        _dex_ok, dex_strings = _collect_dex_strings_shared(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result
        )
        # .so 内容采样取串——仅当有规则用 so_strings 时才做（否则零额外 IO）。
        so_blobs: list[tuple[str, str]] = []
        if any(r.so_strings for r in rules):
            try:
                so_blobs = _collect_app_so_string_blobs(ctx, self.name)
            except Exception:
                logger.exception("[%s] 采样 .so 字符串失败，跳过该路匹配", self.name)

        hits: list[_Hit] = []
        for rule in rules:
            try:
                hit = self._match_rule(rule, so_basenames, file_paths, dex_strings, so_blobs)
            except Exception:
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                hits.append(hit)

        # ★结构性检测（抗 fork）：上面全是「认得出是哪个库」的字面量锚点，fork 改包名 / 删错误串 /
        #   重编译 shellcode 后就全废。本检测只认**手法本身**——DEX 里带一段 base64 文本、解码后是
        #   含 syscall 指令的原始机器码——这一点任何 fork 都改不掉（改了功能就没了）。
        try:
            shellcode_hit = self._detect_embedded_syscall_stub(dex_strings)
        except Exception:
            logger.exception("[%s] 内嵌 syscall 载荷结构检测失败，跳过", self.name)
            shellcode_hit = None
        if shellcode_hit is not None:
            hits.append(shellcode_hit)

        if not hits:
            logger.info("[%s] 未识别到已知 hook/反检测工具特征", self.name)
            self._set_empty_meta(result)
            return result

        anti_frida = any(h.rule.anti_frida for h in hits)
        result.meta["re_toolkit"] = [
            {
                "name": h.rule.name,
                "category": h.rule.category,
                "capability": h.rule.capability,
                "strong": h.strong,
            }
            for h in hits
        ]
        result.meta["hook_frameworks"] = [
            h.rule.name for h in hits if h.rule.category == "hook_framework"
        ]
        result.meta["anti_frida"] = anti_frida
        result.findings.append(self._build_finding(hits, anti_frida))
        return result

    @staticmethod
    def _set_empty_meta(result: AnalyzerResult) -> None:
        result.meta["re_toolkit"] = []
        result.meta["hook_frameworks"] = []
        result.meta["anti_frida"] = False

    # ------------------------------------------------------------------
    # 结构性检测：内嵌 syscall 机器码（base64 文本载荷）——抗 fork
    # ------------------------------------------------------------------

    def _detect_embedded_syscall_stub(self, dex_strings: list[str]) -> "_Hit | None":
        """在 DEX 字符串里找「base64 文本 → 解码后是含 syscall 指令的原始机器码」。

        ★为什么这条抗 fork：字面量锚点（包名 / 错误串 / 具体 base64 值）在 fork 改名、改措辞、
        重新编译 shellcode 后全部失效；但「把可执行的 syscall 桩当文本字面量塞进 DEX」是这套手法的
        **必要构造**——纯 Java 进不了内核，必须先有一段机器码再 mmap 成 RWX 执行。改不掉。

        判据（逐条都为压假阳）：
          1. 候选串足够长且是合法 base64（长度/数量/总解码量三重封顶，防大 APK 上炸开销）；
          2. 解码结果**不是**已知容器格式（ELF / ZIP / PNG / gzip 等）——那是正常的内嵌资源；
          3. 解码字节里存在**指令对齐**的 syscall 指令编码。只用 4 字节定长指令集
             （arm64/arm32/riscv64/mips），随机数据命中概率 ~1/2³²，实测 2000 次随机零命中；
             x86 的 ``0f 05`` / ``cd 80`` 仅 1~2 字节，随机噪声里常见，**不单独作判据**。

        命中即合成一条**技术级**（非工具级）命中：只说"存在这一手法"，不指名是哪个库。
        """
        matches = self._scan_syscall_stub_strings(dex_strings)
        if not matches:
            return None
        rule = _ToolRule(
            name="内嵌 syscall 机器码（base64 文本载荷，技术级）",
            category="evasion",
            capability="把可执行 syscall 桩以 base64 文本嵌在 DEX，运行时解码进 RWX 页执行（绕过 libc/Java hook 层）",
            anti_frida=True,
            note=(
                "★技术级指纹（非工具级）：不指名具体库，抗 fork——改包名 / 删错误串 / 重编译 shellcode "
                "都不影响，因为「机器码以文本形式随 DEX 分发」是这套手法的必要构造。"
                "命中即说明 frida / Java 层 hook 可能被绕过（抓不到≠没有），应退旁路 pcap / tls-keylog。"
            ),
        )
        hit = _Hit(rule=rule)
        hit.strong = True
        for arch, count, preview in matches[:3]:
            hit.evidences.append(Evidence(
                source="dex", location="string-literal",
                snippet=_truncate(f"base64→机器码：{arch} syscall×{count}；载荷首段 {preview}"),
            ))
            hit.matched_features.append(f"syscall_stub:{arch}")
        return hit

    @staticmethod
    def _scan_syscall_stub_strings(dex_strings: list[str]) -> list[tuple[str, int, str]]:
        """扫描候选串，返回 ``[(架构, 对齐 syscall 指令数, 载荷首段十六进制)]``。纯函数，便于单测。

        ★额度记账的三条纪律（复审 P1）：
          ① **解码前**按 base64 长度预估解码后大小 → 超单载荷上限直接跳过，绝不"先分配再判"；
          ② 累计解码量是**硬上限**，同样在解码前扣减，单个巨串不能突破它；
          ③ ``checked`` 只统计**真正解码过**的候选——否则海量无关长 base64 会占满额度，
             把排在后面的真载荷静默挤掉（正是本项目最忌的"抓不到≠没有"）。触顶一律 warning。
        """
        out: list[tuple[str, int, str]] = []
        decoded_budget = _MAX_STUB_DECODE_BYTES
        checked = 0
        skipped_oversize = 0
        exhausted = False
        for s in dex_strings:
            if checked >= _MAX_STUB_CANDIDATES or decoded_budget <= 0:
                exhausted = True
                break
            if not isinstance(s, str) or len(s) < _MIN_STUB_B64_CHARS:
                continue
            compact = "".join(s.split())  # 折叠串内含真实换行（javac 常量折叠形态）
            if len(compact) < _MIN_STUB_B64_CHARS or not _B64_ONLY_RE.fullmatch(compact):
                continue
            # ①②解码前的两道闸：预估解码后字节数 = base64 长度 × 3/4（上界，忽略 padding）。
            est = len(compact) * 3 // 4
            if est > _MAX_STUB_PAYLOAD_BYTES:
                skipped_oversize += 1
                continue  # 远大于任何真实 syscall 桩；跳过且不扣预算（未解码 = 未耗内存）
            if est > decoded_budget:
                exhausted = True
                break
            decoded_budget -= est
            checked += 1
            try:
                data = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
            except Exception:  # noqa: BLE001 — 非法 base64（非候选输入，非内部故障）跳过
                continue
            if len(data) < _MIN_STUB_BYTES or data.startswith(_CONTAINER_MAGICS):
                continue
            need = _MIN_SYSCALL_INSN if len(data) <= _LARGE_STUB_BYTES else _MIN_SYSCALL_INSN_LARGE
            for arch, (insn, align) in _SYSCALL_INSNS.items():
                count = sum(
                    1 for i in range(0, len(data) - len(insn) + 1, align)
                    if data[i:i + len(insn)] == insn
                )
                if count >= need:
                    out.append((arch, count, data[:12].hex(" ")))
                    break
        if exhausted:
            logger.warning(
                "[re_toolkit] 内嵌 syscall 载荷扫描触顶（已查 %d 个候选、剩余预算 %d 字节），"
                "后续候选未检查——本次「未命中」不等于样本无此特征",
                checked, max(0, decoded_budget),
            )
        if skipped_oversize:
            logger.info(
                "[re_toolkit] 跳过 %d 个超 %d 字节的 base64 载荷（远大于真实 syscall 桩，不参与判定）",
                skipped_oversize, _MAX_STUB_PAYLOAD_BYTES,
            )
        return out

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: _ToolRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
        so_blobs: list[tuple[str, str]],
    ) -> _Hit:
        hit = _Hit(rule=rule)

        # 1) .so 库名（basename 精确匹配，大小写不敏感）→ 强证据
        for so in rule.so_names:
            key = so.lower()
            if key in so_basenames:
                ev = Evidence(source="native", location=so_basenames[key], snippet=f"so={so}")
                hit.evidences.append(ev)
                hit.matched_features.append(f"so:{so}")
                hit.strong = True

        # 2) 特征文件（路径子串匹配，大小写不敏感）→ 强证据
        lowered_files = [(p, p.lower()) for p in file_paths]
        for feat in rule.files:
            needle = feat.lower()
            for orig, low in lowered_files:
                if needle in low:
                    ev = Evidence(source="resource", location=orig, snippet=f"file~={feat}")
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"file:{feat}")
                    hit.strong = True
                    break

        # 3) DEX 类包前缀（子串匹配，大小写敏感保留原样）→ 中证据
        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    ev = Evidence(source="dex", location=prefix, snippet=_truncate(s))
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"dex:{prefix}")
                    break

        # 3b) DEX 字符串**内容**子串（大小写敏感）→ 强证据（抗 R8 改名/重打包：只改符号不改串内容）
        for needle in rule.dex_strings:
            for s in dex_strings:
                if needle in s:
                    ev = Evidence(source="dex", location="string-literal",
                                  snippet=_truncate(f"dex_str~={needle}"))
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"dex_str:{_truncate(needle, 24)}")
                    hit.strong = True
                    break

        # 4) .so 内符号/字符串（子串匹配，大小写不敏感）→ 强证据（抗 so 名/包名改名）
        if rule.so_strings:
            needles = [s.lower() for s in rule.so_strings]
            for path, blob in so_blobs:
                if rule.so_strings_all:
                    hit_needles = needles if all(n in blob for n in needles) else []
                else:
                    hit_needles = [n for n in needles if n in blob]
                if hit_needles:
                    joiner = "&" if rule.so_strings_all else "|"
                    tag = joiner.join(hit_needles)
                    ev = Evidence(source="native", location=path,
                                  snippet=_truncate(f"so_str~={tag}"))
                    hit.evidences.append(ev)
                    hit.matched_features.append(f"so_str:{tag}")
                    hit.strong = True
                    break  # 单个 .so 命中即足以佐证本规则

        return hit

    # ------------------------------------------------------------------
    # Finding 组装
    # ------------------------------------------------------------------

    def _build_finding(self, hits: list[_Hit], anti_frida: bool) -> Finding:
        """据命中工具组一条 Finding：按 category 分组列出工具 + 能力 + 抓包/劫持研判。"""
        has_hook = any(h.rule.category == "hook_framework" for h in hits)
        has_instrumentation = any(h.rule.category == "instrumentation" for h in hits)
        # 反 frida（直 syscall 等，罕见于正常 app）或内嵌 frida gadget → HIGH；
        # 仅 hook 框架（bytehook/shadowhook 亦广泛用于合法 APM/崩溃监控，dual-use）→ MEDIUM，勿单凭此定性。
        severity = Severity.HIGH if (anti_frida or has_instrumentation) else Severity.MEDIUM

        # 按 category 分组列工具。
        grouped: dict[str, list[str]] = {}
        for h in hits:
            label = _CATEGORY_LABELS.get(h.rule.category, h.rule.category)
            cap = f"（{h.rule.capability}）" if h.rule.capability else ""
            grouped.setdefault(label, []).append(f"{h.rule.name}{cap}")
        group_lines = [f"  · {label}：{'、'.join(items)}" for label, items in grouped.items()]

        desc_parts = [
            "检测到样本内置逆向 / hook / 反检测工具链：\n" + "\n".join(group_lines) + "。",
        ]
        if has_hook:
            desc_parts.append(
                "内置 hook 框架 = 具备运行时 hook 能力（★ 亦广泛用于合法 APM / 崩溃监控，勿单凭此定性）；"
                "若样本同时申请无障碍/辅助功能权限、或与反检测工具共现，则高度疑似无障碍远控 / "
                "劫持银行·支付 app（结合 REMOTE_CONTROL 线索研判）。"
            )
        if anti_frida:
            anti_names = "、".join(h.rule.name for h in hits if h.rule.anti_frida)
            desc_parts.append(
                f"★ 命中反 frida 工具（{anti_names}）：这类走直 syscall / 内存加载等手段绕过 libc/Java hook 层，"
                "fxapk 的 frida 动态抓包可能**静默失效**（抓不到≠没有）。"
            )

        recommendation_parts = [
            "记录内置 hook/反检测工具链作为关联候选；工具类型相同不能证明同一主体，须比较独特代码哈希、配置与目标范围等独立锚点。",
        ]
        if anti_frida:
            recommendation_parts.append(
                "动态抓包别只靠 frida：改走旁路 pcap（PCAPdroid / 网关 tcpdump）拿接入节点、"
                "tls-keylog 离线解 TLS、或内核层抓包；frida 秒退/无产出优先怀疑被反检测击败而非样本干净。"
            )
        if has_hook:
            recommendation_parts.append(
                "核查无障碍/辅助功能、投影录屏权限与 AccessibilityService，研判是否劫持第三方 app。"
            )

        return Finding(
            id="RE-TOOLKIT-DETECTED",
            title="样本内置逆向/Hook/反检测工具链（疑运行时劫持 / 反抓包能力）",
            severity=severity,
            category="anti_analysis",
            description=" ".join(desc_parts),
            recommendation=" ".join(recommendation_parts),
            evidences=[ev for h in hits for ev in h.evidences],
            references=["https://developer.android.com/topic/security"],
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> list[_ToolRule]:
        data = load_rules(_RULES_NAME)
        if isinstance(data, dict):
            raw = data.get("tools", [])
        elif isinstance(data, list):
            raw = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            return []
        return self._parse_rules(raw)

    def _parse_rules(self, raw: object) -> list[_ToolRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] tools 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_ToolRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            name = entry.get("name")
            category = entry.get("category")
            if not isinstance(name, str) or not name.strip():
                logger.warning("[%s] 跳过缺少 name 的规则条目：%r", self.name, entry)
                continue
            if not isinstance(category, str) or not category.strip():
                logger.warning("[%s] 跳过缺少 category 的规则条目：%s", self.name, name)
                continue
            rules.append(
                _ToolRule(
                    name=name.strip(),
                    category=category.strip(),
                    capability=_str_or_empty(entry.get("capability")),
                    so_names=_as_str_list(entry.get("so_names")),
                    files=_as_str_list(entry.get("files")),
                    dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                    so_strings=_as_str_list(entry.get("so_strings")),
                    so_strings_all=bool(entry.get("so_strings_all", False)),
                    dex_strings=_as_str_list(entry.get("dex_strings")),
                    anti_frida=bool(entry.get("anti_frida", False)),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return rules


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    return _truncate_shared(text, limit)
