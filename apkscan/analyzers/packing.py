"""加固/加壳识别分析器 — 识别国内主流加固厂商 → 调证线索 + 静态不完整告警。

职责（见设计文档 §4 packing 行）：
- 用 ctx.native_libs() + ctx.list_files() + ctx.dex_strings() 三路匹配加固特征。
- 规则来自 apkscan/rules/packers.yaml（梆梆/爱加密/360/腾讯乐固/娜迦/百度/网易易盾/
  阿里聚安全/几维等），每条含 so 名 / 特征文件 / dex 类前缀。
- 证据分级（关键）：so 名匹配 与 特征文件匹配 = 强证据（加固运行时实证）；
  dex 类名/字符串子串匹配 = 弱证据（可能只是某检测/风控库内嵌的"加固名词表"字符串）。
- 判定规则：**判已加固必须该厂商至少有 1 条强证据（so/file）**。
    * 有强证据命中 →
        - Finding(HIGH, "已加固，静态端点不完整，建议脱壳或真机动态补全")
        - Lead(category=PACKER, subject=加固厂商, where_to_request=加固厂商,
               evidence_to_obtain=["未加固原始安装包","开发者实名注册信息","加固/打包账号与操作日志"],
               confidence=HIGH)
        - meta["packed"] = vendor（多厂商命中时取首个；meta["packers"] 记全部）、is_hardened=True
    * 仅弱（dex）证据命中（无任何强证据）→ **不判已加固**：
        - 不产 PACKER Lead、不产 HIGH "建议脱壳" Finding、is_hardened=False、packed=None
        - 改产一条 LOW Finding(PACK-NAME-STRINGS-ONLY)，透明列出命中的厂商名称字符串与具体
          dex 片段，并声明"未发现对应加固运行时特征(.so/特征文件)，判定为未加固"，
          疑似内嵌加固检测/风控库（≥2 家弱命中更确证为检测词表）。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    as_str_list as _as_str_list,
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
    Confidence,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "packers"

#: APK 核心文件名——每个解析器必找的三个。诱饵条目精确冒充它们（实测：411 条诱饵首段无一例外）。
_CORE_APK_NAMES = frozenset({"AndroidManifest.xml", "classes.dex", "resources.arsc"})
#: 多 dex 的 classes2.dex / classes3.dex …（与 _CORE_APK_NAMES 同等对待）。
_EXTRA_DEX_RE = re.compile(r"classes\d+\.dex")

#: 「拒绝分析」诱饵炸弹的声明大小门槛（实测语料里的构造声明 1000MB；正常 APK 单条目远低于此）。
_DENIAL_BOMB_DECLARED_BYTES = 256 * 1024 * 1024

#: stub dex 判据：DEX 字符串数下限。实测双峰分离极干净——加固样本 15~440 条，
#: 正常 App 12867~299356 条，**29 倍鸿沟**，故取 1000 有充足余量。
#: ★这是结构判据、不依赖厂商特征，故对未知壳 / 自研壳同样有效（与抗 fork 的思路一致）。
_STUB_MAX_DEX_STRINGS = 1000
#: 佐证：真 App 的 classes*.dex 通常数 MB；stub 仅 1~57KB。作为第二判据之一（与「有 .so」二选一）。
_STUB_MAX_DEX_BYTES = 1 * 1024 * 1024

# 命中后 Lead 默认可调取证据（规则文件 meta 缺失时的兜底，确保离线/规则缺失仍合规）。
_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "未加固原始安装包",
    "开发者实名注册信息",
    "加固/打包账号与操作日志",
)

_FINDING_TITLE = "已加固，静态端点不完整，建议脱壳或真机动态补全"

# DEX 字符串扫描上限：加固样本字符串池可能很大，避免极端情况下扫描过久。
_MAX_DEX_STRINGS = 200_000

# dex_strings 命中后用于证据片段的截断长度。
_SNIPPET_MAX = 200


@dataclass
class _PackerRule:
    """单条加固厂商规则（从 YAML 规整而来）。"""

    name: str
    vendor: str
    so_names: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    dex_prefixes: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class _Hit:
    """一条规则的命中证据集合。

    证据分级：
    - strong_evidences：so 名 / 特征文件匹配（加固运行时实证，可据此判已加固）。
    - weak_evidences：dex 类名/字符串子串匹配（可能只是内嵌加固名词表字符串，单独不足判加固）。
    evidences / matched_features 保持"全集"语义（强+弱），供 Finding 汇总与 Lead.source_refs 使用。
    """

    rule: _PackerRule
    evidences: list[Evidence] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    strong_evidences: list[Evidence] = field(default_factory=list)
    weak_evidences: list[Evidence] = field(default_factory=list)

    @property
    def is_strong(self) -> bool:
        """是否含至少一条强证据（so/file）；仅此情形可判已加固。"""
        return bool(self.strong_evidences)

    def matched_summary(self) -> str:
        """命中摘要：'产品名[特征1、特征2]'，用于 Finding 描述拼接。"""
        feats = "、".join(self.matched_features) if self.matched_features else "(无)"
        return f"{self.rule.name}[{feats}]"


class PackingAnalyzer(BaseAnalyzer):
    """识别加固厂商，产出 PACKER 线索 + 静态端点不完整 Finding。"""

    name: str = "packing"
    requires: list[str] = ["apk"]  # Android 专属

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules, default_evidence, where_suffix = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用加固规则，跳过识别", self.name)
            result.meta["packed"] = None
            result.meta["packer"] = None
            result.meta["packers"] = []
            result.meta["is_hardened"] = False
            return result

        # 三路数据源各自 try/except，单源失败不影响其余。
        so_basenames = self._collect_so_basenames(ctx)
        file_paths = self._collect_file_paths(ctx)
        dex_iter_ok, dex_strings = self._collect_dex_strings(ctx, result)

        # 容器结构异常与加固规则命中与否无关，故在此提前判定——下方各分支的 return 都返回同一个
        # result 对象，提前 append 对所有路径生效。
        try:
            self._flag_core_name_decoys(result, file_paths)
        except Exception:
            logger.exception("[%s] 诱饵条目检测失败，跳过", self.name)
        try:
            self._flag_denial_bombs(result, ctx, file_paths)
        except Exception:
            logger.exception("[%s] 诱饵炸弹条目检测失败，跳过", self.name)

        hits: list[_Hit] = []
        for rule in rules:
            try:
                hit = self._match_rule(rule, so_basenames, file_paths, dex_strings)
            except Exception:
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.name)
                continue
            if hit.evidences:
                hits.append(hit)

        result.meta["dex_scanned"] = dex_iter_ok

        # 证据分级分流：强命中（so/file）才判已加固；仅弱命中（dex 名词）降级为 LOW INFO。
        strong_hits = [h for h in hits if h.is_strong]
        weak_only_hits = [h for h in hits if not h.is_strong and h.weak_evidences]

        if strong_hits:
            self._emit_hardened(result, strong_hits, default_evidence, where_suffix)
            return result

        # ★结构判据兜底（厂商没认出来 ≠ 没加固）：必须在「无任何命中」分支**之前**调用——
        #   实测三案正是零厂商命中、直接走 not hits 分支返回，若放在后面永远到不了。
        try:
            self._flag_stub_dex(result, file_paths, dex_strings)
        except Exception:
            logger.exception("[%s] stub dex 结构判定失败，跳过", self.name)

        if not hits:
            logger.info("[%s] 未识别到已知加固特征", self.name)
            result.meta.setdefault("packed", None)
            result.meta.setdefault("packer", None)
            result.meta.setdefault("packers", [])
            result.meta.setdefault("is_hardened", False)
            return result

        # 仅弱命中（无任何强证据）→ 不判已加固，产一条 LOW 透明说明 Finding。
        logger.info(
            "[%s] 仅命中加固厂商名称字符串（无 so/特征文件强证据），判定为未加固：%s",
            self.name,
            "、".join(h.rule.name for h in weak_only_hits),
        )
        result.meta["packed"] = None
        result.meta["packer"] = None
        result.meta["packers"] = []
        result.meta["is_hardened"] = False
        result.findings.append(self._build_weak_finding(weak_only_hits))
        return result

    # ------------------------------------------------------------------
    # 容器结构异常：冒充核心文件名的绝对路径诱饵条目
    # ------------------------------------------------------------------

    def _flag_core_name_decoys(self, result: AnalyzerResult, file_paths: list[str]) -> None:
        """检出「以 ``/`` 开头、首段恰为 APK 核心文件名」的诱饵条目，写 meta 并产 Finding。

        ★依据（真实样本实测）：部分样本含数百条此类条目，**首段无一例外**只有三种——
        ``AndroidManifest.xml``×153、``classes.dex``×153、``resources.arsc``×105，即精确瞄准每个
        APK 解析器必找的那三个文件。形如 ``/AndroidManifest.xml///.png``、``/classes.dex/<乱码>.json``。

        ★为什么近乎零假阳：ZIP 规范明确要求条目名**不得以斜杠开头**（不得为绝对路径），Android
        构建工具也从不产生这种条目。出现即人为构造。语料中 多个样本一条都没有。

        ★不做的事：不据此判定"是哪个加固工具"——实测各样本的扩展名分布逐构建随机化，细粒度签名
        每样本都不同，当不了家族键（与 dpt-shell「so 名随机、assets 常量固定」同理）。只报手法。
        """
        decoys = [p for p in file_paths if isinstance(p, str) and p.startswith("/")]
        if not decoys:
            return
        impersonated: dict[str, int] = {}
        for path in decoys:
            head = path[1:].split("/", 1)[0]
            if head in _CORE_APK_NAMES or _EXTRA_DEX_RE.fullmatch(head):
                impersonated[head] = impersonated.get(head, 0) + 1
        result.meta["container_decoy_entries"] = {
            "absolute_path_entries": len(decoys),
            "impersonating_core_names": impersonated,
        }
        if not impersonated:
            return  # 有绝对路径但不冒充核心名：异常但意图不明，只记 meta 不产 Finding

        shown = "、".join(f"{name}×{n}" for name, n in sorted(impersonated.items()))
        result.findings.append(Finding(
            id="APK-CORE-NAME-DECOY-ENTRIES",
            title="APK 内含冒充核心文件名的诱饵条目（容器级反分析构造）",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,  # 结构性事实：条目名违反 ZIP 规范，非统计启发式
            category="anti_analysis",
            description=(
                f"压缩包内有 {len(decoys)} 条**以 / 开头的绝对路径条目**，其中 {sum(impersonated.values())} 条的"
                f"首段恰为 APK 核心文件名（{shown}）。ZIP 规范要求条目名不得为绝对路径，Android 构建工具"
                "也从不产生此类条目——出现即人为构造，意在让解析器在定位这三个核心文件时撞上假条目。\n"
                "★ 已实测：fxapk 自身不受影响（真样本上包名/清单/DEX 均正常解出，诱饵未遮蔽真文件）。"
            ),
            recommendation=(
                "别用会**落盘解压**的工具直接展开该样本（apktool / unzip / 部分反编译器）："
                "绝对路径条目在不同工具下行为不一，可能写到预期外位置或直接报错中断。"
                "宜继续用内存读取方式分析；若必须解压，先剥掉以 / 开头的条目。"
                "该构造可作技术画像用于跨样本关联，但**不宜单独作家族锚点**——实测其细节逐构建随机化。"
            ),
            evidences=[
                Evidence(source="resource", location="zip-entry", snippet=_truncate(p))
                for p in decoys[:5]
            ],
        ))
        logger.info(
            "[%s] 检出诱饵条目 %d 条（冒充核心名 %s）", self.name, len(decoys), shown
        )

    def _flag_stub_dex(
        self, result: AnalyzerResult, file_paths: list[str], dex_strings: list[str]
    ) -> None:
        """结构判据：DEX 小到不像真 App（stub） + 有 App 自有 .so → 判「疑加固·厂商未识别」。

        ★为什么需要：厂商识别靠 so 名 / 特征文件 / 包名等**已知特征**，遇上未知壳或自研壳
        就全部落空、报「未加固」——而真相是 Java 侧几乎什么都没抽到，报告却让人以为静态端点完整。
        实测三个真样本正是如此：classes.dex 仅 1~3KB、DEX 字符串 15~57 条，却被判「未加固」。

        ★阈值有实测依据（真实样本标定）：加固样本 DEX 字符串 15~440 条，正常 App 12867~299356 条，
        **相差 29 倍**，故取 1000 有充足余量。第二判据取「dex 极小」或「有 App 自有 .so」二选一——
        真 App 即便字符串少也不会只有几 KB dex；纯资源类小 App 无 .so 时不误伤。

        ★只报手法不认厂商：不写 ``packed``（那是厂商归属，写了会误导"向该厂商调证"），
        只置 ``is_hardened`` 与 ``hardening_structural``，并产 Finding 明说静态不完整。
        """
        n_str = len(dex_strings)
        if n_str >= _STUB_MAX_DEX_STRINGS:
            return
        so_paths = [p for p in file_paths if isinstance(p, str) and p.lower().endswith(".so")]
        dex_bytes = sum(1 for p in file_paths if isinstance(p, str) and p.endswith(".dex"))
        if not so_paths and dex_bytes:
            return          # 无 native、又确有 dex：可能只是极简 App，不误伤

        result.meta["hardening_structural"] = {
            "dex_strings": n_str,
            "app_so_count": len(so_paths),
            "reason": "stub-dex",
        }
        result.meta["is_hardened"] = True   # 结构上确已加固；厂商未知不影响这个事实
        result.findings.append(Finding(
            id="PACK-UNIDENTIFIED-STUB-DEX",
            title="疑已加固（DEX 仅存壳桩，厂商未识别）——静态端点不完整",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="packing",
            description=(
                f"DEX 字符串仅 {n_str} 条，而真实 App 通常上万条（实测语料正常样本 12867~299356 条、"
                f"加固样本 15~440 条）；同时存在 {len(so_paths)} 个 native 库。这符合**加固壳只留桩 DEX、"
                "真实字节码另行加密存放**的形态，但未命中任何已知厂商特征——即**未知壳或自研壳**。\n"
                "★ 直接后果：Java 侧几乎什么都抽不到。本报告里 endpoints / contacts / config_keys 的"
                "「未发现」**不可解读为「不存在」**——真实逻辑在被加密的 DEX 里。"
            ),
            recommendation=(
                "别据本次静态结果判该样本的网络行为与配置。需**脱壳后重新静态分析**"
                "（`fxapk unpack`，再以 `--extra-dex` 回灌 dump 出的 DEX），或转运行时观测"
                "（floor PCAP 拿实际连接的 IP:端口 + socket 归因）。"
                "★ 厂商未识别不代表未加固——这条正是为未知壳/自研壳兜底。"
            ),
            evidences=[
                Evidence(source="dex", location="classes.dex", snippet=f"dex_strings={n_str}"),
                *[Evidence(source="native", location=p, snippet="app .so")
                  for p in so_paths[:3]],
            ],
        ))
        logger.info(
            "[%s] 结构判定疑加固：DEX 字符串仅 %d 条、native 库 %d 个（厂商未识别）",
            self.name, n_str, len(so_paths),
        )

    def _flag_denial_bombs(
        self, result: AnalyzerResult, ctx: "AnalysisContext", file_paths: list[str]
    ) -> None:
        """检出「声明解压极大、实际压缩很小」的**非核心**条目——「拒绝分析」式诱饵炸弹。

        ★手法：塞一两个声明 1GB、实际只有几 MB 的垃圾条目（如 ``res/1.xml``），任何带 zip 炸弹
        防护的工具见了就拒绝**整个**样本 → 攻击者用我们的防护达成完全的分析拒绝。实测语料中的样本
        各有一对 ``res/1.xml`` + ``assets/1.xml``，声明 1000MB / 压缩 5.5MB（180 倍），三样本参数一致。

        ★fxapk 已不再因此判死整包（见 core.apk._reject_if_zip_bomb）：非核心超限条目只跳过该条目、
        分析照常。此处把它作为**反分析信号**报出来，并提示其它工具可能因此整包失败。
        """
        bombs: list[tuple[str, int]] = []
        for path in file_paths:
            if not isinstance(path, str):
                continue
            try:
                declared = ctx.declared_size(path)
            except Exception:  # noqa: BLE001 — 访问器异常不阻断整体
                logger.debug("[%s] 查声明大小失败：%s", self.name, path, exc_info=True)
                continue
            if declared is not None and declared > _DENIAL_BOMB_DECLARED_BYTES:
                bombs.append((path, declared))
        if not bombs:
            return
        result.meta["denial_bomb_entries"] = [
            {"path": p, "declared_bytes": d} for p, d in sorted(bombs)[:20]
        ]
        shown = "、".join(f"{p}（声明 {d // 1024 // 1024}MB）" for p, d in sorted(bombs)[:3])
        result.findings.append(Finding(
            id="APK-DENIAL-OF-ANALYSIS-BOMB",
            title="APK 内含「拒绝分析」式诱饵炸弹条目（声明解压极大的垃圾条目）",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,  # 结构性事实：中央目录声明值可直接读出
            category="anti_analysis",
            description=(
                f"压缩包内有 {len(bombs)} 个条目声明解压后极大（{shown}），而实际压缩体积很小。"
                "这类条目对 App 运行毫无用处，作用是让**带 zip 炸弹防护的分析工具直接拒绝整个样本**"
                "——用防护本身达成分析拒绝。\n"
                "★ fxapk 已针对性放行：这些非核心条目只被跳过（绝不读取），样本其余部分照常分析。"
            ),
            recommendation=(
                "别因其它工具报「zip 炸弹/ 文件过大」就判该样本无法分析——那正是构造者想要的结果。"
                "换用逐条目按需读取的工具（如本工具），或先剥掉这些条目再交给其它工具。"
                "★ 绝不要真去解压这些条目。"
            ),
            evidences=[
                Evidence(source="resource", location=p, snippet=f"declared={d}")
                for p, d in sorted(bombs)[:5]
            ],
        ))
        logger.info("[%s] 检出「拒绝分析」诱饵炸弹条目 %d 个", self.name, len(bombs))

    def _emit_hardened(
        self,
        result: AnalyzerResult,
        strong_hits: list[_Hit],
        default_evidence: list[str],
        where_suffix: str,
    ) -> None:
        """有强证据命中：产 HIGH Finding + 每厂商一条 PACKER Lead（文案/字段不变）。"""
        vendors = [hit.rule.vendor for hit in strong_hits]
        result.meta["packed"] = vendors[0]
        result.meta["packers"] = vendors
        # 报告概览加固 banner 消费的键。
        result.meta["packer"] = vendors[0]
        result.meta["is_hardened"] = True

        all_evidences: list[Evidence] = []
        for hit in strong_hits:
            all_evidences.extend(hit.evidences)

        product_names = "、".join(hit.rule.name for hit in strong_hits)
        result.findings.append(
            Finding(
                id="PACK-DETECTED",
                title=_FINDING_TITLE,
                severity=Severity.HIGH,
                category="packing",
                description=(
                    f"检测到应用已使用加固/加壳保护（识别厂商：{product_names}）。"
                    "加固会对真实 DEX 加密/隐藏并在运行时还原，"
                    "静态分析无法获取完整的 DEX 字符串、网络端点、第三方 SDK 与支付线索，"
                    "本次静态产出的端点/SDK/支付清单可能严重不完整。"
                    f"命中特征：{'; '.join(h.matched_summary() for h in strong_hits)}。"
                ),
                recommendation=(
                    "建议脱壳后重新静态分析，或在真机/沙箱动态运行抓包补全端点与资金流线索；"
                    "同时将加固厂商作为调证目标，调取未加固原始安装包与打包账号信息。"
                ),
                evidences=all_evidences,
                references=[
                    "https://developer.android.com/topic/security",
                ],
            )
        )

        for hit in strong_hits:
            rule = hit.rule
            where = rule.vendor + where_suffix
            result.leads.append(
                Lead(
                    category=LeadCategory.PACKER,
                    value=rule.name,
                    subject=rule.vendor,
                    where_to_request=where,
                    evidence_to_obtain=list(default_evidence),
                    confidence=Confidence.HIGH,
                    source_refs=list(hit.evidences),
                    notes=self._lead_notes(hit),
                )
            )

    def _build_weak_finding(self, weak_only_hits: list[_Hit]) -> Finding:
        """仅 dex 名词命中（无 so/特征文件）→ 一条 LOW、透明说明的 Finding。

        逐厂商列出命中的加固名称字符串与具体 dex 片段，显式声明"未加固"，
        便于分析员理解为何无加固结论（不吞、可复现）。
        """
        vendor_names = [h.rule.name for h in weak_only_hits]
        multi = len(weak_only_hits) >= 2

        # 逐厂商列具体片段（厂商 → prefix / 截断片段）。
        detail_lines: list[str] = []
        all_weak_evidences: list[Evidence] = []
        for hit in weak_only_hits:
            frags = "；".join(
                f"{ev.location}→{ev.snippet}" for ev in hit.weak_evidences
            )
            detail_lines.append(f"  - {hit.rule.name}：{frags}")
            all_weak_evidences.extend(hit.weak_evidences)

        description_parts = [
            "在 DEX 字符串中检测到加固厂商名称/类名特征字符串（命中厂商："
            f"{'、'.join(vendor_names)}），"
            "但未发现对应加固运行时特征（无 vendor .so 库、无加固特征文件），"
            "疑似为某检测/风控库内嵌的加固名词表（黑名单/检测词表），"
            "并非真实加固运行时，据此判定为【未加固】。",
        ]
        if multi:
            description_parts.append(
                f"本次同时命中 {len(weak_only_hits)} 家加固厂商名称字符串"
                f"（{'、'.join(vendor_names)}），更确证为加固检测词表而非真实加固。"
            )
        description_parts.append("命中的具体 dex 片段（前缀→片段）：\n" + "\n".join(detail_lines))

        return Finding(
            id="PACK-NAME-STRINGS-ONLY",
            title="检测到加固厂商名称字符串，未见加固运行时特征（疑似内嵌加固检测/风控库）",
            severity=Severity.LOW,
            confidence=Confidence.LOW,  # 仅 dex 名称串、无运行时特征 → 弱信号，低置信
            category="packing",
            description="".join(description_parts),
            recommendation=(
                "无需脱壳：本应用未被加固，静态端点/SDK/支付线索完整可信。"
                "如需进一步确认，可人工核对 .so 列表与 assets 特征文件是否存在加固运行时。"
            ),
            evidences=all_weak_evidences,
        )

    # ------------------------------------------------------------------
    # 数据源采集（各自 try/except）
    # ------------------------------------------------------------------

    def _collect_so_basenames(self, ctx: "AnalysisContext") -> dict[str, str]:
        """返回 {小写 basename: 原始路径}。包含 native_libs 与 list_files 中的 .so。"""
        return _collect_so_basenames_shared(ctx, self.name)

    def _collect_file_paths(self, ctx: "AnalysisContext") -> list[str]:
        """APK 内全部文件路径（小写副本用于匹配时另算）。"""
        return _collect_file_paths_shared(ctx, self.name)

    def _collect_dex_strings(
        self, ctx: "AnalysisContext", result: AnalyzerResult | None = None
    ) -> tuple[bool, list[str]]:
        """收集 DEX 字符串（带上限）。返回 (是否成功遍历, 字符串列表)。"""
        return _collect_dex_strings_shared(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result
        )

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: _PackerRule,
        so_basenames: dict[str, str],
        file_paths: list[str],
        dex_strings: list[str],
    ) -> _Hit:
        hit = _Hit(rule=rule)

        # 1) .so 库名（basename 精确匹配，大小写不敏感）→ 强证据
        for so in rule.so_names:
            key = so.lower()
            # 精确 basename 命中
            if key in so_basenames:
                ev = Evidence(source="native", location=so_basenames[key], snippet=f"so={so}")
                hit.evidences.append(ev)
                hit.strong_evidences.append(ev)
                hit.matched_features.append(f"so:{so}")
                continue
            # 容忍规则写不带 .so 后缀 / 库名为前缀（如 libnllvm* / libsgmainso*）的情况
            if not key.endswith(".so"):
                for base, path in so_basenames.items():
                    if base.startswith(key):
                        ev = Evidence(source="native", location=path, snippet=f"so~={so}")
                        hit.evidences.append(ev)
                        hit.strong_evidences.append(ev)
                        hit.matched_features.append(f"so:{so}")
                        break

        # 2) 特征文件（路径子串匹配，大小写不敏感）→ 强证据
        lowered_files = [(p, p.lower()) for p in file_paths]
        for feat in rule.files:
            needle = feat.lower()
            for orig, low in lowered_files:
                if needle in low:
                    ev = Evidence(source="resource", location=orig, snippet=f"file~={feat}")
                    hit.evidences.append(ev)
                    hit.strong_evidences.append(ev)
                    hit.matched_features.append(f"file:{feat}")
                    break

        # 3) DEX 类前缀/字符串特征（子串匹配，大小写敏感保留原样）→ 弱证据
        #    可能只是内嵌加固名词表字符串，单独不足以判已加固。
        for prefix in rule.dex_prefixes:
            for s in dex_strings:
                if prefix in s:
                    ev = Evidence(
                        source="dex",
                        location=prefix,
                        snippet=_truncate(s),
                    )
                    hit.evidences.append(ev)
                    hit.weak_evidences.append(ev)
                    hit.matched_features.append(f"dex:{prefix}")
                    break

        return hit

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_PackerRule], list[str], str]:
        """加载并规整规则，返回 (规则列表, 默认可调证据, where 后缀)。"""
        data = load_rules(_RULES_NAME)

        raw_packers: object
        evidence: list[str] = list(_DEFAULT_EVIDENCE_TO_OBTAIN)
        where_suffix = "（加固厂商）"

        if isinstance(data, dict):
            raw_packers = data.get("packers", [])
            meta = data.get("meta")
            if isinstance(meta, dict):
                ev = _as_str_list(meta.get("evidence_to_obtain"))
                if ev:
                    evidence = ev
                suffix = meta.get("where_to_request_suffix")
                if isinstance(suffix, str):
                    where_suffix = suffix
        elif isinstance(data, list):
            # 容忍顶层直接是 list[规则] 的写法
            raw_packers = data
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                self.name,
                type(data).__name__,
            )
            raw_packers = []

        rules = self._parse_rules(raw_packers)
        return rules, evidence, where_suffix

    def _parse_rules(self, raw: object) -> list[_PackerRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] packers 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_PackerRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            name = entry.get("name")
            vendor = entry.get("vendor")
            if not isinstance(name, str) or not name.strip():
                logger.warning("[%s] 跳过缺少 name 的规则条目：%r", self.name, entry)
                continue
            if not isinstance(vendor, str) or not vendor.strip():
                logger.warning("[%s] 跳过缺少 vendor 的规则条目：%s", self.name, name)
                continue
            rules.append(
                _PackerRule(
                    name=name.strip(),
                    vendor=vendor.strip(),
                    so_names=_as_str_list(entry.get("so_names")),
                    files=_as_str_list(entry.get("files")),
                    dex_prefixes=_as_str_list(entry.get("dex_prefixes")),
                    note=_str_or_empty(entry.get("note")),
                )
            )
        return rules

    @staticmethod
    def _lead_notes(hit: _Hit) -> str:
        parts: list[str] = []
        if hit.rule.note:
            parts.append(hit.rule.note)
        if hit.matched_features:
            parts.append("命中特征：" + "、".join(hit.matched_features))
        parts.append(
            "加固导致真实 DEX 不可见，静态端点/SDK/支付线索可能不完整；"
            "建议脱壳或真机动态补全后再次分析。"
        )
        return " ".join(parts)


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    return _truncate_shared(text, limit)
