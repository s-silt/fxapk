"""网络端点提取分析器 — 从 dex / 资源 / native / manifest 全量抽 URL / 域名 / IP。

职责（见设计文档 §4 endpoints 行）：
- 扫四路数据源：
    * dex   ：ctx.dex_strings()
    * resource：ctx.list_files() + read_file（.xml/.json/assets/res/raw 等文本，bytes latin-1 容错解码）
    * native：.so（read_file 后正则抽可见 ASCII 字符串）
    * manifest：ctx.manifest_xml
- 正则匹配 URL(https?://...)、裸域名、IPv4。
- 产 Endpoint(kind=url|domain|ip)，每个 Endpoint 带 evidences=[Evidence(source=..., location=...)]：
    * is_cleartext：URL 以 http:// 开头（明文）。
    * is_private  ：IP 为 RFC1918 / 127.0.0.0/8 / 0.0.0.0 / 169.254 / 局域网，或域名解析到这类字面（host 本身是私网 IP）。
- 同 value 去重合并（合并 evidences）。
- 过滤明显的 schema/命名空间噪音（xmlns / schemas.android.com / w3.org 等，规则来自 endpoints.yaml）。

约束：
- ★ 只产 Endpoint，**不产 DOMAIN/IP Lead** —— pipeline 富化后统一建（build_endpoint_leads）。
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条数据源/单个文件炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import bisect
import logging
import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.core import infra
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.analyzers._common import EndpointCollector
from apkscan.core.textutil import as_str_list as _as_str_list
from apkscan.core.textutil import host_from_url as _host_from_url
from apkscan.core.textutil import host_is_private as _host_is_private
from apkscan.core.textutil import ip_is_private as _ip_is_private
from apkscan.core.textutil import is_noise_bare_ip as _is_noise_bare_ip
from apkscan.core.textutil import parse_ipv4 as _parse_ipv4
from apkscan.core.textutil import strip_url_tail as _strip_url_tail
from apkscan.core.textutil import truncate as _truncate
from apkscan.core.textutil import valid_url_host as _valid_url_host

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "endpoints"

# DEX 字符串扫描上限：加固/大型样本字符串池可能很大，避免极端情况扫描过久。
# （注意：dex 字符串走 ctx.dex_strings() 独立通道，不经下面的文件级分块，故此限额与本次无关。）
_MAX_DEX_STRINGS = 200_000

#: 回环 IPv4 字面（127.0.0.0/8）——供回环占位启发式扫原文。宽松匹配 4 段，具体回环判定交 ipaddress。
# 前后都不接 [.数字]：``\b`` 会把 "127.2.3.4.5"（版本号 / 5 段串）里的前缀 "127.2.3.4" 误当回环 IP。
# 负向前后瞻确保匹配是**独立**的四段点分串，不是更长点分数字的一截。八位段值域由后续 ip_address 解析兜底。
_LOOPBACK_IPV4_RE = re.compile(r"(?<![\d.])127(?:\.\d{1,3}){3}(?![\d.])")

# 大文件分块扫描参数（替代旧的「截断到前 8MB」语义——反诈调证最忌漏端点/漏真 C2，
# 大 .so / 大资源后段的端点不能丢，故改为分块扫完整个文件）。
_SCAN_CHUNK_BYTES = 4 * 1024 * 1024  # 单块 4MB（解码 + 正则的工作集，内存可控）
# 块间重叠窗口：防 URL/域名/IP 跨块边界被切断。8KB 远超任何真实端点 token（域名 host <255、
# IPv4 ~21 字符、URL 的 host 部分必 <255），跨块的端点必在相邻某一块内完整出现；相对 4MB
# 块（0.2%）重复扫描开销可忽略。满足 spec「重叠 ≥ 最长可能匹配」。
_SCAN_OVERLAP_BYTES = 8 * 1024
# 触发分块的文件阈值：<= 此值直接整文件扫（小文件行为/性能与改前完全一致）。
_CHUNK_THRESHOLD_BYTES = _SCAN_CHUNK_BYTES

# native .so 内可见 ASCII 字符串的最小长度（短串多为噪音）。
_MIN_NATIVE_RUN = 6

# snippet 默认截断长度（规则可覆盖）。
_DEFAULT_SNIPPET_MAX = 300

# 内置兜底噪音（规则缺失/不全时仍能过滤最常见命名空间噪音）。
_FALLBACK_NOISE_HOSTS: tuple[str, ...] = (
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "ns.adobe.com",
    "java.sun.com",
    "xmlpull.org",
    "apache.org",
    "github.com",
    "developer.android.com",
    "localhost",
)
_FALLBACK_NOISE_SUBSTRINGS: tuple[str, ...] = (
    "schemas.android.com/apk",
    "/apk/res/",
    "/apk/res-auto",
    "/2000/svg",
    "/2001/XMLSchema",
    "/1999/xhtml",
    "/1999/xlink",
    "www.w3.org/",
)
_FALLBACK_RESOURCE_EXTS: tuple[str, ...] = (
    ".xml",
    ".json",
    ".js",
    ".html",
    ".htm",
    ".properties",
    ".cfg",
    ".conf",
    ".ini",
    ".txt",
    ".yml",
    ".yaml",
)
_FALLBACK_RESOURCE_DIRS: tuple[str, ...] = ("assets/", "res/", "raw/")
# 噪音 IP 兜底（C4：公认占位/示例 + 本次实测版本号形态）。规则缺失时仍过滤。
_FALLBACK_NOISE_IPS: tuple[str, ...] = (
    "1.2.3.4", "0.0.0.0", "13.3.3.7", "2.1.5.1", "3.2.16.7",
)

# ---------------------------------------------------------------------------
# 正则
# ---------------------------------------------------------------------------

# URL：http/https + ws/wss/mqtt，主机部分到首个空白/引号/反引号/尖括号/中文等终止。
# ws/wss/mqtt 是实时 C2 主力通道（杀猪盘行情推送、远控指令、IM 长连接），不抓就漏整类后端。
_URL_RE = re.compile(
    r"""(?:https?|wss?|mqtt)://[^\s"'`<>()\[\]{}\\^|,;]+""",
    re.IGNORECASE,
)

# IPv4（带可选端口）。后续用 ipaddress 复核合法性。
_IPV4_RE = re.compile(
    r"""(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\w.])"""
)

# 裸域名：label.label(.label)*，TLD 为 2+ 字母。要求至少一个点，且不被 @ / 字母数字粘连。
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w.-])"""
)

# native .so 内可见 ASCII 串（含 URL/域名常见字符）。
_NATIVE_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_NATIVE_RUN)

# 常见文件扩展名集合：用于把 "config.json" 这类文件名误判为域名时排除。
_FILE_EXT_TLDS: frozenset[str] = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "bmp",
        "svg",
        "ico",
        "json",
        "xml",
        "html",
        "htm",
        "css",
        "js",
        "ts",
        "java",
        "kt",
        "so",
        "dex",
        "class",
        "jar",
        "aar",
        "txt",
        "md",
        "properties",
        "cfg",
        "conf",
        "ini",
        "yml",
        "yaml",
        "ttf",
        "otf",
        "woff",
        "woff2",
        "mp3",
        "mp4",
        "wav",
        "ogg",
        "webm",
        "pdf",
        "zip",
        "gz",
        "apk",
        "db",
        "dat",
        "bin",
        "plist",
        "pem",
        "key",
        "crt",
        "smali",
    }
)

# 常见 TLD：末段命中即认可为域名（不再走类名/包名启发式）。
_COMMON_TLDS: frozenset[str] = frozenset(
    {
        # RFC 2606 / RFC 6761 保留 TLD：永不进入根区、永不解析，故零误报风险。
        # 收进来是为了让「刻意用保留 TLD 保证绝不撞真实域名」的测试夹具与文档示例照常被识别为域名。
        "test",
        "example",
        "invalid",
        "localhost",

        "com",
        "cn",
        "net",
        "org",
        "gov",
        "edu",
        "info",
        "biz",
        "co",
        "io",
        "me",
        "tv",
        "cc",
        "top",
        "xyz",
        "vip",
        "club",
        "shop",
        "site",
        "online",
        "app",
        "wang",
        "ltd",
        "pro",
        "asia",
        "mobi",
        "ren",
        "win",
        "link",
        "live",
        "fun",
        "work",
        "store",
        "tech",
        "icu",
        "cloud",
        "hk",
        "tw",
        "mo",
        "jp",
        "kr",
        "sg",
        "us",
        "uk",
        "ru",
        "de",
        "fr",
        "in",
        "ph",
        "my",
        "th",
        "vn",
        "id",
        "to",
        "ws",
        "la",
        "im",
        "so",  # 注意：.so 文件已在 _is_resource_target / 上游排除
        "gg",
        "ai",
        "dev",
    }
)

# 裸域名提取的"安全 TLD 白名单"：仅当末段属此集合才认裸域名。
# 刻意剔除与压缩 JS / 代码标识符高频撞车的短 TLD（id/top/to/me/cc/in/so/ai/im/
# info/store/online/work/link/live/win/name/...）——这些真域名仍可经 URL 的 host 抽到，
# 但作为"裸点分串"出现时几乎全是 a.id / rect.top / f32.store / console.info 之类的代码。
# 这是 JS 混合应用（uni-app/H5+）里把域名误报压到可用水平的关键。
_SAFE_BARE_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "biz", "io", "co",
        "xyz", "vip", "club", "shop", "site", "app", "tech", "cloud",
        "fun", "ltd", "pro", "wang", "ren", "mobi", "asia", "icu",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
    }
)

# 作为"注册主体段"(SLD，TLD 前一段)出现时几乎一定是代码而非域名的常见词。
_CODE_WORDS: frozenset[str] = frozenset(
    {
        "this", "self", "window", "document", "arguments", "console",
        "builder", "component", "child", "container", "clazz", "class",
        "ro", "build", "data", "config", "prototype", "exports", "target",
        "context", "position", "rect", "props", "state", "util", "index",
        "style", "node", "parent", "event", "model", "scope", "options",
        "params", "result", "status", "value", "length", "name", "type",
        "item", "list", "view", "scroll", "offset", "client", "current",
    }
)

# 二进制类扩展：位于 assets/res/raw 等目录但属图片/字体/媒体/压缩等，跳过文本扫描。
_BINARY_EXTS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".ico",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".mp3",
        ".mp4",
        ".wav",
        ".ogg",
        ".webm",
        ".m4a",
        ".aac",
        ".flac",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".apk",
        ".jar",
        ".aar",
        ".dex",
        ".bin",
        ".dat",
        ".db",
        ".keystore",
        ".jks",
    }
)

# 反向域名包名常见根段：用于识别 Java/Kotlin 全限定标识符（非域名）。
_PACKAGE_ROOTS: frozenset[str] = frozenset(
    {
        "com",
        "cn",
        "org",
        "net",
        "io",
        "android",
        "androidx",
        "java",
        "javax",
        "kotlin",
        "kotlinx",
        "dalvik",
        "okhttp3",
        "okio",
        "retrofit2",
    }
)


@dataclass
class _Rules:
    """端点提取规则（从 YAML 规整，缺失用兜底）。"""

    noise_hosts: frozenset[str] = field(default_factory=frozenset)
    noise_substrings: tuple[str, ...] = ()
    resource_exts: tuple[str, ...] = ()
    resource_dirs: tuple[str, ...] = ()
    snippet_max: int = _DEFAULT_SNIPPET_MAX
    noise_ips: frozenset[str] = field(default_factory=frozenset)


def _pos_in_consumed(consumed: list[tuple[int, int]], pos: int) -> bool:
    """pos 是否落在某个已被 URL 覆盖的区间内（半开 [start, end)）。

    ``consumed`` 由 ``_scan_text`` 按 ``_URL_RE.finditer`` 顺序追加，故区间按 start
    严格升序且互不重叠（每段是对应 URL 匹配的子区间）。据此用 bisect 定位候选区间：
    找到 start <= pos 的最右一个区间，只需检查该区间的 end 即可，无需线性扫全部区间
    （旧实现对每个 IP/域名候选 O(URL) 全扫，密集样本上 O(URL×候选)）。

    判定结果与旧 ``any(start <= pos < end for start, end in consumed)`` 逐点一致。
    """
    if not consumed:
        return False
    # bisect_right 按 (start,) 找插入点：所有 start <= pos 的区间都在其左侧，取最右一个。
    idx = bisect.bisect_right(consumed, (pos, float("inf"))) - 1
    if idx < 0:
        return False
    start, end = consumed[idx]
    return pos < end


class EndpointsAnalyzer(BaseAnalyzer):
    """从 dex/resource/native/manifest 提取 URL/域名/IP 端点；另产一条回环占位启发式 Finding
    （硬编码非标准回环 IP + native 库 → 疑似 native 运行时取址占位架构，见 _native_runtime_addressing_finding）。"""

    name: str = "endpoints"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        rules = self._load_rules()
        collector = EndpointCollector()

        # 四路数据源各自 try/except，单源失败不影响其余。
        dex_ok, dex_truncated = self._scan_dex(ctx, collector, rules)
        self._scan_manifest(ctx, collector, rules)
        res_count = self._scan_resources(ctx, collector, rules)
        native_count = self._scan_native(ctx, collector, rules)

        # 稳定排序：kind(url<domain<ip) → value，便于报告/测试确定。
        endpoints = collector.endpoints({"url": 0, "domain": 1, "ip": 2})
        result.endpoints = endpoints

        kinds = {"url": 0, "domain": 0, "ip": 0}
        for ep in endpoints:
            kinds[ep.kind] = kinds.get(ep.kind, 0) + 1
        result.meta.update(
            {
                "dex_scanned": dex_ok,
                "dex_strings_truncated": dex_truncated,
                "resource_files_scanned": res_count,
                "native_files_scanned": native_count,
                "endpoint_total": len(endpoints),
                "url_count": kinds.get("url", 0),
                "domain_count": kinds.get("domain", 0),
                "ip_count": kinds.get("ip", 0),
                "cleartext_count": sum(1 for e in endpoints if e.is_cleartext),
                "private_count": sum(1 for e in endpoints if e.is_private),
            }
        )
        logger.info(
            "[%s] 提取端点 %d 个（url=%d domain=%d ip=%d）",
            self.name,
            len(endpoints),
            kinds.get("url", 0),
            kinds.get("domain", 0),
            kinds.get("ip", 0),
        )
        finding = self._native_runtime_addressing_finding(ctx)
        if finding is not None:
            result.findings.append(finding)
        return result

    # ------------------------------------------------------------------
    # 回环占位启发式：native 运行时取址架构识别
    # ------------------------------------------------------------------

    def _nonstandard_loopback_ips(self, ctx: "AnalysisContext") -> list[tuple[str, str]]:
        """扫 dex 字符串 + manifest **原文**，找"非 127.0.0.1 的回环 IP"字面（127.0.0.0/8、排除 localhost）。

        返回 ``[(ip, source)]``，``source ∈ {"dex", "manifest"}`` 为该字面**首见来源**——供 Finding 证据
        如实溯源（manifest-only 命中不再被误记为 dex）。

        ★不走已抽取的 endpoints：回环/保留段 IP 在端点抽取时被"裸 IP 去噪"当噪音丢了（正是要识破的
        「静默丢」）。标准 127.0.0.1 是常见 localhost 引用（开发/代理），噪声大不采；把**具体的**非标准回环
        地址（如 127.0.209.162）硬编码成后端连接地址才是反常信号——多见于 native 运行时取址占位架构。
        扫描按 _MAX_DEX_STRINGS 封顶、结果去重限量，绝不抛。
        """
        import ipaddress
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _harvest(text: str, source: str) -> None:
            for m in _LOOPBACK_IPV4_RE.findall(text or ""):
                if m in seen:
                    continue
                try:
                    ip = ipaddress.ip_address(m)
                except ValueError:
                    continue
                if ip.version == 4 and ip.is_loopback and m != "127.0.0.1":
                    seen.add(m)
                    out.append((m, source))
                    if len(out) >= 20:  # 限量：够作证据即止
                        return

        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS or len(out) >= 20:
                    break
                if isinstance(s, str) and "127." in s:
                    _harvest(s, "dex")
        except Exception:  # noqa: BLE001 — 单源扫描失败不影响启发式整体
            logger.debug("[%s] 扫 dex 找回环 IP 失败", self.name, exc_info=True)
        try:
            mx = getattr(ctx, "manifest_xml", "") or ""
            if "127." in mx:
                _harvest(mx, "manifest")
        except Exception:  # noqa: BLE001
            logger.debug("[%s] 扫 manifest 找回环 IP 失败", self.name, exc_info=True)
        return out

    def _native_runtime_addressing_finding(self, ctx: "AnalysisContext") -> "Finding | None":
        """★回环占位启发式（A3，识破诱饵地址）：硬编码的非标准回环 IP + 存在 native 库 →
        疑似"native 运行时取址占位"架构——127.x 是本地代理占位、真后端由 .so 解密下发通道后运行时决定。

        此前这类 127.x 端点被一律当私网静默丢，丢掉了这个家族级架构信号。产 Finding 而非丢：明确
        提示"别对该回环地址空调证，真后端在 native / DNS TXT 等下发通道，须动态抓包或逆向 .so 取"。
        无非标准回环 IP 或无 native 库 → None（不误报）。
        """
        loopbacks = self._nonstandard_loopback_ips(ctx)
        if not loopbacks:
            return None
        try:
            has_native = bool(self._collect_so_paths(ctx))
        except Exception:  # noqa: BLE001 — 启发式旁路，采集失败即保守不产 Finding
            logger.debug("[%s] 采集 .so 判定 native 存在性失败", self.name, exc_info=True)
            return None
        if not has_native:
            return None
        shown = "、".join(ip for ip, _ in loopbacks[:5])
        return Finding(
            id="NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER",
            title="疑似 native 运行时取址占位架构（硬编码回环地址 + native 库）",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,  # 启发式：合法本地代理/调试亦可能用非标准回环
            category="anti_analysis",
            description=(
                f"App 把非标准回环地址硬编码成后端连接地址（{shown}），且存在 native 库。这常见于"
                "「native 起本地监听、App 连本地端口、真实后端由 .so 运行时（解密下发通道 / DNS TXT / "
                "远程配置）决定」的取址占位架构——该 127.x 是**本地代理占位、非真实服务器**。"
                "★ 启发式信号：合法本地代理 / 调试转发亦可能用非标准回环，须结合 native 混淆 / 下发通道研判。"
            ),
            recommendation=(
                "别把该回环地址当调证目标（对内网空调证）。真实后端由 native 运行时决定：宜动态抓包"
                "（floor PCAP / socket 归因拿实际连接的公网 IP:端口），或逆向 .so 的下发通道（DNS TXT / "
                "远程配置解密）取真实后端；把该占位架构作为技术画像用于跨样本家族关联。"
            ),
            evidences=[
                Evidence(source=source, location="hardcoded-endpoint", snippet=ip)
                for ip, source in loopbacks[:5]
            ],
        )

    # ------------------------------------------------------------------
    # 数据源扫描
    # ------------------------------------------------------------------

    def _scan_dex(
        self, ctx: "AnalysisContext", collector: EndpointCollector, rules: _Rules
    ) -> tuple[bool, bool]:
        """扫 DEX 字符串池。返回 (是否成功遍历, 是否因超上限被截断)。

        截断标记暴露给 meta（dex_strings_truncated），使"字符串池超 _MAX_DEX_STRINGS
        被截断、后段字符串未扫"这一降级在报告里可见，而非静默丢失端点。
        """
        truncated = False
        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning(
                        "[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_DEX_STRINGS
                    )
                    truncated = True
                    break
                if not isinstance(s, str) or not s:
                    continue
                try:
                    self._scan_text(s, "dex", "dex_strings", collector, rules)
                except Exception:
                    logger.exception("[%s] 解析 DEX 字符串失败，跳过该条", self.name)
        except Exception:
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)
            return False, truncated
        return True, truncated

    def _scan_manifest(
        self, ctx: "AnalysisContext", collector: EndpointCollector, rules: _Rules
    ) -> None:
        try:
            manifest = ctx.manifest_xml
        except Exception:
            logger.exception("[%s] 读取 manifest_xml 失败", self.name)
            return
        if not isinstance(manifest, str) or not manifest:
            return
        try:
            self._scan_text(manifest, "manifest", "AndroidManifest.xml", collector, rules)
        except Exception:
            logger.exception("[%s] 解析 manifest 文本失败", self.name)

    def _scan_resources(
        self, ctx: "AnalysisContext", collector: EndpointCollector, rules: _Rules
    ) -> int:
        """扫资源文本文件（.xml/.json/assets/res/raw 等）。返回扫描文件数。"""
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败（资源扫描）", self.name)
            return 0

        scanned = 0
        for path in files:
            if not self._is_resource_target(path, rules):
                continue
            data = self._safe_read(ctx, path)
            if data is None:
                continue
            scanned += 1
            # 分块扫描：大文件按块解码 + 扫，块间重叠避免跨界漏匹配；小文件整体扫（行为不变）。
            self._scan_bytes_chunked(
                data, "resource", path, collector, rules, self._decode_latin1
            )
        return scanned

    def _scan_native(
        self, ctx: "AnalysisContext", collector: EndpointCollector, rules: _Rules
    ) -> int:
        """扫 native .so：read_file 后正则抽可见 ASCII 串再匹配。返回扫描文件数。"""
        paths = self._collect_so_paths(ctx)
        scanned = 0
        for path in paths:
            data = self._safe_read(ctx, path)
            if data is None:
                continue
            scanned += 1
            # 分块抽 ASCII 串：大 .so（如 12MB+ libweexjss.so）按块跑，块间重叠避免跨界
            # 的端点 ASCII run 被切断；小文件整体扫（行为不变）。
            self._scan_native_bytes_chunked(data, path, collector, rules)
        return scanned

    # ------------------------------------------------------------------
    # 大文件分块扫描（不漏端点：扫完整个文件而非截断到前 8MB）
    # ------------------------------------------------------------------

    def _scan_bytes_chunked(
        self,
        data: bytes,
        source: str,
        location: str,
        collector: EndpointCollector,
        rules: _Rules,
        decode: Callable[[bytes], str],
    ) -> None:
        """对完整 bytes 分块解码 + 扫描（resource 通道），块间重叠避免跨界漏匹配。

        ``<= _CHUNK_THRESHOLD_BYTES`` 直接整体扫（行为/性能与改前一致）；超阈值按
        ``(_SCAN_CHUNK_BYTES - _SCAN_OVERLAP_BYTES)`` 步进、每块取
        ``[start, start+_SCAN_CHUNK_BYTES]`` 字节，decode 后 :meth:`_scan_text`。
        去重由 ``collector.add`` 兜底（同 value 跨块只合并 evidence，不重复产端点；同
        location+snippet 的 evidence 也去重 → 重叠不致端点/证据虚增）。
        """
        n = len(data)
        if n <= _CHUNK_THRESHOLD_BYTES:
            text = decode(data)
            if text:
                try:
                    self._scan_text(text, source, location, collector, rules)
                except Exception:
                    logger.exception("[%s] 解析文件失败，跳过：%s", self.name, location)
            return

        logger.debug(
            "[%s] 大文件分块扫描（%d 字节，块大小 %d，重叠 %d）：%s",
            self.name,
            n,
            _SCAN_CHUNK_BYTES,
            _SCAN_OVERLAP_BYTES,
            location,
        )
        step = _SCAN_CHUNK_BYTES - _SCAN_OVERLAP_BYTES
        start = 0
        while start < n:
            chunk = data[start : start + _SCAN_CHUNK_BYTES]
            text = decode(chunk)
            if text:
                try:
                    self._scan_text(text, source, location, collector, rules)
                except Exception:
                    logger.exception("[%s] 分块扫描失败，跳过该块：%s", self.name, location)
            start += step

    def _scan_native_bytes_chunked(
        self,
        data: bytes,
        location: str,
        collector: EndpointCollector,
        rules: _Rules,
    ) -> None:
        """对完整 native bytes 分块抽 ASCII 串再扫，块间重叠避免跨界 ASCII run 被切断。

        ``<= _CHUNK_THRESHOLD_BYTES`` 整体扫；超阈值按字节分块（重叠 8KB > 任何真实端点串
        且 > ``_MIN_NATIVE_RUN``，跨块 ASCII run 在某块内完整出现）。去重同 collector 兜底。
        """
        n = len(data)
        if n <= _CHUNK_THRESHOLD_BYTES:
            self._scan_native_chunk(data, location, collector, rules)
            return

        logger.debug(
            "[%s] 大 native 分块扫描（%d 字节，块大小 %d，重叠 %d）：%s",
            self.name,
            n,
            _SCAN_CHUNK_BYTES,
            _SCAN_OVERLAP_BYTES,
            location,
        )
        step = _SCAN_CHUNK_BYTES - _SCAN_OVERLAP_BYTES
        start = 0
        while start < n:
            self._scan_native_chunk(
                data[start : start + _SCAN_CHUNK_BYTES], location, collector, rules
            )
            start += step

    def _scan_native_chunk(
        self,
        chunk: bytes,
        location: str,
        collector: EndpointCollector,
        rules: _Rules,
    ) -> None:
        """对一段 native bytes 抽可见 ASCII 串并逐串扫端点。单块异常吞 + logging，不炸整体。"""
        try:
            for m in _NATIVE_ASCII_RE.finditer(chunk):
                ascii_run = m.group().decode("ascii", errors="ignore")
                if not ascii_run:
                    continue
                self._scan_text(ascii_run, "native", location, collector, rules)
        except Exception:
            logger.exception("[%s] 解析 native 文件失败，跳过：%s", self.name, location)

    # ------------------------------------------------------------------
    # 文本 → 端点
    # ------------------------------------------------------------------

    def _scan_text(
        self,
        text: str,
        source: str,
        location: str,
        collector: EndpointCollector,
        rules: _Rules,
    ) -> None:
        """在一段文本里抽 URL / 域名 / IP，命中加入 collector。"""
        # 1) URL（最具体，先抽）。记录已被 URL 覆盖的区间，避免域名/IP 重复抽。
        consumed: list[tuple[int, int]] = []
        for m in _URL_RE.finditer(text):
            raw = m.group()
            cleaned = _strip_url_tail(raw)
            if not cleaned:
                continue
            host = _host_from_url(cleaned)
            if not host:
                continue
            # 跳过 host 明显无效的 URL（http://%s、http://config 这类格式串/代码片段）。
            if not _valid_url_host(host):
                continue
            if self._is_noise(cleaned, host, rules):
                continue
            consumed.append((m.start(), m.start() + len(cleaned)))
            # 明文 scheme：http / ws / mqtt（对应加密的 https / wss / mqtts）。
            is_cleartext = cleaned.lower().startswith(("http://", "ws://", "mqtt://"))
            is_private = _host_is_private(host)
            collector.add(
                cleaned,
                "url",
                Evidence(source=source, location=location, snippet=_truncate(raw, rules.snippet_max)),
                is_cleartext=is_cleartext,
                is_private=is_private,
            )
            # ★ 同时把 URL 的 host 作为独立 domain/ip 端点产出。否则 URL 里的域名/IP
            #   永远拿不到 ICP/WHOIS/ASN 富化与归属 Lead（富化器只作用于 domain/ip）。
            host_snippet = _truncate(raw, rules.snippet_max)
            host_ip = _parse_ipv4(host)
            if host_ip is not None:
                collector.add(
                    host,
                    "ip",
                    Evidence(source=source, location=location, snippet=host_snippet),
                    is_private=_ip_is_private(host_ip),
                )
            elif _looks_like_domain(host) and _url_host_tld_ok(host):
                collector.add(
                    host,
                    "domain",
                    Evidence(source=source, location=location, snippet=host_snippet),
                )
                collector.mark_tier(host, infra.domain_source_tier(location, len(text)))

        # consumed 已按 URL 匹配顺序（start 升序、互不重叠）追加 → 用 bisect O(log n) 判定，
        # 不再对每个 IP/域名候选线性扫全部区间（密集样本上省下 O(URL×候选)）。
        # 2) IPv4（带可选端口）。
        for m in _IPV4_RE.finditer(text):
            if _pos_in_consumed(consumed, m.start()):
                continue
            ip_str = m.group(1)
            ip_obj = _parse_ipv4(ip_str)
            if ip_obj is None:
                continue
            # 裸 IP 去噪（C4）：首段/末段为 0、bogon/保留段（私网/回环/链路本地/保留/
            #   多播）、或公认占位/版本号 denylist（noise_ips：1.2.3.4 / 13.3.3.7 等）。
            #   URL 内的 IP 走上面 host 通道，不受此限。
            if ip_str in rules.noise_ips or _is_noise_bare_ip(ip_str):
                continue
            collector.add(
                ip_str,
                "ip",
                Evidence(source=source, location=location, snippet=_truncate(m.group(), rules.snippet_max)),
                is_private=_ip_is_private(ip_obj),
            )

        # 3) 裸域名。
        for m in _DOMAIN_RE.finditer(text):
            if _pos_in_consumed(consumed, m.start()):
                continue
            raw_domain = m.group(1).rstrip(".")
            if not _looks_like_domain(raw_domain):
                continue
            domain = raw_domain.lower()
            # 裸域名走严格白名单（剔除与 JS 撞车的 TLD/代码词），把混合应用的海量误报压住。
            if not _is_strict_bare_domain(domain):
                continue
            if self._is_noise(domain, domain, rules):
                continue
            collector.add(
                domain,
                "domain",
                Evidence(source=source, location=location, snippet=_truncate(m.group(), rules.snippet_max)),
            )
            collector.mark_tier(domain, infra.domain_source_tier(location, len(text)))

    # ------------------------------------------------------------------
    # 噪音过滤
    # ------------------------------------------------------------------

    def _is_noise(self, full: str, host: str, rules: _Rules) -> bool:
        low_full = full.lower()
        for sub in rules.noise_substrings:
            if sub.lower() in low_full:
                return True
        host = host.lower().rstrip(".")
        for nh in rules.noise_hosts:
            if host == nh or host.endswith("." + nh):
                return True
        return False

    # ------------------------------------------------------------------
    # 采集 / IO 辅助
    # ------------------------------------------------------------------

    def _collect_so_paths(self, ctx: "AnalysisContext") -> list[str]:
        """native_libs() + list_files() 中所有 .so（去重，保序）。"""
        seen: set[str] = set()
        out: list[str] = []
        for getter in (ctx.native_libs, ctx.list_files):
            try:
                items = list(getter())
            except Exception:
                logger.exception("[%s] 采集 .so 路径失败（%s）", self.name, getter.__name__)
                continue
            for p in items:
                if not isinstance(p, str):
                    continue
                if p.lower().endswith(".so") and p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    def _is_resource_target(self, path: str, rules: _Rules) -> bool:
        low = path.replace("\\", "/").lower()
        if low.endswith(".so"):
            return False  # native 走单独通道
        ext = posixpath.splitext(low)[1]
        if ext in rules.resource_exts:
            return True
        for d in rules.resource_dirs:
            if low.startswith(d.lower()):
                # 目录命中但属二进制类扩展（图片/字体/媒体/压缩等）→ 跳过文本扫描。
                if ext in _BINARY_EXTS and ext not in rules.resource_exts:
                    return False
                return True
        return False

    def _safe_read(self, ctx: "AnalysisContext", path: str) -> bytes | None:
        """读单个资源/native 文件为完整 bytes（**不截断**）。失败/非 bytes → None（不抛）。

        改前对 >8MB 文件截断到前 8MB 并 WARNING——反诈调证最忌漏端点/漏真 C2，大文件后段的
        端点直接丢、且 WARNING 吓新手。现改为返回完整 bytes，由 :meth:`_scan_bytes_chunked` /
        :meth:`_scan_native_bytes_chunked` 分块扫完整个文件（内存可控、不漏端点）。
        """
        try:
            data = ctx.read_file(path)
        except Exception:
            logger.exception("[%s] 读取文件失败，跳过：%s", self.name, path)
            return None
        if data is None:
            return None
        if not isinstance(data, (bytes, bytearray)):
            logger.warning("[%s] read_file 返回非 bytes，跳过：%s", self.name, path)
            return None
        return bytes(data)  # 不再截断：完整返回，扫描侧分块处理大文件

    @staticmethod
    def _decode_latin1(data: bytes) -> str:
        try:
            return data.decode("latin-1", errors="ignore")
        except Exception:  # latin-1 几乎不会抛，仅防御
            logger.exception("latin-1 解码失败")
            return ""

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> _Rules:
        data = load_rules(_RULES_NAME)

        noise_hosts: list[str] = list(_FALLBACK_NOISE_HOSTS)
        noise_subs: list[str] = list(_FALLBACK_NOISE_SUBSTRINGS)
        res_exts: list[str] = list(_FALLBACK_RESOURCE_EXTS)
        res_dirs: list[str] = list(_FALLBACK_RESOURCE_DIRS)
        snippet_max = _DEFAULT_SNIPPET_MAX
        noise_ips: list[str] = list(_FALLBACK_NOISE_IPS)

        if isinstance(data, dict):
            hosts = _as_str_list(data.get("noise_hosts"))
            if hosts:
                noise_hosts = hosts
            subs = _as_str_list(data.get("noise_substrings"))
            if subs:
                noise_subs = subs
            exts = _as_str_list(data.get("resource_extensions"))
            if exts:
                res_exts = [e if e.startswith(".") else "." + e for e in exts]
            dirs = _as_str_list(data.get("resource_dirs"))
            if dirs:
                res_dirs = [d if d.endswith("/") else d + "/" for d in dirs]
            ms = data.get("max_string_len")
            if isinstance(ms, int) and ms > 0:
                snippet_max = ms
            nips = _as_str_list(data.get("noise_ips"))
            if nips:
                noise_ips = nips
        else:
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；使用内置兜底",
                self.name,
                type(data).__name__,
            )

        return _Rules(
            noise_hosts=frozenset(h.lower().rstrip(".") for h in noise_hosts),
            noise_substrings=tuple(noise_subs),
            resource_exts=tuple(e.lower() for e in res_exts),
            resource_dirs=tuple(d.lower() for d in res_dirs),
            snippet_max=snippet_max,
            noise_ips=frozenset(ip.strip() for ip in noise_ips),
        )


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _is_strict_bare_domain(domain: str) -> bool:
    """裸域名的严格判定（在 _looks_like_domain 之上再收紧）。

    规则：末段属安全 TLD 白名单 + SLD(末段前一段)≥2 字符且非常见代码词 +
    首段不是反向包名根（com./cn./io. 等）。专治 JS 混合应用里 a.id / rect.top /
    f32.store / console.info 这类点分代码被误判为域名。
    """
    labels = domain.lower().split(".")
    if len(labels) < 2:
        return False
    if labels[-1] not in _SAFE_BARE_TLDS:
        return False
    sld = labels[-2]
    if len(sld) < 2 or sld in _CODE_WORDS:
        return False
    if labels[0] in _PACKAGE_ROOTS:
        return False
    return True


def _url_host_tld_ok(host: str) -> bool:
    """URL 派生 host 是否有**可信的 TLD**——专治 .so 里被截断的 URL 残片。

    ★实测理由（2026-07-26 两案）：native ASCII 串被按块切分时，``http://www.<词>...`` 会在中途断掉，
    留下 ``http://www.hortcut`` / ``http://www.years`` / ``http://www.wencodeuricomponent`` 这种残片。
    裸域名通道有 :func:`_is_strict_bare_domain` 的 TLD 白名单挡着，**URL 通道却没有**，于是
    ``http://www.任意小写词`` 都能派生出一个"域名端点"，还带着 tier=app 被判"建议调证"，直接污染调证清单。

    判据用 ``_COMMON_TLDS``（61 条，含 top/cc/info/me/online/xyz 等真 C2 常用 TLD）而**不用**更窄的
    ``_SAFE_BARE_TLDS``（35 条，缺 top/cc/info）——后者会把真 C2 误杀，与"宁可漏、不可造"里更该守的
    "不可误杀真线索"冲突。多段 host 只看末段。
    """
    labels = host.lower().rsplit(".", 1)
    return len(labels) == 2 and labels[-1] in _COMMON_TLDS


def _looks_like_domain(domain: str) -> bool:
    """判定一个点分串是否像真实域名（而非文件名/类名/包名）。

    入参为原始大小写（用于识别 CamelCase 类名）。排除：
    - 文件名.扩展名（config.json / icon.png）
    - 纯数字 TLD
    - Java/Kotlin 全限定类名（末段 CamelCase，如 ...api.JPushInterface）
    - 反向域名包名（首段为 com/cn/org/net/io/android/androidx 且末段非合法 TLD）
    """
    if "." not in domain:
        return False

    labels = domain.split(".")
    last = labels[-1]
    last_low = last.lower()

    if last_low in _FILE_EXT_TLDS:
        return False
    if last.isdigit():
        return False
    if len(last) < 2:
        return False
    # 真实 TLD 全字母且全小写；末段含大写（CamelCase 类名）→ 非域名。
    if not last.isalpha():
        return False
    if any(ch.isupper() for ch in last):
        return False
    # 末段不是已知/常见 TLD 形态时，进一步排除明显的反向包名（首段是包名根）。
    if last_low not in _COMMON_TLDS:
        first = labels[0].lower()
        if first in _PACKAGE_ROOTS:
            return False
        # 任意一段以大写开头（典型类名/标识符）→ 非域名。
        if any(lbl[:1].isupper() for lbl in labels):
            return False
    return True
