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

import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.core import infra
from apkscan.core.models import AnalyzerResult, Evidence
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
_MAX_DEX_STRINGS = 200_000

# 单个资源/native 文件读取上限（字节）。超过则只扫前段，防止超大文件拖垮。
_MAX_FILE_BYTES = 8 * 1024 * 1024

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

# URL：http/https，主机部分到首个空白/引号/反引号/尖括号/中文等终止。
_URL_RE = re.compile(
    r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""",
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


class EndpointsAnalyzer(BaseAnalyzer):
    """从 dex/resource/native/manifest 提取 URL/域名/IP 端点（只产 Endpoint）。"""

    name: str = "endpoints"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        rules = self._load_rules()
        collector = EndpointCollector()

        # 四路数据源各自 try/except，单源失败不影响其余。
        dex_ok = self._scan_dex(ctx, collector, rules)
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
        return result

    # ------------------------------------------------------------------
    # 数据源扫描
    # ------------------------------------------------------------------

    def _scan_dex(
        self, ctx: "AnalysisContext", collector: EndpointCollector, rules: _Rules
    ) -> bool:
        """扫 DEX 字符串池。返回是否成功遍历。"""
        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning(
                        "[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_DEX_STRINGS
                    )
                    break
                if not isinstance(s, str) or not s:
                    continue
                try:
                    self._scan_text(s, "dex", "dex_strings", collector, rules)
                except Exception:
                    logger.exception("[%s] 解析 DEX 字符串失败，跳过该条", self.name)
        except Exception:
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)
            return False
        return True

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
            text = self._decode_latin1(data)
            if not text:
                continue
            scanned += 1
            try:
                self._scan_text(text, "resource", path, collector, rules)
            except Exception:
                logger.exception("[%s] 解析资源文件失败，跳过：%s", self.name, path)
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
            try:
                for m in _NATIVE_ASCII_RE.finditer(data):
                    chunk = m.group().decode("ascii", errors="ignore")
                    if not chunk:
                        continue
                    self._scan_text(chunk, "native", path, collector, rules)
            except Exception:
                logger.exception("[%s] 解析 native 文件失败，跳过：%s", self.name, path)
        return scanned

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
            is_cleartext = cleaned.lower().startswith("http://")
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
            elif _looks_like_domain(host):
                collector.add(
                    host,
                    "domain",
                    Evidence(source=source, location=location, snippet=host_snippet),
                )
                collector.mark_tier(host, infra.domain_source_tier(location, len(text)))

        def _in_consumed(pos: int) -> bool:
            return any(start <= pos < end for start, end in consumed)

        # 2) IPv4（带可选端口）。
        for m in _IPV4_RE.finditer(text):
            if _in_consumed(m.start()):
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
            if _in_consumed(m.start()):
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
        if len(data) > _MAX_FILE_BYTES:
            logger.warning(
                "[%s] 文件超过上限 %d 字节，仅扫前段：%s", self.name, _MAX_FILE_BYTES, path
            )
            data = bytes(data[:_MAX_FILE_BYTES])
        return bytes(data)

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
