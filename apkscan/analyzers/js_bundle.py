"""js_bundle 分析器：从打包 JS（uni-app / H5 / Cordova / RN）的**字符串字面量内部**
精确提取真实网络端点与硬编码密钥。

为什么单独做一个 JS 分析器（与 endpoints 互补，不重复）：
  压缩 / 混淆后的 bundle 里，`a.length` / `rect.top` / `f32.store` / `console.info`
  这类点分代码会被裸域名正则大量误判为域名。本分析器只在**字符串字面量**
  （单引号 / 双引号 / 反引号包裹）内部抽取，字面量里出现的点分串绝大多数是真域名
  / API 路径，从而把混合应用的误报压到可用水平。

职责（见任务）:
  - 框架识别 → meta['js_framework']：
      uni-app  : io.dcloud / assets/apps/*/www/app-service.js / *.wgt / manifest.json 含 uni
      Cordova  : assets/www/cordova.js
      RN       : assets/index.android.bundle
      generic  : 上述都不命中但存在 assets/www 下的 JS/HTML
  - 收集 assets/www 下 .js/.html/.json + index.android.bundle（单文件 <=8MB、文件数 <=3000）。
  - 在每个文件里：先抽出全部字符串字面量，**只在字面量内部**匹配：
      完整 URL（https?://...）、host（域名 / IPv4）、相对 API 路径（/api...）。
      字面量内 TLD 可放宽（里面的多为真域名），但排除文件名 / 命名空间噪音。
  - 硬编码密钥（字面量 / 键值上下文）：
      appid / appkey / secret / access_key / AES key(16/24/32) / JWT / -----BEGIN
      → Finding（secret 类 HIGH；appid / appkey MEDIUM）。
  - 产 Endpoint(kind=url|domain|ip, evidences=[Evidence(source="js", location=文件)])；
    只产端点（域名 / IP 的 Lead 由 pipeline build_endpoint_leads 统一建）。密钥产 Finding。
  - meta：js_framework / js_files_scanned / js_endpoint_count（+ 细分计数）。

约束:
  - 只依赖 AnalysisContext 公开接口（list_files / read_file），禁止 import androguard。
  - 借鉴 endpoints.py 的正则思路，自实现轻量版，不 import 其私有函数。
  - 逐文件 try/except + logging，不让单个文件炸掉整个 analyze；不静默 pass。
  - 规则可选经 registry.load_rules("js_bundle") 覆盖噪音/扩展，缺失用内置兜底。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.core import infra
from apkscan.core.models import (
    AnalyzerResult,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.secrets import (
    SecretRules,
    is_sdk_constant,
    load_secret_rules,
    looks_like_secret_value as _looks_like_secret_value,
)
from apkscan.analyzers._common import EndpointCollector
from apkscan.core.textutil import as_str_list as _as_str_list
from apkscan.core.textutil import host_from_url as _host_from_url
from apkscan.core.textutil import host_is_private as _host_is_private
from apkscan.core.textutil import ip_is_private as _ip_is_private
from apkscan.core.textutil import is_noise_bare_ip as _is_noise_bare_ip
from apkscan.core.textutil import looks_keyish as _looks_keyish
from apkscan.core.textutil import parse_ipv4 as _parse_ipv4
from apkscan.core.textutil import strip_url_tail as _strip_url_tail
from apkscan.core.textutil import truncate as _short
from apkscan.core.textutil import valid_url_host as _valid_url_host

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "js_bundle"

# 单文件读取上限（字节）。RN bundle / app-service.js 可能数 MB，超过只扫前段。
_MAX_FILE_BYTES = 8 * 1024 * 1024

# 参与扫描的文件数上限，防止资源极多的样本拖垮。
_MAX_FILES = 3000

# snippet 截断长度（规则可覆盖）。
_DEFAULT_SNIPPET_MAX = 200

# 单字符串字面量的最大长度：超长字面量多为内联 base64 / 数据块，跳过端点抽取
# （避免在巨型 data: URI / 内联资源里浪费时间，密钥扫描另走 base64/jwt 通道）。
_MAX_LITERAL_LEN = 4096

# ---------------------------------------------------------------------------
# 框架识别标记
# ---------------------------------------------------------------------------

FRAMEWORK_UNIAPP = "uni-app"
FRAMEWORK_CORDOVA = "Cordova"
FRAMEWORK_RN = "React Native"
FRAMEWORK_GENERIC = "H5"
FRAMEWORK_UNKNOWN = "unknown"

_RN_BUNDLE_NAME = "index.android.bundle"
_CORDOVA_MARKER = "assets/www/cordova.js"

# ---------------------------------------------------------------------------
# 正则
# ---------------------------------------------------------------------------

# 字符串字面量：'...'（无换行）/ "..."（无换行）/ `...`（反引号，可跨行）。
# 不严格处理转义（混淆 JS 里转义极少且不影响端点抽取），只为框出"引号内文本"。
_STRING_LITERAL_RE = re.compile(
    r"""
    '([^'\\\n]*(?:\\.[^'\\\n]*)*)'      # 单引号
    | "([^"\\\n]*(?:\\.[^"\\\n]*)*)"    # 双引号
    | `([^`\\]*(?:\\.[^`\\]*)*)`        # 反引号（可跨行）
    """,
    re.VERBOSE,
)

# 完整 URL（http/https）。host 到首个空白 / 引号 / 反引号 / 括号 / 反斜杠等终止。
_URL_RE = re.compile(
    r"""https?://[^\s"'`<>()\[\]{}\\^|,;]+""",
    re.IGNORECASE,
)

# IPv4（可选端口），后续用 ipaddress 复核。
_IPV4_RE = re.compile(
    r"""(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\w.])"""
)

# 裸域名 / host：label.label(.label)*，TLD 2+ 字母。字面量内可放宽 TLD。
_DOMAIN_RE = re.compile(
    r"""(?<![\w@./-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w.-])"""
)

# 相对 API 路径：以 / 开头，至少两段（/api/... /v1/... /user/login 等），
# 避免把 "/" "/static" 这类单段或资源路径全抓进来——要求含 api/接口风格关键字
# 或形如 /xxx/yyy 的多段路径。
_API_PATH_RE = re.compile(
    r"""(?<![\w.])(/(?:api|app|v\d+|gateway|service|interface|open|mobile|client|user|auth|pay|order|account|member|sys|admin|h5|wap)
        (?:/[A-Za-z0-9_\-.~%]+)*)""",
    re.VERBOSE | re.IGNORECASE,
)

# 硬编码密钥：键值上下文（key : "value" / key = "value" / "key":"value"）。
# value 取引号内或裸 token。
_SECRET_KV_RE = re.compile(
    r"""
    ["']?(?P<key>[A-Za-z_][A-Za-z0-9_]*)["']?        # 键名
    \s*[:=]\s*
    ["'](?P<val>[^"'\n]{6,512})["']                   # 引号内的值
    """,
    re.VERBOSE,
)

# JWT：三段 base64url，用 . 分隔，首段以 eyJ 开头（{"alg" 的 base64url）。
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# PEM 块头。
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*?(?:PRIVATE KEY|RSA|CERTIFICATE|KEY)[A-Z0-9 ]*?-----")

# 文件扩展名 TLD：把 "config.json" / "app.vue" 误判为域名时排除。
_FILE_EXT_TLDS: frozenset[str] = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico",
        "json", "xml", "html", "htm", "css", "js", "ts", "vue", "jsx",
        "tsx", "java", "kt", "so", "dex", "class", "jar", "aar", "wxss",
        "wxml", "txt", "md", "properties", "cfg", "conf", "ini", "yml",
        "yaml", "ttf", "otf", "woff", "woff2", "mp3", "mp4", "wav", "ogg",
        "webm", "pdf", "zip", "gz", "apk", "db", "dat", "bin", "map",
        "scss", "less", "wgt",
    }
)

# 命名空间 / 框架噪音 host（字面量里仍可能出现 schema/库官网，过滤掉）。
_FALLBACK_NOISE_HOSTS: tuple[str, ...] = (
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "ns.adobe.com",
    "java.sun.com",
    "xmlpull.org",
    "apache.org",
    "www.apache.org",
    "github.com",
    "github.io",
    "raw.githubusercontent.com",
    "developer.android.com",
    "developer.mozilla.org",
    "developer.apple.com",
    "registry.npmjs.org",
    "npmjs.com",
    "unpkg.com",
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    "vuejs.org",
    "reactjs.org",
    "facebook.github.io",
    "uniapp.dcloud.io",
    "uniapp.dcloud.net.cn",
    "ask.dcloud.net.cn",
    "localhost",
    "example.com",
    "www.example.com",
    "tools.ietf.org",
    "rfc-editor.org",
)
_FALLBACK_NOISE_SUBSTRINGS: tuple[str, ...] = (
    "schemas.android.com/apk",
    "/2000/svg",
    "/2001/XMLSchema",
    "/1999/xhtml",
    "/1999/xlink",
    "www.w3.org/",
    "ns.adobe.com/",
)

# 作为 SLD（TLD 前一段）出现时几乎一定是代码而非域名的常见词。
# 字面量内的撞车面比 dex 小，但 "object.prototype" / "window.location" 这类
# 字符串模板仍会混进来，保留一道兜底。
_CODE_WORDS: frozenset[str] = frozenset(
    {
        "this", "self", "window", "document", "arguments", "console",
        "prototype", "exports", "module", "navigator", "location",
        "process", "global", "undefined", "function", "object", "array",
        "string", "number", "boolean", "math", "json", "promise",
        "style", "path", "value", "length", "target", "event", "state",
        "props", "data", "config", "options", "params", "context",
    }
)

# 裸域名"安全 TLD 白名单"：字面量内的裸点分串只有末段属此集合才认域名。
# 刻意剔除与 JS 代码 / 数据撞车的伪 TLD（value/abs/opacity/style/path/length…
# 以及股票后缀 sh/sz、和易与属性撞车的 top/to/me/id/in 等）——这些真域名仍可经
# 字面量里的完整 URL（http(s)://）的 host 通道抽到。与 endpoints 分析器保持一致口径。
_SAFE_BARE_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "biz", "io", "co",
        "xyz", "vip", "club", "shop", "site", "app", "tech", "cloud",
        "fun", "ltd", "pro", "wang", "ren", "mobi", "asia", "icu",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
    }
)

# 反向域名包名常见根段：裸域名首段命中即视为 Java/Kotlin 反向包名（非域名）。
_PACKAGE_ROOTS: frozenset[str] = frozenset(
    {
        "com", "cn", "org", "net", "io", "edu", "android", "androidx",
        "java", "javax", "kotlin", "kotlinx", "dalvik", "uts", "uni", "vue",
    }
)

# 密钥键名提示（小写匹配）。命中即视为密钥候选键。
_DEFAULT_SECRET_KEY_HINTS: tuple[str, ...] = (
    "appid",
    "app_id",
    "appkey",
    "app_key",
    "appsecret",
    "app_secret",
    "secret",
    "secretkey",
    "secret_key",
    "access_key",
    "accesskey",
    "accesskeyid",
    "access_key_id",
    "accesskeysecret",
    "access_key_secret",
    "secretaccesskey",
    "secret_access_key",
    "apikey",
    "api_key",
    "aeskey",
    "aes_key",
    "privatekey",
    "private_key",
    "token",
    "client_secret",
    "clientsecret",
    "mch_key",
    "mchkey",
    "paykey",
    "pay_key",
    "signkey",
    "sign_key",
)

# 这些键名虽含 hint 子串但通常不是真正的密钥（降误报）。
_SECRET_KEY_DENY: frozenset[str] = frozenset(
    {
        "token_type",
        "tokentype",
        "tokenname",
        "token_name",
        "secretname",
        "apikeyname",
        "appidname",
        "keyboard",
        "keycode",
        "keydown",
        "keyup",
        "keypress",
        "keyword",
        "keywords",
    }
)

# 明显占位 / 示例值，不当作真实泄露。
_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "",
        "your_app_id",
        "your_appid",
        "yourappid",
        "your_app_key",
        "yourappkey",
        "your_secret",
        "yoursecret",
        "your_key",
        "xxxxxxxx",
        "xxxxxxxxxxxxxxxx",
        "000000000000000000000000",
        "test",
        "demo",
        "none",
        "null",
        "undefined",
        "true",
        "false",
    }
)

# AES key 的典型长度（去引号后的可见字符长度）。
_AES_KEY_LENGTHS: frozenset[int] = frozenset({16, 24, 32})

# 噪音 IP 兜底（C4：与 endpoints 同口径，公认占位/示例 + 版本号形态）。
_FALLBACK_NOISE_IPS: tuple[str, ...] = (
    "1.2.3.4", "0.0.0.0", "13.3.3.7", "2.1.5.1", "3.2.16.7",
)

# Finding id 常量（稳定，供报告 / 测试引用）。
FINDING_SECRET = "JS-HARDCODED-SECRET"
FINDING_APPID = "JS-HARDCODED-APPID"
FINDING_AES_KEY = "JS-HARDCODED-AES-KEY"
FINDING_JWT = "JS-HARDCODED-JWT"
FINDING_PEM = "JS-HARDCODED-PEM"


# ---------------------------------------------------------------------------
# 规则模型
# ---------------------------------------------------------------------------


@dataclass
class _Rules:
    """js_bundle 提取规则（从 YAML 规整，缺失用兜底）。"""

    noise_hosts: frozenset[str] = field(default_factory=frozenset)
    noise_substrings: tuple[str, ...] = ()
    secret_key_hints: tuple[str, ...] = ()
    snippet_max: int = _DEFAULT_SNIPPET_MAX
    noise_ips: frozenset[str] = field(default_factory=frozenset)
    secret_rules: SecretRules = field(default_factory=SecretRules)


@dataclass
class _SecretHit:
    """一处硬编码密钥命中（去重 + 聚合用）。"""

    finding_id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    location: str
    snippet: str


class JsBundleAnalyzer(BaseAnalyzer):
    """从打包 JS 的字符串字面量内部精确提取真实端点与硬编码密钥。"""

    name: str = "js_bundle"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        rules = self._load_rules()
        collector = EndpointCollector()

        try:
            all_files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:  # noqa: BLE001 — list_files 失败不应炸掉 analyze
            logger.exception("[%s] 读取 list_files 失败", self.name)
            all_files = []

        framework = self._detect_framework(ctx, all_files)
        targets = self._collect_targets(all_files)

        # 逐文件累积密钥命中（去重后再产 Finding）。
        secret_hits: dict[tuple[str, str], _SecretHit] = {}
        scanned = 0
        for path in targets:
            if scanned >= _MAX_FILES:
                logger.warning(
                    "[%s] JS 文件数超过上限 %d，截断扫描", self.name, _MAX_FILES
                )
                break
            text = self._read_text(ctx, path)
            if text is None:
                continue
            scanned += 1
            try:
                self._scan_file(text, path, collector, secret_hits, rules)
            except Exception:  # noqa: BLE001 — 单文件失败不影响其余
                logger.exception("[%s] 扫描 JS 文件失败，跳过：%s", self.name, path)

        endpoints = collector.endpoints({"url": 0, "domain": 1, "ip": 2, "path": 3})
        result.endpoints = endpoints
        result.findings = self._build_findings(secret_hits)

        kinds: dict[str, int] = {}
        for ep in endpoints:
            kinds[ep.kind] = kinds.get(ep.kind, 0) + 1
        result.meta.update(
            {
                "js_framework": framework,
                "js_files_scanned": scanned,
                "js_endpoint_count": len(endpoints),
                "js_url_count": kinds.get("url", 0),
                "js_domain_count": kinds.get("domain", 0),
                "js_ip_count": kinds.get("ip", 0),
                "js_path_count": kinds.get("path", 0),
                "js_secret_count": len(result.findings),
            }
        )
        logger.info(
            "[%s] framework=%s 扫描 %d 文件，端点 %d，密钥 Finding %d",
            self.name,
            framework,
            scanned,
            len(endpoints),
            len(result.findings),
        )
        return result

    # ------------------------------------------------------------------
    # 框架识别
    # ------------------------------------------------------------------

    def _detect_framework(self, ctx: "AnalysisContext", files: list[str]) -> str:
        """识别打包框架。优先级：uni-app > Cordova > RN > generic H5 > unknown。"""
        norm = [f.replace("\\", "/") for f in files]
        low = [f.lower() for f in norm]

        # uni-app：io.dcloud / assets/apps/*/www/app-service.js / *.wgt /
        #          manifest.json 含 uni。
        for f in low:
            if "io.dcloud" in f:
                return FRAMEWORK_UNIAPP
            if f.endswith(".wgt"):
                return FRAMEWORK_UNIAPP
            if f.startswith("assets/apps/") and f.endswith("/www/app-service.js"):
                return FRAMEWORK_UNIAPP
            if "/www/app-service.js" in f and "assets/apps/" in f:
                return FRAMEWORK_UNIAPP
        # manifest.json（uni-app 工程清单）含 uni 关键字。
        for path in norm:
            if posixpath.basename(path).lower() == "manifest.json" and (
                "/apps/" in path.lower() or path.lower().startswith("assets/")
            ):
                if self._manifest_looks_uniapp(ctx, path):
                    return FRAMEWORK_UNIAPP

        # Cordova：assets/www/cordova.js。
        for f in low:
            if f == _CORDOVA_MARKER or f.endswith("/www/cordova.js"):
                return FRAMEWORK_CORDOVA

        # React Native：assets/index.android.bundle。
        for f in low:
            if posixpath.basename(f) == _RN_BUNDLE_NAME:
                return FRAMEWORK_RN

        # 通用 H5：存在 assets/www 下的 JS / HTML。
        for f in low:
            if "/www/" in f and (f.endswith(".js") or f.endswith(".html") or f.endswith(".htm")):
                return FRAMEWORK_GENERIC
            if f.startswith("assets/") and (f.endswith(".js") or f.endswith(".html")):
                return FRAMEWORK_GENERIC

        return FRAMEWORK_UNKNOWN

    def _manifest_looks_uniapp(self, ctx: "AnalysisContext", path: str) -> bool:
        """读取 manifest.json 看是否含 uni-app 特征（uni / dcloud / __UNI__）。"""
        text = self._read_text(ctx, path)
        if not text:
            return False
        low = text.lower()
        return "__uni__" in low or "dcloud" in low or '"uni-app"' in low or "uniapp" in low

    # ------------------------------------------------------------------
    # 目标文件收集
    # ------------------------------------------------------------------

    def _collect_targets(self, files: list[str]) -> list[str]:
        """收集 assets/www 下 .js/.html/.json + index.android.bundle（保序去重）。"""
        seen: set[str] = set()
        out: list[str] = []
        for path in files:
            if path in seen:
                continue
            if self._is_target(path):
                seen.add(path)
                out.append(path)
        return out

    @staticmethod
    def _is_target(path: str) -> bool:
        low = path.replace("\\", "/").lower()
        base = posixpath.basename(low)
        if base == _RN_BUNDLE_NAME:
            return True
        # assets/ 或 www/ 路径下的 JS/HTML/JSON。
        in_scope = low.startswith("assets/") or "/www/" in low
        if not in_scope:
            return False
        return (
            low.endswith(".js")
            or low.endswith(".html")
            or low.endswith(".htm")
            or low.endswith(".json")
        )

    # ------------------------------------------------------------------
    # 单文件扫描
    # ------------------------------------------------------------------

    def _scan_file(
        self,
        text: str,
        path: str,
        collector: EndpointCollector,
        secret_hits: dict[tuple[str, str], _SecretHit],
        rules: _Rules,
    ) -> None:
        """在单文件里抽字符串字面量 → 端点；并扫硬编码密钥（键值 / JWT / PEM）。"""
        # 1) 端点：只在字符串字面量内部抽（避免 a.length / rect.top 误判）。
        for m in _STRING_LITERAL_RE.finditer(text):
            literal = m.group(1) or m.group(2) or m.group(3) or ""
            if not literal or len(literal) > _MAX_LITERAL_LEN:
                continue
            self._scan_literal(literal, path, collector, rules)

        # 2) 硬编码密钥：键值上下文（在全文上扫，键名约束已足够精确）。
        for m in _SECRET_KV_RE.finditer(text):
            self._consider_secret_kv(
                m.group("key"), m.group("val"), path, secret_hits, rules
            )

        # 3) JWT（全文）。
        for m in _JWT_RE.finditer(text):
            tok = m.group(0)
            key = (FINDING_JWT, _short(tok, 48))
            secret_hits.setdefault(
                key,
                _SecretHit(
                    finding_id=FINDING_JWT,
                    title="硬编码 JWT 令牌",
                    severity=Severity.HIGH,
                    category="secret",
                    description=(
                        "JS bundle 中出现硬编码 JWT（eyJ... 三段式）。JWT 常携带身份 / "
                        "权限声明，硬编码意味着可冒用该身份调用后端接口。"
                    ),
                    recommendation=(
                        "研判：解码 JWT 头/载荷确认签发方与权限范围；可据此调取后端鉴权日志，"
                        "或在取证侧复现受控调用以固定接口与资金流向。"
                    ),
                    location=path,
                    snippet=_short(tok, rules.snippet_max),
                ),
            )

        # 4) PEM 私钥 / 证书块（全文）。
        for m in _PEM_RE.finditer(text):
            head = m.group(0)
            key = (FINDING_PEM, head)
            secret_hits.setdefault(
                key,
                _SecretHit(
                    finding_id=FINDING_PEM,
                    title="硬编码 PEM 密钥 / 证书",
                    severity=Severity.HIGH,
                    category="secret",
                    description=(
                        "JS bundle 中出现 PEM 块（-----BEGIN ...-----）。内嵌私钥 / 证书"
                        "使加密 / 签名形同虚设，可在取证侧离线解密报文或伪造签名。"
                    ),
                    recommendation=(
                        "研判：提取完整 PEM 辨识为私钥 / 证书 / 公钥；若为私钥，可离线解密"
                        "对应密文通信，作为还原 C2 / 资金通道的关键证据。"
                    ),
                    location=path,
                    snippet=_short(head, rules.snippet_max),
                ),
            )

    def _scan_literal(
        self, literal: str, path: str, collector: EndpointCollector, rules: _Rules
    ) -> None:
        """在单个字符串字面量内部抽 URL / host / IP / 相对 API 路径。"""
        consumed: list[tuple[int, int]] = []

        # 1) 完整 URL（先抽，记录区间避免 host 重复抽）。
        for m in _URL_RE.finditer(literal):
            raw = m.group()
            cleaned = _strip_url_tail(raw)
            if not cleaned:
                continue
            host = _host_from_url(cleaned)
            if not host or not _valid_url_host(host):
                continue
            if self._is_noise(cleaned, host, rules):
                continue
            consumed.append((m.start(), m.start() + len(cleaned)))
            is_cleartext = cleaned.lower().startswith("http://")
            host_ip = _parse_ipv4(host)
            collector.add(
                cleaned,
                "url",
                Evidence(source="js", location=path, snippet=_short(raw, rules.snippet_max)),
                is_cleartext=is_cleartext,
                is_private=(host_ip is not None and _ip_is_private(host_ip)) or _host_is_private(host),
            )
            # 把 URL 的 host 作为独立 domain/ip 端点产出（富化器只作用于 domain/ip）。
            host_snippet = _short(raw, rules.snippet_max)
            if host_ip is not None:
                collector.add(
                    host,
                    "ip",
                    Evidence(source="js", location=path, snippet=host_snippet),
                    is_private=_ip_is_private(host_ip),
                )
            elif _looks_like_domain(host):
                collector.add(
                    host,
                    "domain",
                    Evidence(source="js", location=path, snippet=host_snippet),
                )
                collector.mark_tier(host, infra.domain_source_tier(path, len(literal)))

        def _in_consumed(pos: int) -> bool:
            return any(start <= pos < end for start, end in consumed)

        # 2) IPv4（裸，可选端口）。
        for m in _IPV4_RE.finditer(literal):
            if _in_consumed(m.start()):
                continue
            ip_str = m.group(1)
            ip_obj = _parse_ipv4(ip_str)
            if ip_obj is None:
                continue
            # C4：裸 IP 去噪——bogon/保留段（is_noise_bare_ip）或占位/版本号 denylist。
            if ip_str in rules.noise_ips or _is_noise_bare_ip(ip_str):
                continue
            collector.add(
                ip_str,
                "ip",
                Evidence(source="js", location=path, snippet=_short(m.group(), rules.snippet_max)),
                is_private=_ip_is_private(ip_obj),
            )

        # 3) 裸域名 / host（字面量内放宽 TLD，但排除文件名 / 命名空间 / 代码词）。
        for m in _DOMAIN_RE.finditer(literal):
            if _in_consumed(m.start()):
                continue
            raw_domain = m.group(1).rstrip(".")
            domain = raw_domain.lower()
            if not _looks_like_domain(raw_domain):
                continue
            if not _is_literal_domain(domain):
                continue
            if self._is_noise(domain, domain, rules):
                continue
            collector.add(
                domain,
                "domain",
                Evidence(source="js", location=path, snippet=_short(m.group(), rules.snippet_max)),
            )
            collector.mark_tier(domain, infra.domain_source_tier(path, len(literal)))

        # 4) 相对 API 路径（/api/... /v1/... 等）。
        for m in _API_PATH_RE.finditer(literal):
            if _in_consumed(m.start()):
                continue
            apath = m.group(1)
            # 去掉明显是文件名结尾的（/a/b.js）——这些是静态资源不是接口。
            tail = posixpath.basename(apath)
            if "." in tail and tail.rsplit(".", 1)[-1].lower() in _FILE_EXT_TLDS:
                continue
            collector.add(
                apath,
                "path",
                Evidence(source="js", location=path, snippet=_short(apath, rules.snippet_max)),
            )

    # ------------------------------------------------------------------
    # 硬编码密钥（键值上下文）
    # ------------------------------------------------------------------

    def _consider_secret_kv(
        self,
        key: str,
        value: str,
        path: str,
        secret_hits: dict[tuple[str, str], _SecretHit],
        rules: _Rules,
    ) -> None:
        """判断 key=value 是否为硬编码密钥；命中按类型归 Finding（去重）。"""
        key_low = key.lower()
        if key_low in _SECRET_KEY_DENY:
            return
        hint = next((h for h in rules.secret_key_hints if h in key_low), None)
        if hint is None:
            return
        val = value.strip()
        # C2：value==key / 已知 SDK 常量名 / 常量值 → 非真凭据，drop（杀 SDK 常量名误报）。
        if is_sdk_constant(key, val, rules.secret_rules):
            return
        if not _is_real_secret_value(val):
            return

        # 分类：appid/appkey → MEDIUM；secret/access_key/token/private_key 等 → HIGH。
        is_secretish = any(
            tok in key_low
            for tok in ("secret", "access_key", "accesskey", "privatekey", "private_key", "token", "apikey", "api_key")
        )
        is_appid = ("appid" in key_low or "app_id" in key_low or "appkey" in key_low or "app_key" in key_low)

        # AES key（去引号后长度 16/24/32 且像 key）。appid/appkey 是账号标识而非
        # 对称密钥，即便长度恰好 16/24/32 也优先按 AppID 归类，不走 AES 分支。
        if (
            not is_appid
            and len(val) in _AES_KEY_LENGTHS
            and _looks_keyish(val)
            and not val.isdigit()
        ):
            finding_id = FINDING_AES_KEY
            title = "疑似硬编码 AES 密钥"
            severity = Severity.HIGH
            description = (
                f"JS bundle 中键 '{key}' 的值为 {len(val)} 字符常量，符合 AES-"
                f"{len(val) * 8} 密钥长度且呈密钥形态，疑似硬编码对称密钥。"
            )
            recommendation = (
                "研判：人工确认该常量用于 AES 加解密；若是，则取证侧可离线解密 App "
                "加密的本地隐私数据与回传报文。"
            )
        elif is_secretish:
            finding_id = FINDING_SECRET
            title = "硬编码密钥 / 凭证"
            severity = Severity.HIGH
            description = (
                f"JS bundle 中出现硬编码凭证：键 '{key}' 配置了明文 secret / "
                f"access_key / token。可被直接用于冒充该应用访问后端 / 第三方服务。"
            )
            recommendation = (
                "研判：核实该凭证对应的服务（支付 / 云存储 / 推送 / 短信等），据此向"
                "服务厂商调取调用记录与绑定主体，关联资金 / 通信证据。"
            )
        elif is_appid:
            finding_id = FINDING_APPID
            title = "硬编码 AppID / AppKey"
            severity = Severity.MEDIUM
            description = (
                f"JS bundle 中出现硬编码 AppID / AppKey：键 '{key}'。可据此识别"
                "第三方服务（支付 / 推送 / 地图 / 统计等）的接入账号。"
            )
            recommendation = (
                "研判：以该 AppID / AppKey 向对应第三方平台调取注册主体与调用记录，"
                "用于锁定运营方身份。"
            )
        else:
            # 命中 hint 但既非 secret 又非 appid（如裸 "key"）——保守归 secret/HIGH。
            finding_id = FINDING_SECRET
            title = "硬编码密钥 / 凭证"
            severity = Severity.HIGH
            description = (
                f"JS bundle 中键 '{key}' 配置了疑似密钥常量。"
            )
            recommendation = (
                "研判：人工确认该常量用途；若为凭证可据此调取对应服务记录。"
            )

        snippet = _short(f"{key}={val}", rules.snippet_max)
        dedup = (finding_id, f"{path}:{key_low}:{_short(val, 64)}")
        secret_hits.setdefault(
            dedup,
            _SecretHit(
                finding_id=finding_id,
                title=title,
                severity=severity,
                category="secret",
                description=description,
                recommendation=recommendation,
                location=path,
                snippet=snippet,
            ),
        )

    # ------------------------------------------------------------------
    # Finding 组装
    # ------------------------------------------------------------------

    def _build_findings(
        self, secret_hits: dict[tuple[str, str], _SecretHit]
    ) -> list[Finding]:
        """把去重后的密钥命中聚合为 Finding（同 finding_id 合并 evidences）。"""
        by_id: dict[str, Finding] = {}
        # 稳定顺序：按 (finding_id, location, snippet)。
        for hit in sorted(
            secret_hits.values(),
            key=lambda h: (h.finding_id, h.location, h.snippet),
        ):
            finding = by_id.get(hit.finding_id)
            ev = Evidence(source="js", location=hit.location, snippet=hit.snippet)
            if finding is None:
                by_id[hit.finding_id] = Finding(
                    id=hit.finding_id,
                    title=hit.title,
                    severity=hit.severity,
                    category=hit.category,
                    description=hit.description,
                    recommendation=hit.recommendation,
                    evidences=[ev],
                    references=["CWE-798", "CWE-312"],
                )
            else:
                finding.evidences.append(ev)
        # 输出顺序按 severity 降序再按 id，便于报告/测试稳定。
        sev_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(
            by_id.values(), key=lambda f: (sev_order.get(f.severity, 9), f.id)
        )

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
    # IO 辅助
    # ------------------------------------------------------------------

    def _read_text(self, ctx: "AnalysisContext", path: str) -> str | None:
        """read_file + utf-8 容错解码；失败 / 空返回 None，记日志不抛。"""
        try:
            raw = ctx.read_file(path)
        except Exception:  # noqa: BLE001 — 单文件读取失败不影响其余
            logger.exception("[%s] 读取文件失败，跳过：%s", self.name, path)
            return None
        if raw is None:
            return None
        if not isinstance(raw, (bytes, bytearray)):
            logger.warning("[%s] read_file 返回非 bytes，跳过：%s", self.name, path)
            return None
        if not raw:
            return None
        if len(raw) > _MAX_FILE_BYTES:
            logger.warning(
                "[%s] 文件超过上限 %d 字节，仅扫前段：%s", self.name, _MAX_FILE_BYTES, path
            )
            raw = bytes(raw[:_MAX_FILE_BYTES])
        try:
            return bytes(raw).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001 — utf-8 errors=ignore 几乎不抛，仅防御
            logger.exception("[%s] utf-8 解码失败，跳过：%s", self.name, path)
            return None

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> _Rules:
        data = load_rules(_RULES_NAME)

        noise_hosts: list[str] = list(_FALLBACK_NOISE_HOSTS)
        noise_subs: list[str] = list(_FALLBACK_NOISE_SUBSTRINGS)
        secret_hints: list[str] = list(_DEFAULT_SECRET_KEY_HINTS)
        snippet_max = _DEFAULT_SNIPPET_MAX

        if isinstance(data, dict):
            hosts = _as_str_list(data.get("noise_hosts"))
            if hosts:
                noise_hosts = hosts
            subs = _as_str_list(data.get("noise_substrings"))
            if subs:
                noise_subs = subs
            hints = _as_str_list(data.get("secret_key_hints"))
            if hints:
                secret_hints = hints
            ms = data.get("max_string_len")
            if isinstance(ms, int) and ms > 0:
                snippet_max = ms
        elif data:
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；使用内置兜底",
                self.name,
                type(data).__name__,
            )

        return _Rules(
            noise_hosts=frozenset(h.lower().rstrip(".") for h in noise_hosts),
            noise_substrings=tuple(noise_subs),
            secret_key_hints=tuple(h.lower() for h in secret_hints),
            snippet_max=snippet_max,
            noise_ips=_load_noise_ips(),
            secret_rules=load_secret_rules(),
        )


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _load_noise_ips() -> frozenset[str]:
    """从 endpoints.yaml 读 noise_ips（C4 单一数据源；缺失走内置兜底）。"""
    try:
        data = load_rules("endpoints")
    except Exception:  # noqa: BLE001 — 规则读取失败不应炸掉 analyze
        logger.exception("[js_bundle] 读取 endpoints 规则（noise_ips）失败，用兜底")
        return frozenset(_FALLBACK_NOISE_IPS)
    if isinstance(data, dict):
        nips = _as_str_list(data.get("noise_ips"))
        if nips:
            return frozenset(ip.strip() for ip in nips)
    return frozenset(_FALLBACK_NOISE_IPS)


def _looks_like_domain(domain: str) -> bool:
    """判定点分串是否像真实域名（而非文件名 / 类名 / 包名）。

    入参为原始大小写。排除：文件名.扩展名、纯数字 TLD、末段含大写（CamelCase）。
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
    if not last.isalpha():
        return False
    if any(ch.isupper() for ch in last):
        return False
    return True


def _is_literal_domain(domain: str) -> bool:
    """字面量内裸域名的严格判定。

    教训：压缩 JS 的字面量里也大量出现 `a-i.value` / `1-math.abs` / `style.opacity`
    这类代码片段，以及 `000001.sh` 这类股票代码——若放宽 TLD 就会爆量误报。
    故裸域名必须:末段属安全 TLD 白名单 + SLD≥2 且非代码词 + 首段非反向包名根。
    真实的 .top/.sh 等域名仍可经字面量里的完整 URL(http(s)://) 的 host 抽到。
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


# 形态判定专用规则：长度/多样性门由本模块上游自查（len<8 / distinct<=2 已先 drop），
# 故 min_secret_len/min_distinct_chars 置 1，让共享 looks_like_secret_value 只负责
# keyish + 长纯字母混合熵的决策，与 jadx/config_keys 一致（min_alpha_secret_len 走默认 16）。
_SHAPE_RULES = SecretRules(min_secret_len=1, min_distinct_chars=1)


def _is_real_secret_value(val: str) -> bool:
    """密钥值是否像真实凭证（排除占位 / 过短 / 纯路径 / URL / 模板表达式 / 非凭据形态）。"""
    low = val.strip().lower()
    if low in _PLACEHOLDER_VALUES:
        return False
    if len(val) < 8:
        return False
    if len(set(val)) <= 2:  # "aaaaaaaa" / "00000000" 之类
        return False
    # 模板插值 / 路径 / URL 不是常量密钥。
    if any(ch in val for ch in "{}$<>") or val.startswith(("/", "http://", "https://", "./", "../")):
        return False
    if " " in val:  # 含空格多为句子/说明文本
        return False
    # C2：value 形态判定收敛到共享 looks_like_secret_value（与 jadx/config_keys 一致）：
    #   含数字+字母 / 纯 hex / 含 +/= → looks_keyish=True；此外评审 MEDIUM 修复——
    #   够长（默认≥16）且大小写混合的纯字母值也保留（不误杀纯字母真 secret），
    #   仅纯小写/纯大写或过短的非 keyish 值被 drop（deviceToken 等）。
    if not _looks_like_secret_value(val, _SHAPE_RULES):
        return False
    return True
