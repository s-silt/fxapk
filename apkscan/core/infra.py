"""已知正规基础设施分级（"对齐思知"特性的研判知识库）。

调证目标是 App 自有的、疑似涉诈的服务端 / 资金 / 联系方式归属；而对公有云、
主流第三方 SDK、开源 CDN、标准协议域名等"正规基础设施"本身调证没有意义
（命中只说明 App 用了某个通用服务，不指向涉案主体）。本模块把这类基础设施
集中成一份可维护的后缀/关键字清单，供 pipeline 给每条线索打"是否建议调证"。

设计铁律：
- 全部纯函数、无副作用、无 I/O、type hints；可被任意层安全调用。
- 命中判定基于"域名后缀或关键字子串"，宽进严出：宁可把可疑的判成"建议调证"，
  也不要把 App 自有服务误判成"无需调证"而漏掉调证目标。
"""

from __future__ import annotations

import ipaddress
import logging
from fnmatch import fnmatch

logger = logging.getLogger(__name__)

# 研判建议三态（与 Lead.advice 取值约定一致）。
ADVICE_INVESTIGATE = "建议调证"
ADVICE_SKIP = "无需调证"
ADVICE_REVIEW = "待核"

# 域名来源可信度档（写入 Endpoint.enrichment["tier"]，pipeline 据此降可信）。
TIER_APP = "app"                       # App 自有文件/普通字符串 —— 最可信。
TIER_LIBRARY_FILE = "library-file"     # 来源命中已知第三方库文件路径 —— 疑似库内置。
TIER_BULK_STRING = "bulk-string"       # 来源是超大字符串表 —— 疑似内置域名库噪音。

# tier 可信度排序（app 最优，bulk-string 最差）；dedup 合并时取最优。
_TIER_RANK: dict[str, int] = {TIER_APP: 0, TIER_LIBRARY_FILE: 1, TIER_BULK_STRING: 2}

# 已知正规基础设施：域名后缀 / 关键字集合（全小写）。命中任一 = 正规基础设施，
# 对其本身无需调证。新增第三方/云厂商/开源 CDN 只需往这里加一行。
#
# 判定用"子串包含"匹配域名（已小写、去端口），因此既可写完整后缀
# （如 "dcloud.net.cn"）也可写关键字（如 "getui"）。
KNOWN_INFRA: frozenset[str] = frozenset(
    {
        # ---- DCloud / uni-app（本样本 __UNI__ 打包框架）----
        "dcloud.net.cn",
        "dcloud.io",
        "m3w.cn",  # DCloud uni 短链（m3w.cn/s/...），样本实测误判建议调证

        # ---- 腾讯云 / 腾讯 ----
        "myqcloud.com",
        "qcloud",
        "tencent-cloud",
        "tencentcs.com",
        "qq.com",
        # ---- 阿里云 / 阿里 ----
        "aliyuncs.com",
        "alicdn.com",
        "aliyun",
        "alipayobjects.com",
        # ---- AWS ----
        "amazonaws.com",
        "awsstatic",
        "cloudfront.net",
        # ---- 个推 GeTui（本样本 GETUI_APPID / GTSDK）----
        "getui.com",
        "gepush.com",
        "getui.net",
        "igexin",
        "gtuid",
        # ---- 友盟 ----
        "umeng.com",
        "umengcloud",
        "umsns.com",
        # ---- 高德 ----
        "amap.com",
        "autonavi",
        # ---- 百度 ----
        "baidu.com",
        "bdstatic",
        "bcebos",
        # ---- Google ----
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "googleusercontent.com",
        "google-analytics.com",
        # ---- GitHub ----
        "github.com",
        "githubusercontent.com",
        "github.io",
        # ---- 开源 CDN / 包管理 ----
        "jsdelivr.net",
        "unpkg.com",
        "npmjs.com",
        "npmjs.org",
        "cdnjs",
        "bootcdn",
        # ---- 前端框架官网 ----
        "vuejs.org",
        "nodejs.org",
        "reactjs.org",
        "jquery.com",
        # ---- 标准 / 规范组织 ----
        "w3.org",
        "ietf.org",
        "whatwg.org",
        "schemas.android.com",
        "apache.org",
        # ---- 浏览器引擎 / 厂商 ----
        "mozilla.org",
        "webkit.org",
        "chromium.org",
        "crbug.com",
        # ---- 知识 / 问答 / 社区 ----
        "wikipedia.org",
        "stackoverflow.com",
        "csdn.net",
        # ---- 运营商一键登录 / 推送 / 监控 ----
        "cmpassport.com",
        "cnzz.com",
        "jpush.cn",
        "jpush.io",
        "jiguang.cn",
        "bugly.qq.com",
        "bugly.com",
        "mob.com",
        # ---- 常见前端库 / 工具官网（打包 JS 里高频出现，非涉案主体）----
        "core-js.io",
        "zloirock.ru",          # core-js 作者
        "tc39.es",
        "tc39.github.io",
        "feross.org",
        "flow.org",
        "quilljs.com",
        "gsap.com",
        "greensock.com",
        "tailwindcss.com",
        "lodash.com",
        "momentjs.com",
        "day.js.org",
        "axios-http.com",
        "echarts.apache.org",
        "d3js.org",
        "three.js.org",
        "swiperjs.com",
        "babeljs.io",
        "webpack.js.org",
        "rollupjs.org",
        "vitejs.dev",
        "eslint.org",
        "typescriptlang.org",
        "npmjs.org",
        "yarnpkg.com",
        "jquery.org",
        "datatables.net",
        "fontawesome.com",
        "materialdesignicons.com",
        "iconfont.cn",
        "at.alicdn.com",        # iconfont CDN
        # ---- 标准 / 开源 / 厂商文档 ----
        "openssl.org",
        "sourceforge.net",
        "sf.net",
        "gnu.org",
        "python.org",
        "oracle.com",
        "microsoft.com",
        "apple.com",
        "jetbrains.com",
        "android.com",
        "googlesource.com",
        "w3help.org",
        "w3schools.com",
        "mdn.mozilla.org",
        "caniuse.com",
        "unicode.org",
        "rfc-editor.org",
        "iana.org",
        # ---- 图床 / 素材 / 字体（演示资源，非涉案）----
        "pexels.com",
        "unsplash.com",
        "istockphoto.com",
        "icons8.com",
        "pixabay.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        # ---- 通用 SaaS / 客服 / 统计（SDK 基础设施本身无需调证）----
        "salesforce.com",
        "meiqia.com",
        "udesk.cn",
        "7moor.com",
        "sobot.com",
        "sensorsdata.cn",
        "talkingdata.com",
        "growingio.com",
        "umsns.com",
        "uyun.cn",
        # ---- DCloud / uni 生态补充 ----
        "myqcloud.com",
        "uniapp.dcloud.io",
        "uniapp.dcloud.net.cn",
        "qiniucdn.com",
        "qiniu.com",
        "qnssl.com",
        "upaiyun.com",
        "upcdn.net",
        # ---- Android 系统 / WebView 内部 ----
        "androidplatform.net",      # appassets.androidplatform.net（WebView 资源加载器）
        "android.googlesource.com",
        # ---- 运营商（号码认证 / 一键登录基础设施）----
        "10010.com",                # 中国联通
        "10086.cn",                 # 中国移动
        "10086.com",
        "189.cn",                   # 中国电信
        "mobileservice.cn",         # 移动认证服务
        "wostore.cn",
        "189store.com",
        # ---- 电商 / 通用 CDN ----
        "yzcdn.cn",                 # 有赞 CDN
        "youzan.com",
        "meituan.net",
        "dpfile.com",
        "360buyimg.com",
        "jddebug.com",
        "vipstatic.com",
    }
)

# 纯数字+交易所后缀的"伪域名"(股票/基金代码,如 600000.sh / 399006.sz)：
# 这类不是域名而是行情代码,直接判"待核"剔除出建议调证。
_STOCK_SUFFIXES: tuple[str, ...] = (".sh", ".sz", ".bj", ".hk")


# ---------------------------------------------------------------------------
# C1：library-embedded 分级 + 域名来源可信度档（数据放 rules/domain_tiers.yaml）
# ---------------------------------------------------------------------------

# library-embedded 兜底（规则缺失时仍兜最常见的知名站点噪音，离线/规则缺失不崩）。
_FALLBACK_LIBRARY_EMBEDDED: tuple[str, ...] = (
    "amazon.com", "ebay.com", "bbc.co.uk", "cnn.com", "nytimes.com",
    "wikipedia.org", "facebook.com", "twitter.com", "youtube.com",
    "chase.com", "paypal.com", "pornhub.com", "xvideos.com",
)
# library-file 路径 glob 兜底。
_FALLBACK_LIBRARY_FILE_GLOBS: tuple[str, ...] = (
    "*/uni_modules/*", "*/node_modules/*", "*/vendor/*", "*.min.js",
    "*/static/echarts*", "*echarts.min.js", "*/dist/*",
)
_FALLBACK_BULK_STRING_MIN_LEN = 2000


def _load_domain_tiers() -> tuple[tuple[str, ...], tuple[str, ...], int]:
    """加载 rules/domain_tiers.yaml，返回 (library_embedded_suffixes, library_file_globs,
    bulk_string_min_len)。任何缺失/异常走内置兜底（纯增量，不破坏离线）。

    用延迟导入 registry 避免 infra（被广泛依赖的纯函数模块）与 registry 形成导入环。
    """
    suffixes: tuple[str, ...] = _FALLBACK_LIBRARY_EMBEDDED
    globs: tuple[str, ...] = _FALLBACK_LIBRARY_FILE_GLOBS
    bulk_min = _FALLBACK_BULK_STRING_MIN_LEN
    try:
        from apkscan.core.registry import load_rules

        data = load_rules("domain_tiers")
    except Exception:
        logger.exception("加载 domain_tiers 规则失败，使用内置兜底")
        return suffixes, globs, bulk_min

    if isinstance(data, dict):
        emb = data.get("library_embedded_suffixes")
        if isinstance(emb, list):
            vals = tuple(s.strip().lower() for s in emb if isinstance(s, str) and s.strip())
            if vals:
                suffixes = vals
        gl = data.get("library_file_globs")
        if isinstance(gl, list):
            vals = tuple(s.strip().lower() for s in gl if isinstance(s, str) and s.strip())
            if vals:
                globs = vals
        bm = data.get("bulk_string_min_len")
        if isinstance(bm, int) and bm > 0:
            bulk_min = bm
    return suffixes, globs, bulk_min


# 进程级缓存（规则文件在运行期不变；首次访问后复用，避免每次 classify 都读盘）。
_DOMAIN_TIERS_CACHE: tuple[tuple[str, ...], tuple[str, ...], int] | None = None


def _domain_tiers() -> tuple[tuple[str, ...], tuple[str, ...], int]:
    global _DOMAIN_TIERS_CACHE
    if _DOMAIN_TIERS_CACHE is None:
        _DOMAIN_TIERS_CACHE = _load_domain_tiers()
    return _DOMAIN_TIERS_CACHE


def _is_library_embedded(domain: str) -> str | None:
    """域名是否命中 library-embedded（打包库内置全球站点库）；命中返回匹配后缀。

    与 KNOWN_INFRA 同口径用子串匹配（已小写、去端口）。★ 仅精确后缀，绝不碰任意
    .vip / .com SLD —— 确保真 C2（hxhcapi.vip / hcrsex.com）不受影响。
    """
    d = _normalize_domain(domain)
    if not d:
        return None
    suffixes, _globs, _bulk = _domain_tiers()
    for suffix in suffixes:
        if d == suffix or d.endswith("." + suffix):
            return suffix
    return None


def domain_source_tier(location: str, raw_len: int) -> str:
    """按端点来源判定域名可信度档（纯函数，数据来自 domain_tiers.yaml）。

    - location 命中已知第三方库文件路径 glob → TIER_LIBRARY_FILE。
    - 单条字符串/字面量长度超阈值（典型内置域名库大表）→ TIER_BULK_STRING。
    - 否则 → TIER_APP（最可信）。
    """
    loc = (location or "").replace("\\", "/").lower()
    _suffixes, globs, bulk_min = _domain_tiers()
    for pat in globs:
        if fnmatch(loc, pat):
            return TIER_LIBRARY_FILE
    if raw_len >= bulk_min:
        return TIER_BULK_STRING
    return TIER_APP


def best_tier(a: str | None, b: str | None) -> str:
    """合并两个 tier，取最可信档（app > library-file > bulk-string）；None 视为最差。"""
    ra = _TIER_RANK.get(a or "", 99)
    rb = _TIER_RANK.get(b or "", 99)
    return a if ra <= rb else b  # type: ignore[return-value]


def _normalize_domain(domain: str) -> str:
    """规整域名：去空白、转小写、剥协议/路径/端口，便于后缀/关键字匹配。"""
    d = (domain or "").strip().lower()
    if not d:
        return ""
    # 容错：传进来是 URL 时剥掉 scheme 与路径。
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    # 剥用户信息与端口。
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":", 1)[0]
    return d.strip(".")


def _matched_infra(domain: str) -> str | None:
    """返回命中的 KNOWN_INFRA 关键字/后缀；未命中返回 None。"""
    d = _normalize_domain(domain)
    if not d:
        return None
    for marker in KNOWN_INFRA:
        if marker in d:
            return marker
    return None


def is_known_infra(domain: str) -> bool:
    """域名是否命中已知正规基础设施清单（纯函数）。"""
    return _matched_infra(domain) is not None


def _is_invalid_or_private_domain(domain: str) -> bool:
    """域名是否无效或本身就是私网/回环 IP 字面（这类无法/无需对外调证）。"""
    d = _normalize_domain(domain)
    if not d or "." not in d:
        # 空、或无点（非 FQDN，如 localhost / 单标签）→ 视为无效/待核。
        return True
    try:
        ip = ipaddress.ip_address(d)
    except ValueError:
        return False
    # 是 IP 字面：私网/回环/链路本地/保留 → 待核。
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def classify_domain(domain: str) -> tuple[str, str]:
    """对域名做调证研判分级，返回 (advice, reason)。

    - 命中 KNOWN_INFRA          → ("无需调证", "已知第三方基础设施/库：<匹配>")
    - 命中 library-embedded     → ("无需调证", "第三方库内置站点（library-embedded），非 App 后端：<匹配>")
    - 无效 / 私网/回环 IP 字面   → ("待核", "...")
    - 其它（疑似 App 自有服务）  → ("建议调证", "疑似 App 自有服务，建议落地核查归属")
    """
    matched = _matched_infra(domain)
    if matched is not None:
        return ADVICE_SKIP, f"已知第三方基础设施/库：{matched}"

    # library-embedded：打包库内置的全球站点库（amazon / 各国银行 / 新闻 / 成人站），
    # 非 App 后端，调证无意义。★ 仅精确后缀，绝不碰真 C2 的任意 .vip/.com SLD。
    embedded = _is_library_embedded(domain)
    if embedded is not None:
        return ADVICE_SKIP, f"第三方库内置站点（library-embedded），非 App 后端：{embedded}"

    d = _normalize_domain(domain)
    # 行情代码伪域名（600000.sh / 399006.sz）：SLD 纯数字 + 交易所后缀 → 待核。
    if d.endswith(_STOCK_SUFFIXES):
        sld = d.rsplit(".", 2)[-2] if d.count(".") >= 1 else ""
        if sld.isdigit():
            return ADVICE_REVIEW, "疑似股票/基金行情代码，非真实域名，需人工核"

    if _is_invalid_or_private_domain(domain):
        return ADVICE_REVIEW, "无效域名或私网/回环字面，无法对外调证，需人工核"

    return ADVICE_INVESTIGATE, "疑似 App 自有服务，建议落地核查归属"
