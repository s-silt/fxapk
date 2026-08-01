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
import math
import re
from collections import Counter
from fnmatch import fnmatch

from apkscan.network.fingerprints import is_authoritative_dns_host, is_public_dns_resolver

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
        # 阿里云 DingRTC 音视频通信（接入调度走 gslb 子域）。整棵域由阿里持有，"aliyun"
        # 关键字覆盖不到它，故单列一行。
        "dingrtc.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        # 钉钉移动推送长连接（mcs 子域，形如 portal-hz.mcs.<钉钉主域>）。
        # ★刻意**只列 mcs 子域**、不整体列入钉钉主域：群机器人 webhook（oapi 子域下的
        #   /robot/send）是实测见过的外发通道（见 analyzers/contacts.py 的通道归属表），
        #   主域整体列入等于把那条通道一起判成"无需核查"藏起来——正是本模块要避免的方向。
        "mcs.dingtalk.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        # ---- 华为云 ----
        # ★补这条是被上面的租户桶判据逼出来的：五家云里只有华为云的裸服务端点从来没进过名单，
        #   于是"桶 → 建议核查、裸端点 → 无需核查"这条规则在华为云那一行读起来自相矛盾。
        "myhuaweicloud.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
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
        # ---- 字节跳动 SDK（穿山甲广告 / 应用日志 / 监控）----
        # 实测 2026-07-28 四案：这几个域被整批标成"建议调证"，占满办案人的清单。
        # 全部是可核实的第三方 SDK 自有域，不是 App 后端。★按域边界后缀匹配，不含通配。
        "pangolin-sdk-toutiao.com",
        "snssdk.com",
        "zijieapi.com",
        "bdurl.net",
        "bytedance.com",
        "bytedns.net",
        "byteimg.com",
        # ---- 新浪 / 微博开放平台 ----
        "weibo.com",
        "sinaimg.cn",
        "sina.com.cn",
        # ---- 网易（静态资源 / 开放服务）----
        "126.net",
        "netease.com",
        "163.com",
        # ---- 其它统计 / 监控 SDK ----
        "51.la",          # 51LA 统计
        "tpstelemetry.tencent.com",  # 腾讯 TPS 遥测（tencent.com 本身不整体列入）
        # ---- 崩溃上报 / 证书 / 多媒体库自带域（实测两案里被误当调证目标）----
        "traces.hk",            # crash 上报 SDK（libucrash.so）
        "public-trust.com",     # DigiCert 证书状态服务（DER 里的 OCSP/CRL URL）
        "videolan.org",         # VLC/libvlc 测试流地址
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
        # slf4j / logback：Java 日志门面，报错文档 URL 内嵌在库里（非 App 自有后端）。
        "slf4j.org",
        "qos.ch",
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
        # 阿里系电商门户。带 www 前缀出现，多来自打包库的站点表 / WebView 默认地址 / 深链
        # 演示串；同一后缀也覆盖阿里 SDK 的接口子域（acs.m / h5api.m 等长连接与 mtop 网关）。
        "alibaba.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "taobao.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "yzcdn.cn",                 # 有赞 CDN
        "youzan.com",
        "meituan.net",
        "dpfile.com",
        "360buyimg.com",
        "jddebug.com",
        "vipstatic.com",
        # ---- Flutter / Dart 生态（跨平台框架与包仓库引用）----
        "flutter.dev",
        "flutter.io",
        "dart.io",
        "pub.dev",                  # Dart/Flutter 包仓库
        "dartbug.com",              # Dart issue 追踪
        "baseflow.com",             # Flutter 插件作者（permission_handler 等）
        "dexterous.com",            # Flutter 插件作者（fluttertoast 等）
        # ---- Go 语言官方 ----
        "golang.org",
        "go.dev",
        # ---- 机器学习 / 框架官网 ----
        "tensorflow.org",
        # ---- 代码托管 / CI ----
        "gitee.com",
        "travisci.net",             # Travis CI 持续集成
        # ---- 多媒体 / 编解码标准与厂商（DASH/AV1/音频专利引用）----
        "dashif.org",               # DASH Industry Forum
        "aomedia.org",              # AV1 编解码联盟
        "dolby.com",
        "dts.com",
        "smpte-ra.org",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        # ---- 视频站点（播放器/下载库内置的站点适配表，非 App 后端）----
        # 实测某第三方库把整份站点表编进 DEX：一个样本贡献 6 条这类域名，全被判建议核查。
        "twitch.tv",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "ttvnw.net",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "vimeo.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "coub.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "aparat.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        # ---- 工具库 / 标准组织 ----
        "curl.se",                  # libcurl 官网
        # minizip / unzip 作者站点。zlib 附带的 minizip 源码注释里写着它，被整段编进
        # native 库的字符串表，于是以 www 子域形态被抽成"端点"。
        "winimage.com",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "iptc.org",                 # 图片元数据标准
        "useplus.org",              # PLUS 图片版权标准
        "open.gl",                  # OpenGL 教程站
        "g.co",                     # Google 短链
        # ---- XML 命名空间 URI / 框架代码常量（反编译 Java/资源里的命名空间声明与
        #      Kotlin/Java 常量被端点抽取器误当域名，本质非网络端点）----
        "adobe.com",                # ns.adobe.com XMP/XAP 命名空间
        "xml.org",                  # SAX 命名空间
        "xmlpull.org",              # XmlPull 解析器命名空间
        "purl.org",                 # Dublin Core / RDF 命名空间
        "schema.org",               # 结构化数据词汇
        "openxmlformats.org",       # OOXML 命名空间
        "dispatchers.io",           # Kotlin Dispatchers.IO 被误当域名
        "locale.us",                # Java Locale.US 被误当域名

        # ---- 公共 DNS / DoH 解析器（2026-07-26 实测：两案报告里它们被判"建议调证"，
        #      还把闭环仅有的 6 个调证目标名额全占了，真候选 54 个一个没评估）----
        #      这些是**解析基础设施**，向其运营方调证毫无意义。
        "alidns.com",               # 阿里公共 DNS / DoH（dns.alidns.com、223.5.5.5）
        "doh.pub",                  # 腾讯 DoH
        "dnspod.cn",                # 腾讯 DNSPod
        "doh.360.cn",               # 360 DoH
        "opendns.com",              # Cisco OpenDNS（含 myip.opendns.com 探测端点）
        "cloudflare-dns.com",
        "dns.google",
        "quad9.net",
        "httpdns.aliyuncs.com",     # 阿里 HTTPDNS 解析服务

        # ---- STUN / TURN（WebRTC NAT 穿透公共服务器，非案件后端）----
        "stun.cloudflare.com",
        "stun.freeswitch.org",
        "stun.nextcloud.com",
        "stun.voipbuster.com",
        "stunprotocol.org",

        # ---- 证书链基础设施：CA 官网 / CRL 吊销列表 / OCSP（TLS 校验用，恒出现在任何
        #      带 HTTPS 的 App 里，向 CA 调证与案件无关）----
        "comodoca.com",
        "comodo.net",
        "usertrust.com",
        "globalsign.net",
        "globalsign.com",
        "entrust.net",
        "digicert.com",
        "verisign.com",
        "godaddy.com",
        "letsencrypt.org",
        "sectigo.com",
        # TC TrustCenter（德国 CA，后并入 DigiCert）。根证书仍留在系统/内置 CA 包里，
        # 其官网 URL 随证书策略字段一起被抽出来。
        "trustcenter.de",  # leak-scan: allow 已知基础设施清单条目本身，本表就是这类字面的集中处
        "curl.haxx.se",             # libcurl 证书包来源说明 URL
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
# library-file 路径 glob 兜底（含 jadx 反编译第三方库包路径：库内置 URL/命名空间/常量降待核）。
_FALLBACK_LIBRARY_FILE_GLOBS: tuple[str, ...] = (
    "*/uni_modules/*", "*/node_modules/*", "*/vendor/*", "*.min.js",
    "*/static/echarts*", "*echarts.min.js", "*/dist/*",
    "*/org/xmlpull/*", "*/com/adobe/*", "*/org/apache/*", "*/org/jetbrains/*",
    "*/kotlin/*", "*/kotlinx/*", "*/io/reactivex/*", "*/com/squareup/*",
    "*/androidx/*", "*/android/support/*",
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
    .vip / .com SLD —— 确保真 C2（synthetic-c2a.vip / synthetic-c2b.com）不受影响。
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


#: 对象存储的**租户桶**子域形态：``<桶名>.<服务端点>``。
#:
#: 为什么非要把它从"云厂商整域豁免"里挖出来：五家云厂商的那几个后缀（见下方各条正则）
#: 底下混着两类完全不同的东西——
#:   · 厂商自有门户与静态资源域：与租户无关，判无需核查是对的；
#:   · ``<桶名>.<区域>.<厂商域>``：**租户专属**子域，桶名（腾讯 COS 还带 appid）就是租户凭据，
#:     拿它向云厂商能核出实名、付款与访问日志。
#: 判据不分这两类，一刀切成"云厂商=无需核查"，于是把最能落到人的那类目标静默划掉了。
#: 实测：线索清单里 8 个案子、21 处把这类桶域名列为查询目标，而同一个桶在另一份报告里
#: 被判"无需核查"。
#:
#: ★每条都要求**桶名标签存在**，绝不匹配各家的裸区域端点（形如 ``<区域>.<厂商域>`` 或
#:   ``<服务>.<区域>.<厂商域>`` 那种没有桶名的写法）——没有桶名就没有租户，查不出人，
#:   照旧无需核查。反向用例逐条列在 tests/test_tenant_bucket.py。
#: 租户标识（桶名 / 存储账户名）的**语法**片段。
#:
#: ★刻意不用 ``\w``：Python 正则的 ``\w`` 默认匹配 Unicode，中文与下划线都能通过，于是
#:   ``中文桶.<厂商端点>`` 这种不可能存在的名字也会被认成租户桶，凭空产出一个查不到的目标。
#:   端点后缀写对只解决了「是不是这家厂商」，租户标识本身的合法字符与长度是**另一件事**，
#:   两者都收紧才谈得上宁漏勿宽。
#:
#: 通用形态：DNS 标签字符集，总长 3–63（各厂商公开的桶名下限普遍是 3）。
_BUCKET = r"[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]"
#: 允许含点的变体（虚拟主机式写法把带点的桶名整段放进 host）。
#: 点号带来的额外非法组合（连续点、点与连字符相邻、整体成 IPv4 字面）不在正则里穷举，
#: 统一交给 :func:`_is_valid_bucket_name` 后置校验——写在一处才好测，也才不会某几家漏掉。
_BUCKET_DOTTED = r"[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]"

#: 点与连字符的非法相邻组合：连续点、点后接连字符、连字符后接点。各厂商的桶名规则一致禁止。
_BAD_BUCKET_ADJACENCY = re.compile(r"\.\.|\.-|-\.")
#: 形如 IPv4 字面的标识。对象存储厂商普遍禁止桶名长成 IP 的样子（会与路径式寻址歧义）。
_BUCKET_LOOKS_LIKE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_valid_bucket_name(name: str) -> bool:
    """租户标识本身的语法是否成立（正则只判形态，这里判各家共有的那几条硬约束）。

    ★为什么不塞进正则：点号一旦允许，非法组合就有好几类，逐家写进各自的正则既啰嗦又必定漏
      （已经漏过一轮）。集中在这里，新增厂商时自动受同一套约束保护。
    """
    if not name:
        return False
    if _BAD_BUCKET_ADJACENCY.search(name):
        return False
    return not _BUCKET_LOOKS_LIKE_IPV4.match(name)

_TENANT_BUCKET_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    # ★区域段刻意保持必填：放开成可选，``<区域>.<厂商域>`` 这种裸端点就会被当成「桶名=区域码」
    #   的租户桶——那正是本表开头声明要避免的误判。无区域的两段写法是否真实存在未经证实，
    #   在拿到实证之前不为一个假设的形态牺牲已成立的反向护栏。
    ("百度智能云 BOS", re.compile(rf"^(?P<bucket>{_BUCKET})\.[a-z0-9\-]+\.bcebos\.com$")),
    # ★区域段可选：新形态是 ``<桶>-<appid>.cos.<区域>.myqcloud.com``，而老的 file/pic 域
    #   直接就是 ``<桶>-<appid>.file.myqcloud.com``，没有区域段。写成必填会漏掉老形态。
    ("腾讯云 COS", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.(?:cos|file|pic)(?:[.\-][a-z0-9\-]+)?\.myqcloud\.com$"
    )),
    ("阿里云 OSS", re.compile(rf"^(?P<bucket>{_BUCKET})\.oss-[a-z0-9\-]+\.aliyuncs\.com$")),
    # 这两家的公开规则同样允许桶名含点，故用带点变体——否则合法的带点桶名会被整域豁免吃掉。
    ("AWS S3", re.compile(
        rf"^(?P<bucket>{_BUCKET_DOTTED})\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com$"
    )),
    ("华为云 OBS", re.compile(
        rf"^(?P<bucket>{_BUCKET_DOTTED})\.obs[.\-][a-z0-9\-]+\.myhuaweicloud\.com$"
    )),
    # ★这一条是补一个**正在生效**的漏洞，不是预防：该厂商的整域条目已在已知基础设施名单里，
    #   而本表此前没有它的对象存储形态，于是 ``<桶名>.<存储端点>`` 被整域豁免命中、判无需
    #   核查——既不富化、不进闭环，也不出文书。
    #   该厂商的虚拟主机式写法允许桶名含点，故用带点变体；但仍要求桶名合法（首尾字母数字、
    #   无连续点、长度 3–63），裸存储端点与同域下的其它服务子域都不匹配。
    ("Google Cloud Storage", re.compile(
        rf"^(?P<bucket>{_BUCKET_DOTTED})\.storage\.googleapis\.com$"
    )),
    # ★以下几家此前不在名单里。它们当时之所以没出事，只是因为这些厂商域**恰好**也不在
    #   KNOWN_INFRA 里，于是落到 classify_domain 末尾的兜底档——是运气，不是保护：任何人
    #   往已知基础设施名单里添一条对应的厂商域，这些桶就会被整域豁免静默吃掉，而它们恰恰是
    #   最能落到租户实名的那类目标。
    #
    # ★证据等级（写清楚，免得后人把两者当同一回事）：
    #   · 天翼云 ZOS —— 有在手样本实证，形态取自实际观测到的写法；
    #   · 其余各家 —— 按各厂商**公开的端点域形态**写，未经在手样本验证。
    #     选择容忍这一点，是因为两类错误不对称：形态写窄了只是漏（维持改动前的现状，不更差），
    #     写宽了才会凭空造出查不到的目标。
    #
    # ★「宁漏勿宽」要在**两处**都成立，缺一处就是空话：端点后缀写对只解决「是不是这家厂商」，
    #   租户标识本身的合法字符与长度是另一件事。本表初版只做了前者、租户标识一律用宽松字符类，
    #   于是能匹配出一批语法上不可能存在的账户名——那等于凭空造目标。现按各厂商公开的标识
    #   语法分别收紧（见 _BUCKET / _BUCKET_DOTTED 与 Azure、R2 两条的单独说明）。
    #   反向用例（裸端点、域边界攻击、非法标识）逐条列在 tests/test_tenant_bucket.py。
    ("天翼云 ZOS", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.[a-z0-9\-]+\.zos\.ctyun\.cn$"
    )),
    # 该厂商有两个端点域并存（正则里的可选 ``cs`` 段），桶名段之后固定是 ks3-<区域>。
    ("金山云 KS3", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.ks3-[a-z0-9\-]+\.ksyun(?:cs)?\.com$"
    )),
    ("UCloud US3", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.[a-z0-9\-]+\.ufileos\.com$"
    )),
    ("青云 QingStor", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.[a-z0-9\-]+\.qingstor\.com$"
    )),
    ("京东云 OSS", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.(?:s3|obs)[.\-][a-z0-9\-]+\.jdcloud-oss\.com$"
    )),
    ("小米 FDS", re.compile(rf"^(?P<bucket>{_BUCKET})\.fds\.api\.xiaomi\.com$")),
    # 华为云的旧端点域，与前面那个端点域并存。
    ("华为云 OBS", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.obs(?:[.\-][a-z0-9\-]+)?\.myhwclouds\.com$"
    )),
    # ★这一段是**存储账户名**而非桶名，但同样是租户专属标识、同样能据以核出订阅主体。
    #   该厂商对账户名的公开约束比桶名严得多——只允许 3–24 位小写字母数字，连字符与下划线
    #   都不合法。按通用桶名形态写会接受一批不可能存在的账户名，故此处单独收紧。
    ("Azure Blob", re.compile(
        r"^(?P<bucket>[a-z0-9]{3,24})\.(?:blob|file|queue|table)\.core\.windows\.net$"
    )),
    # ★中间那一段不是区域码，而是该厂商的**账号标识**（32 位十六进制）。写成任意标签会把
    #   ``<桶>.<任意串>.r2...`` 一律认成租户桶，而那种形态不可能对应真实账号。
    #   ★可选的第三段是辖区端点，且**只有公开的那两个取值**——写成任意字母串同样会造出
    #   不存在的端点形态。枚举写死，新增辖区时再加。
    ("Cloudflare R2", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.[0-9a-f]{{32}}(?:\.(?:eu|fedramp))?"
        r"\.r2\.cloudflarestorage\.com$"
    )),
    ("DigitalOcean Spaces", re.compile(
        rf"^(?P<bucket>{_BUCKET})\.[a-z0-9\-]+\.digitaloceanspaces\.com$"
    )),
    # 该厂商同样允许桶名含点。
    ("Yandex Object Storage", re.compile(
        rf"^(?P<bucket>{_BUCKET_DOTTED})\.storage\.yandexcloud\.net$"
    )),
)


def tenant_bucket(domain: str) -> tuple[str, str] | None:
    """域名是否为对象存储的租户桶子域；是则返回 ``(云厂商, 桶名)``，否则 None。

    形态由 :data:`_TENANT_BUCKET_PATTERNS` 判，标识本身的语法由 :func:`_is_valid_bucket_name`
    兜底——两道都过才算。语法不成立的标识对应不到任何真实租户，认下来只会产出一条查不到人的
    线索，比漏更糟。
    """
    d = _normalize_domain(domain)
    if not d:
        return None
    for provider, pattern in _TENANT_BUCKET_PATTERNS:
        m = pattern.match(d)
        if m is None:
            continue
        bucket = m.group("bucket")
        if not _is_valid_bucket_name(bucket):
            continue  # 形态像，但标识本身语法不成立——不是真租户
        return provider, bucket
    return None


def _matched_infra(domain: str) -> str | None:
    """返回命中的 KNOWN_INFRA 关键字/后缀；未命中返回 None。

    两类 marker 区别匹配，避免短域名后缀被当子串误命中：
    - **域名后缀型**（含点，如 ``qq.com`` / ``mob.com``）：要求 ``d == marker`` 或以
      ``.<marker>`` 结尾（域边界）。否则 ``mob.com`` 会子串命中攻击者构造的 ``evilmob.com.cn``，
      把真 C2 误判成"无需调证"——与本模块"宁可建议调证"的取向正好相反。
    - **品牌关键字型**（无点，如 ``aliyun`` / ``qcloud`` / ``igexin``）：保留子串匹配
      （它们本就是为匹配 ``aliyun-xxx.com`` 这类品牌变体而设）。
    """
    d = _normalize_domain(domain)
    if not d:
        return None
    for marker in KNOWN_INFRA:
        if "." in marker:
            if d == marker or d.endswith("." + marker):
                return marker
        elif marker in d:
            return marker
    return None


def is_known_infra(domain: str) -> bool:
    """域名是否命中已知正规基础设施清单（纯函数）。"""
    return _matched_infra(domain) is not None


# XML 命名空间 / schema 声明的常见 host 与 path 片段。出现这些的 URL 是 XML 命名空间
# 标识符（反编译 Java / 资源里大量存在），**不是网络端点**，应在抽取层直接丢弃。
_XML_NS_HOSTS: tuple[str, ...] = (
    "w3.org", "adobe.com", "xml.org", "xmlpull.org", "purl.org", "schema.org",
    "openxmlformats.org", "schemas.android.com", "schemas.microsoft.com",
    "schemas.xmlsoap.org", "xml.apache.org", "java.sun.com", "jcp.org", "iptc.org",
)
_XML_NS_PATH_HINTS: tuple[str, ...] = (
    "/xmlns", "/xml/1998/namespace", "/2000/xmlns", "/2001/xmlschema",
    "/xap/", "/xap-", "/sax/", "/dtd/", "/dc/elements", "/dc/terms",
    "/v1/doc/", "/apk/res/", "/apk/res-auto", "/ns/", "/namespace",
)


def is_xml_namespace_url(url: str) -> bool:
    """URL 是否为 XML 命名空间 / schema 声明（非网络端点）。

    判据：host 命中已知命名空间域（w3.org / adobe.com / xmlpull.org / schemas.* 等），
    或 path 含命名空间惯用片段（``/xmlns``、``/XML/1998/namespace``、``/xap/``、``/sax/``、
    ``/apk/res/`` 等）。命中即应在端点抽取层丢弃，避免反编译代码里的命名空间声明污染调证线索。
    """
    u = (url or "").strip().lower()
    if not u:
        return False
    host = _normalize_domain(u)
    if host:
        for h in _XML_NS_HOSTS:
            if host == h or host.endswith("." + h):
                return True
    return any(hint in u for hint in _XML_NS_PATH_HINTS)


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


# 编码伪域名识别：base64/hex/随机串里夹点会被当域名 → 调证不可回溯（之前靠人工才排掉）。
_HEX_LABEL_RE = re.compile(r"[0-9a-fA-F]+")
_B64_LABEL_RE = re.compile(r"[A-Za-z0-9_+/=-]+")


def _shannon_entropy(s: str) -> float:
    """字符级香农熵（bit/char）；空串 0。base64/随机串近 6，真实词偏低，用于区分编码 vs 真域名。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def looks_like_encoding(domain: str) -> str | None:
    """点分串是否疑似 base64/hex/随机编码伪域名（而非真实可调证域名）。

    命中返回原因串（供"待核"标注），否则 None。判据**保守**——只标 **过长 + 高熵** 的标签，
    既抓住"编码里夹点被误当域名"的不可回溯噪音，又**不误伤短随机 C2（DGA，如 al2x9k.vip）
    与正常词域名**。绝不静默丢弃，只降级为待核 + 标原因，保留可见可人工核。
    """
    for label in str(domain).split("."):
        length = len(label)
        if length < 20:
            continue
        has_digit = any(c.isdigit() for c in label)
        has_alpha = any(c.isalpha() for c in label)
        has_upper = any(c.isupper() for c in label)
        # 长 hex 串（≥20、字母+数字混合）= 摘要/编码，非真实域名标签。
        if has_digit and has_alpha and _HEX_LABEL_RE.fullmatch(label):
            return f"标签「{label[:20]}…」为 {length} 位 hex 串，疑似哈希/编码而非真实域名（不可回溯，需人工核）"
        # base64/base64url：≥22、高熵、且(含大写 或 字母数字混合) = 编码串。
        if (
            length >= 22
            and _B64_LABEL_RE.fullmatch(label)
            and (has_upper or (has_digit and has_alpha))
            and _shannon_entropy(label) >= 4.0
        ):
            return f"标签「{label[:20]}…」过长（{length}）且高熵，疑似 base64/编码或随机串伪域名（不可回溯，需人工核）"
    return None


#: 规范/协议里用作**标识符**的 URL host。这类 URL 写在协议实现里当常量名用，
#: App 从不去连它们（WebRTC 的 RTP 头扩展 URI 就是典型：
#: ``http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02``）。
_PROTOCOL_ID_HOSTS: frozenset[str] = frozenset({
    "www.webrtc.org", "webrtc.org",
    "www.w3.org", "w3.org",
    "www.ietf.org", "ietf.org", "tools.ietf.org", "datatracker.ietf.org",
    "schemas.android.com", "xmlpull.org", "www.xmlpull.org",
    "purl.org", "xmlns.com", "www.iana.org", "iana.org",
})

#: 前导垃圾字符 + 已知域：native 字符串表里域名前面常粘着别的字节。
#: 实测 ``2github.com`` / ``3github.com`` 来自 Go 模块路径 ``…/klauspost/compress`` 前的
#: 类型描述符数字，``0www.entrust.net`` 来自证书 DER 的结构字节。剥掉前导数字/单字母后
#: 若正好是已知基础设施域，那它就是那个域被截断的产物，不是一个新域名。
_STICKY_PREFIX_RE = re.compile(r"^[0-9]{1,3}(?=[a-z])|^[a-z](?=(?:www|github|gitlab)\.)")

#: 单个常见英文词 + 通用 TLD。这类"域名"绝大多数是 native 字符串表里的句子被切出来的
#: （``the.com`` / ``log.com`` / ``tos.org`` 实测均来自 libgojni.so 的 HTML 模板词料区）。
#: ★只降"待核"不排除：团伙确实可能注册短域名，判错的代价必须可回捞。
_COMMON_WORD_SLDS: frozenset[str] = frozenset({
    "the", "log", "tos", "out", "and", "for", "you", "all", "new", "get", "set",
    "use", "one", "two", "our", "not", "but", "can", "has", "was", "are", "his",
    "her", "its", "may", "now", "any", "how", "who", "why", "did", "yes", "off",
    "own", "too", "via", "www", "this", "that", "with", "from", "have", "were",
    "test", "demo", "true", "false", "null", "none", "type", "name", "text",
    # SDK 文档/脚手架里的占位 SLD。★只降待核不判 SKIP：这些名字**确实可注册**
    #   （abc.com、domain.com 都是真实在册域名），判"无需调证"就等于替人下"与本案无关"
    #   的结论，把一个真 C2 藏起来——降噪那点收益换不来这个代价。
    "domain", "example", "yourdomain", "mydomain", "sample", "placeholder",
    "xxx", "xxxx", "abc", "aaa", "todo", "changeme", "host", "server", "api",
    "your-domain", "my-domain", "your-site", "site", "website",
})

#: 标准保留、**不可注册**的顶级域（RFC 2606 / 6761 / 6762 / 8375）+ 约定俗成的本机后缀。
#: 落在这些后缀下的名字不存在注册人，没有可调证的对象。
#:
#: ★刻意**不含** ``example.com/.net/.org``：那几个同样是保留域，但在本仓库里它们是测试与
#:   合成回归语料通用的中性替身（"pay.example.com" 之类），特殊对待会连带改掉检出基线与多处
#:   富化 fixture。那是一次单独的决定，不该顺手夹带在降噪里做掉。
_RESERVED_TLDS: tuple[str, ...] = (
    ".test",         # RFC 2606：测试用
    ".example",      # RFC 2606：文档用
    ".invalid",      # RFC 2606：明确无效
    ".localhost",    # RFC 6761：恒指回环
    ".local",        # RFC 6762：mDNS 链路本地
    ".home.arpa",    # RFC 8375：家庭网络
    ".localdomain",  # 约定俗成的本机后缀（localhost.localdomain），不可路由
)


def _reserved_domain_match(domain: str) -> str | None:
    """域名是否落在标准保留后缀下；是则返回命中的后缀。"""
    d = _normalize_domain(domain)
    if not d:
        return None
    for suffix in _RESERVED_TLDS:
        if d == suffix.lstrip(".") or d.endswith(suffix):
            return suffix
    return None
_GENERIC_TLDS: frozenset[str] = frozenset({"com", "org", "net", "info", "xyz", "top"})


def _sticky_variant_of_known(domain: str) -> str | None:
    """域名是否为「已知基础设施域被粘上前导字节」的产物；是则返回被粘的那个域。"""
    d = _normalize_domain(domain)
    if not d or _matched_infra(d) is not None:
        return None  # 本身就是已知域，不走这条
    stripped = _STICKY_PREFIX_RE.sub("", d, count=1)
    if stripped == d or not stripped:
        return None
    return stripped if _matched_infra(stripped) is not None else None


def _is_common_word_sld(domain: str) -> bool:
    """``<常见英文词>.<通用 TLD>`` 且无子域 —— 极可能是句子被切出来的伪域。"""
    d = _normalize_domain(domain)
    parts = d.split(".")
    if len(parts) != 2:
        return False
    return parts[0] in _COMMON_WORD_SLDS and parts[1] in _GENERIC_TLDS


def classify_domain(domain: str) -> tuple[str, str]:
    """对域名做调证研判分级，返回 (advice, reason)。

    - 命中 KNOWN_INFRA          → ("无需调证", "已知第三方基础设施/库：<匹配>")
    - 命中 library-embedded     → ("无需调证", "第三方库内置站点（library-embedded），非 App 后端：<匹配>")
    - 无效 / 私网/回环 IP 字面   → ("待核", "...")
    - 其它（疑似 App 自有服务）  → ("建议调证", "疑似 App 自有服务，建议落地核查归属")
    """
    # ★必须排在 KNOWN_INFRA 之前：桶域名的后缀正是云厂商域，先走那条就被整域豁免吃掉了。
    bucket = tenant_bucket(domain)
    if bucket is not None:
        provider, name = bucket
        return ADVICE_INVESTIGATE, (
            f"对象存储的租户桶（{provider}）：桶名 {name} 是租户专属标识，"
            "可据此向该云厂商核租户实名 / 付款 / 访问日志"
        )

    matched = _matched_infra(domain)
    if matched is not None:
        return ADVICE_SKIP, f"已知第三方基础设施/库：{matched}"


    if _normalize_domain(domain) in _PROTOCOL_ID_HOSTS:
        return ADVICE_SKIP, "规范/协议里的标识符 URL（如 RTP 头扩展 URI），App 从不连它"

    sticky = _sticky_variant_of_known(domain)
    if sticky is not None:
        # ★只降"待核"，不判"无需调证"：2github.com 语法合法、可被注册和控制，
        #   仅凭"剥掉前导数字后像已知域"证不了它一定是字符串表粘连产物。
        #   判 SKIP 会把一个真 C2 直接藏起来——这个代价换不来那点降噪收益。
        return ADVICE_REVIEW, (
            f"疑为 native 字符串表边界产物（剥掉前导字节后即已知基础设施域 {sticky}），"
            "但该写法本身可注册，需人工核实是否真实存在"
        )

    # library-embedded：打包库内置的全球站点库（amazon / 各国银行 / 新闻 / 成人站），
    # 非 App 后端，调证无意义。★ 仅精确后缀，绝不碰真 C2 的任意 .vip/.com SLD。
    embedded = _is_library_embedded(domain)
    if embedded is not None:
        return ADVICE_SKIP, f"第三方库内置站点（library-embedded），非 App 后端：{embedded}"

    # 编码伪域名（base64/hex/随机串夹点）→ 待核 + 标原因（放在 known-infra/库内置之后，
    # 避免误伤合法 CDN 哈希子域；这类"像域名的编码"调证不可回溯，须人工核而非直接调）。
    enc = looks_like_encoding(domain)
    if enc is not None:
        return ADVICE_REVIEW, enc

    d = _normalize_domain(domain)
    # 行情代码伪域名（600000.sh / 399006.sz）：SLD 纯数字 + 交易所后缀 → 待核。
    if d.endswith(_STOCK_SUFFIXES):
        sld = d.rsplit(".", 2)[-2] if d.count(".") >= 1 else ""
        if sld.isdigit():
            return ADVICE_REVIEW, "疑似股票/基金行情代码，非真实域名，需人工核"

    if _is_invalid_or_private_domain(domain):
        return ADVICE_REVIEW, "无效域名或私网/回环字面，无法对外调证，需人工核"

    if _is_common_word_sld(domain):
        return ADVICE_REVIEW, (
            "单个常见英文词 + 通用 TLD 且无子域，疑为二进制里的句子被切出的伪域名，需人工核"
        )

    reserved = _reserved_domain_match(domain)
    if reserved is not None:
        return ADVICE_REVIEW, (
            f"标准保留的文档/测试域（{reserved}，RFC 2606/6761/6762 明令不可注册）——"
            "不存在可调证的注册人，多为 SDK 文档/脚手架残留；★留待核而非排除：一个没填完的"
            "模板域名本身也是团伙工具链的线索，值得人看一眼"
        )

    return ADVICE_INVESTIGATE, "疑似 App 自有服务，建议落地核查归属"


#: 点分四段字面被当成 IP 的两大来源，实测语料 40 份报告统计：
#:   - 版本号 / 序号（``1.3.1.1``、``1.4.1.14``——同一混淆资源里成**连续递增序列**出现）  # leak-scan: allow 这两个点分四段是被误判成 IP 的**版本号**字面，本注释正是在解释该误判形态，非网络地址
#:   - ASN.1 OID（X.509 证书与加密库常量：``1.3.101.112`` Ed25519、``2.5.4.3`` CN、
#:     ``2.5.29.17`` SAN、``1.3.6.1`` iso.org.dod.internet、``1.3.36.3`` Teletrust）
#: 二者都不是网络地址，却带 confidence=HIGH 进"建议调证"，把闭环预算与外部富化额度吃光。
#:
#: ★判据只**降级为待核**，绝不排除：真实团伙后端确有低段位 IP（如 8.x/47.x 阿里云段），
#:   而"1 开头且四段都小"这种形态在真 IP 里罕见、在版本号里普遍——把握不到十成的事只降不杀。
_OID_ARC_PREFIXES: tuple[str, ...] = (
    "1.3.6.1.",      # iso.org.dod.internet（SNMP/PKIX 全家）
    "1.3.101.",      # EdDSA / X25519 系列
    "1.3.36.",       # Teletrust（德国标准，BSI 曲线）
    "2.5.4.",        # X.500 属性类型（CN/O/OU/C…）
    "2.5.29.",       # X.509 v3 扩展（SAN/keyUsage/CRL…）
    "1.2.840.",      # ANSI/RSA/PKCS 系列
    "2.16.840.",     # 美国 ANSI 组织分支（含 NIST 曲线）
    "2.23.140.",     # CA/Browser Forum 证书策略
)

#: 低值四段的段上限。标定：语料里真实被采纳为 IOC 的 IP，四段全部 ≤32 的一例也没有；
#: 而版本号/序号几乎全在此区间内。
#:
#: ★"零例"指的是**无佐证形态**——语料标定时判据只看字面。真实公网后端确有落在这个形态里的
#:   （AWS 3./23.、Azure 20.、Meta 31.13 段都能凑出四段全 ≤32 的地址），而裸字面本身提不出
#:   端口/URL 上下文来把自己捞回来。故 :func:`classify_ip` 另开一条**双重佐证**的定向豁免
#:   （ASN 归属托管段 + 样本内无同形态编号序列），见下方参数说明；别照旧注释把它当 bug 删掉。
_LOW_OCTET_MAX = 32

#: 样本内同形态低段位兄弟值达到几个就按"编号序列"看待（1.3.1.1 / 1.3.1.6 / 1.4.1.14 成簇）。  # leak-scan: allow 三个点分四段是被误判成 IP 的**版本号**字面，用于说明成簇判据，非网络地址
#: 成簇是版本号的主要产生形态，此时即便 ASN 佐证成立也不升级。
_LOW_OCTET_SEQUENCE_SIBLINGS = 2

#: "裸字面"判据：真实网络地址在样本里通常带端口、出现在 URL 里、或有协议前缀。
#: 命中任一即视为**用作地址**，不降级。
_ADDRESSY_RE = re.compile(r":\d{1,5}\b|//|https?", re.IGNORECASE)


def _strip_port_suffix(value: str) -> str:
    """剥掉 lead 值上的 ``:port`` / ``:port/proto`` 尾缀，取回裸 IP 字面。

    ★不剥就会绕过一切精确匹配：实测两案的动态线索值形如 ``223.5.5.5:53/udp``，
    与名单里的 ``223.5.5.5`` 比不上，公共解析器照样进"建议调证"。

    IPv6 分三种形态，判据不同：

    1. ``[2001:db8::1]:443/tcp`` —— RFC 3986 括号形态，**无歧义**，直接取括号内。
       新产出一律走这个形态（见 ``pcap_ingest.format_peer``）。
    2. ``2001:db8::1`` —— 裸地址，多冒号且无 ``/proto``。**绝不能剥**：末段 ``1`` 本身
       就是个合法端口号，剥了会得到 ``2001:db8:``，把地址毁掉。
    3. ``2001:db8::1:443/tcp`` —— 旧产物里的无括号拼接，字面上**真的有歧义**
       （它既可以是「::1 上的 443 端口」，也可以是一个末段为 443 的裸地址）。
       靠 ``/proto`` 尾缀消歧：那个后缀只由「拼过端口」的生产路径产生，所以它在场
       就说明末段确实是端口。仅在此前提下、且剥完能解析成 IP 时才剥。
    """
    head, proto_sep, _proto = value.partition("/")
    head = head.strip()
    if not head:
        return head

    if head.startswith("["):                       # 形态 1：括号形态，最可靠
        inner, close, _rest = head[1:].partition("]")
        if close:
            return inner.strip()
        return head                                # 只有左括号 —— 坏字面，不猜

    colons = head.count(":")
    if colons == 0:
        return head
    if colons == 1:                                # IPv4:port / host:port，历史行为不变
        return head.rsplit(":", 1)[0]

    # 多冒号 = IPv6 语境（形态 2 或 3）。默认不动，只有消歧成功才剥。
    if not proto_sep:
        return head                                # 形态 2：裸 IPv6，原样返回
    bare, _, port_s = head.rpartition(":")
    if not (port_s.isdigit() and 1 <= int(port_s) <= 65535):
        return head
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        return head                                # 剥完不是合法地址 → 本来就不是 addr:port
    return bare


#: 合法端口区间（与 config/port_norm.py 同口径）。
_PORT_MIN_VALID = 1
_PORT_MAX_VALID = 65535


def format_hostport(ip: str, port: int | str) -> str:
    """把 ``(ip, port)`` 拼成 ``enrichment.runtime.remote_endpoints`` 的规范字面。

    IPv6 加 RFC 3986 方括号，IPv4 原样。**这个字段是跨模块契约**——pcap 与 capture 两条
    生产路径写它，attribution 与 port-normalize 两处读它。四方必须用这里这一对函数，
    否则又会出现"一个字段两套格式"（曾经真的出现过：pcap 改了括号、capture 还在裸拼，
    attribution 于是把 ``[2606:...]`` 当地址解析、IPv6 的运行时归因边静默丢失）。
    """
    host = str(ip)
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def split_hostport(value: object) -> tuple[str, int] | None:
    """:func:`format_hostport` 的逆操作：``"ip:port"`` / ``"[v6]:port"`` → ``(ip, port)``。

    坏形状 / 端口非法 / 剥出来不是合法地址 → ``None``（跳过该条，绝不猜）。

    ★裸 IPv6 带端口（``2001:db8::1:443``，旧产物形态）本身有歧义——末段既可能是端口，也可能
      是地址的最后一组。这里按"末段当端口"解析并**要求剩余部分是合法地址**：真采集数据一定带
      端口，所以这个取舍对生产数据是对的；手编的无端口 IPv6 可能被误切，那正是要用括号形态的原因。
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None

    if text.startswith("["):                      # [v6]:port —— 无歧义，先走这条
        inner, close, rest = text[1:].partition("]")
        if not close or not rest.startswith(":"):
            return None
        head, port_s = inner.strip(), rest[1:]
    else:
        if ":" not in text:
            return None
        head, _, port_s = text.rpartition(":")

    if not head or not port_s.isdecimal():
        return None
    port = int(port_s)
    if not (_PORT_MIN_VALID <= port <= _PORT_MAX_VALID):
        return None
    try:
        ipaddress.ip_address(head)
    except ValueError:
        return None
    return head, port


def match_key(kind_or_category: str, value: str) -> str:
    """Lead ↔ Endpoint 配对用的**唯一**规范化值。

    IP 侧剥 ``:port`` / ``:port/proto`` 尾缀（运行时回灌的 Lead 值形如
    ``198.51.100.7:31861/tcp``，Endpoint 一律裸 IP）；域名侧只做小写。

    ★之所以要一个公共入口而不是各处各写一份：此前只有**选闭环目标**那一处剥了端口，
      而闭环结论回写 Lead（``closure._update_target_leads``）与调证函关联归属链
      （``report.letters``）都还在拿 ``value.lower()`` 精确匹配。后果是同一个真后端
      **被选中当了闭环目标，却拿不到 where_to_request / 五层归属链**——闭环算了、
      文书不知道，调证函把实测后端漏成一句空壳。三处必须用同一把钥匙。
    """
    v = str(value).strip().lower()
    return _strip_port_suffix(v) if str(kind_or_category).upper() == "IP" else v


def is_low_octet_ipv4(value: str) -> bool:
    """该字面是否为"四段全部 ≤ :data:`_LOW_OCTET_MAX`"的 IPv4（纯形态判断，不看 is_global）。

    供调用方在样本内建"同形态兄弟池"，用来识别编号序列。解析不了 → False。
    """
    bare = _strip_port_suffix(value)
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return addr.version == 4 and all(int(p) <= _LOW_OCTET_MAX for p in bare.split("."))


def classify_ip(
    value: str,
    *,
    context: str = "",
    runtime_observed: bool = False,
    hosting_attributed: bool = False,
    low_octet_siblings: int = 0,
    vendor_sdk_binary: str = "",
) -> tuple[str, str]:
    """对 IP 字面做调证研判分级，返回 ``(advice, reason)``——与 :func:`classify_domain` 对称。

    ``context`` 传该端点的证据片段拼接串，用于判断这个字面在样本里是否**当地址用**
    （带端口 / 在 URL 里）。拿不准就不降级。

    ``runtime_observed`` 为真（证据里有 runtime* 来源）时，形态判据一律豁免：
    设备上真发生过到这个地址的连接，它就是地址，四段再小也不是版本号。

    ``hosting_attributed`` / ``low_octet_siblings`` 是低段位降级的**定向豁免**：ASN 富化把这个
    地址归到云/IDC/托管转售段（``hosting_attributed``），且样本里没有同形态的编号序列兄弟
    （``low_octet_siblings`` 少于 :data:`_LOW_OCTET_SEQUENCE_SIBLINGS`）时升回"建议调证"。
    裸字面自己提不出端口/URL 上下文，只能靠外部佐证捞——但佐证必须是**双重**的：
    单看 ASN 无区分度（几乎每个全球 IP 都有 ASN），单看孤值又漏掉版本号最常见的成簇形态。

    ``vendor_sdk_binary`` 传库文件名时表示：这个地址的**全部**证据都落在该第三方 SDK 的
    native 库内，且同一文件里还带着该 SDK 自己的域名（判据见 ``leads._vendor_sdk_constant``）。
    此时判"待核"——厂商 SDK 把接入调度地址硬编码进 .so 是常规做法，与本 App 的后端无关。
    ★只降待核、绝不判 SKIP：同一形态也可能是**自带 .so 的样本**把后端地址烙在里面，
      判 SKIP 等于替人下"与本次分析无关"的结论；待核仍留在清单上、理由写明来源可人工捞回。

    ★两参数默认关闭，离线 / 无富化路径行为逐字不变（仍是"待核 + 人工可捞回"）。
    ★别把佐证放松成"有 asn 数据"或"Shodan 有开放端口"——前者无区分度，后者会把无关活主机
      升成调证对象，两个都把错误翻到代价更高的方向。
    """
    bare = _strip_port_suffix(value)
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        # 非法字面里含四段以上的点分数字 —— OID 的典型形态（1.3.101.112.1）。
        if bare.startswith(_OID_ARC_PREFIXES):
            return ADVICE_REVIEW, f"ASN.1 OID 而非网络地址（{bare}），需人工核"
        return ADVICE_REVIEW, "无法解析为 IP 地址，需人工核"

    if not addr.is_global:
        # 私网、回环、链路本地、文档段（TEST-NET）、组播、保留段——对外调证无从下手。
        return ADVICE_SKIP, "非全球可路由地址（私网/回环/文档/保留段），无调证对象"

    if is_public_dns_resolver(bare):
        # 公共递归解析器：归属是公开的（Google/阿里/腾讯…），向它们调证拿不到任何
        # 与本案有关的东西。样本里硬编码了公共 DNS 是个事实（另有 dns_bypass 通道记录），
        # 但它不是调证对象，不该占 closure 预算与外部富化额度。
        return ADVICE_SKIP, "公共递归解析器（归属公开），非调证对象"

    if is_authoritative_dns_host(bare):
        # 域名托管商的权威 NS 主机：同样是 DNS 基础设施，查它落不到本样本的资产上。
        return ADVICE_SKIP, "域名托管商的权威 DNS 主机（归属公开），非调证对象"  # leak-scan: allow 出口理由串须与上一条公共解析器同措辞，报告内文用词不能一句一变

    if runtime_observed:
        # 设备上真连过 —— 形态判据一概不适用。
        return ADVICE_INVESTIGATE, "运行时观测到的实连地址，建议落地核查归属"

    if vendor_sdk_binary:
        # 全部证据都在某第三方 SDK 的 .so 内，且该文件同时带着该 SDK 自有域名。
        # ★放在形态判据之前：来源比形态硬——即便这个地址在 .so 里写成了带端口的 URL，
        #   它仍然是厂商 SDK 的接入常量，不是本 App 的后端。
        # ★理由只陈述**来源**，不替这个字面定性：本判据先于形态判据触发，落进来的既有
        #   接入调度地址、也有版本号一类被 IP 正则吃掉的常量，写死成"接入地址"就说过头了。
        return ADVICE_REVIEW, (
            f"该字面的全部证据都落在第三方 SDK 的 native 库 {vendor_sdk_binary} 内"
            "（同一文件里还有该 SDK 自有域名），疑为该 SDK 内置常量而非本 App 后端，需人工核"
        )

    if bare.startswith(_OID_ARC_PREFIXES):
        return ADVICE_REVIEW, f"ASN.1 OID 而非网络地址（{bare}），需人工核"

    if _ADDRESSY_RE.search(context or ""):
        return ADVICE_INVESTIGATE, "疑似 App 后端地址，建议落地核查归属"

    if addr.version == 4 and all(int(p) <= _LOW_OCTET_MAX for p in bare.split(".")):
        if hosting_attributed and low_octet_siblings < _LOW_OCTET_SEQUENCE_SIBLINGS:
            return ADVICE_INVESTIGATE, (
                "四段值偏低但 ASN 归属云/IDC 托管段、且样本内无同形态编号序列，"
                "按后端地址处理，建议落地核查归属（★形态存疑，发函前请人工复核）"
            )
        return ADVICE_REVIEW, (
            "四段值均偏低且样本里未当地址使用（无端口/无 URL 上下文），"
            "疑为版本号或序号被当成 IP，需人工核"
        )

    return ADVICE_INVESTIGATE, "疑似 App 后端地址，建议落地核查归属"


def effective_advice(domain: str, tier: object) -> str:
    """综合 ``classify_domain`` 分级 + 来源可信度档（tier）的**最终**调证研判（单一事实源）。

    在 ``classify_domain`` 基础上叠加 C1 来源档降级：当端点仅见于第三方库文件 / 超大字符串表
    （``tier`` ∈ {library-file, bulk-string}）且 classify 仍判"建议调证"时，降为"待核"——
    与 ``pipeline._domain_lead`` 的 C1 逻辑同口径。

    ★ 用途：目标筛选须与**最终 Lead 研判**用同一套判据，避免"被判待核（不建议调证）的库内置档
    端点"在下游被当作可调证目标的判据漂移。
    """
    advice, _reason = classify_domain(domain)
    if advice == ADVICE_INVESTIGATE and tier in (TIER_LIBRARY_FILE, TIER_BULK_STRING):
        return ADVICE_REVIEW
    return advice
