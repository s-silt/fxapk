"""core.infra 单测：C1 域名分级（library-embedded）+ 来源可信度档（tier）。

覆盖：
- library-embedded 知名站点 / 银行 / 成人站 → 无需调证。
- ★ 真 C2 域名（hxhcapi.vip / hcrsex.com）→ 建议调证（回归锁，不得误杀）。
- KNOWN_INFRA 新增 m3w.cn → 无需调证。
- domain_source_tier：library-file / bulk-string / app 三档判定。
- best_tier：多来源取最可信档。
"""

from __future__ import annotations

from apkscan.core import infra


# --- C1：library-embedded 分级 -------------------------------------------


def test_library_embedded_well_known_sites_skip():
    for dom in ("amazon.com", "www.chase.com", "pornhub.com", "bbc.co.uk", "paypal.com"):
        advice, reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_SKIP, f"{dom} 应判 library-embedded 无需调证"
        assert "library-embedded" in reason


def test_real_c2_domains_still_investigate():
    # ★ 真 C2（华彩样本）不得被 library-embedded 误降——精确后缀绝不碰任意 .vip/.com SLD。
    for dom in ("hxhcapi.vip", "hcrsex.com", "api.hxhcapi.vip", "pay.hcrsex.com"):
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_INVESTIGATE, f"{dom} 应建议调证（真 C2 不得误杀）"


# --- classify_ip：点分四段字面未必是网络地址 ------------------------------


def test_classify_ip_real_backends_still_investigate():
    """★最重要的一条：真实团伙后端不得被任何降级判据碰到。

    取自实测语料里已进调证清单的形态：境外 IDC 段、带高位端口的裸后端。
    """
    for value in (
        "103.36.167.109:443/tcp",
        "134.175.85.26:30147/tcp",
        "154.206.232.17",
        "45.202.1.163",
        "65.75.210.121",
        "15.204.18.128",
        "222.167.33.27",
        "8.210.13.45",
    ):
        advice, _reason = infra.classify_ip(value)
        assert advice == infra.ADVICE_INVESTIGATE, f"{value} 应建议调证（真后端不得误杀）"


def test_classify_ip_version_numbers_demoted_not_dropped():
    """★真样本回归：混淆资源里的连续递增编号被 IP 正则吃掉，以 HIGH 置信度占满闭环 Top6。

    只降"待核"不排除——四段皆小在真 IP 里罕见但不是不可能。
    """
    for value in ("1.3.1.1", "1.3.1.6", "1.4.1.14", "1.2.0.4"):
        advice, reason = infra.classify_ip(value)
        assert advice == infra.ADVICE_REVIEW, value
        assert "版本号" in reason or "序号" in reason


def test_classify_ip_low_octets_with_address_context_kept():
    """同样的字面，若样本里带端口或出现在 URL 中，就是当地址用的 → 不降。"""
    advice, _ = infra.classify_ip("1.2.3.4", context="connect to 1.2.3.4:8443 now")
    assert advice == infra.ADVICE_INVESTIGATE
    advice, _ = infra.classify_ip("1.2.3.4", context="http://1.2.3.4/api/login")
    assert advice == infra.ADVICE_INVESTIGATE


def test_classify_ip_asn1_oids_demoted():
    """X.509 / 加密库常量：1.3.101.112 是 Ed25519 的 OID，不是地址。"""
    for value in ("1.3.101.112", "2.5.29.17", "2.5.4.3", "1.2.840.113549"):
        advice, reason = infra.classify_ip(value)
        assert advice == infra.ADVICE_REVIEW, value
        assert "OID" in reason


def test_classify_ip_public_resolvers_skip():
    """公共递归解析器归属公开，向它们调证拿不到与本案有关的任何东西 → 不占预算。"""
    for value in ("223.5.5.5", "114.114.114.114", "8.8.8.8", "119.29.29.29", "120.53.53.53"):
        advice, _reason = infra.classify_ip(value)
        assert advice == infra.ADVICE_SKIP, value


def test_classify_ip_strips_port_suffix():
    """★不剥 ':port/proto' 尾缀，一切精确匹配都会被绕过（实测动态线索值就是这个形态）。"""
    assert infra.classify_ip("223.5.5.5:53/udp")[0] == infra.ADVICE_SKIP
    assert infra.classify_ip("114.114.114.114:53/udp")[0] == infra.ADVICE_SKIP
    assert infra.classify_ip("1.3.1.1:0/tcp")[0] == infra.ADVICE_REVIEW


def test_classify_ip_runtime_observed_exempts_shape_rules():
    """★设备上真连过就是地址，四段再小也不是版本号——形态判据一律让位于观测事实。"""
    advice, reason = infra.classify_ip("1.3.1.1", runtime_observed=True)
    assert advice == infra.ADVICE_INVESTIGATE
    assert "运行时" in reason
    # 但公共解析器与非全球地址仍先行判定（观测到不等于该调证）
    assert infra.classify_ip("223.5.5.5", runtime_observed=True)[0] == infra.ADVICE_SKIP
    assert infra.classify_ip("10.0.0.5", runtime_observed=True)[0] == infra.ADVICE_SKIP


def test_classify_ip_non_global_skips():
    for value in ("10.0.0.5", "127.0.0.1", "192.0.2.10", "198.18.0.8", "169.254.1.1"):
        assert infra.classify_ip(value)[0] == infra.ADVICE_SKIP, value


def test_m3w_cn_is_infra_skip():
    advice, reason = infra.classify_domain("m3w.cn")
    assert advice == infra.ADVICE_SKIP
    assert "m3w.cn" in reason


def test_library_embedded_does_not_touch_arbitrary_tld():
    # 任意 .com SLD（非枚举站点）仍建议调证，证明只精确后缀匹配。
    advice, _ = infra.classify_domain("evil-fraud-backend.com")
    assert advice == infra.ADVICE_INVESTIGATE


# --- C3：收紧 tier 假阳（框架/库/开发基础设施域名误判建议调证）-------------

# 这些是框架/库/开发基础设施的具体引用域名（非 C2），应判 ADVICE_SKIP。
_FRAMEWORK_INFRA_DOMAINS = (
    "flutter.dev", "flutter.io", "dart.io", "pub.dev", "dartbug.com",
    "baseflow.com", "dexterous.com", "golang.org", "go.dev", "googleapis.com",
    "gstatic.com", "mozilla.org", "openssl.org", "oracle.com", "tensorflow.org",
    "jetbrains.com", "github.com", "gitee.com", "dashif.org", "aomedia.org",
    "dolby.com", "dts.com", "sf.net", "w3.org", "apache.org", "curl.se",
    "iptc.org", "useplus.org", "open.gl", "g.co", "android.com",
    "androidplatform.net", "travisci.net",
)


def test_framework_infra_domains_skip():
    for dom in _FRAMEWORK_INFRA_DOMAINS:
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_SKIP, f"{dom} 应判框架/库基础设施 无需调证"


def test_framework_infra_subdomains_skip():
    # 子域同样命中（域边界后缀匹配，非裸 TLD 子串）。
    for dom in ("api.flutter.dev", "pkg.go.dev", "cdn.gstatic.com", "www.github.com"):
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_SKIP, f"{dom} 子域应命中框架基础设施"


def test_resolver_stun_ca_infra_skip():
    """★无修复即失败（2026-07-26 真案实测）：公共 DNS / DoH / STUN / 证书链域名不得判"建议调证"。

    修前两案报告把 dns.alidns.com、doh.pub、stun.*、crl.comodoca.com、entrust.net 等一并标成
    建议调证，还把闭环仅有的 6 个调证目标名额全占了，真候选 54 个一个没评估——办案人拿到的
    是一份指向证书吊销列表和公共 DNS 的"调证清单"。
    """
    for dom in ("dns.alidns.com", "doh.pub", "doh.360.cn", "myip.opendns.com",
                "resolvers-cn.httpdns.aliyuncs.com",
                "stun.cloudflare.com", "stun.freeswitch.org", "stun.voipbuster.com",
                "crl.comodoca.com", "crl.usertrust.com", "crl.globalsign.net",
                "entrust.net", "godaddy.com", "logo.verisign.com", "curl.haxx.se"):
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_SKIP, f"{dom} 应判基础设施 无需调证"


def test_real_c2_not_killed_by_framework_infra():
    # ★ 守卫：真可疑 C2 域名不得被新增条目误降为无需调证。
    for dom in ("aqecw.com", "mmybp.com", "bubdm.com", "91669.lol"):
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_INVESTIGATE, f"{dom} 应仍建议调证（真 C2 不得误杀）"


# --- C1：domain_source_tier 来源档 ---------------------------------------


def test_source_tier_library_file():
    loc = "assets/apps/X/www/uni_modules/lime-echart/static/echarts.min.js"
    assert infra.domain_source_tier(loc, 50) == infra.TIER_LIBRARY_FILE


def test_source_tier_min_js_glob():
    assert infra.domain_source_tier("assets/static/js/vendor.min.js", 50) == infra.TIER_LIBRARY_FILE


def test_source_tier_app():
    assert infra.domain_source_tier("assets/apps/X/www/app-service.js", 50) == infra.TIER_APP


def test_source_tier_bulk_string():
    # 超大字符串表（>=阈值）→ bulk-string。
    assert infra.domain_source_tier("dex_strings", 5000) == infra.TIER_BULK_STRING


def test_source_tier_app_short_string_normal_location():
    assert infra.domain_source_tier("AndroidManifest.xml", 100) == infra.TIER_APP


# --- C1：best_tier 合并 ---------------------------------------------------


def test_best_tier_app_beats_library():
    assert infra.best_tier(infra.TIER_APP, infra.TIER_LIBRARY_FILE) == infra.TIER_APP
    assert infra.best_tier(infra.TIER_LIBRARY_FILE, infra.TIER_APP) == infra.TIER_APP


def test_best_tier_library_beats_bulk():
    assert infra.best_tier(infra.TIER_LIBRARY_FILE, infra.TIER_BULK_STRING) == infra.TIER_LIBRARY_FILE


def test_best_tier_none_is_worst():
    assert infra.best_tier(None, infra.TIER_BULK_STRING) == infra.TIER_BULK_STRING
    assert infra.best_tier(infra.TIER_APP, None) == infra.TIER_APP


# --- A：XML 命名空间 / 框架常量噪音域名 → 无需调证（jadx 干扰收紧）------------


def test_xml_namespace_and_framework_const_domains_skip():
    # 反编译 Java 里的 XML 命名空间域 + Kotlin/Java 常量被误当域名，应判无需调证。
    for dom in (
        "ns.adobe.com", "xml.org", "xmlpull.org", "purl.org", "schema.org",
        "openxmlformats.org", "dispatchers.io", "locale.us",
    ):
        advice, _reason = infra.classify_domain(dom)
        assert advice == infra.ADVICE_SKIP, f"{dom} 应判 XML 命名空间/框架常量 无需调证"


def test_namespace_const_additions_dont_kill_real_c2():
    # 守卫：新增噪音条目不得误降真可疑域（含同后缀变体）。
    for dom in ("aqecw.com", "mmybp.com", "evil-adobe.com.cn", "fakexml.org.cn"):
        assert infra.classify_domain(dom)[0] == infra.ADVICE_INVESTIGATE, dom


# --- B：is_xml_namespace_url 命名空间 URI 识别 ----------------------------


def test_is_xml_namespace_url_true_for_namespace_uris():
    for u in (
        "http://ns.adobe.com/xap/1.0/",
        "http://xmlpull.org/v1/doc/features.html",
        "http://www.w3.org/2000/xmlns/",
        "http://schemas.android.com/apk/res/android",
        "http://purl.org/dc/elements/1.1/",
        "https://schemas.xmlsoap.org/soap/envelope/",
    ):
        assert infra.is_xml_namespace_url(u) is True, u


def test_is_xml_namespace_url_false_for_real_endpoints():
    for u in (
        "https://api.aqecw.com/login",
        "http://app-api2.bubdm.com/notify",
        "https://1358355812.cos.ap-chengdu.myqcloud.com/x.json",
        "",
    ):
        assert infra.is_xml_namespace_url(u) is False, u


# --- C：jadx 反编译第三方库包路径 → library-file（降待核）------------------


def test_source_tier_jadx_library_packages():
    for loc in (
        r"sources\org\xmlpull\v1\XmlPullParser.java",
        "sources/com/adobe/xmp/XMPMeta.java",
        "sources/kotlinx/coroutines/Dispatchers.java",
        "sources/org/apache/commons/io/IOUtils.java",
        "sources/androidx/core/app/NotificationCompat.java",
    ):
        assert infra.domain_source_tier(loc, 50) == infra.TIER_LIBRARY_FILE, loc


def test_source_tier_app_package_still_app():
    # App 自有包路径仍判 app（不被库包 glob 误降）。
    assert infra.domain_source_tier("sources/com/zmeiop/vsnmyuor/MainActivity.java", 50) == infra.TIER_APP
