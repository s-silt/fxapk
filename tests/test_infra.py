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


def test_m3w_cn_is_infra_skip():
    advice, reason = infra.classify_domain("m3w.cn")
    assert advice == infra.ADVICE_SKIP
    assert "m3w.cn" in reason


def test_library_embedded_does_not_touch_arbitrary_tld():
    # 任意 .com SLD（非枚举站点）仍建议调证，证明只精确后缀匹配。
    advice, _ = infra.classify_domain("evil-fraud-backend.com")
    assert advice == infra.ADVICE_INVESTIGATE


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
