"""静态域名降噪：把不可能是调证对象的东西挪出「建议调证」。

实测（2026-07-28 四案）：某报告有 74 条「建议调证」，里面大量是 SDK 遥测域、文档占位串。
``max_targets`` 截断后，真业务节点可能一条都进不去五层归属。

★方向纪律：降噪走在**漏报**方向上，所以分两档、绝不一刀切——
- 可核实的第三方 SDK 自有域 → 无需调证（团伙控制不了 bytedance.com 的子域）；
- 形态可疑但**可注册**的（占位词、保留后缀）→ 只降待核，绝不判「无需调证」。
  判「无需调证」等于替办案人下「与本案无关」的结论；一个真 C2 就此被藏起来，
  换来的那点清单长度不值。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra

_INV = infra.ADVICE_INVESTIGATE
_SKIP = infra.ADVICE_SKIP
_REVIEW = infra.ADVICE_REVIEW


# ---------------------------------------------------------------------------
# 第三方 SDK：可核实归属 → 无需调证
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "arv.pangolin-sdk-toutiao.com",  # 穿山甲广告
    "is.snssdk.com",                 # 字节应用日志
    "mon.zijieapi.com",              # 字节监控
    "dig.bdurl.net",
    "sdk.51.la",                     # 51LA 统计
    "tpstelemetry.tencent.com",      # 腾讯 TPS 遥测
    "api.weibo.com",                 # 微博开放平台
    "static.ws.126.net",             # 网易静态资源
])
def test_third_party_sdk_hosts_are_not_subpoena_targets(domain: str) -> None:
    """这些域归属可核实、团伙控制不了，占着调证清单纯属噪音。"""
    advice, reason = infra.classify_domain(domain)
    assert advice == _SKIP, f"{domain} 仍在调证清单里"
    assert "第三方" in reason


@pytest.mark.parametrize("domain", [
    # 实测：这六个良性域名全部落进「建议核查」出口。前四个归属可核实、其子域不可能被
    # 外人控制；后两个是编译期烙进 native 字符串表的**文档/官网 URL**，不是端点。
    "gslb.dingrtc.com",            # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "portal-hz.mcs.dingtalk.com",  # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "www.alibaba.com",             # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "www.taobao.com",              # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "www.trustcenter.de",          # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "www.winimage.com",            # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
])
def test_vendor_and_toolchain_hosts_are_not_subpoena_targets(domain: str) -> None:
    """厂商自有服务域 + 编译期烙进二进制的官网/文档 URL，都不是可落地核查的对象。

    最典型的是名单里那个 CA 官网与 minizip 作者站（后者来自 zlib 附带的 minizip 源码
    注释）：它们从来不是 App 连接的地址，是**源码注释被编进字符串表**的产物，占着出口
    名额还会把真候选挤出 ``max_targets``。
    """
    advice, reason = infra.classify_domain(domain)
    assert advice == _SKIP, f"{domain} 仍判 {advice}"
    assert "第三方" in reason


@pytest.mark.parametrize("domain", [
    "appgallery.huawei.com",         # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "api.huangye.miui.com",          # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "global.api.huangye.miui.com",   # leak-scan: allow 判据夹具，验父域条目按域边界覆盖其子域
    "app.mibi.xiaomi.com",           # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "file.market.xiaomi.com",        # leak-scan: allow 判据夹具，验该域已挪出建议核查出口
    "www.stripe.com",                # leak-scan: allow 判据夹具，验官网主机名已挪出建议核查出口
])
def test_vendor_store_and_wallet_hosts_are_not_subpoena_targets(domain: str) -> None:
    """手机厂商的应用市场 / 钱包 / 黄页与一家支付服务：归属事先已知，没有核查价值。

    ★判的是「归属无需再核」，不是「这条信息没用」——样本里出现钱包或应用市场链接本身仍是
      有意义的观察，它照常留在报告里，只是不再作为「向谁核这个域名归谁」的目标。
    """
    advice, reason = infra.classify_domain(domain)
    assert advice == _SKIP, f"{domain} 仍判 {advice}"
    assert "第三方" in reason


@pytest.mark.parametrize("domain", [
    "xiaomi.com",                       # leak-scan: allow 判据夹具，验厂商主域未被整体放行
    "huawei.com",                       # leak-scan: allow 判据夹具，验厂商主域未被整体放行
    "unknown-service.xiaomi.com",       # leak-scan: allow 判据夹具，验只放行具体子域而非整域
    "some-other.huawei.com",            # leak-scan: allow 判据夹具，验只放行具体子域而非整域
])
def test_phone_vendor_root_domains_stay_subpoena_targets(domain: str) -> None:
    """★只放行具体子域，**绝不放行**这两家的主域。

    理由与钉钉那条同源，但这里多一层：两家主域下都有对象存储端点。主域整体列入后，凡是
    租户桶判据没覆盖到的写法都会掉进整域豁免被静默吃掉——那正是本模块刚修过的那类缺陷。

    ★两层都断言：先直接锁「主域不在名单匹配范围内」，再锁最终档位。只锁后者是间接的——
      日后若新增一条更早的特判把这些域名判成建议核查，即便有人误把主域加进名单，测试仍会绿。
    """
    assert infra._matched_infra(domain) is None, f"{domain} 落进了已知基础设施名单的匹配范围"
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 被整域豁免吞掉了"


def test_exact_host_entry_covers_the_root_but_not_its_subdomains() -> None:
    """★精确匹配语义：根域豁免、子域一概不豁免。

    这条语义是为「根域是官网、子域却承载租户资源」那类域专设的。只用后缀匹配时两个选择
    都不对：整域列入吃掉租户资源，完全不列则官网根域一直占着核查清单。

    ★同时锁住它**不会**泄漏成后缀匹配——任意子域、右侧追加、标签粘连都不得命中。
    """
    assert infra._matched_infra("stripe.com") == "stripe.com"  # leak-scan: allow 判据夹具，验精确条目命中根域自身

    for other in (
        "evil.stripe.com",           # leak-scan: allow 判据夹具，验精确条目不泄漏到任意子域
        "stripe.com.attacker.top",   # leak-scan: allow 判据夹具，验精确条目不被右侧追加绕过
        "notstripe.com",             # leak-scan: allow 判据夹具，验精确条目不被标签粘连绕过
    ):
        assert infra._matched_infra(other) is None, f"精确条目泄漏到了 {other}"


@pytest.mark.parametrize("host", [
    "buy.stripe.com",       # leak-scan: allow 判据夹具，验租户级收款页未被整域豁免吞掉
    "checkout.stripe.com",  # leak-scan: allow 判据夹具，验租户级收款页未被整域豁免吞掉
    "invoice.stripe.com",   # leak-scan: allow 判据夹具，验租户级收款页未被整域豁免吞掉
])
def test_payment_tenant_pages_stay_subpoena_targets(host: str) -> None:
    """★这家只放行官网主机名，**绝不放行整域**——租户控制在 URL 路径上，不在 DNS 上。

    商户自建的收款页（含托管账单，其 URL 直接带商户账号标识）都挂在这几个固定子域下。
    整域列入会把「涉案收款通道」这类最该核的线索一起判成无需核查，而分类器只看主机名，
    事后没有任何护栏能把它们捞回来——这与对象存储那种「租户在主机名里」的形态不是一回事，
    tenant_bucket 那道前置护栏在这里帮不上忙。
    """
    assert infra._matched_infra(host) is None, f"{host} 落进了名单匹配范围（整域被误列？）"
    assert infra.classify_domain(host)[0] == _INV, f"租户级收款页被判成无需核查：{host}"


@pytest.mark.parametrize("endpoint", [
    "obs.cn-north-4.myhuaweicloud.com",          # leak-scan: allow 判据夹具，验租户桶端点未被整域条目吞掉
    "obs-cn-north-4.myhuaweicloud.com",          # leak-scan: allow 判据夹具，验另一种连字符写法同样受护
    "obs-website.cn-north-4.myhuaweicloud.com",  # leak-scan: allow 判据夹具，验静态网站端点写法同样受护
])
def test_vendor_tenant_buckets_survive_the_new_entries(endpoint: str) -> None:
    """★厂商域已在名单里的那家，其对象存储桶必须仍留在核查出口。

    第三种写法（静态网站端点，比常规写法多一段区域标签）此前不匹配租户桶判据，正被整域
    条目吃着——那是现实风险而非构造，也正是「不列主域」这条约束的实证。

    ★这里不再拿另一家的 host-style 写法当用例：那家公开的接口是 path-style（桶在 URL 路径
      里而非主机名里），按主机名构造的形态找不到公开依据，当实证用是虚的。
    """
    domain = f"0123456789abcdef.{endpoint}"
    assert infra.tenant_bucket(domain) is not None, f"桶形态没被认出：{domain}"
    assert infra.classify_domain(domain)[0] == _INV, f"租户桶被整域豁免吃掉：{domain}"


@pytest.mark.parametrize("endpoint", [
    "obs.cn-north-4.internal.myhuaweicloud.com",           # leak-scan: allow 判据夹具，验端点尾部不接受额外标签
    "obs-website-cn-north-4.internal.myhuaweicloud.com",   # leak-scan: allow 判据夹具，验静态网站端点无连字符写法
])
def test_undocumented_endpoint_shapes_are_not_treated_as_buckets(endpoint: str) -> None:
    """★补上一种写法时不得顺手放宽尾部：两种官方结构分别写死，别给它们统一加可选标签。

    统一追加可选标签会顺带接受这类没有公开依据的形态，等于把刚收紧的宽度又放回去——
    认下来就是凭空造出一个查不到租户的目标。
    """
    domain = f"0123456789abcdef.{endpoint}"
    assert infra.tenant_bucket(domain) is None, f"未公开的端点形态被当成了租户桶：{domain}"


@pytest.mark.parametrize("domain", [
    "xiaomi-pay.top",                    # leak-scan: allow 边界攻击夹具，验名单不含无点关键字
    "huawei-app.vip",                    # leak-scan: allow 边界攻击夹具，验名单不含无点关键字
    "stripe-pay.top",                    # leak-scan: allow 边界攻击夹具，验名单不含无点关键字
    "appgallery.huawei.com.evil.tld",    # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "notstripe.com",                     # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
])
def test_vendor_lookalike_domains_still_investigated(domain: str) -> None:
    """★名单里刻意不写无点关键字：那会走子串匹配，把可被任意注册的近似域一并判成无需核查。"""
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 被名单误吞"


def test_dingtalk_robot_channel_host_stays_a_subpoena_target() -> None:
    """★只放行钉钉推送长连接子域，**不放行**主域——群机器人 webhook 必须留在出口里。

    ``oapi`` 子域下的 ``/robot/send`` 是实测见过的外发通道（analyzers/contacts.py 有归属
    条目）。上面那条把 ``mcs`` 子域挪出出口时若图省事写成整个主域，这条通道会被一起判成
    "无需核查"藏起来——漏报方向，代价换不来清单短一行。
    """
    advice, _reason = infra.classify_domain("oapi.dingtalk.com")  # leak-scan: allow 判据夹具，验钉钉主域未被整体放行
    assert advice == _INV


@pytest.mark.parametrize("domain", [
    "evil163.com.cn",       # 后缀边界攻击：不得因 163.com 在名单里就被放过
    "not163.com",
    "fake-bytedance.com",
    "snssdk.com.attacker.top",
    "myweibo.com",
    "faketaobao.com",              # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "taobao.com.attacker.top",     # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "notmcs.dingtalk.com",         # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "evil-dingrtc.com",            # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
])
def test_suffix_boundary_attacks_still_investigated(domain: str) -> None:
    """★名单按域边界匹配，不是子串。构造成"含已知域"的真 C2 必须照旧进调证清单。"""
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 被名单误吞"


# ---------------------------------------------------------------------------
# 标准保留后缀：不可注册 → 但只降待核
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "foo.test", "bar.invalid", "printer.local", "svc.localhost",
    "localhost.localdomain", "gw.home.arpa", "anything.example",
])
def test_reserved_suffixes_leave_the_subpoena_list(domain: str) -> None:
    """RFC 2606/6761/6762/8375 保留后缀：不存在注册人，没有调证对象。"""
    advice, reason = infra.classify_domain(domain)
    assert advice == _REVIEW, f"{domain} 仍判 {advice}"
    assert "保留" in reason


def test_reserved_suffixes_are_never_skipped_outright() -> None:
    """★只降待核、不判无需调证：留在清单里给人看一眼。

    一个没填完的模板域名本身也是团伙工具链的线索；判"无需调证"是替人下了结论。
    """
    for d in ("foo.test", "printer.local", "localhost.localdomain"):
        assert infra.classify_domain(d)[0] != _SKIP


def test_example_com_is_deliberately_untouched() -> None:
    """★``example.com`` 同为保留域，但本仓库拿它当测试与合成回归语料的中性替身。

    特殊对待它会连带改掉检出基线与多处富化 fixture——那是一次单独的决定，不该顺手夹带在
    降噪里做掉。这条测试把「刻意没做」钉成明确契约，免得日后被当成漏了。
    """
    assert infra.classify_domain("api.example.com")[0] == _INV
    assert infra.classify_domain("pay.example.com")[0] == _INV


# ---------------------------------------------------------------------------
# 占位 SLD：可注册 → 只降待核
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "yourdomain.com", "your-domain.com", "mydomain.com",
    "domain.com", "xxx.com", "abc.com", "website.com", "placeholder.com",
])
def test_boilerplate_placeholders_drop_to_review(domain: str) -> None:
    """SDK 文档/脚手架里的占位 SLD——**都是真实在册域名**，故只降待核。"""
    advice, reason = infra.classify_domain(domain)
    assert advice == _REVIEW, f"{domain} 仍判 {advice}"
    assert "人工核" in reason


@pytest.mark.parametrize("domain", [
    "api.yourdomain.com",   # 有子域 → 不是占位形态，可能是真业务
    "xxx.evil-c2.top",
    "mytest.com",           # 不在词表里
    "hxhcapi.vip",
    # ★三段形态里最容易误伤的一类：``<占位词>.com.cn`` 是**可注册的真实域名**。
    #   判据一旦放宽到"至少两段"，parts[0] 是占位词、parts[1] 恰是 com/net，
    #   这些真域名就被整批降成待核——漏报方向，且极隐蔽。
    "api.com.cn",
    "test.com.cn",
    "log.net.cn",
])
def test_placeholder_rule_needs_the_bare_two_part_shape(domain: str) -> None:
    """★占位判据只认「单词 + 通用 TLD 且**无子域**」。

    带子域的形态是正常业务命名，一并降级会把真后端埋进人工堆——漏报方向。
    """
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 被占位判据误伤"
