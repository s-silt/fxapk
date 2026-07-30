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
