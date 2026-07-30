"""第三方 SDK 与 DNS 基础设施噪音：解析器补档、站点适配表、.so 内嵌接入常量。

来自 2026-07-30 对 7 月 28 日一批样本的重跑核对。那批报告的「建议核查」出口里，有一大截
既不是该 App 的资产、也不可能被外人控制：

1. 某第三方库把**整份公共解析器清单**编进 DEX。名单原先只收了各服务商的默认档
   （OpenDNS 的 208.67.222.222），于是同一家的家庭过滤档（208.67.220.123）照旧被判
   建议核查——一个样本贡献 20 余条。
2. 同一批字符串里还有播放器/下载库内置的**站点适配表**（twitch / vimeo / coub / aparat）
   与视频标准组织域（smpte-ra）。
3. 厂商 SDK 把接入调度地址**硬编码进 .so**：两个不同案子、不同包名的样本，各自内嵌同样
   三个 IP、同处同一个厂商库文件——按"该特征是否为本样本独有"，它是 SDK 常量，不是资产。

★方向纪律沿用既有两档：可核实的公共基础设施 → 无需核查；来源可疑但**地址本身可能是真后端**
  的（.so 内嵌常量）→ 只降待核，绝不判无需核查。第 3 类判 SKIP 就等于替人下结论，
  而自带 .so 的样本把后端烙在库里是真实存在的形态。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra
from apkscan.core.leads import _vendor_sdk_constant, _vendor_sdk_libraries, build_endpoint_leads
from apkscan.core.models import Endpoint, Evidence

_INV = infra.ADVICE_INVESTIGATE
_SKIP = infra.ADVICE_SKIP
_REVIEW = infra.ADVICE_REVIEW

#: 厂商 SDK 库：多 ABI 各一份拷贝，判据须把它们折成同一个来源。
_LIB_A64 = "lib/arm64-v8a/libDingRtc.so"
_LIB_A32 = "lib/armeabi-v7a/libDingRtc.so"

#: 该 SDK 自己的域名（命中 KNOWN_INFRA），用来认出这个库是厂商 SDK 的二进制。
_SDK_DOMAINS = ("gslb.dingrtc.com", "portal-hz.mcs.dingtalk.com")  # leak-scan: allow 判据夹具：SDK 自有域名，用于认出厂商库

#: 与上面域名同处一个库文件的裸地址。实测在两个不同案子的样本里同现。
_SDK_IPS = ("198.51.100.11", "198.51.100.12", "198.51.100.13")  # leak-scan: allow 判据夹具：与 SDK 自有域名同处一 .so 的内嵌常量，测的正是该来源判据


def _ep(kind: str, value: str, *locations: str) -> Endpoint:
    return Endpoint(
        kind=kind,
        value=value,
        evidences=[Evidence(source="static", location=loc, snippet=value) for loc in locations],
    )


def _sdk_sample() -> list[Endpoint]:
    """一个厂商 SDK 库同时贡献自有域名与内嵌地址的端点集合。"""
    eps = [_ep("domain", d, _LIB_A64, _LIB_A32) for d in _SDK_DOMAINS]
    eps += [_ep("ip", v, _LIB_A64, _LIB_A32) for v in _SDK_IPS]
    return eps


# ---------------------------------------------------------------------------
# 1. 公共解析器补档 + 权威 NS：可核实的 DNS 基础设施 → 无需核查
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "208.67.220.123",   # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "208.67.222.123",   # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "185.228.168.168",  # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "185.228.169.168",  # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "199.85.126.10",    # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "199.85.127.10",    # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "209.244.0.3",      # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "209.244.0.4",      # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "216.146.35.35",    # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "216.146.36.36",    # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "77.88.8.88",       # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "77.88.8.2",        # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "195.46.39.39",     # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "168.95.1.1",       # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "168.95.192.1",     # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "80.80.80.80",      # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
    "80.80.81.81",      # leak-scan: allow 公共解析器名单夹具，判据测的就是该地址被识别为解析器
])
def test_filtering_tier_resolvers_leave_the_list(value: str) -> None:
    """★同一服务商的过滤档/家庭档与默认档同属基础设施，不能只收默认档。"""
    advice, reason = infra.classify_ip(value)
    assert advice == _SKIP, f"{value} 仍判 {advice}"
    assert "解析器" in reason


@pytest.mark.parametrize("value", [
    "205.251.193.186",  # leak-scan: allow 权威 NS 名单夹具，判据测的就是该地址被识别为托管商 NS
    "205.251.194.188",  # leak-scan: allow 权威 NS 名单夹具，判据测的就是该地址被识别为托管商 NS
    "205.251.197.22",   # leak-scan: allow 权威 NS 名单夹具，判据测的就是该地址被识别为托管商 NS
    "205.251.199.99",   # leak-scan: allow 权威 NS 名单夹具，判据测的就是该地址被识别为托管商 NS
])
def test_authoritative_ns_hosts_leave_the_list(value: str) -> None:
    """域名托管商的权威 NS：DNS 基础设施，向托管商查它与本样本无关。"""
    advice, reason = infra.classify_ip(value)
    assert advice == _SKIP, f"{value} 仍判 {advice}"
    assert "权威 DNS" in reason


def test_ns_range_neighbours_are_not_whitelisted_wholesale() -> None:
    """★只放行实测见过的地址，不按网段整段放行。

    整段放行等于凭记忆断言"这个 /21 全是某厂商 NS"——本仓没有可离线核对的官方前缀表。
    同网段里没见过的地址必须照旧进出口，让人看一眼。
    """
    assert infra.classify_ip("205.251.200.1")[0] == _INV  # leak-scan: allow 边界夹具：同网段但未实测见过，必须照旧进出口
    assert infra.classify_ip("205.251.192.7")[0] == _INV  # leak-scan: allow 边界夹具：同网段但未实测见过，必须照旧进出口


# ---------------------------------------------------------------------------
# 2. 播放器站点适配表 / 标准组织域 → 无需核查
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "api.twitch.tv",       # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
    "usher.ttvnw.net",     # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
    "player.vimeo.com",    # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
    "coub.com",            # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
    "www.aparat.com",      # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
    "www.smpte-ra.org",    # leak-scan: allow 站点适配表夹具，验该域已挪出建议核查出口
])
def test_player_site_table_domains_leave_the_list(domain: str) -> None:
    """播放器/下载库内置的站点适配表与视频标准组织域，都不是该 App 的后端。"""
    advice, reason = infra.classify_domain(domain)
    assert advice == _SKIP, f"{domain} 仍判 {advice}"
    assert "第三方" in reason


@pytest.mark.parametrize("domain", [
    "faketwitch.tv",           # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "vimeo.com.attacker.top",  # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
    "my-coub.com",             # leak-scan: allow 边界攻击夹具，验名单按域边界而非子串匹配
])
def test_new_site_table_entries_keep_domain_boundaries(domain: str) -> None:
    """构造成"含已知域"的可疑域名必须照旧进出口。"""
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 被名单误吞"


# ---------------------------------------------------------------------------
# 3. 厂商 SDK 库内嵌的接入常量 → 只降待核
# ---------------------------------------------------------------------------


def test_vendor_library_recognised_by_its_own_domains() -> None:
    """认库靠的是"这个 .so 里有 ≥2 个已知第三方基础设施域名"，且多 ABI 折成一个名字。"""
    libs = _vendor_sdk_libraries(_sdk_sample())
    assert libs == {"libdingrtc.so"}


def test_single_known_domain_is_not_enough_to_recognise_a_vendor_library() -> None:
    """★门槛取 2：塞一个已知域名就能让同文件里的真后端降档，那道门等于没有。"""
    eps = [
        _ep("domain", _SDK_DOMAINS[0], _LIB_A64),
        _ep("ip", _SDK_IPS[0], _LIB_A64),
    ]
    assert _vendor_sdk_libraries(eps) == set()
    leads = {l.value: l for l in build_endpoint_leads(eps, online=False)}
    assert leads[_SDK_IPS[0]].advice == _INV, "只有一个已知域名时不得降档"


def test_wired_vendor_sdk_constant_drops_to_review() -> None:
    """★接线锁：build_endpoint_leads 必须自己认出厂商库并把库名传给 classify_ip。

    只退 leads 侧接线（infra 的参数留着）时，单元层仍全绿而本测试必红——正是
    "参数加了但没人传"的形态。
    """
    leads = {l.value: l for l in build_endpoint_leads(_sdk_sample(), online=False)}

    for ip in _SDK_IPS:
        assert leads[ip].advice == _REVIEW, f"{ip} 仍判 {leads[ip].advice}"
        assert "libdingrtc.so" in (leads[ip].notes or ""), "理由须写明来源库，人才捞得回"


def test_vendor_sdk_constant_never_becomes_skip() -> None:
    """★只降待核：自带 .so 的样本也可能把真后端烙在库里，判无需核查就是替人下结论。"""
    leads = {l.value: l for l in build_endpoint_leads(_sdk_sample(), online=False)}
    for ip in _SDK_IPS:
        assert leads[ip].advice != _SKIP


def test_extra_evidence_outside_the_library_blocks_the_demotion() -> None:
    """还有别的来源（dex 串/资源/运行时）就不只是 SDK 常量——判据不适用，留在出口里。"""
    eps = _sdk_sample()
    eps.append(_ep("ip", "8.210.13.45", _LIB_A64, "classes.dex"))  # leak-scan: allow 边界夹具：证据跨库与 dex 两源，验降档判据不适用
    got = _vendor_sdk_constant(eps[-1], _vendor_sdk_libraries(eps))
    assert got == ""
    leads = {l.value: l for l in build_endpoint_leads(eps, online=False)}
    assert leads["8.210.13.45"].advice == _INV  # leak-scan: allow 边界夹具：证据跨库与 dex 两源，验降档判据不适用


def test_runtime_observation_outranks_the_library_provenance() -> None:
    """设备上真连过就是真连过——来源判据不得盖掉运行时观测。"""
    advice, reason = infra.classify_ip(
        _SDK_IPS[0], runtime_observed=True, vendor_sdk_binary="libdingrtc.so"
    )
    assert advice == _INV
    assert "运行时" in reason
