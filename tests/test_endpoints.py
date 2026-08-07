"""EndpointsAnalyzer 的单测：用 conftest 的 FakeContext 喂合成数据。

覆盖：
- 基本属性 name/requires。
- 四路来源（dex / resource / native / manifest）各能抽出端点并标 source。
- URL / 域名 / IP 三种 kind 的识别。
- is_cleartext（http://）/ is_private（RFC1918 等）标记。
- 同 value 去重合并 evidences；标志位取并集。
- 噪音过滤（xmlns / schemas.android.com / w3.org / 命名空间 URI）。
- 类名/包名/文件名不被误判为域名（JPushInterface / com.tencent.mm / config.json）。
- ★ 契约：只产 Endpoint，不产任何 Lead；findings 为空。
- 不命中（无网络字符串）→ 空端点。
- 鲁棒性：单数据源（dex_strings / list_files / native_libs / read_file）抛异常不炸整个 analyze。
- fixture 样例上下文能正确产出端点。
"""

from __future__ import annotations

from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.core.models import AnalyzerResult, Endpoint

from tests.conftest import FakeContext


def _analyze(
    *,
    manifest_xml: str = "",
    files: dict[str, bytes] | None = None,
    dex_strings: list[str] | None = None,
    native_libs: list[str] | None = None,
    platform: str = "android",
) -> AnalyzerResult:
    ctx = FakeContext(
        manifest_xml=manifest_xml,
        files=files,
        dex_strings=dex_strings,
        native_libs=native_libs,
        platform=platform,
    )
    return EndpointsAnalyzer().analyze(ctx)


def _by_value(result: AnalyzerResult) -> dict[str, Endpoint]:
    return {ep.value: ep for ep in result.endpoints}


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires():
    analyzer = EndpointsAnalyzer()
    assert analyzer.name == "endpoints"
    assert analyzer.requires == []


# --- 不命中 ---------------------------------------------------------------


def test_no_network_strings_yields_no_endpoints():
    result = _analyze(
        dex_strings=["com.example.app.MainActivity", "just a label", "1234"],
        files={"res/layout/main.xml": b"<LinearLayout/>"},
    )
    assert result.error is None
    assert result.endpoints == []
    assert result.leads == []
    assert result.findings == []
    assert result.meta["endpoint_total"] == 0


# --- ★ 契约：只产 Endpoint，不产 Lead（普通输入不产 Finding） ---------------


def test_ordinary_endpoints_emit_no_lead_or_finding():
    result = _analyze(
        dex_strings=[
            "https://pay.fraud-gw.cn/notify",
            "http://10.0.0.8/admin",
            "139.59.12.34",  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
        ]
    )
    # 端点应有，但绝不产 Lead（DOMAIN/IP Lead 由 pipeline 富化后统一建）；
    # 无「非标准回环 + native」组合 → 也不产回环占位 Finding。
    assert result.endpoints
    assert result.leads == []
    assert result.findings == []


# --- ★ 回环占位启发式（A3）：native 运行时取址架构 ------------------------


def test_nonstandard_loopback_plus_native_emits_placeholder_finding():
    """★硬编码非标准回环 IP（127.0.209.162）+ native 库 → 产「native 运行时取址占位」Finding。"""
    result = _analyze(
        dex_strings=["backend=127.0.209.162", "some.label"],
        native_libs=["lib/arm64-v8a/libclientcore.so"],
    )
    fids = [f.id for f in result.findings]
    assert "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER" in fids
    f = next(f for f in result.findings if f.id == "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER")
    assert f.category == "anti_analysis"
    assert "127.0.209.162" in f.description


def test_loopback_without_native_no_finding():
    """★无 native 库 → 不产 Finding（缺架构前提，不误报）。"""
    result = _analyze(dex_strings=["backend=127.0.209.162"], native_libs=[])
    assert all(f.id != "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER" for f in result.findings)


def test_standard_localhost_not_flagged():
    """★标准 127.0.0.1（localhost）+ native → 不产 Finding（常见本地引用，噪声大不采）。"""
    result = _analyze(dex_strings=["proxy=127.0.0.1"], native_libs=["lib/arm64-v8a/libx.so"])
    assert all(f.id != "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER" for f in result.findings)


def test_loopback_manifest_only_evidence_source_is_manifest():
    """★P1 无修复即失败：回环 IP **只**来自 manifest 原文 → 证据 source 须为 "manifest"（不再恒记 "dex"）。"""
    result = _analyze(
        dex_strings=["nothing.here"],  # dex 无回环
        manifest_xml='<manifest><meta-data android:value="127.0.209.162"/></manifest>',
        native_libs=["lib/arm64-v8a/libclientcore.so"],
    )
    f = next(f for f in result.findings if f.id == "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER")
    srcs = {e.source for e in f.evidences}
    assert srcs == {"manifest"}  # 修前恒 "dex" → 此断言必失败


def test_loopback_regex_rejects_dotted_version_prefix():
    """★P1 无修复即失败：形如 127.2.3.4.5 的版本/多段串**不得**被当回环 IP（\\b 会误取前缀 127.2.3.4）。

    仅此一条"回环样"串 + native 库：修前正则取到 127.2.3.4 → 误产 Finding；修后独立性前后瞻拒之 → 无 Finding。
    """
    result = _analyze(
        dex_strings=["build.version=127.2.3.4.5"],
        native_libs=["lib/arm64-v8a/libclientcore.so"],
    )
    assert all(f.id != "NATIVE-RUNTIME-ADDRESSING-PLACEHOLDER" for f in result.findings)


# --- dex 来源：URL / IP / 域名 -------------------------------------------


def test_dex_url_extracted_with_source():
    result = _analyze(dex_strings=["api base: https://api.fraud-gw.cn/v1/pay"])
    eps = _by_value(result)
    assert "https://api.fraud-gw.cn/v1/pay" in eps
    ep = eps["https://api.fraud-gw.cn/v1/pay"]
    assert ep.kind == "url"
    assert ep.is_cleartext is False
    assert any(ev.source == "dex" for ev in ep.evidences)


def test_dex_bare_domain_extracted():
    result = _analyze(dex_strings=["host=cdn.heika-pay.cn"])
    eps = _by_value(result)
    assert "cdn.heika-pay.cn" in eps
    assert eps["cdn.heika-pay.cn"].kind == "domain"


def test_dex_ipv4_extracted():
    result = _analyze(dex_strings=["connect 139.59.12.34:443"])  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    eps = _by_value(result)
    assert "139.59.12.34" in eps  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    ep = eps["139.59.12.34"]  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert ep.kind == "ip"
    assert ep.is_private is False


# --- 明文标记（http://）--------------------------------------------------


def test_cleartext_http_url_flagged():
    result = _analyze(dex_strings=["http://gw.heika-pay.cn/notify"])
    ep = _by_value(result)["http://gw.heika-pay.cn/notify"]
    assert ep.kind == "url"
    assert ep.is_cleartext is True


def test_https_url_not_cleartext():
    result = _analyze(dex_strings=["https://gw.heika-pay.cn/notify"])
    ep = _by_value(result)["https://gw.heika-pay.cn/notify"]
    assert ep.is_cleartext is False


# --- 私网标记 ------------------------------------------------------------


def test_bare_private_rfc1918_ip_filtered():
    # C4 新语义：裸的私网/保留 IP 无调证价值，直接不产端点（区别于旧"产出+标私网"）。
    for ip in ("10.0.0.5", "192.168.1.100", "172.16.5.9", "169.254.1.1"):
        result = _analyze(dex_strings=[f"server {ip}"])
        assert ip not in _by_value(result), f"裸 {ip} 应被 C4 过滤不产端点"


def test_private_host_in_url_still_flagged():
    # URL host 内的私网 IP 仍产端点并标私网（host 通道不受裸 IP 过滤影响）。
    result = _analyze(dex_strings=["http://10.0.0.5:8080/admin"])
    eps = _by_value(result)
    assert eps["10.0.0.5"].is_private is True


def test_loopback_private_and_network_addr_filtered():
    # C4 新语义：裸 127.0.0.1 / 0.0.0.0 / x.x.x.0 全作保留/网络地址噪音被过滤，不产端点。
    result = _analyze(dex_strings=["bind 127.0.0.1", "any 0.0.0.0", "net 10.0.0.0"])
    eps = _by_value(result)
    assert "127.0.0.1" not in eps
    assert "0.0.0.0" not in eps
    assert "10.0.0.0" not in eps


def test_loopback_in_url_still_extracted():
    # URL 形式 http://127.0.0.1/ 仍产 IP 端点（host 通道）。
    result = _analyze(dex_strings=["http://127.0.0.1/health"])
    assert "127.0.0.1" in _by_value(result)


def test_version_and_placeholder_ips_filtered():
    # C4：版本号被当 IP（13.3.3.7 / 2.1.5.1 / 3.2.16.7）+ 占位 IP（1.2.3.4）裸出现 → 不产端点。
    result = _analyze(
        dex_strings=["v13.3.3.7", "ver 2.1.5.1", "sdk 3.2.16.7", "addr 1.2.3.4"]
    )
    eps = _by_value(result)
    for ip in ("13.3.3.7", "2.1.5.1", "3.2.16.7", "1.2.3.4"):
        assert ip not in eps, f"{ip} 应被 noise_ips 过滤"


def test_real_public_ips_kept():
    # C4 回归锁：真实公网 IP 不在 denylist、非保留段 → 保留（不得误杀）。
    # 注：原用例拿 8.8.8.8 当"真实公网 IP"的例子，但它是公共 DNS 解析器、已入 noise_ips
    #     （见下条测试的实测理由），故换成不具解析器身份的公网 IP，本意不变。
    result = _analyze(dex_strings=["c2 139.59.12.34", "backend 45.11.22.33"])  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    eps = _by_value(result)
    assert "139.59.12.34" in eps  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert "45.11.22.33" in eps  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert eps["139.59.12.34"].is_private is False  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面


def test_url_derived_resolver_ip_also_filtered():
    """★无修复即失败：URL 里的解析器 IP 同样要过 noise_ips。

    实测：`https://1.12.12.12/dns-query`（公共 DoH）从 URL 通道绕过了裸 IP 的 denylist，
    仍被判"建议调证"并占用闭环调证名额。同一个值不能因来源不同而结论不一致。
    """
    result = _analyze(dex_strings=[
        "https://1.12.12.12/dns-query", "https://1.1.1.1/dns-query",
        "http://139.59.12.34:8080/api",  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    ])
    vals = {e.value for e in result.endpoints}
    assert "1.12.12.12" not in vals and "1.1.1.1" not in vals
    assert "139.59.12.34" in vals, "真后端 IP 不得被误杀"  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert "http://139.59.12.34:8080/api" in vals, "URL 本身仍应保留"  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面


def test_url_host_with_bogus_tld_not_emitted_as_domain():
    """★无修复即失败（2026-07-26 真案实测）：URL 里 host 的 TLD 不可信 → 不派生 domain 端点。

    .so 的 ASCII 串被分块切分时，`http://www.<词>…` 会在中途断掉，留下 `http://www.hortcut`
    这种残片。裸域名通道有 TLD 白名单挡着、URL 通道却没有，于是 `http://www.任意小写词` 都能
    派生出"域名端点"，还带 tier=app 被判"建议调证"，直接污染调证清单。
    """
    result = _analyze(dex_strings=[
        "http://www.hortcut", "http://www.years", "http://www.wencodeuricomponent",
        "http://www.interpretation", "http://www.recent",
        "https://real-c2.top/api", "http://backend.example-c2.cc/x",
    ])
    vals = {e.value for e in result.endpoints}
    for bogus in ("www.hortcut", "www.years", "www.wencodeuricomponent",
                  "www.interpretation", "www.recent"):
        assert bogus not in vals, f"{bogus} 的 TLD 不可信，不应派生 domain 端点"
    # ★真 C2 常用 TLD（.top / .cc）必须保留——判据用 _COMMON_TLDS 而非更窄的 _SAFE_BARE_TLDS
    assert "real-c2.top" in vals, ".top 是真 C2 常用 TLD，不得误杀"
    assert "backend.example-c2.cc" in vals, ".cc 是真 C2 常用 TLD，不得误杀"


def test_public_dns_resolver_ips_filtered():
    """★无修复即失败（2026-07-26 真案实测）：公共 DNS 解析器 IP 裸出现 → 不产端点。

    修前报告把 1.1.1.1 / 1.12.12.12 / 203.107.1.1 等判成"建议调证"，且因闭环目标排序在
    纯静态报告上塌缩为按字符串排，这些以 "1." 开头的解析器 IP 恰好排最前，把仅有的 6 个调证
    目标名额全占了，真候选 54 个一个没评估。向解析器运营方调证毫无意义。
    """
    result = _analyze(dex_strings=[
        "dns 8.8.8.8", "dns 1.1.1.1", "dns 114.114.114.114", "dns 223.5.5.5",
        "dns 119.29.29.29", "dns 1.12.12.12", "httpdns 203.107.1.1", "c2 139.59.12.34",  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    ])
    eps = _by_value(result)
    for ip in ("8.8.8.8", "1.1.1.1", "114.114.114.114", "223.5.5.5",
               "119.29.29.29", "1.12.12.12", "203.107.1.1"):
        assert ip not in eps, f"{ip} 是公共 DNS 解析器，应被 noise_ips 过滤"
    assert "139.59.12.34" in eps, "真 C2 不得被这批 denylist 误杀"  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面


def test_public_ip_not_private():
    result = _analyze(dex_strings=["139.59.12.34 backend"])  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert _by_value(result)["139.59.12.34"].is_private is False  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面


def test_cleartext_url_with_private_host_flags_both():
    result = _analyze(dex_strings=["http://192.168.0.10:8080/api"])
    ep = _by_value(result)["http://192.168.0.10:8080/api"]
    assert ep.kind == "url"
    assert ep.is_cleartext is True
    assert ep.is_private is True


# --- resource / manifest / native 来源 -----------------------------------


def test_resource_json_extracted():
    result = _analyze(
        files={"assets/config.json": b'{"api":"https://pay.heika-gw.cn/notify"}'}
    )
    ep = _by_value(result)["https://pay.heika-gw.cn/notify"]
    assert any(
        ev.source == "resource" and ev.location == "assets/config.json"
        for ev in ep.evidences
    )


def test_manifest_url_extracted():
    manifest = (
        '<?xml version="1.0"?>'
        '<manifest package="com.x">'
        '<meta-data android:value="https://sdk.fraud-gw.cn/init"/>'
        "</manifest>"
    )
    result = _analyze(manifest_xml=manifest)
    ep = _by_value(result)["https://sdk.fraud-gw.cn/init"]
    assert any(
        ev.source == "manifest" and ev.location == "AndroidManifest.xml"
        for ev in ep.evidences
    )


def test_native_so_string_extracted():
    # .so 内嵌可见 ASCII 串（前置 ELF 头 + 二进制噪音 + 一个 URL）
    blob = b"\x7fELF\x00\x00garbage\x00https://c2.fraud-gw.cn/beacon\x00\x01\x02"
    result = _analyze(
        files={"lib/arm64-v8a/libfoo.so": blob},
        native_libs=["lib/arm64-v8a/libfoo.so"],
    )
    ep = _by_value(result)["https://c2.fraud-gw.cn/beacon"]
    assert any(ev.source == "native" for ev in ep.evidences)
    assert result.meta["native_files_scanned"] >= 1


def test_native_so_via_list_files_only():
    # .so 不在 native_libs，仅出现在 files，也应被扫描
    blob = b"\x00\x00http://c2-backup.fraud-gw.cn/b\x00"
    result = _analyze(files={"assets/payload.so": blob})
    eps = _by_value(result)
    assert "http://c2-backup.fraud-gw.cn/b" in eps


# --- 去重合并 ------------------------------------------------------------


def test_dedup_merges_evidences_across_sources():
    url = "https://pay.heika-gw.cn/notify"
    result = _analyze(
        dex_strings=[url],
        files={"assets/a.json": f'{{"u":"{url}"}}'.encode()},
        manifest_xml=f'<manifest><x v="{url}"/></manifest>',
    )
    eps = _by_value(result)
    assert url in eps
    ep = eps[url]
    sources = {ev.source for ev in ep.evidences}
    assert {"dex", "resource", "manifest"} <= sources
    # 只一个 Endpoint 实例
    assert sum(1 for e in result.endpoints if e.value == url) == 1


def test_flags_union_on_merge():
    # 用公网 IP（私网裸 IP 已被 C4 过滤；解析器 IP 亦已入 noise_ips，故取普通公网 IP）验证同 value 去重合并。
    ip = "45.11.22.33"  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    result = _analyze(dex_strings=[f"a {ip}", f"b {ip}"])
    matches = [e for e in result.endpoints if e.value == ip]
    assert len(matches) == 1
    assert matches[0].is_private is False
    # 两条命中同 source/location 仍按 (source,location) 去重 → 1 条证据
    assert len(matches[0].evidences) == 1


# --- 噪音过滤 ------------------------------------------------------------


def test_namespace_noise_filtered():
    result = _analyze(
        dex_strings=[
            "http://schemas.android.com/apk/res/android",
            "http://www.w3.org/2000/svg",
            "https://www.w3.org/2001/XMLSchema",
        ]
    )
    assert result.endpoints == []


def test_noise_subdomain_of_noise_host_filtered():
    result = _analyze(dex_strings=["http://foo.schemas.android.com/x"])
    assert result.endpoints == []


def test_real_domain_kept_alongside_noise():
    result = _analyze(
        dex_strings=[
            "http://schemas.android.com/apk/res/android",  # 噪音
            "https://real.heika-gw.cn/api",  # 业务
        ]
    )
    values = {e.value for e in result.endpoints}
    assert "https://real.heika-gw.cn/api" in values
    assert not any("schemas.android.com" in v for v in values)


# --- 类名 / 包名 / 文件名不误判为域名 ------------------------------------


def test_java_class_name_not_domain():
    result = _analyze(
        dex_strings=[
            "cn.jpush.android.api.JPushInterface",
            "com.tencent.mm.opensdk.IWXAPI",
            "androidx.core.view.ViewCompat",
        ]
    )
    assert result.endpoints == []


def test_filename_not_domain():
    result = _analyze(
        files={"assets/x.json": b"icon.png logo.jpg config.json data.bin"}
    )
    # 这些都是文件名，不应被当域名
    assert result.endpoints == []


# --- fixture 样例上下文 ---------------------------------------------------


def test_fixture_ctx_extracts_endpoints(fake_ctx):
    result = EndpointsAnalyzer().analyze(fake_ctx)
    assert result.error is None
    values = {e.value for e in result.endpoints}
    # 样例 dex/资源含 https://pay.example.com/notify 与 http://1.2.3.4:8080/api
    assert "https://pay.example.com/notify" in values
    assert "http://1.2.3.4:8080/api" in values
    # JPush 类名不应成为域名
    assert not any("JPushInterface" in v for v in values)
    # 契约：无 Lead / Finding
    assert result.leads == []
    assert result.findings == []


def test_fixture_cleartext_url_flagged(fake_ctx):
    result = EndpointsAnalyzer().analyze(fake_ctx)
    eps = {e.value: e for e in result.endpoints}
    ep = eps["http://1.2.3.4:8080/api"]
    assert ep.is_cleartext is True
    # 1.2.3.4 为公网 IP，host 非私网
    assert ep.is_private is False


# --- 鲁棒性：单数据源抛异常不炸整个 analyze ------------------------------


def test_dex_strings_failure_still_scans_others():
    class _Ctx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("boom dex")

    ctx = _Ctx(files={"assets/c.json": b'{"u":"https://pay.heika-gw.cn/n"}'})
    result = EndpointsAnalyzer().analyze(ctx)
    assert result.error is None
    assert result.meta["dex_scanned"] is False
    assert any(e.value == "https://pay.heika-gw.cn/n" for e in result.endpoints)


def test_list_files_failure_still_scans_dex():
    class _Ctx(FakeContext):
        def list_files(self):  # type: ignore[override]
            raise RuntimeError("boom list_files")

    ctx = _Ctx(dex_strings=["https://pay.heika-gw.cn/n"])
    result = EndpointsAnalyzer().analyze(ctx)
    assert result.error is None
    assert any(e.value == "https://pay.heika-gw.cn/n" for e in result.endpoints)


def test_native_libs_failure_does_not_crash():
    class _Ctx(FakeContext):
        def native_libs(self):  # type: ignore[override]
            raise RuntimeError("boom native_libs")

    ctx = _Ctx(dex_strings=["https://pay.heika-gw.cn/n"])
    result = EndpointsAnalyzer().analyze(ctx)
    assert result.error is None
    assert any(e.value == "https://pay.heika-gw.cn/n" for e in result.endpoints)


def test_read_file_failure_skips_file_only():
    class _Ctx(FakeContext):
        def read_file(self, path):  # type: ignore[override]
            raise RuntimeError("boom read_file")

    ctx = _Ctx(
        files={"assets/c.json": b'{"u":"https://x.heika-gw.cn"}'},
        dex_strings=["https://dex.heika-gw.cn/n"],
    )
    result = EndpointsAnalyzer().analyze(ctx)
    assert result.error is None
    # 资源读失败被吞，dex 仍命中
    assert any(e.value == "https://dex.heika-gw.cn/n" for e in result.endpoints)


def test_manifest_non_string_does_not_crash():
    ctx = FakeContext(dex_strings=["https://pay.heika-gw.cn/n"])
    ctx.manifest_xml = None  # type: ignore[assignment]
    result = EndpointsAnalyzer().analyze(ctx)
    assert result.error is None
    assert any(e.value == "https://pay.heika-gw.cn/n" for e in result.endpoints)


# --- C1：域名来源可信度档（tier）---------------------------------------


def test_domain_from_library_file_marked_tier():
    # 来源是第三方库文件（uni_modules/.../echarts.min.js）→ tier=library-file。
    result = _analyze(
        files={
            "assets/apps/X/www/uni_modules/lime-echart/static/echarts.min.js":
                b"var u='https://lib-cdn.fraud-x.cn/a';",
        }
    )
    eps = _by_value(result)
    assert eps["lib-cdn.fraud-x.cn"].enrichment.get("tier") == "library-file"


def test_domain_from_app_file_marked_app_tier():
    # 普通 app 文件 → tier=app。
    result = _analyze(
        files={"assets/apps/X/www/app-service.js": b"var u='https://api.fraud-x.cn/a';"}
    )
    eps = _by_value(result)
    assert eps["api.fraud-x.cn"].enrichment.get("tier") == "app"


def test_ip_from_library_file_marked_tier():
    # ★IP 与域名同口径标来源档。此前只有域名分支标，IP 整类缺两个方向：
    #   vendor 文件里的 IP 不降档（漏降），DEX/app 文件里的同值 IP 也标不上 app 档、
    #   best_tier 救不回 vendor 侧的降档（误杀无救济）。URL-host 与裸 IP 两条通道都锁。
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    lib = "assets/apps/X/www/uni_modules/lime-echart/static/echarts.min.js"
    # URL-host 通道
    result = _analyze(files={lib: f"var u='https://{GLOBAL_FIXTURE_IP}:8545/a';".encode()})
    assert _by_value(result)[GLOBAL_FIXTURE_IP].enrichment.get("tier") == "library-file"
    # 裸 IP 通道
    result = _analyze(files={lib: f"var ip='{GLOBAL_FIXTURE_IP}';".encode()})
    assert _by_value(result)[GLOBAL_FIXTURE_IP].enrichment.get("tier") == "library-file"


def test_large_resource_and_manifest_do_not_mass_demote_to_bulk_string():
    """>2KB 的资源文件 / manifest 里的端点不因**整块**长度被整批判 bulk-string。

    ★bulk-string 判据的语义是「**单条**字符串/字面量超阈值（2000，典型内置域名库大表）」。
      但 _scan_text 的 text 在 manifest 通道是整份 XML、在 resource 通道是整文件或 4MB 分块，
      长度必超阈值——照 len(text) 传就等于把这两路来源里的端点全部降档。实测 3.8KB 的
      assets 配置里的真后端就中招（域名侧还连富化都不发起）。故这两路传 raw_len=0，
      只让路径 glob 判据生效；dex/native 是逐条通道，照旧按真实单条长度判。
    """
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    filler = "x" * 3000  # 把整块推过 2000 阈值，但单条字面量本身很短
    body = f'{{"api":"https://api.fraud-x.cn/a","node":"{GLOBAL_FIXTURE_IP}","pad":"{filler}"}}'
    eps = _by_value(_analyze(files={"assets/myapp/config.json": body.encode()}))
    for value in ("api.fraud-x.cn", GLOBAL_FIXTURE_IP):
        assert eps[value].enrichment.get("tier") == "app", (
            f"{value} 因整块文本长度被误判 bulk-string"
        )

    manifest = (
        '<?xml version="1.0"?><manifest><!-- ' + filler + ' -->'
        f'<data android:host="api.fraud-x.cn"/><data android:host="{GLOBAL_FIXTURE_IP}"/></manifest>'
    )
    eps = _by_value(_analyze(manifest_xml=manifest))
    for value in ("api.fraud-x.cn", GLOBAL_FIXTURE_IP):
        assert eps[value].enrichment.get("tier") == "app", f"manifest 里的 {value} 被误降"


def test_dex_bulk_string_still_demotes():
    """对照：dex 是逐条通道，**单条**超阈值仍判 bulk-string——降噪本身没被关掉。"""
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    huge = "https://api.fraud-x.cn/a " + GLOBAL_FIXTURE_IP + " " + "y" * 2500
    eps = _by_value(_analyze(dex_strings=[huge]))
    for value in ("api.fraud-x.cn", GLOBAL_FIXTURE_IP):
        assert eps[value].enrichment.get("tier") == "bulk-string", f"{value} 未判 bulk-string"


def test_web_platform_does_not_demote_site_own_minified_code():
    """analyze-web（ctx.platform="web"）下不套用 APK 的 glob 先验。

    ★endpoints 的 requires=[]，analyze-web 里照跑，且 .js/.html/.json 命中资源目标。
      此前它恒用 context="apk"，于是站点自有的 main.min.js 里的后端被判 library-file
      → 降待核 → 不发函/不闭环/不富化，是漏报方向的误伤。web_evidence 的豁免救不回
      非配置形态的值。
    """
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    body = f'var api="https://api.fraud-x.cn/a";var node="{GLOBAL_FIXTURE_IP}";'.encode()
    eps = _by_value(_analyze(files={"web/static/js/main.min.js": body}, platform="web"))
    for value in ("api.fraud-x.cn", GLOBAL_FIXTURE_IP):
        assert eps[value].enrichment.get("tier") == "app", f"web 语境误降站点自有代码里的 {value}"

    # 对照一：同路径在 APK 语境仍降档（既有语义不变）
    eps = _by_value(_analyze(files={"web/static/js/main.min.js": body}))
    assert eps["api.fraud-x.cn"].enrichment.get("tier") == "library-file"
    # 对照二：vendor 命名同样是 app 档——文件名不再决定 tier（见 infra.name_vendor_hint），
    # 「一簇同文件常量占满 Top-N」改由 closure 的同源去拥塞治，那条判据不看名字。
    eps = _by_value(_analyze(files={"web/chunk-vendors.bc47.js": body}, platform="web"))
    assert eps["api.fraud-x.cn"].enrichment.get("tier") == "app"


def test_ip_from_app_file_marked_app_tier():
    # 对照：app 文件里的 IP 标 app 档——这是 best_tier 救回通道的生产侧。
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    result = _analyze(
        files={"assets/apps/X/www/app-service.js": f"var u='https://{GLOBAL_FIXTURE_IP}/a';".encode()}
    )
    assert _by_value(result)[GLOBAL_FIXTURE_IP].enrichment.get("tier") == "app"


# --- meta 统计 -----------------------------------------------------------


def test_meta_counts_reported():
    # 用两个公网 IP（裸私网 IP 已被 C4 过滤）+ 一个 URL 内私网 host 维持 private_count。
    result = _analyze(
        dex_strings=[
            "https://a.heika-gw.cn/x",
            "http://b.heika-gw.cn/y",
            "http://10.0.0.1:9000/p",   # URL host 私网 → 标 private（host 通道）
            "8.8.4.4",
            "139.59.12.34",  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
            "host=cdn.heika-gw.cn",
        ]
    )
    meta = result.meta
    assert meta["endpoint_total"] == len(result.endpoints)
    assert meta["url_count"] >= 2
    assert meta["ip_count"] >= 2
    assert meta["domain_count"] >= 1
    assert meta["cleartext_count"] >= 1
    assert meta["private_count"] >= 1


# ---------------------------------------------------------------------------
# 问题 3：大文件分块扫描（不漏端点 + WARNING 降级）
# ---------------------------------------------------------------------------

import logging  # noqa: E402

from apkscan.analyzers import endpoints as _ep_mod  # noqa: E402

# 块大小 / 重叠（与实现常量对齐，测试据此定位边界）。
_CHUNK = _ep_mod._SCAN_CHUNK_BYTES
_OVERLAP = _ep_mod._SCAN_OVERLAP_BYTES
_STEP = _CHUNK - _OVERLAP


def _filler(n: int) -> bytes:
    """生成 n 字节无端点的可打印 ASCII 填充（避免被正则误命中域名/URL/IP）。"""
    return b"X" * n


def _native_with_endpoints_at(positions: dict[int, str], total: int) -> bytes:
    """构造 total 字节的合成 native bytes，在指定字节偏移处嵌入端点字符串（其余填充）。

    端点前后补空格，确保 _NATIVE_ASCII_RE（可见 ASCII run）能切出干净的 run。
    """
    buf = bytearray(_filler(total))
    for off, token in positions.items():
        payload = (" " + token + " ").encode("ascii")
        buf[off : off + len(payload)] = payload
    return bytes(buf)


def test_native_large_file_endpoints_beyond_8mb():
    """大 native（>8MB）：8MB 之后（~9MB / ~12MB）的端点不被漏（改前截断到 8MB 会丢）。"""
    total = 13 * 1024 * 1024  # 13MB，贴近真样本 libweexjss.so
    big = _native_with_endpoints_at(
        {
            9 * 1024 * 1024: "https://past8mb-c2.example.cn/x",
            12 * 1024 * 1024: "https://second-c2.example.cn/y",
        },
        total,
    )
    result = _analyze(native_libs=["lib/x/big.so"], files={"lib/x/big.so": big})
    values = _by_value(result)
    assert "https://past8mb-c2.example.cn/x" in values, "9MB 处端点（>8MB）应被扫到"
    assert "https://second-c2.example.cn/y" in values, "12MB 处端点（>8MB）应被扫到"


def test_resource_large_file_not_truncated():
    """大资源文本（>8MB）：8MB 后的端点不被漏。"""
    total = 10 * 1024 * 1024
    buf = bytearray(_filler(total))
    token = b'"u":"https://res-past8mb.example.cn/z"'
    off = 9 * 1024 * 1024
    buf[off : off + len(token)] = token
    result = _analyze(files={"assets/big.json": bytes(buf)})
    assert "https://res-past8mb.example.cn/z" in _by_value(result)


def test_chunk_boundary_url_not_split():
    """跨块边界的 URL（放在步进点 _STEP 附近）：靠重叠窗口完整抽到，不被切断。"""
    total = _CHUNK + 2 * 1024 * 1024  # > 阈值，触发分块
    token = "https://boundary-c2.example.cn/cut"
    # 把 URL 起点放在第一块末尾、跨进步进点：起点 = _STEP - len(token)//2，使其横跨 chunk0/chunk1。
    off = _STEP - len(token) // 2
    big = _native_with_endpoints_at({off: token}, total)
    result = _analyze(native_libs=["lib/x/edge.so"], files={"lib/x/edge.so": big})
    assert token in _by_value(result), "跨块边界 URL 应被重叠窗口完整抽到"


def test_chunked_dedup_no_double_count():
    """重叠区里的端点只产 1 个 Endpoint（按 value 去重），证据不因重叠膨胀。"""
    total = _CHUNK + 2 * 1024 * 1024
    token = "https://overlap-once.example.cn/p"
    # 放在重叠区内（步进点之后、第一块末尾之前 = [_STEP, _CHUNK)），会被 chunk0、chunk1 各命中一次。
    off = _STEP + _OVERLAP // 4
    big = _native_with_endpoints_at({off: token}, total)
    result = _analyze(native_libs=["lib/x/dup.so"], files={"lib/x/dup.so": big})
    matched = [e for e in result.endpoints if e.value == token]
    assert len(matched) == 1, "重叠区端点应只产 1 个 Endpoint（value 去重）"
    # 证据按 (source, location, snippet) 去重 → 同一 location 不该出现重复证据。
    locs = [(ev.source, ev.location, ev.snippet) for ev in matched[0].evidences]
    assert len(locs) == len(set(locs)), "证据不应因重叠重复膨胀"


def test_no_truncation_warning_emitted(caplog):
    """扫 >8MB 文件时不再出现「文件超过上限...仅扫前段」WARNING（GUI 日志不被吓人噪声刷屏）。"""
    total = 12 * 1024 * 1024
    big = _native_with_endpoints_at({10 * 1024 * 1024: "https://c2.example.cn/late"}, total)
    with caplog.at_level(logging.WARNING):
        _analyze(native_libs=["lib/x/big.so"], files={"lib/x/big.so": big})
    assert not any("文件超过上限" in r.message for r in caplog.records)
    assert not any("仅扫前段" in r.message for r in caplog.records)


def test_small_file_endpoints_unchanged():
    """不回归：小文件（< 阈值）端点抽取与改前一致（整体扫，行为不变）。"""
    result = _analyze(
        files={"assets/c.json": b'{"u":"https://small.example.cn/api"}'},
        native_libs=["lib/x/s.so"],
    )
    # native 也走小文件整体扫路径。
    result2 = _analyze(
        native_libs=["lib/x/s.so"],
        files={"lib/x/s.so": b"  https://native-small.example.cn/n  "},
    )
    assert "https://small.example.cn/api" in _by_value(result)
    assert "https://native-small.example.cn/n" in _by_value(result2)


def test_large_native_does_not_crash_on_empty_overlap_chunks():
    """大文件分块在无端点的纯填充块上不崩、不误产端点（只 8MB 后那个真端点出现）。"""
    total = 11 * 1024 * 1024
    big = _native_with_endpoints_at({10 * 1024 * 1024: "https://only-one.example.cn/x"}, total)
    result = _analyze(native_libs=["lib/x/big.so"], files={"lib/x/big.so": big})
    values = _by_value(result)
    assert "https://only-one.example.cn/x" in values
    # 填充 "X"*N 不该产任何端点。
    assert all("only-one.example.cn" in v or "example" not in v for v in values)


# --- WebSocket / MQTT 实时 C2 端点（杀猪盘行情推送 / 远控 / IM 长连接） ----------


def test_wss_url_extracted_and_host_derived() -> None:
    result = _analyze(dex_strings=["wss://c2.evil-trade.com:8443/ws"])
    url_ep = next((ep for ep in result.endpoints if ep.kind == "url"), None)
    assert url_ep is not None and url_ep.value.startswith("wss://")
    assert url_ep.is_cleartext is False  # wss 加密
    assert "c2.evil-trade.com" in _by_value(result)  # host 派生 domain 端点供富化


def test_ws_marked_cleartext() -> None:
    result = _analyze(dex_strings=["ws://c2.evil-trade.com/rt"])
    url_ep = next(ep for ep in result.endpoints if ep.kind == "url")
    assert url_ep.value.startswith("ws://")
    assert url_ep.is_cleartext is True  # ws 明文（对标 http://）


def test_mqtt_url_extracted() -> None:
    result = _analyze(dex_strings=["mqtt://broker.evil-trade.com:1883"])
    url_ep = next((ep for ep in result.endpoints if ep.kind == "url"), None)
    assert url_ep is not None and url_ep.value.startswith("mqtt://")
    assert "broker.evil-trade.com" in _by_value(result)


# ---------------------------------------------------------------------------
# 组 F #1：_scan_text 的 _in_consumed 从线性扫改 bisect（结果须与旧实现完全一致）
# ---------------------------------------------------------------------------


def _linear_in_consumed(consumed: list[tuple[int, int]], pos: int) -> bool:
    """旧实现（线性扫全部区间）的参照，供对照 bisect 版结果一致。"""
    return any(start <= pos < end for start, end in consumed)


def test_in_consumed_matches_linear_reference() -> None:
    """bisect 版 _in_consumed 对每个位置的判定须与旧线性实现逐点一致。"""
    from apkscan.analyzers.endpoints import _pos_in_consumed

    # 非重叠、按 start 升序的区间（与 _scan_text 里 consumed 的构造不变量一致）。
    consumed = [(5, 10), (20, 25), (40, 50), (100, 101)]
    for pos in range(-5, 130):
        assert _pos_in_consumed(consumed, pos) == _linear_in_consumed(
            consumed, pos
        ), f"pos={pos} bisect 与线性不一致"


def test_in_consumed_empty_consumed() -> None:
    from apkscan.analyzers.endpoints import _pos_in_consumed

    assert _pos_in_consumed([], 0) is False
    assert _pos_in_consumed([], 99999) is False


def test_dense_urls_ip_domain_consistency() -> None:
    """密集混合输入：URL 内的 host（IP/域名）不应再被裸 IP/域名通道重复抽出，
    行为须与旧线性实现一致（用可观察的端点集合验证）。"""
    text = (
        "https://a.fraud-gw.cn/1 https://b.fraud-gw.cn/2 "
        "http://139.59.12.34:80/x https://c.fraud-gw.cn/3 "  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
        "45.11.22.33 raw.heika-pay.cn https://d.fraud-gw.cn/4"  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    )
    result = _analyze(dex_strings=[text])
    values = {e.value for e in result.endpoints}
    # URL 全在
    for u in (
        "https://a.fraud-gw.cn/1",
        "https://b.fraud-gw.cn/2",
        "http://139.59.12.34:80/x",  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
        "https://c.fraud-gw.cn/3",
        "https://d.fraud-gw.cn/4",
    ):
        assert u in values
    # URL host 派生的 domain/ip 也在
    assert "a.fraud-gw.cn" in values
    assert "139.59.12.34" in values  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    # URL 之外的裸 IP / 裸域名也应被抽到（用非解析器公网 IP——8.8.8.8 已入 noise_ips）
    assert "45.11.22.33" in values  # leak-scan: allow 端点抽取夹具，验「真后端不得被 noise_ips/低段位降噪误杀」，值须是公网字面
    assert "raw.heika-pay.cn" in values


# ---------------------------------------------------------------------------
# 组 F #2：DEX strings 截断在 meta 标记 dex_strings_truncated
# ---------------------------------------------------------------------------


def test_dex_truncation_marked_when_over_limit() -> None:
    """dex_strings 超过 _MAX_DEX_STRINGS → meta['dex_strings_truncated'] 为 True。"""
    limit = _ep_mod._MAX_DEX_STRINGS
    # 超阈值：limit + 少量。用无端点的填充字符串（不产端点，仅测截断标记）。
    strings = [f"label_{i}" for i in range(limit + 5)]
    result = _analyze(dex_strings=strings)
    assert result.meta.get("dex_strings_truncated") is True


def test_dex_truncation_not_marked_when_under_limit() -> None:
    """未超阈值 → dex_strings_truncated 不设或为 False。"""
    result = _analyze(dex_strings=["https://pay.heika-gw.cn/n", "just a label"])
    assert result.meta.get("dex_strings_truncated", False) is False


def test_dex_truncation_flag_false_on_empty_dex() -> None:
    result = _analyze(files={"assets/c.json": b'{"u":"https://x.heika-gw.cn"}'})
    assert result.meta.get("dex_strings_truncated", False) is False


# ---------------------------------------------------------------------------
# 组 F #3：ApkContext._read_cache 单文件上限（大 .so 不常驻内存）
# ---------------------------------------------------------------------------

from apkscan.core.apk import ApkContext, _MAX_READ_CACHE_BYTES  # noqa: E402
from apkscan.core.models import AnalysisConfig  # noqa: E402


class _StubApk:
    """最小 androguard.APK 桩：只实现 read_file 用到的 get_file(path)->bytes|None。"""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files
        self.calls: list[str] = []

    def get_file(self, path: str) -> bytes:
        self.calls.append(path)
        if path not in self._files:
            raise KeyError(path)  # 模拟 androguard 对缺失文件抛异常
        return self._files[path]


def _apk_ctx(files: dict[str, bytes]) -> tuple[ApkContext, _StubApk]:
    stub = _StubApk(files)
    ctx = ApkContext(apk=stub, dex_objs=[], config=AnalysisConfig(online=False))
    return ctx, stub


def test_read_cache_caches_small_file() -> None:
    """小文件读到后进缓存：第二次读命中缓存，不再回落 get_file。"""
    ctx, stub = _apk_ctx({"assets/small.txt": b"hello"})
    assert ctx.read_file("assets/small.txt") == b"hello"
    assert ctx.read_file("assets/small.txt") == b"hello"
    # 只调一次底层 get_file → 第二次命中缓存。
    assert stub.calls == ["assets/small.txt"]


def test_read_cache_skips_large_file() -> None:
    """超上限的大文件不进缓存：每次读都回落 get_file（不常驻内存），字节仍完整。"""
    big = b"\x00" * (_MAX_READ_CACHE_BYTES + 1)
    ctx, stub = _apk_ctx({"lib/x/big.so": big})
    assert ctx.read_file("lib/x/big.so") == big
    assert ctx.read_file("lib/x/big.so") == big
    # 两次读 → 两次底层调用（未缓存）。
    assert stub.calls == ["lib/x/big.so", "lib/x/big.so"]


def test_read_cache_at_limit_is_cached() -> None:
    """恰好等于上限的文件仍进缓存（阈值为 <=）。"""
    at_limit = b"\x00" * _MAX_READ_CACHE_BYTES
    ctx, stub = _apk_ctx({"lib/x/edge.so": at_limit})
    assert ctx.read_file("lib/x/edge.so") == at_limit
    assert ctx.read_file("lib/x/edge.so") == at_limit
    assert stub.calls == ["lib/x/edge.so"]


def test_read_cache_caches_none_miss() -> None:
    """未命中（None）仍缓存，避免对同一缺失路径重复查询底层。"""
    ctx, stub = _apk_ctx({})
    assert ctx.read_file("assets/missing.txt") is None
    assert ctx.read_file("assets/missing.txt") is None
    # 只调一次 → None 被缓存。
    assert stub.calls == ["assets/missing.txt"]
