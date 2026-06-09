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
) -> AnalyzerResult:
    ctx = FakeContext(
        manifest_xml=manifest_xml,
        files=files,
        dex_strings=dex_strings,
        native_libs=native_libs,
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


# --- ★ 契约：只产 Endpoint，不产 Lead ------------------------------------


def test_never_emits_leads_or_findings():
    result = _analyze(
        dex_strings=[
            "https://pay.fraud-gw.cn/notify",
            "http://10.0.0.8/admin",
            "139.59.12.34",
        ]
    )
    # 端点应有，但绝不产 Lead / Finding（DOMAIN/IP Lead 由 pipeline 富化后统一建）
    assert result.endpoints
    assert result.leads == []
    assert result.findings == []


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
    result = _analyze(dex_strings=["connect 139.59.12.34:443"])
    eps = _by_value(result)
    assert "139.59.12.34" in eps
    ep = eps["139.59.12.34"]
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
    result = _analyze(dex_strings=["dns 8.8.8.8", "c2 139.59.12.34"])
    eps = _by_value(result)
    assert "8.8.8.8" in eps
    assert "139.59.12.34" in eps
    assert eps["8.8.8.8"].is_private is False


def test_public_ip_not_private():
    result = _analyze(dex_strings=["8.8.8.8 dns"])
    assert _by_value(result)["8.8.8.8"].is_private is False


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
    # 用公网 IP（私网裸 IP 已被 C4 过滤）验证同 value 去重合并。
    ip = "8.8.4.4"
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


# --- meta 统计 -----------------------------------------------------------


def test_meta_counts_reported():
    # 用两个公网 IP（裸私网 IP 已被 C4 过滤）+ 一个 URL 内私网 host 维持 private_count。
    result = _analyze(
        dex_strings=[
            "https://a.heika-gw.cn/x",
            "http://b.heika-gw.cn/y",
            "http://10.0.0.1:9000/p",   # URL host 私网 → 标 private（host 通道）
            "8.8.4.4",
            "139.59.12.34",
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
