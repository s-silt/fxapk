"""JsBundleAnalyzer 的单测：用 FakeContext 喂合成打包 JS / HTML / manifest。

覆盖:
- 基本属性 name / requires。
- ★ 字面量内 URL 被提取（api.real-fraud.top），同文件里 b.length / a.length 不误判为域名。
- 框架识别：uni-app（assets/apps/__UNI__X/www/app-service.js）/ Cordova / RN / generic / unknown。
- 硬编码 appkey → MEDIUM Finding；secret/access_key/token/private_key → HIGH；AES key/JWT/PEM。
- 占位 / 示例值不产 Finding（降误报）。
- 相对 API 路径、裸 IP、明文 URL 标志。
- 只产 Endpoint（无 DOMAIN/IP Lead），密钥产 Finding。
- meta：js_framework / js_files_scanned / js_endpoint_count。
- 鲁棒性：list_files / read_file 抛异常时不炸整个 analyze。
"""

from __future__ import annotations

from apkscan.analyzers.js_bundle import (
    FINDING_AES_KEY,
    FINDING_APPID,
    FINDING_JWT,
    FINDING_PEM,
    FINDING_SECRET,
    FRAMEWORK_CORDOVA,
    FRAMEWORK_GENERIC,
    FRAMEWORK_RN,
    FRAMEWORK_UNIAPP,
    FRAMEWORK_UNKNOWN,
    JsBundleAnalyzer,
)
from apkscan.core.models import AnalyzerResult, Severity

from tests.conftest import FakeContext

_UNIAPP_PATH = "assets/apps/__UNI__X/www/app-service.js"


def _analyze(files: dict[str, bytes] | None = None) -> AnalyzerResult:
    return JsBundleAnalyzer().analyze(FakeContext(files=files))


def _values(result: AnalyzerResult) -> set[str]:
    return {ep.value for ep in result.endpoints}


def _finding_ids(result: AnalyzerResult) -> set[str]:
    return {f.id for f in result.findings}


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires() -> None:
    analyzer = JsBundleAnalyzer()
    assert analyzer.name == "js_bundle"
    assert analyzer.requires == []


# --- ★ 核心断言：字面量内端点提取 + 压缩 JS 不误判 -----------------------


def test_uniapp_literal_url_extracted_and_length_not_misjudged() -> None:
    payload = (
        b"var a=b.length;"
        b"var t=rect.top;"
        b"var s='https://api.real-fraud.top/pay';"
        b"var k={appkey:'aB3xY7zQ1mN5pL9k'};"
        b"function f(){return a.length+c.length;}"
    )
    result = _analyze({_UNIAPP_PATH: payload})

    values = _values(result)
    # 字面量内真实端点被抽到（URL + host）。
    assert "https://api.real-fraud.top/pay" in values
    assert "api.real-fraud.top" in values
    # ★ 压缩 JS 的 b.length / a.length / rect.top / c.length 绝不能被当域名。
    assert "b.length" not in values
    assert "a.length" not in values
    assert "rect.top" not in values
    assert "c.length" not in values
    assert not any("length" in v for v in values)
    assert not any(v.endswith(".top") and "length" in v for v in values)

    # 硬编码 appkey 产 Finding。
    assert FINDING_APPID in _finding_ids(result)
    appid_finding = next(f for f in result.findings if f.id == FINDING_APPID)
    assert appid_finding.severity == Severity.MEDIUM
    assert appid_finding.category == "secret"
    assert appid_finding.evidences
    assert appid_finding.evidences[0].source == "js"

    # 框架识别为 uni-app；只产端点不产 Lead。
    assert result.meta["js_framework"] == FRAMEWORK_UNIAPP
    assert result.leads == []
    assert result.meta["js_files_scanned"] == 1
    assert result.meta["js_endpoint_count"] == len(result.endpoints)


def test_length_top_outside_literal_never_extracted() -> None:
    # 即便没有任何字面量端点，纯压缩代码也不应产出任何 domain 端点。
    result = _analyze(
        {"assets/www/app-service.js": b"var a=b.length,c=d.top,e=f.store,g=h.id;"}
    )
    domains = {ep.value for ep in result.endpoints if ep.kind == "domain"}
    assert domains == set()


# --- 框架识别 -------------------------------------------------------------


def test_framework_uniapp_by_io_dcloud() -> None:
    result = _analyze({"assets/data/io.dcloud.uniapp.config": b"{}"})
    assert result.meta["js_framework"] == FRAMEWORK_UNIAPP


def test_framework_uniapp_by_manifest_json() -> None:
    result = _analyze(
        {"assets/apps/__UNI__F7A0431/www/manifest.json": b'{"id":"__UNI__F7A0431","uni-app":{}}'}
    )
    assert result.meta["js_framework"] == FRAMEWORK_UNIAPP


def test_framework_cordova() -> None:
    result = _analyze({"assets/www/cordova.js": b"// cordova bootstrap"})
    assert result.meta["js_framework"] == FRAMEWORK_CORDOVA


def test_framework_react_native() -> None:
    result = _analyze({"assets/index.android.bundle": b"var x='https://rn.example.org/a';"})
    assert result.meta["js_framework"] == FRAMEWORK_RN


def test_framework_generic_h5() -> None:
    result = _analyze({"assets/www/index.html": b"<html></html>", "assets/www/main.js": b"//"})
    assert result.meta["js_framework"] == FRAMEWORK_GENERIC


def test_framework_unknown_when_no_js() -> None:
    result = _analyze({"res/drawable/icon.png": b"\x89PNG"})
    assert result.meta["js_framework"] == FRAMEWORK_UNKNOWN
    assert result.meta["js_files_scanned"] == 0


# --- 硬编码密钥分类 -------------------------------------------------------


def test_secret_key_is_high() -> None:
    result = _analyze(
        {_UNIAPP_PATH: b"var c={app_secret:'zwBt8Xsz3V9RCAZJLbfcL5x'};"}  # leak-scan: allow JS 包夹具，模拟被检出的硬编码凭据，值为合成串
    )
    assert FINDING_SECRET in _finding_ids(result)
    f = next(x for x in result.findings if x.id == FINDING_SECRET)
    assert f.severity == Severity.HIGH


def test_access_key_is_high() -> None:
    result = _analyze(
        {_UNIAPP_PATH: b'{"access_key_id":"AKIDz8krbsJ5yKBZQpn7","access_key_secret":"Gu5t9xGARNpq86cd98joQYCN3"}'}
    )
    ids = _finding_ids(result)
    assert FINDING_SECRET in ids


def test_aes_key_detected() -> None:
    # 32 字符、字母数字混合、键名含 aeskey → AES key HIGH。
    result = _analyze(
        {_UNIAPP_PATH: b"var k={aesKey:'0123456789abcdef0123456789abXY12'};"}
    )
    assert FINDING_AES_KEY in _finding_ids(result)
    f = next(x for x in result.findings if x.id == FINDING_AES_KEY)
    assert f.severity == Severity.HIGH


def test_jwt_detected() -> None:
    jwt = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        b".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    result = _analyze({_UNIAPP_PATH: b"var t='" + jwt + b"';"})
    assert FINDING_JWT in _finding_ids(result)
    f = next(x for x in result.findings if x.id == FINDING_JWT)
    assert f.severity == Severity.HIGH


def test_pem_detected() -> None:
    pem = b"-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA\\n-----END RSA PRIVATE KEY-----"
    result = _analyze({_UNIAPP_PATH: b"var p='" + pem + b"';"})
    assert FINDING_PEM in _finding_ids(result)


def test_appid_is_medium() -> None:
    result = _analyze({_UNIAPP_PATH: b"var c={appId:'wx1234567890abcdef'};"})
    assert FINDING_APPID in _finding_ids(result)
    f = next(x for x in result.findings if x.id == FINDING_APPID)
    assert f.severity == Severity.MEDIUM


# --- 降误报：占位 / 示例值不产 Finding ------------------------------------


def test_placeholder_secret_not_flagged() -> None:
    result = _analyze(
        {_UNIAPP_PATH: b"var c={appKey:'your_app_key',appSecret:'',apiKey:'xxxxxxxxxxxxxxxx'};"}
    )
    assert FINDING_APPID not in _finding_ids(result)
    assert FINDING_SECRET not in _finding_ids(result)


def test_secret_value_with_space_not_flagged() -> None:
    # 含空格的多为说明文本，非凭证常量。
    result = _analyze({_UNIAPP_PATH: b"var c={secret:'this is not a key really'};"})
    assert FINDING_SECRET not in _finding_ids(result)


def test_keyword_like_key_name_denied() -> None:
    # keyword / token_type 等含 hint 子串但不是密钥。
    result = _analyze(
        {_UNIAPP_PATH: b"var c={keyword:'abcdef123456',token_type:'Bearer'};"}
    )
    assert result.findings == []


def test_sdk_constant_value_equals_key_not_flagged() -> None:
    # C2：value==key（OPPOPUSH_APPKEY="OPPOPUSH_APPKEY"）+ KEY_DEVICE_TOKEN=deviceToken
    # 等 SDK 常量名/值 → 不产 Finding。
    result = _analyze(
        {
            _UNIAPP_PATH: (
                b"var c={"
                b"OPPOPUSH_APPKEY:'OPPOPUSH_APPKEY',"
                b"KEY_DEVICE_TOKEN:'deviceToken',"
                b"METHOD_CHECK_APPKEY:'dc_checkappkey'"
                b"};"
            )
        }
    )
    assert FINDING_SECRET not in _finding_ids(result)
    assert FINDING_APPID not in _finding_ids(result)


def test_non_keyish_secret_value_not_flagged() -> None:
    # C2：value 不像凭据形态（纯字母无数字/非 hex）→ 不产 Finding。
    result = _analyze({_UNIAPP_PATH: b"var c={appSecret:'deviceToken'};"})
    assert FINDING_SECRET not in _finding_ids(result)


def test_appid_numeric_still_medium() -> None:
    # ★ 回归锁：数字型 appid=100215079（looks_keyish=True）仍产 MEDIUM。
    result = _analyze({_UNIAPP_PATH: b"var c={appid:'100215079'};"})
    assert FINDING_APPID in _finding_ids(result)
    f = next(x for x in result.findings if x.id == FINDING_APPID)
    assert f.severity == Severity.MEDIUM


def test_js_version_ip_filtered_real_ip_kept() -> None:
    # C4：js 路径裸 IP——版本号 2.1.5.1 / 占位 1.2.3.4 过滤，真公网 IP（全球可达）保留。
    result = _analyze(
        {_UNIAPP_PATH: b"var a='2.1.5.1';var b='1.2.3.4';var c='45.76.10.20';"}  # leak-scan: allow JS bundle 抽取夹具，验真后端不被 noise 判据误杀
    )
    ips = {ep.value for ep in result.endpoints if ep.kind == "ip"}
    assert "2.1.5.1" not in ips
    assert "1.2.3.4" not in ips
    assert "45.76.10.20" in ips  # leak-scan: allow JS bundle 抽取夹具，验真后端不被 noise 判据误杀


# --- 端点：路径 / IP / 明文 ----------------------------------------------


def test_relative_api_path_extracted() -> None:
    result = _analyze({_UNIAPP_PATH: b"var u='/api/v1/user/login';"})
    paths = {ep.value for ep in result.endpoints if ep.kind == "path"}
    assert "/api/v1/user/login" in paths


def test_bare_ip_in_literal_extracted() -> None:
    result = _analyze({_UNIAPP_PATH: b"var h='http://203.0.113.45:8080/cb';"})
    ips = {ep.value for ep in result.endpoints if ep.kind == "ip"}
    assert "203.0.113.45" in ips
    url = next(ep for ep in result.endpoints if ep.kind == "url")
    assert url.is_cleartext is True


def test_filename_in_literal_not_domain() -> None:
    # 字面量里的 config.json / app.vue 是文件名不是域名。
    result = _analyze({_UNIAPP_PATH: b"var f='config.json';var g='pages/index.vue';"})
    domains = {ep.value for ep in result.endpoints if ep.kind == "domain"}
    assert "config.json" not in domains
    assert "index.vue" not in domains


def test_backtick_template_literal_scanned() -> None:
    result = _analyze({_UNIAPP_PATH: b"var u=`https://tpl.fraud-host.cn/notify`;"})
    assert "tpl.fraud-host.cn" in _values(result)


# --- 只产 Endpoint / 密钥 Finding，互不混淆 -------------------------------


def test_only_endpoints_no_leads() -> None:
    result = _analyze(
        {_UNIAPP_PATH: b"var u='https://a.fraud-domain.com/x';var k={appKey:'realKey1234abcd'};"}
    )
    assert result.leads == []
    assert result.endpoints
    assert result.findings


# --- 鲁棒性 ---------------------------------------------------------------


def test_list_files_failure_does_not_crash() -> None:
    class _Ctx(FakeContext):
        def list_files(self):  # type: ignore[override]
            raise RuntimeError("boom list_files")

    result = JsBundleAnalyzer().analyze(_Ctx())
    assert result.error is None
    assert result.endpoints == []
    assert result.meta["js_files_scanned"] == 0


def test_read_file_failure_does_not_crash() -> None:
    class _Ctx(FakeContext):
        def read_file(self, path: str):  # type: ignore[override]
            raise RuntimeError("boom read_file")

    ctx = _Ctx(files={_UNIAPP_PATH: b"var u='https://x.fraud.cn/a';"})
    result = JsBundleAnalyzer().analyze(ctx)
    assert result.error is None
    # 文件读取失败被吞并记录，端点为空但 analyze 不炸。
    assert result.endpoints == []


def test_non_js_files_ignored() -> None:
    # dex_strings 不应被本分析器读取；非 assets/www 的 JS 也不扫。
    result = _analyze({"lib/x/foo.js": b"var u='https://ignored.example.org/a';"})
    assert _values(result) == set()
    assert result.meta["js_files_scanned"] == 0


# --- 大文件分块：不漏端点 + 无吓人 WARNING（问题 3 同因覆盖到 js_bundle）---------


def test_large_bundle_endpoint_after_8mb_not_dropped() -> None:
    """>8MB 的 index.android.bundle 后段（9MB 处）的端点不被截断丢失（改前会丢）。"""
    pad = b"// padding line\n" * (9 * 1024 * 1024 // 16)  # ~9MB 良性填充
    blob = pad + b"\nvar c2='https://evil-c2-after8mb.top/cmd';\n"
    result = _analyze({_UNIAPP_PATH: blob})
    assert "https://evil-c2-after8mb.top/cmd" in _values(result)
    assert result.meta["js_files_scanned"] == 1


def test_large_bundle_secret_after_8mb_not_dropped() -> None:
    """>8MB 文件后段的硬编码密钥（JWT）不被截断丢失。"""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRs"
    pad = b"x" * (9 * 1024 * 1024)
    blob = pad + f"\nvar t='{jwt}';\n".encode()
    result = _analyze({_UNIAPP_PATH: blob})
    assert FINDING_JWT in _finding_ids(result)


def test_url_across_chunk_boundary_not_split() -> None:
    """跨 4MB 块边界的 URL 字面量被块间重叠完整抽到，不被切断。"""
    from apkscan.analyzers.js_bundle import _SCAN_CHUNK_BYTES

    url = "https://boundary-c2.example-fraud.cn/path"
    lit = f"var u='{url}';"
    # 让字面量起点落在首块末尾的重叠窗内（块边界 _SCAN_CHUNK_BYTES 之前 100 字节起）。
    head = b"a" * (_SCAN_CHUNK_BYTES - 100)
    tail = b"b" * (2 * 1024 * 1024)
    blob = head + lit.encode() + b"\n" + tail
    result = _analyze({_UNIAPP_PATH: blob})
    assert url in _values(result)


def test_overlap_does_not_double_count_endpoint() -> None:
    """落在重叠窗内的端点被相邻两块各扫一次，collector 去重后仍只产 1 个端点。"""
    from apkscan.analyzers.js_bundle import _SCAN_CHUNK_BYTES, _SCAN_OVERLAP_CHARS

    url = "https://dedup-c2.example-fraud.cn/x"
    lit = f"var u='{url}';"
    # 放在重叠窗中部（块0尾 + 块1头都覆盖）。
    pos = _SCAN_CHUNK_BYTES - _SCAN_OVERLAP_CHARS // 2
    blob = b"a" * pos + lit.encode() + b"\n" + b"b" * (2 * 1024 * 1024)
    result = _analyze({_UNIAPP_PATH: blob})
    matches = [ep for ep in result.endpoints if ep.value == url]
    assert len(matches) == 1


def test_large_bundle_no_truncation_warning(caplog) -> None:  # type: ignore[no-untyped-def]
    """大文件不再打「文件超过上限/仅扫前段」WARNING（吓新手的噪声已删）。"""
    import logging

    pad = b"y" * (9 * 1024 * 1024)
    blob = pad + b"\nvar u='https://q.fraud.cn/a';\n"
    with caplog.at_level(logging.WARNING, logger="apkscan.analyzers.js_bundle"):
        _analyze({_UNIAPP_PATH: blob})
    assert not any("仅扫前段" in r.message or "文件超过上限" in r.message for r in caplog.records)


def test_small_bundle_behavior_unchanged() -> None:
    """<= 阈值的小文件走整体扫，行为与改前一致（无回归）。"""
    result = _analyze({_UNIAPP_PATH: b"var u='https://api.real-fraud.top/login';"})
    assert "https://api.real-fraud.top/login" in _values(result)
    assert result.meta["js_files_scanned"] == 1

#: vendor bundle 夹具路径：文件名用扁平 vendor 命名，目录取分析器会扫的位置。
_VENDOR_PATH = "assets/apps/__UNI__X/www/chunk-vendors.bc47c059.js"
#: 夹具 IP 取 6to4 已弃用段——文档段（RFC 5737）会被 is_noise_bare_ip 当噪音滤掉，
#: 端点根本进不来，断言会以"两种原因产出同一个绿"的方式失效。
_VENDOR_IP_A = "192.88.99.9"   # leak-scan: allow 见 tests/doc_addresses.GLOBAL_FIXTURE_NET
_VENDOR_IP_B = "192.88.99.44"  # leak-scan: allow 同上


def test_vendor_bundle_ip_constants_are_tier_demoted() -> None:
    """第三方 vendor bundle 里的 IP 常量必须打上 library-file 档，不能进最高档。

    ★锁的是一次实测事故：一份 ``chunk-vendors.<hash>.js`` 里第三方库硬编码的公共节点，
      28 个 IP 全部以 ``is_c2=true`` / 建议调证进了闭环主目标，把真实站点挤到第 25 位
      之后——办案方拿到的前 6 个"目标"没有一个是本案后端。

    两个缺陷叠加才造成它，**两个都被这条锁住**：
      ① ``mark_tier`` 此前只在**域名**分支调用，IP 整类不降档；
      ② vendor glob 只有带路径的 ``*/static/js/chunk-vendors*``，扁平文件名匹配不上。

    ★必须走 ``_analyze`` 真入口。先前写过一版在测试里自己调 ``mark_tier``，
      把分析器里那行删掉照样绿——假绿，锁不住缺陷①。
    """
    from apkscan.core import infra

    js = f'var rpc="https://{_VENDOR_IP_A}:8545/rpc";var bare="{_VENDOR_IP_B}";'.encode()
    by = {ep.value: ep for ep in _analyze({_VENDOR_PATH: js}).endpoints}

    for ip in (_VENDOR_IP_A, _VENDOR_IP_B):
        assert ip in by, f"{ip} 未被提取——夹具或提取逻辑变了，本条断言已失去意义"
        tier = by[ip].enrichment.get("tier")
        assert tier == infra.TIER_LIBRARY_FILE, (
            f"vendor bundle 里的 IP {ip} 未降档（tier={tier!r}）——它会以最高档进调证出口"
        )

    # ★对照：站点自身的业务 bundle 不降档，真后端不受误伤
    app_path = "assets/apps/__UNI__X/www/app-service.js"
    app_by = {ep.value: ep for ep in _analyze({app_path: js}).endpoints}
    assert app_by[_VENDOR_IP_A].enrichment.get("tier") == infra.TIER_APP

    # ★★锁必须走到 Lead 层：只断言 tier 锁不住这次事故。第一版就止步于此，而复审实跑发现
    #   ``_ip_lead`` 通篇不读 ``enrichment["tier"]``——档标上了、没有任何消费者，那 28 个 IP
    #   照旧 advice=建议调证 / is_c2=true 进闭环主目标。「提取出信号 ≠ 接上了线」。
    from apkscan.core.leads import build_endpoint_leads

    leads = {ld.value: ld for ld in build_endpoint_leads([by[_VENDOR_IP_A], by[_VENDOR_IP_B]])}
    for ip in (_VENDOR_IP_A, _VENDOR_IP_B):
        ld = leads[ip]
        # 前置断言：降档**之前**确实判最高档。没有它，判据哪天把这些 IP 判成别的档，
        # 下面两条会以"本来就不是建议调证"的方式假绿。
        assert ld.base_advice == infra.ADVICE_INVESTIGATE, (
            f"{ip} 的 base_advice={ld.base_advice!r}，夹具已不再触发本条要锁的场景"
        )
        assert ld.advice == infra.ADVICE_REVIEW, f"{ip} 未降为待核（advice={ld.advice!r}）"
        assert "source_tier" in (ld.downgrades or {}), f"{ip} 降了档却没留墓碑，出口无法解释"
        # LOW 编码「静态出处只有库文件」这一证据强度事实，撤销降档后仍成立（判据链、不随降档走）
        from apkscan.core.models import Confidence
        assert ld.confidence == Confidence.LOW, f"{ip} 降档后 confidence={ld.confidence}"

    # 对照：app 档的同一个 IP 仍判最高档——降档不是把 IP 整类压低
    app_lead = build_endpoint_leads([app_by[_VENDOR_IP_A]])[0]
    assert app_lead.advice == infra.ADVICE_INVESTIGATE, "业务 bundle 里的 IP 被误伤降档"


def test_runtime_observed_ip_not_downgraded_by_vendor_tier() -> None:
    """真连过的对端不因"它也出现在某个库文件里"降档——与 classify_ip 的形态豁免同口径。

    ★这条防的是最贵的那类错：涉诈后端 IP 恰好也被某个第三方库当公共节点写死，或攻击者
      刻意把业务 bundle 命名成 chunk-vendors。只要 pcap 里真有连接，就不该被静态出处压低。
    """
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import OBSERVED_CONTACT_SOURCES, Endpoint, Evidence

    ep = Endpoint(
        value=_VENDOR_IP_A, kind="ip", is_private=False,
        evidences=[Evidence(source=sorted(OBSERVED_CONTACT_SOURCES)[0],
                            location=_VENDOR_PATH, snippet=f"https://{_VENDOR_IP_A}:8545/rpc")],
        enrichment={"tier": infra.TIER_LIBRARY_FILE},
    )
    lead = build_endpoint_leads([ep])[0]
    assert lead.advice == infra.ADVICE_INVESTIGATE, "实连过的对端被 tier 降档了"
    assert not (lead.downgrades or {}), f"实连过的对端不该有降档墓碑：{lead.downgrades}"


def test_runtime_derived_source_does_not_exempt_ip_tier_downgrade() -> None:
    """``runtime-derived``（手编/回灌）**不豁免** tier 降档——豁免口径必须是严格的实连证据。

    ★钉的是 `leads.py` 里 `OBSERVED_CONTACT_SOURCES` 与 ``startswith("runtime")`` 的差：
      后者会把「只证明出现在 runtime 报告里」的 runtime-derived 也当实连证据放行。
      复审实测把口径突变回 startswith 后全仓仍绿——本条就是补上的那把锁。
    """
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import OBSERVED_CONTACT_SOURCES, Endpoint, Evidence

    # 前置断言：夹具用的来源必须真的不在严格口径里，否则本条锁的差集不存在
    assert "runtime-derived" not in OBSERVED_CONTACT_SOURCES

    ep = Endpoint(
        value=_VENDOR_IP_A, kind="ip", is_private=False,
        evidences=[Evidence(source="runtime-derived", location=_VENDOR_PATH,
                            snippet=f"https://{_VENDOR_IP_A}:8545/rpc")],
        enrichment={"tier": infra.TIER_LIBRARY_FILE},
    )
    lead = build_endpoint_leads([ep])[0]
    assert lead.advice == infra.ADVICE_REVIEW, "runtime-derived 被当成实连证据豁免了降档"
    assert "source_tier" in (lead.downgrades or {})


def test_runtime_observed_domain_not_downgraded_by_vendor_tier() -> None:
    """域名侧的实连豁免必须与 IP 侧对称——真连过的域名不因出现在库文件里降档。

    ★此前只有 IP 侧有这条豁免。域名带 runtime 实连证据 + library-file tier 时会被压
      「待核」，于是 `is_runtime_contact` 徽标标着实连、advice 却是待核，出口自相矛盾，
      且 runtime-first 的闭环候选被 `targets.py` 的 advice 门直接挡掉。
    """
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import OBSERVED_CONTACT_SOURCES, Endpoint, Evidence

    def _lead(source: str):
        ep = Endpoint(
            value="api.fraud-x.cn", kind="domain", is_private=False,
            evidences=[Evidence(source=source, location=_VENDOR_PATH,
                                snippet="https://api.fraud-x.cn/a")],
            enrichment={"tier": infra.TIER_LIBRARY_FILE},
        )
        return build_endpoint_leads([ep])[0]

    live = _lead(sorted(OBSERVED_CONTACT_SOURCES)[0])
    assert live.advice == infra.ADVICE_INVESTIGATE, "实连过的域名被 tier 降档了"
    assert not (live.downgrades or {}), f"实连过的域名不该有降档墓碑：{live.downgrades}"

    # 对照：纯静态来源仍降档——豁免只对实连证据开口，不是把域名侧降档整体关掉
    static = _lead("static")
    assert static.advice == infra.ADVICE_REVIEW
    assert "source_tier" in (static.downgrades or {})


def test_bulk_string_ip_is_tier_demoted_at_lead_level() -> None:
    """bulk-string 档的 IP 同样降待核并留墓碑（超大字符串表里的 IP 常量）。"""
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Endpoint, Evidence

    ep = Endpoint(
        value=_VENDOR_IP_A, kind="ip", is_private=False,
        evidences=[Evidence(source="static", location="dex_strings",
                            snippet=f"https://{_VENDOR_IP_A}/x")],
        enrichment={"tier": infra.TIER_BULK_STRING},
    )
    lead = build_endpoint_leads([ep])[0]
    assert lead.advice == infra.ADVICE_REVIEW
    assert "source_tier" in (lead.downgrades or {})


def test_non_investigate_ip_with_vendor_tier_gets_no_tombstone() -> None:
    """非最高档的 IP（私网→无需调证）不因 tier 长出墓碑——降档只作用于「建议调证」。

    删掉 `_ip_lead` 里 `advice == ADVICE_INVESTIGATE` 前置后本条变红：
    无需调证的 lead 会带上 source_tier 墓碑 + LOW，是出口可见的噪音。
    """
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Endpoint, Evidence

    ep = Endpoint(
        value="192.168.10.9", kind="ip", is_private=True,
        evidences=[Evidence(source="static", location=_VENDOR_PATH, snippet="x")],
        enrichment={"tier": infra.TIER_LIBRARY_FILE},
    )
    lead = build_endpoint_leads([ep])[0]
    assert lead.advice == infra.ADVICE_SKIP
    assert not (lead.downgrades or {}), f"无需调证的 lead 长出了墓碑：{lead.downgrades}"


def test_tier_demoted_lead_gets_no_forensic_paths() -> None:
    """降档后的 Lead 不追加「建议调证」专属的取证路径——`_apply_forensic` 必须读压完的档。

    ★复审实测：把 `_apply_forensic(lead.advice, …)` 突变回传**压档前**的 advice 后全仓仍绿。
      本条用对照差集锁住：同一端点 app 档（最高档）比 vendor 档多出的 evidence_to_obtain
      即取证路径追加——差集为空说明降档 lead 也被追加了（突变生效的形态）。
      域名侧同一突变面，一并锁。
    """
    from apkscan.core import infra
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Endpoint, Evidence

    def _lead(kind: str, value: str, tier: str):
        ep = Endpoint(
            value=value, kind=kind, is_private=False,
            evidences=[Evidence(source="static", location=_VENDOR_PATH,
                                snippet=f"https://{value}/x")],
            enrichment={"tier": tier},
        )
        return build_endpoint_leads([ep])[0]

    for kind, value in (("ip", _VENDOR_IP_A), ("domain", "api.fraud-x.cn")):
        control = _lead(kind, value, infra.TIER_APP)
        demoted = _lead(kind, value, infra.TIER_LIBRARY_FILE)
        assert control.advice == infra.ADVICE_INVESTIGATE, f"{kind} 对照组未判最高档，锁失效"
        assert demoted.advice == infra.ADVICE_REVIEW, f"{kind} 降档未生效，锁失效"
        gained = set(control.evidence_to_obtain) - set(demoted.evidence_to_obtain)
        assert gained, (
            f"{kind} 对照组没有多出任何取证路径——要么 forensic 不再追加（本条失去意义），"
            "要么降档 lead 也被追加了（_apply_forensic 读了压档前的 advice）"
        )


def test_flat_vendor_bundle_names_hit_library_file_glob() -> None:
    """扁平命名的 vendor bundle 要能命中 glob（网页证据没有 /static/js/ 那一层）。"""
    from apkscan.core import infra

    for loc in ("chunk-vendors.bc47c059.js", "evidence/chunk-vendors.abc.js",
                "vendors~main.1a2b.js", "vendor.9f8e.js"):
        assert infra.domain_source_tier(loc, 0) == infra.TIER_LIBRARY_FILE, loc
    for loc in ("app.204b4fda.js", "evidence/index.html"):
        assert infra.domain_source_tier(loc, 0) == infra.TIER_APP, loc


def test_web_context_keeps_site_own_minified_code_at_app_tier() -> None:
    """web 证据语境不照搬 APK 的 glob 表——站点自己的压缩代码不是第三方库。

    ★这条锁的是**降噪机制自身的误伤面**，方向与上面几条相反：在 APK 内部
      「``.min.js`` ≈ 第三方库」是个还行的先验；网页证据里站点自有业务代码几乎必然压缩过、
      资源路径又常含 ``/dist/``。若照搬，涉诈站自有后端会被整批降成待核——不发调证函、
      不进闭环、不做 ICP/WHOIS 富化，是**漏报**方向的误伤，比误报贵得多。
    """
    from apkscan.core import infra

    # web 语境：站点自有代码保持最高档
    for loc in ("static/js/app.a1b2.min.js", "js/main.min.js",
                "dist/assets/index.js", "assets/vendor/config.js"):
        assert infra.domain_source_tier(loc, 0, context="web") == infra.TIER_APP, loc
    # web 语境：明确的 vendor 命名仍然降档（降噪没被整体关掉）
    for loc in ("chunk-vendors.bc47c059.js", "static/js/chunk-vendors.abc.js"):
        assert infra.domain_source_tier(loc, 0, context="web") == infra.TIER_LIBRARY_FILE, loc
    # APK 语境（默认）不受影响：同样这些路径照旧判 library-file
    for loc in ("static/js/app.a1b2.min.js", "js/main.min.js", "assets/vendor/config.js"):
        assert infra.domain_source_tier(loc, 0) == infra.TIER_LIBRARY_FILE, loc


def test_basename_globs_do_not_traverse_directories() -> None:
    """vendor 文件名判据只比 basename——``fnmatch`` 的 ``*`` 跨 ``/``，写成全路径模式会整树降档。"""
    from apkscan.core import infra

    for loc in ("assets/vendor.min/app.business.js",  # 目录恰好叫 vendor.min
                "vendor.abc/deep/path/app.js",
                "chunk-vendors-copycat/settings.json"):
        assert infra.domain_source_tier(loc, 0) == infra.TIER_APP, f"{loc} 被目录穿透降档"
