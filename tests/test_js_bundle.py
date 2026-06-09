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
        {_UNIAPP_PATH: b"var c={app_secret:'zwBt8Xsz3V9RCAZJLbfcL5x'};"}
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
        {_UNIAPP_PATH: b"var a='2.1.5.1';var b='1.2.3.4';var c='45.76.10.20';"}
    )
    ips = {ep.value for ep in result.endpoints if ep.kind == "ip"}
    assert "2.1.5.1" not in ips
    assert "1.2.3.4" not in ips
    assert "45.76.10.20" in ips


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
