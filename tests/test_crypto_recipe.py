"""crypto_recipe 分析器（C5a）单测。

覆盖：
- 配方提取命中（合成 JS）：CryptoJS + 硬编码 key + iv 推导 + 信封字段 → CRYPTO_RECIPE lead
  + meta["crypto_recipe"] 各字段正确。
- 本地真样本真值验证（skipif 保护，无样本环境不挂）：key / AES / iv 含 md5。
- 无 CryptoJS → 不产配方。
- 规则缺失走兜底：monkeypatch load_rules 返回 {} 仍正确提取。
全程 type hints。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.analyzers import crypto_recipe as cr
from apkscan.analyzers.crypto_recipe import CryptoRecipeAnalyzer
from apkscan.core.models import LeadCategory
from tests.conftest import FakeContext

_EXPECTED_KEY = "55f0e4afd83cf8dcae7a4d3daf663467"
_GROUNDTRUTH_APKS = sorted((Path(__file__).resolve().parent.parent / "ybku").glob("*.apk"))

# 合成 JS：CryptoJS AES-CFB/Pkcs7 + 硬编码 key（utf8）+ iv=MD5(key+ts).substring(0,16)
# + 请求信封 {timestamp,data} —— 复刻真样本形态（值是合成的，不是真 key）。
_SYNTHETIC_JS = """
var cu = CryptoJS;
var wl = "0123456789abcdef0123456789abcdef";
function vu(e){ return cu.MD5(e).toString().substring(0,16); }
function yu(e,t,n){
  const i=cu.enc.Utf8.parse(t), o=cu.enc.Utf8.parse(n);
  return cu.AES.decrypt(e,i,{iv:o,mode:cu.mode.CFB,padding:cu.pad.Pkcs7}).toString(cu.enc.Utf8);
}
request.use((async e=>{
  const t=function(e,t){
    const n=(new Date).getTime(), i=vu(t+n), o=cu.enc.Utf8.parse(t), r=cu.enc.Utf8.parse(i);
    return {timestamp:n, data:cu.AES.encrypt(e,o,{iv:r,mode:cu.mode.CFB,padding:cu.pad.Pkcs7}).toString()};
  }(JSON.stringify(e.data), wl);
  e.data={data:t.data, timestamp:t.timestamp};
}));
"""


def _ctx_with_js(js: str, path: str = "assets/apps/__UNI__X/www/app-service.js") -> FakeContext:
    return FakeContext(files={path: js.encode("utf-8")})


# ---------------------------------------------------------------------------
# 配方提取命中（合成 JS）
# ---------------------------------------------------------------------------


def test_recipe_extracted_from_synthetic_js() -> None:
    ctx = _ctx_with_js(_SYNTHETIC_JS)
    result = CryptoRecipeAnalyzer().analyze(ctx)

    leads = [l for l in result.leads if l.category == LeadCategory.CRYPTO_RECIPE]
    assert len(leads) == 1
    assert leads[0].advice == "建议调证"

    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["algo"] == "AES"
    assert meta["mode"] == "CFB"
    assert meta["padding"] == "Pkcs7"
    assert meta["key_encoding"] == "utf8"
    assert meta["iv_derive"] == "md5(key+ts)[:16]"
    assert meta["key"] == "0123456789abcdef0123456789abcdef"
    assert "data" in meta["envelope_fields"]
    assert "timestamp" in meta["envelope_fields"]
    assert meta["payload_encoding"] == "base64"
    assert result.meta.get("crypto_recipe_count") == 1


def test_recipe_emits_finding() -> None:
    ctx = _ctx_with_js(_SYNTHETIC_JS)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    findings = [f for f in result.findings if f.id == cr.FINDING_RECIPE]
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert findings[0].category == "crypto"


def test_recipe_lead_value_masks_key() -> None:
    """Lead.value 摘要不暴露完整 key（首尾各 4 字符 + …）。"""
    ctx = _ctx_with_js(_SYNTHETIC_JS)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    lead = next(l for l in result.leads if l.category == LeadCategory.CRYPTO_RECIPE)
    assert "0123…cdef" in lead.value
    assert "0123456789abcdef0123456789abcdef" not in lead.value


# ---------------------------------------------------------------------------
# 负样本 / 兜底
# ---------------------------------------------------------------------------


def test_no_recipe_when_no_cryptojs() -> None:
    """纯端点 JS（无 CryptoJS） → 不产配方 lead / meta。"""
    js = 'var api="https://pay.example.com/notify"; fetch(api);'
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    assert not [l for l in result.leads if l.category == LeadCategory.CRYPTO_RECIPE]
    assert "crypto_recipe" not in result.meta


def test_no_recipe_when_cryptojs_but_no_key() -> None:
    """有 CryptoJS token 但无硬编码 key 常量 → 不产配方（is_usable=False）。"""
    js = "var x = CryptoJS.AES.encrypt(data, someVar, {mode:CryptoJS.mode.CFB});"
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    assert "crypto_recipe" not in result.meta


def test_rules_missing_falls_back_to_builtin(monkeypatch: pytest.MonkeyPatch) -> None:
    """load_rules 返回 {} → 仍用内置 token 正确提取。"""
    monkeypatch.setattr(cr, "load_rules", lambda name: {})
    ctx = _ctx_with_js(_SYNTHETIC_JS)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["algo"] == "AES"
    assert meta["key"] == "0123456789abcdef0123456789abcdef"


def test_analyzer_never_raises_on_bad_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """list_files 抛异常 → analyze 不崩，返回空配方。"""

    class _BoomCtx(FakeContext):
        def list_files(self) -> list[str]:
            raise RuntimeError("boom")

    result = CryptoRecipeAnalyzer().analyze(_BoomCtx())
    assert "crypto_recipe" not in result.meta


def test_hex_key_encoding_detected() -> None:
    """key 经 enc.Hex.parse 包裹 → key_encoding=hex。"""
    js = """
    var CryptoJS;
    var hk = "00112233445566778899aabbccddeeff";
    var i = CryptoJS.enc.Hex.parse(hk);
    var ct = CryptoJS.AES.encrypt(plain, i, {mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7});
    """
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["key_encoding"] == "hex"
    assert meta["mode"] == "CBC"


# ---------------------------------------------------------------------------
# 泛化：放宽 key 变量名长度（未/半混淆 bundle）+ iv 推导真识别（fixed/same_as_key/unknown）
# ---------------------------------------------------------------------------


def test_recipe_extracted_with_long_key_varname() -> None:
    """未混淆 bundle：key 变量名 >4 字符（secretKey）仍能命中（修复前 1..4 漏抓）。"""
    js = """
    var CryptoJS;
    var secretKey = "0123456789abcdef0123456789abcdef";
    var k = CryptoJS.enc.Utf8.parse(secretKey);
    function vu(e){ return CryptoJS.MD5(e).toString().substring(0,16); }
    var ct = CryptoJS.AES.encrypt(plain, k,
        {iv: CryptoJS.enc.Utf8.parse(vu(secretKey)), mode:CryptoJS.mode.CFB, padding:CryptoJS.pad.Pkcs7});
    """
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["key"] == "0123456789abcdef0123456789abcdef"
    assert meta["algo"] == "AES"
    assert meta["iv_derive"] == "md5(key+ts)[:16]"


def test_iv_derive_fixed_detected() -> None:
    """固定 iv（iv:enc.Utf8.parse("字面量")）→ iv_derive=fixed + iv_value，不再误标 md5。"""
    js = """
    var CryptoJS;
    var kk = "0123456789abcdef0123456789abcdef";
    var key = CryptoJS.enc.Utf8.parse(kk);
    var ct = CryptoJS.AES.encrypt(plain, key,
        {iv: CryptoJS.enc.Utf8.parse("1234567890abcdef"), mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7});
    """
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["iv_derive"] == "fixed"
    assert meta["iv_value"] == "1234567890abcdef"


def test_iv_derive_same_as_key_detected() -> None:
    """iv 与 key 用同一变量 → iv_derive=same_as_key，不再误标 md5。"""
    js = """
    var CryptoJS;
    var kk = "0123456789abcdef0123456789abcdef";
    var key = CryptoJS.enc.Utf8.parse(kk);
    var ct = CryptoJS.AES.encrypt(plain, key,
        {iv: CryptoJS.enc.Utf8.parse(kk), mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7});
    """
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["iv_derive"] == "same_as_key"


def test_iv_derive_unknown_when_no_md5_no_iv() -> None:
    """无 md5、无 iv 字面量、iv 非同 key → iv_derive=unknown（不伪造 md5 推导）。"""
    js = """
    var CryptoJS;
    var kk = "0123456789abcdef0123456789abcdef";
    var key = CryptoJS.enc.Utf8.parse(kk);
    var ivv = CryptoJS.lib.WordArray.random(16);
    var ct = CryptoJS.AES.encrypt(plain, key,
        {iv: ivv, mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7});
    """
    ctx = _ctx_with_js(js)
    result = CryptoRecipeAnalyzer().analyze(ctx)
    meta = result.meta.get("crypto_recipe")
    assert isinstance(meta, dict)
    assert meta["iv_derive"] == "unknown"


# ---------------------------------------------------------------------------
# 本地真样本真值验证（skipif 保护）
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _GROUNDTRUTH_APKS, reason="本地无样本，跳过真值验证")
def test_groundtruth_key_extracted() -> None:
    from apkscan.core.apk import load_apk
    from apkscan.core.models import AnalysisConfig

    # 遍历本地 ybku/ 下的样本，找出产出目标加密配方的那个（按 key 定位，不硬编码样本文件名）。
    for apk in _GROUNDTRUTH_APKS:
        ctx = load_apk(str(apk), AnalysisConfig(online=False))
        result = CryptoRecipeAnalyzer().analyze(ctx)
        meta = result.meta.get("crypto_recipe")
        if not isinstance(meta, dict) or meta.get("key") != _EXPECTED_KEY:
            continue
        assert meta["algo"] == "AES"
        assert meta["mode"] == "CFB"
        assert meta["padding"] == "Pkcs7"
        assert meta["key_encoding"] == "utf8"
        assert "md5" in meta["iv_derive"]
        assert "app-service.js" in meta["source"]

        leads = [l for l in result.leads if l.category == LeadCategory.CRYPTO_RECIPE]
        assert len(leads) == 1
        return

    pytest.skip("本地样本中未找到目标加密配方")
