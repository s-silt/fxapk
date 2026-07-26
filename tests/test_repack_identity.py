"""repack_identity：自研马甲包 vs 正版重打包判别。零真实案件数据，全部合成 bytes。

每条断言对应实现里一段可删除的逻辑（删掉即红）：verdict 三态门、随机别名判定、品牌豁免、
弱信号不定 verdict、措辞边界（不许断言改动内容）、meta 结构与双胞胎画像。
"""
from __future__ import annotations

from apkscan.analyzers.repack_identity import (
    RepackIdentityAnalyzer,
    classify_sig_alias,
    decide_verdict,
    profile_stack,
)
from apkscan.core.models import CertInfo, Severity
from tests.conftest import FakeContext

_REPACK_ID = "REPACK-IDENTITY-SUSPECTED"
_SELF_ID = "REPACK-IDENTITY-SELF-BUILT"

_ELF = b"\x7fELF" + b"\x00" * 16

#: 四族商业栈（RN + OpenCV + card.io + SQLCipher），对齐实测重打包件的完整栈形态。
_RICH_STACK_FILES = {
    "lib/arm64-v8a/libhermes.so": _ELF,
    "lib/arm64-v8a/libjsi.so": _ELF,
    "lib/arm64-v8a/libopencv_java4.so": _ELF,
    "lib/arm64-v8a/libcardioDecider.so": _ELF,
    "lib/arm64-v8a/libsqlcipher.so": _ELF,
}


def _analyze(
    files: dict[str, bytes] | None = None,
    *,
    package_name: str = "com.sample.demoapp",
    dex_strings: list[str] | None = None,
    certificates: list[CertInfo] | None = None,
) -> object:
    files = dict(files or {})
    native_libs = [p for p in files if p.endswith(".so")]
    return RepackIdentityAnalyzer().analyze(
        FakeContext(
            package_name=package_name,
            files=files,
            native_libs=native_libs,
            dex_strings=dex_strings,
            certificates=certificates,
        )
    )


def _meta(result) -> dict:
    return result.meta["repack_identity"]


def _ids(result) -> list[str]:
    return [f.id for f in result.findings]


def _cert(sha256: str = "ab" * 32, *, is_debug: bool = False) -> CertInfo:
    return CertInfo(
        subject="CN=Synthetic",
        issuer="CN=Synthetic",
        sha256=sha256,
        not_before="2024-01-01T00:00:00",
        not_after="2049-01-01T00:00:00",
        is_debug=is_debug,
    )


# ---------------------------------------------------------------------------
# repack_suspected：随机别名 + 完整商业栈才判（AND 门）
# ---------------------------------------------------------------------------


def test_repack_suspected_on_random_alias_plus_rich_stack():
    """★核心场景：随机 8 位大写重签别名 + 四族商业栈 → repack_suspected。"""
    files = {"META-INF/QQWWEEDD.RSA": b"\x30\x82", **_RICH_STACK_FILES}
    result = _analyze(files)
    assert _meta(result)["verdict"] == "repack_suspected"
    assert _REPACK_ID in _ids(result)
    assert _meta(result)["signature"]["random_aliases"] == ["QQWWEEDD"]


def test_repack_finding_mandates_diff_verification_wording():
    """★verdict=repack_suspected 时，描述必须明确「接口/域名可能属于被仿冒的正版应用，须差分核实」。"""
    files = {"META-INF/QQWWEEDD.RSA": b"\x30\x82", **_RICH_STACK_FILES}
    result = _analyze(files)
    f = next(f for f in result.findings if f.id == _REPACK_ID)
    assert "可能属于被仿冒的正版应用" in f.description
    assert "作为调证线索前须与官方包差分核实" in f.description


def test_repack_wording_stays_within_evidence():
    """★边界：仅能确定「被重签名」，不许断言改动内容——禁词直接卡死在测试里。"""
    files = {"META-INF/QQWWEEDD.RSA": b"\x30\x82", **_RICH_STACK_FILES}
    result = _analyze(files)
    f = next(f for f in result.findings if f.id == _REPACK_ID)
    text = f.title + f.description + f.recommendation
    for banned in ("后门", "植入", "注入", "恶意"):
        assert banned not in text, f"措辞越界：{banned!r} 超出样本自身可证明的范围"


def test_random_alias_alone_is_not_repack():
    """随机别名单独出现（栈单薄）不判 repack：语料中确有随机别名 + 单薄栈的自研样本。"""
    files = {
        "META-INF/LWXXEIGO.RSA": b"\x30\x82",
        "lib/arm64-v8a/libsqlcipher.so": _ELF,  # 仅 1 族
    }
    result = _analyze(files)
    assert _meta(result)["verdict"] == "unknown"
    assert _REPACK_ID not in _ids(result)


def test_rich_stack_alone_is_not_repack():
    """完整商业栈 + 常规 CERT 别名不判 repack：无法与正主自己的正常发布件区分。"""
    files = {"META-INF/CERT.RSA": b"\x30\x82", **_RICH_STACK_FILES}
    result = _analyze(files)
    assert _meta(result)["verdict"] == "unknown"
    assert _REPACK_ID not in _ids(result)


def test_brand_alias_matching_package_is_not_random():
    """8+ 位大写品牌词与包名段相关 → package-brand 豁免，不判 repack（防误伤正版原厂签名）。"""
    files = {"META-INF/BRANDPAY.RSA": b"\x30\x82", **_RICH_STACK_FILES}
    result = _analyze(files, package_name="com.brandpay.wallet")
    assert _meta(result)["signature"]["alias_classes"]["BRANDPAY"] == "package-brand"
    assert _meta(result)["verdict"] != "repack_suspected"


# ---------------------------------------------------------------------------
# self_built：无重打包信号 + 栈单薄 + 正向标记
# ---------------------------------------------------------------------------


def test_self_built_on_short_alias_and_thin_stack():
    """品牌缩写式短别名 + 单一框架 → self_built（INFO 级倾向，非确证）。"""
    files = {
        "META-INF/HXK.RSA": b"\x30\x82",
        "lib/arm64-v8a/libflutter.so": _ELF,
    }
    result = _analyze(files)
    assert _meta(result)["verdict"] == "self_built"
    f = next(f for f in result.findings if f.id == _SELF_ID)
    assert f.severity == Severity.INFO


def test_debug_cert_counts_as_self_built_marker():
    """调试证书是自研正向标记：无签名块文件也能凭它 + 薄栈判 self_built。"""
    result = _analyze(
        {"lib/arm64-v8a/libnative.so": _ELF},
        certificates=[_cert(is_debug=True)],
    )
    assert _meta(result)["verdict"] == "self_built"


def test_thin_stack_without_positive_marker_stays_unknown():
    """仅栈单薄、无任何自研正向标记 → unknown：单一框架的正版被常规名重签后与自研不可分。"""
    result = _analyze(
        {"META-INF/CERT.RSA": b"\x30\x82", "lib/arm64-v8a/libflutter.so": _ELF},
        certificates=[_cert()],
    )
    assert _meta(result)["verdict"] == "unknown"
    assert result.findings == []


# ---------------------------------------------------------------------------
# 弱信号与三态不变量
# ---------------------------------------------------------------------------


def test_versioned_api_paths_recorded_but_never_decisive():
    """版本化接口路径是弱信号：只进 meta/signals，绝不把 verdict 推向 repack。"""
    apis = [f"/api/v1/user/endpoint{i}" for i in range(6)]
    result = _analyze(
        {"META-INF/Signer.RSA": b"\x30\x82"},
        dex_strings=apis,
    )
    assert _meta(result)["api_paths"]["versioned_count"] == 6
    assert "versioned-api-paths" in [s["id"] for s in _meta(result)["signals"]]
    assert _meta(result)["verdict"] == "unknown"


def test_meta_structure_and_three_state_on_empty_context():
    """空上下文：不炸、meta 结构齐全、verdict 落三态之一（且为 unknown）、无 Finding。"""
    result = RepackIdentityAnalyzer().analyze(FakeContext())
    meta = _meta(result)
    for key in ("verdict", "signals", "signature", "stack"):
        assert key in meta
    assert meta["verdict"] in {"self_built", "repack_suspected", "unknown"}
    assert meta["verdict"] == "unknown"
    assert result.findings == []


def test_hostile_context_never_raises():
    """certificates()/dex_strings() 全炸也不抛：保底 unknown 的 meta 仍在。"""

    class HostileContext(FakeContext):
        def certificates(self):
            raise RuntimeError("boom")

        def dex_strings(self):
            raise RuntimeError("boom")

    result = RepackIdentityAnalyzer().analyze(HostileContext())
    assert _meta(result)["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# meta 明细：签名摘要 / 双胞胎画像 / 多签名块
# ---------------------------------------------------------------------------


def test_cert_summary_in_signature_meta():
    result = _analyze(
        {"META-INF/CERT.RSA": b"\x30\x82"},
        certificates=[_cert(sha256="cd" * 32)],
    )
    sig = _meta(result)["signature"]
    assert sig["cert_count"] == 1
    assert sig["cert_sha256s"] == ["cd" * 32]


def test_content_profile_enables_twin_matching():
    """双胞胎比对画像：DEX 大小清单（zip 声明大小）+ .so 数量清单必须落 meta。"""
    files = {
        "classes.dex": b"d" * 100,
        "classes2.dex": b"d" * 200,
        "lib/arm64-v8a/libflutter.so": _ELF,
    }
    result = _analyze(files)
    profile = _meta(result)["content_profile"]
    assert profile["dex_sizes"] == [["classes.dex", 100], ["classes2.dex", 200]]
    assert profile["so_count"] == 1
    assert profile["so_names"] == ["libflutter.so"]


def test_multiple_signature_files_recorded_as_signal():
    """单包多签名块：记录明细供人核（不参与 verdict）。"""
    files = {
        "META-INF/AAAABBBB.RSA": b"\x30\x82",
        "META-INF/CCCCDDDD.RSA": b"\x30\x82",
    }
    result = _analyze(files)
    assert len(_meta(result)["signature"]["sig_files"]) == 2
    assert "multiple-signature-files" in [s["id"] for s in _meta(result)["signals"]]


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


def test_classify_sig_alias_tiers():
    assert classify_sig_alias("CERT", "com.a.b") == "conventional"
    assert classify_sig_alias("ANDROID", "com.a.b") == "conventional"
    assert classify_sig_alias("ABCDEFGH", "com.a.b") == "random-like"
    assert classify_sig_alias("GXZ", "com.a.b") == "short-alias"
    # 7 位是缓冲带：既不算随机也不算缩写（宁 unknown 不误判）。
    assert classify_sig_alias("ABCDEFG", "com.a.b") == "neutral"
    assert classify_sig_alias("Signer", "com.a.b") == "neutral"
    assert classify_sig_alias("BRANDPAY", "com.brandpay.wallet") == "package-brand"


def test_profile_stack_families():
    hits = profile_stack(
        ["libhermes.so", "libjsi.so", "libopencv_java4.so", "libcardioDecider.so", "libmisc.so"]
    )
    assert set(hits) == {"react_native", "opencv", "cardio"}
    assert hits["react_native"] == ["libhermes.so", "libjsi.so"]
    assert profile_stack(["libmisc.so"]) == {}


def test_decide_verdict_three_state():
    assert (
        decide_verdict(
            has_random_alias=True, has_short_alias=False, family_count=4, has_debug_cert=False
        )
        == "repack_suspected"
    )
    # AND 门：随机别名或完整栈单独都不够。
    assert (
        decide_verdict(
            has_random_alias=True, has_short_alias=False, family_count=1, has_debug_cert=False
        )
        == "unknown"
    )
    assert (
        decide_verdict(
            has_random_alias=False, has_short_alias=False, family_count=4, has_debug_cert=False
        )
        == "unknown"
    )
    assert (
        decide_verdict(
            has_random_alias=False, has_short_alias=True, family_count=1, has_debug_cert=False
        )
        == "self_built"
    )
    # 随机别名在场即阻断 self_built（矛盾信号 → unknown）。
    assert (
        decide_verdict(
            has_random_alias=True, has_short_alias=True, family_count=0, has_debug_cert=False
        )
        == "unknown"
    )
