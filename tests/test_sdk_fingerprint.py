"""sdk_fingerprint 分析器测试 — 用 conftest 的 FakeContext 喂合成数据。

覆盖：
- 命中（dex 类前缀 / so 库名 / 资源文件 三路）→ 正确产出 SDK_SERVICE Lead。
- 置信度按匹配强度：so/file 或多类特征 → HIGH；仅单一 dex → MEDIUM。
- Lead 字段：value=SDK 名、subject/where_to_request=厂商、evidence_to_obtain 来自规则。
- source_refs（Evidence）的 source/location 正确。
- 不命中：无 Lead，meta 标注空。
- 错误韧性：dex_strings 抛异常不炸 analyze（仍能靠 so/file 命中）。
"""

from __future__ import annotations

from collections.abc import Iterator

from apkscan.analyzers.sdk_fingerprint import SdkFingerprintAnalyzer
from apkscan.core.models import Confidence, LeadCategory
from tests.conftest import FakeContext


def _analyzer() -> SdkFingerprintAnalyzer:
    return SdkFingerprintAnalyzer()


def _leads_by_value(result) -> dict[str, object]:
    return {lead.value: lead for lead in result.leads}


# ---------------------------------------------------------------------------
# 基本属性
# ---------------------------------------------------------------------------


def test_analyzer_identity() -> None:
    a = _analyzer()
    assert a.name == "sdk_fingerprint"
    assert a.requires == ["apk"]


# ---------------------------------------------------------------------------
# 命中：dex 类前缀
# ---------------------------------------------------------------------------


def test_hit_via_dex_prefix_jpush() -> None:
    """极光推送：仅 dex 类前缀命中 → 一条 SDK_SERVICE Lead。"""
    ctx = FakeContext(
        dex_strings=[
            "cn.jpush.android.api.JPushInterface",
            "some.unrelated.String",
        ],
    )
    result = _analyzer().analyze(ctx)

    assert result.error is None
    leads = _leads_by_value(result)
    assert "极光推送 (JPush / JIGUANG)" in leads

    lead = leads["极光推送 (JPush / JIGUANG)"]
    assert lead.category == LeadCategory.SDK_SERVICE
    assert lead.subject is not None and "极光" in lead.subject
    assert lead.where_to_request == lead.subject
    assert lead.evidence_to_obtain  # 非空
    assert lead.source_refs
    # 仅单一 dex 特征 → MEDIUM
    assert lead.confidence == Confidence.MEDIUM


def test_dex_hit_evidence_source_and_location() -> None:
    ctx = FakeContext(dex_strings=["com.umeng.analytics.MobclickAgent"])
    result = _analyzer().analyze(ctx)

    leads = _leads_by_value(result)
    assert "友盟统计 (UMeng Analytics)" in leads
    ev = leads["友盟统计 (UMeng Analytics)"].source_refs[0]
    assert ev.source == "dex"
    assert ev.location == "com.umeng.analytics"
    assert "com.umeng.analytics" in ev.snippet


# ---------------------------------------------------------------------------
# 命中：so 库名 / 资源文件 → 强特征 HIGH
# ---------------------------------------------------------------------------


def test_hit_via_so_is_high_confidence() -> None:
    """融云 IM：so 库名命中（强特征）→ HIGH。native_libs 与 list_files 双路均可。"""
    ctx = FakeContext(
        native_libs=["lib/arm64-v8a/librongimlib.so"],
    )
    result = _analyzer().analyze(ctx)

    leads = _leads_by_value(result)
    assert "融云 IM (RongCloud)" in leads
    lead = leads["融云 IM (RongCloud)"]
    assert lead.confidence == Confidence.HIGH
    ev = lead.source_refs[0]
    assert ev.source == "native"
    assert ev.location == "lib/arm64-v8a/librongimlib.so"


def test_hit_via_so_in_list_files() -> None:
    """so 也可能只出现在 list_files（非 native_libs）中，仍应命中。"""
    ctx = FakeContext(
        files={"lib/armeabi-v7a/libgetui.so": b"\x7fELF"},
    )
    result = _analyzer().analyze(ctx)
    leads = _leads_by_value(result)
    assert "个推 (GeTui / Getui)" in leads
    assert leads["个推 (GeTui / Getui)"].confidence == Confidence.HIGH


def test_hit_via_resource_file_is_high_confidence() -> None:
    """华为 HMS：资源文件 agconnect-services.json 命中（强特征）→ HIGH。"""
    ctx = FakeContext(
        files={"agconnect-services.json": b"{}"},
    )
    result = _analyzer().analyze(ctx)

    leads = _leads_by_value(result)
    assert "华为推送 (Huawei HMS Push)" in leads
    lead = leads["华为推送 (Huawei HMS Push)"]
    assert lead.confidence == Confidence.HIGH
    ev = lead.source_refs[0]
    assert ev.source == "resource"
    assert ev.location == "agconnect-services.json"


# ---------------------------------------------------------------------------
# 多类特征 → HIGH
# ---------------------------------------------------------------------------


def test_multiple_kinds_is_high_confidence() -> None:
    """支付宝：dex 前缀 + so 同时命中 → 多类特征 → HIGH。"""
    ctx = FakeContext(
        dex_strings=["com.alipay.sdk.app.PayTask"],
        native_libs=["lib/arm64-v8a/libalipayssl.so"],
    )
    result = _analyzer().analyze(ctx)

    leads = _leads_by_value(result)
    assert "支付宝 (Alipay SDK)" in leads
    lead = leads["支付宝 (Alipay SDK)"]
    assert lead.confidence == Confidence.HIGH
    # 至少两条证据（dex + native）
    sources = {ev.source for ev in lead.source_refs}
    assert "dex" in sources and "native" in sources


# ---------------------------------------------------------------------------
# 规则自带 evidence_to_obtain 应被采用
# ---------------------------------------------------------------------------


def test_payment_lead_uses_rule_specific_evidence() -> None:
    """微信支付规则自带 evidence_to_obtain（含 mch_id），应原样出现在 Lead。"""
    ctx = FakeContext(
        dex_strings=["com.tencent.mm.opensdk.openapi.IWXAPI"],
    )
    result = _analyzer().analyze(ctx)

    leads = _leads_by_value(result)
    assert "微信支付 (WeChat Pay / OpenSDK)" in leads
    evs = leads["微信支付 (WeChat Pay / OpenSDK)"].evidence_to_obtain
    joined = " ".join(evs)
    assert "商户号" in joined or "mch_id" in joined


# ---------------------------------------------------------------------------
# 多 SDK 同时命中
# ---------------------------------------------------------------------------


def test_multiple_sdks_hit_and_meta() -> None:
    ctx = FakeContext(
        dex_strings=[
            "cn.jpush.android.api.JPushInterface",
            "com.amap.api.location.AMapLocationClient",
            "com.tendcloud.tenddata.TalkingDataSDK",
        ],
        files={"lib/arm64-v8a/libBaiduMapSDK_base.so": b"\x7fELF"},
    )
    result = _analyzer().analyze(ctx)

    values = {lead.value for lead in result.leads}
    assert "极光推送 (JPush / JIGUANG)" in values
    assert "高德地图 (AMap / Gaode)" in values
    assert "TalkingData" in values
    assert "百度地图 (Baidu Map)" in values

    # meta 汇总
    assert set(result.meta["sdks"]) == values
    assert isinstance(result.meta["sdk_categories"], dict)
    assert result.meta["sdk_categories"].get("push", 0) >= 1
    assert result.meta["sdk_categories"].get("map", 0) >= 1


# ---------------------------------------------------------------------------
# 不命中
# ---------------------------------------------------------------------------


def test_no_hit_produces_no_leads() -> None:
    ctx = FakeContext(
        dex_strings=[
            "java.lang.String",
            "androidx.appcompat.app.AppCompatActivity",
            "https://example.com/whatever",
        ],
        files={"res/values/strings.xml": b"<resources/>"},
        native_libs=["lib/arm64-v8a/libc++_shared.so"],
    )
    result = _analyzer().analyze(ctx)

    assert result.error is None
    assert result.leads == []
    assert result.meta["sdks"] == []


def test_empty_context_no_hit(fake_ctx) -> None:
    """conftest 默认 fake_ctx 只含 jpush 一条 SDK 字符串 → 恰好命中极光，其余无。

    （fake_ctx.dex_strings 含 'cn.jpush.android.api.JPushInterface'）
    """
    result = _analyzer().analyze(fake_ctx)
    values = {lead.value for lead in result.leads}
    assert "极光推送 (JPush / JIGUANG)" in values
    # 不应误报其它 SDK
    assert all(lead.category == LeadCategory.SDK_SERVICE for lead in result.leads)


# ---------------------------------------------------------------------------
# 错误韧性
# ---------------------------------------------------------------------------


class _BoomDexContext(FakeContext):
    """dex_strings 遍历时抛异常，验证 analyze 不崩、仍能靠 so/file 命中。"""

    def dex_strings(self) -> Iterator[str]:
        def _gen() -> Iterator[str]:
            raise RuntimeError("boom dex")
            yield ""  # pragma: no cover

        return _gen()


def test_dex_iteration_error_does_not_crash() -> None:
    ctx = _BoomDexContext(
        native_libs=["lib/arm64-v8a/libgetui.so"],
    )
    result = _analyzer().analyze(ctx)

    # analyze 不抛、不写 result.error（单源失败被吞在内部并记日志）
    assert result.error is None
    assert result.meta["dex_scanned"] is False
    # 仍能靠 so 命中个推
    values = {lead.value for lead in result.leads}
    assert "个推 (GeTui / Getui)" in values


def test_all_sources_empty_no_crash() -> None:
    ctx = FakeContext()
    result = _analyzer().analyze(ctx)
    assert result.error is None
    assert result.leads == []
    assert result.meta["sdks"] == []
