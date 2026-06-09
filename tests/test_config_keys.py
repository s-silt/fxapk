"""config_keys 分析器测试 —— 用 conftest 的 FakeContext 喂合成数据。

覆盖（任务要求的核心断言）：
- manifest <meta-data> 抠出真实 key=value → CONFIG_KEY Lead，value 含
  'GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3'，subject 指向"个推 / 每日互动"。
- 各 key 的厂商归属（个推 / DCloud / 智数渠道 → 个推）。
- APPSECRET / APPKEY 等敏感凭据 → 额外 Finding(HIGH, secret)。
- uni-app manifest.json：id/name/confusion → meta + uni_encrypted=True + Finding。
- Lead 通用字段：confidence=HIGH、advice="建议调证"、where_to_request==subject。
- resource 引用（@xxx）→ value="@资源引用"。
- 未知 key → subject="待核（应用配置）"。
- 错误韧性：manifest 解析失败 / 无配置 → error 仍为 None。
"""

from __future__ import annotations

import json

from apkscan.analyzers.config_keys import ConfigKeysAnalyzer
from apkscan.core.models import Confidence, LeadCategory, Severity
from tests.conftest import FakeContext


def _analyzer() -> ConfigKeysAnalyzer:
    return ConfigKeysAnalyzer()


def _leads_by_value(result) -> dict[str, object]:
    return {lead.value: lead for lead in result.leads}


# 真实样本已验证的 <meta-data> 配置。
_REAL_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.budget.book.deep">\n'
    '  <application>\n'
    '    <meta-data android:name="GETUI_APPID" '
    'android:value="DVRqpR8NztAJAfq8f4dbv3"/>\n'
    '    <meta-data android:name="PUSH_APPID" '
    'android:value="DVRqpR8NztAJAfq8f4dbv3"/>\n'
    '    <meta-data android:name="PUSH_APPKEY" '
    'android:value="xML3o7rBgL6naCbxeYS9m8"/>\n'
    '    <meta-data android:name="PUSH_APPSECRET" '
    'android:value="zwBt8Xsz3V9RCAZJLbfcL5"/>\n'
    '    <meta-data android:name="ZX_APPID_GETUI" '
    'android:value="913e6a50-c3b6-4989-8ac6-1ecb53649be3"/>\n'
    '    <meta-data android:name="ZX_CHANNEL_ID" '
    'android:value="C01-GEztJH0JLdBC"/>\n'
    '    <meta-data android:name="GTSDK_VERSION" android:value="3.3.7.0"/>\n'
    '    <meta-data android:name="DCLOUD_STREAMAPP_CHANNEL" '
    'android:value="com.budget.book.deep|__UNI__F7A0431|128087290804|"/>\n'
    '    <meta-data android:name="THEME_COLOR" android:resource="@color/primary"/>\n'
    '  </application>\n'
    '</manifest>\n'
)


def _uni_manifest_json() -> bytes:
    return json.dumps(
        {
            "id": "__UNI__F7A0431",
            "name": "示例记账",
            "version": {"name": "1.0.0", "code": "100"},
            "description": "记账本",
            "plus": {"confusion": {"resources": "*.html,*.js,*.css"}},
        },
        ensure_ascii=False,
    ).encode("utf-8")


def _real_ctx() -> FakeContext:
    return FakeContext(
        package_name="com.budget.book.deep",
        manifest_xml=_REAL_MANIFEST,
        files={
            "assets/apps/__UNI__F7A0431/www/manifest.json": _uni_manifest_json(),
        },
    )


# ---------------------------------------------------------------------------
# 基本属性
# ---------------------------------------------------------------------------


def test_analyzer_identity() -> None:
    a = _analyzer()
    assert a.name == "config_keys"
    assert a.requires == []


# ---------------------------------------------------------------------------
# ★ 核心：抠出具体值 GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3
# ---------------------------------------------------------------------------


def test_getui_appid_concrete_value_lead() -> None:
    result = _analyzer().analyze(_real_ctx())
    assert result.error is None

    leads = _leads_by_value(result)
    assert "GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3" in leads

    lead = leads["GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3"]
    assert lead.category == LeadCategory.CONFIG_KEY
    assert lead.subject is not None
    assert "个推" in lead.subject or "每日互动" in lead.subject
    assert lead.where_to_request == lead.subject
    assert lead.confidence == Confidence.HIGH
    assert lead.advice == "建议调证"
    assert lead.evidence_to_obtain  # 非空
    # source_refs 指向 manifest，snippet 含真实值。
    ev = lead.source_refs[0]
    assert ev.source == "manifest"
    assert "DVRqpR8NztAJAfq8f4dbv3" in ev.snippet


def test_zx_appid_getui_attributed_to_getui() -> None:
    """ZX_APPID_GETUI 应优先匹配最长前缀，归属个推（智数渠道）。"""
    result = _analyzer().analyze(_real_ctx())
    leads = _leads_by_value(result)

    key = "ZX_APPID_GETUI=913e6a50-c3b6-4989-8ac6-1ecb53649be3"
    assert key in leads
    subject = leads[key].subject
    assert subject is not None and ("个推" in subject or "每日互动" in subject)


def test_dcloud_channel_attributed_to_dcloud() -> None:
    result = _analyzer().analyze(_real_ctx())
    leads = _leads_by_value(result)

    key = "DCLOUD_STREAMAPP_CHANNEL=com.budget.book.deep|__UNI__F7A0431|128087290804|"
    assert key in leads
    subject = leads[key].subject
    assert subject is not None and "DCloud" in subject


# ---------------------------------------------------------------------------
# 敏感凭据 → Finding(HIGH, secret)
# ---------------------------------------------------------------------------


def test_appsecret_produces_secret_finding() -> None:
    result = _analyzer().analyze(_real_ctx())

    secret_findings = [f for f in result.findings if f.category == "secret"]
    assert secret_findings, "PUSH_APPSECRET / PUSH_APPKEY 应产出 secret Finding"
    assert all(f.severity == Severity.HIGH for f in secret_findings)

    titles = " ".join(f.title for f in secret_findings)
    assert "PUSH_APPSECRET" in titles
    assert "PUSH_APPKEY" in titles


def test_plain_appid_is_not_secret_finding() -> None:
    """GETUI_APPID 不含 SECRET/KEY/TOKEN 关键词，不应误判为 secret。"""
    result = _analyzer().analyze(_real_ctx())
    secret_keys = [f.title for f in result.findings if f.category == "secret"]
    assert not any("GETUI_APPID" in t for t in secret_keys)


def test_sdk_constant_appkey_value_not_secret_finding() -> None:
    """C2：value==key（OPPOPUSH_APPKEY=OPPOPUSH_APPKEY）的 meta-data 不应产 secret Finding。

    虽然 key 名含 APPKEY，但 value 是常量名本身（非真凭据），按新语义不产 Finding；
    CONFIG_KEY lead 仍照常产出（无信息损失）。
    """
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.test.app">\n'
        '  <application>\n'
        '    <meta-data android:name="OPPOPUSH_APPKEY" android:value="OPPOPUSH_APPKEY"/>\n'
        '    <meta-data android:name="KEY_DEVICE_TOKEN" android:value="deviceToken"/>\n'
        '    <meta-data android:name="METHOD_CHECK_APPKEY" android:value="dc_checkappkey"/>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    result = _analyzer().analyze(FakeContext(manifest_xml=manifest))
    assert [f for f in result.findings if f.category == "secret"] == []
    # CONFIG_KEY lead 仍产出（无信息损失）。
    leads = _leads_by_value(result)
    assert "OPPOPUSH_APPKEY=OPPOPUSH_APPKEY" in leads


# ---------------------------------------------------------------------------
# uni-app manifest.json：confusion → 加密 Finding + meta
# ---------------------------------------------------------------------------


def test_uni_app_encrypted_and_meta() -> None:
    result = _analyzer().analyze(_real_ctx())

    assert result.meta.get("uni_encrypted") is True
    assert result.meta.get("uni_appid") == "__UNI__F7A0431"
    assert result.meta.get("uni_app_name") == "示例记账"

    enc_findings = [f for f in result.findings if f.id == "CONFIG-UNIAPP-ENCRYPTED"]
    assert len(enc_findings) == 1
    f = enc_findings[0]
    assert f.severity == Severity.MEDIUM
    assert "脱壳" in f.description


def test_uni_app_without_confusion_sets_false() -> None:
    ctx = FakeContext(
        files={
            "assets/apps/__UNI__ABC/www/manifest.json": json.dumps(
                {"id": "__UNI__ABC", "name": "clean"}
            ).encode("utf-8"),
        },
    )
    result = _analyzer().analyze(ctx)
    assert result.meta.get("uni_encrypted") is False
    assert not [f for f in result.findings if f.id == "CONFIG-UNIAPP-ENCRYPTED"]


# ---------------------------------------------------------------------------
# resource 引用 → "@资源引用"
# ---------------------------------------------------------------------------


def test_resource_reference_value() -> None:
    result = _analyzer().analyze(_real_ctx())
    leads = _leads_by_value(result)
    assert "THEME_COLOR=@资源引用" in leads


# ---------------------------------------------------------------------------
# 未知 key → 待核
# ---------------------------------------------------------------------------


def test_unknown_key_subject_is_pending() -> None:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.test.app">\n'
        '  <application>\n'
        '    <meta-data android:name="MY_CUSTOM_FLAG" android:value="42"/>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    result = _analyzer().analyze(FakeContext(manifest_xml=manifest))
    leads = _leads_by_value(result)
    assert "MY_CUSTOM_FLAG=42" in leads
    assert leads["MY_CUSTOM_FLAG=42"].subject == "待核（应用配置）"


# ---------------------------------------------------------------------------
# meta：config_key_count
# ---------------------------------------------------------------------------


def test_config_key_count_meta() -> None:
    result = _analyzer().analyze(_real_ctx())
    assert result.meta["config_key_count"] == len(result.leads)
    assert result.meta["config_key_count"] >= 9  # 9 个 meta-data + uni 字段


# ---------------------------------------------------------------------------
# 额外配置文件：strings.xml / dcloud_uniplugins.json
# ---------------------------------------------------------------------------


def test_strings_xml_key_values() -> None:
    strings = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '  <string name="UMENG_APPKEY">5f0a1b2c3d4e</string>\n'
        '  <string name="app_name">记账</string>\n'
        '</resources>\n'
    )
    ctx = FakeContext(
        files={"res/values/strings.xml": strings.encode("utf-8")},
    )
    result = _analyzer().analyze(ctx)
    leads = _leads_by_value(result)
    assert "UMENG_APPKEY=5f0a1b2c3d4e" in leads
    subject = leads["UMENG_APPKEY=5f0a1b2c3d4e"].subject
    assert subject is not None and "友盟" in subject
    # APPKEY → secret Finding
    assert any(
        f.category == "secret" and "UMENG_APPKEY" in f.title for f in result.findings
    )


# ---------------------------------------------------------------------------
# 错误韧性 / 空输入
# ---------------------------------------------------------------------------


def test_empty_context_clean_return() -> None:
    result = _analyzer().analyze(FakeContext())
    assert result.error is None
    assert result.leads == []
    assert result.meta["config_key_count"] == 0


def test_malformed_manifest_does_not_crash() -> None:
    result = _analyzer().analyze(FakeContext(manifest_xml="<manifest><broken"))
    # 单源失败被吞内部并记日志，analyze 不抛、error 仍 None。
    assert result.error is None
    assert result.meta["config_key_count"] == 0


def test_config_key_lead_common_fields_and_advice_grading() -> None:
    result = _analyzer().analyze(_real_ctx())
    assert result.leads
    for lead in result.leads:
        assert lead.category == LeadCategory.CONFIG_KEY
        assert lead.confidence == Confidence.HIGH
        assert lead.where_to_request == lead.subject
        # advice 三态之一（凭据=建议调证、框架样板=无需调证、其余=待核）。
        assert lead.advice in ("建议调证", "无需调证", "待核")

    by_val = _leads_by_value(result)
    # 凭据 / AppID / 渠道 / __UNI__ → 建议调证
    assert by_val["GETUI_APPID=DVRqpR8NztAJAfq8f4dbv3"].advice == "建议调证"
    assert by_val["PUSH_APPSECRET=zwBt8Xsz3V9RCAZJLbfcL5"].advice == "建议调证"
    assert by_val["ZX_CHANNEL_ID=C01-GEztJH0JLdBC"].advice == "建议调证"
    # 版本号等框架/系统样板 → 无需调证（降噪，不淹没真凭据线索）
    assert by_val["GTSDK_VERSION=3.3.7.0"].advice == "无需调证"
