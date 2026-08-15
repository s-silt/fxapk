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

import pytest

from apkscan.analyzers.config_keys import ConfigKeysAnalyzer
from apkscan.core import infra
from apkscan.core.infra import ADVICE_SKIP
from apkscan.core.models import AnalyzerResult, Confidence, Lead, LeadCategory, Severity
from tests.conftest import FakeContext


def _analyzer() -> ConfigKeysAnalyzer:
    return ConfigKeysAnalyzer()


def _leads_by_value(result: AnalyzerResult) -> dict[str, Lead]:
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
    '    <meta-data android:name="GTSDK_VERSION" android:value="3.2.16.7"/>\n'  # leak-scan: allow SDK 版本号夹具，不是网络地址
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
    # 版本号等框架/系统样板 → 降噪档（不淹没真凭据线索）
    assert by_val["GTSDK_VERSION=3.2.16.7"].advice == ADVICE_SKIP

# ---------------------------------------------------------------------------
# 厂商推送凭据的**归属**：拿到值还不够，得知道该向谁调取
# ---------------------------------------------------------------------------
#
# ★这一组锁的是 subject，不是「能不能提取」：未命中任何规则的 <meta-data> 照样会成为
#   CONFIG_KEY 线索（分析器对全部 meta-data 一视同仁），只是 subject 落到「待核（应用配置）」。
#   差别在于那条线索能不能落地——「MIPUSH_APPID=<值>，向谁调取？待核」是废线索。


def _ctx(manifest_body: str) -> FakeContext:
    return FakeContext(
        package_name="com.example.app",
        manifest_xml=(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.example.app">\n'
            f'  <application>\n{manifest_body}  </application>\n'
            '</manifest>\n'
        ),
        files={},
    )


def _meta(name: str, value: str) -> str:
    return f'    <meta-data android:name="{name}" android:value="{value}"/>\n'


@pytest.mark.parametrize(("key_name", "expect_in_subject"), [
    # 各家 SDK 的标准连写形态——原先只有下划线前缀（MI_/OPPO_/VIVO_），接不住这些。
    ("MIPUSH_APPID", "小米"),
    ("MIPUSH_APPKEY", "小米"),
    ("OPPOPUSH_APPKEY", "OPPO"),
    ("VIVOPUSH_APPID", "vivo"),
    # 魅族/荣耀此前整家无归属规则，只收已见过形态的具体键名。
    ("MEIZU_APPID", "魅族"),
    ("FLYME_APPID", "魅族"),
    ("HONOR_APPID", "荣耀"),
])
def test_vendor_push_credential_is_attributed_to_the_vendor(
    key_name: str, expect_in_subject: str
) -> None:
    """★走真入口：厂商推送凭据要带**具体归属**，否则拿到值也不知道向谁调取。

    规则退回原状（去掉连写前缀 / 删掉魅族荣耀两家），本测试即红——那时这些键仍会产出线索，
    但 subject 是「待核（应用配置）」。
    """
    result = _analyzer().analyze(_ctx(_meta(key_name, "Abc123Xyz789Def456")))
    assert result.error is None

    lead = _leads_by_value(result).get(f"{key_name}=Abc123Xyz789Def456")
    assert lead is not None, f"{key_name} 没产出线索"
    assert lead.subject and expect_in_subject in lead.subject, (
        f"{key_name} 的归属是 {lead.subject!r}——拿到值却不知道向谁调取，线索落不了地"
    )
    assert lead.where_to_request == lead.subject
    assert lead.advice == infra.ADVICE_INVESTIGATE


@pytest.mark.parametrize("key_name", [
    # ★负例：厂商命名空间下的**非凭据**配置。它们与推送无关，绝不能被归成「推送」——
    #   _advice_for 对命中规则的键一律给最高档，误归属会直接产出错误的调取落点。
    "HONOR_THEME",
    "MEIZU_CHANNEL_CONFIG",
    "FLYME_FEATURE_FLAG",
])
def test_vendor_namespace_non_credential_keys_are_not_attributed_to_push(key_name: str) -> None:
    """厂商命名空间 ≠ 推送凭据形态。收 `MEIZU_` / `HONOR_` 这类宽前缀就会踩这里。"""
    result = _analyzer().analyze(_ctx(_meta(key_name, "some_value_here")))
    assert result.error is None

    lead = _leads_by_value(result).get(f"{key_name}=some_value_here")
    assert lead is not None
    # ★断言的是 subject（归属主体），不是 notes 里的 SDK 名：subject 才是文书的受文对象。
    #   未命中任何规则时它是兜底的「待核（应用配置）」——那正是我们要的结果：拿到了值，
    #   但不冒充知道该找谁。误归属后 subject 会变成厂商公司全称，据此就会发出错误的函。
    assert lead.subject == "待核（应用配置）", (
        f"{key_name} 被误归给了 {lead.subject!r}——厂商命名空间不等于推送凭据形态，"
        f"据此产出的是指向该厂商的错误落点"
    )


def test_vendor_push_credential_end_to_end_has_concrete_value_and_recipient() -> None:
    """端到端：两家的凭据同时在场时，各自带对的具体值与受文对象。"""
    result = _analyzer().analyze(
        _ctx(_meta("MIPUSH_APPID", "2882303761520123456")
             + _meta("MEIZU_APPKEY", "xML3o7rBgL6naCbxeYS9m8"))
    )
    assert result.error is None

    by_val = _leads_by_value(result)
    mi = by_val.get("MIPUSH_APPID=2882303761520123456")
    mz = by_val.get("MEIZU_APPKEY=xML3o7rBgL6naCbxeYS9m8")
    assert mi is not None and mz is not None

    assert mi.category == LeadCategory.CONFIG_KEY
    assert mi.subject and "小米" in mi.subject
    assert mz.subject and "魅族" in mz.subject, "魅族归属没锁住——删光魅族规则这条才会红"
    assert mi.advice == infra.ADVICE_INVESTIGATE
