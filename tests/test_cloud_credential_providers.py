"""云 / SaaS 凭据提供方精确上下文注册表与脱敏路由测试（Stage 2）。

覆盖：
1. 7 家受批厂商（aliyun/tencent_cloud/huawei_cloud/qiniu/upyun/rongcloud/agora）精确上下文配置键的合成无效占位符；
2. 通用键名与伪相似键名（api_key/secret/token/password/aws_secret_access_key 等）零误报；
3. 实际 BackendCredentialAnalyzer.analyze() 输出、Evidence/Lead/notes/location 与 digest 投影均仅含固定
   `[REDACTED]` 标记，绝不泄露原始占位符全文、前缀或长度；
4. 命中按受批注册表标签区分候选服务方路由（where_to_request / evidence_to_obtain 七家互异），明确须先核实
   主体与授权，绝不路由至旧版「使用/登录所获凭据」文案；置信度降为 MEDIUM，不硬编码厂商归属
5. 既有 legacy 后端凭据（Basic-Auth / DB DSN / JDBC / AKIA / LTAI）工作流、HIGH 置信度与指导文案保持不变；
6. 只认完整键值语法（JSON 完整键 + 字符串标量、assets 明文 XML 完整 <string>、整行引号字面量），
   编译资源（res/values、res/xml、AndroidManifest.xml）不扫；同组键每处出现各留一条确定性 source_refs。
"""

from __future__ import annotations

import pytest

import base64
import json

import fxapk.analyzers.backend_credential as bc_mod
from fxapk.analyzers.backend_credential import (
    STAGE2_INTEGRATION_GAPS,
    BackendCredentialAnalyzer,
    is_cloud_provider_hit_value,
    is_contextual_config_key,
    load_cloud_credential_providers,
    redact_credential_value,
)
from fxapk.analyzers.config_keys import ConfigKeysAnalyzer
from fxapk.core.leads import (
    _apply_default_advice,
    cloud_credential_provider_routing,
    is_redacted_cloud_provider_credential_value,
)
from fxapk.core.models import Confidence, Lead, LeadCategory
from fxapk.core.stage_preservation import dedup_leads
from fxapk.report.digest import _compact_lead
from fxapk.report.letters import build_letters


class _Ctx:
    def __init__(self, dex=None, files=None, contents=None, manifest_xml: str = "") -> None:
        self._dex = list(dex or [])
        self._files = list(files or [])
        self._contents = dict(contents or {})
        self.manifest_xml = manifest_xml
    def dex_strings(self):
        return list(self._dex)

    def list_files(self):
        return list(self._files)

    def read_file(self, path: str):
        return self._contents.get(path)


# 7 家精确厂商上下文配置键的合成无效占位符（长度与前缀各异，用于验证绝不泄露全文、前缀或长度）。
_SYNTHETIC_PROVIDER_CASES: tuple[tuple[str, str, str], ...] = (
    ("aliyun", "aliyun_access_key_secret", "SYNTH_INVALID_ALIYUN_PLACEHOLDER_90123456"),
    ("tencent_cloud", "tencent_secret_key", "SYNTH_INVALID_TENCENT_PLACEHOLDER_7890123456"),
    ("huawei_cloud", "huaweicloud_sdk_sk", "SYNTH_INVALID_HUAWEI_PLACEHOLDER_56789012345678"),
    ("qiniu", "qiniu_kodo_secret_key", "SYNTH_INVALID_QINIU_PLACEHOLDER_3456789012"),
    ("upyun", "upyun_operator_password", "SYNTH_INVALID_UPYUN_PLACEHOLDER_1234567890123"),
    ("rongcloud", "rongcloud_app_secret", "SYNTH_INVALID_RONGCLOUD_PLACEHOLDER_23456789"),
    ("agora", "agora_app_certificate", "SYNTH_INVALID_AGORA_PLACEHOLDER_4567890123456789"),
)


def test_seven_exact_provider_inventory() -> None:
    rules = load_cloud_credential_providers()
    assert [r.provider_id for r in rules] == [
        "aliyun",
        "tencent_cloud",
        "huawei_cloud",
        "qiniu",
        "upyun",
        "rongcloud",
        "agora",
    ]
    for rule in rules:
        assert rule.verification_status == "unverified"
        assert (rule.where_to_request, rule.evidence_to_obtain) == cloud_credential_provider_routing(rule.label)
        assert rule.label in rule.where_to_request
        assert all(rule.label in item for item in rule.evidence_to_obtain)
        assert all(is_contextual_config_key(k) for k in rule.config_keys)
    # 七家路由互异，不是同一条通用文案
    assert len({r.label for r in rules}) == 7
    assert len({r.where_to_request for r in rules}) == 7
    assert len({r.evidence_to_obtain for r in rules}) == 7


def test_seven_providers_analyze_output_redaction_and_routing() -> None:
    dex_entries = [
        f'{config_key} = "{placeholder}"'
        for _, config_key, placeholder in _SYNTHETIC_PROVIDER_CASES[:4]
    ]
    xml_entries = "\n".join(
        [
            f'    <string name="{_SYNTHETIC_PROVIDER_CASES[4][1]}" translatable="false">{_SYNTHETIC_PROVIDER_CASES[4][2]}</string>',
            f'    <string tools:ignore="ExtraTranslation" name="{_SYNTHETIC_PROVIDER_CASES[5][1]}">{_SYNTHETIC_PROVIDER_CASES[5][2]}</string>',
        ]
    )
    _, agora_key, agora_placeholder = _SYNTHETIC_PROVIDER_CASES[6]
    json_doc = json.dumps({"rtc": {"region_hint": "synthetic", agora_key: agora_placeholder}})
    xml_doc = f'<?xml version="1.0" encoding="utf-8"?>\n<resources xmlns:tools="http://schemas.android.com/tools">\n{xml_entries}\n</resources>\n'
    ctx = _Ctx(
        dex=dex_entries,
        files=["assets/config/cloud_sdk.xml", "assets/config/cloud_sdk.json"],
        contents={
            "assets/config/cloud_sdk.xml": xml_doc.encode("utf-8"),
            "assets/config/cloud_sdk.json": json_doc.encode("utf-8"),
        },
    )

    result = BackendCredentialAnalyzer().analyze(ctx)
    assert result.meta["backend_credential_count"] == 7
    assert len(result.leads) == 7

    labels = {r.provider_id: r.label for r in load_cloud_credential_providers()}
    by_value = {lead.value: lead for lead in result.leads}
    serialized_leads = []
    seen_where: set[str] = set()
    seen_evidence: set[tuple[str, ...]] = set()

    for provider_id, config_key, placeholder in _SYNTHETIC_PROVIDER_CASES:
        expected_value = f"{provider_id}:{config_key}=[REDACTED]"
        assert expected_value in by_value
        lead = by_value[expected_value]

        assert is_cloud_provider_hit_value(lead.value)
        assert is_redacted_cloud_provider_credential_value(lead.value)
        assert lead.category is LeadCategory.BACKEND_CREDENTIAL
        assert lead.confidence is Confidence.MEDIUM
        assert lead.advice == "建议调证"
        # 不硬编码候选厂商归属
        assert lead.subject is None

        # 按注册表标签指明候选服务方，且明确须先核实主体与授权；绝不指向「登录/使用所获凭据」
        label = labels[provider_id]
        expected_where, expected_evidence = cloud_credential_provider_routing(label)
        assert lead.where_to_request == expected_where
        assert lead.evidence_to_obtain == list(expected_evidence)
        assert lead.where_to_request.startswith("无直接调证对象")
        assert f"候选服务方：{label}" in lead.where_to_request
        assert "核实涉案主体" in lead.where_to_request and "授权" in lead.where_to_request
        assert all(label in item for item in lead.evidence_to_obtain)
        assert "登录" not in lead.where_to_request
        assert all("登录" not in item and "使用" not in item for item in lead.evidence_to_obtain)
        assert "未验证" in (lead.notes or "")
        assert "禁止直接使用" in (lead.notes or "")
        seen_where.add(lead.where_to_request)
        seen_evidence.add(tuple(lead.evidence_to_obtain))

        # 任何 Evidence / Lead / notes / location / digest 投影均不出现原始值、前缀或长度
        lead_dict = {
            "category": lead.category.value,
            "value": lead.value,
            "subject": lead.subject,
            "advice": lead.advice,
            "confidence": lead.confidence.value,
            "where_to_request": lead.where_to_request,
            "evidence_to_obtain": list(lead.evidence_to_obtain),
            "notes": lead.notes,
            "source_refs": [
                {"source": ev.source, "location": ev.location, "snippet": ev.snippet}
                for ev in lead.source_refs
            ],
        }
        serialized_leads.append(lead_dict)
        compact_unredacted = _compact_lead(lead_dict, redact=False, pii_flag=[False])
        compact_redacted = _compact_lead(lead_dict, redact=True, pii_flag=[False])

        combined_blob = json.dumps(
            {
                "lead": lead_dict,
                "compact_unredacted": compact_unredacted,
                "compact_redacted": compact_redacted,
            },
            ensure_ascii=False,
        )
        assert placeholder not in combined_blob
        assert placeholder[:6] not in combined_blob
        assert placeholder[-6:] not in combined_blob
        assert str(len(placeholder)) not in combined_blob
        # 默认受保护输出（digest redact=True）仍保留候选服务方路由，值只是固定标记
        assert compact_redacted["where_to_request"] == expected_where
        assert compact_redacted["confidence"] == Confidence.MEDIUM.value
        # digest 会对 BACKEND_CREDENTIAL 再次掩码：不回显固定标记，也不回退为原始值
        redacted_value = str(compact_redacted["value"])
        assert redacted_value != lead.value
        assert expected_value not in redacted_value
        assert placeholder not in redacted_value
        # 掩码结果确定，与原始值内容/长度无关（只依赖已固定的标记）
        assert _compact_lead(dict(lead_dict), redact=True, pii_flag=[False]) == compact_redacted

    # 七家实际输出路由互异
    assert len(seen_where) == 7
    assert len(seen_evidence) == 7

    # 无直接调证对象 → letters 不生成空壳协查函
    assert build_letters({"leads": serialized_leads}) == []


def test_generic_lookalikes_and_non_credentials_do_not_match() -> None:
    lookalikes = [
        'api_key = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'secret_key = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'access_token = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'password = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'app_secret = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'aws_secret_access_key = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'aliyun_unknown_custom_field = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'tencent_secret_key = "${ENV_PLACEHOLDER_VALUE_123456}"',
        'qiniu_secret_key = "{{TEMPLATE_PLACEHOLDER_123456}}"',
        'agora_app_certificate = "short_val"',
        '<string name="client_secret">SYNTH_GENERIC_XML_LOOKALIKE_1234567890</string>',
        # 带命名空间/多词的引号键、后缀扩展键、属性读写、表达式、非字面量、非法引号值的合法前缀
        '"sdk.aliyun_access_key_secret": "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        '"my aliyun_access_key_secret": "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'aliyun_access_key_secret_backup = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'secret = config.aliyun_access_key_secret',
        'cfg.aliyun_access_key_secret = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'aliyun_access_key_secret = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890" + suffix',
        'aliyun_access_key_secret == "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"',
        'aliyun_access_key_secret = loadSecretFromKeystore()',
        'aliyun_access_key_secret = "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890$!"',
        "aliyun_access_key_secret = \"SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890'",
    ]
    xml_lookalikes = "\n".join(
        [
            '<string name="sdk.agora_app_certificate">SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890</string>',
            '<string name="agora_app_certificate">SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890$!</string>',
            '<!-- <string name="agora_app_certificate">SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890</string> -->',
            '<string name="agora_app_certificate"><span>SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890</span></string>',
        ]
    )
    broken_xml = "<string name=\"agora_app_certificate'>SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890</string>"
    # 编译资源（ARSC/AXML）不在新检测器范围内，即使解码后形似明文也不扫
    compiled = '<string name="upyun_secret_key">SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890</string>'
    contents = {
        "assets/config/lookalike.txt": "\n".join(lookalikes),
        "assets/config/lookalike.xml": f"<resources>\n{xml_lookalikes}\n</resources>",
        "assets/config/broken.xml": f"<resources>\n{broken_xml}\n</resources>",
        # 畸形 JSON 不回退正则；非字符串标量 / 数组不是字符串标量值
        "assets/config/broken.json": '{"qiniu_secret_key": "SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890", ',
        "assets/config/nonscalar.json": json.dumps(
            {
                "qiniu_secret_key": 42,
                "upyun_secret_key": ["SYNTH_GENERIC_LOOKALIKE_VALUE_1234567890"],
            }
        ),
        "res/values/strings.xml": compiled,
        "res/xml/cloud_config.xml": compiled,
        "AndroidManifest.xml": compiled,
    }
    ctx = _Ctx(
        dex=lookalikes,
        files=list(contents),
        contents={path: text.encode("utf-8") for path, text in contents.items()},
    )
    result = BackendCredentialAnalyzer().analyze(ctx)
    assert result.leads == []
    assert result.meta["backend_credential_count"] == 0


def test_grouped_cloud_key_keeps_every_source_occurrence_across_reanalysis() -> None:
    raw_values = (
        "SYNTH_INVALID_QINIU_FILE_A_PLACEHOLDER_A",
        "SYNTH_INVALID_QINIU_FILE_B_PLACEHOLDER_B",
        "SYNTH_INVALID_QINIU_FILE_B_PLACEHOLDER_C",
    )
    contents = {
        "assets/a/cloud.json": json.dumps({"qiniu_secret_key": raw_values[0]}).encode("utf-8"),
        "assets/b/cloud.json": json.dumps(
            {"primary": {"qiniu_secret_key": raw_values[1]}, "backup": {"qiniu_secret_key": raw_values[2]}}
        ).encode("utf-8"),
    }
    marker = "qiniu:qiniu_secret_key=[REDACTED]"
    expected_refs = [
        ("resource", "assets/a/cloud.json", f"{marker} #1"),
        ("resource", "assets/b/cloud.json", f"{marker} #1"),
        ("resource", "assets/b/cloud.json", f"{marker} #2"),
    ]

    def refs(lead: Lead) -> list[tuple[str, str, str]]:
        return [(ev.source, ev.location, ev.snippet) for ev in lead.source_refs]

    first = BackendCredentialAnalyzer().analyze(_Ctx(files=sorted(contents, reverse=True), contents=contents))
    # 计数是分组键数（1 组），不是不同凭据数（3 个）
    assert first.meta["backend_credential_count"] == 1
    assert [lead.value for lead in first.leads] == [marker]
    assert refs(first.leads[0]) == expected_refs
    blob = json.dumps(refs(first.leads[0]))
    assert all(raw not in blob and raw[-6:] not in blob for raw in raw_values)

    # 复分析：文件列举顺序不同，source_refs 仍确定；与先前结果合并既不丢也不重
    second = BackendCredentialAnalyzer().analyze(_Ctx(files=sorted(contents), contents=contents))
    assert refs(second.leads[0]) == expected_refs
    merged = dedup_leads(first.leads + second.leads)
    assert len(merged) == 1
    assert refs(merged[0]) == expected_refs


def test_legacy_backend_credential_workflow_unaffected() -> None:
    basic_line = "Authorization: Basic " + base64.b64encode(b"admin:LegacyPass123").decode("ascii")
    cloud_line = 'aliyun_oss_access_key_secret: "SYNTH_ALIYUN_OSS_INVALID_PLACEHOLDER_889900"'
    ctx = _Ctx(dex=[basic_line, cloud_line])

    leads = BackendCredentialAnalyzer().analyze(ctx).leads
    assert len(leads) == 2
    by_val = {lead.value: lead for lead in leads}

    legacy_lead = by_val["Basic admin:LegacyPass123"]
    cloud_lead = by_val["aliyun:aliyun_oss_access_key_secret=[REDACTED]"]

    assert legacy_lead.confidence is Confidence.HIGH
    assert legacy_lead.advice == "建议调证"
    assert "依法登录取证" in (legacy_lead.where_to_request or "")
    assert any("依法登录后台" in item for item in legacy_lead.evidence_to_obtain)
    assert (legacy_lead.notes or "").startswith("高敏：硬编码后端/管理凭据")

    aliyun_label = next(r.label for r in load_cloud_credential_providers() if r.provider_id == "aliyun")
    expected_where, expected_evidence = cloud_credential_provider_routing(aliyun_label)
    assert cloud_lead.confidence is Confidence.MEDIUM
    assert cloud_lead.where_to_request == expected_where
    assert cloud_lead.evidence_to_obtain == list(expected_evidence)
    assert legacy_lead.where_to_request != cloud_lead.where_to_request


def test_leads_default_guidance_fallback_for_cloud_provider_hit() -> None:
    lead = Lead(
        category=LeadCategory.BACKEND_CREDENTIAL,
        value="qiniu:qiniu_secret_key=[REDACTED]",
        where_to_request=None,
        evidence_to_obtain=[],
        advice="",
    )
    _apply_default_advice([lead])
    assert lead.advice == "建议调证"
    expected_where, expected_evidence = cloud_credential_provider_routing("qiniu")
    assert lead.where_to_request == expected_where
    assert lead.evidence_to_obtain == list(expected_evidence)
    assert redact_credential_value("ANY_RAW_SECRET_VALUE") == "[REDACTED]"
    assert "config_keys_cross_analyzer_dedup" in STAGE2_INTEGRATION_GAPS


def test_cloud_dex_char_budget_skip_sets_truncated_and_preserves_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    positive_dex = 'qiniu_secret_key = "SYNTH_INVALID_QINIU_SHORT_123456"'
    monkeypatch.setattr(bc_mod, "_MAX_CLOUD_SCAN_CHARS", len(positive_dex))

    # 恰好等于上限：仍扫描并命中，不置截断
    boundary_result = BackendCredentialAnalyzer().analyze(_Ctx(dex=[positive_dex]))
    assert "dex_strings_truncated" not in boundary_result.meta
    assert [lead.value for lead in boundary_result.leads] == ["qiniu:qiniu_secret_key=[REDACTED]"]

    # 超过上限：跳过云扫描、置截断，传统凭据不受影响
    basic_raw = "Authorization: Basic " + base64.b64encode(b"admin:LegacyPass123").decode("ascii")
    long_dex = positive_dex + "\n" + basic_raw
    assert len(long_dex) > len(positive_dex)
    result = BackendCredentialAnalyzer().analyze(_Ctx(dex=[long_dex]))
    assert result.meta.get("dex_strings_truncated") is True
    assert [lead.value for lead in result.leads] == ["Basic admin:LegacyPass123"]


def test_same_provider_distinct_keys_distinguishable_after_protected_projection() -> None:
    raw_a = "SYNTH_INVALID_ALIYUN_KEY_A_PLACEHOLDER_111111"
    raw_b = "SYNTH_INVALID_ALIYUN_KEY_B_PLACEHOLDER_2222222222"
    ctx = _Ctx(
        dex=[
            f'aliyun_access_key_secret = "{raw_a}"',
            f'aliyun_oss_access_key_secret = "{raw_b}"',
        ]
    )
    result = BackendCredentialAnalyzer().analyze(ctx)
    assert len(result.leads) == 2
    projected = []
    for lead in result.leads:
        lead_dict = {
            "category": lead.category.value,
            "value": lead.value,
            "subject": lead.subject,
            "advice": lead.advice,
            "confidence": lead.confidence.value,
            "where_to_request": lead.where_to_request,
            "evidence_to_obtain": list(lead.evidence_to_obtain),
            "notes": lead.notes,
            "source_refs": [
                {"source": ev.source, "location": ev.location, "snippet": ev.snippet}
                for ev in lead.source_refs
            ],
        }
        projected.append(_compact_lead(lead_dict, redact=True, pii_flag=[False]))

    # 默认 digest value 脱敏保持一致（同长度前缀后缀落入同一掩码），但受保护的 notes 保留精确注册表键名以供区分跟进
    assert projected[0]["value"] != result.leads[0].value
    assert projected[1]["value"] != result.leads[1].value
    assert projected[0]["notes"] != projected[1]["notes"]
    assert "aliyun_access_key_secret" in str(projected[0]["notes"])
    assert "aliyun_oss_access_key_secret" in str(projected[1]["notes"])
    blob = json.dumps(projected, ensure_ascii=False)
    for raw in (raw_a, raw_b):
        assert raw not in blob
        assert raw[:6] not in blob
        assert raw[-6:] not in blob
        assert str(len(raw)) not in blob


def test_cross_analyzer_decoded_manifest_and_plaintext_assets_end_to_end() -> None:
    cloud_manifest_raw = "SYNTH_INVALID_TENCENT_MANIFEST_SECRET_88888888"
    cloud_asset_raw = "SYNTH_INVALID_ALIYUN_ASSET_SECRET_9999999999"
    legacy_push_val = "DVRqpR8NztAJAfq8f4dbv3"
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.synth">\n'
        "  <application>\n"
        f'    <meta-data android:name="tencent_secret_key" android:value="{cloud_manifest_raw}"/>\n'
        f'    <meta-data android:name="GETUI_APPID" android:value="{legacy_push_val}"/>\n'
        "  </application>\n"
        "</manifest>\n"
    )
    asset_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        f'  <string name="aliyun_access_key_secret" translatable="false">{cloud_asset_raw}</string>\n'
        "</resources>\n"
    )
    ctx = _Ctx(
        manifest_xml=manifest_xml,
        files=["assets/config/cloud_sdk.xml"],
        contents={"assets/config/cloud_sdk.xml": asset_xml.encode("utf-8")},
    )

    ck_res = ConfigKeysAnalyzer().analyze(ctx)
    bc_res = BackendCredentialAnalyzer().analyze(ctx)

    assert ck_res.findings == []
    assert bc_res.findings == []

    combined_leads = ck_res.leads + bc_res.leads
    by_val = {lead.value: lead for lead in combined_leads}
    assert set(by_val) == {
        "tencent_secret_key=[REDACTED]",
        f"GETUI_APPID={legacy_push_val}",
        "aliyun:aliyun_access_key_secret=[REDACTED]",
    }
    # 无关传统配置键保持既有建议调证与厂商归属
    legacy_lead = by_val[f"GETUI_APPID={legacy_push_val}"]
    assert legacy_lead.category is LeadCategory.CONFIG_KEY
    assert legacy_lead.advice == "建议调证"
    assert legacy_lead.confidence is Confidence.HIGH
    assert "个推" in (legacy_lead.subject or "")

    serialized_leads = []
    compact_leads = []
    for lead in combined_leads:
        lead_dict = {
            "category": lead.category.value,
            "value": lead.value,
            "subject": lead.subject,
            "advice": lead.advice,
            "confidence": lead.confidence.value,
            "where_to_request": lead.where_to_request,
            "evidence_to_obtain": list(lead.evidence_to_obtain),
            "notes": lead.notes,
            "source_refs": [
                {"source": ev.source, "location": ev.location, "snippet": ev.snippet}
                for ev in lead.source_refs
            ],
        }
        serialized_leads.append(lead_dict)
        compact_leads.append(_compact_lead(lead_dict, redact=True, pii_flag=[False]))

    letters = build_letters({"leads": serialized_leads})
    # 云凭据候选不产额外协查函：合并结果与仅传统键结果一致
    legacy_only = [d for d in serialized_leads if d["value"] == f"GETUI_APPID={legacy_push_val}"]
    assert letters == build_letters({"leads": legacy_only})

    # 已知可发函对照：同形状传统键 Lead，补当前案件直接证据 scope（仅生成草稿，不发送）
    control = dict(legacy_only[0])
    control["source_refs"] = [dict(ref, scope="case_evidence") for ref in control["source_refs"]]
    control_letters = build_letters({"leads": [control]})
    assert len(control_letters) == 1
    assert control_letters[0]["target"] == f"GETUI_APPID={legacy_push_val}"
    letters = letters + control_letters

    full_blob = json.dumps(
        {
            "leads": serialized_leads,
            "findings": [f.__dict__ for f in (ck_res.findings + bc_res.findings)],
            "digest_leads": compact_leads,
            "letters": letters,
        },
        ensure_ascii=False,
    )
    for secret in (cloud_manifest_raw, cloud_asset_raw):
        assert secret not in full_blob
        assert secret[:6] not in full_blob
        assert secret[-6:] not in full_blob
        assert str(len(secret)) not in full_blob
