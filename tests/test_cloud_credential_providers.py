"""云 / SaaS 凭据提供方精确上下文注册表与脱敏路由测试（Stage 2）。

覆盖：
1. 7 家受批厂商（aliyun/tencent_cloud/huawei_cloud/qiniu/upyun/rongcloud/agora）精确上下文配置键的合成无效占位符；
2. 通用键名与伪相似键名（api_key/secret/token/password/aws_secret_access_key 等）零误报；
3. 实际 BackendCredentialAnalyzer.analyze() 输出、Evidence/Lead/notes/location 与 digest 投影均仅含固定
   `[REDACTED]` 标记，绝不泄露原始占位符全文、前缀或长度；
4. 命中按受批注册表标签区分候选服务方路由（where_to_request / evidence_to_obtain 七家互异），明确须先核实
   主体与授权，绝不路由至旧版「使用/登录所获凭据」文案；置信度降为 MEDIUM，不硬编码厂商归属
   （subject=None，verification_status=unverified）；
5. 既有 legacy 后端凭据（Basic-Auth / DB DSN / JDBC / AKIA / LTAI）工作流、HIGH 置信度与指导文案保持不变。
"""

from __future__ import annotations

import base64
import json

from fxapk.analyzers.backend_credential import (
     STAGE2_INTEGRATION_GAPS,
    BackendCredentialAnalyzer,
    is_cloud_provider_hit_value,
    is_contextual_config_key,
    load_cloud_credential_providers,
    redact_credential_value,
)
from fxapk.core.leads import (
    _apply_default_advice,
    cloud_credential_provider_routing,
    is_redacted_cloud_provider_credential_value,
)
from fxapk.core.models import Confidence, Lead, LeadCategory
from fxapk.report.digest import _compact_lead
from fxapk.report.letters import build_letters


class _Ctx:
    def __init__(self, dex=None, files=None, contents=None) -> None:
        self._dex = list(dex or [])
        self._files = list(files or [])
        self._contents = dict(contents or {})

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
        f'    <string name="{config_key}">{placeholder}</string>'
        for _, config_key, placeholder in _SYNTHETIC_PROVIDER_CASES[4:]
    )
    ctx = _Ctx(
        dex=dex_entries,
        files=["res/values/strings.xml"],
        contents={"res/values/strings.xml": f"<resources>\n{xml_entries}\n</resources>".encode("utf-8")},
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
    ]
    ctx = _Ctx(
        dex=lookalikes,
        files=["res/values/strings.xml"],
        contents={"res/values/strings.xml": "\n".join(lookalikes).encode("utf-8")},
    )
    result = BackendCredentialAnalyzer().analyze(ctx)
    assert result.leads == []
    assert result.meta["backend_credential_count"] == 0


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
