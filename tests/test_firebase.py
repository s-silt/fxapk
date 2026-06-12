"""firebase 分析器测试 —— 用 conftest 的 FakeContext 喂合成数据。

覆盖（任务要求的核心断言）：
- res/values/strings.xml 注入键（firebase_database_url / google_api_key / project_id）
  → project_id 的 CONFIG_KEY Lead、databaseURL 的 domain Endpoint、meta["firebase_project_id"]。
- assets/google-services.json → 解析出 project_id / database_url / storage_bucket / api_key。
- firebaseio.com 域名经 infra 仍判"建议调证"（回归护栏：不被误降为"无需调证"）。
- 坏 JSON / 无 firebase 配置 → 不抛、空产出、error 仍为 None。
- Lead 通用字段：CONFIG_KEY、subject 指向 Google/GCP、where_to_request、evidence_to_obtain。
- meta["firebase"] 记录有哪个键记哪个。
"""

from __future__ import annotations

import json

from apkscan.analyzers.firebase import FirebaseAnalyzer
from apkscan.core.infra import ADVICE_INVESTIGATE, classify_domain
from apkscan.core.models import LeadCategory
from tests.conftest import FakeContext


def _analyzer() -> FirebaseAnalyzer:
    return FirebaseAnalyzer()


def _leads_by_value(result) -> dict[str, object]:
    return {lead.value: lead for lead in result.leads}


def _project_id_lead(result):
    for lead in result.leads:
        if lead.category == LeadCategory.CONFIG_KEY and lead.value.startswith(
            "firebase_project_id="
        ):
            return lead
    return None


# ---------------------------------------------------------------------------
# 合成数据
# ---------------------------------------------------------------------------

_STRINGS_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<resources>\n"
    '  <string name="firebase_database_url">'
    "https://demo-proj-default-rtdb.firebaseio.com</string>\n"
    '  <string name="google_api_key">AIzaSyA-FAKE-KEY-1234567890abcdef</string>\n'
    '  <string name="project_id">demo-proj-rat</string>\n'
    '  <string name="gcm_defaultSenderId">123456789012</string>\n'
    '  <string name="google_storage_bucket">demo-proj-rat.appspot.com</string>\n'
    '  <string name="app_name">记账</string>\n'
    "</resources>\n"
)


def _google_services_json() -> bytes:
    return json.dumps(
        {
            "project_info": {
                "project_number": "987654321098",
                "project_id": "json-proj-c2",
                "firebase_url": "https://json-proj-c2.firebaseio.com",
                "storage_bucket": "json-proj-c2.appspot.com",
            },
            "client": [
                {
                    "api_key": [{"current_key": "AIzaSyB-JSON-KEY-abcdef1234567890"}],
                }
            ],
        },
        ensure_ascii=False,
    ).encode("utf-8")


def _strings_ctx() -> FakeContext:
    return FakeContext(
        files={"res/values/strings.xml": _STRINGS_XML.encode("utf-8")},
    )


def _json_ctx() -> FakeContext:
    return FakeContext(
        files={"assets/google-services.json": _google_services_json()},
    )


# ---------------------------------------------------------------------------
# 基本属性
# ---------------------------------------------------------------------------


def test_analyzer_identity() -> None:
    a = _analyzer()
    assert a.name == "firebase"
    assert a.requires == []


# ---------------------------------------------------------------------------
# strings.xml 源
# ---------------------------------------------------------------------------


def test_strings_xml_project_id_lead() -> None:
    result = _analyzer().analyze(_strings_ctx())
    assert result.error is None

    lead = _project_id_lead(result)
    assert lead is not None
    assert lead.value == "firebase_project_id=demo-proj-rat"
    assert lead.category == LeadCategory.CONFIG_KEY
    assert lead.subject is not None and (
        "Google" in lead.subject or "GCP" in lead.subject
    )
    assert lead.where_to_request is not None and "Google" in lead.where_to_request
    assert lead.evidence_to_obtain  # 非空
    # notes 应提示 Firebase 亦正规常用，需结合敏感行为研判。
    assert "正规" in lead.notes


def test_strings_xml_meta_firebase_project_id() -> None:
    result = _analyzer().analyze(_strings_ctx())
    assert result.meta.get("firebase_project_id") == "demo-proj-rat"


def test_strings_xml_meta_firebase_dict() -> None:
    result = _analyzer().analyze(_strings_ctx())
    fb = result.meta.get("firebase")
    assert isinstance(fb, dict)
    assert fb.get("project_id") == "demo-proj-rat"
    assert fb.get("database_url") == "https://demo-proj-default-rtdb.firebaseio.com"
    assert fb.get("storage_bucket") == "demo-proj-rat.appspot.com"
    assert fb.get("api_key") == "AIzaSyA-FAKE-KEY-1234567890abcdef"
    assert fb.get("sender_id") == "123456789012"


def test_strings_xml_database_url_domain_endpoint() -> None:
    """databaseURL 走 Endpoint(kind=domain)，让 pipeline 统一建 DOMAIN Lead。"""
    result = _analyzer().analyze(_strings_ctx())
    domains = [ep for ep in result.endpoints if ep.kind == "domain"]
    hosts = {ep.value for ep in domains}
    assert "demo-proj-default-rtdb.firebaseio.com" in hosts
    # 分析器本身不产 DOMAIN Lead（遵循 endpoints 约定，pipeline build_endpoint_leads 统一建）。
    assert not any(lead.category == LeadCategory.DOMAIN for lead in result.leads)


# ---------------------------------------------------------------------------
# google-services.json 源
# ---------------------------------------------------------------------------


def test_google_services_json_parsed() -> None:
    result = _analyzer().analyze(_json_ctx())
    assert result.error is None

    assert result.meta.get("firebase_project_id") == "json-proj-c2"
    fb = result.meta.get("firebase")
    assert isinstance(fb, dict)
    assert fb.get("project_id") == "json-proj-c2"
    assert fb.get("database_url") == "https://json-proj-c2.firebaseio.com"
    assert fb.get("storage_bucket") == "json-proj-c2.appspot.com"
    assert fb.get("api_key") == "AIzaSyB-JSON-KEY-abcdef1234567890"

    lead = _project_id_lead(result)
    assert lead is not None
    assert lead.value == "firebase_project_id=json-proj-c2"


def test_google_services_json_database_url_endpoint() -> None:
    result = _analyzer().analyze(_json_ctx())
    hosts = {ep.value for ep in result.endpoints if ep.kind == "domain"}
    assert "json-proj-c2.firebaseio.com" in hosts


# ---------------------------------------------------------------------------
# 回归护栏：firebaseio.com 域名 advice = 建议调证（不被 infra 误降）
# ---------------------------------------------------------------------------


def test_firebaseio_domain_is_investigate_not_skipped() -> None:
    """firebaseio.com / firebaseapp.com 是 App 自有 C2/数据回传，绝不可当 Google 公共服务降级。"""
    advice, _reason = classify_domain("demo-proj-default-rtdb.firebaseio.com")
    assert advice == ADVICE_INVESTIGATE
    advice2, _ = classify_domain("demo-proj.firebaseapp.com")
    assert advice2 == ADVICE_INVESTIGATE


# ---------------------------------------------------------------------------
# 错误韧性 / 空输入
# ---------------------------------------------------------------------------


def test_empty_context_clean_return() -> None:
    result = _analyzer().analyze(FakeContext())
    assert result.error is None
    assert result.leads == []
    assert result.endpoints == []
    assert "firebase_project_id" not in result.meta


def test_malformed_json_does_not_crash() -> None:
    ctx = FakeContext(files={"assets/google-services.json": b"{not valid json,,,"})
    result = _analyzer().analyze(ctx)
    assert result.error is None
    assert result.leads == []
    assert "firebase_project_id" not in result.meta


def test_no_firebase_config_empty_output() -> None:
    """有 strings.xml 但无任何 firebase 键 → 不产 project_id lead，不写 meta。"""
    strings = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        '  <string name="app_name">记账</string>\n'
        '  <string name="UMENG_APPKEY">5f0a1b2c3d4e</string>\n'
        "</resources>\n"
    )
    ctx = FakeContext(files={"res/values/strings.xml": strings.encode("utf-8")})
    result = _analyzer().analyze(ctx)
    assert result.error is None
    assert _project_id_lead(result) is None
    assert "firebase_project_id" not in result.meta


def test_malformed_strings_xml_does_not_crash() -> None:
    ctx = FakeContext(files={"res/values/strings.xml": b"<resources><broken"})
    result = _analyzer().analyze(ctx)
    assert result.error is None
    assert result.leads == []
