"""第二波 RUNTIME_CREDENTIAL（运行时登录态/明文凭据采集）纯逻辑单测。

策略（与 test_cryptohook / test_merge 同范式）：全程无设备/无 Frida，只测可测纯函数——
- cryptohook.normalize_credential_event：规范化 + 高敏值截断/脱敏 + token 形态/熵闸过占位。
- cryptohook.FRIDA_OKHTTP_HOOK_JS：Frida JS 常量完整性（多 fallback 类名、send 通道）。
- merge.merge_runtime_credentials：合成 credential_events + shared_prefs xml → RUNTIME_CREDENTIAL
  Lead；OkHttp 明文 host 复用 _endpoints_from_plaintext 走 infra 分级并入端点。

真机部分（frida JS 注入 okhttp interceptor-before dump + adb pull shared_prefs）无法单测，
由用户在 MuMu 复验，与现有 cryptohook 真机 JS 行为一致。
"""

from __future__ import annotations

from typing import Any

from apkscan.core.models import LeadCategory, Report
from apkscan.dynamic import cryptohook, merge


# ---------------------------------------------------------------------------
# 合成帮助器
# ---------------------------------------------------------------------------


def _make_report(
    *,
    endpoints: list[Any] | None = None,
    leads: list[Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=list(leads or []),
        endpoints=list(endpoints or []),
        findings=[],
        analyzer_status=[],
    )


def _okhttp_payload(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": cryptohook.CREDENTIAL_MSG_TYPE,
        "source": "okhttp",
        "url": "https://api.fraud-c2.cn/login",
        "method": "POST",
    }
    base.update(kw)
    return base


def _send(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "send", "payload": payload}


# ===========================================================================
# normalize_credential_event
# ===========================================================================


def test_normalize_credential_drops_non_dict_and_unknown_source() -> None:
    assert cryptohook.normalize_credential_event("x") is None
    assert cryptohook.normalize_credential_event({"source": "okhttp"}) is None  # 缺 url/key
    # 未知 source（既非 okhttp 也非 sharedprefs）→ None
    assert (
        cryptohook.normalize_credential_event(
            {"source": "memory", "url": "https://x.cn/a"}
        )
        is None
    )


def test_normalize_credential_okhttp_keeps_host_and_url() -> None:
    ev = cryptohook.normalize_credential_event(_okhttp_payload())
    assert ev is not None
    assert ev["source"] == "okhttp"
    assert ev["url"] == "https://api.fraud-c2.cn/login"
    assert ev["method"] == "POST"


def test_normalize_credential_truncates_authorization_token() -> None:
    """Authorization/Bearer token 是高敏个人信息：回传只留前后几位、中间打码（不留全文）。"""
    full = "Bearer " + "A" * 200
    ev = cryptohook.normalize_credential_event(
        _okhttp_payload(headers={"Authorization": full})
    )
    assert ev is not None
    auth = ev["headers"]["Authorization"]
    # 不留全文：长度远小于原始 200+ 字符
    assert len(auth) < 60
    # 但保留可比对的前后片段
    assert auth.startswith("Bearer A")
    assert "…" in auth or "*" in auth


def test_normalize_credential_masks_phone_number() -> None:
    """登录手机号是受害人高敏个人信息：中间打码。"""
    ev = cryptohook.normalize_credential_event(
        _okhttp_payload(body='{"mobile":"13800138000","pwd":"x"}')
    )
    assert ev is not None
    body = ev["body"]
    # 完整手机号不得出现在回传里（中间已打码）
    assert "13800138000" not in body
    assert "138" in body and "8000" in body  # 前后保留可比对


def test_normalize_credential_sharedprefs_token_passes_shape_gate() -> None:
    """真 token 形态（够长/多样）保留（截断后）；占位/空值过形态闸 → 占位标记。"""
    real = cryptohook.normalize_credential_event(
        {
            "type": cryptohook.CREDENTIAL_MSG_TYPE,
            "source": "sharedprefs",
            "name": "token",
            "value": "Abc123Xyz789Def456Ghi012Jkl345",
            "file": "user_prefs.xml",
        }
    )
    assert real is not None
    assert real["source"] == "sharedprefs"
    assert real["name"] == "token"
    # 真 token 形态保留（但截断，不留全文）
    assert real["value"]
    assert len(real["value"]) <= 40


def test_normalize_credential_placeholder_value_gated_out() -> None:
    """非凭据形态的值（占位/常量名 deviceToken 之类）→ 形态闸过滤为占位标记，不回传明文。"""
    ev = cryptohook.normalize_credential_event(
        {
            "type": cryptohook.CREDENTIAL_MSG_TYPE,
            "source": "sharedprefs",
            "name": "token",
            "value": "deviceToken",  # SDK 常量名，非真凭据
        }
    )
    assert ev is not None
    # 形态闸判非凭据 → value 被占位（不泄非凭据明文，且标明经过闸）
    assert ev["value"] != "deviceToken"


def test_normalize_credential_never_raises_on_garbage() -> None:
    assert cryptohook.normalize_credential_event(None) is None
    assert cryptohook.normalize_credential_event([]) is None
    # headers 类型错误也不抛
    ev = cryptohook.normalize_credential_event(_okhttp_payload(headers="notadict"))
    assert ev is not None  # url 仍在，headers 降级为空


# ===========================================================================
# make_typed_handler 路由（复用现有工厂）
# ===========================================================================


def test_credential_typed_handler_routes_and_never_raises() -> None:
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_typed_handler(
        sink, cryptohook.CREDENTIAL_MSG_TYPE, cryptohook.normalize_credential_event
    )
    handler(_send(_okhttp_payload()), None)
    # 别的通道（crypto）→ 忽略
    handler(_send({"type": cryptohook.CRYPTO_MSG_TYPE, "src": "cipher"}), None)
    handler("garbage", None)  # type: ignore[arg-type]
    handler({"type": "send", "payload": "notadict"}, None)
    assert len(sink) == 1
    assert sink[0]["source"] == "okhttp"


# ===========================================================================
# Frida OkHttp JS 常量完整性
# ===========================================================================


def test_frida_okhttp_hook_js_integrity() -> None:
    js = cryptohook.FRIDA_OKHTTP_HOOK_JS
    assert "Java.perform" in js
    # 多 fallback 类名（R8 混淆：随版本/混淆变化）
    assert "okhttp3.RealCall" in js
    assert "RealInterceptorChain" in js
    assert "send(" in js  # 回传通道
    assert cryptohook.CREDENTIAL_MSG_TYPE in js  # 通道判别值与 Python 一致


# ===========================================================================
# merge.merge_runtime_credentials
# ===========================================================================


def _write_runtime_report(
    tmp_path: Any,
    *,
    credential_events: list[dict[str, Any]] | None = None,
) -> str:
    import json

    payload = {
        "package_name": "com.test.app",
        "credential_events": list(credential_events or []),
    }
    path = tmp_path / "runtime_report.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_merge_credentials_produces_runtime_credential_lead(tmp_path: Any) -> None:
    rr = _write_runtime_report(
        tmp_path,
        credential_events=[
            {
                "source": "okhttp",
                "url": "https://api.fraud-c2.cn/login",
                "method": "POST",
                "headers": {"Authorization": "Bearer A…ZZZ"},
                "body": '{"mobile":"138****8000"}',
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_credentials(report, rr)

    cred_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.RUNTIME_CREDENTIAL
    ]
    assert len(cred_leads) >= 1
    assert stats["credential_leads"] >= 1
    lead = cred_leads[0]
    # 合规提示：含高敏个人信息处置
    assert "高敏" in lead.notes or "合规" in lead.notes
    # where_to_request：凭 token/手机号向平台/运营商调证
    assert lead.where_to_request


def test_merge_credentials_okhttp_host_merged_as_endpoint_via_infra(tmp_path: Any) -> None:
    """OkHttp 明文真实 host 复用 _endpoints_from_plaintext 并入端点，走 infra 分级。"""
    rr = _write_runtime_report(
        tmp_path,
        credential_events=[
            {"source": "okhttp", "url": "https://c2.fraud-gw.cn/api/login", "method": "POST"}
        ],
    )
    report = _make_report()
    merge.merge_runtime_credentials(report, rr)

    # host 作为 domain 端点并入
    values = {ep.value for ep in report.endpoints}
    assert "c2.fraud-gw.cn" in values
    # 走 infra 分级：疑似 App 自有服务 → 建议调证（DOMAIN lead）
    from apkscan.core import infra

    domain_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.DOMAIN
    ]
    assert any(
        lead.value == "c2.fraud-gw.cn" and lead.advice == infra.ADVICE_INVESTIGATE
        for lead in domain_leads
    )


def test_merge_credentials_known_infra_host_marked_skip(tmp_path: Any) -> None:
    """OkHttp 明文 host 命中 KNOWN_INFRA（CDN）→ 无需调证，绝不把 CDN 当 C2。"""
    rr = _write_runtime_report(
        tmp_path,
        credential_events=[
            {"source": "okhttp", "url": "https://res.myqcloud.com/a", "method": "GET"}
        ],
    )
    report = _make_report()
    merge.merge_runtime_credentials(report, rr)

    from apkscan.core import infra

    lead = next(
        (lead for lead in report.leads if lead.value == "res.myqcloud.com"), None
    )
    assert lead is not None
    assert lead.advice == infra.ADVICE_SKIP


def test_merge_credentials_sharedprefs_token_lead(tmp_path: Any) -> None:
    rr = _write_runtime_report(
        tmp_path,
        credential_events=[
            {
                "source": "sharedprefs",
                "name": "token",
                "value": "Abc1…f456",
                "file": "user_prefs.xml",
            }
        ],
    )
    report = _make_report()
    stats = merge.merge_runtime_credentials(report, rr)
    assert stats["credential_leads"] >= 1
    cred_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.RUNTIME_CREDENTIAL
    ]
    assert any("token" in lead.value for lead in cred_leads)


def test_merge_credentials_empty_when_no_events(tmp_path: Any) -> None:
    rr = _write_runtime_report(tmp_path, credential_events=[])
    report = _make_report()
    stats = merge.merge_runtime_credentials(report, rr)
    assert stats["credential_leads"] == 0
    assert not [
        lead for lead in report.leads if lead.category == LeadCategory.RUNTIME_CREDENTIAL
    ]


def test_merge_credentials_never_raises_on_missing_file() -> None:
    report = _make_report()
    stats = merge.merge_runtime_credentials(report, "nonexistent_runtime_report.json")
    assert stats["credential_leads"] == 0


def test_merge_credentials_dedups_repeated_events(tmp_path: Any) -> None:
    """同一 (source, key) 凭据多次出现 → 去重为一条 Lead。"""
    rr = _write_runtime_report(
        tmp_path,
        credential_events=[
            {"source": "sharedprefs", "name": "token", "value": "Abc1…f456", "file": "p.xml"},
            {"source": "sharedprefs", "name": "token", "value": "Abc1…f456", "file": "p.xml"},
        ],
    )
    report = _make_report()
    merge.merge_runtime_credentials(report, rr)
    cred_leads = [
        lead for lead in report.leads if lead.category == LeadCategory.RUNTIME_CREDENTIAL
    ]
    token_leads = [lead for lead in cred_leads if "token" in lead.value]
    assert len(token_leads) == 1


# ===========================================================================
# extract_sharedprefs_credentials（从 shared_prefs xml 正则抠凭据）
# ===========================================================================

_PREFS_XML = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="token">Abc123Xyz789Def456Ghi012Jkl345</string>
    <string name="merchant_no">M88888888</string>
    <string name="invite_code">FX2024</string>
    <string name="mobile">13800138000</string>
    <int name="login_status" value="1" />
    <string name="nickname">张三</string>
</map>
"""


def test_extract_sharedprefs_credentials_picks_sensitive_keys() -> None:
    creds = cryptohook.extract_sharedprefs_credentials(_PREFS_XML, "user_prefs.xml")
    keys = {c["name"] for c in creds}
    # 命中敏感键：token / 商户号 / 邀请码 / 手机号 / 登录态
    assert "token" in keys
    assert "merchant_no" in keys
    assert "invite_code" in keys
    # 普通键（nickname）不抠
    assert "nickname" not in keys


def test_extract_sharedprefs_credentials_truncates_token() -> None:
    creds = cryptohook.extract_sharedprefs_credentials(_PREFS_XML, "user_prefs.xml")
    token = next(c for c in creds if c["name"] == "token")
    # 真 token 截断：不留全文
    assert len(token["value"]) < len("Abc123Xyz789Def456Ghi012Jkl345")


def test_extract_sharedprefs_credentials_never_raises_on_bad_xml() -> None:
    assert cryptohook.extract_sharedprefs_credentials("<not valid xml", "x.xml") == []
    assert cryptohook.extract_sharedprefs_credentials("", "x.xml") == []
