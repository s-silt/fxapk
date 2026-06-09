"""sensitive_api 分析器单测：FakeContext 喂合成 DEX 字符串，断言 Finding / 降级 / 误报收敛。"""

from __future__ import annotations

from apkscan.analyzers import sensitive_api
from apkscan.analyzers.sensitive_api import SensitiveApiAnalyzer, _token_match
from apkscan.core.models import Severity
from tests.conftest import FakeContext


def _run(dex_strings: list[str]):
    return SensitiveApiAnalyzer().analyze(FakeContext(dex_strings=dex_strings))


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def _sev(result, fid: str) -> Severity:
    return next(f.severity for f in result.findings if f.id == fid)


# ---------------------------------------------------------------------------
# 词边界匹配
# ---------------------------------------------------------------------------


def test_token_match_word_boundary() -> None:
    assert _token_match("getDeviceId", "getDeviceId") is True
    assert _token_match("getDeviceId", "Landroid/telephony/TelephonyManager;->getDeviceId()V") is True
    assert _token_match("getDeviceId", "getDeviceIdentifier") is False  # 不误命中更长方法名
    assert _token_match("getDeviceId", "myGetDeviceId") is False  # 前边界


def test_token_match_skips_false_boundary_then_hits() -> None:
    """同串内先假后真：必须走 start=idx+1 继续找，命中后段真实出现（核心收敛回路）。"""
    assert _token_match("getDeviceId", "getDeviceIdentifier;getDeviceId()V") is True


def test_token_match_dot_slash_boundary() -> None:
    assert _token_match("getDeviceId", "a.getDeviceId(") is True
    assert _token_match("getDeviceId", "getDeviceId.") is True  # 末尾点号也是非标识符边界
    assert _token_match("getDeviceId", "Lx;->getDeviceId(") is True


# ---------------------------------------------------------------------------
# 命中 + require_class 确认
# ---------------------------------------------------------------------------


def test_get_device_id_with_telephony_class_high() -> None:
    r = _run(["getDeviceId", "Landroid/telephony/TelephonyManager;"])
    assert "SAPI-IMEI" in _ids(r)
    assert _sev(r, "SAPI-IMEI") == Severity.HIGH
    f = next(f for f in r.findings if f.id == "SAPI-IMEI")
    assert f.category == "sensitive_api"
    assert f.evidences[0].source == "dex"


def test_method_without_class_downgraded() -> None:
    """require_class 未命中 → 降一级 + description 标注未确认调用点。"""
    r = _run(["getDeviceId"])  # 无 TelephonyManager 类
    assert _sev(r, "SAPI-IMEI") == Severity.MEDIUM
    f = next(f for f in r.findings if f.id == "SAPI-IMEI")
    assert "未" in f.description and "调用" in f.description


def test_send_sms_high() -> None:
    r = _run(["sendTextMessage", "Landroid/telephony/SmsManager;"])
    assert "SAPI-SEND-SMS" in _ids(r)
    assert _sev(r, "SAPI-SEND-SMS") == Severity.HIGH


def test_contacts_uri_high_no_class_required() -> None:
    """通讯录规则无 require_class（强信号），命中即 HIGH（不降级）。"""
    r = _run(["content://com.android.contacts/data"])
    assert "SAPI-CONTACTS" in _ids(r)
    assert _sev(r, "SAPI-CONTACTS") == Severity.HIGH


def test_clipboard_get_primary_clip() -> None:
    r = _run(["getPrimaryClip", "Landroid/content/ClipboardManager;"])
    assert "SAPI-CLIPBOARD" in _ids(r)


def test_medium_rule_downgrades_to_low() -> None:
    """MEDIUM 规则在 require_class 未命中时降到 LOW（验证降级阶梯 MEDIUM→LOW 档）。"""
    r = _run(["getPrimaryClip"])  # 无 ClipboardManager 类
    assert _sev(r, "SAPI-CLIPBOARD") == Severity.LOW
    f = next(f for f in r.findings if f.id == "SAPI-CLIPBOARD")
    assert "未" in f.description


def test_require_all_needs_all_tokens() -> None:
    """SAPI-ANDROID-ID 用 require_all：android_id 单独不触发，须与 getString 共现。"""
    assert "SAPI-ANDROID-ID" not in _ids(_run(["android_id"]))  # 缺 getString
    r = _run(["android_id", "getString", "Landroid/provider/Settings$Secure;"])
    assert "SAPI-ANDROID-ID" in _ids(r)
    assert _sev(r, "SAPI-ANDROID-ID") == Severity.LOW  # 高频弱信号，LOW 起评


def test_new_sensitive_api_rules() -> None:
    r = _run([
        "getSimOperator", "Landroid/telephony/TelephonyManager;",
        "getSerial", "Landroid/os/Build;",
        "content://call_log", "content://sms/inbox",
        "Landroid/media/MediaRecorder",
    ])
    assert {"SAPI-SIM-OPERATOR", "SAPI-SERIAL", "SAPI-CALLLOG", "SAPI-READ-SMS", "SAPI-AUDIO-RECORD"} <= _ids(r)


def test_sms_intercept_require_all() -> None:
    r = _run(["android.provider.Telephony.SMS_RECEIVED", "abortBroadcast"])
    assert _sev(r, "SAPI-SMS-INTERCEPT") == Severity.HIGH
    # 缺 abortBroadcast → 不触发
    assert "SAPI-SMS-INTERCEPT" not in _ids(_run(["android.provider.Telephony.SMS_RECEIVED"]))


def test_mac_via_networkinterface() -> None:
    """Android 6+ 经 NetworkInterface 读 wlan0（getMacAddress 之外的真实路径）。"""
    r = _run(["getHardwareAddress", "Ljava/net/NetworkInterface;", "wlan0"])
    assert "SAPI-MAC" in _ids(r)


def test_location_request_updates() -> None:
    r = _run(["requestLocationUpdates", "Landroid/location/LocationManager;"])
    assert "SAPI-LOCATION" in _ids(r)


def test_imsi_and_phone_number() -> None:
    r = _run(["getSubscriberId", "getLine1Number", "Landroid/telephony/TelephonyManager;"])
    assert {"SAPI-IMSI", "SAPI-PHONE-NUMBER"} <= _ids(r)


# ---------------------------------------------------------------------------
# 误报收敛
# ---------------------------------------------------------------------------


def test_benign_strings_no_false_positive() -> None:
    """同名更长方法（getDeviceIdentifier）/ 非 SmsManager 的 sendText → 不命中。"""
    r = _run(["getDeviceIdentifier", "sendText", "someUnrelatedString"])
    assert r.findings == []


def test_no_sensitive_api_no_findings() -> None:
    r = _run(["java.lang.String", "onCreate", "Landroidx/appcompat"])
    assert r.findings == []
    assert r.meta["sensitive_apis"] == []
    assert r.meta["sensitive_api_count"] == 0
    assert r.error is None


# ---------------------------------------------------------------------------
# meta / 鲁棒性
# ---------------------------------------------------------------------------


def test_meta_counts_matched() -> None:
    r = _run(["getDeviceId", "Landroid/telephony/TelephonyManager;", "getPrimaryClip", "Landroid/content/ClipboardManager;"])
    assert set(r.meta["sensitive_apis"]) == {"SAPI-IMEI", "SAPI-CLIPBOARD"}
    assert r.meta["sensitive_api_count"] == 2
    assert r.meta["dex_scanned"] is True


def test_no_lead_emitted() -> None:
    """与 permissions 一致：本 analyzer 只产 Finding，不产 Lead。"""
    r = _run(["getDeviceId", "Landroid/telephony/TelephonyManager;"])
    assert r.leads == []


def test_dex_iteration_error_does_not_crash(monkeypatch) -> None:
    class _BoomCtx(FakeContext):
        def dex_strings(self):  # type: ignore[override]
            raise RuntimeError("dex boom")

    r = SensitiveApiAnalyzer().analyze(_BoomCtx())
    # collect_dex_strings 内部吞异常 → dex_scanned=False，findings 空，不抛
    assert r.meta["dex_scanned"] is False
    assert r.findings == []


def test_rules_missing_uses_no_findings(monkeypatch) -> None:
    monkeypatch.setattr(sensitive_api, "load_rules", lambda name: {})
    r = _run(["getDeviceId", "Landroid/telephony/TelephonyManager;"])
    assert r.findings == []
    assert r.meta["sensitive_apis"] == []


def test_rule_entry_without_tokens_skipped(monkeypatch) -> None:
    monkeypatch.setattr(
        sensitive_api,
        "load_rules",
        lambda name: {"apis": [{"id": "X", "title": "x"}, {"id": "Y", "dex_tokens": ["onCreate"]}]},
    )
    r = _run(["onCreate"])
    assert "Y" in _ids(r)
    assert "X" not in _ids(r)  # 无 dex_tokens 被跳过


def test_toplevel_list_rules_parsed(monkeypatch) -> None:
    """顶层直接是 list[规则] 也能解析。"""
    monkeypatch.setattr(
        sensitive_api, "load_rules", lambda name: [{"id": "Z", "dex_tokens": ["onCreate"], "severity": "HIGH"}]
    )
    r = _run(["onCreate"])
    assert "Z" in _ids(r)


def test_bad_entries_skipped_others_survive(monkeypatch) -> None:
    monkeypatch.setattr(
        sensitive_api,
        "load_rules",
        lambda name: {
            "apis": [
                "not-a-dict",
                {"title": "缺 id"},
                {"id": "OK", "dex_tokens": ["onCreate"]},
            ]
        },
    )
    r = _run(["onCreate"])
    assert _ids(r) == {"OK"}


def test_toplevel_non_dict_list_no_findings(monkeypatch) -> None:
    monkeypatch.setattr(sensitive_api, "load_rules", lambda name: "garbage")
    assert _run(["getDeviceId", "Landroid/telephony/TelephonyManager;"]).findings == []
