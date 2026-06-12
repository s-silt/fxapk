"""第二波（最后一个动态功能）无障碍远控指令与目标银行清单捕获纯逻辑单测。

背景：无障碍远控木马劫持银行/支付 app 自动转账。运行时 hook
AccessibilityService.onAccessibilityEvent（记被操作 app 包名 = 目标清单）、dispatchGesture /
performGlobalAction（下发手势 = 远控指令）、MediaProjectionManager.createVirtualDisplay
（屏幕录制开启）。

★ 边界（务必照做）：无障碍远控逻辑绝大多数要诱导真人操作才走，launch-only 抓不到——降 P2，
模块/Lead/Finding 明标「需引导式人工动态，launch-only 抓不到」。

策略（与 test_clipboard / test_credential / test_victim_db 同范式）：全程无设备/无 Frida，
只测可测纯函数——

- cryptohook.normalize_remote_control_event：合成 payload（onAccessibilityEvent 带 packageName /
  dispatchGesture / performGlobalAction / createVirtualDisplay）→ 规范化、限流、不抛。
- cryptohook.FRIDA_ACCESSIBILITY_HOOK_JS：Frida JS 常量完整性（hook 抽象基类回调 best-effort、
  dispatchGesture 限流、send 通道、MediaProjection）。
- merge.merge_runtime_remote_control：合成 events → 工行包产 REMOTE_CONTROL Lead 映射机构主体 +
  回传 host 并入端点走 infra（CDN 不升）+ 手势/MediaProjection 产 Finding（不 Lead 化）+ 未知包
  不滥产 Lead + launch-only notes；坏/空不抛。
- bank_packages 映射命中/未命中。

真机部分（frida JS 注入 AccessibilityService hook 抓实际无障碍事件）无法单测，由用户在 MuMu
配合引导式人工操作复验。
"""

from __future__ import annotations

from typing import Any

from apkscan.core import infra
from apkscan.core.models import Endpoint, Lead, LeadCategory, Report
from apkscan.dynamic import cryptohook, merge

# 工行真实包名（命中 bank_packages）。
_ICBC_PKG = "com.icbc.mobile.android"
# 支付宝真实包名（命中 bank_packages 精确键）。
_ALIPAY_PKG = "com.eg.android.AlipayGphone"
# 未知/无关包名（不应产 Lead，进 Finding/notes）。
_UNKNOWN_PKG = "com.random.unknown.app"
# 屏幕回传 C2（未命中 KNOWN_INFRA → 建议调证）。
_C2_HOST = "evil-c2.com"
# CDN（命中 KNOWN_INFRA → 无需调证，不应升 C2）。
_CDN_HOST = "cdn.jsdelivr.net"


def _make_report(
    *,
    endpoints: list[Endpoint] | None = None,
    leads: list[Lead] | None = None,
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


# ===========================================================================
# normalize_remote_control_event —— 规范化 / 限流 / 不抛
# ===========================================================================


def test_normalize_rc_drops_non_dict() -> None:
    assert cryptohook.normalize_remote_control_event("x") is None
    assert cryptohook.normalize_remote_control_event(None) is None
    assert cryptohook.normalize_remote_control_event(123) is None
    assert cryptohook.normalize_remote_control_event({}) is None


def test_normalize_rc_accessibility_event_with_package() -> None:
    """onAccessibilityEvent 带 packageName → event=accessibility_event + target_package。"""
    ev = cryptohook.normalize_remote_control_event(
        {"event": "accessibility_event", "package": _ICBC_PKG, "ts": 1700000000000}
    )
    assert ev is not None
    assert ev["event"] == "accessibility_event"
    assert ev["target_package"] == _ICBC_PKG
    assert ev["ts"] == 1700000000000


def test_normalize_rc_gesture_event() -> None:
    """dispatchGesture / performGlobalAction → event=gesture，记 action（远控指令）。"""
    ev = cryptohook.normalize_remote_control_event(
        {"event": "gesture", "action": "dispatchGesture"}
    )
    assert ev is not None
    assert ev["event"] == "gesture"
    assert ev["action"] == "dispatchGesture"

    ev2 = cryptohook.normalize_remote_control_event(
        {"event": "gesture", "action": "performGlobalAction:GLOBAL_ACTION_BACK"}
    )
    assert ev2 is not None
    assert ev2["action"] == "performGlobalAction:GLOBAL_ACTION_BACK"


def test_normalize_rc_screencapture_event() -> None:
    """createVirtualDisplay → event=screencapture（屏幕录制开启）。"""
    ev = cryptohook.normalize_remote_control_event(
        {"event": "screencapture", "action": "createVirtualDisplay"}
    )
    assert ev is not None
    assert ev["event"] == "screencapture"


def test_normalize_rc_host_event() -> None:
    """屏幕/控件树回传 host → event=screen_upload + host（供 merge 并入端点走 infra）。"""
    ev = cryptohook.normalize_remote_control_event(
        {"event": "screen_upload", "host": _C2_HOST}
    )
    assert ev is not None
    assert ev["host"] == _C2_HOST


def test_normalize_rc_unknown_event_dropped() -> None:
    """无识别 event/字段（既无 package 也无 action 也无 host）→ None（不留空事件）。"""
    assert cryptohook.normalize_remote_control_event({"event": "weird"}) is None
    assert cryptohook.normalize_remote_control_event({"foo": "bar"}) is None


def test_normalize_rc_ts_only_int() -> None:
    ev = cryptohook.normalize_remote_control_event(
        {"event": "gesture", "action": "dispatchGesture", "ts": "bad"}
    )
    assert ev is not None
    assert ev["ts"] is None


# ===========================================================================
# FRIDA_ACCESSIBILITY_HOOK_JS —— Frida JS 常量完整性
# ===========================================================================


def test_remote_control_msg_type_constant() -> None:
    assert cryptohook.ACCESSIBILITY_MSG_TYPE == "apkscan-accessibility"


def test_frida_accessibility_hook_js_integrity() -> None:
    js = cryptohook.FRIDA_ACCESSIBILITY_HOOK_JS
    assert "Java.perform" in js
    # 抽象基类回调 best-effort + 全局动作 + 手势 + 屏幕录制。
    assert "AccessibilityService" in js
    assert "onAccessibilityEvent" in js
    assert "dispatchGesture" in js
    assert "performGlobalAction" in js
    assert "createVirtualDisplay" in js
    assert "getPackageName" in js
    # 回传通道判别值与 Python 端约定一致。
    assert "apkscan-accessibility" in js
    # best-effort：每个 hook 包 try/catch，不抛。
    assert "try {" in js
    assert "send(" in js
    # dispatchGesture 高频 → 限流（计数/采样）。
    assert "_CAP" in js or "_cap" in js


# ===========================================================================
# bank_packages 映射命中 / 未命中
# ===========================================================================


def test_bank_packages_mapping_exact_hit() -> None:
    """支付宝精确包名 → 蚂蚁集团。"""
    subject = merge._bank_subject_of_package(_ALIPAY_PKG)
    assert subject is not None
    assert "支付宝" in subject


def test_bank_packages_mapping_prefix_hit() -> None:
    """工行子包（前缀匹配 com.icbc.）→ 中国工商银行。"""
    subject = merge._bank_subject_of_package(_ICBC_PKG)
    assert subject is not None
    assert "工商银行" in subject


def test_bank_packages_mapping_miss() -> None:
    """未知包名 → None（不映射、不滥产 Lead）。"""
    assert merge._bank_subject_of_package(_UNKNOWN_PKG) is None
    assert merge._bank_subject_of_package("") is None


# ===========================================================================
# merge_runtime_remote_control —— 目标包→机构 Lead / 回传 host 走 infra / 手势 Finding
# ===========================================================================


def _rc_events(events: list[dict[str, Any]]) -> Any:
    """构造 monkeypatch._load_events_field 用的桩：仅 remote_control_events 返回。"""
    return lambda path, field: events if field == "remote_control_events" else []


def test_merge_rc_known_bank_produces_lead(monkeypatch, tmp_path) -> None:
    """目标含工行包 → 产 REMOTE_CONTROL Lead，映射机构主体 + 调证去向。"""
    report = _make_report()
    events = [
        {"event": "accessibility_event", "target_package": _ICBC_PKG},
    ]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    stats = merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    rc_leads = [l for l in report.leads if l.category == LeadCategory.REMOTE_CONTROL]
    assert len(rc_leads) == 1
    lead = rc_leads[0]
    assert "工商银行" in (lead.subject or "")
    assert _ICBC_PKG in lead.value
    assert lead.where_to_request  # 向目标银行/支付机构调被害人流水
    assert lead.evidence_to_obtain  # [被害账户交易流水, 异常转账记录, 设备登录指纹]
    assert any("流水" in e for e in lead.evidence_to_obtain)
    # launch-only 诚实标注。
    assert "launch-only" in lead.notes or "人工" in lead.notes
    assert stats["rc_leads"] == 1


def test_merge_rc_unknown_package_no_lead(monkeypatch, tmp_path) -> None:
    """未知包名 → 不产 Lead（进 Finding/notes，不滥产 Lead）。"""
    report = _make_report()
    events = [{"event": "accessibility_event", "target_package": _UNKNOWN_PKG}]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    stats = merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    rc_leads = [l for l in report.leads if l.category == LeadCategory.REMOTE_CONTROL]
    assert rc_leads == []
    assert stats["rc_leads"] == 0


def test_merge_rc_upload_host_into_endpoints_infra(monkeypatch, tmp_path) -> None:
    """屏幕/控件树回传 host → 并入端点走 infra 分级：C2 host 建议调证，CDN 不升。"""
    report = _make_report()
    events = [
        {"event": "screen_upload", "host": _C2_HOST},
        {"event": "screen_upload", "host": _CDN_HOST},
    ]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    values = {ep.value for ep in report.endpoints}
    assert _C2_HOST in values
    assert _CDN_HOST in values
    # C2 host → 建议调证（DOMAIN Lead）；CDN → 无需调证（不当 C2）。
    c2_lead = next((l for l in report.leads if l.value == _C2_HOST), None)
    assert c2_lead is not None
    assert c2_lead.advice == infra.ADVICE_INVESTIGATE
    cdn_lead = next((l for l in report.leads if l.value == _CDN_HOST), None)
    assert cdn_lead is not None
    assert cdn_lead.advice == infra.ADVICE_SKIP


def test_merge_rc_gestures_produce_finding_not_lead(monkeypatch, tmp_path) -> None:
    """远控手势序列 + MediaProjection 开启 → 产 Finding（severity 高），不 Lead 化。"""
    report = _make_report()
    events = [
        {"event": "accessibility_event", "target_package": _ICBC_PKG},
        {"event": "gesture", "action": "dispatchGesture"},
        {"event": "gesture", "action": "dispatchGesture"},
        {"event": "gesture", "action": "performGlobalAction:GLOBAL_ACTION_BACK"},
        {"event": "screencapture", "action": "createVirtualDisplay"},
    ]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    stats = merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    # 手势/MediaProjection 不产 Lead（行为定性证据走 Finding）。
    gesture_leads = [
        l for l in report.leads
        if l.category == LeadCategory.REMOTE_CONTROL and "手势" in (l.notes or "")
    ]
    assert gesture_leads == []
    # 产一条 attack_surface/runtime 类 Finding，描述实测无障碍远控行为。
    rc_findings = [f for f in report.findings if "远控" in f.title or "无障碍" in f.title]
    assert len(rc_findings) == 1
    finding = rc_findings[0]
    assert finding.category in ("attack_surface", "runtime")
    # 描述含下发手势数 / 劫持包名 / 屏幕录制开启。
    assert "3" in finding.description or "手势" in finding.description
    assert "屏幕" in finding.description or "录制" in finding.description
    assert stats["gesture_count"] == 3
    assert stats["screencapture"] == 1


def test_merge_rc_finding_without_gestures_still_notes_targets(monkeypatch, tmp_path) -> None:
    """仅目标包名（无手势/无屏幕录制）→ 仍产 Lead，但不强行产手势 Finding。"""
    report = _make_report()
    events = [{"event": "accessibility_event", "target_package": _ALIPAY_PKG}]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    rc_leads = [l for l in report.leads if l.category == LeadCategory.REMOTE_CONTROL]
    assert len(rc_leads) == 1
    # 无手势/无屏幕录制 → 不产手势行为 Finding（宁缺毋滥）。
    rc_findings = [f for f in report.findings if "远控" in f.title or "无障碍" in f.title]
    assert rc_findings == []


def test_merge_rc_dedup_leads(monkeypatch, tmp_path) -> None:
    """同一目标包多次被劫持 → 去重，只产一条 Lead。"""
    report = _make_report()
    events = [
        {"event": "accessibility_event", "target_package": _ICBC_PKG},
        {"event": "accessibility_event", "target_package": _ICBC_PKG},
        {"event": "accessibility_event", "target_package": _ICBC_PKG},
    ]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))

    rc_leads = [l for l in report.leads if l.category == LeadCategory.REMOTE_CONTROL]
    assert len(rc_leads) == 1


def test_merge_rc_empty_events_no_throw(monkeypatch, tmp_path) -> None:
    """缺/空 remote_control_events（旧报告无该字段）→ 零统计、不抛、不产 Lead/Finding。"""
    report = _make_report()
    monkeypatch.setattr(merge, "_load_events_field", lambda path, field: [])
    stats = merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))
    assert stats["rc_leads"] == 0
    assert report.leads == []
    assert report.findings == []


def test_merge_rc_bad_events_skipped(monkeypatch, tmp_path) -> None:
    """坏事件（非 dict / 缺字段）不抛、被跳过；好事件仍处理。"""
    report = _make_report()
    events = [
        "not-a-dict",
        {"event": "accessibility_event"},  # 缺 target_package
        {"target_package": ""},  # 空包名
        {"event": "accessibility_event", "target_package": _ICBC_PKG},  # 唯一好事件
    ]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    stats = merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))
    assert stats["rc_leads"] == 1
    rc_leads = [l for l in report.leads if l.category == LeadCategory.REMOTE_CONTROL]
    assert _ICBC_PKG in rc_leads[0].value


def test_merge_rc_meta_marked(monkeypatch, tmp_path) -> None:
    """meta 打标 runtime_remote_control。"""
    report = _make_report()
    events = [{"event": "accessibility_event", "target_package": _ICBC_PKG}]
    monkeypatch.setattr(merge, "_load_events_field", _rc_events(events))
    merge.merge_runtime_remote_control(report, str(tmp_path / "rr.json"))
    assert report.meta.get("runtime_remote_control") is True


# ===========================================================================
# LeadCategory.REMOTE_CONTROL 登记
# ===========================================================================


def test_remote_control_lead_category_exists() -> None:
    assert LeadCategory.REMOTE_CONTROL.value == "REMOTE_CONTROL"


def test_remote_control_html_label_registered() -> None:
    from apkscan.report import html

    assert LeadCategory.REMOTE_CONTROL in html.CATEGORY_LABELS
    assert LeadCategory.REMOTE_CONTROL in html.CATEGORY_ORDER
