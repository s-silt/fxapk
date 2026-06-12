"""第二波 剪贴板链上地址运行时抓取（资金流起点·运行时确认）纯逻辑单测。

策略（与 test_cryptohook / test_credential / test_victim_db 同范式）：全程无设备/无 Frida，
只测可测纯函数——

- cryptohook.normalize_clipboard_event：★ 隐私护栏——收到剪贴板文本后立即用 chainaddr
  抽出校验通过的地址，**只保留地址、丢弃原文**；含验证码/密码/聊天等隐私串绝不进输出；
  无合法地址 → 空事件。
- cryptohook.FRIDA_CLIPBOARD_HOOK_JS：Frida JS 常量完整性（hook getPrimaryClip/getText、
  send 回传通道、字节上限）。
- merge.merge_runtime_clipboard：合成 clipboard_events → PAYMENT 类 Lead（value=地址、
  is_runtime_seen=True、notes 标链 + 运行时来源）；坏/空事件不抛；与静态同地址去重。
- chainaddr 校验联动：随机串（非合法地址）被滤掉。

真机部分（frida JS 注入 ClipboardManager hook 抓实际剪贴板文本）无法单测，由用户在 MuMu
复验，与现有 cryptohook 真机 JS 行为一致。
"""

from __future__ import annotations

from typing import Any

from apkscan.core.models import Confidence, Evidence, Lead, LeadCategory, Report
from apkscan.dynamic import cryptohook, merge

# 测试用合法链上地址（过 chainaddr 校验和）。
# TRON（Base58Check，0x41 前缀）：USDT-TRC20 常见收款地址。
_TRON_ADDR = "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC"
# EVM（EIP-55 混合大小写校验和通过）：vitalik.eth 地址。
_EVM_ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def _make_report(
    *,
    leads: list[Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> Report:
    return Report(
        package_name="com.test.app",
        meta=dict(meta or {}),
        leads=list(leads or []),
        endpoints=[],
        findings=[],
        analyzer_status=[],
    )


# ===========================================================================
# normalize_clipboard_event —— 隐私护栏（最关键）
# ===========================================================================


def test_normalize_clipboard_drops_non_dict() -> None:
    assert cryptohook.normalize_clipboard_event("x") is None
    assert cryptohook.normalize_clipboard_event(None) is None
    assert cryptohook.normalize_clipboard_event(123) is None


def test_normalize_clipboard_extracts_address_and_discards_text() -> None:
    """★ 隐私护栏：剪贴板含地址 + 验证码/密码/聊天 → 只留地址，原文/隐私串绝不在输出里。"""
    secret = "验证码 938271 密码 hunter2 转账到这个钱包"
    text = f"{secret} {_TRON_ADDR} 谢谢"
    ev = cryptohook.normalize_clipboard_event({"text": text})
    assert ev is not None
    assert ev["addresses"] == [{"value": _TRON_ADDR, "chain": "TRON", "checksum_verified": True}]

    # 序列化整条事件，断言原文/隐私串任何片段都不出现（全文不落盘的铁证）。
    blob = repr(ev)
    assert "938271" not in blob
    assert "hunter2" not in blob
    assert "验证码" not in blob
    assert "密码" not in blob
    assert "谢谢" not in blob
    assert secret not in blob


def test_normalize_clipboard_empty_when_no_valid_address() -> None:
    """无合法地址（纯隐私文本/随机串）→ 该事件为空、不留任何内容。"""
    assert cryptohook.normalize_clipboard_event({"text": "验证码 938271 你好世界"}) is None
    # 随机看似 base58/hex 的串（校验和过不了）也被滤掉。
    assert cryptohook.normalize_clipboard_event({"text": "0x1234567890abcdef not an address"}) is None
    assert cryptohook.normalize_clipboard_event({"text": ""}) is None
    assert cryptohook.normalize_clipboard_event({}) is None


def test_normalize_clipboard_random_string_filtered_by_checksum() -> None:
    """chainaddr 校验联动：T 开头但校验和不对的随机 34 串被滤掉。"""
    fake_tron = "T" + "1" * 33  # 形态像 TRON 但 Base58Check 过不了
    assert cryptohook.normalize_clipboard_event({"text": fake_tron}) is None


def test_normalize_clipboard_multiple_addresses_dedup() -> None:
    """一段含多个不同链地址 + 重复地址 → 去重保序，全部校验通过。"""
    text = f"USDT {_TRON_ADDR} 或 ETH {_EVM_ADDR} 再发一次 {_TRON_ADDR}"
    ev = cryptohook.normalize_clipboard_event({"text": text})
    assert ev is not None
    values = [a["value"] for a in ev["addresses"]]
    assert values == [_EVM_ADDR, _TRON_ADDR]  # find_addresses 按候选正则顺序（EVM 在前）、去重
    chains = {a["chain"] for a in ev["addresses"]}
    assert chains == {"TRON", "EVM"}


def test_normalize_clipboard_carries_ts_when_int() -> None:
    ev = cryptohook.normalize_clipboard_event({"text": _TRON_ADDR, "ts": 1700000000000})
    assert ev is not None
    assert ev["ts"] == 1700000000000
    ev2 = cryptohook.normalize_clipboard_event({"text": _TRON_ADDR, "ts": "bad"})
    assert ev2 is not None
    assert ev2["ts"] is None


# ===========================================================================
# FRIDA_CLIPBOARD_HOOK_JS —— Frida JS 常量完整性
# ===========================================================================


def test_clipboard_msg_type_constant() -> None:
    assert cryptohook.CLIPBOARD_MSG_TYPE == "apkscan-clipboard"


def test_frida_clipboard_hook_js_integrity() -> None:
    js = cryptohook.FRIDA_CLIPBOARD_HOOK_JS
    assert "Java.perform" in js
    assert "ClipboardManager" in js
    assert "getPrimaryClip" in js
    assert "getText" in js
    # 回传通道判别值与 Python 端约定一致。
    assert "apkscan-clipboard" in js
    # best-effort：每个 hook 包 try/catch，不抛。
    assert "try {" in js
    assert "send(" in js


# ===========================================================================
# merge_runtime_clipboard —— PAYMENT 类 Lead + is_runtime_seen + 去重
# ===========================================================================


def _clip_event(addresses: list[dict[str, Any]]) -> dict[str, Any]:
    return {"addresses": addresses, "ts": 1700000000000}


def test_merge_clipboard_produces_payment_lead_runtime_seen(monkeypatch, tmp_path) -> None:
    """合成 clipboard_events → PAYMENT 类 Lead、value=地址、is_runtime_seen=True、notes 标链。"""
    report = _make_report()
    events = [
        _clip_event([{"value": _TRON_ADDR, "chain": "TRON", "checksum_verified": True}])
    ]
    monkeypatch.setattr(
        merge, "_load_events_field", lambda path, field: events if field == "clipboard_events" else []
    )
    stats = merge.merge_runtime_clipboard(report, str(tmp_path / "runtime_report.json"))

    assert stats["clipboard_leads"] == 1
    lead = next(l for l in report.leads if l.value == _TRON_ADDR)
    assert lead.category == LeadCategory.PAYMENT
    assert lead.is_runtime_seen is True  # source 以 runtime 开头
    assert "TRON" in lead.notes
    assert "剪贴板" in lead.notes
    # source_refs 至少一条 runtime 证据。
    assert any(str(ev.source).startswith("runtime") for ev in lead.source_refs)
    # meta 打标。
    assert report.meta.get("runtime_clipboard") is True


def test_merge_clipboard_dedup_with_static_marks_runtime(monkeypatch, tmp_path) -> None:
    """静态已抠到同地址 PAYMENT Lead → 不产重复，合并标注 runtime 确认（升为 is_runtime_seen）。"""
    static_lead = Lead(
        category=LeadCategory.PAYMENT,
        value=_TRON_ADDR,
        subject="待核（疑似收款主体）",
        source_refs=[Evidence(source="dex", location="classes.dex", snippet=_TRON_ADDR)],
        confidence=Confidence.HIGH,
    )
    report = _make_report(leads=[static_lead])
    assert static_lead.is_runtime_seen is False  # 起点：纯静态

    events = [
        _clip_event([{"value": _TRON_ADDR, "chain": "TRON", "checksum_verified": True}])
    ]
    monkeypatch.setattr(
        merge, "_load_events_field", lambda path, field: events if field == "clipboard_events" else []
    )
    merge.merge_runtime_clipboard(report, str(tmp_path / "runtime_report.json"))

    # 不产重复：仍只有一条该地址的 PAYMENT Lead。
    same = [l for l in report.leads if l.category == LeadCategory.PAYMENT and l.value == _TRON_ADDR]
    assert len(same) == 1
    # 静态那条被追加 runtime 证据 → 升为 is_runtime_seen。
    assert same[0].is_runtime_seen is True


def test_merge_clipboard_empty_events_no_throw(monkeypatch, tmp_path) -> None:
    """缺/空 clipboard_events（旧报告无该字段）→ 零统计、不抛、不产 Lead。"""
    report = _make_report()
    monkeypatch.setattr(merge, "_load_events_field", lambda path, field: [])
    stats = merge.merge_runtime_clipboard(report, str(tmp_path / "runtime_report.json"))
    assert stats == {"clipboard_leads": 0}
    assert report.leads == []


def test_merge_clipboard_bad_events_skipped(monkeypatch, tmp_path) -> None:
    """坏事件（非 dict / addresses 非 list / 地址缺 value）不抛、被跳过。"""
    report = _make_report()
    events = [
        "not-a-dict",
        {"addresses": "not-a-list"},
        {"addresses": [{"chain": "TRON"}]},  # 缺 value
        {"addresses": [{"value": "", "chain": "TRON"}]},  # 空 value
        _clip_event([{"value": _EVM_ADDR, "chain": "EVM", "checksum_verified": True}]),  # 唯一好事件
    ]
    monkeypatch.setattr(
        merge, "_load_events_field", lambda path, field: events if field == "clipboard_events" else []
    )
    stats = merge.merge_runtime_clipboard(report, str(tmp_path / "runtime_report.json"))
    assert stats["clipboard_leads"] == 1
    assert [l.value for l in report.leads] == [_EVM_ADDR]
