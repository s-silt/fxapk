"""apkscan.dynamic.cryptohook 的单测（P0 运行时密钥 hook 纯逻辑层）。

策略：全程无设备/无 Frida，只测 on_message handler 规范化、活体配方反推、冒充品牌抽取、
transformation 拆分、Frida JS 常量完整性。Frida JS 本身的真机行为由用户在 MuMu 复验。
"""

from __future__ import annotations

import base64
import json
from typing import Any

from apkscan.dynamic import cryptohook

# 真样本 key（32 个 ASCII 字符，按 UTF-8 当 key —— CryptoJS enc.Utf8.parse 口径）。
_KEY = "55f0e4afd83cf8dcae7a4d3daf663467"
_KEY_HEX = _KEY.encode("utf-8").hex()  # JS 侧 getEncoded() 回传的 key bytes 的 hex


def _send(payload: dict[str, Any]) -> dict[str, Any]:
    """包成 Frida send 消息。"""
    return {"type": "send", "payload": {"type": cryptohook.CRYPTO_MSG_TYPE, **payload}}


def _cipher_init(**kw: Any) -> dict[str, Any]:
    base = {"src": "cipher", "event": "init", "transformation": "AES/CFB/PKCS5Padding"}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# make_message_handler
# ---------------------------------------------------------------------------


def test_make_message_handler_collects_send_payload() -> None:
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    handler(_send(_cipher_init(key_hex=_KEY_HEX, iv_hex="61626364616263646162636461626364")), None)
    assert len(sink) == 1
    ev = sink[0]
    assert ev["src"] == "cipher"
    assert ev["event"] == "init"
    assert ev["key_hex"] == _KEY_HEX
    assert ev["transformation"] == "AES/CFB/PKCS5Padding"


def test_handler_ignores_non_apkscan_and_error_messages() -> None:
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    # 非本通道 send
    handler({"type": "send", "payload": {"type": "other", "src": "x"}}, None)
    # error 消息（JS 异常）：记 warning、不入 sink、不抛
    handler({"type": "error", "description": "boom", "stack": "..."}, None)
    # payload 非 dict
    handler({"type": "send", "payload": "notadict"}, None)
    # message 非 dict
    handler("garbage", None)  # type: ignore[arg-type]
    handler(None, None)
    assert sink == []


def test_handler_never_raises_on_garbage_payload() -> None:
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    # payload 缺 src/event → normalize 返回 None，不入 sink、不抛
    handler(_send({"foo": "bar"}), None)
    assert sink == []


def test_handler_logs_warning_on_error_message(caplog) -> None:
    """error 消息（JS 异常）必须记 warning（JS 异常诊断的唯一出口），不入 sink、不抛。"""
    import logging

    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    with caplog.at_level(logging.WARNING):
        handler({"type": "error", "description": "TypeError: x", "stack": "..."}, None)
    assert sink == []
    assert any("Frida JS 异常" in r.message for r in caplog.records)


def test_handler_swallows_exception_in_body(monkeypatch, caplog) -> None:
    """不变量 #8 最后防线：handler 内部抛异常被吞住（绝不炸 Frida 会话），记 exception。"""
    import logging

    def _boom(payload: Any) -> dict[str, Any]:
        raise RuntimeError("normalize boom")

    monkeypatch.setattr(cryptohook, "normalize_crypto_event", _boom)
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    with caplog.at_level(logging.ERROR):
        handler(_send(_cipher_init(key_hex=_KEY_HEX)), None)  # 不抛即通过
    assert sink == []
    assert any("处理 Frida 消息异常" in r.message for r in caplog.records)


def test_handler_respects_sink_cap(monkeypatch) -> None:
    monkeypatch.setattr(cryptohook, "_SINK_CAP", 2)
    sink: list[dict[str, Any]] = []
    handler = cryptohook.make_message_handler(sink)
    for i in range(4):
        handler(_send(_cipher_init(src=f"cipher{i}", key_hex=_KEY_HEX)), None)
    # 2 条真事件 + 1 条 _capped 占位（触发一次性 warning 后停）
    real = [e for e in sink if not e.get("_capped")]
    capped = [e for e in sink if e.get("_capped")]
    assert len(real) == 2
    assert len(capped) == 1


# ---------------------------------------------------------------------------
# normalize_crypto_event
# ---------------------------------------------------------------------------


def test_normalize_drops_non_dict_and_missing_fields() -> None:
    assert cryptohook.normalize_crypto_event("x") is None
    assert cryptohook.normalize_crypto_event({"src": "cipher"}) is None  # 缺 event
    assert cryptohook.normalize_crypto_event({"event": "init"}) is None  # 缺 src


def test_normalize_rejects_bad_hex_key() -> None:
    ev = cryptohook.normalize_crypto_event(
        {"src": "cipher", "event": "init", "key_hex": "ZZZZ", "iv_hex": "not-hex"}
    )
    assert ev is not None
    assert ev["key_hex"] is None  # 非合法 hex → None
    assert ev["iv_hex"] is None


# ---------------------------------------------------------------------------
# recipe_from_events
# ---------------------------------------------------------------------------


def test_recipe_from_events_prefers_utf8_key_when_ascii() -> None:
    events = [_cipher_init(key_hex=_KEY_HEX)]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert recipe["key"] == _KEY  # 可见 ASCII → 还原成 utf8 串
    assert recipe["key_encoding"] == "utf8"
    assert recipe["algo"] == "AES"
    assert recipe["mode"] == "CFB"
    assert recipe["padding"] == "Pkcs7"


def test_recipe_from_events_hex_key_when_binary() -> None:
    bin_key_hex = "00112233445566778899aabbccddeeff"  # 含不可见字节
    events = [_cipher_init(key_hex=bin_key_hex)]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert recipe["key"] == bin_key_hex
    assert recipe["key_encoding"] == "hex"


def test_recipe_from_events_constant_iv_sets_fixed() -> None:
    iv_ascii = "abcdefghijklmnop"  # 16 可见 ASCII
    iv_hex = iv_ascii.encode("utf-8").hex()
    events = [
        _cipher_init(key_hex=_KEY_HEX, iv_hex=iv_hex),
        _cipher_init(key_hex=_KEY_HEX, iv_hex=iv_hex),  # 恒定
    ]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert recipe["iv_derive"] == "fixed"
    # key_encoding=utf8 且 iv 可见 ASCII → iv_value 用 ascii 串
    assert recipe["iv_value"] == iv_ascii


def test_recipe_from_events_varying_iv_not_fixed() -> None:
    """风险缓解：iv 每请求变（md5(key+ts)）时绝不设 fixed，仅反哺 key、iv 交静态推导。"""
    events = [
        _cipher_init(key_hex=_KEY_HEX, iv_hex="61626364616263646162636461626364"),
        _cipher_init(key_hex=_KEY_HEX, iv_hex="71727374717273747172737471727374"),  # 变化
    ]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert "iv_derive" not in recipe  # 不设 fixed
    assert "iv_value" not in recipe
    assert recipe["key"] == _KEY  # key 仍反哺


def test_recipe_from_events_none_when_no_key() -> None:
    events = [{"src": "cipher", "event": "doFinal", "plaintext_b64": "eyJhIjoxfQ=="}]
    assert cryptohook.recipe_from_events(events) is None
    assert cryptohook.recipe_from_events([]) is None


def test_recipe_from_events_dominant_key_wins() -> None:
    other = "aa" * 16
    events = [
        _cipher_init(key_hex=_KEY_HEX),
        _cipher_init(key_hex=_KEY_HEX),
        _cipher_init(key_hex=other),
    ]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert recipe["key"] == _KEY  # 出现 2 次 > 1 次


def test_recipe_from_events_mac_key_only_as_fallback() -> None:
    """Mac(HMAC) key 仅在无 cipher/secretkeyspec key 时兜底。"""
    mac_hex = "aabbccddeeff00112233445566778899"
    events = [{"src": "mac", "event": "init", "key_hex": mac_hex}]
    recipe = cryptohook.recipe_from_events(events)
    assert recipe is not None
    assert recipe["key_encoding"] == "hex"
    assert recipe["key"] == mac_hex


# ---------------------------------------------------------------------------
# transformation_parts
# ---------------------------------------------------------------------------


def test_transformation_parts_full() -> None:
    assert cryptohook.transformation_parts("AES/CFB/PKCS5Padding") == ("AES", "CFB", "Pkcs7")
    assert cryptohook.transformation_parts("AES/CBC/NoPadding") == ("AES", "CBC", "NoPadding")
    assert cryptohook.transformation_parts("DESede/ECB/PKCS7Padding") == ("3DES", "ECB", "Pkcs7")


def test_transformation_parts_algo_only() -> None:
    assert cryptohook.transformation_parts("AES") == ("AES", "", "")
    assert cryptohook.transformation_parts("") == ("", "", "")


# ---------------------------------------------------------------------------
# brand_hints_from_events
# ---------------------------------------------------------------------------


def _doFinal_plain(obj: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return {
        "src": "cipher",
        "event": "doFinal",
        "opmode": 2,
        "plaintext_b64": base64.b64encode(raw).decode("ascii"),
    }


def test_brand_hints_from_events_extracts_webname() -> None:
    events = [_doFinal_plain({"webName": "示例证券", "register": "/api/register"})]
    hints = cryptohook.brand_hints_from_events(events)
    assert "示例证券" in hints


def test_brand_hints_from_events_catches_industry_token() -> None:
    events = [_doFinal_plain({"foo": "华西银行股份有限公司", "x": 1})]
    hints = cryptohook.brand_hints_from_events(events)
    assert any("银行" in h for h in hints)


def test_brand_hints_from_events_empty_when_no_plaintext() -> None:
    assert cryptohook.brand_hints_from_events([_cipher_init(key_hex=_KEY_HEX)]) == []
    assert cryptohook.brand_hints_from_events([]) == []


# ---------------------------------------------------------------------------
# Frida JS 常量完整性
# ---------------------------------------------------------------------------


def test_frida_crypto_hook_js_integrity() -> None:
    js = cryptohook.FRIDA_CRYPTO_HOOK_JS
    assert "Java.perform" in js
    assert "javax.crypto.Cipher" in js
    assert "doFinal" in js
    assert "SecretKeySpec" in js
    assert "IvParameterSpec" in js
    assert "CryptoJS" in js  # WebView 补充路径
    assert "send(" in js  # 回传通道
    assert "apkscan-crypto" in js  # 通道判别值与 Python 端一致
