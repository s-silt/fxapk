"""config-chain Tier A：确定性自动解密（_stage_decrypt_candidates）测试。

覆盖：配方已知 → 本地 appcrypto 解密文候选 → 解出域名/IP 回灌端点（source=config-decrypted、不误升 runtime
徽标）；无配方 → 跳过留给 AI；无候选 → no-op。解密用 cryptography 现造 fixture（缺库 skip）。
"""

from __future__ import annotations

import base64
import json

import pytest

from apkscan.core import pipeline
from apkscan.core.models import AnalysisConfig, Lead, LeadCategory


def _state():
    return pipeline._PipelineState(ctx=None, config=AnalysisConfig(), platform="android", capabilities=set())  # type: ignore[arg-type]


_KEY = b"0123456789abcdef0123456789abcdef"  # 32B → AES-256
_IV = b"fedcba9876543210"  # 16B
_RECIPE = {
    "algo": "AES", "mode": "CBC", "padding": "Pkcs7",
    "key": _KEY.decode(), "key_encoding": "utf8",
    "iv_derive": "fixed", "iv_value": _IV.decode(), "payload_encoding": "base64",
}


def _encrypt(plaintext: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def test_auto_decrypts_and_feeds_back_endpoints() -> None:
    pytest.importorskip("cryptography")
    ct = _encrypt(json.dumps({"domains": ["api.evil-c2.com"], "ips": ["45.11.22.33"]}).encode())
    st = _state()
    st.meta["crypto_recipe"] = _RECIPE
    st.meta["decrypt_candidates"] = [
        {"ciphertext": ct, "consumer": "m1136x", "method": "run", "location": "C.java"}
    ]
    pipeline._stage_decrypt_candidates(st)

    auto = st.meta["decrypt_candidates_auto"]
    assert auto["attempted"] == 1 and auto["decrypted"] == 1
    assert set(auto["results"][0]["domains"]) == {"api.evil-c2.com"}
    values = {ep.value for ep in st.endpoints}
    assert "api.evil-c2.com" in values and "45.11.22.33" in values

    ep = next(ep for ep in st.endpoints if ep.value == "api.evil-c2.com")
    assert ep.evidences[0].source == "config-decrypted"  # 非 runtime* 来源
    # ★信任边界：解密回灌端点不误升"确认 C2"/"运行时出现"徽标
    lead = Lead(category=LeadCategory.DOMAIN, value=ep.value, source_refs=list(ep.evidences))
    assert lead.is_runtime_contact is False and lead.is_runtime_seen is False


def test_decrypt_plaintext_bare_domain() -> None:
    """解出的明文直接就是域名（非 JSON）也能抽出回灌。"""
    pytest.importorskip("cryptography")
    ct = _encrypt(b"www.p2z4e.com")
    st = _state()
    st.meta["crypto_recipe"] = _RECIPE
    st.meta["decrypt_candidates"] = [{"ciphertext": ct, "location": "App.java"}]
    pipeline._stage_decrypt_candidates(st)
    assert st.meta["decrypt_candidates_auto"]["decrypted"] == 1
    assert "www.p2z4e.com" in {ep.value for ep in st.endpoints}


def test_no_recipe_skips_leaves_for_ai() -> None:
    st = _state()
    st.meta["decrypt_candidates"] = [{"ciphertext": "QUJDREVGR0hJSktMTU5P", "consumer": "x"}]
    pipeline._stage_decrypt_candidates(st)
    assert st.meta["decrypt_candidates_auto"]["reason"] == "no crypto_recipe"
    assert st.endpoints == []


def test_wrong_recipe_decrypt_fails_gracefully() -> None:
    """配方不对（key 错）→ 解密失败(UTF-8 校验)→ decrypted=0、不回灌、不抛。"""
    pytest.importorskip("cryptography")
    ct = _encrypt(b"www.p2z4e.com")
    st = _state()
    bad = dict(_RECIPE, key="wrongkeywrongkeywrongkeywrongkey")  # 32B 但错
    st.meta["crypto_recipe"] = bad
    st.meta["decrypt_candidates"] = [{"ciphertext": ct, "location": "x"}]
    pipeline._stage_decrypt_candidates(st)
    assert st.meta["decrypt_candidates_auto"]["decrypted"] == 0
    assert st.endpoints == []


def test_no_candidates_noop() -> None:
    st = _state()
    pipeline._stage_decrypt_candidates(st)
    assert "decrypt_candidates_auto" not in st.meta
