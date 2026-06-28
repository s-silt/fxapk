"""infra 的"编码伪域名"噪音识别单测。

痛点：base64/hex/随机串里夹了点，会被当成域名（`aGVsbG8.d29ybGQ.example`），调证时不可回溯。
``looks_like_encoding`` 识别这类高熵/编码标签，``classify_domain`` 据此降级为"待核"+标原因，
**不静默丢弃**（保留可见、可人工核），且**不误伤短 DGA C2/ 正常域名**。
"""

from __future__ import annotations

from apkscan.core import infra


def test_flags_long_base64_label() -> None:
    reason = infra.looks_like_encoding("abcdefghijklmnop1234567890ABCDEF.example.com")
    assert reason is not None and ("编码" in reason or "base64" in reason)


def test_flags_long_hex_label() -> None:
    reason = infra.looks_like_encoding("a1b2c3d4e5f6a7b8c9d0e1f2.com")
    assert reason is not None and "hex" in reason.lower()


def test_spares_short_dga_c2() -> None:
    """短随机 C2（DGA 风格）不能被误判为编码噪音——它可能是真后端。"""
    assert infra.looks_like_encoding("al2x9k.vip") is None
    assert infra.looks_like_encoding("evil-c2.example.com") is None


def test_spares_real_word_and_normal_domain() -> None:
    assert infra.looks_like_encoding("verylongbusinessname.com") is None
    assert infra.looks_like_encoding("api.legit-company.com") is None
    assert infra.looks_like_encoding("pay.gateway.cn") is None


def test_classify_downgrades_encoding_to_review() -> None:
    advice, reason = infra.classify_domain("aGVsbG8gd29ybGQgdGhpczEyMzQ.example.com")
    assert advice == infra.ADVICE_REVIEW
    assert "编码" in reason or "随机" in reason or "hex" in reason.lower()


def test_classify_real_suspicious_domain_still_investigate() -> None:
    """真·可疑 App 自有域名仍判建议调证（没被噪音过滤吞掉）。"""
    advice, _reason = infra.classify_domain("api.evil-backend.vip")
    assert advice == infra.ADVICE_INVESTIGATE


def test_entropy_helper_monotonic() -> None:
    low = infra._shannon_entropy("aaaaaaaa")
    high = infra._shannon_entropy("aB3xK9zQ")
    assert high > low
