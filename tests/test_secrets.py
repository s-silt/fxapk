"""core.secrets 共享密钥形态判定测试（C2 + 评审 no-false-kill 修复）。

两面覆盖：
- 误报被过滤：SDK 常量名自映射 / 常量值 / 不像凭据形态。
- 真线索仍命中（评审修复）：放在标准 SDK 键名下的真凭据、纯字母大小写混合长 secret。
"""

from __future__ import annotations

from apkscan.core.secrets import (
    SecretRules,
    is_real_secret,
    is_sdk_constant,
    load_secret_rules,
    looks_like_secret_value,
)

_RULES = load_secret_rules()


# --- C2 已知误报仍被过滤 -----------------------------------------------------


def test_self_mapping_constant_is_dropped() -> None:
    # MIPUSH_APPKEY=MIPUSH_APPKEY（value==key）→ 非凭据。
    assert is_sdk_constant("MIPUSH_APPKEY", "MIPUSH_APPKEY", _RULES)
    assert not is_real_secret("MIPUSH_APPKEY", "MIPUSH_APPKEY", _RULES)


def test_constant_value_is_dropped() -> None:
    # KEY_DEVICE_TOKEN=deviceToken / METHOD_CHECK_APPKEY=dc_checkappkey → value 在常量值表。
    assert is_sdk_constant("KEY_DEVICE_TOKEN", "deviceToken", _RULES)
    assert is_sdk_constant("METHOD_CHECK_APPKEY", "dc_checkappkey", _RULES)
    assert not is_real_secret("KEY_DEVICE_TOKEN", "deviceToken", _RULES)


def test_value_is_another_constant_name_dropped() -> None:
    # value 本身就是某 SDK 常量键名（X_APPKEY=mipush_appkey）→ 仍 drop（看 value，非 key）。
    assert is_sdk_constant("X_APPKEY", "mipush_appkey", _RULES)


# --- 评审 HIGH：标准 SDK 键名下的真凭据不得被误吞 ----------------------------


def test_real_credential_under_sdk_key_name_is_kept() -> None:
    # ★评审 HIGH 回归锁：真小米 appkey 放在标准键名 MIPUSH_APPKEY 下不得被键名短路误吞。
    assert not is_sdk_constant("MIPUSH_APPKEY", "5621543878901", _RULES)
    assert is_real_secret("MIPUSH_APPKEY", "5621543878901", _RULES)


def test_real_oppo_credential_under_sdk_key_name_is_kept() -> None:
    assert is_real_secret("OPPOPUSH_APPKEY", "a1b2c3d4e5f6", _RULES)


def test_real_mipush_appid_under_sdk_key_name_is_kept() -> None:
    # 13 位真小米 appid 数字串（looks_keyish 含数字+字母? 纯数字也算 keyish? -> 纯数字 hex 形态）。
    assert is_real_secret("MIPUSH_APPID", "2882303761517", _RULES)


# --- 评审 MEDIUM：纯字母大小写混合长 secret 不得被 looks_keyish=False 误杀 ----


def test_pure_alpha_mixedcase_long_secret_is_kept() -> None:
    # aBcdEfGhiJkLmnOp（16 位大小写混合纯字母）→ 有熵，保留（评审 MEDIUM 回归锁）。
    assert looks_like_secret_value("aBcdEfGhiJkLmnOp", _RULES)
    assert is_real_secret("app_secret", "aBcdEfGhiJkLmnOp", _RULES)


def test_pure_alpha_all_lower_is_dropped() -> None:
    # 全小写纯字母（无大小写熵，多为单词/标识符）→ 仍 drop，避免把普通字段当 secret。
    assert not looks_like_secret_value("abcdefghijklmnop", _RULES)


def test_short_alpha_mixedcase_is_dropped() -> None:
    # 短纯字母混合大小写（deviceToken 类，<16）→ 不够熵，仍 drop。
    assert not looks_like_secret_value("deviceToken", _RULES)
    assert not looks_like_secret_value("getUserProfile", _RULES)


# --- 真凭据形态仍命中 --------------------------------------------------------


def test_classic_keyish_secrets_kept() -> None:
    for v in ("Abc123Xyz789Def456", "xML3o7rBgL6naCbxeYS9m8", "5f0a1b2c3d4e", "100215079"):
        assert looks_like_secret_value(v, _RULES), v


# --- 规则缺失走兜底（离线不崩） ----------------------------------------------


def test_fallback_rules_have_alpha_threshold() -> None:
    # 默认 SecretRules 含纯字母阈值（评审 MEDIUM 新增字段，缺失走兜底）。
    r = SecretRules()
    assert r.min_alpha_secret_len >= 12
