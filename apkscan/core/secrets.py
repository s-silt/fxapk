"""硬编码密钥"值形态判定"共享逻辑（C2 降噪）——jadx / js_bundle / config_keys 共读。

核心问题：jadx / 部分分析器把 SDK 常量名当密钥误报（MIPUSH_APPKEY=MIPUSH_APPKEY、
KEY_DEVICE_TOKEN=deviceToken、METHOD_CHECK_APPKEY=dc_checkappkey 全是 HIGH 误报）。

本模块把"value 是否像真实凭据"的判定收敛成单一权威实现，三处分析器共用，
规则数据放 rules/secrets.yaml（缺失走内置兜底，离线/规则缺失不崩）：
- value == key（去大小写/去引号）→ 不是凭据（常量名自映射）。
- value ∈ sdk_constant_values（或 value 本身就是某 SDK 常量键名）→ 已知 SDK 常量，非凭据。
  ★只看 value 形态，不按 key 名一票否决：真 App 常把真凭据放在标准键名
   （MIPUSH_APPKEY 等）下，按键名短路会误吞真凭据（评审 HIGH 修复）。
- value 不像凭据形态（textutil.looks_keyish=False）→ 非凭据。
- value 去重字符数 < min_distinct_chars / 长度 < min_secret_len → 非凭据。

铁律：只杀误报、不误杀真凭据。真凭据（Abc123Xyz789Def456 / xML3o7rBgL6naCbxeYS9m8 /
100215079 / GUID / 5f0a1b2c3d4e）全部 looks_keyish=True、value!=key、不在常量名表。

约束：纯函数 + 一次性规则加载，无 androguard 依赖，全程 type hints。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from apkscan.core.registry import load_rules
from apkscan.core.textutil import as_str_list as _as_str_list
from apkscan.core.textutil import looks_keyish as _looks_keyish

logger = logging.getLogger(__name__)

_RULES_NAME = "secrets"

# 内置兜底（规则文件缺失时使用，保证离线/规则缺失行为可控）。
_FALLBACK_SDK_CONSTANT_KEYS: frozenset[str] = frozenset(
    {
        "mipush_appid",
        "mipush_appkey",
        "oppopush_appkey",
        "oppopush_appsecret",
        "vivopush_appkey",
        "hms_appid",
        "key_device_token",
        "method_check_appkey",
        "meizu_appkey",
        "honor_appid",
    }
)
_FALLBACK_SDK_CONSTANT_VALUES: frozenset[str] = frozenset(
    {
        "devicetoken",
        "dc_checkappkey",
        "mipush_appkey",
        "oppopush_appkey",
        "key_device_token",
        "method_check_appkey",
    }
)
_FALLBACK_MIN_SECRET_LEN = 8
_FALLBACK_MIN_DISTINCT_CHARS = 4
# 纯字母（无数字/非 hex/无 base64 字符）但够长且大小写混合时，视为有熵的可疑凭据
# 而非一票否决（评审 MEDIUM 修复：纯字母真 AppSecret 不应被 looks_keyish=False 误杀）。
# 阈值取保守的 16：足以放过 deviceToken(11)/getUserProfile(14) 等普通标识符。
_FALLBACK_MIN_ALPHA_SECRET_LEN = 16


@dataclass(frozen=True)
class SecretRules:
    """密钥检测白名单 / 形态门槛（从 rules/secrets.yaml 规整，缺失走兜底）。"""

    sdk_constant_keys: frozenset[str] = field(default_factory=frozenset)
    sdk_constant_values: frozenset[str] = field(default_factory=frozenset)
    min_secret_len: int = _FALLBACK_MIN_SECRET_LEN
    min_distinct_chars: int = _FALLBACK_MIN_DISTINCT_CHARS
    min_alpha_secret_len: int = _FALLBACK_MIN_ALPHA_SECRET_LEN


def load_secret_rules() -> SecretRules:
    """读取 rules/secrets.yaml 并规整为 SecretRules；任何缺失/异常走内置兜底。"""
    keys: frozenset[str] = _FALLBACK_SDK_CONSTANT_KEYS
    values: frozenset[str] = _FALLBACK_SDK_CONSTANT_VALUES
    min_len = _FALLBACK_MIN_SECRET_LEN
    min_distinct = _FALLBACK_MIN_DISTINCT_CHARS
    min_alpha_len = _FALLBACK_MIN_ALPHA_SECRET_LEN

    data = load_rules(_RULES_NAME)
    if isinstance(data, dict):
        k = _as_str_list(data.get("sdk_constant_keys"))
        if k:
            keys = frozenset(s.lower() for s in k)
        v = _as_str_list(data.get("sdk_constant_values"))
        if v:
            values = frozenset(s.lower() for s in v)
        ml = data.get("min_secret_len")
        if isinstance(ml, int) and ml > 0:
            min_len = ml
        md = data.get("min_distinct_chars")
        if isinstance(md, int) and md > 0:
            min_distinct = md
        mal = data.get("min_alpha_secret_len")
        if isinstance(mal, int) and mal > 0:
            min_alpha_len = mal
    elif data:
        logger.warning("secrets 规则顶层应为 dict，实际 %s；使用内置兜底", type(data).__name__)

    return SecretRules(
        sdk_constant_keys=keys,
        sdk_constant_values=values,
        min_secret_len=min_len,
        min_distinct_chars=min_distinct,
        min_alpha_secret_len=min_alpha_len,
    )


def _strip_quotes(s: str) -> str:
    """去掉值两端成对引号（jadx 抽出的常量名有时带引号）。"""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1].strip()
    return s


def is_sdk_constant(key: str, value: str, rules: SecretRules) -> bool:
    """key/value 是否命中已知 SDK 常量白名单（value==key、或值在常量表）。

    覆盖 C2 误报：MIPUSH_APPKEY=MIPUSH_APPKEY（value==key）、KEY_DEVICE_TOKEN=deviceToken
    （value∈sdk_constant_values）、METHOD_CHECK_APPKEY=dc_checkappkey（value∈表）。

    no-false-kill（评审 HIGH 修复）：**只看 value 形态，不按键名一票否决**。
    `sdk_constant_keys`（mipush_appkey 等）恰是真实 App 配真凭据时用的标准键名——
    若按键名短路，会把 `MIPUSH_APPKEY=5621543878901`（真小米 appkey）当常量误吞。
    原"键名白名单"对 C2 已知误报（MIPUSH_APPKEY=MIPUSH_APPKEY /
    KEY_DEVICE_TOKEN=deviceToken / METHOD_CHECK_APPKEY=dc_checkappkey）是冗余的：
    它们已被 value==key 与 sdk_constant_values 覆盖。键名仅在 value **本身就是**
    常量名/占位形态时才参与判定（看值，不看键），从而保留真凭据值。
    """
    k = _strip_quotes(key).lower()
    v = _strip_quotes(value).lower()
    if not v:
        return True
    if v == k:  # 常量名自映射（MIPUSH_APPKEY=MIPUSH_APPKEY），非真实凭据。
        return True
    if v in rules.sdk_constant_values:
        return True
    # 键名表只用于：value 自身就长得像"另一个 SDK 常量键名"（如 X_APPKEY=mipush_appkey）。
    # 仍是看 value（v ∈ sdk_constant_keys），绝不按 key 名（k ∈ sdk_constant_keys）短路。
    if v in rules.sdk_constant_keys:
        return True
    return False


def _looks_like_alpha_secret(v: str, min_alpha_len: int) -> bool:
    """纯字母值是否有足够熵像凭据：够长 + 大小写混合（评审 MEDIUM 修复）。

    `looks_keyish` 对纯字母（无数字/非 hex/无 base64 字符）返回 False，会误杀纯字母
    真 AppSecret（aBcdEfGhiJkLmnOp 等）。这里对"够长且大小写混合"的纯字母值给保留，
    不一票否决。阈值保守（默认 16），放过 deviceToken(11)/getUserProfile(14) 等普通标识符。
    纯字母全小写 / 全大写（无大小写熵，多为单词或宏名）仍返回 False。
    """
    if len(v) < min_alpha_len:
        return False
    if not v.isalpha():
        return False
    has_lower = any(c.islower() for c in v)
    has_upper = any(c.isupper() for c in v)
    return has_lower and has_upper


def looks_like_secret_value(value: str, rules: SecretRules) -> bool:
    """value 是否像真实凭据形态（长度 / 多样性 / looks_keyish / 长纯字母混合熵）。

    不像凭据（如 deviceToken / dc_checkappkey / MIPUSH_APPKEY —— 无数字、非 hex、
    无 base64 字符且不够长）→ False。真凭据（Abc123Xyz789Def456 / 长纯字母混合大小写
    的 AppSecret）→ True。
    """
    v = _strip_quotes(value)
    if len(v) < rules.min_secret_len:
        return False
    if len(set(v)) < rules.min_distinct_chars:
        return False
    if _looks_keyish(v):
        return True
    # looks_keyish=False 但是够长的大小写混合纯字母值 → 有熵，保留（不误杀纯字母真 secret）。
    return _looks_like_alpha_secret(v, rules.min_alpha_secret_len)


def is_real_secret(key: str, value: str, rules: SecretRules) -> bool:
    """综合判定：key=value 是否为真实硬编码凭据（C2 三道闸合一）。

    True 仅当：非 SDK 常量白名单命中（含 value==key）且 value 像真实凭据形态。
    保守：拿不准（looks_keyish=False）一律判 False（只丢 Finding，CONFIG_KEY lead 仍保留 key=value）。
    """
    if is_sdk_constant(key, value, rules):
        return False
    return looks_like_secret_value(value, rules)
