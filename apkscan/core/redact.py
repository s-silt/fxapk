"""高敏值脱敏（隐私安全）。

fxapk 会提取受害人 PII / 钱包私钥助记词 / 后端凭据 / 运行时登录态等**高敏物证**。这些在**本地完整
report.json** 里完整保留（取证需要、本地不外发），但在喂给 AI agent 的**紧凑摘要（digest）**里
**默认脱敏**——避免把可直接控资金 / 登录的明文凭据带进可能经云端模型处理的 agent 上下文。
agent 仍能看到「存在哪类高敏线索 + 调证去向」，需要明文时读本地完整报告。
"""

from __future__ import annotations

#: 高敏类别：其 value 在 agent 摘要里默认脱敏（明文只留本地完整报告）。
SENSITIVE_CATEGORIES = frozenset(
    {"WALLET_SECRET", "BACKEND_CREDENTIAL", "RUNTIME_CREDENTIAL", "VICTIM_DATA"}
)


def mask(value: str) -> str:
    """中间脱敏：保留首尾少量字符与长度信息，不泄露明文。"""
    s = str(value or "")
    if not s:
        return s
    if len(s) <= 8:
        return "***（已脱敏）"
    return f"{s[:3]}***{s[-2:]}（已脱敏，{len(s)} 字符）"


def redact_value(category: object, value: object) -> object:
    """高敏类别的字符串 value → 脱敏；其余原样返回。"""
    if str(category or "") in SENSITIVE_CATEGORIES and isinstance(value, str):
        return mask(value)
    return value
