"""高敏值脱敏（隐私安全）。

fxapk 会提取受害人 PII / 钱包私钥助记词 / 后端凭据 / 运行时登录态等**高敏物证**。digest **默认明文**
（取证查看需要看到实际值）；仅当 `fxapk digest --redact`（如要把摘要喂可能经云端模型处理的 agent）时
才对高敏类 value 脱敏，明文始终在本地完整 report.json 里。脱敏后 agent 仍能看到「存在哪类高敏线索
+ 调证去向」，需要明文时读本地完整报告。
"""

from __future__ import annotations

#: 高敏类别：其 value 在 agent 摘要里默认脱敏（明文只留本地完整报告）。
#: ★ 须与 models.LeadCategory 的高敏类目**同步维护**：新增「可直接控资金 / 登录 / 含受害人 PII /
#: 可解全部流量」的类别时务必加进来，否则会绕过 digest 脱敏。
SENSITIVE_CATEGORIES = frozenset(
    {
        "WALLET_SECRET",  # 钱包私钥 / 助记词
        "BACKEND_CREDENTIAL",  # 后端 / 管理凭据
        "RUNTIME_CREDENTIAL",  # 运行时登录态 / 凭据
        "VICTIM_DATA",  # 受害人物证（PII）
        "CRYPTO_RECIPE",  # 应用层加密配方（含 key/iv，凭此可解全部加密流量）
    }
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
    """高敏类别的 value → 脱敏；其余原样返回。

    非字符串高敏 value（如携带 key/iv 的 dict/list、数字）先 str() 再脱敏——否则会绕过
    脱敏把明文带进可能经云端模型处理的 agent 上下文。value 为 None 时原样放行（非敏感物证）。
    """
    if str(category or "") in SENSITIVE_CATEGORIES and value is not None:
        return mask(value if isinstance(value, str) else str(value))
    return value
