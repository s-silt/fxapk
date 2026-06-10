"""sensitive_api 分析器：扫 DEX 里**实际调用**的敏感 API → Finding（数据窃取/拦截/指纹）。

与 permissions 分析器互补（声明 vs 实调）：
  - permissions 只读 manifest 声明的权限（"申请了什么"）；
  - 本分析器扫 DEX 字符串里的敏感 **方法引用**（"代码里真碰了什么"）——
    IMEI/IMSI/SIM/手机号、短信发送、通讯录、定位、剪贴板、安装来源/已装应用枚举、
    Android ID/MAC 等。二者交叉（声明却没实调、实调却没声明）在报告层供研判。

反诈意义：这些 API 是设备指纹、短信验证码窃取/拦截转发、通讯录批量上传、剪贴板
（钱包地址/口令）窃取的代码落点，是「非法获取公民个人信息 / 帮信」的直接技术佐证。

约束（与 permissions/sdk_fingerprint 一致）：
  - 只依赖 AnalysisContext 公开接口（dex_strings），禁止 import androguard。
  - 规则数据化（apkscan/rules/sensitive_api.yaml + load_rules）。
  - 误报收敛：方法名 token 命中后，若规则带 require_class（类名片段），未同时命中类名则
    **降一级 severity** 并在 description 标注「未确认调用点（可能为同名字符串/日志）」，
    宁可降级也不漏报真调用。规则可用 ``require_all``（多 token 全命中才触发）进一步收窄
    高频弱信号（如 android_id 须与 getString 共现）。
  - 单点解析异常 try/except + logging，不静默 pass、不炸 analyze。
  - 全程 type hints。

require_class 语义说明（重要，避免误判 severity 可信度）：
  ``ctx.dex_strings()`` 暴露的是 DEX **字符串池**（方法名串、类描述符串、内联常量各自独立），
  **不含 method→class 绑定**。故 require_class 命中只证明「该框架类描述符在 DEX 里被引用」
  （提高这是真实调用的可能性），**不等于「该方法确实调在该类上」**——大型 app 里
  TelephonyManager 等框架类几乎必然在场。真正的调用点确认需 jadx 反编译或运行时 hook。
  本分析器据此把「类在场」作为升信号/不降级的依据，研判时仍应以 jadx/runtime 为准。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apkscan.analyzers._common import as_str_list as _as_str_list
from apkscan.analyzers._common import collect_dex_strings as _collect_dex_strings
from apkscan.analyzers._common import str_or_empty as _str_or_empty
from apkscan.core.models import AnalyzerResult, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "sensitive_api"

# DEX 字符串扫描上限（与 sdk_fingerprint 同口径）。
_MAX_DEX_STRINGS = 200_000

# severity 降级阶梯（require_class 未命中时降一级，避免同名字符串误报当实调）。
_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}

_SEVERITY_BY_NAME = {s.name: s for s in Severity}


def _severity_from(value: Any, fallback: Severity) -> Severity:
    name = str(value).strip().upper()
    return _SEVERITY_BY_NAME.get(name, fallback)


def _is_ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _token_match(token: str, s: str) -> bool:
    """token 是否在 s 里按标识符边界出现（前后字符非 [A-Za-z0-9_]）。

    避免 ``getDeviceId`` 误命中 ``getDeviceIdentifier``，同时仍命中方法签名/裸方法名
    （``->getDeviceId()V``、独立 ``getDeviceId``）。token 自身含非标识符字符（如
    ``content://...``、``Landroid/telephony``）时边界判定天然成立。
    """
    n = len(token)
    if not n:
        return False
    start = 0
    while True:
        idx = s.find(token, start)
        if idx < 0:
            return False
        before = s[idx - 1] if idx > 0 else ""
        after = s[idx + n] if idx + n < len(s) else ""
        if not _is_ident_char(before) and not _is_ident_char(after):
            return True
        start = idx + 1


@dataclass
class _ApiRule:
    """单条敏感 API 规则（从 YAML 规整而来）。"""

    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    dex_tokens: list[str] = field(default_factory=list)  # 方法名片段（任一命中即触发）
    require_all: list[str] = field(default_factory=list)  # 全部命中才触发（收窄高频弱信号）
    require_class: list[str] = field(default_factory=list)  # 类名片段（命中则升信号/不降级）
    description: str = ""
    recommendation: str = ""
    evidence_to_obtain: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class SensitiveApiAnalyzer(BaseAnalyzer):
    """扫 DEX 里实际调用的敏感 API，产出 category=\"sensitive_api\" 的 Finding。"""

    name: str = "sensitive_api"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        if not rules:
            logger.info("[%s] 无可用敏感 API 规则，跳过", self.name)
            result.meta["sensitive_apis"] = []
            return result

        dex_ok, dex_strings = _collect_dex_strings(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS
        )
        result.meta["dex_scanned"] = dex_ok

        matched: list[str] = []
        for rule in rules:
            try:
                finding = self._match_rule(rule, dex_strings)
            except Exception:  # noqa: BLE001 — 单条规则失败不影响其余
                logger.exception("[%s] 规则匹配失败，跳过：%s", self.name, rule.id)
                continue
            if finding is not None:
                result.findings.append(finding)
                matched.append(rule.id)

        result.meta["sensitive_apis"] = matched
        result.meta["sensitive_api_count"] = len(matched)
        if matched:
            logger.info("[%s] 命中敏感 API %d 项：%s", self.name, len(matched), "、".join(matched))
        return result

    # ------------------------------------------------------------------
    # 单规则匹配
    # ------------------------------------------------------------------

    def _match_rule(self, rule: _ApiRule, dex_strings: list[str]) -> Finding | None:
        """命中 → Finding；require_class 未命中则降级 + 标注未确认调用点。

        触发条件：带 ``require_all`` 时须**全部**命中（收窄高频弱信号）；否则任一
        ``dex_tokens`` 命中即可。
        """
        if rule.require_all:
            if not all(self._token_present(t, dex_strings) for t in rule.require_all):
                return None
            hit_token = rule.require_all[0]
        else:
            hit_token = self._first_hit(rule.dex_tokens, dex_strings)
            if hit_token is None:
                return None

        class_confirmed = True
        if rule.require_class:
            class_confirmed = self._first_hit(rule.require_class, dex_strings) is not None

        severity = rule.severity if class_confirmed else _DOWNGRADE[rule.severity]
        description = rule.description
        if rule.evidence_to_obtain:
            bullets = "\n".join(f"  - {item}" for item in rule.evidence_to_obtain)
            description = f"{description}\n\n可调取证据：\n{bullets}".strip()
        if not class_confirmed:
            description = (
                f"{description}\n\n注意：仅命中方法名 token「{hit_token}」，未在 DEX 中确认其调用类"
                f"（{'/'.join(rule.require_class)}）——可能为同名字符串/日志，已降级，建议 jadx/runtime 复核。"
            ).strip()

        evidences = [
            Evidence(source="dex", location=hit_token, snippet=f"dex token：{hit_token}")
        ]
        return Finding(
            id=rule.id,
            title=rule.title,
            severity=severity,
            category="sensitive_api",
            description=description,
            recommendation=rule.recommendation,
            evidences=evidences,
            references=list(rule.references),
        )

    @staticmethod
    def _token_present(token: str, dex_strings: list[str]) -> bool:
        """token 是否按标识符边界出现在任一 DEX 字符串里。"""
        if not token:
            return False
        return any(_token_match(token, s) for s in dex_strings)

    @classmethod
    def _first_hit(cls, tokens: list[str], dex_strings: list[str]) -> str | None:
        """返回首个在任一 DEX 字符串里**按标识符边界**出现的 token；无 → None。

        词边界（token 前后非 [A-Za-z0-9_]）收敛误报：``getDeviceId`` 不再误命中
        ``getDeviceIdentifier``，但仍命中 ``...->getDeviceId()V`` / 裸方法名等真实形态。
        """
        for tok in tokens:
            if cls._token_present(tok, dex_strings):
                return tok
        return None

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> list[_ApiRule]:
        data = load_rules(_RULES_NAME)
        raw: object
        if isinstance(data, dict):
            raw = data.get("apis", [])
        elif isinstance(data, list):
            raw = data
        else:
            if data:
                logger.warning(
                    "[%s] 规则顶层应为 dict/list，实际 %s；无规则可用",
                    self.name,
                    type(data).__name__,
                )
            raw = []
        return self._parse_rules(raw)

    def _parse_rules(self, raw: object) -> list[_ApiRule]:
        if not isinstance(raw, list):
            logger.warning("[%s] apis 字段应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        rules: list[_ApiRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 规则条目：%r", self.name, entry)
                continue
            api_id = entry.get("id")
            tokens = _as_str_list(entry.get("dex_tokens"))
            require_all = _as_str_list(entry.get("require_all"))
            if not isinstance(api_id, str) or not api_id.strip():
                logger.warning("[%s] 跳过缺 id 的规则条目：%r", self.name, entry)
                continue
            if not tokens and not require_all:
                logger.warning("[%s] 跳过无 dex_tokens/require_all 的规则条目：%s", self.name, api_id)
                continue
            rules.append(
                _ApiRule(
                    id=api_id.strip(),
                    title=_str_or_empty(entry.get("title")) or api_id.strip(),
                    severity=_severity_from(entry.get("severity"), Severity.MEDIUM),
                    dex_tokens=tokens,
                    require_all=require_all,
                    require_class=_as_str_list(entry.get("require_class")),
                    description=_str_or_empty(entry.get("description")),
                    recommendation=_str_or_empty(entry.get("recommendation")),
                    evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                    references=_as_str_list(entry.get("references")),
                )
            )
        return rules
