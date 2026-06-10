"""permissions 分析器：危险权限 → Finding（风险佐证 / 调证意义）。

职责（见设计文档 §3/§4 "permissions" 行）：
  - 用 ctx.permissions() 取声明的权限列表。
  - 对照危险权限规则（apkscan/rules/permissions.yaml），逐条命中产出
    Finding(category="permission")，severity 按敏感度（涉诈核心的短信/通讯录/
    通话记录/录音/安装包/悬浮窗等给 HIGH，并在 description 点明取证意义）。
  - 识别高危权限组合（短信劫持 / 个人信息批量窃取 / 银行木马 overlay）→ 额外 Finding。
  - 统计写入 AnalyzerResult.meta，供报告"技术附录·权限"区使用。

约束：
  - 只依赖 AnalysisContext 公开接口（permissions()），禁止 import androguard。
  - 规则经 registry.load_rules("permissions") 读取。
  - 解析/单条命中异常 try/except + logging，不让单点失败炸掉整个 analyze；不静默 pass。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apkscan.core.models import (
    AnalyzerResult,
    Evidence,
    Finding,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# Android 标准权限的全限定前缀；规则键用短名（去前缀）匹配。
_PERM_PREFIX = "android.permission."

_SEVERITY_BY_NAME = {s.name: s for s in Severity}


def _short_name(permission: str) -> str:
    """把权限全限定名归一为短名（最后一段）。

    "android.permission.READ_SMS" -> "READ_SMS"
    "com.huawei.permission.sec.MDM" -> "MDM"
    无点的裸名原样返回。
    """
    perm = permission.strip()
    if not perm:
        return ""
    return perm.rsplit(".", 1)[-1]


def _severity_from(value: Any, fallback: Severity) -> Severity:
    """把规则里的 severity 字符串解析为 Severity，无法判定回退。"""
    name = str(value).strip().upper()
    return _SEVERITY_BY_NAME.get(name, fallback)


def _as_str_list(value: Any) -> list[str]:
    """把规则字段宽松归一为 list[str]（兼容标量/None/列表）。"""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


class PermissionsAnalyzer(BaseAnalyzer):
    """检测危险权限与高危权限组合，产出 category=\"permission\" 的 Finding。"""

    name = "permissions"
    requires: list[str] = ["apk"]  # Android 专属（权限声明）；IPA 上自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = load_rules("permissions")
        if not isinstance(rules, dict):
            logger.warning(
                "permissions 规则顶层应为 dict，实际 %s；按空规则处理",
                type(rules).__name__,
            )
            rules = {}

        permissions = self._read_permissions(ctx, result)

        # 短名 -> 原始全限定名（取首个），用于命中时回填证据。
        short_to_full: dict[str, str] = {}
        for perm in permissions:
            short = _short_name(perm)
            if short and short not in short_to_full:
                short_to_full[short] = perm
        present_short: set[str] = set(short_to_full)

        dangerous_rules = rules.get("dangerous", {})
        if not isinstance(dangerous_rules, dict):
            logger.warning(
                "permissions 规则 dangerous 段应为 dict，实际 %s；按空处理",
                type(dangerous_rules).__name__,
            )
            dangerous_rules = {}

        matched_short: list[str] = []
        try:
            matched_short = self._emit_dangerous(
                dangerous_rules, short_to_full, result
            )
        except Exception:  # noqa: BLE001 — 单点失败不应炸掉整个 analyze
            logger.exception("permissions 危险权限 Finding 生成失败")
            result.error = "permissions 危险权限 Finding 生成失败（详见日志）"

        try:
            self._emit_combos(rules.get("combos", []), present_short, result)
        except Exception:  # noqa: BLE001
            logger.exception("permissions 权限组合 Finding 生成失败")
            if not result.error:
                result.error = "permissions 权限组合 Finding 生成失败（详见日志）"

        result.meta = {
            "permission_count": len(permissions),
            "permissions": permissions,
            "dangerous_count": len(matched_short),
            "dangerous_matched": matched_short,
        }
        return result

    # ------------------------------------------------------------------
    # 读取权限
    # ------------------------------------------------------------------

    def _read_permissions(
        self, ctx: "AnalysisContext", result: AnalyzerResult
    ) -> list[str]:
        """安全读取 ctx.permissions()；异常记 error，返回空列表，不抛出。"""
        try:
            raw = ctx.permissions()
        except Exception:  # noqa: BLE001
            logger.exception("读取权限列表失败")
            result.error = "读取权限列表失败（详见日志）"
            return []
        out: list[str] = []
        # 按短名去重：android.permission.READ_SMS 与裸 READ_SMS 视为同一权限，
        # 保留首次出现的原始形态（全限定名优先于裸名时取首个）。
        seen_short: set[str] = set()
        for item in raw or []:
            perm = str(item).strip()
            if not perm:
                continue
            short = _short_name(perm)
            if short in seen_short:
                continue
            seen_short.add(short)
            out.append(perm)
        return out

    # ------------------------------------------------------------------
    # 危险权限 Finding
    # ------------------------------------------------------------------

    def _emit_dangerous(
        self,
        dangerous_rules: dict[str, Any],
        short_to_full: dict[str, str],
        result: AnalyzerResult,
    ) -> list[str]:
        """对命中的危险权限逐条产出 Finding，返回命中的短名列表。"""
        matched: list[str] = []
        for short, full in short_to_full.items():
            tpl = dangerous_rules.get(short)
            if not isinstance(tpl, dict):
                continue
            try:
                result.findings.append(self._finding_for(short, full, tpl))
                matched.append(short)
            except Exception:  # noqa: BLE001 — 单条权限失败不影响其余
                logger.exception("生成危险权限 Finding 失败：%s", short)
        return matched

    def _finding_for(
        self, short: str, full: str, tpl: dict[str, Any]
    ) -> Finding:
        """根据规则模板为单个危险权限构造 Finding。"""
        severity = _severity_from(tpl.get("severity"), Severity.MEDIUM)
        description = str(tpl.get("description", "")).strip()

        # 取证意义并入 description 末尾，强化调证可读性。
        evidence_to_obtain = _as_str_list(tpl.get("evidence_to_obtain"))
        if evidence_to_obtain:
            bullets = "\n".join(f"  - {item}" for item in evidence_to_obtain)
            description = f"{description}\n\n可调取证据：\n{bullets}".strip()

        ev = Evidence(
            source="manifest",
            location=f"uses-permission[@android:name=\"{full}\"]",
            snippet=f'<uses-permission android:name="{full}"/>',
        )
        return Finding(
            id=str(tpl.get("id", f"PERM-{short}")),
            title=str(tpl.get("title", short)),
            severity=severity,
            category="permission",
            description=description,
            recommendation=str(tpl.get("recommendation", "")).strip(),
            evidences=[ev],
            references=_as_str_list(tpl.get("references")),
        )

    # ------------------------------------------------------------------
    # 权限组合 Finding
    # ------------------------------------------------------------------

    def _emit_combos(
        self,
        combos: Any,
        present_short: set[str],
        result: AnalyzerResult,
    ) -> None:
        """对完全满足 require 的高危权限组合产出额外 Finding。"""
        if not isinstance(combos, list):
            if combos:
                logger.warning(
                    "permissions 规则 combos 段应为 list，实际 %s；忽略",
                    type(combos).__name__,
                )
            return
        for combo in combos:
            if not isinstance(combo, dict):
                continue
            try:
                self._emit_one_combo(combo, present_short, result)
            except Exception:  # noqa: BLE001 — 单个组合失败不影响其余
                logger.exception("生成权限组合 Finding 失败：%s", combo.get("id"))

    def _emit_one_combo(
        self,
        combo: dict[str, Any],
        present_short: set[str],
        result: AnalyzerResult,
    ) -> None:
        require = _as_str_list(combo.get("require"))
        if not require:
            return
        if not all(req in present_short for req in require):
            return

        severity = _severity_from(combo.get("severity"), Severity.HIGH)
        evidences = [
            Evidence(
                source="manifest",
                location="uses-permission",
                snippet="；".join(require),
            )
        ]
        result.findings.append(
            Finding(
                id=str(combo.get("id", "PERM-COMBO")),
                title=str(combo.get("title", "高危权限组合")),
                severity=severity,
                category="permission",
                description=str(combo.get("description", "")).strip(),
                recommendation=str(combo.get("recommendation", "")).strip(),
                evidences=evidences,
                references=_as_str_list(combo.get("references")),
            )
        )
