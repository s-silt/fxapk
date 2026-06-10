"""证书分析器 — 签名证书 → 调证线索 + 调试/可疑证书发现。

职责（见设计文档 §4 certificate 行）：
- 用 ctx.certificates() 拿 CertInfo 列表。
- 每张证书 → Lead(category=SIGNING)：证书指纹用于跨样本关联同一开发者，
  无直接调证对象（指纹本身不归属某家厂商），但相同指纹的其他涉诈 App 是可调取证据。
- 调试证书（is_debug 或 issuer/subject 含 "Android Debug" 等特征）→ Finding(HIGH)：
  正规上架应用不会用 debug.keystore 签名，涉诈批量打包样本常残留。
- 可疑/弱证书特征（占位主体、空身份字段、二次打包工具）→ Finding(MEDIUM/INFO)。

约束：
- 只依赖 AnalysisContext 公开接口（这里只用 certificates()），禁止 import androguard。
- 规则从 apkscan/rules/certificate.yaml 经 registry.load_rules 读取。
- 单点解析异常 try/except + logging，不让单张证书炸掉整个 analyze；不静默 pass。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext
    from apkscan.core.models import CertInfo

logger = logging.getLogger(__name__)

_RULES_NAME = "certificate"

# load_rules 找不到文件时的兜底默认值，保证离线/规则缺失仍可识别 debug 证书。
_DEFAULT_DEBUG_ISSUERS: tuple[str, ...] = (
    "Android Debug",
    "CN=Android Debug",
    "O=Android",
)


class CertificateAnalyzer(BaseAnalyzer):
    """从签名证书提取 SIGNING 线索，并对调试/可疑证书产出 Finding。"""

    name: str = "certificate"
    requires: list[str] = ["apk"]  # Android 专属；IPA 上 pipeline 自动 skipped

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        debug_issuers = _as_str_list(rules.get("debug_issuers")) or list(_DEFAULT_DEBUG_ISSUERS)
        debug_subjects = _as_str_list(rules.get("debug_subjects"))
        suspicious_subjects = _as_str_list(rules.get("suspicious_subjects"))
        weak_subjects = _as_str_list(rules.get("weak_subjects"))
        short_validity_days = _as_int(rules.get("short_validity_days"), default=365)

        try:
            certs = ctx.certificates()
        except Exception:  # 上下文取证书失败：记录后整体置错，不抛出
            logger.exception("[%s] 读取证书列表失败", self.name)
            result.error = "读取证书列表失败"
            return result

        if not certs:
            logger.info("[%s] 未发现签名证书", self.name)
            result.meta["cert_count"] = 0
            return result

        result.meta["cert_count"] = len(certs)
        schemes_union: set[str] = set()
        cert_dicts: list[dict] = []

        for idx, cert in enumerate(certs):
            try:
                self._process_cert(
                    cert,
                    idx,
                    result,
                    debug_issuers=debug_issuers,
                    debug_subjects=debug_subjects,
                    suspicious_subjects=suspicious_subjects,
                    weak_subjects=weak_subjects,
                    short_validity_days=short_validity_days,
                )
                for scheme in cert.schemes or []:
                    if isinstance(scheme, str):
                        schemes_union.add(scheme)
                cert_dicts.append(_cert_to_dict(cert))
            except Exception:
                # 单张证书解析失败不应影响其余证书；记录原因，继续。
                logger.exception("[%s] 处理证书失败（index=%s）", self.name, idx)

        result.meta["schemes"] = sorted(schemes_union)
        # 报告概览/附录消费的键：签名主体、签名指纹、证书明细表。
        result.meta["certificates"] = cert_dicts
        if cert_dicts:
            result.meta["sign_subject"] = cert_dicts[0].get("subject") or None
            result.meta["sign_sha256"] = cert_dicts[0].get("sha256") or None
        return result

    # ------------------------------------------------------------------
    # 单张证书处理
    # ------------------------------------------------------------------

    def _process_cert(
        self,
        cert: "CertInfo",
        idx: int,
        result: AnalyzerResult,
        *,
        debug_issuers: list[str],
        debug_subjects: list[str],
        suspicious_subjects: list[str],
        weak_subjects: list[str],
        short_validity_days: int,
    ) -> None:
        subject = (cert.subject or "").strip()
        issuer = (cert.issuer or "").strip()
        sha256 = (cert.sha256 or "").strip()

        cert_ev = Evidence(
            source="cert",
            location=subject or f"cert[{idx}]",
            snippet=f"sha256={sha256}" if sha256 else "",
        )

        # 1) SIGNING 线索：证书指纹 → 跨样本关联同一开发者
        lead = Lead(
            category=LeadCategory.SIGNING,
            value=sha256 or f"cert[{idx}]",
            subject=subject or None,
            where_to_request="证书指纹用于跨样本关联同一开发者；无直接调证对象",
            evidence_to_obtain=["相同签名指纹的其他涉诈App"],
            confidence=Confidence.HIGH,
            source_refs=[cert_ev],
            notes=self._lead_notes(cert, issuer, subject),
        )
        result.leads.append(lead)

        # 2) 调试证书 → Finding(HIGH)
        if self._is_debug_cert(cert, issuer, subject, debug_issuers, debug_subjects):
            result.findings.append(
                Finding(
                    id=f"CERT-DEBUG-{idx}",
                    title="使用调试证书（debug keystore）签名",
                    severity=Severity.HIGH,
                    category="signing",
                    description=(
                        "该 APK 使用 Android SDK 自带的调试证书（Android Debug）签名。"
                        "正规上架应用应使用开发者正式 release 证书，"
                        "调试签名常见于临时/批量打包的涉诈或测试样本，"
                        f"表明非正规渠道发布。subject={subject!r} issuer={issuer!r}"
                    ),
                    recommendation=(
                        "结合分发渠道核实是否为非官方/灰产打包；"
                        "以该指纹检索是否存在相同调试证书签名的其他涉诈样本。"
                    ),
                    evidences=[cert_ev],
                    references=[
                        "https://developer.android.com/studio/publish/app-signing",
                    ],
                )
            )

        # 3) 可疑占位主体 → Finding(MEDIUM)
        matched_suspicious = _first_match(subject, suspicious_subjects) or _first_match(
            issuer, suspicious_subjects
        )
        if matched_suspicious is not None:
            result.findings.append(
                Finding(
                    id=f"CERT-SUSPICIOUS-{idx}",
                    title="签名证书主体可疑（占位 / 二次打包特征）",
                    severity=Severity.MEDIUM,
                    category="signing",
                    description=(
                        "证书主体或签发者命中可疑特征 "
                        f"{matched_suspicious!r}（占位 DN / 测试 / 二次打包工具痕迹），"
                        f"subject={subject!r} issuer={issuer!r}。"
                        "此类证书在批量灰产打包样本中高频出现，建议人工复核。"
                    ),
                    recommendation="人工核实证书主体真实性，并以指纹聚类同源样本。",
                    evidences=[cert_ev],
                )
            )

        # 4) 弱身份字段（关键字段缺失）→ Finding(INFO)
        matched_weak = _first_match(subject, weak_subjects)
        if matched_weak is not None:
            result.findings.append(
                Finding(
                    id=f"CERT-WEAK-{idx}",
                    title="签名证书身份信息缺失",
                    severity=Severity.INFO,
                    category="signing",
                    description=(
                        f"证书主体关键身份字段缺失（命中 {matched_weak!r}），"
                        f"subject={subject!r}，难以据此直接定位真实主体，需人工核实。"
                    ),
                    recommendation="结合 ICP/应用商店发布信息人工核实开发者主体。",
                    evidences=[cert_ev],
                )
            )

        # 5) 短有效期 → Finding(INFO)
        validity_days = self._validity_days(cert)
        if validity_days is not None and 0 <= validity_days < short_validity_days:
            result.findings.append(
                Finding(
                    id=f"CERT-SHORTVALID-{idx}",
                    title="签名证书有效期异常短",
                    severity=Severity.INFO,
                    category="signing",
                    description=(
                        f"证书有效期约 {validity_days} 天（阈值 {short_validity_days} 天），"
                        f"not_before={cert.not_before!r} not_after={cert.not_after!r}。"
                        "正规发布证书通常有效期很长（数十年），过短有效期偏离常态。"
                    ),
                    recommendation="结合其他特征综合研判是否为临时/一次性打包样本。",
                    evidences=[cert_ev],
                )
            )

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _load_rules(self) -> dict:
        data = load_rules(_RULES_NAME)
        if isinstance(data, dict):
            return data
        logger.warning("[%s] 规则顶层应为 dict，实际 %s；使用内置默认", self.name, type(data).__name__)
        return {}

    @staticmethod
    def _is_debug_cert(
        cert: "CertInfo",
        issuer: str,
        subject: str,
        debug_issuers: list[str],
        debug_subjects: list[str],
    ) -> bool:
        if getattr(cert, "is_debug", False):
            return True
        if _first_match(issuer, debug_issuers) is not None:
            return True
        if _first_match(subject, debug_subjects) is not None:
            return True
        return False

    @staticmethod
    def _lead_notes(cert: "CertInfo", issuer: str, subject: str) -> str:
        parts: list[str] = []
        if cert.schemes:
            parts.append("签名方案=" + "/".join(str(s) for s in cert.schemes))
        if cert.not_before or cert.not_after:
            parts.append(f"有效期 {cert.not_before or '?'} ~ {cert.not_after or '?'}")
        if issuer and issuer == subject:
            parts.append("自签名（issuer==subject）")
        elif issuer:
            parts.append(f"issuer={issuer}")
        return "；".join(parts)

    @staticmethod
    def _validity_days(cert: "CertInfo") -> int | None:
        nb = _parse_dt(cert.not_before)
        na = _parse_dt(cert.not_after)
        if nb is None or na is None:
            return None
        try:
            return (na - nb).days
        except Exception:
            logger.debug("证书有效期计算失败：%r ~ %r", cert.not_before, cert.not_after, exc_info=True)
            return None


# ---------------------------------------------------------------------------
# 模块级工具函数
# ---------------------------------------------------------------------------


def _cert_to_dict(cert: "CertInfo") -> dict:
    """把 CertInfo 规整成报告附录证书表所需的 dict。"""
    return {
        "subject": (cert.subject or "").strip(),
        "issuer": (cert.issuer or "").strip(),
        "sha256": (cert.sha256 or "").strip(),
        "not_before": cert.not_before or "",
        "not_after": cert.not_after or "",
        "schemes": [s for s in (cert.schemes or []) if isinstance(s, str)],
        "is_debug": bool(getattr(cert, "is_debug", False)),
    }


def _as_str_list(value: object) -> list[str]:
    """把规则字段规整为 str 列表（容忍 None / 非 list / 含非 str 元素）。"""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _as_int(value: object, *, default: int) -> int:
    if isinstance(value, bool):  # bool 是 int 子类，单列排除
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _first_match(text: str, needles: list[str]) -> str | None:
    """返回第一个出现在 text 中的特征子串（大小写不敏感），无则 None。"""
    if not text:
        return None
    haystack = text.lower()
    for needle in needles:
        if needle and needle.lower() in haystack:
            return needle
    return None


_DT_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d",
    "%Y%m%d%H%M%SZ",
)


def _parse_dt(value: str | None) -> datetime | None:
    """尽力解析证书时间字符串；解析不出返回 None（不抛）。"""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    # 优先 ISO 解析（处理带时区/微秒的格式）
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    logger.debug("无法解析证书时间字符串：%r", value)
    return None
