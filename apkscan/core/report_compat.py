"""报告分析修订兼容检查：只比较复现坐标，返回非阻断提示。"""

from __future__ import annotations

from collections.abc import Mapping


class _Auto:
    """调用方未注入当前值时使用运行环境探测。"""


_AUTO = _Auto()


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _short(value: str) -> str:
    return value[:12] if len(value) > 12 else value


def _ruleset_text(value: object) -> str:
    """规则加载失败的公共哨兵不是可比较摘要。"""
    text = _text(value)
    return "" if text.casefold() == "unknown" else text


def report_revision_warnings(
    meta: Mapping[str, object] | object,
    *,
    current_version: str | None = None,
    current_build_commit: str | None | _Auto = _AUTO,
    current_ruleset_digest: str | None | _Auto = _AUTO,
) -> list[str]:
    """比较报告与当前 fxapk 的复现坐标；一致返回空列表，不一致返回一条安全提示。"""
    report_meta = _mapping(meta)
    manifest = _mapping(report_meta.get("evidence_manifest"))

    if current_version is None:
        from apkscan import __version__

        current_version = __version__
    if isinstance(current_build_commit, _Auto):
        from apkscan.core.integrity import current_build_provenance

        current_build_commit = _text(current_build_provenance().get("build_commit")) or None
    if isinstance(current_ruleset_digest, _Auto):
        from apkscan.core.registry import ruleset_digest

        current_ruleset_digest = _ruleset_text(ruleset_digest()) or None

    report_version = _text(report_meta.get("tool_version")) or _text(
        manifest.get("tool_version")
    )
    report_commit = _text(manifest.get("build_commit"))
    report_rules = _ruleset_text(report_meta.get("ruleset_digest"))
    current_version_text = _text(current_version)
    current_commit_text = _text(current_build_commit)
    current_rules_text = _ruleset_text(current_ruleset_digest)

    differences: list[str] = []
    if not report_version:
        differences.append("未记录工具版本")
    elif current_version_text and report_version != current_version_text:
        differences.append(f"工具版本 {_short(report_version)} → {_short(current_version_text)}")
    if report_commit and current_commit_text and report_commit != current_commit_text:
        differences.append(f"代码修订 {_short(report_commit)} → {_short(current_commit_text)}")
    if report_rules and current_rules_text and report_rules != current_rules_text:
        differences.append(f"规则摘要 {_short(report_rules)} → {_short(current_rules_text)}")

    if not differences:
        return []
    detail = "；".join(differences)
    return [
        "警告：本报告的分析修订与当前 fxapk 不一致"
        f"（{detail}）。判据可能已变化，请用原始检材重新分析后再下结论。"
    ]


__all__ = ["report_revision_warnings"]
