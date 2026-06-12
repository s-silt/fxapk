"""apkscan.report.letters — 把 report.json 的 leads 套打成「调证函 / 协查文书」草稿。

fxapk 的 Lead 已结构化 subject/where_to_request/evidence_to_obtain/value/source_refs，
离「一步生成可发的协查函草稿」只差一个模板引擎。本模块把可办案化的线索变成结构化文书
草稿（markdown 正文 + 字段 dict），让办案动作（向交易所发函冻结收款地址、向注册商调
WHOIS 实名、向云厂商调租户日志）有现成底稿。

铁律（与 report/ioc.py 一致）：纯函数层**禁** print/typer，对坏输入容错返回空/跳过，
**绝不抛**。唯一打印的地方是 cli 的 letters 命令。

严格过滤（核验明确要求，否则生成荒谬空壳函）——只对满足**全部**条件的 Lead 套打：
  1) advice == "建议调证"（只对建议调证的）；
  2) evidence_to_obtain 非空（没有可调取证据的不发函）；
  3) where_to_request 是**真实受文机关**——跳过含「非调证对象 / 无直接调证对象 /
     解密配方 / 跨样本关联」等标记的 Lead。背景：certificate 的 SIGNING Lead
     （where_to_request="证书指纹用于跨样本关联…无直接调证对象"）和 crypto_recipe 的 Lead
     （"（解密配方，非调证对象）…"）套进受文机关会生成空壳函，必须排除。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from apkscan.core.registry import load_rules

logger = logging.getLogger(__name__)

# 研判建议中代表「应套打调证函」的取值（过滤条件 1）。
_ADVICE_INVESTIGATE = "建议调证"

# where_to_request 命中任一标记即判定为「非真实受文机关」→ 跳过（过滤条件 3）。
# 这些是分析器对「无直接调证对象」类 Lead 的占位文案，套进受文机关会产生空壳函。
_NON_RECIPIENT_MARKERS: tuple[str, ...] = (
    "非调证对象",
    "无直接调证对象",
    "解密配方",
    "跨样本关联",
)

# 模板 YAML 名（apkscan/rules/letter_templates.yaml）。
_TEMPLATES_NAME = "letter_templates"

# 缺模板时的通用兜底键。
_DEFAULT_TEMPLATE_KEY = "_default"

# 文书顶部固定免责声明（法律措辞克制，不替办案单位下定性结论）。
DISCLAIMER: str = (
    "**本文书为线索建议草稿，需办案单位审核、依法定程序签发；"
    "受文机关为据线索推导的候选、非武断认定。**"
)

# 文件名安全化：去掉文件系统非法字符 + 控制字符。
_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')


def _str_or_empty(value: Any) -> str:
    """把字段值转成字符串；None / 缺失 → 空串。"""
    if value is None:
        return ""
    return str(value)


def _str_list(value: Any) -> list[str]:
    """把字段规整为非空 str 列表（容忍 None / 非 list / 含非 str / 空白元素）。"""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif item is not None and not isinstance(item, str):
            # 非 str（如数字）也尽力字符串化，避免丢证据项。
            text = str(item).strip()
            if text:
                out.append(text)
    return out


def _is_non_recipient(where_to_request: str) -> bool:
    """where_to_request 是否为「非真实受文机关」占位文案（命中任一标记即 True）。"""
    return any(marker in where_to_request for marker in _NON_RECIPIENT_MARKERS)


def _is_actionable(lead: dict[str, Any]) -> bool:
    """该 Lead 是否可办案化（满足全部 3 个套打条件）。"""
    if lead.get("advice") != _ADVICE_INVESTIGATE:
        return False  # 条件 1：只对建议调证的
    if not _str_list(lead.get("evidence_to_obtain")):
        return False  # 条件 2：必须有可调取证据
    recipient = _str_or_empty(lead.get("where_to_request")).strip()
    if not recipient:
        return False  # 无受文机关
    if _is_non_recipient(recipient):
        return False  # 条件 3：跳过非真实受文机关占位文案
    return True


def _evidence_refs(lead: dict[str, Any]) -> list[str]:
    """从 source_refs 取每条 Evidence 的 evidence_id；无则降级为 source:location。

    report.json 的 Evidence 已带 evidence_id（report/json.py 注入）。坏形状容错跳过。
    """
    refs = lead.get("source_refs")
    if not isinstance(refs, list):
        return []
    out: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        eid = ref.get("evidence_id")
        if isinstance(eid, str) and eid.strip():
            out.append(eid.strip())
            continue
        # 降级：source:location（与 ioc._first_source 同构）。
        source = _str_or_empty(ref.get("source"))
        location = _str_or_empty(ref.get("location"))
        if source or location:
            out.append(f"{source}:{location}")
    return out


def _load_templates() -> dict[str, dict[str, str]]:
    """读取 letter_templates.yaml，规整为 {category: {field: text}}；坏形状返回空 dict。"""
    data = load_rules(_TEMPLATES_NAME)
    if not isinstance(data, dict):
        logger.warning("letter_templates 顶层应为 dict，实际 %s；走通用兜底", type(data).__name__)
        return {}
    out: dict[str, dict[str, str]] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        tmpl: dict[str, str] = {}
        for fk, fv in value.items():
            if isinstance(fk, str) and isinstance(fv, str):
                tmpl[fk] = fv
        out[key] = tmpl
    return out


def _template_for(category: str, templates: dict[str, dict[str, str]]) -> dict[str, str]:
    """取 category 模板；缺则走 _default 兜底；再缺则硬编码通用兜底，绝不崩。"""
    tmpl = templates.get(category) or templates.get(_DEFAULT_TEMPLATE_KEY)
    if tmpl:
        return tmpl
    return {
        "title": "协查函",
        "recipient_hint": "受文机关为据线索推导的候选机构",
        "target_desc": "涉案样本中提取的调证标的",
        "evidence_lead_in": "建议依法调取以下材料：",
    }


def _build_body_md(
    *,
    template: dict[str, str],
    recipient: str,
    target: str,
    subject: str,
    evidence_items: list[str],
    evidence_refs: list[str],
) -> str:
    """套打 markdown 正文：顶部固定免责声明 → 受文机关 → 标的 → 待调取证据 → 出处。"""
    title = template.get("title", "协查函")
    recipient_hint = template.get("recipient_hint", "")
    target_desc = template.get("target_desc", "")
    evidence_lead_in = template.get("evidence_lead_in", "建议依法调取以下材料：")

    lines: list[str] = []
    # 1) 顶部显著免责（固定，最先出现）
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    # 2) 标题
    lines.append(f"# {title}（标的：{target}）")
    lines.append("")
    # 3) 受文机关
    lines.append(f"**受文机关（候选）：** {recipient}")
    if recipient_hint:
        lines.append("")
        lines.append(recipient_hint)
    lines.append("")
    # 4) 标的归属
    if subject:
        lines.append(f"**标的归属（待核）：** {subject}")
        lines.append("")
    lines.append(f"**调证标的：** {target}")
    if target_desc:
        lines.append("")
        lines.append(target_desc)
    lines.append("")
    # 5) 待调取证据清单
    lines.append(f"## 拟调取证据\n\n{evidence_lead_in}")
    lines.append("")
    for item in evidence_items:
        lines.append(f"- {item}")
    lines.append("")
    # 6) 证据出处（可回溯锚点）
    if evidence_refs:
        lines.append("## 证据出处（样本内锚点）")
        lines.append("")
        for ref in evidence_refs:
            lines.append(f"- `{ref}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _lead_to_letter(
    lead: dict[str, Any], templates: dict[str, dict[str, str]]
) -> dict[str, Any]:
    """把单条可办案化 Lead 套打成文书 dict（字段见模块 docstring）。"""
    category = _str_or_empty(lead.get("category"))
    recipient = _str_or_empty(lead.get("where_to_request")).strip()
    target = _str_or_empty(lead.get("value"))
    subject = _str_or_empty(lead.get("subject"))
    evidence_items = _str_list(lead.get("evidence_to_obtain"))
    evidence_refs = _evidence_refs(lead)
    template = _template_for(category, templates)

    body_md = _build_body_md(
        template=template,
        recipient=recipient,
        target=target,
        subject=subject,
        evidence_items=evidence_items,
        evidence_refs=evidence_refs,
    )
    return {
        "category": category,
        "subject": subject,  # 标的归属（公司/人）
        "recipient": recipient,  # 受文机关（取自 where_to_request）
        "target": target,  # 标的 = Lead.value
        "evidence_items": evidence_items,  # = evidence_to_obtain
        "evidence_refs": evidence_refs,  # evidence_id 优先、降级 source:location
        "title": f"{template.get('title', '协查函')}（标的：{target}）",
        "body_md": body_md,
    }


def build_letters(report: dict[str, Any]) -> list[dict[str, Any]]:
    """遍历 report 的 leads，对可办案化的 Lead 生成文书草稿 dict 列表。

    Args:
        report: report.json 解析出的 dict。坏输入（非 dict、缺 leads、leads 非 list、
            元素非 dict）一律容错——返回空列表或跳过坏元素，绝不抛。

    Returns:
        文书 dict 列表（字段见模块 docstring）；无可办案化 Lead → 空列表。
    """
    if not isinstance(report, dict):
        return []
    leads = report.get("leads")
    if not isinstance(leads, list):
        return []

    templates = _load_templates()
    out: list[dict[str, Any]] = []
    for lead in leads:
        if not isinstance(lead, dict):
            continue  # 脏数据跳过，不抛
        if not _is_actionable(lead):
            continue  # 严格过滤：不可办案化的不套打
        try:
            out.append(_lead_to_letter(lead, templates))
        except Exception:  # 单条套打异常不应炸掉整体；记录后跳过。
            logger.exception("套打单条文书失败：value=%r", lead.get("value"))
    return out


def _safe_filename(value: str, *, fallback: str = "letter") -> str:
    """把标的值清成安全文件名片段（去非法字符、压空白、截断、空则兜底）。"""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", value)
    cleaned = re.sub(r"\s+", "_", cleaned).strip("_. ")
    if len(cleaned) > 60:
        cleaned = cleaned[:60].rstrip("_. ")
    return cleaned or fallback


def write_letters(letters: list[dict[str, Any]], out_dir: str) -> list[str]:
    """把文书写到 <out_dir>/letters/ 下，每份一个 md，再写 index.md 索引。

    文件名：<category>_<value安全名>.md（同名追加序号去重）。编码 UTF-8。
    即使 letters 为空也写一个 index.md（稳定输出）。返回写出的路径列表（含 index.md）。
    """
    base = Path(out_dir) / "letters"
    base.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    index_lines: list[str] = [
        f"> {DISCLAIMER}",
        "",
        "# 调证 / 协查文书索引",
        "",
        f"共 {len(letters)} 份文书草稿。",
        "",
    ]

    used_names: set[str] = set()
    for letter in letters:
        category = _safe_filename(_str_or_empty(letter.get("category")), fallback="LEAD")
        target = _str_or_empty(letter.get("target"))
        stem = f"{category}_{_safe_filename(target)}"
        # 同名去重：追加 -2 / -3…
        name = stem
        seq = 1
        while name in used_names:
            seq += 1
            name = f"{stem}-{seq}"
        used_names.add(name)

        filename = f"{name}.md"
        file_path = base / filename
        body = _str_or_empty(letter.get("body_md"))
        try:
            file_path.write_text(body, encoding="utf-8")
        except OSError:
            logger.exception("写出文书失败：%s", file_path)
            continue
        written.append(str(file_path))

        recipient = _str_or_empty(letter.get("recipient"))
        index_lines.append(f"- [{target}]({filename}) — 受文机关（候选）：{recipient}")

    if not letters:
        index_lines.append("（本样本无可套打的调证线索。）")
    index_lines.append("")

    index_path = base / "index.md"
    index_path.write_text("\n".join(index_lines).rstrip() + "\n", encoding="utf-8")
    written.append(str(index_path))
    return written
