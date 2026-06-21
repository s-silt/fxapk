"""暴露面研判（纯函数）：把已采集指纹映射到「暴露的敏感文件/误配」与「技术栈/后台框架」。

★ 定位与边界：本模块是**侦查/取证情报**，不是攻击工具。
- 只做：从 shodan/recon **已采集的指纹**匹配 ``rules/exposure.yaml`` → 产出「暴露了什么 / 是什么栈」+
  取证价值 + 弱点类(CWE) + caveat。**零网络、零 payload、零利用代码**，绝不向目标发起任何动作。
- 不做：per-CVE 的 RCE 利用靶单 / exploit / 自动利用。技术栈只识别 + 给「框架级已知漏洞、须授权人工评估」
  的通用方向，具体利用由授权操作者对单个确认目标自行评估。
- 用途：国外取证「打源站」前，先看**暴露泄露**（/.git /.env 等直达源码/密钥/源站真IP）与**栈/后台指纹**
  （给方向 + 同后台串案），指引授权后人工取证。

匹配：逐字段·小写子串·任一命中即该条命中（与既有 rules 风格一致）。
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from apkscan.core.registry import load_rules

logger = logging.getLogger(__name__)

_RULES_NAME = "exposure"

#: 指纹字段（须与 enrichers 真实输出对齐；规则与主机指纹都按这些键比对）。
_FP_KEYS = (
    "server", "x_powered_by", "title", "product", "cpe", "cookie", "exposed_path", "module",
)

#: 统一 caveat —— 每条研判都带，明确情报性质与不自动利用。
CAVEAT = "情报方向·须授权后人工验证利用·工具不自动执行/不投递 payload"

# 规则只读一次（进程级缓存；YAML 解析失败安全回退空）。
_RULES_LOCK = threading.Lock()
_RULES_CACHE: dict[str, Any] | None = None


def _rules() -> dict[str, Any]:
    global _RULES_CACHE
    with _RULES_LOCK:
        if _RULES_CACHE is None:
            try:
                data = load_rules(_RULES_NAME)
                _RULES_CACHE = data if isinstance(data, dict) else {}
            except Exception:  # noqa: BLE001 — 规则加载失败不得炸主流程
                logger.warning("exposure 规则加载失败，本次按空规则处理", exc_info=True)
                _RULES_CACHE = {}
        return _RULES_CACHE


def _add(fp: dict[str, set[str]], field: str, value: object) -> None:
    if isinstance(value, str) and value.strip():
        fp[field].add(value.strip().lower())


def build_host_fingerprint(shodan: object, recon: object) -> dict[str, set[str]]:
    """把一台主机的 shodan + recon 富化拍平成 8 个小写字符串集合（供规则子串匹配）。坏字段安全跳过。"""
    sh = shodan if isinstance(shodan, dict) else {}
    rc = recon if isinstance(recon, dict) else {}
    fp: dict[str, set[str]] = {k: set() for k in _FP_KEYS}

    for svc in sh.get("services") or []:
        if not isinstance(svc, dict):
            continue
        _add(fp, "product", svc.get("product"))
        _add(fp, "server", svc.get("product"))  # product(如 nginx/Apache) 也作 server 指纹
        _add(fp, "server", svc.get("http_server"))
        _add(fp, "title", svc.get("http_title"))
        _add(fp, "module", svc.get("module"))
        cpe = svc.get("cpe")
        for c in cpe if isinstance(cpe, list) else [cpe]:
            _add(fp, "cpe", c)

    for h in rc.get("http") or []:
        if not isinstance(h, dict):
            continue
        _add(fp, "server", h.get("server"))
        _add(fp, "x_powered_by", h.get("x_powered_by"))
        _add(fp, "title", h.get("title"))
        for c in h.get("cookies") or []:
            _add(fp, "cookie", c)

    for p in rc.get("exposed_paths") or []:
        if not isinstance(p, dict):
            continue
        _add(fp, "exposed_path", p.get("path"))
        _add(fp, "title", p.get("title"))

    return fp


#: cookie 名是离散 token，用**精确**匹配（否则 "sessionid" 会子串误命中 "jsessionid"）。其余字段子串匹配。
_EXACT_MATCH_KEYS = frozenset({"cookie"})


def _matches(rule: dict[str, Any], fp: dict[str, set[str]]) -> bool:
    """规则任一指纹字段的任一值命中主机对应字段即算命中。

    cookie 精确匹配（离散 token）；其余字段小写子串匹配（如 "nginx" 命中 "nginx/1.18"）。
    """
    for key in _FP_KEYS:
        needles = rule.get(key)
        if not isinstance(needles, list):
            continue
        haystack = fp.get(key) or set()
        exact = key in _EXACT_MATCH_KEYS
        for n in needles:
            if isinstance(n, str) and n.strip():
                nl = n.strip().lower()
                if exact:
                    if nl in haystack:
                        return True
                elif any(nl in h for h in haystack):
                    return True
    return False


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v.strip()]


def assess_exposure(shodan: object, recon: object) -> dict[str, list[dict[str, Any]]]:
    """据已采集指纹产出 {exposed_files: [...], tech_stack: [...]}。绝不抛（坏规则/坏字段安全跳过）。

    - exposed_files: 命中的暴露敏感文件/误配 [{name, severity, forensic_value, refs, caveat}]。
    - tech_stack: 识别到的技术栈/后台框架 [{name, note, caveat}]——仅识别，无 per-CVE RCE 靶单。
    """
    rules = _rules()
    fp = build_host_fingerprint(shodan, recon)

    exposed: list[dict[str, Any]] = []
    for rule in rules.get("exposed_files") or []:
        if not isinstance(rule, dict):
            continue
        try:
            if _matches(rule, fp):
                exposed.append(
                    {
                        "name": rule.get("name"),
                        "severity": rule.get("severity"),
                        "forensic_value": rule.get("forensic_value"),
                        "refs": _as_str_list(rule.get("refs")),
                        "caveat": CAVEAT,
                    }
                )
        except Exception:  # noqa: BLE001 — 单条规则匹配失败不影响其余
            logger.debug("exposure 规则匹配异常，跳过：%r", rule.get("name"), exc_info=True)

    stacks: list[dict[str, Any]] = []
    for rule in rules.get("tech_stack") or []:
        if not isinstance(rule, dict):
            continue
        try:
            if _matches(rule, fp):
                entry: dict[str, Any] = {"name": rule.get("name"), "note": rule.get("note"), "caveat": CAVEAT}
                if rule.get("forensic_value_hint"):
                    entry["forensic_value"] = rule.get("forensic_value_hint")
                stacks.append(entry)
        except Exception:  # noqa: BLE001 — 单条规则匹配失败不影响其余
            logger.debug("tech_stack 规则匹配异常，跳过：%r", rule.get("name"), exc_info=True)

    return {"exposed_files": exposed, "tech_stack": stacks}
