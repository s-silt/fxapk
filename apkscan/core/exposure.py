"""后台框架/技术栈指纹研判（纯函数）：把被动采集的服务器 banner 映射到「技术栈 / 后台框架」。

★ 定位与边界：本模块是**取证串案情报**，用于团伙串并，不是攻击工具。
- 只做：从 shodan / webcheck **被动采集的服务 banner 指纹**匹配 ``rules/exposure.yaml`` 的技术栈
  规则 → 识别「这台服务器是什么栈 / 什么后台框架」（PHP / Laravel / ThinkPHP / Spring / 致远 /
  泛微 / 通达 OA…）。**零网络、零 payload**，对目标零流量，绝不发起任何动作。
- 用途：**同后台框架 = 疑同团伙基础设施**——多个样本命中同一后台 / 面板指纹，可并簇串案。仅做识别，
  不研判漏洞、不给利用方向。

匹配：逐字段·小写子串·任一命中即该条命中（与既有 rules 风格一致）。
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from apkscan.core.registry import load_rules

logger = logging.getLogger(__name__)

_RULES_NAME = "exposure"

#: 指纹字段（须与被动 enrichers 真实输出对齐；规则与主机指纹都按这些键比对）。
_FP_KEYS = (
    "server", "x_powered_by", "title", "product", "cpe", "cookie", "module",
)

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


def build_host_fingerprint(shodan: object, webcheck: object) -> dict[str, set[str]]:
    """把一台主机的 shodan + webcheck **被动 banner** 拍平成小写字符串集合（供规则子串匹配）。

    数据全部来自对目标**零流量**的被动采集：Shodan 已扫库的服务 banner（product / version /
    http.server / http.title / cpe / module）、webcheck 的技术栈识别（tech-stack）。坏字段安全跳过。
    """
    sh = shodan if isinstance(shodan, dict) else {}
    wc = webcheck if isinstance(webcheck, dict) else {}
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

    # webcheck 技术栈识别（Wappalyzer 类，被动）：把识别到的技术名并入 product / title 桶，
    # 让后台框架规则（Laravel / ThinkPHP…）也能据被动技术栈命中。
    tech = wc.get("tech-stack")
    techs = tech.get("technologies") if isinstance(tech, dict) else tech
    for t in techs if isinstance(techs, list) else []:
        name = t.get("name") if isinstance(t, dict) else t
        _add(fp, "product", name)
        _add(fp, "title", name)

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


def assess_tech_stack(shodan: object, webcheck: object) -> list[dict[str, Any]]:
    """据被动 banner 指纹识别技术栈 / 后台框架，返回 [{name, note}]。绝不抛（坏规则 / 坏字段安全跳过）。

    仅识别栈 / 后台框架，用作**同后台 = 疑同团伙**的串案信号；不研判漏洞、不给利用方向。
    """
    rules = _rules()
    fp = build_host_fingerprint(shodan, webcheck)

    stacks: list[dict[str, Any]] = []
    for rule in rules.get("tech_stack") or []:
        if not isinstance(rule, dict):
            continue
        try:
            if _matches(rule, fp):
                stacks.append({"name": rule.get("name"), "note": rule.get("note")})
        except Exception:  # noqa: BLE001 — 单条规则匹配失败不影响其余
            logger.debug("tech_stack 规则匹配异常，跳过：%r", rule.get("name"), exc_info=True)
    return stacks
