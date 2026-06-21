"""自检诊断（AI 友好）：逐项报告**哪个能力通 / 不通 / 怎么修**，输出稳定 JSON。

供任意 AI agent（Codex / Claude / 其它）在驱动 fxapk 前先 ``fxapk selfcheck`` 自检：知道图谱串案、
解密、jadx、动态脱壳抓包、联网富化、web-check 等可选能力哪些就绪、哪些缺、各自一句话修复指引——
agent 据此决定走哪条路 / 提示用户装什么，而非试错。纯结构化输出、绝不抛、不暴露任何敏感数据。
"""

from __future__ import annotations

import importlib.util
import logging
import os
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)

# status 取值：ok（就绪）| missing（可选能力未装）| disabled（未配置/未开启）| unreachable（配了但连不上）。
_STATUS_OK = "ok"
_STATUS_MISSING = "missing"
_STATUS_DISABLED = "disabled"
_STATUS_UNREACHABLE = "unreachable"

#: 可选 Python 依赖：(name, import 名, 修复, 用途)。
_OPTIONAL_DEPS = (
    ("graph", "kuzu", "pip install fxapk[graph]", "本地案件图谱串案（fxapk graph）"),
    ("decrypt", "cryptography", "pip install cryptography", "解密运行时 {data,timestamp} 加密信封"),
)

#: 工具 / 动态能力：(cap 名, category, 修复, 用途)。状态由 detect_capabilities 判定。
_CAP_COMPONENTS = (
    ("jadx", "tool", "下载 fxapk-jadx 插件包并启用，或装 jadx 到 PATH", "深度反编译补端点/密钥"),
    ("adb", "tool", "装 Android platform-tools，或用自包含发行包（内置 adb）", "设备通信（动态前置）"),
    ("frida", "dynamic", "pip install frida-tools", "脱壳 / 抓包的 Frida 注入"),
    ("frida-dexdump", "dynamic", "pip install frida-dexdump", "frida-dexdump 脱壳"),
    ("mitmproxy", "dynamic", "pip install mitmproxy", "抓包流量解析"),
    ("device", "dynamic", "USB 接好已 root 的真机/模拟器并 adb 连上", "真机脱壳 / 抓包"),
)


def _component(name: str, category: str, status: str, detail: str, fix: str = "") -> dict[str, str]:
    return {"name": name, "category": category, "status": status, "detail": detail, "fix": fix}


def _dep_component(label: str, module: str, fix: str, why: str) -> dict[str, str]:
    installed = importlib.util.find_spec(module) is not None
    return _component(
        label,
        "optional-dep",
        _STATUS_OK if installed else _STATUS_MISSING,
        f"{why}（依赖 {module}）",
        "" if installed else fix,
    )


def _webcheck_component(probe: bool) -> dict[str, str]:
    url = (os.environ.get("FXAPK_WEBCHECK_URL") or "").strip().rstrip("/")
    if not url:
        return _component(
            "webcheck", "network", _STATUS_DISABLED,
            "web-check OSINT 再查一轮（域名/IP 地理/SSL/端口/技术栈/威胁/子域）",
            "设环境变量 FXAPK_WEBCHECK_URL 指向本地 web-check 实例（docker run -p 3000:3000 lissy93/web-check）",
        )
    if not probe:
        return _component("webcheck", "network", _STATUS_OK, f"已配置：{url}（未探测连通）", "")
    reachable = False
    try:
        import requests

        requests.get(url, timeout=4)
        reachable = True
    except Exception as exc:  # noqa: BLE001 — 探测失败=不可达，给修复指引，不抛
        logger.debug("webcheck 探测失败：%s（%s）", url, exc)
    return _component(
        "webcheck", "network",
        _STATUS_OK if reachable else _STATUS_UNREACHABLE,
        f"web-check 实例：{url}",
        "" if reachable else f"实例不可达，确认已启动并监听该地址：{url}",
    )


def run_selfcheck(*, online: bool = True, probe_network: bool = True) -> dict[str, Any]:
    """逐项自检，返回 {components:[{name,category,status,detail,fix}], summary, ok}。绝不抛。"""
    from apkscan.core.registry import detect_capabilities

    try:
        caps = detect_capabilities(online=online)
    except Exception:  # noqa: BLE001 — 探测异常按空能力处理，不阻断自检
        logger.exception("[selfcheck] 能力探测异常，按空集处理")
        caps = set()

    components: list[dict[str, str]] = [
        _component("core", "core", _STATUS_OK, "静态分析核心（零环境，always-on）"),
    ]
    components += [_dep_component(label, mod, fix, why) for label, mod, fix, why in _OPTIONAL_DEPS]
    for cap, category, fix, why in _CAP_COMPONENTS:
        ok = cap in caps
        components.append(
            _component(cap, category, _STATUS_OK if ok else _STATUS_MISSING, why, "" if ok else fix)
        )

    net_ok = "online" in caps
    components.append(
        _component(
            "online-enrichment", "network",
            _STATUS_OK if net_ok else _STATUS_DISABLED,
            "whois / rdap / ICP 备案 / ASN / DoH 归属富化（喂主体归属 + 辖区分流）",
            "" if net_ok else "确保本机可出网且用 --online（注意 whois 走 DNS，部分环境不可用）",
        )
    )
    components.append(_webcheck_component(probe_network and online))

    summary = Counter(c["status"] for c in components)
    # 整体 ok：核心就绪 + 无「配了却连不上」的硬故障（missing/disabled 是可选能力未启用，可接受）。
    ok = not any(c["status"] == _STATUS_UNREACHABLE for c in components)
    return {"components": components, "summary": dict(summary), "ok": ok}
