"""自检诊断（AI 友好）：逐项报告**哪个能力通 / 不通 / 怎么修**，输出稳定 JSON。

供任意 AI agent（Codex / Claude / 其它）在驱动 fxapk 前先 ``fxapk selfcheck`` 自检：知道图谱串案、
解密、jadx、动态脱壳抓包、联网富化等可选能力哪些就绪、哪些缺、各自一句话修复指引——
agent 据此决定走哪条路 / 提示用户装什么，而非试错。纯结构化输出、绝不抛、不暴露任何敏感数据。
"""

from __future__ import annotations

import importlib.util
import logging
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


def build_credential_components() -> list[dict[str, str]]:
    """逐个需要凭据的富化源报「已配 / 未配」。**只看变量在不在，绝不读它的值**。

    为什么这一项必须有
    ------------------
    没配 key 的源会安静地不查。落到报告里，那条线索就成了"未发现"——而真相是
    **压根没查**。这两者的差别很实：前者可以写进结论，后者只是一条没做完的活。
    把凭据就绪度摆到台面上，"没查成"才有地方体现。

    绝不回显值：这里只判断 ``os.environ`` 里键在不在，连长度、前缀都不输出。
    """
    import os

    from apkscan.core.registry import discover_enrichers

    out: list[dict[str, str]] = []
    try:
        enrichers = discover_enrichers()
    except Exception:  # noqa: BLE001 — 自检自身绝不抛
        logger.exception("[selfcheck] 富化源发现异常，凭据项跳过")
        return out

    for enricher in sorted(enrichers, key=lambda e: e.name):
        # required_env / name 都是 BaseEnricher 上的声明字段，直接取。
        required = tuple(enricher.required_env or ())
        if not required:
            continue  # 无需凭据的源（whois/rdap/dns…）由 online-enrichment 一项统一覆盖
        name = enricher.name
        # ★.strip() 不可少：真正决定该源发不发查询的两处（enrichment._provider_configured 与
        #   multisource._credential）都是 strip 后判空。这里若不 strip，一个纯空白的
        #   FXAPK_XX_KEY="  " 会被自检说成「已配置」、还不给修复指引，而实际上那个源根本不查
        #   ——恰好是最坏的方向：人以为查过了。
        configured = any((os.environ.get(var) or "").strip() for var in required)
        out.append(_component(
            f"credential:{name}",
            "credential",
            _STATUS_OK if configured else _STATUS_DISABLED,
            f"{name} 富化源的访问凭据"
            + ("（已配置）" if configured else "（未配置 → 该源不会被查询，其结果缺失属"
                                              "「没查成」而非「查了没有」）"),
            "" if configured else f"在 .env 或环境里设 {' 或 '.join(required)}",
        ))
    return out


def _git_head(package_dir: str) -> str:
    """若包目录位于 git 工作树内，返回 HEAD 短哈希；否则空串。绝不抛。"""
    from pathlib import Path

    try:
        here = Path(package_dir).resolve()
    except Exception:  # noqa: BLE001 — 路径解析失败按"不在工作树"处理
        return ""
    for parent in [here, *here.parents]:
        git_dir = parent / ".git"
        if not git_dir.exists():
            continue
        try:
            head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
            if head.startswith("ref: "):
                ref_path = git_dir / head[5:].strip()
                if ref_path.exists():
                    return ref_path.read_text(encoding="utf-8").strip()[:12]
                packed = git_dir / "packed-refs"
                if packed.exists():
                    target = head[5:].strip()
                    for line in packed.read_text(encoding="utf-8").splitlines():
                        parts = line.split()
                        if len(parts) == 2 and parts[1] == target:
                            return parts[0][:12]
                return ""
            return head[:12]
        except Exception:  # noqa: BLE001 — 读不到就当没有，诊断项不该炸
            logger.debug("[selfcheck] 读 git HEAD 失败：%s", git_dir, exc_info=True)
            return ""
    return ""


def build_version_component() -> dict[str, str]:
    """版本自诊断：报告实际导入的是哪份代码，并在被遮蔽时 fail-closed 告警。

    ★为什么需要它：在旧源码目录下跑 ``python -m apkscan.cli`` 时，当前目录的 ``apkscan``
    包会遮蔽 editable 安装的那份，报告写出的 ``tool_version`` 是旧版本号（实测写成
    0.10.0.dev0），而 ``pip show`` 与 ``fxapk --version`` 都显示新版本。这是 Python 的
    导入规则使然、不是算法错误，但读报告的人无从察觉自己看的是旧版结果——
    取证工具的"同版本同结果"承诺正是栽在这种地方。
    """
    import importlib.metadata as _md
    from pathlib import Path

    import apkscan

    imported_version = getattr(apkscan, "__version__", "") or ""
    import_path = ""
    try:
        import_path = str(Path(apkscan.__file__).resolve().parent)
    except Exception:  # noqa: BLE001
        logger.debug("[selfcheck] 解析 apkscan 包路径失败", exc_info=True)

    dist_version = ""
    dist_location = ""
    try:
        dist = _md.distribution("fxapk")
        dist_version = dist.version
        located = getattr(dist, "_path", None) or dist.locate_file("")
        dist_location = str(located)
    except Exception:  # noqa: BLE001 — 未安装（直接跑源码树）是合法情形
        logger.debug("[selfcheck] 未找到已安装的 fxapk 分发", exc_info=True)

    head = _git_head(import_path) if import_path else ""
    detail = (
        f"version={imported_version or '未知'} "
        f"import_path={import_path or '未知'} "
        f"distribution={dist_version or '未安装'} "
        f"distribution_location={dist_location or '-'} "
        f"git_head={head or '-'}"
    )

    # 只有"两边都拿到了版本号且不一致"才算故障——未安装时对不上是正常的。
    if dist_version and imported_version and dist_version != imported_version:
        return _component(
            "version", "core", _STATUS_UNREACHABLE,
            detail + f"　★不一致：已安装 {dist_version}，实际导入 {imported_version}",
            "当前目录下有同名 apkscan 包遮蔽了已安装版本。换个工作目录再跑，"
            "或用 `python -m pip install -e .` 重装后确认 import_path 指向预期位置。",
        )
    return _component("version", "core", _STATUS_OK, detail)


def _dep_component(label: str, module: str, fix: str, why: str) -> dict[str, str]:
    installed = importlib.util.find_spec(module) is not None
    return _component(
        label,
        "optional-dep",
        _STATUS_OK if installed else _STATUS_MISSING,
        f"{why}（依赖 {module}）",
        "" if installed else fix,
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
        # ★放在核心项之后、任何能力项之前：其它项全绿也挡不住"你跑的根本不是这份代码"。
        build_version_component(),
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

    # 凭据就绪度：紧跟联网项——两者一起才回答得了"某个源为什么没有结果"。
    components += build_credential_components()

    summary = Counter(c["status"] for c in components)
    # 整体 ok：核心就绪 + 无「配了却连不上」的硬故障（missing/disabled 是可选能力未启用，可接受）。
    ok = not any(c["status"] == _STATUS_UNREACHABLE for c in components)
    return {"components": components, "summary": dict(summary), "ok": ok}
