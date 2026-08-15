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
    # ★"源码树自称的版本"取同包 __init__ 的 _FALLBACK_VERSION（发版时与 pyproject 同步）。
    #   为什么读这个私有名而不是 pyproject.toml：pyproject 不进 wheel、site-packages 里没有，
    #   只有源码树才有；而 _FALLBACK_VERSION 随代码本体走，任何安装形态下都在。selfcheck 与它
    #   同属 apkscan 包，包内读私有名是刻意选择；getattr 兜底防未来改名时自检自身炸掉。
    fallback_version = getattr(apkscan, "_FALLBACK_VERSION", "") or ""
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

    # ★重装目标必须是**绝对路径**，不能给裸 `-e .`：核对 import_path 无误，不等于当前 shell
    #   就站在那棵树的根上（例：经 PYTHONPATH 导入 A 树，而 cwd 在 B 树——照 `-e .` 装的是 B，
    #   静默覆盖原安装）。import_path 是 <项目根>/apkscan，其父目录即项目根，直接算给调用方。
    #   ★仅当该目录确是源码树（有 pyproject.toml）才给 editable 重装命令：非 editable 安装时
    #   import_path 在 site-packages 下，给 `pip install -e "<site-packages>"` 是无意义命令。
    project_root = str(Path(import_path).parent) if import_path else ""
    _is_source_tree = bool(project_root) and (Path(project_root) / "pyproject.toml").is_file()
    if _is_source_tree:
        reinstall = (f'`python -m pip install -e "{project_root}"`（uv 建的 venv 不带 pip，'
                     f'用 `uv pip install -e "{project_root}"`）')
    elif project_root:
        reinstall = (f'import_path（{project_root}）不是源码树、其下无 pyproject.toml，'
                     f'不适用 editable 重装；这多半是正式发行包，请改按包名重装/升级到预期版本')
    else:
        reinstall = "`python -m pip install -e <该工作树的绝对路径>`（uv 建的 venv 用 `uv pip install -e <同上>`）"

    head = _git_head(import_path) if import_path else ""
    detail = (
        f"version={imported_version or '未知'} "
        f"source_version={fallback_version or '未知'} "
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
            "当前目录下有同名 apkscan 包遮蔽了已安装版本。★先核对 detail 里的 import_path "
            "是否为你预期的工作树：不是则换到预期目录再跑，**切勿在当前目录重装**——"
            "那会把这棵非预期的树装成 editable、静默覆盖原安装、自检假性转绿。"
            f"确认 import_path 无误后仍不一致，再按**绝对路径**重装刷新：{reinstall}。"
            "★不要用 `pip install -e .`：核对 import_path 无误不等于当前 shell 就在那棵树的根上。",
        )
    # ★第二条判据：源码树自称的版本 vs 安装元数据。上一条抓不住这类故障——__version__ 优先取
    #   importlib.metadata，只要装了包，imported 恒等于 dist，上面那条比对永远"一致"。而 editable
    #   安装后 pyproject 升版没重装时，元数据停在旧版号：跑的明明是新代码，报告 tool_version、
    #   corpus 主键四元组、integrity 指纹却全写旧版号（实测：pyproject 1.6.1 / 元数据 1.5.2，
    #   报告写 1.5.2 且自检报 ok）。"同样本同版本→同结果"正是从这个口子破掉。
    #   反方向（fallback 比元数据旧）＝发版时忘了同步 _FALLBACK_VERSION 与 pyproject，
    #   版本口径同样分裂，一并 fail-closed。
    #
    #   ★这条判据的 fail-open 边界（须如实把握，勿当成"任何形态都兜得住"）：
    #   两个版本源**任一为空即静默放行**。空的合法情形是「未安装、直接跑源码树」（dist 为空）——
    #   此时 __version__ 走 _FALLBACK_VERSION，报告写的版本本就正确，不报是对的。
    #   不合法情形是 _FALLBACK_VERSION 被改名/清空导致 fallback 为空：判据在生产环境静默失效，
    #   仅靠 test_fallback_version_contract_holds 与 test_stale_metadata_wiring_survives_rename
    #   在**测试阶段**拦截，已发布产物不会因此 fail-closed。要闭合这一点需产物级测试
    #   （wheel / sdist / editable / 冻结包各装一遍比对三源），本函数不承担。
    if dist_version and fallback_version and dist_version != fallback_version:
        return _component(
            "version", "core", _STATUS_UNREACHABLE,
            detail + f"　★不一致：安装元数据 {dist_version}，源码树声明 {fallback_version}",
            "版本口径分裂。★先核对 detail 里的 import_path 是否为你预期的工作树，据此分流——"
            "① 是：安装元数据滞后于源码树（pyproject 升版后没重装），报告 tool_version 会写成旧版号；"
            f"用运行本工具的解释器按**绝对路径**重装刷新：{reinstall}。"
            "★不要用 `pip install -e .`：核对 import_path 无误不等于当前 shell 就在那棵树的根上。"
            "② 否：是另一棵 apkscan 源码树遮蔽了已安装版本——换到预期目录再跑，"
            "★切勿在当前目录重装，否则会把这棵非预期的树装成 editable、静默覆盖原安装、自检假性转绿。"
            "若正式发行包报此故障，则是发版时 _FALLBACK_VERSION 未与 pyproject 同步。",
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
