"""分析器/富化器基类、自动发现、能力探测、规则加载。

自动发现：用 pkgutil.iter_modules 扫描 apkscan.analyzers / apkscan.enrichers，
import 后实例化所有 Base* 的具体子类（跳过抽象基类）→ 新增模块无需改任何中心文件。
"""

from __future__ import annotations

import importlib
import importlib.resources
import inspect
import logging
import pkgutil
import socket
from abc import ABC, abstractmethod
from types import ModuleType
from typing import TYPE_CHECKING

import yaml

from apkscan.core import device, tools
from apkscan.core.models import AnalyzerResult, EnrichmentResult, Endpoint

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """静态分析器基类。

    name:     稳定标识，用于报告/状态/日志。
    requires: 需要的能力（空 = 永远可用）；registry 探测后决定是否运行。
              可选值见 detect_capabilities()，如 "jadx" / "adb" / "online"。
    """

    name: str = ""
    requires: list[str] = []

    @abstractmethod
    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        """对上下文做分析，返回 AnalyzerResult。异常由 pipeline 捕获并记录。"""
        ...


class BaseEnricher(ABC):
    """联网富化器基类。

    name:        稳定标识。
    applies_to:  适用的端点类型，元素为 "domain" / "ip"。
    phase:       富化阶段（两遍富化调度用）：
                 - ``"attribution"``（默认）：第①遍，查归属（rdap/whois/dns/asn/icp/webcheck），
                   定服务器辖区（国内/国外/未知）。
                 - ``"overseas"``：第②遍，境外被动取证（shodan/certs），**仅对国外(+未知)端点跑**。
    active:      **是否会向目标发起连接的标记**。本仓当前富化器全部为被动（``active=False``），
                 只读第三方公开库 / OSINT，对目标零流量；保留该标记以便审计声明「不接触目标」。
    """

    name: str = ""
    applies_to: list[str] = []
    phase: str = "attribution"
    active: bool = False

    @abstractmethod
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        """对单个端点做富化，返回 EnrichmentResult。异常由 pipeline 捕获并记录。"""
        ...


# ---------------------------------------------------------------------------
# 自动发现
# ---------------------------------------------------------------------------


def _iter_package_modules(package_name: str) -> list[ModuleType]:
    """import 并返回某包下所有子模块。单模块导入失败记录后跳过。"""
    modules: list[ModuleType] = []
    try:
        package = importlib.import_module(package_name)
    except Exception:
        logger.exception("无法导入包：%s", package_name)
        return modules

    pkg_path = getattr(package, "__path__", None)
    if pkg_path is None:
        logger.warning("%s 不是包（无 __path__），跳过自动发现", package_name)
        return modules

    for mod_info in pkgutil.iter_modules(pkg_path):
        if mod_info.name.startswith("_"):
            continue
        full_name = f"{package_name}.{mod_info.name}"
        try:
            modules.append(importlib.import_module(full_name))
        except Exception:
            logger.exception("导入模块失败，跳过：%s", full_name)
    return modules


def _instantiate_subclasses(modules: list[ModuleType], base: type) -> list:
    """实例化 modules 中所有 base 的具体子类（跳过 base 自身与抽象类）。"""
    seen: set[type] = set()
    instances: list = []
    for module in modules:
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, base) or obj is base:
                continue
            if inspect.isabstract(obj):
                continue
            # 仅实例化定义于被扫描模块内的类，避免重复（import 进来的同名类）
            if obj.__module__ != module.__name__:
                continue
            if obj in seen:
                continue
            seen.add(obj)
            try:
                instances.append(obj())
            except Exception:
                logger.exception("实例化失败，跳过：%s", obj)
    return instances


# requires 可声明的已知能力名：detect_capabilities() 探测的 + pipeline 按平台注入的 apk/ipa。
# 分析器 requires 里出现此集合外的名字（如把 "jadx" 拼成 "jdax"）会让它永久被 skip，且
# skipped 理由像"环境缺工具"而非代码 bug——极难发现，故自动发现期校验并点名告警。
_KNOWN_CAPABILITIES: frozenset[str] = frozenset(
    {"apk", "ipa", "jadx", "adb", "online", "frida", "frida-dexdump", "mitmproxy", "device"}
)


def _dedup_and_validate(instances: list, *, kind: str) -> list:
    """对自动发现的实例做 name 唯一性 + requires 能力名校验（不静默，快速失败式告警）。

    - **重名 name**：复制新模块时最常见的错。两个同名分析器都会跑、meta 互相覆盖、报告出现
      两条同名 status 却无法区分——这里保留首个、对后续重名 ``logger.error`` 点名两个类。
    - **requires 拼写错**：未知能力名会让分析器永久 skip 且伪装成"缺工具"，``logger.error`` 点名。
    name 为空的实例直接跳过并告警（无名分析器无法被状态/报告引用）。
    """
    seen: dict[str, object] = {}
    kept: list = []
    for inst in instances:
        name = getattr(inst, "name", "") or ""
        if not name:
            logger.error("%s %s 的 name 为空，已跳过", kind, type(inst).__name__)
            continue
        if name in seen:
            logger.error(
                "%s name 冲突：'%s' 已被 %s 占用，跳过 %s（重名会互相覆盖，请改名）",
                kind, name, type(seen[name]).__name__, type(inst).__name__,
            )
            continue
        requires = getattr(inst, "requires", None)
        if isinstance(requires, list):
            unknown = [c for c in requires if c not in _KNOWN_CAPABILITIES]
            if unknown:
                logger.error(
                    "%s '%s' 的 requires 含未知能力名 %s（疑似拼写错误→永久 skip）；已知能力：%s",
                    kind, name, unknown, sorted(_KNOWN_CAPABILITIES),
                )
        seen[name] = inst
        kept.append(inst)
    return kept


def discover_analyzers() -> list[BaseAnalyzer]:
    """发现并实例化 apkscan.analyzers 下所有 BaseAnalyzer 具体子类（含重名/requires 校验）。"""
    modules = _iter_package_modules("apkscan.analyzers")
    return _dedup_and_validate(_instantiate_subclasses(modules, BaseAnalyzer), kind="分析器")


def discover_enrichers() -> list[BaseEnricher]:
    """发现并实例化 apkscan.enrichers 下所有 BaseEnricher 具体子类（含重名校验）。"""
    modules = _iter_package_modules("apkscan.enrichers")
    return _dedup_and_validate(_instantiate_subclasses(modules, BaseEnricher), kind="富化器")


# ---------------------------------------------------------------------------
# 能力探测
# ---------------------------------------------------------------------------


def detect_capabilities(online: bool = True) -> set[str]:
    """探测可用能力集合。

    静态/工具类：
    - "jadx" / "adb"：对应外部工具在 PATH 中。
    - "online"：当 online=True 且本机有出网连通性时加入。

    动态(脱壳/抓包)类（探测助手见 apkscan.core.device，全部不抛）：
    - "frida" / "frida-dexdump" / "mitmproxy"：对应外部工具在 PATH 中。
    - "device"：有至少一台在线 adb 设备。

    返回的集合用于决定 requires 不满足的分析器/能力是否跳过。
    """
    caps: set[str] = set()

    # jadx 不内置：PATH 上有则用，否则看独立 jadx 插件包（jadx-addon/，自带 JRE）是否就位；
    # adb 走 tools.has_adb（frozen 看 exe 同目录随包 adb.exe）。
    if tools.has_jadx():
        caps.add("jadx")
    if tools.has_adb():
        caps.add("adb")

    if online and _has_network():
        caps.add("online")

    # 动态能力（无设备/工具时静默不加入；探测助手内部已 try/except+logging）。
    if device.has_frida():
        caps.add("frida")
    if device.has_frida_dexdump():
        caps.add("frida-dexdump")
    if device.has_mitmproxy():
        caps.add("mitmproxy")
    if device.has_device():
        caps.add("device")

    return caps


# 连通性探测锚点（host, port）：混合**境内**（阿里/腾讯 DoH）+ **境外**（RDAP / Cloudflare）。
# 只做 TCP:443 连接、不发任何请求（不泄露探测意图、不在 provider 侧留日志）；任一可达即判在线。
# ★不再单锚境外 DNS（旧版 1.1.1.1:53 / 8.8.8.8:53）：这类境外锚点在部分网络（如 GFW）会被
#   阻断/污染，探测假阴性"无网" → 把本可正常工作的**境内** provider（DoH / ICP 备案查询等）
#   富化整体误关。境内锚点在前：常见部署环境下最可能命中，命中即短路，联网场景近乎零延迟。
_NETWORK_PROBE_HOSTS: tuple[tuple[str, int], ...] = (
    ("dns.alidns.com", 443),  # 阿里 DoH，境内高可用
    ("doh.pub", 443),         # 腾讯 DoH，境内高可用
    ("rdap.org", 443),        # RDAP，境外（境内通常亦可达）
    ("1.1.1.1", 443),         # Cloudflare，境外兜底（用 443 而非易被污染的 53）
)


def _has_network(timeout: float = 1.5) -> bool:
    """探测出网连通性：对代表性 provider 锚点做 TCP:443 连接（不发请求），任一可达即在线。

    锚点混合境内 + 境外，避免单靠境外 DNS 在受限网络下假阴性、误关整个富化层（见
    ``_NETWORK_PROBE_HOSTS`` 说明）。命中即短路返回；全不可达（真离线）最坏付
    ``len(hosts) × timeout``（默认 4 × 1.5s）。绝不抛。
    """
    for host, port in _NETWORK_PROBE_HOSTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                logger.debug("网络探测命中：%s:%s", host, port)
                return True
        except OSError:
            logger.debug("网络探测失败：%s:%s", host, port, exc_info=True)
    return False


# ---------------------------------------------------------------------------
# 规则加载
# ---------------------------------------------------------------------------


def ruleset_digest() -> str:
    """对全部内置规则文件内容算稳定摘要（sha256 前 16 hex）：同一套规则 → 同一 digest。

    供报告标注「本次结果由哪套规则产出」，是可复现性 / 回归对比的锚点（规则一改 digest 就变）。
    只哈希 rules/ 下的 .yaml/.txt（文件名 + 内容，按名排序保证稳定）。任何读取失败 → "unknown"
    （绝不抛，不得影响主流程）。

    ★换行归一化（CRLF/CR → LF）后再哈希：规则文件在 Windows（autocrlf）与 Linux 上 checkout 出的
    字节 EOL 不同，若直接哈希会让**同一套规则**在不同平台/安装形态算出不同 digest，违背"同规则→
    同 digest"。归一化使 digest 只随规则**内容**变，与 checkout 的换行风格无关。
    """
    import hashlib

    try:
        rules_dir = importlib.resources.files("apkscan") / "rules"
        entries = sorted(
            (e for e in rules_dir.iterdir() if e.name.endswith((".yaml", ".txt"))),
            key=lambda e: e.name,
        )
        if not entries:
            return "unknown"
        h = hashlib.sha256()
        for entry in entries:
            content = entry.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            h.update(entry.name.encode("utf-8"))
            h.update(b"\0")
            h.update(content)
            h.update(b"\0")
        return h.hexdigest()[:16]
    except Exception:
        logger.debug("ruleset_digest 计算失败，返回 unknown", exc_info=True)
        return "unknown"


def load_rules(name: str) -> dict | list:
    """读取 apkscan/rules/<name>.yaml。

    用 importlib.resources 锚顶层包 ``apkscan`` 定位资源（rules/ 是数据目录、非子包，
    故锚 'apkscan' 而非 'apkscan.rules'），不依赖 ``Path(__file__)`` 相对路径——
    这样在 PyInstaller onefile 等打包形态下仍成立（exe-ready）。

    找不到 / 解析失败 → 记 warning（用 logging，不静默 pass）并返回空 dict。
    name 可带或不带 .yaml 后缀。
    """
    stem = name[:-5] if name.endswith(".yaml") else name

    try:
        resource = importlib.resources.files("apkscan") / "rules" / f"{stem}.yaml"
        text = resource.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("规则文件不存在：rules/%s.yaml", stem)
        return {}
    except (OSError, ModuleNotFoundError):
        logger.exception("定位/读取规则资源失败：rules/%s.yaml", stem)
        return {}

    try:
        data = yaml.safe_load(text)
    except Exception:
        logger.exception("解析规则失败：rules/%s.yaml", stem)
        return {}

    if data is None:
        logger.warning("规则文件为空：rules/%s.yaml", stem)
        return {}
    if not isinstance(data, (dict, list)):
        logger.warning(
            "规则文件顶层类型应为 dict/list，实际 %s：rules/%s.yaml", type(data).__name__, stem
        )
        return {}
    return data
