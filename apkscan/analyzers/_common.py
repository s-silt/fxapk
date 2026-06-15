"""分析器共享工具 —— 标量规整、文本资源判定、snippet 截取、端点收集器、数据采集。

把多个分析器逐字重复的私有实现收敛到这里，作为单一权威版本。全部保持与原各分析器
私有实现逐字一致的行为（测试是契约），只是消除重复。

约束：
- 只依赖 AnalysisContext 公开接口与 core.models / core.textutil，禁止 import androguard。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeGuard

from apkscan.core.models import Confidence, Endpoint, Evidence

# 标量工具：转发 textutil 的权威实现，供分析器以共享版引用。
from apkscan.core.textutil import as_str_list as as_str_list
from apkscan.core.textutil import truncate as truncate

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

__all__ = [
    "as_str_list",
    "truncate",
    "str_or_empty",
    "nonempty_str",
    "parse_confidence",
    "TEXT_RESOURCE_SUFFIXES",
    "TEXT_RESOURCE_PREFIXES",
    "BINARY_RESOURCE_SUFFIXES",
    "is_text_resource",
    "snippet_around",
    "EndpointCollector",
    "collect_so_basenames",
    "collect_file_paths",
    "collect_dex_strings",
]

# DEX 字符串扫描上限：样本字符串池可能很大，避免极端情况下扫描过久。
_MAX_DEX_STRINGS = 200_000

# 视为文本、值得做关键字扫描的资源后缀 / 路径前缀（payment / contacts 共用）。
TEXT_RESOURCE_SUFFIXES: tuple[str, ...] = (
    ".json", ".xml", ".txt", ".properties", ".js", ".html", ".htm",
    ".cfg", ".conf", ".ini", ".csv", ".kv", ".plist",
)
TEXT_RESOURCE_PREFIXES: tuple[str, ...] = ("assets/", "res/raw/", "res/xml/")

# 已知二进制资源后缀：即使落在文本前缀目录（assets/ 等）下也**绝不**按文本扫描。
# 把字体/图片/音视频/原生库/压缩包解码成 utf-8 去跑正则既错（在字体里"找邮箱"）又危险——
# 曾因 "assets/" 前缀把 512KB 的 MaterialIcons-Regular.otf 当文本喂给 contacts，触发
# email 正则灾难性回溯卡死 4.6 分钟。优先级高于前缀/后缀命中。
BINARY_RESOURCE_SUFFIXES: tuple[str, ...] = (
    # 字体
    ".otf", ".ttf", ".ttc", ".woff", ".woff2", ".eot",
    # 图片
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svgz", ".tif", ".tiff",
    # 音视频
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".aac", ".m4a", ".flac", ".mov", ".avi", ".mkv",
    # 原生库 / 可执行 / 字节码
    ".so", ".dex", ".jar", ".class", ".arsc",
    # 压缩 / 二进制数据
    ".zip", ".gz", ".tar", ".7z", ".bin", ".dat", ".pak", ".lottie", ".pdf",
)


# ---------------------------------------------------------------------------
# 标量规整
# ---------------------------------------------------------------------------


def str_or_empty(value: object) -> str:
    """规则字段取 str（去空白），非 str / None → 空串。"""
    return value.strip() if isinstance(value, str) else ""


def nonempty_str(value: object) -> TypeGuard[str]:
    """value 是非空（strip 后非空）字符串。"""
    return isinstance(value, str) and bool(value.strip())


def parse_confidence(value: object) -> Confidence | None:
    """把规则的 confidence 字段解析为 Confidence；无法判定返回 None。"""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return Confidence[value.strip().upper()]
    except KeyError:
        return None


# ---------------------------------------------------------------------------
# 文本资源判定 / snippet
# ---------------------------------------------------------------------------


def is_text_resource(
    path: str,
    *,
    suffixes: tuple[str, ...],
    prefixes: tuple[str, ...],
) -> bool:
    """路径是否为值得做文本扫描的资源（后缀或路径前缀命中）。

    二进制资源（字体/图片/音视频/.so/压缩包等）优先排除：即使落在 assets/ 等文本前缀下
    也不按文本扫描——把二进制解码成 utf-8 跑正则既错又可能触发灾难性回溯。
    """
    low = path.lower()
    if low.endswith(BINARY_RESOURCE_SUFFIXES):
        return False
    if low.endswith(suffixes):
        return True
    return low.startswith(prefixes)


def snippet_around(text: str, m: object, radius: int = 60) -> str:
    """截取命中位置周边片段，便于人工复核。

    m 需提供 start()/end()（re.Match 或等价替身）。取片段失败时回退为整段截断。
    """
    try:
        start = max(0, m.start() - radius)  # type: ignore[attr-defined]
        end = min(len(text), m.end() + radius)  # type: ignore[attr-defined]
    except Exception:
        return truncate(text, 160)
    seg = text[start:end].replace("\n", " ").strip()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{seg}{suffix}"


# ---------------------------------------------------------------------------
# 端点收集器（endpoints / js_bundle 共用）
# ---------------------------------------------------------------------------


@dataclass
class EndpointCollector:
    """累积去重的端点表：value -> Endpoint，evidences 合并。"""

    by_value: dict[str, Endpoint] = field(default_factory=dict)
    _ev_keys: dict[str, set[tuple[str, str]]] = field(default_factory=dict)

    def add(
        self,
        value: str,
        kind: str,
        evidence: Evidence,
        *,
        is_cleartext: bool = False,
        is_private: bool = False,
    ) -> None:
        ep = self.by_value.get(value)
        if ep is None:
            ep = Endpoint(
                value=value,
                kind=kind,
                evidences=[],
                is_cleartext=is_cleartext,
                is_private=is_private,
            )
            self.by_value[value] = ep
            self._ev_keys[value] = set()
        else:
            # 标志位取并集（任一来源标明文/私网即视为明文/私网）。
            ep.is_cleartext = ep.is_cleartext or is_cleartext
            ep.is_private = ep.is_private or is_private

        ev_key = (evidence.source, evidence.location)
        if ev_key not in self._ev_keys[value]:
            self._ev_keys[value].add(ev_key)
            ep.evidences.append(evidence)

    def mark_tier(self, value: str, tier: str) -> None:
        """给已收集的端点写域名来源可信度档（C1）。多来源取最可信档（app 优先）。

        延迟导入 infra 的合并器，避免 _common 顶层依赖 infra。tier 写入
        Endpoint.enrichment["tier"]，pipeline 据此对非 infra 域名降可信到"待核"。
        """
        ep = self.by_value.get(value)
        if ep is None:
            return
        from apkscan.core.infra import best_tier

        current = ep.enrichment.get("tier")
        ep.enrichment["tier"] = best_tier(current, tier) if current else tier

    def endpoints(self, order: dict[str, int]) -> list[Endpoint]:
        """稳定排序：按 order 给出的 kind 权重，再按 value。"""
        return sorted(
            self.by_value.values(),
            key=lambda e: (order.get(e.kind, 9), e.value),
        )


# ---------------------------------------------------------------------------
# 数据源采集（sdk_fingerprint / packing / payment 共用）
# ---------------------------------------------------------------------------


def collect_so_basenames(
    ctx: "AnalysisContext", analyzer_name: str
) -> dict[str, str]:
    """返回 {小写 basename: 原始路径}。包含 native_libs 与 list_files 中的 .so。"""
    result: dict[str, str] = {}
    try:
        libs = list(ctx.native_libs())
    except Exception:
        logger.exception("[%s] 读取 native_libs 失败", analyzer_name)
        libs = []
    try:
        files = list(ctx.list_files())
    except Exception:
        logger.exception("[%s] 读取 list_files 失败（用于 .so 采集）", analyzer_name)
        files = []

    for path in libs + files:
        if not isinstance(path, str):
            continue
        base = posixpath.basename(path.replace("\\", "/"))
        if base.lower().endswith(".so"):
            result.setdefault(base.lower(), path)
    return result


def collect_file_paths(ctx: "AnalysisContext", analyzer_name: str) -> list[str]:
    """APK 内全部文件路径（仅保留 str 条目）。"""
    try:
        return [p for p in ctx.list_files() if isinstance(p, str)]
    except Exception:
        logger.exception("[%s] 读取 list_files 失败", analyzer_name)
        return []


def collect_dex_strings(
    ctx: "AnalysisContext",
    analyzer_name: str,
    *,
    max_strings: int = _MAX_DEX_STRINGS,
) -> tuple[bool, list[str]]:
    """收集 DEX 字符串（带上限）。返回 (是否成功遍历, 字符串列表)。"""
    strings: list[str] = []
    try:
        for idx, s in enumerate(ctx.dex_strings()):
            if idx >= max_strings:
                logger.warning(
                    "[%s] DEX 字符串超过上限 %d，截断扫描", analyzer_name, max_strings
                )
                break
            if isinstance(s, str) and s:
                strings.append(s)
    except Exception:
        logger.exception("[%s] 遍历 dex_strings 失败", analyzer_name)
        return False, strings
    return True, strings
