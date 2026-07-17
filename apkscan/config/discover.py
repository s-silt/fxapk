"""远程配置对象的**被动发现**：给定 URL，判它是否 App 疑似运行时拉取的远程配置对象。

纯离线、零网络：仅按 ``rules/remote_config.yaml`` 的对象存储/CDN host 家族 + 配置类后缀/路径做启发式分类。
判定口径（降噪）：
- host 命中对象存储/CDN 家族 → 入选（``object-storage-host``）；
- 非对象存储 host → 须**同时**命中配置类后缀 + 配置类路径（双证）才入选，避免把普通 ``*.json`` 端点当配置。

下载 + 多层解码在授权档（slice-1b）据发现清单执行，本模块只产候选、绝不联网。全程绝不抛（坏 URL → None）。
"""

from __future__ import annotations

import fnmatch
import logging
from urllib.parse import urlsplit

from apkscan.config.models import RemoteConfigCandidate
from apkscan.core.registry import load_rules

logger = logging.getLogger(__name__)

_RULES_NAME = "remote_config"

# 规则缺失/损坏时的兜底（保证无 YAML 也能发现主流对象存储；与 rules/remote_config.yaml 对齐）。
_FALLBACK_STORE_FAMILIES: dict[str, tuple[str, ...]] = {
    "aliyun-oss": ("*.oss-*.aliyuncs.com", "oss-*.aliyuncs.com"),
    "tencent-cos": ("*.cos.*.myqcloud.com", "cos.*.myqcloud.com", "*.file.myqcloud.com"),
    "huawei-obs": ("*.obs.*.myhuaweicloud.com", "obs.*.myhuaweicloud.com"),
    "aws-s3": ("*.s3.amazonaws.com", "*.s3.*.amazonaws.com", "s3.amazonaws.com", "s3.*.amazonaws.com"),
    "qiniu": ("*.clouddn.com", "*.qiniucdn.com", "*.qbox.me", "*.qnssl.com"),
}
_FALLBACK_CONFIG_EXTS: tuple[str, ...] = (
    ".dat", ".json", ".bin", ".conf", ".cfg", ".config", ".data", ".db", ".enc", ".txt", ".key",
)
_FALLBACK_CONFIG_PATH_HINTS: tuple[str, ...] = ("/config", "/conf/", "/appconfig", "/settings")


class DiscoveryRules:
    """加载后的发现规则（host 家族 + 配置后缀 + 路径线索），规则缺失时回落内置兜底。"""

    def __init__(
        self,
        families: dict[str, tuple[str, ...]],
        exts: tuple[str, ...],
        path_hints: tuple[str, ...],
    ) -> None:
        self.families = families
        self.exts = exts
        self.path_hints = path_hints

    @classmethod
    def load(cls) -> "DiscoveryRules":
        rules = load_rules(_RULES_NAME)
        if not isinstance(rules, dict):
            return cls(_FALLBACK_STORE_FAMILIES, _FALLBACK_CONFIG_EXTS, _FALLBACK_CONFIG_PATH_HINTS)
        families = _families_from_rules(rules.get("store_families")) or _FALLBACK_STORE_FAMILIES
        exts = _str_tuple(rules.get("config_object_exts")) or _FALLBACK_CONFIG_EXTS
        hints = _str_tuple(rules.get("config_path_hints")) or _FALLBACK_CONFIG_PATH_HINTS
        return cls(families, exts, hints)


def _families_from_rules(value: object) -> dict[str, tuple[str, ...]]:
    """把 YAML 的 ``{family: [patterns]}`` 规范成 ``{str: tuple[str]}``；坏结构 → 空 dict（回落兜底）。"""
    if not isinstance(value, dict):
        return {}
    out: dict[str, tuple[str, ...]] = {}
    for kind, patterns in value.items():
        if isinstance(kind, str) and (pats := _str_tuple(patterns)):
            out[kind] = pats
    return out


def _str_tuple(value: object) -> tuple[str, ...]:
    """把 YAML 列表规范成非空字符串元组（小写化留给调用方，此处只清洗类型）。"""
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str) and v)


def _store_kind(host: str, families: dict[str, tuple[str, ...]]) -> str | None:
    """host（已小写）命中的对象存储/CDN 家族名；不命中 → None。"""
    for kind, patterns in families.items():
        if any(fnmatch.fnmatch(host, pat) for pat in patterns):
            return kind
    return None


def classify_config_url(
    url: str, source_ref: str, rules: DiscoveryRules
) -> RemoteConfigCandidate | None:
    """判单个 URL 是否远程配置对象候选；不是 / 坏 URL → None。绝不抛。

    对象存储/CDN host → 入选；否则须配置后缀 + 配置路径双证。``reasons`` 记全部命中依据。
    """
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if not host or parsed.scheme.lower() not in ("http", "https"):
        return None
    path = parsed.path or ""
    low_path = path.lower()

    reasons: list[str] = []
    kind = _store_kind(host, rules.families)
    if kind:
        reasons.append("object-storage-host")
    has_ext = any(low_path.endswith(ext) for ext in rules.exts)
    has_hint = any(hint in low_path for hint in rules.path_hints)
    if has_ext:
        reasons.append("config-like-ext")
    if has_hint:
        reasons.append("config-like-path")

    # 判定：对象存储 host 单证入选；非对象存储 host 须后缀 + 路径双证（降噪）。
    if kind is None and not (has_ext and has_hint):
        return None
    return RemoteConfigCandidate(
        url=url,
        host=host,
        store_kind=kind or "http",
        object_path=path,
        reasons=tuple(reasons),
        source_ref=source_ref,
    )


__all__ = ["DiscoveryRules", "classify_config_url"]
