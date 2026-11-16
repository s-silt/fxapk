"""网络基础设施类别的**规范取值**——五层归属（core/attribution）与角色推理（attribution/assemble）共用同一份，
消除两处硬编码字符串漂移（assemble 曾自维护 ``{"cloud","idc"}`` / ``{"cdn"}``，须与 core 的 ``CAT_*`` 对齐，
一处改名另一处静默失配）。

★保持**字符串常量**（非 Enum）：这些值同时是 ``rules/providers.yaml`` 的类别键与富化器输出的 ``category``
字面量，换 Enum 会破坏 YAML 字符串键匹配与 dict 比较。语义分组（共享基础设施 / CDN / 非公共 CDN 托管等）
由各模块按需从这些常量自建（如 ``_SHARED_INFRA_CATEGORIES`` / ``_CDN_CATEGORIES``），但类别**值**只此一份。
"""

from __future__ import annotations

CAT_TELECOM = "telecom"
CAT_CLOUD = "cloud"
CAT_IDC = "idc"
CAT_CDN = "cdn"
CAT_SECURITY_PROXY = "security_proxy"
CAT_HOSTING_RESELLER = "hosting_reseller"
CAT_ENTERPRISE = "enterprise_network"
CAT_UNKNOWN = "unknown"

__all__ = [
    "CAT_CDN",
    "CAT_CLOUD",
    "CAT_ENTERPRISE",
    "CAT_HOSTING_RESELLER",
    "CAT_IDC",
    "CAT_SECURITY_PROXY",
    "CAT_TELECOM",
    "CAT_UNKNOWN",
]
