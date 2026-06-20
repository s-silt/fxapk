"""强指纹 kind 的强弱权重（配置而非代码逻辑：调权重无须改 schema、无须迁移）。

权重用于 link / cluster 的排名与置信分计算。未注册的 kind 默认权重 1.0、非 strong——
A 期新增线索类型即便忘了在此注册也不会崩，只是排名靠后（约束 C7 的安全垫）。
"""

from __future__ import annotations

# kind -> {weight, strength}。strength ∈ {"strong", "medium"}。
# 强档：高区分度、几乎不会被无关包共用（调试证书已在 extract_fingerprints 上游排除）。
# 中档：前端工程级，区分度中等。
WEIGHT_CONFIG: dict[str, dict] = {
    "sign": {"weight": 10.0, "strength": "strong"},
    "c2": {"weight": 10.0, "strength": "strong"},
    # 钱包私钥/助记词共享 = 同一操作者铁证（校验和近零误报），最强连边。
    "wallet_secret": {"weight": 11.0, "strength": "strong"},
    "crypto_addr": {"weight": 9.0, "strength": "strong"},
    # A 期新增：后台 host / 自建 IM 服务器 = 同伙运营基础设施，强连边。
    "admin_host": {"weight": 9.0, "strength": "strong"},
    "im_server": {"weight": 8.0, "strength": "strong"},
    "telegram_bot": {"weight": 8.0, "strength": "strong"},
    "firebase_project": {"weight": 5.0, "strength": "medium"},
    "uni_appid": {"weight": 5.0, "strength": "medium"},
}

_DEFAULT_WEIGHT = 1.0


def get_weight(kind: str) -> float:
    """该 kind 的连边权重；未注册默认 1.0（绝不崩）。"""
    return float(WEIGHT_CONFIG.get(kind, {}).get("weight", _DEFAULT_WEIGHT))


def is_strong(kind: str) -> bool:
    """该 kind 是否强指纹（高区分度）；未注册默认 False。"""
    return WEIGHT_CONFIG.get(kind, {}).get("strength") == "strong"
