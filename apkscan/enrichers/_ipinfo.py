"""共享 IP 归属查询：单 IP → ISP / 机构(云厂商 / IDC) / ASN / 国家。

把 asn.py 里对单个 IP 的 ip-api.com 查询逻辑抽成可复用的模块级函数
``lookup_ip(ip, *, http=...) -> dict``，供 asn（IP 富化器）与 dns（域名解析后对每个
A 记录 IP 查托管）共用，避免重复造轮子。

本模块只负责**一次网络查询 + 字段提取**，不含缓存与限速：
- 缓存：由各调用方（asn / dns）按自家缓存键自行管理。
- 限速：调用方在调用前自行 ``_respect_rate_limit``（ip-api 免费档 45/min 硬限）。

⚠️ 明文 HTTP：ip-api 免费档不支持 HTTPS（HTTPS 需付费 key）。仅对"建议调证"端点查询
已缩小暴露面（见 asn.py 注释）。

错误处理（符合规范）：网络/HTTP/解析异常向上抛，由调用方 ``enrich`` 统一转 ok=False；
接口语义失败（``status != "success"``）以 ValueError 抛出。
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
IPINFO_TIMEOUT = 8

#: ip-api 免费接口地址模板与需要的字段（明文 HTTP，见模块 docstring）。
IPINFO_API_URL = "http://ip-api.com/json/{ip}"
IPINFO_FIELDS = "status,country,isp,org,as,query"


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _extract(payload: dict[str, Any]) -> dict[str, str | None]:
    """从 ip-api 返回 JSON 提取关心字段。

    - ``isp``：网络服务商。
    - ``org``：归属机构（常为云厂商 / IDC）。
    - ``asn``：ASN（含编号与名称，源字段名为 ``as``）。
    - ``country``：国家。
    """
    return {
        "isp": _to_str(payload.get("isp")),
        "org": _to_str(payload.get("org")),
        "asn": _to_str(payload.get("as")),
        "country": _to_str(payload.get("country")),
    }


def lookup_ip(ip: str, *, http: Any = None, timeout: int = IPINFO_TIMEOUT) -> dict[str, str | None]:
    """对单个 IP 查 ip-api，返回 ``{isp, org, asn, country}``。

    :param http: requests 兼容模块（须有 ``get(url, **kwargs)``）。
        默认用本模块导入的 ``requests``；显式传入便于让 asn 把自己（已被测试 monkeypatch）
        的 requests 透传进来，保持既有 mock 路径不变。
    :raises ValueError: 接口返回非对象 / ``status != "success"``。
    :raises Exception: 网络/HTTP/解析异常（如 timeout、4xx/5xx）原样向上抛。
    """
    client = http if http is not None else requests

    url = IPINFO_API_URL.format(ip=ip)
    resp = client.get(url, params={"fields": IPINFO_FIELDS}, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()

    if not isinstance(payload, dict):
        raise ValueError(f"ip-api 返回非对象：{type(payload).__name__}")

    status = payload.get("status")
    if status != "success":
        message = payload.get("message") or status or "unknown"
        raise ValueError(f"ip-api 查询未成功：{message}")

    return _extract(payload)
