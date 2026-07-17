"""授权档：下载远程配置对象的原始字节。

**门控由调用方（pipeline 阶段）负责**——本模块只在被明确调用时下载，且自带超时 + 响应体大小硬帽 +
Content-Length 预检。任何失败（无 requests / 连接错 / 非 200 / 超大）→ ``ok=False`` + error，绝不抛。
下到的是**未信任的第三方字节**：只存不执行，交给 ``config.decode`` 离线多层解码。
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 配置对象应很小；硬帽防超大响应耗尽内存/带宽
_CHUNK = 8192


def _target_is_safe(url: str) -> tuple[bool, str]:
    """★SSRF 防护：URL 来自对手可控的 APK 字符串——解析其 host，凡命中回环/私网/链路本地（含云元数据
    169.254.169.254）/保留/多播段一律拒连（防被诱导访问分析机内网或窃取云 IAM 凭据）。

    IP 字面量直接判；域名走 getaddrinfo，**全部**解析地址都须安全才放行（任一落内网即拒）。解析失败 → 拒。
    残留 DNS-rebinding（解析判公网、连接时重绑内网）需自定义 adapter 校验实连 IP，本层配合 allow_redirects
    =False 已堵住直连与重定向两条主路径。绝不抛。
    """
    host = urlsplit(url).hostname if isinstance(url, str) else None
    if not host:
        return False, "无法解析 host"
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        candidates.append(ipaddress.ip_address(host))  # host 是 IP 字面量
    except ValueError:
        try:
            for info in socket.getaddrinfo(host, None):
                try:
                    candidates.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        except (socket.gaierror, OSError):
            return False, "DNS 解析失败"
    if not candidates:
        return False, "无可解析地址"
    for ip in candidates:
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False, f"目标解析到受限地址 {ip}（内网/回环/元数据段）"
    return True, ""


@dataclass(frozen=True)
class FetchResult:
    """一次下载的结果。``ok`` 时 ``raw`` 为字节；否则 ``error`` 记原因（不抛给调用方）。"""

    url: str
    ok: bool
    raw: bytes | None
    status: int | None
    error: str | None


def fetch_config_object(
    url: str, *, timeout: float = _DEFAULT_TIMEOUT, max_bytes: int = _DEFAULT_MAX_BYTES
) -> FetchResult:
    """流式下载 ``url`` 的原始字节，带超时 + 大小硬帽。任何失败 → ok=False + error，绝不抛。"""
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        return FetchResult(url, False, None, None, "非 http(s) URL")
    safe, why = _target_is_safe(url)
    if not safe:
        logger.warning("[remote_config] 拒绝下载（SSRF 防护）%s：%s", url, why)
        return FetchResult(url, False, None, None, f"目标被 SSRF 防护拒绝：{why}")
    try:
        import requests
    except ImportError:
        return FetchResult(url, False, None, None, "requests 未安装，无法下载")

    # ★墙钟总预算：scalar timeout 只管单次 recv 间隔，慢速滴流可事实挂死；额外设总时限硬顶。
    deadline = time.monotonic() + max(timeout * 3, 30.0)
    resp = None
    try:
        # ★allow_redirects=False：对手服务器可 302 重定向到内网/元数据（SSRF），禁跟随（只下直连 URL）。
        resp = requests.get(url, timeout=timeout, stream=True, allow_redirects=False)
        status = resp.status_code
        if status != 200:
            return FetchResult(url, False, None, status, f"HTTP {status}")
        declared = resp.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            return FetchResult(url, False, None, status, f"响应体过大（声明 {declared}B > 上限 {max_bytes}B）")
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(_CHUNK):
            if time.monotonic() > deadline:
                return FetchResult(url, False, None, status, "下载总时限超限，已中止（慢速滴流防护）")
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                return FetchResult(url, False, None, status, f"响应体超上限 {max_bytes}B，已中止下载")
            chunks.append(chunk)
        return FetchResult(url, True, b"".join(chunks), status, None)
    except Exception as exc:  # noqa: BLE001 — requests 各类异常 + 读取异常一律降级，绝不抛
        logger.warning("[remote_config] 下载失败 %s：%s", url, type(exc).__name__)
        return FetchResult(url, False, None, None, f"下载异常：{type(exc).__name__}")
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:  # noqa: BLE001 — 关闭失败无关紧要
                pass


__all__ = ["FetchResult", "fetch_config_object"]
