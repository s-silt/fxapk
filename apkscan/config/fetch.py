"""授权档：下载远程配置对象的原始字节。

**门控由调用方（pipeline 阶段）负责**——本模块只在被明确调用时下载，且自带超时 + 墙钟总时限 + 响应体
大小硬帽 + Content-Length 预检。任何失败（无 requests / 连接错 / 非 200 / 超大 / 被 SSRF 防护拒）→
``ok=False`` + error，绝不抛。下到的是**未信任的第三方字节**：只存不执行，交给 ``config.decode`` 离线解码。

★SSRF 双层防护（URL 来自对手可控的 APK 字符串）：
1. **预解析校验** ``_target_is_safe``：连接前把 host 解析成 IP，凡内网/回环/链路本地(含云元数据
   169.254.169.254)/保留/多播即拒；并 ``allow_redirects=False`` 禁 302→内网。
2. **连接层实连 IP 校验** ``_assert_peer_public``：requests 会**再解析一次**——恶意 DNS 可第一次返公网
   IP 骗过预检、第二次返内网 IP(DNS-rebinding/TOCTOU)。故在 urllib3 建立 TCP socket 后、TLS 握手与 HTTP
   请求发出**之前**，校验**实际连接的 peer IP**；命中受限段即掐断，彻底堵死 rebinding。urllib3 内部 API
   变动时优雅降级为仅预解析校验（不崩、不regress到无防护）。
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 配置对象应很小；硬帽防超大响应耗尽内存/带宽
_CHUNK = 8192

_IpAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


def _ip_is_blocked(addr: _IpAddr) -> bool:
    """是否受限地址（内网/回环/链路本地含云元数据/保留/多播/未指定）——SSRF 目标黑名单的单一判据。"""
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def _target_is_safe(url: str) -> tuple[bool, str]:
    """★SSRF 预解析校验：解析 host 的所有地址，任一落受限段即拒（防被诱导访问内网/窃取云 IAM 凭据）。

    IP 字面量直接判；域名走 getaddrinfo，**全部**解析地址都须安全才放行。解析失败 → 拒。
    这是第一层；DNS-rebinding（预检判公网、连接时返内网）由连接层 ``_assert_peer_public`` 兜底。绝不抛。
    """
    host = urlsplit(url).hostname if isinstance(url, str) else None
    if not host:
        return False, "无法解析 host"
    candidates: list[_IpAddr] = []
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
        if _ip_is_blocked(ip):
            return False, f"目标解析到受限地址 {ip}（内网/回环/元数据段）"
    return True, ""


class _BlockedPeerError(Exception):
    """连接层校验：实际连接的 peer IP 落受限段（DNS-rebinding 防护）。经 urllib3/requests 包装成连接错误。"""


def _assert_peer_public(sock: Any) -> None:  # noqa: ANN401 — urllib3 socket，鸭子类型
    """校验一个**已连接** socket 的对端 IP 非受限段；命中即关闭 + 抛 _BlockedPeerError（TLS/HTTP 前）。

    拿不到 peer（getpeername 失败）→ 不阻断（预解析校验已把关），也不误杀。绝不因自身逻辑抛非
    _BlockedPeerError 的异常。
    """
    try:
        ip_text = sock.getpeername()[0]
        addr = ipaddress.ip_address(ip_text)
    except (OSError, IndexError, TypeError, ValueError):
        return
    if _ip_is_blocked(addr):
        try:
            sock.close()
        except OSError:
            pass
        raise _BlockedPeerError(f"连接到受限地址 {addr}（DNS-rebinding 防护）")


# --------------------------------------------------------------------------- #
# IP 钉定传输：在 urllib3 建立 TCP socket 后、TLS/HTTP 之前校验实连 peer IP。
# urllib3 内部 API 变动时整体降级（_GUARDED_ADAPTER_CLS=None → 仅预解析校验）。
# --------------------------------------------------------------------------- #
try:
    from requests.adapters import HTTPAdapter as _RequestsHTTPAdapter
    from urllib3.connection import HTTPConnection as _U3HTTPConn
    from urllib3.connection import HTTPSConnection as _U3HTTPSConn
    from urllib3.connectionpool import HTTPConnectionPool as _U3HTTPPool
    from urllib3.connectionpool import HTTPSConnectionPool as _U3HTTPSPool
    from urllib3.poolmanager import PoolManager as _U3PoolManager

    class _PeerGuardMixin:
        def _new_conn(self):  # type: ignore[no-untyped-def]
            sock = super()._new_conn()  # type: ignore[misc]  # 已连接的原始 TCP socket（TLS 尚未包装）
            _assert_peer_public(sock)
            return sock

    class _GuardedHTTPConnection(_PeerGuardMixin, _U3HTTPConn):
        pass

    class _GuardedHTTPSConnection(_PeerGuardMixin, _U3HTTPSConn):
        pass

    class _GuardedHTTPConnectionPool(_U3HTTPPool):
        ConnectionCls = _GuardedHTTPConnection  # type: ignore[assignment]  # 混入 mixin 的动态子类

    class _GuardedHTTPSConnectionPool(_U3HTTPSPool):
        ConnectionCls = _GuardedHTTPSConnection  # type: ignore[assignment]

    class _GuardedPoolManager(_U3PoolManager):
        def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
            super().__init__(*args, **kwargs)
            self.pool_classes_by_scheme = {
                "http": _GuardedHTTPConnectionPool,
                "https": _GuardedHTTPSConnectionPool,
            }

    class _GuardedAdapter(_RequestsHTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):  # type: ignore[no-untyped-def]
            self.poolmanager = _GuardedPoolManager(
                num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
            )

    _GUARDED_ADAPTER_CLS: type | None = _GuardedAdapter
except Exception:  # noqa: BLE001 — urllib3 内部结构变动 → 降级到预解析校验（不崩、不 regress 到无防护）
    _GUARDED_ADAPTER_CLS = None


def _build_guarded_session() -> Any:  # noqa: ANN401 — requests.Session | None（懒加载）
    """构建挂了 IP 钉定 adapter 的会话（http+https，禁重试）。requests 缺失 → None；挂载失败 → 普通会话。"""
    try:
        import requests
    except ImportError:
        return None
    session = requests.Session()
    if _GUARDED_ADAPTER_CLS is not None:
        try:
            adapter = _GUARDED_ADAPTER_CLS(max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        except Exception:  # noqa: BLE001 — 挂载失败仍返回普通会话（预解析校验仍生效）
            logger.warning("[remote_config] 挂载 IP 钉定 adapter 失败，回落普通会话", exc_info=True)
    return session


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
    """流式下载 ``url`` 的原始字节，带超时 + 墙钟总时限 + 大小硬帽 + SSRF 双层防护。任何失败 → ok=False。"""
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        return FetchResult(url, False, None, None, "非 http(s) URL")
    safe, why = _target_is_safe(url)  # 第一层：预解析校验
    if not safe:
        logger.warning("[remote_config] 拒绝下载（SSRF 预解析防护）%s：%s", url, why)
        return FetchResult(url, False, None, None, f"目标被 SSRF 防护拒绝：{why}")
    session = _build_guarded_session()  # 第二层：连接层实连 IP 校验（防 DNS-rebinding）
    if session is None:
        return FetchResult(url, False, None, None, "requests 未安装，无法下载")

    # ★墙钟总预算：scalar timeout 只管单次 recv 间隔，慢速滴流可事实挂死；额外设总时限硬顶。
    deadline = time.monotonic() + max(timeout * 3, 30.0)
    resp = None
    try:
        # ★allow_redirects=False：对手服务器可 302 重定向到内网/元数据（SSRF），禁跟随（只下直连 URL）。
        resp = session.get(url, timeout=timeout, stream=True, allow_redirects=False)
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
    except Exception as exc:  # noqa: BLE001 — requests 各类异常（含 rebinding 掐断）一律降级，绝不抛
        logger.warning("[remote_config] 下载失败 %s：%s", url, type(exc).__name__)
        return FetchResult(url, False, None, None, f"下载异常：{type(exc).__name__}")
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:  # noqa: BLE001 — 关闭失败无关紧要
                pass
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


__all__ = ["FetchResult", "fetch_config_object"]
