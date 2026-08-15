"""富化器 HTTP 响应体硬上限——防上游 / 代理 / 被劫持响应返回巨型 JSON/文本，在 response.json()/.text
前就把分析机内存撑爆。

requests 不带 stream 时会在 get() 里直接把整个 body 下进 resp.content；故必须 stream=True + 有界读，
在下载阶段就设累计字节硬帽、超限即中止连接，而不是下完再限记录数（那时内存已炸）。
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

#: 单次富化响应体硬上限（16MB）：远超任何合法 RDAP / Shodan / FOFA / certspotter JSON，
#: 拦住异常 / 被劫持 / 压缩炸弹式的巨型响应。
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class ResponseTooLarge(requests.RequestException):
    """响应体超过 _MAX_RESPONSE_BYTES——作为 requests 异常上抛，被既有 provider 错误处理捕获。"""


def _cap_body(resp: requests.Response, max_bytes: int) -> requests.Response:
    """流式读 resp body、累计超 max_bytes 即中止连接；回填 _content 让 resp.json()/.text/.status_code 照常用。"""
    total = 0
    chunks: list[bytes] = []
    try:
        for chunk in resp.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ResponseTooLarge(f"富化响应体超上限 {max_bytes} 字节，中止（疑异常/被劫持响应）")
            chunks.append(chunk)
    finally:
        resp.close()
    resp._content = b"".join(chunks)  # requests 内部字段：预设后 .content/.json()/.text 直接可用
    resp._content_consumed = True  # type: ignore[attr-defined]
    return resp


class CappedSession(requests.Session):
    """requests.Session：GET/POST 响应体流式读取并硬限 _MAX_RESPONSE_BYTES（default session 用它，
    注入的假 session 不受影响）。

    ★POST 同样限体（codex 复审 B1）：走 session.post 的源（如 Quake）此前绕过 body cap——被劫持/异常
    上游返回巨型 JSON 会在 .json() 前灌爆内存，正是本模块要防的场景。
    """

    def get(self, url: str | bytes, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        kwargs.setdefault("stream", True)
        return _cap_body(super().get(url, **kwargs), _MAX_RESPONSE_BYTES)

    def post(self, url: str | bytes, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        kwargs.setdefault("stream", True)
        return _cap_body(super().post(url, **kwargs), _MAX_RESPONSE_BYTES)


def capped_get(url: str, **kwargs: Any) -> requests.Response:
    """requests.get 的有界替身：body 超 _MAX_RESPONSE_BYTES 即中止（用于不走共享 session 的直连富化器）。"""
    kwargs.setdefault("stream", True)
    return _cap_body(requests.get(url, **kwargs), _MAX_RESPONSE_BYTES)


def capped_post(url: str, **kwargs: Any) -> requests.Response:
    """requests.post 的有界替身：body 超 _MAX_RESPONSE_BYTES 即中止（明文 ip-api /batch 等 POST 源用）。"""
    kwargs.setdefault("stream", True)
    return _cap_body(requests.post(url, **kwargs), _MAX_RESPONSE_BYTES)


class _CappedRequests:
    """裸 ``requests`` 模块的有界替身：``.get`` / ``.post`` 均流式限体。

    供**转发 http 客户端**的直连富化器（asn/dns/rdap/icp）在生产用——把模块级 ``requests`` 符号绑成
    本 shim，即让所有走该符号的联网调用自动限体；测试仍可 ``monkeypatch.setattr(mod, "requests", fake)``
    覆盖它注入自己的假响应（fake 无需支持流式，因为本 shim 只在生产真实路径上生效）。
    """

    get = staticmethod(capped_get)
    post = staticmethod(capped_post)


#: 模块级单例：绑给富化器的 ``requests`` 符号即全局限体（见 _CappedRequests）。
capped_requests = _CappedRequests()


# --------------------------------------------------------------------------- #
# 重定向 SSRF 防护（用于会跟随第三方 3xx 的源，如 RDAP 经 rdap.org bootstrap 跳各注册局）
# --------------------------------------------------------------------------- #
#: 手动跟随重定向的最大跳数。
_MAX_REDIRECTS = 5
#: 视为重定向的 HTTP 状态码。
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


class SSRFBlocked(requests.RequestException):
    """重定向目标解析到私网/保留地址——拒绝，防敌意 referral 把请求引向内网/云元数据端点（169.254.169.254 等）。"""


def _host_is_public(host: str) -> bool:
    """host 解析出的**全部** IP 均为公网可路由地址才算安全；任一私网/环回/链路本地/保留/多播/未指定 → 不安全。

    ★覆盖边界（如实标注）：这是**预解析**校验——校验通过到 requests 真正连接之间存在 DNS 重绑定 TOCTOU 窗口
    （requests 会再解析一次，可能拿到不同 IP）。完整防护需固定 IP 连接 + 保留 Host 头，本工具威胁模型下
    （入口 rdap.org 固定、referral 命中概率低）取预解析拒绝为相称缓解；字面私网 IP（如元数据端点）无 DNS、直接命中。
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, ValueError):
        return False  # 解析不了 → 保守拒绝（绝不放行未知目标）
    saw = False
    for info in infos:
        raw = str(info[4][0])
        try:
            addr = ipaddress.ip_address(raw.split("%", 1)[0])  # 去 IPv6 scope id
        except ValueError:
            return False
        saw = True
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return saw


def guarded_get(client: Any, url: str, *, timeout: Any = None,
                max_redirects: int = _MAX_REDIRECTS, **kwargs: Any) -> requests.Response:
    """经 ``client``（须有 ``.get``）请求 ``url`` 并**手动**跟随重定向，每个重定向目标先做 SSRF 校验。

    ★仅对**重定向目标**（hop>0）校验 host——初始 URL 由调用方给定（RDAP 为固定可信 rdap.org、非上游可控），
    不做校验；这也让离线测试（fake 返回非重定向）不触发任何 DNS 解析。生产走 ``capped_requests``（body 限体），
    测试可注入 fake。``allow_redirects`` 恒 False（自己逐跳跟随，才能在跟随前拦截）。
    """
    current = url
    for hop in range(max_redirects + 1):
        if hop > 0:
            host = urlparse(current).hostname
            if not host or not _host_is_public(host):
                raise SSRFBlocked(f"拒绝跟随重定向到私网/保留/不可解析目标：{current!r}")
        resp = client.get(current, timeout=timeout, allow_redirects=False, **kwargs)
        status = getattr(resp, "status_code", 200)
        location = None
        if status in _REDIRECT_STATUS:
            headers = getattr(resp, "headers", None) or {}
            location = headers.get("Location") or headers.get("location")
        if not location:
            return resp
        current = urljoin(current, location)
    raise SSRFBlocked(f"重定向次数超过 {max_redirects}，中止：{url!r}")
