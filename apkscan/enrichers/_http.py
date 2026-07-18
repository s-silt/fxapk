"""富化器 HTTP 响应体硬上限——防上游 / 代理 / 被劫持响应返回巨型 JSON/文本，在 response.json()/.text
前就把分析机内存撑爆。

requests 不带 stream 时会在 get() 里直接把整个 body 下进 resp.content；故必须 stream=True + 有界读，
在下载阶段就设累计字节硬帽、超限即中止连接，而不是下完再限记录数（那时内存已炸）。
"""

from __future__ import annotations

from typing import Any

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
    """requests.Session：GET 响应体流式读取并硬限 _MAX_RESPONSE_BYTES（default session 用它，注入的假 session 不受影响）。"""

    def get(self, url: str | bytes, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        kwargs.setdefault("stream", True)
        return _cap_body(super().get(url, **kwargs), _MAX_RESPONSE_BYTES)


def capped_get(url: str, **kwargs: Any) -> requests.Response:
    """requests.get 的有界替身：body 超 _MAX_RESPONSE_BYTES 即中止（用于不走共享 session 的直连富化器）。"""
    kwargs.setdefault("stream", True)
    return _cap_body(requests.get(url, **kwargs), _MAX_RESPONSE_BYTES)
