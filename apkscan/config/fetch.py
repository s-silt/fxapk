"""授权档：下载远程配置对象的原始字节。

**门控由调用方（pipeline 阶段）负责**——本模块只在被明确调用时下载，且自带超时 + 响应体大小硬帽 +
Content-Length 预检。任何失败（无 requests / 连接错 / 非 200 / 超大）→ ``ok=False`` + error，绝不抛。
下到的是**未信任的第三方字节**：只存不执行，交给 ``config.decode`` 离线多层解码。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 配置对象应很小；硬帽防超大响应耗尽内存/带宽
_CHUNK = 8192


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
    try:
        import requests
    except ImportError:
        return FetchResult(url, False, None, None, "requests 未安装，无法下载")

    resp = None
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        status = resp.status_code
        if status != 200:
            return FetchResult(url, False, None, status, f"HTTP {status}")
        declared = resp.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            return FetchResult(url, False, None, status, f"响应体过大（声明 {declared}B > 上限 {max_bytes}B）")
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(_CHUNK):
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
