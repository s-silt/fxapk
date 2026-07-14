"""tshark 可选深度后端：用 Wireshark 的 ``tshark`` 从 pcap 抽 pcap_ingest（纯 stdlib）抓不到的深度信号。

首个信号 = **明文 HTTP**（Host / URL / method / UA）：涉诈 App 常用明文 HTTP 下发配置、上报设备信息，
而 pcap_ingest 只抽 IP:port / TLS SNI / DNS / QUIC，不解 HTTP。tshark 的 HTTP dissector 远强于手搓，且
``-T fields`` 的 TSV 输出格式稳定、可离线 mock 测。

★tshark 是**可选外部工具**（非 Python 依赖）：不在 PATH → 静默禁用（保住模块"零依赖 / 零环境"），
运行超时 / 出错 / 输出畸形 → 降级为空。绝不抛。
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass

from apkscan.core.models import Endpoint, Evidence

logger = logging.getLogger(__name__)

_SOURCE = "runtime-tshark"
_TSHARK_TIMEOUT = 60.0  # tshark 子进程超时（秒）：大 pcap 给足但有上限
_MAX_OUTPUT = 4 * 1024 * 1024  # tshark stdout 上限（防超大 pcap 撑内存）
_MAX_REQUESTS = 5000  # 解析记录数上限
_MAX_ENDPOINTS = 500  # 产出端点数上限

#: tshark ``-T fields`` 抽取字段（顺序即 TSV 列序；默认 TAB 分隔）。
_HTTP_FIELDS = (
    "http.host",
    "http.request.method",
    "http.request.uri",
    "http.user_agent",
    "ip.dst",
    "tcp.dstport",
)


@dataclass
class HttpRequest:
    """tshark 从 pcap 解出的一条明文 HTTP 请求。"""

    host: str
    method: str = ""
    uri: str = ""
    user_agent: str = ""
    dst_ip: str = ""
    dst_port: str = ""


def has_tshark() -> bool:
    """PATH 上是否有 tshark（可选深度后端；缺则静默禁用）。"""
    return shutil.which("tshark") is not None


def run_tshark_http(pcap_path: str, timeout: float = _TSHARK_TIMEOUT) -> str | None:
    """跑 ``tshark -Y http.request -T fields ...`` 抽明文 HTTP 请求 → TSV 文本。tshark 缺/超时/出错 → None。"""
    bin_ = shutil.which("tshark")
    if not bin_:
        return None
    cmd = [bin_, "-r", str(pcap_path), "-Y", "http.request", "-T", "fields"]
    for f in _HTTP_FIELDS:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0),
        )
        return proc.stdout[:_MAX_OUTPUT]
    except (subprocess.TimeoutExpired, OSError, ValueError):
        logger.warning("[tshark] 运行超时/失败（忽略，降级为空）", exc_info=True)
        return None


def parse_http_fields(text: str) -> list[HttpRequest]:
    """解析 tshark ``-T fields`` 的 TSV（每行一请求、列序见 _HTTP_FIELDS，缺字段留空）→ HttpRequest 列表。绝不抛。"""
    out: list[HttpRequest] = []
    if not isinstance(text, str):
        return out
    for line in text.splitlines():
        if len(out) >= _MAX_REQUESTS:
            break
        if not line.strip():
            continue
        cols = line.split("\t")
        # 列不足补空；host 为空的行（非 HTTP 或 tshark 没解出 host）跳过。
        cols += [""] * (len(_HTTP_FIELDS) - len(cols))
        host = cols[0].strip()
        if not host:
            continue
        out.append(
            HttpRequest(
                host=host,
                method=cols[1].strip(),
                uri=cols[2].strip(),
                user_agent=cols[3].strip(),
                dst_ip=cols[4].strip(),
                dst_port=cols[5].strip(),
            )
        )
    return out


def extract_http(pcap_path: str) -> list[HttpRequest]:
    """跑 tshark 抽 pcap 的明文 HTTP 请求。tshark 缺/失败 → 空列表。绝不抛。"""
    text = run_tshark_http(pcap_path)
    if text is None:
        return []
    return parse_http_fields(text)


def to_endpoints(requests: list[HttpRequest], observed_at: float | None = None) -> list[Endpoint]:
    """把 HTTP 请求按 Host 聚成 domain 端点（一 Host 一端点，snippet 附代表性 method/URI/UA）。

    明文 HTTP 后端是 pcap_ingest 抓不到的调证线索：mitm 看不到（若不过代理），但 tshark 直接从裸包解。
    """
    by_host: dict[str, HttpRequest] = {}
    for r in requests:
        by_host.setdefault(r.host, r)  # 每 Host 留首条作代表（method/URI）
    endpoints: list[Endpoint] = []
    for host, rep in by_host.items():
        if len(endpoints) >= _MAX_ENDPOINTS:
            break
        url = f"http://{host}{rep.uri}" if rep.uri.startswith("/") else host
        ua = f"（UA: {rep.user_agent}）" if rep.user_agent else ""
        snippet = (f"明文 HTTP {rep.method} {url} → {rep.dst_ip}:{rep.dst_port}{ua}").strip()
        endpoints.append(
            Endpoint(
                value=host,
                kind="domain",
                evidences=[Evidence(source=_SOURCE, location="http", snippet=snippet[:200], observed_at=observed_at)],
            )
        )
    return endpoints
