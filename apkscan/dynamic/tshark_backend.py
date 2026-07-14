"""tshark 可选深度后端：用 Wireshark 的 ``tshark`` 从 pcap 抽 pcap_ingest（纯 stdlib）抓不到的深度信号。

首个信号 = **明文 HTTP**（Host / URL / method / UA）：涉诈 App 常用明文 HTTP 下发配置、上报设备信息，
而 pcap_ingest 只抽 IP:port / TLS SNI / DNS / QUIC，不解 HTTP。tshark 的 HTTP dissector 远强于手搓，且
``-T fields`` 的 TSV 输出格式稳定、可离线 mock 测。

★tshark 是**可选外部工具**（非 Python 依赖）：不在 PATH → 静默禁用（保住模块"零依赖 / 零环境"），
运行超时 / 出错 / 输出畸形 → 降级为空。绝不抛。
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import sys
import tempfile
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
    """跑 ``tshark -Y http.request -T fields ...`` 抽明文 HTTP 请求 → TSV 文本。tshark 缺/超时/出错 → None。

    ``-E occurrence=f``：同帧多值字段只取首次（否则 tshark 逗号聚合会让 host="a,b"）。stdout 落临时文件、
    只读回 _MAX_OUTPUT 字节（内存有界，绝不 OOM）；UTF-8 解码（tshark 全平台输出 UTF-8，errors=replace 永不抛）；
    达上限即丢拦腰截断的末行（防半截假域名）。
    """
    bin_ = shutil.which("tshark")
    if not bin_:
        return None
    cmd = [bin_, "-r", str(pcap_path), "-Y", "http.request", "-T", "fields", "-E", "occurrence=f"]
    for f in _HTTP_FIELDS:
        cmd += ["-e", f]
    try:
        with tempfile.TemporaryFile() as tmp:
            proc = subprocess.run(
                cmd,
                stdout=tmp,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
                creationflags=(subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0),
            )
            if proc.returncode != 0:
                logger.warning("[tshark] 非零退出码 %s（降级继续；可能坏 pcap / 不支持的格式）", proc.returncode)
            tmp.seek(0)
            raw = tmp.read(_MAX_OUTPUT)  # 读侧封顶 → 内存有界
    except (subprocess.TimeoutExpired, OSError, ValueError):
        logger.warning("[tshark] 运行超时/失败（降级为空）", exc_info=True)
        return None
    text = raw.decode("utf-8", "replace")
    if len(raw) >= _MAX_OUTPUT:  # 达上限 = 可能被截断 → 丢拦腰末行（rfind 无 \n 得空串，安全降级）
        text = text[: text.rfind("\n") + 1]
    return text


def parse_http_fields(text: str) -> list[HttpRequest]:
    """解析 tshark ``-T fields`` 的 TSV（每行一请求、列序见 _HTTP_FIELDS，缺字段留空）→ HttpRequest 列表。绝不抛。"""
    out: list[HttpRequest] = []
    if not isinstance(text, str):
        return out
    n = len(_HTTP_FIELDS)
    for line in text.splitlines():
        if len(out) >= _MAX_REQUESTS:
            break
        if not line.strip():
            continue
        cols = line.split("\t")
        host = cols[0].strip() if cols else ""
        if not host:  # 非 HTTP / tshark 没解出 host → 跳过
            continue
        method = cols[1].strip() if len(cols) > 1 else ""
        # ★tshark -T fields 不转义字段值里的 tab：URI/UA 内嵌 tab 会致列溢出、后续列错位。列数≠预期时，
        #   uri/ua/ip/port 一律不可信 → 置空（host 最左、method 受 dissector 方法名约束，仍可信保留）。
        uri = ua = dst_ip = dst_port = ""
        if len(cols) == n:
            uri, ua, dst_ip, dst_port = cols[2].strip(), cols[3].strip(), cols[4].strip(), cols[5].strip()
            try:  # dst_ip 须合法 IP、dst_port 须纯数字，否则置空（防污染证据）
                ipaddress.ip_address(dst_ip)
            except ValueError:
                dst_ip = ""
            if not dst_port.isdigit():
                dst_port = ""
        out.append(HttpRequest(host=host, method=method, uri=uri, user_agent=ua, dst_ip=dst_ip, dst_port=dst_port))
    return out


def extract_http(pcap_path: str) -> list[HttpRequest]:
    """跑 tshark 抽 pcap 的明文 HTTP 请求。tshark 缺/失败 → 空列表。绝不抛。"""
    text = run_tshark_http(pcap_path)
    if text is None:
        return []
    return parse_http_fields(text)


def _normalize_host(raw: str) -> tuple[str, str]:
    """Host 头 → (value, kind)：剥 :port、小写、去尾点；IP 字面量 → kind=ip，否则 domain。坏/空 → ("","")。

    Host 头可能是 IP 字面量、带 ":port"、大小写不一、含尾点（``a.com.``）——不归一则 dedup 键与端点 value 都错。
    """
    h = raw.split(",", 1)[0].strip()  # 逗号聚合兜底（源头已 occurrence=f）
    if not h:
        return "", ""
    if h.startswith("["):  # IPv6 字面量 [::1]:8080 → 取括号内
        h = (h[1 : h.find("]")] if "]" in h else h.strip("[]"))
    elif h.count(":") == 1:  # host:port → 末段全数字才当端口剥掉（IPv6 无括号有多冒号，不误剥）
        left, _, right = h.rpartition(":")
        if right.isdigit():
            h = left
    h = h.strip().lower().rstrip(".")
    if not h:
        return "", ""
    try:
        ipaddress.ip_address(h)
        return h, "ip"
    except ValueError:
        return h, "domain"


def to_endpoints(requests: list[HttpRequest], observed_at: float | None = None) -> list[Endpoint]:
    """把 HTTP 请求按归一化 Host 聚成端点（一 Host 一端点，snippet 附代表性 method/URI/UA）。

    明文 HTTP 后端是 pcap_ingest 抓不到的调证线索：mitm 看不到（若不过代理），但 tshark 直接从裸包解。
    端点标 ``is_cleartext=True``（定义上就是明文 HTTP）；Host 为 IP 字面量则 kind=ip、否则 domain。
    """
    by_host: dict[str, HttpRequest] = {}
    kinds: dict[str, str] = {}
    for r in requests:
        value, kind = _normalize_host(r.host)
        if not value:
            continue
        by_host.setdefault(value, r)  # 每归一化 Host 留首条作代表
        kinds[value] = kind
    endpoints: list[Endpoint] = []
    for value, rep in by_host.items():
        if len(endpoints) >= _MAX_ENDPOINTS:
            break
        url = f"http://{rep.host}{rep.uri}" if rep.uri.startswith("/") else value
        ua = f"（UA: {rep.user_agent}）" if rep.user_agent else ""
        snippet = (f"明文 HTTP {rep.method} {url} → {rep.dst_ip}:{rep.dst_port}{ua}").strip()
        endpoints.append(
            Endpoint(
                value=value,
                kind=kinds[value],
                evidences=[Evidence(source=_SOURCE, location="http", snippet=snippet[:200], observed_at=observed_at)],
                is_cleartext=True,
            )
        )
    return endpoints
