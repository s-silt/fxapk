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
from pathlib import Path

from apkscan.core.models import Endpoint, Evidence

logger = logging.getLogger(__name__)

_SOURCE = "runtime-tshark"
_SOURCE_DECRYPTED = "runtime-tls-decrypted"  # P2：NSS TLS Key Log 解密还原的应用层
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

#: P2 解密路径字段：HTTP/1.1 与 HTTP/2 成对（涉诈 App 常走 OkHttp/Cronet 的 h2）。列序即 TSV 列序；
#: 解析时按对合并（http.* 空则取 http2.* 对应伪头）。h2 伪头在 tshark 里去掉冒号：:authority→authority 等。
_DECRYPT_FIELDS = (
    "http.host",                # 0  HTTP/1.1 Host
    "http2.headers.authority",  # 1  HTTP/2 :authority
    "http.request.method",      # 2
    "http2.headers.method",     # 3  :method
    "http.request.uri",         # 4
    "http2.headers.path",       # 5  :path
    "http.user_agent",          # 6
    "http2.headers.user_agent", # 7
    "ip.dst",                   # 8
    "tcp.dstport",              # 9
)

#: NSS Key Log 行标签（RFC-ish 事实标准；用于校验 tls.keys 确是 keylog 而非任意文件）。
_NSS_KEYLOG_LABELS = frozenset({
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
})


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


# ---------------------------------------------------------------------------
# P2：NSS TLS Key Log 解密——用授权插桩落下的 tls.keys 解密 floor.pcap 的 TLS，
#     抽出加密应用层（HTTP/1.1-over-TLS + HTTP/2）的真实业务后端。
#     ★门控：仅当 keylog 文件显式存在且确是 NSS Key Log 时才解密——密钥出自授权设备/App 插桩，
#       其存在即授权信号；消费端只用已获得的 keylog 解自己抓的 pcap（与 Wireshark 同性质）。
# ---------------------------------------------------------------------------
def _looks_like_keylog(keylog_path: Path) -> bool:
    """前 200 行内出现任一 NSS Key Log 标签（CLIENT_RANDOM 等）→ True。避免把任意文件当 keylog 喂给 tshark。"""
    try:
        with open(keylog_path, encoding="utf-8", errors="replace") as fh:
            for _ in range(200):
                line = fh.readline(4096)  # ★每行封顶 4096B：防病态单行大文件（无换行）readline 全量入内存 OOM
                if not line:
                    break
                if line.split(" ", 1)[0].strip() in _NSS_KEYLOG_LABELS:
                    return True
    except OSError:
        logger.debug("[tshark] 读 keylog 失败（按非 keylog 处理）", exc_info=True)
    return False


def run_tshark_decrypt(pcap_path: str, keylog_path: str, timeout: float = _TSHARK_TIMEOUT) -> str | None:
    """用 NSS Key Log 解密 pcap 的 TLS，跑 ``tshark -o tls.keylog_file:<keys> -Y "http.request or http2..."``
    抽解密后 HTTP/1.1+HTTP/2 请求 → TSV。tshark 缺 / keylog 无效或非 NSS / 超时 / 出错 → None（绝不抛）。

    内存/超时/截断防护同 :func:`run_tshark_http`。keylog 校验：文件存在、非空、且确含 NSS 标签才放行。
    """
    bin_ = shutil.which("tshark")
    if not bin_:
        return None
    kp = Path(keylog_path)
    try:
        if not kp.is_file() or kp.stat().st_size == 0 or not _looks_like_keylog(kp):
            return None  # 无有效 NSS keylog → 不解密（门控：无密钥不动 TLS）
    except OSError:
        return None
    # ★-o pref 值用正斜杠：tshark 在 Windows 上对反斜杠的 pref 值可能解析异常（-r 是普通文件参数、反斜杠无碍）。
    keylog_arg = kp.as_posix()
    # 先试 tls.keylog_file（Wireshark 3.0+）；旧版（<3.0，协议名还是 ssl，tls.keylog_file 为未知 pref →
    # 非零退出且空产出）回退试 ssl.keylog_file。不与 tls 并传，避免现代 Wireshark 因未知 ssl 别名破功。
    rc, raw = _run_decrypt_once(bin_, pcap_path, "tls.keylog_file", keylog_arg, timeout)
    if rc is None:
        return None  # 超时/子进程失败 → 降级为空
    if rc != 0 and not raw:
        logger.warning("[tshark] tls.keylog_file 非零且空产出，回退试 ssl.keylog_file（疑似 Wireshark <3.0）")
        rc2, raw2 = _run_decrypt_once(bin_, pcap_path, "ssl.keylog_file", keylog_arg, timeout)
        if rc2 is not None and raw2:
            rc, raw = rc2, raw2
    if rc != 0:
        logger.warning("[tshark] 解密路径非零退出码 %s（降级继续）", rc)
    text = raw.decode("utf-8", "replace")
    if len(raw) >= _MAX_OUTPUT:  # 达上限 = 可能被截断 → 丢拦腰末行
        text = text[: text.rfind("\n") + 1]
    return text


def _run_decrypt_once(
    bin_: str, pcap_path: str, pref_name: str, keylog_arg: str, timeout: float
) -> tuple[int | None, bytes]:
    """跑一次解密 tshark（``-o <pref_name>:<keylog>``）→ (returncode, raw_bytes)；超时/OSError → (None, b"")。

    stdout 落临时文件、读侧封顶 _MAX_OUTPUT（内存有界）。绝不抛。供 tls/ssl 两种 keylog pref 名复用。
    """
    cmd = [
        bin_, "-r", str(pcap_path),
        "-o", f"{pref_name}:{keylog_arg}",
        "-Y", "http.request or http2.headers.method",
        "-T", "fields", "-E", "occurrence=f",
    ]
    for f in _DECRYPT_FIELDS:
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
            tmp.seek(0)
            return proc.returncode, tmp.read(_MAX_OUTPUT)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        logger.warning("[tshark] 解密运行超时/失败（降级为空）", exc_info=True)
        return None, b""


def _col(cols: list[str], i: int) -> str:
    """安全取第 i 列并 strip；越界 → ""（防 tab 溢出/短行 IndexError）。"""
    return cols[i].strip() if i < len(cols) else ""


def parse_decrypted_fields(text: str) -> list[HttpRequest]:
    """解析解密 TSV（列序见 _DECRYPT_FIELDS；http.* 与 http2.* 成对，http.* 空则取 h2 伪头）→ HttpRequest 列表。绝不抛。"""
    out: list[HttpRequest] = []
    if not isinstance(text, str):
        return out
    n = len(_DECRYPT_FIELDS)
    for line in text.splitlines():
        if len(out) >= _MAX_REQUESTS:
            break
        if not line.strip():
            continue
        cols = line.split("\t")
        host = _col(cols, 0) or _col(cols, 1)  # HTTP/1.1 Host || HTTP/2 :authority
        if not host:  # 无 host/authority → 非请求或未解出 → 跳过
            continue
        method = _col(cols, 2) or _col(cols, 3)
        # tab 溢出防护同明文路径：列数≠预期时只信最左的 host/method（主机名/方法名不含 tab），其余置空。
        uri = ua = dst_ip = dst_port = ""
        if len(cols) == n:
            uri = _col(cols, 4) or _col(cols, 5)
            ua = _col(cols, 6) or _col(cols, 7)
            dst_ip, dst_port = _col(cols, 8), _col(cols, 9)
            try:
                ipaddress.ip_address(dst_ip)
            except ValueError:
                dst_ip = ""
            if not dst_port.isdigit():
                dst_port = ""
        out.append(HttpRequest(host=host, method=method, uri=uri, user_agent=ua, dst_ip=dst_ip, dst_port=dst_port))
    return out


def extract_decrypted_http(pcap_path: str, keylog_path: str) -> list[HttpRequest]:
    """用 keylog 解密 pcap 抽 HTTP/1.1+HTTP/2 请求。tshark 缺 / keylog 无效 / 失败 → 空列表。绝不抛。"""
    text = run_tshark_decrypt(pcap_path, keylog_path)
    if text is None:
        return []
    return parse_decrypted_fields(text)


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


def to_endpoints(
    requests: list[HttpRequest],
    observed_at: float | None = None,
    *,
    source: str = _SOURCE,
    is_cleartext: bool = True,
    scheme: str = "http",
    label: str = "明文 HTTP",
    location: str = "http",
) -> list[Endpoint]:
    """把 HTTP 请求按归一化 Host 聚成端点（一 Host 一端点，snippet 附代表性 method/URI/UA）。

    明文 HTTP 后端是 pcap_ingest 抓不到的调证线索：mitm 看不到（若不过代理），但 tshark 直接从裸包解。
    默认标 ``is_cleartext=True``（明文 HTTP）；Host 为 IP 字面量则 kind=ip、否则 domain。
    解密路径经 :func:`decrypted_to_endpoints` 复用此函数，仅换 source/scheme/label 且 is_cleartext=False。
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
        url = f"{scheme}://{rep.host}{rep.uri}" if rep.uri.startswith("/") else value
        ua = f"（UA: {rep.user_agent}）" if rep.user_agent else ""
        snippet = (f"{label} {rep.method} {url} → {rep.dst_ip}:{rep.dst_port}{ua}").strip()
        endpoints.append(
            Endpoint(
                value=value,
                kind=kinds[value],
                evidences=[Evidence(source=source, location=location, snippet=snippet[:200], observed_at=observed_at)],
                is_cleartext=is_cleartext,
            )
        )
    return endpoints


def decrypted_to_endpoints(requests: list[HttpRequest], observed_at: float | None = None) -> list[Endpoint]:
    """TLS 解密还原的 HTTP/1.1+HTTP/2 请求 → 端点：``is_cleartext=False``、来源标 TLS 解密、scheme=https。

    这是 pcap_ingest（只到 SNI）与明文 tshark 路径（只到明文 HTTP）都够不到的层——解密后才见 h2
    ``:authority``/``:path`` 的真实业务后端与 URL。
    """
    return to_endpoints(
        requests,
        observed_at,
        source=_SOURCE_DECRYPTED,
        is_cleartext=False,
        scheme="https",
        label="TLS 解密",
        location="tls-http",
    )
