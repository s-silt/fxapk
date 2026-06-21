"""主动探测富化器：对**国外·建议调证·公网 IP**做轻量侦查取证（opt-in，门控滴水不漏）。

★ 本模块是 apkscan 唯一**主动向目标发起连接**的富化器。海外服务器难直接调证，被动 OSINT
（Shodan/web-check）受限于"扫库时点"且未必覆盖该主机；本模块对授权目标做**仅侦查**的实时探测，
补全暴露面情报指引取证落点：开放端口/服务、TLS 证书主体、HTTP 指纹、暴露的后台路径。

合规硬边界（务必贯彻，逐条对应 enrich() 内的门控）：
- **opt-in 显式开关**：仅当环境变量 ``FXAPK_ACTIVE_RECON=1`` 时启用；未开 → 立即 ok=False
  返回，**绝不触网**（与其它 enricher 的 key 门控同档，但这是主动探测，门控更严）。
- **启动授权声明日志**：本进程首次对目标发起**仅侦查连接**（TCP/TLS/HTTP/路径）前，``logger.warning``
  打一条授权声明（操作者须在授权范围内使用），留痕可审计。注：为判定目标是否落在「仅公网 IP」范围内，
  对 domain 会**先做一次 DNS 解析**——该解析是名称查询（发往解析器、对目标主机零字节流量），不在本声明
  覆盖的"探测连接"之列，故排在声明之前（必须先解析出 IP 才能跑公网二次校验）。
- **仅国外 + 建议调证 + 公网 IP**：★「仅国外」+「仅建议调证」两道辖区/研判闸由**两遍富化编排
  担保**（见 pipeline._run_enrichment 的 _gate：active=True 仅对【国外 + effective_advice=建议调证】
  端点放行），**不在本模块内部**——故本 enricher **不得脱离两遍编排单独调用**。本模块 enrich() 内部
  仅做**与目标直接相关的二次自检**：domain 先解析为 IP；非公网（私网/回环/链路本地/保留/CGNAT/非全局）
  一律跳过；已知 CDN/基础设施域名跳过（非 App 自有后端，探测无价值且打到第三方头上）。
- **限速 + 超时预算**：每目标整体超时预算 + 单连接超时 + 进程级并发闸（信号量），避免对目标造成
  压力、也避免拖死 pipeline。
- **仅侦查，绝不利用**：只做 TCP connect（端口是否 listen）/ TLS 握手取证书 / HTTP HEAD-or-GET
  取响应头与标题与状态码 / 后台路径**只看状态码+标题**。绝不发 exploit payload、绝不提交任何
  凭据、绝不做认证爆破、绝不做全端口段扫描、绝不做 DoS。
- **错误隔离 + 不炸主流程**：每个子探测各自 try/except，单点失败只跳过该项；整体异常吞成
  ok=False，绝不抛、绝不裸 except、绝不在 try 里 swallow log（debug 记录）。

CVE/漏洞：本模块**不**做漏洞判定——已知漏洞方向由 Shodan 的 CPE→CVE 情报提供（见 enrichers/shodan）。
本模块只交付"暴露了什么"，研判"可能有什么洞"留给情报层，且仅作方向提示不含 exploit。
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
import threading
from typing import Any

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: opt-in 主开关（值为 "1" / "true" / "yes" / "on" 才启用，大小写不敏感）。未设/其它值 → 不探测。
_ENV_ENABLE = "FXAPK_ACTIVE_RECON"

#: 可选并发上限覆盖（进程级信号量；默认 _MAX_CONCURRENCY）。
_ENV_CONCURRENCY = "FXAPK_ACTIVE_RECON_CONCURRENCY"

#: curated 探测端口：常见 Web/管理后台/数据库/远程管理端口（**不是**全端口段扫描）。
#: 选取依据：诈骗 App 后端高频暴露面——Web(80/443/8080/8443/8888)、管理面板、数据库(3306/5432/
#: 6379/27017/9200)、远程管理(22/3389)、消息/缓存中间件。仅 connect 探活，不抓 banner 之外内容。
_CURATED_PORTS: tuple[int, ...] = (
    21,     # FTP
    22,     # SSH
    23,     # Telnet（暴露即高危信号）
    80,     # HTTP
    443,    # HTTPS
    445,    # SMB
    1433,   # MSSQL
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5601,   # Kibana
    6379,   # Redis（常未授权）
    8080,   # HTTP-alt / 管理面板
    8443,   # HTTPS-alt
    8888,   # 常见后台/Jupyter/面板
    9000,   # PHP-FPM / 管理面板 / Portainer
    9200,   # Elasticsearch（常未授权）
    27017,  # MongoDB（常未授权）
)

#: TCP connect 探测的单连接超时（秒）。
_CONNECT_TIMEOUT = 3.0

#: TLS 握手 + 取证书超时（秒）。
_TLS_TIMEOUT = 5.0

#: HTTP(S) 单请求超时（秒）。
_HTTP_TIMEOUT = 5.0

#: 每目标整体超时预算（秒）：所有子探测累计软上限，超了就停止后续探测（已得结果照常返回）。
_TARGET_BUDGET = 30.0

#: 进程级并发闸默认值（同时在探的连接数上限；避免一次扫一片目标时打爆本机/被目标限流）。
_MAX_CONCURRENCY = 8

#: HTTP 响应体读取上限（字节）：只为抽 <title>，不下载整页（避免大响应耗时/耗内存）。
_HTTP_BODY_CAP = 65536

#: 标题/响应头展示截断上限（防个别超长值刷爆报告）。
_MAX_TITLE_LEN = 200
_MAX_HEADER_LEN = 200

#: curated 暴露后台/敏感路径（**只看状态码+标题，绝不提交凭据/payload**）。
#: 选取依据：诈骗后台/运维面板/框架管理端常见入口；命中 200/302/401/403 即"存在该入口"的暴露信号。
_CURATED_PATHS: tuple[str, ...] = (
    # ---- 后台 / 管理端 / 监控（暴露即入口信号）----
    "/admin",
    "/login",
    "/api",
    "/actuator",        # Spring Boot Actuator（常泄露 env/heapdump）
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/druid",           # Druid 监控台（常未授权）
    "/swagger-ui.html",
    "/swagger",
    "/api-docs",
    "/v2/api-docs",
    "/openapi.json",
    "/phpmyadmin",
    "/console",
    "/dashboard",
    "/grafana",
    "/management",
    # ---- 暴露的敏感文件 / 误配（暴露本身即直接取证价值：源码/密钥/源站真IP/数据）----
    "/.env",            # DB凭据/APP_KEY/源站直连
    "/.git/config",     # 源码 + 硬编码密钥 + 源站真IP
    "/.git/HEAD",
    "/.svn/entries",    # SVN 源码泄露
    "/.DS_Store",       # 目录结构泄露
    "/phpinfo.php",     # 服务器环境/绝对路径/环境变量
    "/info.php",
    "/www.zip",         # 整站源码备份
    "/backup.sql",      # 数据库导出
    "/database.sql",
    "/.well-known/security.txt",
)

#: 探测后台路径时认为"该入口存在/有价值"的状态码（含鉴权拦截，恰恰证明入口存在）。
_INTERESTING_STATUS: frozenset[int] = frozenset({200, 201, 204, 301, 302, 401, 403, 405, 500})


# 进程级并发闸：模块级单例，跨所有端点共享（pipeline 按端点并发，多个 recon 实例共用同一把闸）。
_SEMAPHORE_LOCK = threading.Lock()
_SEMAPHORE: threading.BoundedSemaphore | None = None

# 授权声明日志只打一次（本进程首次实际探测前）。
_AUTH_NOTICE_LOCK = threading.Lock()
_auth_notice_emitted = False


def _enabled() -> bool:
    """opt-in 主开关是否开启（FXAPK_ACTIVE_RECON ∈ {1,true,yes,on}，大小写不敏感）。"""
    val = (os.environ.get(_ENV_ENABLE) or "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _concurrency() -> int:
    """并发闸大小（可被 FXAPK_ACTIVE_RECON_CONCURRENCY 覆盖；非法/越界回落默认）。"""
    raw = (os.environ.get(_ENV_CONCURRENCY) or "").strip()
    if not raw:
        return _MAX_CONCURRENCY
    try:
        n = int(raw)
    except ValueError:
        return _MAX_CONCURRENCY
    return n if 1 <= n <= 64 else _MAX_CONCURRENCY


def _semaphore() -> threading.BoundedSemaphore:
    """取进程级并发闸（首次按当前配置惰性建；之后复用，保证全局串行化探测量）。"""
    global _SEMAPHORE
    with _SEMAPHORE_LOCK:
        if _SEMAPHORE is None:
            _SEMAPHORE = threading.BoundedSemaphore(_concurrency())
        return _SEMAPHORE


def _emit_auth_notice_once() -> None:
    """本进程首次对目标发起仅侦查连接前，打一条授权声明日志（可审计留痕）。仅打一次。

    时序：domain 目标的 DNS 解析（判公网用）排在本声明之前——DNS 是名称查询、对目标主机零流量，
    不属本声明覆盖的"探测连接"；声明只在通过全部门控、即将真正连接目标时才打（不对被门控拒绝的目标误打）。
    """
    global _auth_notice_emitted
    with _AUTH_NOTICE_LOCK:
        if _auth_notice_emitted:
            return
        _auth_notice_emitted = True
    logger.warning(
        "主动探测已启用（%s=1）：将对【国外·建议调证·公网 IP】目标发起仅侦查连接"
        "（TCP connect / TLS 证书 / HTTP 指纹 / 后台路径状态码）——"
        "绝不漏洞利用/爆破/DoS。操作者须确保已获授权、在合法取证范围内使用。",
        _ENV_ENABLE,
    )


def _resolve_to_ip(value: str, kind: str) -> str | None:
    """把端点解析为可探测的目标 IP；domain 走 DNS 解析。解析不到 / 异常 → None（不抛）。"""
    if kind == "ip":
        return value
    try:
        # 只取一个地址即可（探测目标）；getaddrinfo 兼容 IPv4/IPv6。
        infos = socket.getaddrinfo(value, None, proto=socket.IPPROTO_TCP)
    except OSError:
        logger.debug("recon DNS 解析失败：%s", value, exc_info=True)
        return None
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            return sockaddr[0]
    return None


def _is_public_ip(ip: str) -> bool:
    """目标 IP 是否为可探测的公网地址（防误探内网/回环/CGNAT/保留段）。

    用 ipaddress.is_global 严判：私网(RFC1918)/回环/链路本地/保留/CGNAT(100.64/10)/非全局
    全部判 False → 跳过。is_global 在 Python 3.11+ 对 IPv4/IPv6 都成立。
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_global)


class ReconEnricher(BaseEnricher):
    """对【国外·建议调证·公网 IP】端点做主动侦查（opt-in，配 FXAPK_ACTIVE_RECON=1 才启用）。

    阶段标识 ``phase="attack_surface"`` + ``active=True``：供两遍富化调度识别这是**主动探测阶段**
    的 enricher。★「仅国外 + 仅建议调证」由两遍富化编排（pipeline._run_enrichment 的 _gate）担保，
    **不在本类内部**——本 enricher 不得脱离两遍编排单独调用。enrich() 内部仅兜 opt-in + CDN +
    私网 + 公网 IP 这几道与目标直接相关的自检；辖区/研判闸依赖上游编排。
    """

    name = "recon"
    applies_to = ["ip", "domain"]
    #: 攻击面阶段（两遍富化的第二遍）；active=True 标记其为主动探测，与被动 enricher 区分。
    phase = "attack_surface"
    active = True

    def __init__(self) -> None:
        # 本模块不写缓存文件（探测是实时态、有时效，不缓存到磁盘）；保留 lock 习惯位以备扩展。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 子探测
    def _scan_ports(self, ip: str, deadline: float) -> tuple[list[int], dict[int, str]]:
        """对 curated 端口逐个 TCP connect 探活（仅 connect，不发任何 payload）。

        返回 (open_ports, banner_hint)；banner_hint 仅在握手即得的轻量提示（如 SSH banner），
        不主动索要。超过 deadline 立即停止后续端口（已得结果照常返回）。
        """
        import time

        open_ports: list[int] = []
        for port in _CURATED_PORTS:
            if time.monotonic() >= deadline:
                logger.debug("recon 端口探测超预算，提前停止：%s", ip)
                break
            sem = _semaphore()
            acquired = sem.acquire(timeout=_CONNECT_TIMEOUT)
            if not acquired:
                continue  # 并发闸忙，跳过该端口（不阻塞整体预算）
            try:
                with socket.create_connection((ip, port), timeout=_CONNECT_TIMEOUT):
                    open_ports.append(port)
            except OSError:
                # 连接被拒/超时/不可达=端口未开放，属正常结果，不记噪音 traceback。
                logger.debug("recon 端口未开放：%s:%s", ip, port)
            except Exception:  # noqa: BLE001 — 单端口探测失败不得影响其它端口
                logger.debug("recon 端口探测异常：%s:%s", ip, port, exc_info=True)
            finally:
                sem.release()
        return open_ports, {}

    def _grab_tls(self, ip: str, port: int, server_name: str | None) -> dict[str, Any] | None:
        """对 (ip, port) 做 TLS 握手并取对端证书（CN/SAN/issuer/有效期）。失败 → None（不抛）。

        ★ 安全说明（为何此处**故意** CERT_NONE，且不构成 MITM 风险）：
          取证目标恰恰是"该服务器声明了什么证书"——自签 / 过期 / CN 不匹配的证书**本身就是情报**
          （正规后端不会这样）。若开启验证，会把这些最该记录的证书直接握手失败丢掉，与取证目标相反。
          MITM 威胁模型在此**不适用**：本连接是只读侦查，**绝不发送任何凭据 / cookie / 密钥 /
          敏感数据**（见 _http_exchange），没有可被中间人窃取的秘密；拿到的证书也**只作为观测证据
          记录**，绝不用于任何信任决策。故这是取证场景下的正确取舍，非配置疏忽。
        """
        ctx = ssl._create_unverified_context()  # 取证：只观测对端证书，不做信任决策（见上）
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=_TLS_TIMEOUT) as sock:
                # 带 SNI（用域名）以拿到正确的虚拟主机证书；纯 IP 时不带 SNI。
                with ctx.wrap_socket(sock, server_hostname=server_name or None) as tls:
                    # ★ 必须取 DER：CERT_NONE（不验证）下 getpeercert()(非 binary) 恒返回 {}，会吞光
                    #   subject/issuer/SAN/有效期；getpeercert(binary_form=True) 仍给完整 DER，再解析。
                    der = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()
        except Exception:  # noqa: BLE001 — TLS 失败（非 TLS 端口/超时）不得影响其它探测
            logger.debug("recon TLS 取证失败：%s:%s", ip, port, exc_info=True)
            return None
        return _parse_cert(der, cipher, port)

    def _probe_http(
        self, ip: str, port: int, use_tls: bool, server_name: str | None
    ) -> dict[str, Any] | None:
        """对 (ip, port) 发一个 HTTP(S) 请求取 Server/X-Powered-By 头 + <title> + 状态码。

        用裸 socket 手写最小 HTTP/1.1 GET（不引第三方、可精确控超时/读取上限/SNI）。
        失败 → None（不抛）。只 GET 根路径，不提交任何参数/凭据/payload。
        """
        host_header = server_name or ip
        try:
            raw = _http_exchange(
                ip, port, use_tls, host_header, path="/", timeout=_HTTP_TIMEOUT
            )
        except Exception:  # noqa: BLE001 — HTTP 探测失败不得影响其它探测
            logger.debug("recon HTTP 指纹失败：%s:%s", ip, port, exc_info=True)
            return None
        if raw is None:
            return None
        status, headers, body, cookies = raw
        info: dict[str, Any] = {
            "port": port,
            "scheme": "https" if use_tls else "http",
            "status": status,
        }
        server = headers.get("server")
        if server:
            info["server"] = server[:_MAX_HEADER_LEN]
        powered = headers.get("x-powered-by")
        if powered:
            info["x_powered_by"] = powered[:_MAX_HEADER_LEN]
        title = _extract_title(body)
        if title:
            info["title"] = title[:_MAX_TITLE_LEN]
        if cookies:
            info["cookies"] = cookies[:8]  # 只留 cookie 名（栈指纹用），不留值
        return info

    def _probe_paths(
        self, ip: str, port: int, use_tls: bool, server_name: str | None, deadline: float
    ) -> list[dict[str, Any]]:
        """对 curated 后台路径逐个 HEAD/GET，只看状态码+标题（绝不提交凭据/payload）。

        命中"有意义状态码"（含 401/403 鉴权拦截——证明入口存在）才记入暴露路径。
        超 deadline 停止后续路径。
        """
        import time

        found: list[dict[str, Any]] = []
        host_header = server_name or ip
        for path in _CURATED_PATHS:
            if time.monotonic() >= deadline:
                logger.debug("recon 路径探测超预算，提前停止：%s:%s", ip, port)
                break
            try:
                raw = _http_exchange(
                    ip, port, use_tls, host_header, path=path, timeout=_HTTP_TIMEOUT
                )
            except Exception:  # noqa: BLE001 — 单路径失败不得影响其它路径
                logger.debug("recon 路径探测异常：%s:%s%s", ip, port, path, exc_info=True)
                continue
            if raw is None:
                continue
            status, _headers, body, _cookies = raw
            if status not in _INTERESTING_STATUS:
                continue
            entry: dict[str, Any] = {"path": path, "status": status}
            title = _extract_title(body)
            if title:
                entry["title"] = title[:_MAX_TITLE_LEN]
            found.append(entry)
        return found

    # ------------------------------------------------------------------ 编排
    def _recon(self, ip: str, server_name: str | None) -> dict[str, Any]:
        """对单个公网 IP 跑全部子探测，归一成稳定 dict。每子探测错误隔离，整体守 _TARGET_BUDGET。"""
        import time

        deadline = time.monotonic() + _TARGET_BUDGET
        open_ports, _banner = self._scan_ports(ip, deadline)

        tls: dict[int, dict[str, Any]] = {}
        http: list[dict[str, Any]] = []
        exposed_paths: list[dict[str, Any]] = []

        # 只对**开放**端口做后续 TLS/HTTP/路径探测（开放端口才有意义，省时）。
        tls_ports = [p for p in open_ports if p in (443, 8443)]
        http_plain_ports = [p for p in open_ports if p in (80, 8080, 8888, 9000)]
        http_tls_ports = [p for p in open_ports if p in (443, 8443)]

        for port in tls_ports:
            if time.monotonic() >= deadline:
                break
            cert = self._grab_tls(ip, port, server_name)
            if cert:
                tls[port] = cert

        for port in http_plain_ports:
            if time.monotonic() >= deadline:
                break
            info = self._probe_http(ip, port, use_tls=False, server_name=server_name)
            if info:
                http.append(info)
                exposed_paths.extend(
                    self._tag_port(
                        self._probe_paths(ip, port, False, server_name, deadline), port, "http"
                    )
                )

        for port in http_tls_ports:
            if time.monotonic() >= deadline:
                break
            info = self._probe_http(ip, port, use_tls=True, server_name=server_name)
            if info:
                http.append(info)
                exposed_paths.extend(
                    self._tag_port(
                        self._probe_paths(ip, port, True, server_name, deadline), port, "https"
                    )
                )

        return {
            "target_ip": ip,
            "open_ports": sorted(open_ports),
            "services": _ports_to_services(open_ports),
            "tls": {str(k): v for k, v in tls.items()},  # JSON key 必须是 str
            "http": http,
            "exposed_paths": exposed_paths,
            "active": True,  # 标记：主动探测·已授权（渲染层据此标注）
            "source": "recon",
        }

    @staticmethod
    def _tag_port(entries: list[dict[str, Any]], port: int, scheme: str) -> list[dict[str, Any]]:
        """给路径探测结果补上端口/scheme 标注（便于报告定位是哪个服务的哪条路径）。"""
        for e in entries:
            e["port"] = port
            e["scheme"] = scheme
        return entries

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        value = (ep.value or "").strip()
        if not value:
            return EnrichmentResult(provider=self.name, ok=False, error="空值，跳过主动探测")

        # 门控 1：opt-in 主开关。未开 → 立即返回，绝不触网（最硬的一道闸）。
        if not _enabled():
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error=f"未设 {_ENV_ENABLE}=1，跳过主动探测（opt-in，主动探测默认关闭）",
            )

        # 门控 2：CDN/已知第三方基础设施域名不探（不是 App 自有后端，探测无价值且打到第三方）。
        #   延迟导入 infra 避免无谓耦合；纯函数，安全。
        from apkscan.core import infra

        if ep.kind == "domain" and infra.is_known_infra(value):
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error=f"已知第三方基础设施/CDN，跳过主动探测：{value}",
            )

        # 门控 3：端点已标内网/回环（is_private）直接跳过（防误探）。
        if ep.is_private:
            return EnrichmentResult(
                provider=self.name, ok=False, error="内网/回环端点，跳过主动探测"
            )

        # 门控 4：解析为目标 IP，并二次自检必须是公网 IP（防 DNS 把域名解析到内网/CGNAT）。
        ip = _resolve_to_ip(value, ep.kind)
        if not ip:
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"无法解析为 IP，跳过主动探测：{value}"
            )
        if not _is_public_ip(ip):
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                error=f"非公网 IP（私网/回环/CGNAT/保留），跳过主动探测：{ip}",
            )

        # 全部门控通过 → 首次探测前打授权声明日志（可审计留痕）。
        _emit_auth_notice_once()

        # 实际探测；任何未预期异常吞成 ok=False，绝不炸主流程。
        try:
            server_name = value if ep.kind == "domain" else None
            data = self._recon(ip, server_name)
        except Exception as exc:  # noqa: BLE001 — 主动探测失败不得炸主流程
            logger.debug("recon 主动探测失败：%s（%s）", value, exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}"
            )

        return EnrichmentResult(provider=self.name, ok=True, data=data)


# ---------------------------------------------------------------------------
# 纯函数辅助（无 I/O 之外的副作用；便于单测）
# ---------------------------------------------------------------------------

#: 端口→服务名映射（仅展示用；探测不依赖此猜测，以实际握手为准）。
_PORT_SERVICE: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-panel",
    9000: "PHP-FPM/Panel", 9200: "Elasticsearch", 27017: "MongoDB",
}


def _ports_to_services(ports: list[int]) -> list[dict[str, Any]]:
    """把开放端口列表归一成 [{port, service}]（service 为常见服务名猜测，仅展示用）。"""
    return [{"port": p, "service": _PORT_SERVICE.get(p, "")} for p in sorted(set(ports))]


def _parse_cert(der: object, cipher: object, port: int) -> dict[str, Any]:
    """把对端 TLS 证书（**DER 字节**）归一成稳定 dict（subject/issuer/SAN/有效期）。坏证书安全留空。

    ★ 必须用 DER 解析：CERT_NONE（取证不验证）下 ``ssl.getpeercert()``（非 binary）恒返回 ``{}``，
    会吞光所有证书字段；``getpeercert(binary_form=True)`` 仍给完整 DER。用已在依赖中的 cryptography 解析。
    自签 / 过期 / CN 不匹配的证书**本身就是取证情报**（见 _grab_tls 安全说明），故全程不做信任校验、坏证书留空不抛。
    """
    out: dict[str, Any] = {"port": port}
    if isinstance(cipher, tuple) and cipher:
        out["cipher"] = str(cipher[0])  # 记 cipher 作"该端口确为 TLS"的存在证明
    if not der or not isinstance(der, (bytes, bytearray)):
        return out

    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_der_x509_certificate(bytes(der))
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        if subject:
            out["subject"] = subject
        if issuer:
            out["issuer"] = issuer
        try:
            # *_utc 属性（cryptography 42+）避免已弃用的 naive datetime。
            out["not_before"] = cert.not_valid_before_utc.isoformat()
            out["not_after"] = cert.not_valid_after_utc.isoformat()
        except Exception:  # noqa: BLE001 — 有效期坏字段不得影响其它证书字段
            logger.debug("recon 证书有效期解析失败（port=%s）", port, exc_info=True)
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            # san_ext.value 运行时即 SubjectAlternativeName（有 get_values_for_type）；Pyright 仅见基类。
            sans = san_ext.value.get_values_for_type(x509.DNSName)  # type: ignore[attr-defined]
            if sans:
                out["san"] = [str(s) for s in sans[:30]]
        except x509.ExtensionNotFound:
            pass  # 无 SAN 扩展属正常
        except Exception:  # noqa: BLE001 — SAN 坏字段不得影响其它证书字段
            logger.debug("recon 证书 SAN 解析失败（port=%s）", port, exc_info=True)
    except Exception:  # noqa: BLE001 — 坏证书/解析失败留空不抛（取证就是要拿到畸形证书）
        logger.debug("recon 证书 DER 解析失败（port=%s）", port, exc_info=True)
    return out


def _http_exchange(
    ip: str, port: int, use_tls: bool, host_header: str, path: str, timeout: float
) -> "tuple[int, dict[str, str], str, list[str]] | None":
    """对 (ip, port) 发一个最小 HTTP/1.1 GET，返回 (status, headers, body)。失败抛由调用方兜底。

    手写裸 socket：精确控超时/读取上限/SNI，且不引第三方依赖。只 GET，不带任何 body/凭据/payload。
    并发受全局信号量约束。
    """
    sem = _semaphore()
    acquired = sem.acquire(timeout=timeout)
    if not acquired:
        return None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        sem.release()
        return None

    try:
        sock.settimeout(timeout)
        if use_tls:
            # 取证场景故意不验证证书（见 ReconEnricher._grab_tls 安全说明）：仅做只读 HTTP 指纹，
            # 绝不发送凭据/敏感数据，响应也不用于信任决策，故 MITM 威胁模型不适用。
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni = host_header if not _looks_like_ip(host_header) else None
            sock = ctx.wrap_socket(sock, server_hostname=sni)

        # Connection: close 让对端发完即关，便于读到 EOF；不发凭据/cookie/参数。
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {_host_for_header(host_header)}\r\n"
            "User-Agent: apkscan-recon/forensic\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        sock.sendall(req)

        chunks: list[bytes] = []
        total = 0
        while total < _HTTP_BODY_CAP:
            try:
                buf = sock.recv(8192)
            except (socket.timeout, OSError):
                break
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
        raw = b"".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        sem.release()

    return _parse_http_response(raw)


def _looks_like_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_for_header(host: str) -> str:
    """构造合法的 HTTP Host 头值：IPv6 字面量按 RFC 7230 加方括号（``2606::1`` → ``[2606::1]``）。

    否则裸 IPv6 拼进 ``Host:`` 会被对端反代/WAF 判非法（常返 400），导致该 IPv6 目标的 HTTP/路径指纹静默失效。
    """
    try:
        import ipaddress

        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _parse_http_response(raw: bytes) -> "tuple[int, dict[str, str], str, list[str]] | None":
    """从原始 HTTP 响应字节抽 (status_code, headers_lower, body_text, cookie_names)。无法解析 → None。

    cookie_names：从 Set-Cookie 头抽出的 cookie 名列表（如 PHPSESSID/laravel_session/JSESSIONID）——
    供技术栈指纹（exposure.tech_stack），只取**名**不取值（不留存任何会话凭据值）。
    """
    if not raw:
        return None
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        head, body = raw, b""
    else:
        head, body = raw[:sep], raw[sep + 4 :]
    try:
        head_text = head.decode("iso-8859-1")
    except Exception:  # noqa: BLE001 — 解析失败按无结果处理（不抛）
        return None
    lines = head_text.split("\r\n")
    if not lines:
        return None
    # 状态行：HTTP/1.1 200 OK
    status = 0
    parts = lines[0].split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            kl = k.strip().lower()
            vv = v.strip()
            if kl == "set-cookie":
                # 只取 cookie 名（= 之前），绝不留存值（不落任何会话凭据）。
                name = vv.split("=", 1)[0].strip()
                if name and name not in cookies:
                    cookies.append(name)
            headers[kl] = vv
    body_text = body.decode("utf-8", errors="replace")
    return status, headers, body_text, cookies


def _extract_title(body: str) -> str:
    """从 HTML 抽 <title>（轻量，正则即可；取不到 → 空串）。不解析/执行任何脚本。"""
    if not body:
        return ""
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return " ".join(m.group(1).split()).strip()
