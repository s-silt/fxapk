"""证书透明度（crt.sh）富化器：被动查 CT 日志拿历史/关联证书的 SAN/子域，**串案**。

★ 定位：攻击面阶段（``phase="attack_surface"``）的**被动** enricher（``active=False``，
对目标**零流量**——只查公共 CT 日志库 crt.sh，不向被查域名发任何连接）。免 key，与 ``cve``
（同被动）/``recon``（主动）同阶段、互补：本模块产出"**关联主机名/子域**"情报，疑同团伙基础设施。

为什么有用（串案价值）：
- 涉诈团伙批量给同一基础设施签证书——CT 日志（Certificate Transparency）公开记录了**每张**为
  ``*.{domain}`` / ``sub.{domain}`` 签发的证书，含其 ``name_value``（SAN / 覆盖的子域）与
  ``issuer_name``（签发 CA）。被动拉取即得该域名**历史 + 当前**的全部关联主机名；
- 这些子域常指向同团伙的其它后台 / API / 备用域，可**并簇串案**（与 Shodan ``hostnames``
  互补：CT 覆盖"曾经签过证但现在 DNS 已撤"的影子子域，Shodan 只看扫库时点的解析）；
- 本组件**只产数据不主动连**——产出的子域可作为 ``recon`` 主动探测的额外目标，但是否探测由
  ``recon`` 自身的 opt-in + 公网 IP + CDN 门控决定，本模块绝不触达它们。

crt.sh JSON 接口（``https://crt.sh/?q=%25.{domain}&output=json``，``%25`` 即 URL 编码的 ``%``
通配，匹配 ``*.{domain}``）：
- 返回 list[证书记录]，每条含 ``name_value``（可多行，\\n 分隔多个 SAN）、``common_name``、
  ``issuer_name``、``id`` 等。本模块抽 name_value/common_name 归一去重成关联主机名列表，
  并汇总出现过的 issuer。
- crt.sh **常超时 / 限流 / 偶发 502**：优雅失败——任何网络/解析异常 → ``ok=False`` 不炸主流程；
  限速（进程级闸，礼貌对待公共服务）+ 按 domain 本地 JSON 缓存（原子写）避免重复拉取。

合规：只查公共 CT 日志（被动情报，对被查域名零流量），不向目标发起任何连接 / 扫描 / 利用。
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: crt.sh JSON 接口。``%25`` = URL 编码的 ``%`` 通配，``%25.{domain}`` 匹配 ``*.{domain}``。
CRTSH_URL = "https://crt.sh/"
#: crt.sh 经常很慢（CT 库巨大、共享免费实例），给较宽超时但不无限等。
CRTSH_TIMEOUT = 20

#: 归一化截断上限（防个别热门域名拉回上万条证书塞爆缓存 / 报告）。
_MAX_HOSTNAMES = 80
_MAX_ISSUERS = 20

#: 进程级礼貌限速：crt.sh 是公共免费服务，相邻请求间隔下限（秒），避免一次跑一片域名打爆它。
_MIN_INTERVAL = 1.5

CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "certs.json"


# ---------------------------------------------------------------------------
# 进程级礼貌限速器：pipeline 按端点并发，多个 certs 实例共用同一把闸（模块级单例），
# 保证对 crt.sh 的相邻请求至少间隔 _MIN_INTERVAL 秒（礼貌对待公共服务，避免被限流）。
# ---------------------------------------------------------------------------
_RATE_LOCK = threading.Lock()
_last_request_at = 0.0


def _throttle() -> None:
    """阻塞到距上次请求 ≥ _MIN_INTERVAL 秒（进程级全局闸，线程安全）。"""
    global _last_request_at
    with _RATE_LOCK:
        now = time.monotonic()
        wait = _MIN_INTERVAL - (now - _last_request_at)
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        _last_request_at = now


def _normalize_host(raw: object, base_domain: str) -> str | None:
    """把单条 SAN / CN 归一成可用主机名；过滤无效/无关项。无效 → None。

    - 去通配前缀 ``*.``（``*.evil.com`` → ``evil.com``，保留为关联域）；
    - 去首尾空白 / 末尾点 / 转小写；
    - 丢弃邮箱型 SAN（含 ``@``）、空串；
    - 只保留属于 base_domain 域树的主机名（等于 base_domain 或以 ``.base_domain`` 结尾）——
      crt.sh 偶尔回带其它 SAN（同证书多域），与本案 base_domain 无关的不并入，避免串错案。
    """
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or "@" in host or " " in host:
        return None
    base = (base_domain or "").strip().lower().rstrip(".")
    if not base:
        return None
    if host == base or host.endswith("." + base):
        return host
    return None


def _parse_crtsh(payload: object, base_domain: str) -> dict[str, Any]:
    """把 crt.sh JSON（list[证书记录]）归一成稳定字段：关联主机名 + issuer 汇总。

    每条记录的 ``name_value`` 可多行（\\n 分隔多个 SAN），``common_name`` 单值；都纳入归一。
    坏字段安全跳过（绝不抛）。
    """
    hosts: list[str] = []
    seen: set[str] = set()
    issuers: list[str] = []
    seen_issuers: set[str] = set()
    cert_count = 0

    records = payload if isinstance(payload, list) else []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        cert_count += 1
        # name_value 可能是多行字符串（多个 SAN）；common_name 单值。
        candidates: list[str] = []
        nv = rec.get("name_value")
        if isinstance(nv, str):
            candidates.extend(nv.splitlines())
        cn = rec.get("common_name")
        if isinstance(cn, str):
            candidates.append(cn)
        for cand in candidates:
            host = _normalize_host(cand, base_domain)
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        issuer = rec.get("issuer_name")
        if isinstance(issuer, str) and issuer.strip():
            iss = issuer.strip()
            if iss not in seen_issuers:
                seen_issuers.add(iss)
                issuers.append(iss)

    hosts.sort()
    return {
        "domain": (base_domain or "").strip().lower().rstrip("."),
        "related_hostnames": hosts[:_MAX_HOSTNAMES],
        "hostname_total": len(hosts),
        "issuers": issuers[:_MAX_ISSUERS],
        "cert_count": cert_count,
        "source": "crtsh",
    }


class CertsEnricher(BaseEnricher):
    """对域名查 crt.sh 证书透明度日志，产出关联子域（串案；被动、免 key）。

    阶段标识 ``phase="attack_surface"`` + ``active=False``：攻击面阶段的**被动** enricher
    （对被查域名零流量，只查公共 CT 库），与 ``recon``（主动探测）区分。免 key、无门控开关——
    被动 OSINT 默认可跑（仅 ``--online`` 下随其它富化器在线程池里跑）。结果按 domain 本地缓存。
    """

    name = "certs"
    applies_to = ["domain"]
    #: 攻击面阶段（两遍富化的第二遍）；active=False 标记被动（不向目标发连接）。
    phase = "attack_surface"
    active = False

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, Any]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄与另一线程 os.replace
        撞同一文件会抛 PermissionError，让缓存静默丢失。读写共用一把锁消除该重叠窗口。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("certs(crt.sh) 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("certs(crt.sh) 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, Any]:
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[domain] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace；tmp 名带 pid+线程 id 唯一后缀，避免多写者互相覆盖/撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("certs(crt.sh) 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query(self, domain: str) -> dict[str, Any]:
        """查 crt.sh JSON 接口并归一。网络/HTTP/解析异常向上抛由 enrich() 统一兜底。"""
        _throttle()  # 礼貌限速：相邻请求间隔下限（进程级全局闸）
        # ★ 传**字面** % 通配（匹配 *.{domain}）；requests 会自动编码成 %25 → 最终请求 ?q=%25.{domain}。
        #   切勿把这里改成 "%25.{domain}"，否则被二次编码成 %2525（错误）。docstring 示例是已编码的 wire 形态。
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=CRTSH_TIMEOUT,
        )
        resp.raise_for_status()
        # crt.sh 偶发返回空体 / HTML 错误页：按"无结果"归一，不抛（json() 失败才抛）。
        text = (resp.text or "").strip()
        if not text:
            return _parse_crtsh([], domain)
        payload = resp.json()
        return _parse_crtsh(payload, domain)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        value = (ep.value or "").strip().lower().rstrip(".")
        if not value:
            return EnrichmentResult(provider=self.name, ok=False, error="空值，跳过 crt.sh 查询")

        # 1) 缓存命中直接返回（不再触网）。持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(value)
        if isinstance(cached, dict):
            logger.debug("certs(crt.sh) 缓存命中：%s", value)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 网络查询。crt.sh 常超时/限流 → 任何异常吞成 ok=False，绝不炸主流程。
        try:
            data = self._query(value)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            # 不带 exc_info：超时/限流/502 很常见，整段 traceback 是噪音；消息已含异常摘要。
            logger.debug("certs(crt.sh) 查询失败：%s（%s）", value, exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}"
            )

        # 3) 成功才写缓存（失败不缓存，便于后续重试）。查无结果（空列表）也缓存，避免对慢接口复查。
        self._save_cache_entry(value, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
