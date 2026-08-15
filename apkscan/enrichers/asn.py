"""ASN 富化器：对 IP 查归属 ISP / 机构(云厂商 / IDC) / ASN / 国家。

用 ip-api.com 免费接口（``http://ip-api.com/json/{ip}?fields=...``）。
免费档限速约 45 次/分钟：限速集中到共享的 ``_ipinfo.lookup_ip`` 内部（进程级共享限速器），
asn 与 dns 共用同一闸，避免各自限速叠加（~90/min）触发 429。
结果带本地 JSON 文件缓存（键=IP，放 ``.apkscan_cache/asn.json``）避免重复查询。

错误处理（符合规范）：
- 网络/解析全部异常 → 返回 ``EnrichmentResult(ok=False, error=...)``，不抛出、不静默。
- 接口返回 ``status != "success"`` → 同样视为失败（ok=False）。
- 全程 logging 记录，不裸 ``except: pass``。
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers import _http, _ipinfo

#: 本模块 ``requests`` 符号 = 有界 shim（get/post 流式限体，防被劫持上游灌爆内存，codex B1）。
#: 生产走此 shim；测试仍可 ``monkeypatch.setattr(asn, "requests", fake)`` 覆盖注入假响应。
requests = _http.capped_requests

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
ASN_TIMEOUT = 8

#: ip-api 免费接口地址模板与需要的字段（实际查询逻辑下沉到 _ipinfo.lookup_ip，dns 也复用）。
#: 这两个常量保留作向后兼容 / 测试断言锚点，与 _ipinfo 同源。
#: ⚠️ 明文 HTTP：ip-api 免费档不支持 HTTPS（HTTPS 需付费 key），故被查 IP（疑似 C2）会以
#: 明文经过在途节点 —— 向在途观察者披露正在查询的目标，且响应未认证、归属可被中间人篡改。
#: 敏感目标慎用 / 改用支持 HTTPS 的权威源（如 RDAP）。仅对"建议调证"端点查询已缩小暴露面。
ASN_API_URL = _ipinfo.IPINFO_API_URL
ASN_FIELDS = _ipinfo.IPINFO_FIELDS

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "asn.json"

#: ASN 富化缓存 TTL（秒）。IP→ASN 映射会随 IP 被重分配/回收而变（虽比 DNS 稳）——无 TTL 会把首次
#: 归属永久固化，IP 迁到新 ASN 后仍返回旧归属（辖区/网络运营方判定失真、串案锚点用旧归属）。取 7 天：
#: ASN 重分配远慢于 DNS 换 IP，7 天既省同批次重复查询、又保证跨基础设施变更能重查（对齐 dns.py TTL 纪律）。
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
#: 缓存条目里记录写入时刻的字段名（epoch 秒）。旧缓存无此字段 → 视为过期、触发重查。
_CACHED_AT_KEY = "_cached_at"


class AsnEnricher(BaseEnricher):
    """对 IP 端点做 ASN 富化（ISP / 机构 / ASN / 国家）。"""

    name = "asn"
    applies_to = ["ip"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄 open 与另一线程的
        os.replace(asn.json) 撞同一文件会抛 PermissionError(WinError 5)/Errno 13，
        让缓存静默丢失。读写共用一把锁消除该重叠窗口；enrich() 经 _load_cache_locked 进入。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("ASN 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("ASN 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        """持锁读缓存，供 enrich() 的命中检查用，避免与并发写的 os.replace 撞车。"""
        with self._lock:
            return self._load_cache()

    @staticmethod
    def _cache_is_fresh(entry: dict[str, Any]) -> bool:
        """缓存条目是否在 TTL 内（未过期）。无 ``_cached_at``（旧缓存）→ 判过期、触发重查。"""
        stamped = entry.get(_CACHED_AT_KEY)
        if not isinstance(stamped, (int, float)):
            return False
        return (time.time() - stamped) < CACHE_TTL_SECONDS

    def _save_cache_entry(self, ip: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            # 打时间戳供 TTL 过期判断（见 CACHE_TTL_SECONDS）。
            cache[ip] = {**entry, _CACHED_AT_KEY: time.time()}
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：先写临时文件再 replace，避免崩溃/并发时留半截坏缓存（读侧虽容忍坏文件
                # 重查，但原子替换从源头消除半截文件）。
                # tmp 名带 pid+线程 id 唯一后缀：避免多写者复用固定 asn.json.tmp 互相覆盖/再撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("ASN 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query(self, ip: str) -> dict[str, str | None]:
        """实际网络查询；网络/HTTP/解析异常向上抛由 enrich() 统一捕获。

        查询逻辑下沉到共享的 ``_ipinfo.lookup_ip``（dns 富化器同样复用）：限速（进程级共享
        限速器）与内存缓存都在 ``lookup_ip`` 内部完成，asn 不再各自限速（避免与 dns 叠加触发
        429）。本处只负责透传本模块的 ``requests``（被测试 monkeypatch 的就是它，保持既有 mock
        路径）。接口语义失败（``status != "success"``）由 ``lookup_ip`` 以 ValueError 抛出，
        同样由 enrich() 转 ok=False。
        """
        return _ipinfo.lookup_ip(ip, http=requests, timeout=ASN_TIMEOUT)

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        ip = (ep.value or "").strip()
        if not ip:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空 IP，跳过 ASN 查询"
            )

        # 1) 缓存命中且未过期直接返回（不消耗网络）。过期（超 TTL / 无时间戳的旧缓存）→ 重查，
        #    避免 IP 迁到新 ASN 后永久返回旧归属。持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(ip)
        if isinstance(cached, dict) and self._cache_is_fresh(cached):
            logger.debug("ASN 缓存命中：%s", ip)
            data = {k: v for k, v in cached.items() if k != _CACHED_AT_KEY}
            return EnrichmentResult(provider=self.name, ok=True, data=data)
        if isinstance(cached, dict):
            logger.debug("ASN 缓存过期，重查：%s", ip)

        # 2) 网络查询，全部异常吞成 ok=False，绝不炸主流程。
        try:
            data = self._query(ip)
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            # 不带 exc_info：富化失败（超时/限速/无应答）很常见，整段 traceback 是噪音；
            # 消息已含异常摘要，排障足够。
            logger.debug("ASN 查询失败：%s（%s）", ip, exc)
            return EnrichmentResult(
                provider=self.name, ok=False, error=f"{type(exc).__name__}: {exc}"
            )

        # 3) 成功才写缓存（失败不缓存，便于后续重试）。
        self._save_cache_entry(ip, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
