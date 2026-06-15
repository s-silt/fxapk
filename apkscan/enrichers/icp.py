"""ICP 备案富化器：对中国域名查 ICP 备案主体（实名）/ 备案号 / 单位性质。

ICP 备案权威数据在工信部（``beian.miit.gov.cn``），官方查询有强反爬 / 验证码，
没有稳定的免费公开 API。本模块设计为**可插拔 provider**：

- ``_query(domain) -> dict`` 为内部查询点，默认实现 best-effort 调一个公开第三方
  接口（若配置可用）；无 key / 接口不可用 / 解析失败时，抛出 ``IcpUnavailable``。
- ``enrich()`` 捕获后返回 ``EnrichmentResult(ok=False, error="...需人工核...")``，
  并在 ``data`` 里给出**人工核验链接**（工信部官网 + 域名直查 URL），
  方便调证人员一键去官方核实。

要替换为自有 provider：子类覆写 ``_query`` 即可（成功返回字段 dict，
不可用抛 ``IcpUnavailable``，其它异常由 ``enrich`` 统一转成 ok=False）。

错误处理（符合规范）：
- 网络/解析全部异常 → 返回 ``EnrichmentResult(ok=False, error=...)``，不抛出、不静默。
- 全程 logging 记录，不裸 ``except: pass``。

结果带本地 JSON 文件缓存（键=域名，放 ``.apkscan_cache/icp.json``）避免重复查询。
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

import requests

from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
ICP_TIMEOUT = 8

#: 工信部 ICP 备案官方查询入口（人工核验落点）。
MIIT_BEIAN_URL = "https://beian.miit.gov.cn/"

#: 域名直查模板（部分公开第三方备案查询站，便于人工带域名直达）。
MANUAL_LOOKUP_URL = "https://icp.chinaz.com/{domain}"

#: 人工核验固定提示语。
MANUAL_HINT = "ICP 自动查询不可用，需人工核（工信部 beian.miit.gov.cn）"

#: 本地缓存目录与文件。
CACHE_DIR = Path(".apkscan_cache")
CACHE_FILE = CACHE_DIR / "icp.json"


class IcpUnavailable(Exception):
    """ICP 自动查询不可用（无 provider / 无 key / 接口失效）。

    与一般网络异常区分：这类情况是“预期内的不可用”，``enrich`` 会附上人工核验链接。
    """


def _manual_data(domain: str) -> dict[str, Any]:
    """构造人工核验所需的固定 data：状态 + 工信部链接 + 域名直查链接。"""
    return {
        "status": "manual_required",
        "hint": MANUAL_HINT,
        "miit_url": MIIT_BEIAN_URL,
        "lookup_url": MANUAL_LOOKUP_URL.format(domain=domain),
    }


def _to_str(value: Any) -> str | None:
    """统一成可 JSON 序列化的字符串；None/空 → None。"""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


class IcpEnricher(BaseEnricher):
    """对中国域名端点做 ICP 备案富化（主体 / 备案号 / 单位性质）。

    默认无可用 provider → 优雅降级为“需人工核”，并返回工信部核验链接。
    """

    name = "icp"
    applies_to = ["domain"]

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 缓存
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        """读缓存文件。★必须持 self._lock 调用：Windows 下读句柄 open 与另一线程的
        os.replace(icp.json) 撞同一文件会抛 PermissionError(WinError 5)/Errno 13，
        让缓存静默丢失。读写共用一把锁消除该重叠窗口；enrich() 经 _load_cache_locked 进入。"""
        if not CACHE_FILE.is_file():
            return {}
        try:
            text = CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            logger.warning("ICP 缓存读取/解析失败，忽略：%s", CACHE_FILE, exc_info=True)
            return {}
        if not isinstance(data, dict):
            logger.warning("ICP 缓存顶层非 dict，忽略：%s", CACHE_FILE)
            return {}
        return data

    def _load_cache_locked(self) -> dict[str, dict[str, Any]]:
        """持锁读缓存，供 enrich() 的命中检查用，避免与并发写的 os.replace 撞车。"""
        with self._lock:
            return self._load_cache()

    def _save_cache_entry(self, domain: str, entry: dict[str, Any]) -> None:
        with self._lock:
            cache = self._load_cache()
            cache[domain] = entry
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                # 原子写：临时文件 + replace，避免崩溃/并发留半截坏缓存。
                # tmp 名带 pid+线程 id 唯一后缀：避免多写者复用固定 icp.json.tmp 互相覆盖/再撞 replace。
                tmp = CACHE_FILE.with_name(
                    f"{CACHE_FILE.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(CACHE_FILE)
            except Exception:
                logger.warning("ICP 缓存写入失败：%s", CACHE_FILE, exc_info=True)

    # ------------------------------------------------------------------ 查询
    def _query(self, domain: str) -> dict[str, str | None]:
        """实际查询点（可插拔）。

        默认实现：best-effort 调公开第三方备案接口。由于无稳定免费 API，
        默认配置下抛 ``IcpUnavailable``，由 ``enrich`` 转成“需人工核”。

        要接入自有 provider：子类覆写本方法，成功返回如下字段 dict——
            {"subject": ..., "license_no": ..., "site_name": ..., "nature": ...}
        不可用时抛 ``IcpUnavailable``；网络/解析异常正常向上抛由 ``enrich`` 兜底。
        """
        endpoint = self._provider_url(domain)
        if not endpoint:
            # 无配置的 provider —— 预期内不可用，触发人工核验路径。
            raise IcpUnavailable("未配置 ICP 查询 provider")

        resp = requests.get(endpoint, timeout=ICP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"ICP provider 返回非对象：{type(payload).__name__}")
        return self._parse(payload)

    def _provider_url(self, domain: str) -> str | None:
        """返回可用 provider 的查询 URL；默认无 provider → None。

        子类可覆写此处接入自有备案查询服务，``_query`` 的网络/缓存骨架即可复用。
        """
        return None

    def _parse(self, payload: dict[str, Any]) -> dict[str, str | None]:
        """从 provider 返回 JSON 提取关心字段；子类可按自家结构覆写。"""
        return {
            "subject": _to_str(payload.get("subject") or payload.get("unitName")),
            "license_no": _to_str(
                payload.get("license_no") or payload.get("mainLicence")
            ),
            "site_name": _to_str(payload.get("site_name") or payload.get("siteName")),
            "nature": _to_str(payload.get("nature") or payload.get("natureName")),
        }

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="空域名，跳过 ICP 查询"
            )

        # 1) 缓存命中直接返回（不消耗网络）。仅缓存成功结果。
        #    持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(domain)
        if isinstance(cached, dict):
            logger.debug("ICP 缓存命中：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 查询。区分两类失败：
        #    - IcpUnavailable：预期内不可用 → 附人工核验链接，明确提示人工核。
        #    - 其它异常：网络/HTTP/解析错误 → 同样优雅降级到人工核，但 error 带异常信息。
        try:
            data = self._query(domain)
        except IcpUnavailable as exc:
            # 「未配置 provider」是系统性不可用（每个域名都一样）：只在首个域名记一次，
            # 之后各域名静默返回人工核验链接，避免逐域名刷 INFO 噪声（与 whois 降级一致）。
            if not getattr(self, "_unavailable_logged", False):
                self._unavailable_logged = True
                logger.info(
                    "ICP 自动查询不可用（%s）；本次起对各域名静默返回人工核验链接", exc
                )
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data=_manual_data(domain),
                error=MANUAL_HINT,
            )
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            logger.warning("ICP 查询失败：%s（%s）", domain, exc, exc_info=True)
            manual = _manual_data(domain)
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data=manual,
                error=f"{type(exc).__name__}: {exc}（{MANUAL_HINT}）",
            )

        # 3) 成功才写缓存（失败/需人工核不缓存，便于后续接入 provider 后重查）。
        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
