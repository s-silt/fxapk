"""ICP 备案富化器：对中国域名查 ICP 备案主体（实名）/ 备案号 / 单位性质。

ICP 备案权威数据在工信部（``beian.miit.gov.cn``），官方查询有强反爬 / 验证码，
没有稳定的免费公开 API。本模块设计为**可插拔 provider**，默认在配置
``FXAPK_ICP_HAPI_KEY`` 后调用 HAPI：

- ``_query(domain) -> dict`` 为内部查询点；HAPI token 只走 Authorization header。
  无 key / 接口不可用 / 解析失败时明确降级，绝不把“没查成”写成“无备案”。
- ``enrich()`` 捕获后返回稳定错误分类码或 ``no_record`` 状态，
  并在 ``data`` 里给出**人工核验链接**（工信部官网 + 域名直查 URL），
  方便调证人员一键去官方核实。

要替换为自有 provider：子类覆写 ``_query`` 即可（成功返回字段 dict，
不可用抛 ``IcpUnavailable``，其它异常由 ``enrich`` 统一转成 ok=False）。

错误处理（符合规范）：
- 网络/解析全部异常 → 返回 ``EnrichmentResult(ok=False, error=...)``，不抛出、不静默。
- 全程 logging 记录，不裸 ``except: pass``。

结果带本地 JSON 文件缓存（键=provider/schema/域名，放 ``.apkscan_cache/icp.json``）避免重复查询，
同时阻止不同 provider 之间复用彼此结果。
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from apkscan.core.enrichment import safe_error_type
from apkscan.core.redact import safe_exception_diagnostic
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher
from apkscan.enrichers import _http

#: 本模块 ``requests`` 符号 = 有界 shim（get 流式限体，防被劫持上游灌爆内存，codex B1）。
#: 生产走此 shim；测试仍可 ``monkeypatch.setattr(icp, "requests", fake)`` 覆盖。
requests = _http.capped_requests

logger = logging.getLogger(__name__)

#: 查询超时（秒）。
ICP_TIMEOUT = 8

#: HAPI ICP 查询接口与凭据变量。凭据只走 Authorization header，绝不拼 URL / data。
HAPI_URL = "https://api.8450.cn/api/icp"
HAPI_KEY_ENV = "FXAPK_ICP_HAPI_KEY"

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


class IcpNoRecord(Exception):
    """Provider 已成功回答，但没有匹配的备案记录。"""


class HapiResponseError(Exception):
    """HAPI 业务层失败；只携带稳定分类码，绝不携带上游正文或凭据。"""

    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


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


def _hapi_error_type(code: int) -> str:
    """把 HAPI 业务码压成稳定、无正文的本地分类。"""
    if code in {504, 505, 506, 509, 510, 515, 516, 518, 520}:
        return "authentication_failed"
    if code in {507, 508, 514, 519, 521, 522}:
        return "quota_insufficient"
    if code in {511, 517}:
        return "rate_limited"
    if code in {502, 503, 530, 531, 532, 533, 535}:
        return "provider_unavailable"
    if code == 534:
        return "invalid_request"
    return "provider_error"


def _hapi_http_error_type(status_code: int) -> str:
    """把 HAPI HTTP 状态压成稳定、无正文的本地分类。"""
    if status_code in {401, 403}:
        return "authentication_failed"
    if status_code == 402:
        return "quota_insufficient"
    if status_code == 429:
        return "rate_limited"
    if 500 <= status_code <= 599:
        return "provider_unavailable"
    if 400 <= status_code <= 499:
        return "invalid_request"
    return "provider_error"


_HAPI_RECORD_KEYS = {
    "unitName",
    "subject",
    "companyName",
    "serviceLicence",
    "mainLicence",
    "mainLicense",
    "license_no",
    "site_name",
    "siteName",
    "serviceName",
    "nature",
    "natureName",
    "domain",
    "domainName",
    "ym",
}
_HAPI_WRAPPER_KEYS = ("list", "items", "records", "rows", "data", "result")
_HAPI_PAGE_KEYS = {"total", "count", "page", "pageNum", "pageSize", "pages"}


def _hapi_candidates(params: Any, *, depth: int = 0) -> list[dict[str, Any]]:
    """有界展开 HAPI 已知包装层；未知非空结构视为解析错误。"""
    if depth > 4:
        raise ValueError("ICP provider 包装层过深")
    if params in (None, "", [], {}):
        return []
    if isinstance(params, list):
        candidates: list[dict[str, Any]] = []
        for item in params:
            if not isinstance(item, (dict, list)):
                raise ValueError("ICP provider 列表项类型无效")
            candidates.extend(_hapi_candidates(item, depth=depth + 1))
        return candidates
    if not isinstance(params, dict):
        raise ValueError(f"ICP provider params 类型无效：{type(params).__name__}")

    if _HAPI_RECORD_KEYS.intersection(params):
        return [params]

    wrapped = [params[key] for key in _HAPI_WRAPPER_KEYS if key in params]
    if wrapped:
        candidates = []
        for nested in wrapped:
            candidates.extend(_hapi_candidates(nested, depth=depth + 1))
        return candidates

    if set(params).issubset(_HAPI_PAGE_KEYS):
        return []
    raise ValueError("ICP provider 返回未知非空结构")


def _normalise_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _candidate_is_ancestor(wanted: str, candidate: str) -> bool:
    """仅接受候选是查询域的祖先；根域查询不得反向吸收任意子域记录。"""
    return candidate.count(".") >= 1 and wanted.endswith(f".{candidate}")


def _hapi_record(params: Any, domain: str) -> dict[str, Any] | None:
    """取与查询域名匹配的一条；显式错域绝不回退到列表首条。"""
    candidates = _hapi_candidates(params)
    if not candidates:
        return None

    wanted = _normalise_domain(domain)
    explicit: list[tuple[str, dict[str, Any]]] = []
    for candidate in candidates:
        raw = _to_str(
            candidate.get("domain")
            or candidate.get("domainName")
            or candidate.get("ym")
        )
        if raw:
            candidate_domain = _normalise_domain(raw)
            explicit.append((candidate_domain, candidate))
    exact = [candidate for candidate_domain, candidate in explicit if candidate_domain == wanted]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None

    ancestors = [
        (candidate_domain, candidate)
        for candidate_domain, candidate in explicit
        if _candidate_is_ancestor(wanted, candidate_domain)
    ]
    if ancestors:
        # 最长标签路径就是离查询域最近、最具体的祖先；同层多条无法可靠消歧。
        best_depth = max(candidate_domain.count(".") for candidate_domain, _ in ancestors)
        nearest = [
            candidate
            for candidate_domain, candidate in ancestors
            if candidate_domain.count(".") == best_depth
        ]
        return nearest[0] if len(nearest) == 1 else None
    if explicit:
        return None
    # 单条无 domain 的响应可由查询上下文约束；多条无 domain 无法可靠归因。
    return candidates[0] if len(candidates) == 1 else None


class IcpEnricher(BaseEnricher):
    """对中国域名端点做 ICP 备案富化（主体 / 备案号 / 单位性质）。

    配置 HAPI token 后自动初筛；未配置或查询失败时优雅降级为“需人工核”。
    """

    name = "icp"
    applies_to = ["domain"]
    required_env = (HAPI_KEY_ENV,)

    def __init__(self) -> None:
        # 缓存写入串行化，避免并发富化时写坏 JSON 文件。
        self._lock = threading.Lock()
        uses_default_hapi = (
            type(self)._query is IcpEnricher._query
            and type(self)._provider_url is IcpEnricher._provider_url
        )
        # 自定义 provider 不应被 HAPI key 的能力门禁误判为 disabled。
        self.required_env = (HAPI_KEY_ENV,) if uses_default_hapi else ()
        if uses_default_hapi:
            self._cache_namespace = "hapi:v1"
        else:
            provider_id = f"{type(self).__module__}.{type(self).__qualname__}"
            self._cache_namespace = f"custom:{provider_id}:v1"

    def _cache_key(self, domain: str) -> str:
        return f"{self._cache_namespace}|{domain}"

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
            cache[self._cache_key(domain)] = entry
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

        默认实现：配置 token 后调用 HAPI；未配置时抛 ``IcpUnavailable``，
        由 ``enrich`` 转成“需人工核”。

        要接入自有 provider：子类覆写本方法，成功返回如下字段 dict——
            {"subject": ..., "license_no": ..., "site_name": ..., "nature": ...}
        不可用时抛 ``IcpUnavailable``；网络/解析异常正常向上抛由 ``enrich`` 兜底。
        """
        endpoint = self._provider_url(domain)
        if not endpoint:
            # 无配置的 provider —— 预期内不可用，触发人工核验路径。
            raise IcpUnavailable("未配置 ICP 查询 provider")

        if endpoint == HAPI_URL:
            return self._query_hapi(domain)

        resp = requests.get(endpoint, timeout=ICP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"ICP provider 返回非对象：{type(payload).__name__}")
        return self._parse(payload)

    def _query_hapi(self, domain: str) -> dict[str, str | None]:
        """调用 HAPI；token 仅进请求头，报告/异常/缓存均不接触凭据。"""
        token = (os.environ.get(HAPI_KEY_ENV) or "").strip()
        if not token:
            raise IcpUnavailable("未配置 ICP 查询 provider")

        resp = requests.post(
            HAPI_URL,
            headers={"Authorization": f"Bearer {token}"},
            data={
                "type": "web",
                "search": domain,
                "pageNum": "1",
                "pageSize": "10",
            },
            timeout=ICP_TIMEOUT,
        )
        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code and not 200 <= status_code <= 299:
            raise HapiResponseError(_hapi_http_error_type(status_code))
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError(f"ICP provider 返回非对象：{type(payload).__name__}")

        raw_code = payload.get("code")
        if raw_code is None:
            raise ValueError("ICP provider 缺少有效状态码")
        try:
            code = int(raw_code)
        except ValueError:
            raise ValueError("ICP provider 缺少有效状态码") from None
        if code != 200:
            raise HapiResponseError(_hapi_error_type(code))

        record = _hapi_record(payload.get("params"), domain)
        if record is None:
            raise IcpNoRecord
        data = self._parse(record)
        if not data.get("subject") and not data.get("license_no"):
            raise ValueError("ICP provider 记录缺少备案主体和备案号")
        data.update(
            {
                "main_license_no": _to_str(
                    record.get("main_license_no")
                    or record.get("mainLicence")
                    or record.get("mainLicense")
                ),
                "approval_time": _to_str(
                    record.get("approval_time")
                    or record.get("updateRecordTime")
                    or record.get("verifyTime")
                    or record.get("examineDate")
                ),
                "provider_name": "hapi",
            }
        )
        return data

    def _provider_url(self, domain: str) -> str | None:
        """返回可用 provider 的查询 URL；HAPI 未配置时 → None。

        子类可覆写此处接入自有备案查询服务，``_query`` 的网络/缓存骨架即可复用。
        """
        del domain
        return HAPI_URL if (os.environ.get(HAPI_KEY_ENV) or "").strip() else None

    def _parse(self, payload: dict[str, Any]) -> dict[str, str | None]:
        """从 provider 返回 JSON 提取关心字段；子类可按自家结构覆写。"""
        return {
            "subject": _to_str(
                payload.get("subject")
                or payload.get("unitName")
                or payload.get("companyName")
            ),
            "license_no": _to_str(
                payload.get("license_no")
                or payload.get("serviceLicence")
                or payload.get("mainLicence")
                or payload.get("mainLicense")
            ),
            "site_name": _to_str(
                payload.get("site_name")
                or payload.get("siteName")
                or payload.get("serviceName")
            ),
            "nature": _to_str(payload.get("nature") or payload.get("natureName")),
        }

    # ------------------------------------------------------------------ 入口
    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        domain = (ep.value or "").strip().lower()
        if not domain:
            return EnrichmentResult(
                provider=self.name, ok=False, error="invalid_input"
            )

        # 1) 缓存命中直接返回（不消耗网络）。仅缓存成功结果。
        #    持锁读，避免与并发写 os.replace 撞车（Windows race）。
        cache = self._load_cache_locked()
        cached = cache.get(self._cache_key(domain))
        if isinstance(cached, dict):
            logger.debug("ICP 缓存命中：%s", domain)
            return EnrichmentResult(provider=self.name, ok=True, data=dict(cached))

        # 2) 查询。区分两类失败：
        #    - IcpUnavailable：预期内不可用 → 附人工核验链接，明确提示人工核。
        #    - 其它异常：网络/HTTP/解析错误 → 同样优雅降级到人工核。
        #    ★两类的 error 都只放**稳定分类码**：它会进报告 JSON 与 enricher_status，
        #      而异常消息可能夹带 provider URL（含 key）与响应正文。人工核验指引本就在
        #      data["hint"]／data["miit_url"]／data["lookup_url"] 里，不必挤进 error。
        try:
            data = self._query(domain)
        except IcpNoRecord:
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"_source_status": "no_record", "provider_name": "hapi"},
            )
        except HapiResponseError as exc:
            manual = _manual_data(domain)
            manual["provider_name"] = "hapi"
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data=manual,
                error=exc.error_type,
            )
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
                error="provider_unavailable",
            )
        except Exception as exc:  # noqa: BLE001 — 富化失败不得炸主流程
            logger.debug(
                "ICP 查询失败：%s（%s）", domain, safe_exception_diagnostic(exc)
            )
            return EnrichmentResult(
                provider=self.name,
                ok=False,
                data=_manual_data(domain),
                error=safe_error_type(exc),
            )

        # 3) 成功才写缓存（失败/需人工核不缓存，便于后续接入 provider 后重查）。
        self._save_cache_entry(domain, data)
        return EnrichmentResult(provider=self.name, ok=True, data=data)
