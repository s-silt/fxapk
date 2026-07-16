"""PR5 被动情报 provider 抽象基类。

IntelProvider 是**无状态抽象基类**：暴露三个模板方法 lookup_ip/lookup_domain/
lookup_cert，各自委托共享守卫 _dispatch：校验 query 类型、声明能力、实体类型
匹配、能力对应的 canonical query 值、凭据可用性，再在密钥安全的 try/except 内
调用适配器唯一的抽象钩子 _fetch。_fetch 的返回值先经后置契约校验
（provider/capability/query 精确、仅 SUCCESS/EMPTY）才交给调用者；违约或异常都
转成脱敏的 FAILURE。

子类契约由 ``__init_subclass__`` 在类定义期 fail-fast 校验四个声明
（name/capabilities/required_env/active），与 enrichers 的非静默纪律一致。基类
**不**限制子类携带自定义 __init__（注入 client）、私有 helper、常量、__slots__，
也不限制间接继承或多重继承 —— 这些是 PR6 适配器做依赖注入与单测所必需的。

**非多态强制。** 声明校验与三个核心守卫（canonical 值、凭据可用性、后置契约）
都是**模块级函数**，由 __init_subclass__ 与 _dispatch 直接按名调用，绝不经
self/cls 动态派发。因此 adapter 即便定义了同名私有 helper（如 _validate_fetched），
也无法覆盖或绕过核心契约 —— _fetch 是唯一的多态查询钩子。dispatch 读取的是在
定义期已被校验的**类声明**（经 ``type(self)``），实例上偶然的同名属性不改变分发。

本模块不发起任何网络 I/O，不实现任何真实 provider。
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import final

from apkscan.intel.models import (
    CAPABILITY_ENTITY_KIND,
    IntelCapability,
    IntelResult,
    IntelStatus,
    ProviderContractError,
    _ENV_NAME_RE,
    _PROVIDER_NAME_RE,
    validate_certificate_value,
)
from apkscan.network import NetworkEntity
from apkscan.network.fingerprints import normalize_domain, normalize_ip

logger = logging.getLogger(__name__)

#: 异常类型名不是合法 Python 标识符时的兜底 reason。
_FALLBACK_EXCEPTION_NAME = "ProviderError"


def _safe_exception_name(exc: BaseException) -> str:
    """返回异常的类型名（仅当它是合法标识符），否则返回 ProviderError。

    绝不返回异常对象、消息或 traceback —— 消息可能内嵌带凭据的 URL。
    """
    name = type(exc).__name__
    return name if name.isidentifier() else _FALLBACK_EXCEPTION_NAME


# ---------------------------------------------------------------------------
# 模块级、非多态的校验与守卫。
#
# 这些函数**不是**类方法：__init_subclass__ 与 _dispatch 直接按名调用它们，不经
# self/cls 派发。因此 adapter 定义同名私有 helper 无法覆盖它们，核心契约不可被
# 意外或恶意绕过。_fetch 是唯一保留的多态查询钩子。
# ---------------------------------------------------------------------------


def _validate_declarations(cls: type) -> None:
    """在类定义期 fail-fast 校验四个声明；任何违约抛 ValueError/TypeError。

    读取 ``cls`` 上经 MRO 解析的四个声明值（数据属性，非可调用派发），因此中间
    基类无法通过覆盖某个「校验 helper」让 concrete leaf 的非法声明蒙混过关。
    """
    name = cls.name  # type: ignore[attr-defined]
    if not isinstance(name, str) or not _PROVIDER_NAME_RE.fullmatch(name):
        raise ValueError(f"provider name must match ^[a-z][a-z0-9_]*$, got {name!r}")

    caps = cls.capabilities  # type: ignore[attr-defined]
    if not isinstance(caps, frozenset):
        raise TypeError("capabilities must be a frozenset")
    if not caps:
        raise ValueError("capabilities must not be empty")
    for cap in caps:
        if not isinstance(cap, IntelCapability):
            raise TypeError("capabilities must contain IntelCapability members")

    env = cls.required_env  # type: ignore[attr-defined]
    if not isinstance(env, tuple):
        raise TypeError("required_env must be a tuple")
    seen: set[str] = set()
    for entry in env:
        if not isinstance(entry, str) or not _ENV_NAME_RE.fullmatch(entry):
            raise ValueError(
                f"required_env names must match ^[A-Za-z_][A-Za-z0-9_]*$, got {entry!r}"
            )
        if entry in seen:
            raise ValueError(f"duplicate required_env name: {entry!r}")
        seen.add(entry)

    if cls.active is not False:  # type: ignore[attr-defined]
        raise ValueError("active must be exactly False (passive-only declaration)")


def _require_canonical_value(capability: IntelCapability, query: NetworkEntity) -> None:
    """能力对应的 canonical query 值校验；非 canonical 抛 ValueError（在 _fetch 之前）。"""
    value = query.value
    if capability is IntelCapability.LOOKUP_IP:
        if normalize_ip(value) != value:
            raise ValueError(f"non-canonical IP query value: {value!r}")
    elif capability is IntelCapability.LOOKUP_DOMAIN:
        if normalize_domain(value) != value:
            raise ValueError(f"non-canonical domain query value: {value!r}")
    else:  # LOOKUP_CERT
        validate_certificate_value(value)


def _missing_credentials(required_env: tuple[str, ...]) -> tuple[str, ...]:
    """any-one 语义：required_env 中任一变量有非空 stripped 值即启用，否则返回缺失名单。

    只读 os.environ 的**值是否存在**，从不返回或记录值本身。
    """
    if not required_env:
        return ()
    for name in required_env:
        if (os.environ.get(name) or "").strip():
            return ()
    return tuple(required_env)


def _validate_fetched(
    provider_name: str,
    capability: IntelCapability,
    query: NetworkEntity,
    fetched: object,
) -> IntelResult:
    """后置契约校验：_fetch 返回值必须是精确匹配、仅 SUCCESS/EMPTY 的 IntelResult。"""
    if not isinstance(fetched, IntelResult):
        raise ProviderContractError("_fetch must return an IntelResult")
    if fetched.provider != provider_name:
        raise ProviderContractError("_fetch result provider mismatch")
    if fetched.capability is not capability:
        raise ProviderContractError("_fetch result capability mismatch")
    if fetched.query.to_dict() != query.to_dict():
        raise ProviderContractError("_fetch result query mismatch")
    if fetched.status not in (IntelStatus.SUCCESS, IntelStatus.EMPTY):
        raise ProviderContractError("_fetch may only return SUCCESS or EMPTY")
    return fetched


def _dispatch(
    provider: "IntelProvider", capability: IntelCapability, query: NetworkEntity
) -> IntelResult:
    """共享分发守卫（模块级、非多态）。

    这是 lookup_* 的唯一实现路径：三个 @final 模板方法直接按名调用本函数，绝不经
    ``self._dispatch`` 派发，因此 adapter 即便定义同名 ``_dispatch`` 方法也无法绕过
    核心契约 —— ``_fetch`` 是唯一保留的多态查询钩子。

    依次：类型检查 query → 声明能力 → 实体类型匹配 → canonical 值 → 凭据可用性 →
    在密钥安全的 try/except 内调用 ``provider._fetch`` 并做后置契约校验。
    """
    if not isinstance(query, NetworkEntity):
        raise TypeError("query must be a NetworkEntity")

    # 读定义期已校验的类声明（经 type(provider)），而非实例属性：name 是稳定的
    # provider 标识，分发不应受实例上偶然同名属性影响。
    cls = type(provider)
    provider_name = cls.name

    if capability not in cls.capabilities:
        return IntelResult.unsupported(
            provider_name, capability, query, "capability_not_supported"
        )

    expected_kind = CAPABILITY_ENTITY_KIND[capability]
    if query.kind is not expected_kind:
        return IntelResult.unsupported(
            provider_name, capability, query, "entity_kind_mismatch"
        )

    # 核心守卫一律调用模块级函数（非多态）：adapter 的同名私有 helper 不会被意外
    # 命中，核心契约无法被绕过。_fetch 是唯一多态查询钩子。
    _require_canonical_value(capability, query)

    missing = _missing_credentials(cls.required_env)
    if missing:
        return IntelResult.unavailable(provider_name, capability, query, missing)

    try:
        fetched = provider._fetch(capability, query)
        return _validate_fetched(provider_name, capability, query, fetched)
    except Exception as exc:  # noqa: BLE001 - 脱敏后转 FAILURE，见下
        reason = _safe_exception_name(exc)
        logger.debug(
            "intel fetch failed provider=%s capability=%s error=%s",
            provider_name,
            capability.value,
            reason,
        )
        return IntelResult.failure(provider_name, capability, query, reason)


class IntelProvider(ABC):
    """无状态的被动情报适配器契约。

    子类声明 name/capabilities/required_env/active 四个类属性，并实现唯一的
    抽象钩子 _fetch。active 必须恰好为 False —— 这是可审计的被动声明。子类可以
    自由携带自定义 __init__、私有 helper、常量与 __slots__，也可间接/多重继承；
    但**无法**通过同名 helper 覆盖声明校验或核心守卫（它们是模块级函数）。
    """

    #: 小写 provider 标识（^[a-z][a-z0-9_]*$）。子类必须覆盖。
    name: str = ""
    #: 声明支持的能力集合（非空 frozenset）。
    capabilities: frozenset[IntelCapability] = frozenset()
    #: 凭据环境变量名（任一非空即启用）；可为空。
    required_env: tuple[str, ...] = ()
    #: 被动声明；必须恰好为 False。
    active: bool = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # 只对**具体** provider（已实现 _fetch）fail-fast 校验四声明；仍把 _fetch
        # 留作抽象的中间基类（依赖注入用的共享层）留待其具体子类校验，不被过早拒绝。
        # 注意：__init_subclass__ 由 type.__new__ 调用，早于 ABCMeta 计算
        # __abstractmethods__，故不能依赖 __abstractmethods__，改看 _fetch 本身。
        # 校验走模块级函数 _validate_declarations（非多态），adapter 无法覆盖。
        fetch = getattr(cls, "_fetch", None)
        if getattr(fetch, "__isabstractmethod__", False):
            return
        _validate_declarations(cls)

    # ---- 公开模板方法 ----
    # @final：这些是密封的模板方法，唯一多态钩子是 _fetch。运行时不强制（保持普通
    # ABC），但 Pyright 会在 PR6 adapter 非故意覆写 lookup_* 时静态报错。共享分发
    # 走模块级函数 _dispatch（非多态），adapter 即便定义同名 _dispatch 也无法绕过。

    @final
    def lookup_ip(self, entity: NetworkEntity) -> IntelResult:
        return _dispatch(self, IntelCapability.LOOKUP_IP, entity)

    @final
    def lookup_domain(self, entity: NetworkEntity) -> IntelResult:
        return _dispatch(self, IntelCapability.LOOKUP_DOMAIN, entity)

    @final
    def lookup_cert(self, entity: NetworkEntity) -> IntelResult:
        return _dispatch(self, IntelCapability.LOOKUP_CERT, entity)

    # ---- 适配器唯一钩子 ----

    @abstractmethod
    def _fetch(self, capability: IntelCapability, query: NetworkEntity) -> IntelResult:
        """执行被动查询并返回 SUCCESS 或 EMPTY 的 IntelResult。PR5 无真实实现。"""
        raise NotImplementedError
