"""androguard 驱动的 AnalysisContext 实现。

★ 接口契约：androguard 的 import 只允许出现在本文件。
分析器一律通过 AnalysisContext 协议访问数据，禁止直接依赖 androguard。

懒解析：DEX / 证书等昂贵操作按需触发并缓存。
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Iterator
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any

from apkscan.core.models import (
    AnalysisConfig,
    CertInfo,
    Component,
    ComponentSet,
)

logger = logging.getLogger(__name__)


_ANDROGUARD_SILENCED = False


def _silence_androguard_logging() -> None:
    """关闭 androguard 4.x 的 loguru 噪音（解析大 APK 会刷出上百 MB DEBUG）。

    androguard 用 loguru 而非 stdlib logging，stdlib 的 level 配置管不到它，故显式 disable。

    **启动提速**：本函数会 import loguru（拉起 loguru→asyncio ~114ms）；故**不在模块导入期
    调用**，而是延迟到真正 import androguard 之前（load_apk / _load_extra_dex 内）才调一次。
    这样 ``import apkscan.cli``（doctor/gui/--version/--help 等不分析的命令）不再白付 loguru。
    幂等：只在首次（androguard 用到前）执行 import+disable。loguru 缺失则跳过并记 debug。
    """
    global _ANDROGUARD_SILENCED
    if _ANDROGUARD_SILENCED:
        return
    try:
        from loguru import logger as _loguru_logger

        _loguru_logger.disable("androguard")
        _ANDROGUARD_SILENCED = True
    except Exception:
        logger.debug("禁用 androguard loguru 失败（忽略）", exc_info=True)


# 合法 NCName：首字符字母/下划线，其余字母/数字/下划线/'-'/'.'（不含冒号）。
_NCNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")


@lru_cache(maxsize=512)
def _uri_lxml_ok(uri: str) -> bool:
    """该 uri 能否作为 namespace URI 被 lxml ``etree.Element`` 接受（以 lxml 实判为准）。

    不用手搓字符黑名单：lxml 拒收的字符集远比直觉广——除空白/C0-C1 控制符/NUL 外，还含
    ``< > | ^ [ ] { } ` "`` 等可见 ASCII 及全部非 ASCII（0xA0-0xFF）。黑名单必有漏网，加固壳
    换个投毒字符即可绕过、让构造再次抛 'Invalid namespace URI'。直接问 lxml 最稳，对任意投毒
    变体都满足"净化结果必被 lxml 接受"的后置条件。按 uri 串 memoize（get_xml_obj 对每个
    START_TAG 都读一次 nsmap，避免重复探测）。空串 '' 合法（保留）。
    """
    if not uri:
        return True  # 空 URI 对 lxml 合法，快路返回（兼具防版本差异）
    try:
        from lxml import etree  # type: ignore[reportMissingModuleSource]

        etree.Element("_p", nsmap={"_p": uri})  # type: ignore[reportUnknownMemberType]
    except ValueError:
        return False
    except Exception:  # noqa: BLE001 - lxml 缺失/异常不阻塞解析，保守保留（绝不误丢合法项）
        logger.debug("lxml namespace URI 校验异常，保守保留：%r", uri, exc_info=True)
        return True
    return True


def _sanitize_nsmap(raw: dict[str | None, str]) -> dict[str | None, str]:
    """净化 AXML 的 {prefix: uri} 命名空间映射，使其能被 lxml ``etree.Element`` 接受。

    背景：加固壳在二进制 AndroidManifest 注入【非法 namespace URI / 前缀】（反分析投毒）。
    androguard 在 APK() 构造期把 manifest 转 lxml，``etree.Element(tag, nsmap=...)`` 对非法
    URI/前缀抛 ValueError，而 androguard 只救 'Invalid namespace prefix'，坏 URI 落 else:
    raise → 整个 APK() 构造崩 → fxapk fail-fast、静态阶段全死。apktool 的宽容 AXML 解码器
    则跳过非法项继续出包名/资源。本函数对齐 apktool：丢坏项、留好项、空前缀降级为默认 ns，
    让 lxml 不再抛、manifest 降级可解。

    逐项 {prefix: uri} 规则（顺序固定，保证幂等）：
      1. URI 被 lxml 拒收（含空白/控制符/NUL/`< > | ^` 等可见 ASCII 及非 ASCII，见
         :func:`_uri_lxml_ok`）→ 整对丢弃（投毒 URI 无法安全救回；据下游分析，android: 属性
         走属性自带 URI(getAttributeNamespace)，与 nsmap 无关，丢弃不会让组件/exported 解析
         读空）。空串 URI '' 合法，保留。
      2. 前缀规整：None 保留；'' → None（空前缀=默认命名空间，不丢、不留 ''）；
         非法 NCName（含 '<!--'/空格/冒号/数字开头）→ 整对丢弃（无法安全规整）；合法则原样留。
      3. 规整后若出现重复 key（如多个空前缀都→None），保留首个、丢后续。
      4. 返回新 dict，绝不原地改 raw（纯函数，便于单测）。

    Args:
        raw: 原始 {prefix: uri} 映射；prefix 可能为 None/''/非法 NCName，uri 可能被投毒。

    Returns:
        净化后的新 dict，可安全传给 ``etree.Element(nsmap=...)``。
    """
    out: dict[str | None, str] = {}
    for prefix, uri in raw.items():
        # 1) URI 坏（以 lxml 实判为准）→ 整对丢弃（空串 '' 合法，lxml 接受）。
        if uri is not None and not _uri_lxml_ok(uri):
            continue
        # 2) 前缀规整。
        key: str | None
        if prefix is None or prefix == "":
            key = None  # 空前缀 = 默认命名空间
        elif _NCNAME_RE.match(prefix) is not None:
            key = prefix
        else:
            continue  # 非法 NCName，无法安全规整 → 丢弃
        # 3) 去重：保留首个出现的 key。
        if key in out:
            continue
        out[key] = uri
    return out


_AXML_NSMAP_PATCHED = False


def _install_axml_nsmap_shim() -> None:
    """幂等 monkeypatch androguard ``AXMLParser.nsmap``（property），使其返回净化映射。

    把原 property 取到的 {prefix: uri} 过 :func:`_sanitize_nsmap` 后再返回，让被加固壳投毒
    的非法 namespace URI/前缀在抵达 ``etree.Element`` 前被剔除，避免 APK() 构造期崩溃。

    幂等：用模块级标记 ``_AXML_NSMAP_PATCHED`` 防重复包裹（否则多次 load_apk 会把 property
    层层套娃）。安装失败时 ``logging.exception`` 如实记录后回退原行为（不 swallow、不裸 pass）。
    androguard 的 import 只允许出现在本文件。
    """
    global _AXML_NSMAP_PATCHED
    if _AXML_NSMAP_PATCHED:
        return
    try:
        from androguard.core.axml import AXMLParser

        original = AXMLParser.nsmap
        if not isinstance(original, property):
            logger.warning("AXMLParser.nsmap 非 property（androguard 版本变化？），跳过 shim")
            return
        original_fget = original.fget
        if original_fget is None:
            logger.warning("AXMLParser.nsmap property 无 getter，跳过 shim")
            return

        def _sanitized_nsmap(self: Any) -> dict[str | None, str]:
            return _sanitize_nsmap(original_fget(self))

        AXMLParser.nsmap = property(_sanitized_nsmap)  # type: ignore  # noqa: PGH003 - property 无 setter，monkeypatch 替换
        _AXML_NSMAP_PATCHED = True
    except Exception:  # noqa: BLE001 - 装 shim 失败要如实记录后回退原行为，不阻塞加载
        logger.exception("安装 AXML nsmap 净化 shim 失败，回退原行为（坏命名空间可能仍致解析失败）")


class ApkParseError(RuntimeError):
    """APK 无法解析（损坏 / 非 APK）。fail fast 用。"""


#: read_file 缓存的单文件上限：超过此值的文件（大 .so / 大资源）读到后不进 _read_cache，
#: 避免巨型二进制随分析常驻内存（缓存本意是让多个分析器重复读小文本资源命中，大文件重复读
#: 罕见，收益远不抵内存代价）。与 snapshot.py 的 _MAX_PREREAD_BYTES（预读进快照的单文件上限）
#: 同口径 32MB：两处都在挡"病态超大单文件把内存撑爆"，取相同阈值保持一致。正确性不受影响——
#: 未缓存只是每次重读，read_file 返回的字节完全一致。
_MAX_READ_CACHE_BYTES = 32 * 1024 * 1024


class ApkContext:
    """AnalysisContext 的真实实现，由 androguard 驱动。

    通过 load_apk() 构造，不要直接实例化。
    """

    platform: str = "android"  # 包平台（IPA 走 IpaContext，返回 "ios"）

    def __init__(
        self,
        apk: Any,  # androguard.core.apk.APK；动态访问其方法，故标 Any
        dex_objs: list[Any],
        config: AnalysisConfig,
        *,
        apk_path: str = "",
        extra_dex_objs: list[Any] | None = None,
        dex_available: bool = True,
        apk_validation_ok: bool = True,
    ) -> None:
        # apk: androguard.core.apk.APK；dex_objs: list[DEX]
        self._apk = apk
        self._dex_objs = dex_objs
        # extra_dex_objs: 脱壳 dump 出来、外部传入的额外 DEX（androguard DEX 实例）。
        # 其字符串并入 dex_strings() 产出，使脱壳后的隐藏端点/SDK 也能被静态分析命中。
        self._extra_dex_objs = list(extra_dex_objs or [])
        self.config = config
        # apk_path: APK 原始文件绝对路径（jadx/unpack 等增强器需要；无则空串，增强器应优雅跳过）。
        self.apk_path = apk_path
        # 供 pipeline 写入 Report.meta，使"加固导致 DEX 不可见 / 合法性校验异常"
        # 这类降级在报告里显式可见，而非静默当成"扫描完毕无命中"。
        self.dex_available = dex_available
        self.apk_validation_ok = apk_validation_ok

    # ---- 标量属性 -------------------------------------------------------

    @cached_property
    def package_name(self) -> str:
        try:
            return self._apk.get_package() or ""
        except Exception:  # noqa: BLE001 - 协议要求始终返回值
            logger.exception("get_package 失败")
            return ""

    @cached_property
    def manifest_xml(self) -> str:
        """解码后的 AndroidManifest.xml 文本。"""
        try:
            axml = self._apk.get_android_manifest_axml()
            raw = axml.get_xml()
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            return str(raw)
        except Exception:  # noqa: BLE001
            logger.exception("解码 AndroidManifest.xml 失败")
            return ""

    # ---- 协议方法 -------------------------------------------------------

    def permissions(self) -> list[str]:
        try:
            return list(self._apk.get_permissions() or [])
        except Exception:
            logger.exception("get_permissions 失败")
            return []

    def components(self) -> ComponentSet:
        return self._components

    @cached_property
    def _components(self) -> ComponentSet:
        return ComponentSet(
            activities=self._collect_components("activity", self._apk.get_activities),
            services=self._collect_components("service", self._apk.get_services),
            receivers=self._collect_components("receiver", self._apk.get_receivers),
            providers=self._collect_components("provider", self._apk.get_providers),
        )

    def _collect_components(self, kind: str, getter) -> list[Component]:
        out: list[Component] = []
        try:
            names = getter() or []
        except Exception:
            logger.exception("枚举组件失败：kind=%s", kind)
            return out
        for name in names:
            out.append(Component(name=name, exported=self._is_exported(kind, name), kind=kind))
        return out

    def _is_exported(self, kind: str, name: str) -> bool:
        """组件是否导出（含 intent-filter 隐式导出）。无法判定时返回 False。

        androguard 4.x 已无 get_element，且 exported 的隐式导出语义需自行判定，
        故统一从 manifest XML 解析（见 _exported_map），版本无关。
        """
        m = self._exported_map
        if name in m:
            return m[name]
        resolved = _resolve_name(name, self.package_name or "")
        return m.get(resolved, False)

    @cached_property
    def _exported_map(self) -> dict[str, bool]:
        """构造 {组件名: exported}（FQN 与原始名双键）。

        直接用 androguard 已从二进制 AXML 解析好的 manifest 树（lxml Element），
        不再用 stdlib 解析字符串：AXML 结构上不含 DTD/外部实体，无 XXE 面，
        且省去再解析一次。androguard 4.x 已无 get_element，故自行判定 exported。

        判定规则：显式 android:exported 优先；未声明时，含 <intent-filter> 视为
        （潜在）导出——对调证更安全：不漏报可被外部触发的攻击面。
        """
        mapping: dict[str, bool] = {}
        try:
            root = self._apk.get_android_manifest_xml()
        except Exception:
            logger.exception("获取 manifest 解析树失败，exported 判定降级为全 False")
            return mapping
        if root is None:
            return mapping

        ns = "{http://schemas.android.com/apk/res/android}"
        try:
            pkg = root.get("package") or self.package_name or ""
            app = root.find("application")
        except Exception:
            logger.exception("遍历 manifest 树失败")
            return mapping
        if app is None:
            return mapping

        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.findall(tag):
                try:
                    name = el.get(ns + "name") or el.get("name")
                    if not name:
                        continue
                    exported_attr = el.get(ns + "exported")
                    if exported_attr is None:
                        exported_attr = el.get("exported")
                    if exported_attr is not None:
                        exported = str(exported_attr).strip().lower() == "true"
                    else:
                        exported = el.find("intent-filter") is not None
                    mapping[_resolve_name(name, pkg)] = exported
                    mapping[name] = exported  # 兼容以相对名查询
                except Exception:
                    logger.exception("解析单个组件 exported 失败，跳过：tag=%s", tag)
        return mapping

    def dex_strings(self) -> Iterator[str]:
        """产出全部 DEX 字符串池（主 DEX + 外部脱壳 DEX）。

        逐个 DEX 取，单个失败不影响其余。外部 extra dex（脱壳 dump）紧随主 DEX 产出。
        首次访问解码并缓存为 tuple（见 _dex_strings_tuple）；多个分析器重复遍历时直接
        命中缓存，避免对同一 DEX 反复做 mutf8 解码。迭代顺序/内容与逐 DEX 直出完全一致。
        """
        return iter(self._dex_strings_tuple)

    @cached_property
    def _dex_strings_tuple(self) -> tuple[str, ...]:
        """全部 DEX 字符串的不可变快照：主 DEX 在前、extra 脱壳 DEX 在后。

        一次性解码并缓存，使 dex_strings() 的重复遍历（6+ 个分析器）只解码一次。
        顺序与 _dex_objs → _extra_dex_objs 逐 DEX 产出严格一致。
        """
        out: list[str] = []
        for dex in self._dex_objs:
            out.extend(_iter_dex_strings(dex))
        for dex in self._extra_dex_objs:
            out.extend(_iter_dex_strings(dex))
        return tuple(out)

    def list_files(self) -> list[str]:
        try:
            return list(self._apk.get_files() or [])
        except Exception:
            logger.exception("get_files 失败")
            return []

    @cached_property
    def _read_cache(self) -> dict[str, bytes | None]:
        """read_file 的按需字节缓存：path -> bytes|None（None 也缓存，避免重复未命中查询）。

        bytes 不可变，缓存返回值语义不变；多个分析器对同一文本资源的重复读取直接命中。
        """
        return {}

    def read_file(self, path: str) -> bytes | None:
        cache = self._read_cache
        if path in cache:
            return cache[path]
        try:
            data = self._apk.get_file(path)
        except Exception:
            # androguard 对缺失文件抛 FileNotPresent；视为正常缺失但仍记录
            logger.debug("read_file 未命中：%s", path, exc_info=True)
            data = None
        # 超大文件（大 .so / 大资源）不进缓存，避免常驻内存。None（未命中）仍缓存以避免重复
        # 未命中查询；小文件照常缓存供多分析器重复读命中。未缓存的大文件仍返回完整字节。
        if data is None or len(data) <= _MAX_READ_CACHE_BYTES:
            cache[path] = data
        else:
            logger.debug(
                "read_file 跳过缓存（超 %d 字节，避免常驻内存）：%s（%d 字节）",
                _MAX_READ_CACHE_BYTES,
                path,
                len(data),
            )
        return data

    def native_libs(self) -> list[str]:
        """APK 内所有 .so 路径（含 lib/<abi>/ 下）。"""
        return [f for f in self.list_files() if f.endswith(".so")]

    def certificates(self) -> list[CertInfo]:
        return self._certificates

    @cached_property
    def _certificates(self) -> list[CertInfo]:
        out: list[CertInfo] = []
        try:
            certs = self._apk.get_certificates() or []
        except Exception:
            logger.exception("get_certificates 失败")
            return out

        schemes = self._signature_schemes()
        for cert in certs:
            try:
                out.append(self._to_certinfo(cert, schemes))
            except Exception:
                logger.exception("解析证书失败：%r", cert)
        return out

    def _signature_schemes(self) -> list[str]:
        schemes: list[str] = []
        for scheme, checker in (
            ("v1", getattr(self._apk, "is_signed_v1", None)),
            ("v2", getattr(self._apk, "is_signed_v2", None)),
            ("v3", getattr(self._apk, "is_signed_v3", None)),
        ):
            if checker is None:
                continue
            try:
                if checker():
                    schemes.append(scheme)
            except Exception:
                logger.exception("签名方案检测失败：%s", scheme)
        return schemes

    @staticmethod
    def _to_certinfo(cert: Any, schemes: list[str]) -> CertInfo:
        """把 asn1crypto x509.Certificate 转成 CertInfo。"""
        subject = _human(getattr(cert, "subject", None))
        issuer = _human(getattr(cert, "issuer", None))

        sha256 = ""
        digest = getattr(cert, "sha256", None)
        if isinstance(digest, (bytes, bytearray)):
            sha256 = digest.hex()
        else:
            try:
                der = cert.dump()  # asn1crypto: DER bytes
                sha256 = hashlib.sha256(der).hexdigest()
            except Exception:
                logger.exception("计算证书 SHA256 失败")

        not_before = _dt(getattr(cert, "not_valid_before", None))
        not_after = _dt(getattr(cert, "not_valid_after", None))

        is_debug = "Android Debug" in subject or "Android Debug" in issuer

        return CertInfo(
            subject=subject,
            issuer=issuer,
            sha256=sha256,
            not_before=not_before,
            not_after=not_after,
            is_debug=is_debug,
            schemes=list(schemes),
        )


def _iter_dex_strings(dex: Any) -> Iterator[str]:
    """惰性产出单个 DEX 的字符串池，bytes 解码为 str。单个 DEX 失败记录后跳过。

    坏 DEX 只跳过自身：get_strings() 抛错、返回 None、或返回非可迭代/迭代中途抛错，
    都记日志后中断本 DEX，不让异常冒泡中断整个 dex_strings 生成器（否则后续含 extra
    脱壳 DEX 全产不出，与"单 DEX 失败跳过"的契约不符）。
    """
    try:
        strings = dex.get_strings()
    except Exception:
        logger.exception("get_strings 失败：dex=%r", dex)
        return
    if strings is None:
        logger.warning("get_strings 返回 None，跳过该 DEX：dex=%r", dex)
        return
    try:
        for s in strings:
            if isinstance(s, bytes):
                yield s.decode("utf-8", errors="replace")
            else:
                yield str(s)
    except Exception:
        logger.exception("遍历 DEX 字符串失败，跳过该 DEX：dex=%r", dex)
        return


def _load_extra_dex(extra_dex: list[str]) -> list:
    """把 extra_dex 路径列表（脱壳 dump 的 .dex 文件）解析为 androguard DEX 实例列表。

    - 单个文件读取/解析失败 → try/except + logging 跳过，不影响主流程（不裸 pass、不吞错）。
    - androguard 的 import 只允许出现在本文件。
    """
    _silence_androguard_logging()  # 用 androguard 前才禁其 loguru（避免启动期白付 loguru）
    from androguard.core.dex import DEX

    out: list = []
    for path in extra_dex:
        try:
            buff = Path(path).read_bytes()
            out.append(DEX(buff))
        except Exception as exc:  # noqa: BLE001 - 坏/不兼容 DEX 跳过即可，不炸主流程
            # 收敛成一行 warning + 异常摘要（不打整坨 traceback）：frida-dexdump dump 的
            # Android 10+ DEX 常因 androguard 不认 hidden-api flag 抛 ValueError
            # （HiddenApiClassDataItem.*ApiFlag），是已知库限制、会成批出现，整坨 traceback
            # 纯噪音。仍如实记录（不 swallow），只是不再刷屏。
            logger.warning("解析额外 DEX 失败，跳过：%s（%s: %s）", path, type(exc).__name__, exc)
    return out


def _resolve_name(name: str, pkg: str) -> str:
    """把 manifest 里的组件名解析为全限定名（FQN）。

    ".Foo" -> pkg+".Foo"；"Foo"（无点）-> pkg+".Foo"；已是 FQN 原样返回。
    """
    name = name.strip()
    if not name:
        return name
    if name.startswith("."):
        return pkg + name if pkg else name
    if "." not in name and pkg:
        return f"{pkg}.{name}"
    return name


def _human(name: Any) -> str:
    """从 asn1crypto Name 取人类可读字符串。"""
    if name is None:
        return ""
    human = getattr(name, "human_friendly", None)
    if human is not None:
        return str(human)
    return str(name)


def _dt(value: Any) -> str:
    """日期时间转 ISO 字符串。"""
    if value is None:
        return ""
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return str(iso())
        except Exception:
            logger.exception("日期 isoformat 失败")
    return str(value)


def load_apk(
    path: str,
    config: AnalysisConfig,
    extra_dex: list[str] | None = None,
) -> ApkContext:
    """加载 APK 并构造 ApkContext。

    APK 无法解析时抛 ApkParseError（fail fast）。

    extra_dex: 额外的 .dex 文件路径列表（脱壳 dump 出来的）。其字符串并入 dex_strings()
               产出，使脱壳后的隐藏端点/SDK 也能被静态分析命中。单个 dex 失败不影响主流程。
    """
    # androguard 的 import 只允许出现在本文件。
    _silence_androguard_logging()  # 用 androguard 前才禁其 loguru（避免启动期白付 loguru）
    # 加固壳常在二进制 manifest 注入非法 namespace URI（反分析投毒），会让 APK() 构造期
    # 的 lxml etree.Element 抛 ValueError 致整体 fail-fast。装幂等 shim 净化 nsmap，对齐
    # apktool 的宽容降级，让 manifest 可解（包名/组件/权限/证书等不再因此全丢）。
    _install_axml_nsmap_shim()
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    try:
        apk = APK(path)
    except Exception as exc:  # noqa: BLE001 - 转成清晰的领域异常
        logger.exception("APK 解析失败：%s", path)
        raise ApkParseError(f"无法解析 APK：{path}（{exc}）") from exc

    apk_validation_ok = True
    try:
        if not apk.is_valid_APK():
            raise ApkParseError(f"非法 APK（结构校验未通过）：{path}")
    except ApkParseError:
        raise
    except Exception:  # noqa: BLE001 - is_valid_APK 自身异常不应阻塞，但要记录并标记
        logger.exception("is_valid_APK 检测异常，继续尝试加载：%s", path)
        apk_validation_ok = False

    dex_objs: list = []
    dex_available = True
    try:
        # ★ 提速（实测 22.8s→8.8s，2.6x）：只建 DEX 对象（字符串池/类/方法即够静态分析），从已解析的
        #   apk 直接取各 classes*.dex 字节构造 DEX。**不走 AnalyzeAPK**——后者会重复解析一遍 APK，
        #   还构建并丢弃 androguard 最耗时的 Analysis 交叉引用图（本项目从不使用 dx）。
        for dex_bytes in apk.get_all_dex():
            try:
                dex_objs.append(DEX(dex_bytes))
            except Exception:
                logger.exception("单个 DEX 解析失败，跳过：%s", path)
    except Exception:
        # DEX 不可见（加固）不应使整体失败：manifest/资源/证书仍可用
        logger.exception("DEX 解析失败（可能加固），降级为无 DEX 字符串：%s", path)
        dex_objs = []
    # 额外 DEX（脱壳 dump）解析；失败的单个 dex 已在 _load_extra_dex 内跳过。
    extra_dex_objs = _load_extra_dex(list(extra_dex or [])) if extra_dex else []

    # DEX 解析成功但为空（典型加固/无 dex）同样视为"静态 DEX 不可用"，需在报告显式告警。
    # 注意：仅主 DEX 为空时才告警；若 extra dex（脱壳）补回了字符串，则视为可用。
    if not dex_objs and not extra_dex_objs:
        dex_available = False

    try:
        apk_path = str(Path(path).resolve())
    except Exception:
        logger.exception("解析 APK 绝对路径失败，回退原始路径：%s", path)
        apk_path = path

    return ApkContext(
        apk=apk,
        dex_objs=dex_objs,
        config=config,
        apk_path=apk_path,
        extra_dex_objs=extra_dex_objs,
        dex_available=dex_available,
        apk_validation_ok=apk_validation_ok,
    )
