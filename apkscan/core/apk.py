"""androguard 驱动的 AnalysisContext 实现。

★ 接口契约：androguard 的 import 只允许出现在本文件。
分析器一律通过 AnalysisContext 协议访问数据，禁止直接依赖 androguard。

懒解析：DEX / 证书等昂贵操作按需触发并缓存。
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
import subprocess
import zipfile
import zlib
from collections.abc import Iterator, Mapping
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, BinaryIO, NoReturn

from apkscan.core.redact import safe_exception_diagnostic, safe_exception_text
from apkscan.core import tools
from apkscan.core.models import (
    AnalysisConfig,
    CertInfo,
    Component,
    ComponentSet,
)

logger = logging.getLogger(__name__)


_ANDROGUARD_SILENCED = False

# ---------------------------------------------------------------------------
# 清单包名交叉校验（对抗“清单投毒”：构造 AndroidManifest 让 androguard 静默 mis-parse，
# 而 aapt / Android 运行时照常识别 → fxapk 拿到错的包名，动态抓包/脱壳打错目标）。
# ---------------------------------------------------------------------------
_AAPT_TIMEOUT = 30.0
# Android 包名形态：≥2 段、每段以字母/下划线起、只含 [A-Za-z0-9_]（用于识别 androguard 的畸形输出）。
_PKG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


def _looks_like_package(s: str) -> bool:
    """是否像合法 Android 包名（畸形/为空/含怪字符 → False）。"""
    return bool(s) and len(s) <= 255 and bool(_PKG_RE.match(s))


def _parse_aapt_package(stdout: str) -> str:
    """从 ``aapt/aapt2 dump badging`` 输出解析 ``package: name='...'``；解不出 → ""。"""
    m = re.search(r"package:\s*name='([^']*)'", stdout or "")
    return m.group(1).strip() if m else ""


# 二进制 AXML 结构常量（用于绕开 androguard 直读字符串池）。
_AXML_TYPE = 0x0003  # RES_XML_TYPE（文件头）
_RES_STRING_POOL = 0x0001  # RES_STRING_POOL_TYPE
_RES_XML_START_ELEMENT = 0x0102  # RES_XML_START_ELEMENT_TYPE
_UTF8_FLAG = 0x100  # 字符串池 flags：UTF-8 编码位


def _axml_package_from_bytes(raw: bytes) -> str:
    """容错：直接从二进制 AndroidManifest.xml 读 ``<manifest package=...>``，不经 androguard/lxml。

    用途：清单投毒（把元素/属性命名空间或属性值的字符串引用构造成非法/越界）会让 androguard
    解析出空包名，但 ``package`` 字符串本身仍在字符串池里。本函数按 AXML 二进制结构直读、
    容错跳过畸形项，恢复真实包名；只返回形如合法包名的值（``_looks_like_package``）。

    任何异常/越界/未命中 → 返回 ``""``（绝不抛、绝不臆造）。
    """
    try:
        data = raw
        n = len(data)
        if n < 8 or struct.unpack_from("<H", data, 0)[0] != _AXML_TYPE:
            return ""

        def u16(o: int) -> int:
            return struct.unpack_from("<H", data, o)[0]

        def u32(o: int) -> int:
            return struct.unpack_from("<I", data, o)[0]

        # 字符串池 chunk 紧跟 8 字节文件头。
        sp = 8
        if sp + 28 > n or u16(sp) != _RES_STRING_POOL:
            return ""
        sp_size = u32(sp + 4)
        str_count = u32(sp + 8)
        utf8 = bool(u32(sp + 16) & _UTF8_FLAG)
        strings_start = u32(sp + 20)
        if not (0 < str_count <= 1_000_000):
            return ""
        offs_base = sp + 28
        data_base = sp + strings_start
        if offs_base + 4 * str_count > n:
            return ""

        def get_str(i: int) -> str:
            if not (0 <= i < str_count):
                return ""
            p = data_base + u32(offs_base + 4 * i)
            if not (0 <= p < n):
                return ""
            if utf8:
                q = p + 1
                if data[p] & 0x80:  # 字符数 varint 占 2 字节
                    q += 1
                b = data[q]
                q += 1
                if b & 0x80:  # 字节数 varint 占 2 字节
                    b = ((b & 0x7F) << 8) | data[q]
                    q += 1
                return data[q:q + b].decode("utf-8", "ignore")
            length = u16(p)
            q = p + 2
            if length & 0x8000:  # 字符数占 2 个 u16
                length = ((length & 0x7FFF) << 16) | u16(q)
                q += 2
            return data[q:q + length * 2].decode("utf-16-le", "ignore")

        # 跳过字符串池，遍历后续 chunk 找 <manifest> START_ELEMENT，取其 package 属性。
        pos = sp + sp_size
        guard = 0
        while pos + 16 <= n and guard < 100_000:
            guard += 1
            ctype = u16(pos)
            csize = u32(pos + 4)
            if csize < 16:
                break
            if ctype == _RES_XML_START_ELEMENT and get_str(u32(pos + 20)) == "manifest":
                attr_start = u16(pos + 24)
                attr_count = u16(pos + 28)
                base = pos + 16 + attr_start
                for a in range(min(attr_count, 512)):
                    ap = base + a * 20
                    if ap + 20 > n:
                        break
                    if get_str(u32(ap + 4)) != "package":
                        continue
                    # 优先 rawValue（字符串索引）；投毒把 typedValue.data 打成 0xFFFFFFFF 时它仍有效。
                    val = (get_str(u32(ap + 8)) or get_str(u32(ap + 16))).strip()
                    return val if _looks_like_package(val) else ""
                return ""  # 命中 manifest 但无合法 package
            pos += csize
        return ""
    except Exception:  # noqa: BLE001 - 容错直读：任何异常都退回 ""，绝不影响主流程
        logger.debug("AXML 字符串池直读包名失败（忽略）", exc_info=True)
        return ""


def _decide_manifest_package(
    andro: str, aapt: str | None, apk_valid: bool, axml: str = ""
) -> tuple[str, str | None]:
    """据 androguard / aapt / AXML 字符串池三来源交叉校验包名，返回 (权威包名, 异常描述 or None)。

    ``aapt is None`` = aapt 不可用（无第二意见）；``aapt == ""`` = aapt 跑了但没解出。
    ``axml`` = 直接从二进制 AndroidManifest 字符串池容错直读的包名（不经 androguard），仅在
    androguard 畸形/为空且无 aapt 权威值时作最后兜底（治元素/属性命名空间或字符串引用投毒——
    androguard 静默失败、aapt 又不可用的场景）。
    权威取值优先与 Android 安装/运行时一致的 aapt：androguard 畸形/为空、或与 aapt 不一致 → 采信 aapt。
    绝不臆造：``axml`` 是对清单原始字节的真实读取（非构造），且仅在须恢复且形如合法包名时采用，同时发异常信号。
    """
    andro = (andro or "").strip()
    aapt_s = (aapt or "").strip()
    axml_s = (axml or "").strip()
    andro_ok = _looks_like_package(andro)
    if aapt is not None and aapt_s:  # 有第二意见
        if andro and aapt_s != andro:
            return aapt_s, (
                f"androguard 解析包名={andro!r}、aapt={aapt_s!r} 不一致——疑清单投毒；"
                "已采信 aapt（与安装/运行时一致）"
            )
        if not andro_ok and _looks_like_package(aapt_s):
            return aapt_s, (
                f"androguard 未解出合法包名（得 {andro!r}），aapt 得 {aapt_s!r}——"
                "疑清单解析被投毒破坏；已采信 aapt"
            )
        return andro or aapt_s, None
    # 无 aapt 第二意见（aapt 不可用，或跑了没解出）。
    if apk_valid and not andro_ok:
        # androguard 畸形/空但 APK 结构有效 → 疑清单投毒。用 AXML 字符串池容错直读兜底。
        if _looks_like_package(axml_s):
            return axml_s, (
                f"androguard 未解出合法包名（得 {andro!r}），已由 AndroidManifest 字符串池容错直读"
                f"回退为包名={axml_s!r}——疑清单投毒（元素/属性命名空间或字符串引用被构造破坏），"
                "已按容错解析恢复，请人工核实"
            )
        return andro, (
            f"androguard 解析包名={andro!r} 畸形/为空，而 APK 结构有效——"
            "清单解析可能不可靠（疑清单投毒）；无 aapt 交叉校验，请人工核实"
        )
    return andro, None


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


_HIDDENAPI_FLAGS_RELAXED = False
#: 本次进程里每一次放行事件。必须保留重复项：样本 B 使用了与样本 A 相同的未知 flag，
#: 仍是 B 自己的解析事实；若只存 set，再做集合差会把 B 的事件误删。
_HIDDENAPI_UNKNOWN_FLAG_EVENTS: list[str] = []


def _relax_hiddenapi_flags() -> None:
    """让 androguard 容忍它不认识的 hidden-api flag 取值，而不是整个 DEX 拒载。

    ★这是 androguard 的建模错误，不是 DEX 坏了。AOSP 的 hiddenapi flag 里，低三位是访问限制
      档（0-6），**高位是可叠加的位掩码**（core-platform-api、test-api，新版本还在加）。
      androguard 4.1.4 把高位建成了互斥 IntEnum（只有 0/1/2），于是 3/4/6 这些完全合法的
      组合一律 ``ValueError``，整个 DEX 随之拒载。

    ★实测代价：四次脱壳各抓到 33 个 DEX，只有 10 个载入，23 个卡在这里——静态可见性凭空
      少了约七成，而报告里只是一行 warning。放行是安全的：本工具从不读这些 flag（要的是
      字符串/类/方法），且 DEX 各 map 段按各自偏移独立解析，一个 hiddenapi 段不合预期不会
      污染其余段。

    容错生效过就记下来（``hiddenapi_flags_relaxed``），别让"载进来了"看着像"本来就没问题"。
    幂等；androguard 结构变了（拿不到那两个枚举）则跳过并记 debug，绝不抛。
    """
    global _HIDDENAPI_FLAGS_RELAXED
    if _HIDDENAPI_FLAGS_RELAXED:
        return
    try:
        from androguard.core.dex import HiddenApiClassDataItem

        for enum_name in ("RestrictionApiFlag", "DomapiApiFlag"):
            enum_cls = getattr(HiddenApiClassDataItem, enum_name)

            def _missing_(cls, value, _label: str = enum_name):  # noqa: ANN001
                # 放宽的是"库还不认识的合法档位"，不是"什么都收"：非整数/负数仍走原来的
                # ValueError——把解析错误也放行，等于把坏数据伪装成正常数据。
                # （bool 不必单列：True/False 恒等于已有成员 1/0，压根到不了这里。）
                if not isinstance(value, int) or value < 0:
                    return None
                _HIDDENAPI_UNKNOWN_FLAG_EVENTS.append(f"{_label}={value}")
                # 造伪成员保留原值：调用方拿到的仍是个 int，语义"未知档位"如实体现在名字里。
                pseudo = int.__new__(cls, value)
                pseudo._name_ = f"UNKNOWN_{value}"
                pseudo._value_ = value
                return pseudo

            enum_cls._missing_ = classmethod(_missing_)
        _HIDDENAPI_FLAGS_RELAXED = True
    except Exception:  # noqa: BLE001 - 兼容垫失败不得影响主流程（大不了回到成批拒载）
        logger.debug("放宽 androguard hidden-api flag 校验失败（忽略）", exc_info=True)


def hiddenapi_flags_snapshot() -> int:
    """返回放行事件游标，用作“本样本从哪里开始”的基线。"""
    return len(_HIDDENAPI_UNKNOWN_FLAG_EVENTS)


def hiddenapi_relax_report(since: int | None = None) -> dict[str, object]:
    """有没有用到 hidden-api flag 容错、放行了哪些取值。供 meta 如实登记。

    ★``since``（本样本加载前的事件游标）必须传：batch 是单进程顺序跑多个样本，不切片就会把
      前一个样本的放行写进后一个报告。不能用 set 快照做差——后一个样本若碰到**相同取值**，
      集合差会误判为零；事件游标既隔离样本，也保留重复取值在后续样本中的真实出现。

    ``applied`` 仍是进程级事实（垫子装没装），不按样本收窄：垫子本身幂等、一次性，不该回退
    （回退等于让后面的样本重新成批拒载）。判读"这份报告要不要提容错"看的是 ``unknown_flags``
    非空——那才是本样本自己的账。
    """
    start = since if isinstance(since, int) and since >= 0 else 0
    waved = set(_HIDDENAPI_UNKNOWN_FLAG_EVENTS[start:])
    return {
        "applied": _HIDDENAPI_FLAGS_RELAXED,
        "unknown_flags": sorted(waved),
    }


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
    """幂等 monkeypatch androguard AXML 命名空间处理，使其返回净化映射。

    把原 property 取到的 {prefix: uri} 过 :func:`_sanitize_nsmap` 后再返回，让被加固壳投毒
    的非法 namespace URI/前缀在抵达 ``etree.Element`` 前被剔除；同时把坏 namespace URI 从
    tag / attribute name 的 ``{uri}name`` 拼接路径上剔除，避免 APK() 构造期崩溃。

    幂等：用模块级标记 ``_AXML_NSMAP_PATCHED`` 防重复包裹（否则多次 load_apk 会把 property
    层层套娃）。安装失败时 ``logging.exception`` 如实记录后回退原行为（不 swallow、不裸 pass）。
    androguard 的 import 只允许出现在本文件。
    """
    global _AXML_NSMAP_PATCHED
    if _AXML_NSMAP_PATCHED:
        return
    try:
        from androguard.core.axml import AXMLParser, AXMLPrinter

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

        original_print_namespace = AXMLPrinter._print_namespace

        def _sanitized_print_namespace(self: Any, uri: str) -> str:
            if uri and not _uri_lxml_ok(str(uri)):
                return ""
            return original_print_namespace(self, uri)

        AXMLPrinter._print_namespace = _sanitized_print_namespace  # type: ignore[method-assign]
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

#: 单文件解压后大小硬上限：防 zip 炸弹（zip 条目声明的解压后体积可与压缩体积严重不成比例，
#: 恶意构造的样本可让单个条目声明解压到几 GB 甚至更大，真正读取时才会真正解压——"读"这个
#: 动作本身就会把分析机内存打爆）。与 _MAX_READ_CACHE_BYTES（是否缓存的软阈值）不同，这是
#: "允不允许读"的硬性红线，须远大于任何合法单文件（正常 APK 内最大的 .so/资源文件通常在几十
#: 到一两百 MB 量级），故取 500MB：既能拦住典型 zip 炸弹，又不误伤合法大文件。
_MAX_DECOMPRESSED_FILE_BYTES = 500 * 1024 * 1024

#: 单实例生命周期内 _read_cache 累计缓存总量上限：防"许多个体各自都在
#: _MAX_READ_CACHE_BYTES 以下"的文件累加撑爆内存——zip 炸弹的另一变体，不是单文件超大，
#: 是数量多（如几千个刚好卡在 32MB 以下的伪装文本资源）。单文件上限挡不住这种累加。与
#: snapshot.py 的 _MAX_SNAPSHOT_TOTAL_BYTES（64MB，那是"预读进快照"场景）同思路，这里
#: 覆盖主路径；256MB 远超正常样本全部文本资源实测量级（snapshot.py 注释：实测整包文本
#: ~8MB），只挡病态累加，不误伤真实场景。
_MAX_TOTAL_CACHE_BYTES = 256 * 1024 * 1024

#: 有界解压时每次从 zip 读取压缩输入的块大小：压缩输入分块流式喂 decompressobj，不再一次性
#: 按（可伪造的）compressed_size 物化——伪造巨大 compressed_size 此前可逼出 ≤ 整个 APK 体积的
#: 一份额外拷贝。1MiB 兼顾吞吐与瞬时内存。
_INFLATE_CHUNK_BYTES = 1024 * 1024


class ZipEntryTooLargeError(RuntimeError):
    """apkInspector 实际解压产出超过单条目硬上限。"""

    entry: str | None
    limit: int

    def __init__(self, entry: str | None, limit: int) -> None:
        self.entry = entry
        self.limit = limit
        display_entry = entry if entry is not None else "<未知条目>"
        super().__init__(f"疑 zip 炸弹：条目 {display_entry} 实际解压产出超 {limit} 字节上限")


_ZIP_EXTRACT_PATCHED = False


def _bounded_extract_file_based_on_header_info(
    apk_file: BinaryIO,
    local_header_info: Mapping[str, Any],
    central_directory_info: Mapping[str, Any],
) -> tuple[bytes, str]:
    """按 apkInspector 原分支提取条目，但按实际解压产出施加单文件硬上限。"""

    cap = _MAX_DECOMPRESSED_FILE_BYTES
    raw_entry = central_directory_info.get("filename")
    entry = raw_entry if isinstance(raw_entry, str) else None

    def _raise_too_large(indicator: str) -> NoReturn:
        logger.warning(
            "apkInspector 有界解压拒绝（疑 zip 炸弹）：条目 %s 实际产出超 %d 字节上限（%s）",
            entry if entry is not None else "<未知条目>",
            cap,
            indicator,
        )
        raise ZipEntryTooLargeError(entry, cap)

    def _bounded_read(size: int, indicator: str) -> bytes:
        # ZIP 头字段正常为无符号整数。若异常调用者传入负数，也不能让 read(-1)
        # 退化为无界读取；改为最多探测 cap + 1 字节。
        read_size = cap + 1 if size < 0 else min(size, cap + 1)
        data = apk_file.read(read_size)
        if len(data) > cap:
            _raise_too_large(indicator)
        return data

    def _bounded_inflate(
        compressed_size: int,
        indicator: str,
        *,
        require_pure: bool,
    ) -> bytes:
        """从 apk_file 当前位置分块读取至多 compressed_size 字节喂 decompressobj，产出封顶。

        压缩输入不再一次性物化：原函数 ``read(compressed_size)`` 会把伪造的巨大
        compressed_size 一口气读到 EOF（≤ 整个 APK 的一份拷贝）；现在每次只读
        ``_INFLATE_CHUNK_BYTES``，瞬时额外内存 ≤ 块大小 + 产出上限。流语义与
        ``zlib.decompress(whole, -15)`` 一致：短读（EOF）照原样、尾随垃圾忽略、
        不完整流抛 ``zlib.error``。
        """
        c_obj = zlib.decompressobj(-15)
        output = bytearray()
        # 负值按原 read(-1) 语义读到 EOF；ZIP 头字段正常为无符号整数。
        left: int | None = None if compressed_size < 0 else compressed_size
        pending = b""

        while True:
            if not pending:
                want = _INFLATE_CHUNK_BYTES if left is None else min(left, _INFLATE_CHUNK_BYTES)
                if want <= 0:
                    break
                pending = apk_file.read(want)
                if not pending:
                    break  # EOF：与原函数 read(compressed_size) 的短读一致
                if left is not None:
                    left -= len(pending)
            remaining = cap + 1 - len(output)
            if remaining <= 0:
                _raise_too_large(indicator)
            output.extend(c_obj.decompress(pending, remaining))
            if len(output) > cap:
                _raise_too_large(indicator)
            pending = c_obj.unconsumed_tail
            if c_obj.eof:
                break

        # decompressobj 对截断流可能只留下 eof=False 而不主动抛错；
        # zlib.decompress 对同类输入会抛 zlib.error，因此在这里显式对齐。
        # ★不调 flush：受 max_length 截断的输出必伴随 unconsumed_tail、已在循环里继续处理，
        #   到 eof（Z_STREAM_END）时 inflate 没有滞留输出；而 ``Decompress.flush(length)`` 的参数
        #   是**初始缓冲区大小**不是上限——传 ``cap + 1 - len(output)`` 会让小文件也申请 ~500MiB
        #   临时缓冲（codex 第三轮复审 P1；tracemalloc 实测 flush(500MiB) 峰值 500MiB）。
        #   ``decompress(data, max_length)`` 则按需分块增长、不按 max_length 预分配
        #   （CPython 3.11.15 / 3.12.10 实测 max_length=500MiB 峰值 0.1MiB），故 max_length 无须再切块。
        if not c_obj.eof:
            raise zlib.error("Error -5 while decompressing data: incomplete or truncated stream")

        # 普通 DEFLATED 与 zlib.decompress 一致，忽略 unused_data。篡改分支
        # 则保留原 apkInspector 的“必须是纯 deflate 流”判定：原函数把 compressed_size
        # 范围内、deflate 流结束后仍存在的字节都算进 unused_data——流式读法下这些字节
        # 可能尚未被读出（left > 0），须探测一个字节判定「文件里确实还有」。
        if require_pure:
            trailing = bool(c_obj.unused_data or c_obj.unconsumed_tail)
            if not trailing and (left is None or left > 0):
                trailing = bool(apk_file.read(1))
            if trailing:
                raise ValueError("Invalid or non-pure deflate")

        return bytes(output)

    filename_length = int(local_header_info["file_name_length"])
    if (
        int(local_header_info["compressed_size"]) == 0
        or int(local_header_info["uncompressed_size"]) == 0
    ):
        compressed_size = int(central_directory_info["compressed_size"])
        uncompressed_size = int(central_directory_info["uncompressed_size"])
    else:
        compressed_size = int(local_header_info["compressed_size"])
        uncompressed_size = int(local_header_info["uncompressed_size"])

    extra_field_length = int(local_header_info["extra_field_length"])
    compression_method = int(local_header_info["compression_method"])

    # Skip the offset + local header to reach the compressed data
    local_header_size = 30
    offset = int(central_directory_info["relative_offset_of_local_file_header"])
    apk_file.seek(offset + local_header_size + filename_length + extra_field_length)

    if compression_method == 0:  # Stored (no compression)
        uncompressed_data = _bounded_read(uncompressed_size, "STORED")
        extracted_data = uncompressed_data
        indicator = "STORED"
    elif compression_method == 8:
        # -15 for windows size due to raw stream with no header or trailer；压缩输入分块流式读
        extracted_data = _bounded_inflate(
            compressed_size,
            "DEFLATED",
            require_pure=False,
        )
        indicator = "DEFLATED"
    elif compressed_size == uncompressed_size:
        compressed_data = _bounded_read(
            uncompressed_size,
            "STORED_TAMPERED",
        )
        extracted_data = compressed_data
        indicator = "STORED_TAMPERED"
    else:
        cur_loc = apk_file.tell()
        try:
            extracted_data = _bounded_inflate(
                compressed_size,
                "DEFLATED_TAMPERED",
                require_pure=True,
            )
            indicator = "DEFLATED_TAMPERED"
        except ZipEntryTooLargeError:
            # 实际解压已确认越界，不能再把同一数据按 STORED 回退读取。
            raise
        except Exception as exc:  # noqa: BLE001 - 与 apkInspector 原回退口径一致
            logger.debug("%s", safe_exception_diagnostic(exc))
            apk_file.seek(cur_loc)
            compressed_data = _bounded_read(
                uncompressed_size,
                "STORED_TAMPERED",
            )
            extracted_data = compressed_data
            indicator = "STORED_TAMPERED"

    return extracted_data, indicator


def _install_bounded_zip_extract_shim() -> None:
    """幂等安装 apkInspector 实际解压产出上限。

    现有 Level 1 闸信任 ZIP 中央目录声明的解压后大小，能快速拒绝明显超限条目，
    但无法约束 apkInspector 根据 local header 读取后由 DEFLATE 实际产生的字节数。
    本 Level 2 闸直接按实际产出封顶，阻止伪造声明大小的 zip 炸弹在内存中膨胀。

    apkInspector.headers 按名导入了解压函数，因此同时替换 headers 与 extract
    模块中的名字。安装失败时记录异常并恢复原行为，不阻塞 APK 加载。
    """
    global _ZIP_EXTRACT_PATCHED

    if _ZIP_EXTRACT_PATCHED:
        return

    try:
        import apkInspector.extract as _x
        import apkInspector.headers as _h

        original_headers_extract = _h.extract_file_based_on_header_info
        original_extract_extract = _x.extract_file_based_on_header_info

        try:
            _h.extract_file_based_on_header_info = _bounded_extract_file_based_on_header_info
            _x.extract_file_based_on_header_info = _bounded_extract_file_based_on_header_info
        except Exception:
            # 防止只替换成功一个模块时留下半安装状态。
            _h.extract_file_based_on_header_info = original_headers_extract
            _x.extract_file_based_on_header_info = original_extract_extract
            raise

        _ZIP_EXTRACT_PATCHED = True
    except Exception:  # noqa: BLE001 - 安装失败记录后回退，不阻塞既有加载路径
        logger.exception(
            "安装 apkInspector 有界解压 shim 失败，"
            "回退原行为（伪造声明大小的 zip 炸弹可能仍触发无界解压）"
        )


class ApkContext:
    """AnalysisContext 的真实实现，由 androguard 驱动。

    通过 load_apk() 构造，不要直接实例化。
    """

    platform: str = "android"  # 包平台

    def __init__(
        self,
        apk: Any,  # androguard.core.apk.APK；动态访问其方法，故标 Any
        dex_objs: list[Any],
        config: AnalysisConfig,
        *,
        apk_path: str = "",
        extra_dex_objs: list[Any] | None = None,
        extra_dex_paths: list[str] | None = None,
        dex_available: bool = True,
        apk_validation_ok: bool = True,
        extra_dex_report: dict[str, object] | None = None,
        hiddenapi_flags_baseline: int | None = None,
        jadx_cache_root: str | None = None,
        jadx_baseline_index: str | None = None,
    ) -> None:
        # apk: androguard.core.apk.APK；dex_objs: list[DEX]
        self._apk = apk
        self._dex_objs = dex_objs
        # _read_cache 累计已缓存字节数（防病态多文件累加撑爆内存，见 _MAX_TOTAL_CACHE_BYTES）。
        self._cached_bytes = 0
        # extra_dex_objs: 脱壳 dump 出来、外部传入的额外 DEX（androguard DEX 实例）。
        # 其字符串并入 dex_strings() 产出，使脱壳后的隐藏端点/SDK 也能被静态分析命中。
        self._extra_dex_objs = list(extra_dex_objs or [])
        # extra_dex_paths: 上述额外 DEX 的**原始文件路径**（androguard 只吃字节流、不保留路径）。
        # jadx 增强器需要文件路径把这些 dump DEX 一并喂进反编译——否则加固样本只反编译出壳桩、
        # 真实代码只以字符串池形式可见。注意与 _extra_dex_objs 的区别：这里存路径（含 androguard
        # 解析失败、但 jadx 更宽容的解析器可能仍能反编译的那些），供 jadx 自行取用。
        self.extra_dex_paths: list[str] = list(extra_dex_paths or [])
        # jadx 持久索引 cache root（opt-in：None=不启用；jadx 增强器 getattr 兼容读取）。
        self.jadx_cache_root: str | None = jadx_cache_root
        # 调用方断言为官方参照的 jadx 索引 key（opt-in，须同时启用 cache root）。
        self.jadx_baseline_index: str | None = jadx_baseline_index
        self.config = config
        # apk_path: APK 原始文件绝对路径（jadx/unpack 等增强器需要；无则空串，增强器应优雅跳过）。
        self.apk_path = apk_path
        # 供 pipeline 写入 Report.meta，使"加固导致 DEX 不可见 / 合法性校验异常"
        # 这类降级在报告里显式可见，而非静默当成"扫描完毕无命中"。
        self.dex_available = dex_available
        self.apk_validation_ok = apk_validation_ok
        # 额外 DEX 的加载账目（requested/loaded/failed + 失败样例）。脱壳产物成批不兼容
        # 是常态，"请求了几个"与"真解析成功几个"必须分开呈现，否则报告会把"没看见"
        # 说成"看过了没有"。pipeline 写进 meta.extra_dex_visibility。
        self.extra_dex_report: dict[str, object] = dict(extra_dex_report or {})
        # 本样本加载**前**已放行的 hidden-api flag 取值。放行记录攒在进程级集合里，而 batch
        # 单进程顺序跑多个样本，不减这条基线就会把上一个样本的账写进这一份报告（见
        # hiddenapi_relax_report 的 since 参数）。缺省 0：单样本路径本就无前账。
        self.hiddenapi_flags_baseline: int = hiddenapi_flags_baseline or 0

    # ---- 标量属性 -------------------------------------------------------

    @cached_property
    def _andro_package(self) -> str:
        """androguard 直接解析出的原始包名（未交叉校验）。"""
        try:
            return self._apk.get_package() or ""
        except Exception:  # noqa: BLE001 - 协议要求始终返回值
            logger.exception("get_package 失败")
            return ""

    @cached_property
    def _aapt_package(self) -> str | None:
        """用 aapt/aapt2 拿“第二意见”包名（与 Android 运行时一致）；aapt 不可用 → None（不改判）。"""
        exe = tools.aapt_path()
        if not exe or not self.apk_path:
            return None
        try:
            proc = subprocess.run(
                [exe, "dump", "badging", self.apk_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_AAPT_TIMEOUT,
                check=False,
            )
        except Exception:  # noqa: BLE001 - 第二意见拿不到不影响主流程
            logger.debug("aapt dump badging 失败（忽略，无第二意见）", exc_info=True)
            return None
        return _parse_aapt_package(proc.stdout or "")

    @cached_property
    def _axml_package(self) -> str:
        """AXML 字符串池容错直读的 package（不经 androguard，兜底清单投毒）；读不到 → ""。"""
        raw = b""
        try:
            raw = self._apk.get_file("AndroidManifest.xml") or b""
        except Exception:  # noqa: BLE001 - 拿不到原始字节则退回 apk_path
            raw = b""
        if not raw and self.apk_path:
            try:
                with zipfile.ZipFile(self.apk_path) as zf:
                    # zip 炸弹前置拦截（与 read_file 同口径）：清单兜底直读也查声明大小，
                    # 否则高压缩比 AndroidManifest.xml 会绕过 read_file 被全量解压致 OOM。
                    mf_info = zf.getinfo("AndroidManifest.xml")
                    if mf_info.file_size > _MAX_DECOMPRESSED_FILE_BYTES:
                        logger.warning(
                            "AndroidManifest.xml 声明解压 %d 字节超 %d 上限（疑 zip 炸弹），放弃兜底直读",
                            mf_info.file_size,
                            _MAX_DECOMPRESSED_FILE_BYTES,
                        )
                        raw = b""
                    else:
                        raw = zf.read("AndroidManifest.xml")
            except Exception:  # noqa: BLE001 - 读不到就放弃兜底
                logger.debug("读取 AndroidManifest.xml 原始字节失败（忽略）", exc_info=True)
                raw = b""
        return _axml_package_from_bytes(raw) if raw else ""

    @cached_property
    def _pkg_decision(self) -> tuple[str, str | None]:
        return _decide_manifest_package(
            self._andro_package,
            self._aapt_package,
            self.apk_validation_ok,
            axml=self._axml_package,
        )

    @property
    def package_name(self) -> str:
        """权威包名（androguard × aapt 交叉校验后的值）——治清单投毒导致的错包名。"""
        return self._pkg_decision[0]

    @cached_property
    def manifest_anomaly(self) -> str | None:
        """清单解析异常描述（包名交叉校验不一致 / androguard 畸形）；正常 → None，供 manifest 分析器发 Finding。"""
        return self._pkg_decision[1]

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

    @cached_property
    def _declared_sizes(self) -> dict[str, int]:
        """zip 中央目录里每个条目「声明的解压后大小」（不解压，纯元数据读取，代价小）。

        供 read_file 读取前拦截 zip 炸弹用。androguard 的 ``self._apk.zip`` 是未文档化的内部
        实现（可能是标准库 zipfile 或 androguard 自研 ZipEntry，视内部路径而定），不直接依赖它
        ——改用标准库单独对 apk_path 开一次只读句柄，接口稳定。只在有 apk_path 时可用；打不开 /
        无 apk_path 时返回空 dict（查不到视为「无法判断」，read_file 照原逻辑放行，不误伤）。
        """
        if not self.apk_path:
            return {}
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                return {info.filename: info.file_size for info in zf.infolist()}
        except Exception:
            logger.debug("[apk] 声明大小映射构建失败，跳过 zip 炸弹前置校验", exc_info=True)
            return {}

    def declared_size(self, path: str) -> int | None:
        """zip 声明的解压后大小（读中央目录元数据、不解压）；无 apk_path/查不到 → None。

        供分析器（如 native_fingerprint）在 read_file 前拦截超大 .so——read_file 自身的 500MB
        上限远高于单分析器的按需阈值，故须让调用方拿到声明大小自行卡更严的门。
        """
        return self._declared_sizes.get(path)

    def read_file(self, path: str) -> bytes | None:
        cache = self._read_cache
        if path in cache:
            return cache[path]
        declared = self._declared_sizes.get(path)
        if declared is not None and declared > _MAX_DECOMPRESSED_FILE_BYTES:
            logger.warning(
                "read_file 跳过（声明解压后 %d 字节超过 %d 上限，疑 zip 炸弹）：%s",
                declared,
                _MAX_DECOMPRESSED_FILE_BYTES,
                path,
            )
            cache[path] = None
            return None
        try:
            data = self._apk.get_file(path)
        except ZipEntryTooLargeError as exc:
            logger.warning(
                "read_file 跳过（实际解压产出超 %d 字节上限，疑 zip 炸弹）：%s",
                exc.limit,
                path,
            )
            data = None
        except Exception:
            # androguard 对缺失文件抛 FileNotPresent；视为正常缺失但仍记录
            logger.debug("read_file 未命中：%s", path, exc_info=True)
            data = None
        # 超大文件（大 .so / 大资源）不进缓存，避免常驻内存。None（未命中）仍缓存以避免重复
        # 未命中查询；小文件照常缓存供多分析器重复读命中。未缓存的文件（无论何种原因）仍
        # 返回完整字节，只是每次重读——不缓存只影响性能，不影响正确性。
        if data is None:
            cache[path] = data
        elif len(data) > _MAX_READ_CACHE_BYTES:
            logger.debug(
                "read_file 跳过缓存（超 %d 字节，避免常驻内存）：%s（%d 字节）",
                _MAX_READ_CACHE_BYTES,
                path,
                len(data),
            )
        elif self._cached_bytes + len(data) > _MAX_TOTAL_CACHE_BYTES:
            # 单文件不大，但累计缓存量将超总量上限——防"许多个体都在阈值以下"的病态累加。
            logger.debug(
                "read_file 跳过缓存（累计缓存量将超总量上限 %d 字节）：%s（%d 字节，当前已缓存 %d 字节）",
                _MAX_TOTAL_CACHE_BYTES,
                path,
                len(data),
                self._cached_bytes,
            )
        else:
            cache[path] = data
            self._cached_bytes += len(data)
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


def _load_extra_dex(extra_dex: list[str]) -> tuple[list, list[dict[str, str]]]:
    """把 extra_dex 路径列表（脱壳 dump 的 .dex 文件）解析为 androguard DEX 实例列表。

    返回 ``(DEX 实例列表, 失败明细列表)``。失败明细每项含 ``path`` / ``sha256`` /
    ``error_type`` / ``error``。

    ★为什么要把失败带出去：脱壳产物成批不兼容是常态——实测两个样本各 dump 33 个 DEX，
    androguard 因不认 Android 10+ 的 hidden-api flag 抛 ValueError，各只解析成功 10 个。
    只记 warning 的话，报告里看到的是"33 个并入 + 分析器 0 error"，读的人会以为
    33 个都分析过了。失败数必须走到 meta 与 visibility，否则"没看见"会被当成"没有"。

    - 单个文件读取/解析失败 → try/except + logging 跳过，不影响主流程（不裸 pass、不吞错）。
    - androguard 的 import 只允许出现在本文件。
    """
    _silence_androguard_logging()  # 用 androguard 前才禁其 loguru（避免启动期白付 loguru）
    _relax_hiddenapi_flags()  # 别让 androguard 不认识的 hidden-api flag 把整个 DEX 拒在门外
    from androguard.core.dex import DEX

    out: list = []
    failures: list[dict[str, str]] = []
    for path in extra_dex:
        digest = ""
        try:
            buff = Path(path).read_bytes()
            digest = hashlib.sha256(buff).hexdigest()
            out.append(DEX(buff))
        except Exception as exc:  # noqa: BLE001 - 坏/不兼容 DEX 跳过即可，不炸主流程
            # 收敛成一行 warning + 异常摘要（不打整坨 traceback）：frida-dexdump dump 的
            # Android 10+ DEX 常因 androguard 不认 hidden-api flag 抛 ValueError
            # （HiddenApiClassDataItem.*ApiFlag），是已知库限制、会成批出现，整坨 traceback
            # 纯噪音。仍如实记录（不 swallow），只是不再刷屏。
            logger.warning(
                "解析额外 DEX 失败，跳过：%s（%s）", path, safe_exception_diagnostic(exc)
            )
            failures.append({
                "path": str(path),
                "sha256": digest,
                "error_type": type(exc).__name__,
                "error": safe_exception_text(exc),
            })
    return out, failures


#: meta.extra_dex_visibility 里保留的失败明细上限——成批不兼容时逐条列会把 meta 撑肿，
#: 失败**总数**与错误类型分布才是判读要用的，逐条只留头几条做样例。
_MAX_EXTRA_DEX_FAILURE_SAMPLES = 10


def build_extra_dex_report(
    requested: list[str], loaded: int, failures: list[dict[str, str]]
) -> dict[str, object]:
    """把额外 DEX 的加载结果整理成可写进 ``meta.extra_dex_visibility`` 的结构。

    ``complete`` 表示请求的 DEX 全部解析成功——只有它为真时，"额外 DEX 已并入分析"
    才是一句完整的话。
    """
    by_error: dict[str, int] = {}
    for item in failures:
        key = item.get("error_type") or "Unknown"
        by_error[key] = by_error.get(key, 0) + 1
    return {
        "requested": len(requested),
        "loaded": loaded,
        "failed": len(failures),
        "complete": bool(requested) and not failures,
        "failures_by_error": by_error,
        "failure_samples": failures[:_MAX_EXTRA_DEX_FAILURE_SAMPLES],
    }


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


#: androguard 的 ``APK(path)`` 构造期 / ``get_all_dex()`` 会**急切解压**的条目。只有这些条目声明
#: 超上限才真能把我们炸出 OOM；其余条目由 read_file 的逐条闸拦住即可。
_EAGERLY_DECOMPRESSED_RE = re.compile(r"^(AndroidManifest\.xml|resources\.arsc|classes\d*\.dex)$")


def _reject_if_zip_bomb(path: str) -> None:
    """交给 androguard 全量解析前的 zip 炸弹前置拦截（Level 1：信中央目录声明大小）。

    Level 2（按实际解压产出封顶）见 :func:`_install_bounded_zip_extract_shim`，两者互补。

    androguard 的 ``APK(path)`` 在构造期解压 manifest / resources.arsc，``get_all_dex()`` 解压各 dex
    ——这些绕过 read_file 的逐条 file_size 闸，声明超上限时能炸出 OOM，故对**这些条目**仍 fail-fast。

    ★但只对它们（实测修正）：原实现对**任意**条目超限就拒绝整个 APK，反被当成「拒绝分析」式反制——
    真实语料里 多个样本各塞了一对 ``res/1.xml`` + ``assets/1.xml``，声明 1000MB、压缩仅 5.5MB（180 倍），
    参数三样本完全一致，显然是同一工具注入的诱饵炸弹。它们不是 androguard 急切解压的对象，却让整个
    样本被判死、什么都分析不到——攻击者用我们的防护达成了完全的分析拒绝。现改为：非急切解压的超限
    条目只 **warning + 跳过**（read_file 的逐条闸本就拒读它们），分析照常进行。

    打不开/非 zip → 不在此判死，交由 androguard 报既有领域错误。
    """
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except Exception:  # noqa: BLE001 - 打不开/非 zip：交 androguard 走既有错误路径，不在此提前判死
        logger.debug("[apk] zip 炸弹前置扫描失败（忽略，交 androguard）：%s", path, exc_info=True)
        return

    deferred: list[str] = []
    for info in infos:
        if info.file_size <= _MAX_DECOMPRESSED_FILE_BYTES:
            continue
        if _EAGERLY_DECOMPRESSED_RE.match(info.filename):
            raise ApkParseError(
                f"拒绝加载 APK（核心条目 {info.filename} 声明解压 {info.file_size} 字节 > "
                f"{_MAX_DECOMPRESSED_FILE_BYTES} 上限，疑 zip 炸弹）：{path}"
            )
        deferred.append(f"{info.filename}({info.file_size}B)")
    if deferred:
        logger.warning(
            "[apk] %d 个非核心条目声明解压超 %d 上限，已跳过该条目、继续分析（疑「拒绝分析」式诱饵炸弹）：%s",
            len(deferred), _MAX_DECOMPRESSED_FILE_BYTES, "、".join(deferred[:5]),
        )


def load_apk(
    path: str,
    config: AnalysisConfig,
    extra_dex: list[str] | None = None,
    jadx_cache_root: str | None = None,
    jadx_baseline_index: str | None = None,
) -> ApkContext:
    """加载 APK 并构造 ApkContext。

    APK 无法解析时抛 ApkParseError（fail fast）。

    extra_dex: 额外的 .dex 文件路径列表（脱壳 dump 出来的）。其字符串并入 dex_strings()
               产出，使脱壳后的隐藏端点/SDK 也能被静态分析命中。单个 dex 失败不影响主流程。
    jadx_cache_root: jadx 持久索引 cache root（opt-in；None=不启用，jadx 增强器现行为不变）。
    """
    # androguard 的 import 只允许出现在本文件。
    _silence_androguard_logging()  # 用 androguard 前才禁其 loguru（避免启动期白付 loguru）
    # 加固壳常在二进制 manifest 注入非法 namespace URI（反分析投毒），会让 APK() 构造期
    # 的 lxml etree.Element 抛 ValueError 致整体 fail-fast。装幂等 shim 净化 nsmap，对齐
    # apktool 的宽容降级，让 manifest 可解（包名/组件/权限/证书等不再因此全丢）。
    _install_axml_nsmap_shim()
    # apkInspector 信 local header 且 DEFLATE 无界；任何 APK 构造前先装实际产出闸（Level 2）。
    _install_bounded_zip_extract_shim()
    # 本样本放行了哪些 hidden-api flag，要从**此刻**起算：集合是进程级的，batch 顺序跑多个
    # 样本时，不取基线就会把前一个样本的放行记录算到这一个头上。在任何 DEX 解析之前抓。
    hiddenapi_baseline = hiddenapi_flags_snapshot()
    # zip 炸弹前置拦截：在 androguard 全量解析（内部解压 DEX/manifest）前先按声明大小拒炸弹。
    _reject_if_zip_bomb(path)
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
    except ZipEntryTooLargeError as exc:
        # ★DEX 是核心条目：Level 2 按实际产出拒读，与 Level 1 对核心条目声明超限的 fail-fast
        #   同一口径——必须整体拒绝，不能落进下面的「可能加固」降级继续分析。否则把炸弹放在
        #   classes2.dex 就能让已解析的主 DEX 一并清空（dex_objs=[]）、形成静态分析规避
        #   （codex 复审 P2）。
        raise ApkParseError(
            f"拒绝加载 APK（DEX 条目 {exc.entry or '<未知条目>'} 实际解压超 {exc.limit} 字节上限，"
            f"疑 zip 炸弹）：{path}"
        ) from exc
    except Exception:
        # DEX 不可见（加固）不应使整体失败：manifest/资源/证书仍可用
        logger.exception("DEX 解析失败（可能加固），降级为无 DEX 字符串：%s", path)
        dex_objs = []
    # 额外 DEX（脱壳 dump）解析；失败的单个 dex 已在 _load_extra_dex 内跳过，
    # 失败明细随 context 带出，最终落到 meta.extra_dex_visibility 与 visibility.dex。
    requested_extra = list(extra_dex or [])
    extra_dex_objs, extra_dex_failures = (
        _load_extra_dex(requested_extra) if requested_extra else ([], [])
    )

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
        # jadx 要按路径把 dump DEX 一并反编译。传**全部请求路径**（含 androguard 解析失败的）：
        # androguard 因不认 Android 10+ hidden-api flag 拒载的 DEX，jadx 的解析器往往仍能反编译。
        extra_dex_paths=requested_extra,
        dex_available=dex_available,
        apk_validation_ok=apk_validation_ok,
        extra_dex_report=build_extra_dex_report(
            requested_extra, len(extra_dex_objs), extra_dex_failures
        ),
        hiddenapi_flags_baseline=hiddenapi_baseline,
        jadx_cache_root=jadx_cache_root,
        jadx_baseline_index=jadx_baseline_index,
    )
