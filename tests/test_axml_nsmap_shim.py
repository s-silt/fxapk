"""AXML nsmap 净化 shim 的单测（对应 apkscan/core/apk.py 的 _sanitize_nsmap + shim）。

背景：加固壳在二进制 AndroidManifest(AXML) 里注入【非法 namespace URI】（含空格/控制符/
NUL 等反分析投毒）。androguard 在 APK() 构造期把 manifest 转 lxml，etree.Element(tag,
nsmap=...) 对非法 URI 抛 ValueError，androguard 的 except 只救 'Invalid namespace prefix'，
坏 URI 落 else: raise → 冲出 APK() → fxapk fail-fast，整个静态阶段死。

本套测试覆盖：
- 纯函数 _sanitize_nsmap：坏 URI 丢弃、空前缀→None、坏前缀丢弃、合法原样、幂等不改入参。
- 幂等 shim _install_axml_nsmap_shim：包装 AXMLParser.nsmap 返回净化值，重复安装不套娃。
- 端到端反转：装 shim 前 AXMLPrinter(...).get_xml_obj() 因坏 URI raise（复现根因），装 shim
  后不再 raise（对齐 apktool 的宽容降级）。
"""

from __future__ import annotations

import copy

import pytest
from lxml import etree

from apkscan.core.apk import _install_axml_nsmap_shim, _sanitize_nsmap

_ANDROID_URI = "http://schemas.android.com/apk/res/android"


# ======================================================================
# A. 纯函数 _sanitize_nsmap
# ======================================================================


def test_sanitize_drops_uri_with_internal_space() -> None:
    """URI 含内部空格 → 整对丢弃；合法 android 项保留。"""
    out = _sanitize_nsmap({"android": _ANDROID_URI, "bad": "http://bad uri/x"})
    assert out == {"android": _ANDROID_URI}


def test_sanitize_drops_uri_with_leading_or_trailing_space() -> None:
    """URI 前导/尾随空格、纯空白 → 丢弃（lxml 拒收）。"""
    out = _sanitize_nsmap(
        {
            "a": " http://foo/x",
            "b": "http://foo/x ",
            "c": "   ",
            "ok": _ANDROID_URI,
        }
    )
    assert out == {"ok": _ANDROID_URI}


def test_sanitize_drops_uri_with_control_char() -> None:
    """URI 含 C0 控制符 / NUL → 丢弃（这是第三类报文 'All strings must be XML compatible'）。"""
    out = _sanitize_nsmap(
        {
            "x": "http://foo\x01bar",
            "y": "http://foo\x00bar",
            "z": "http://foo\tbar",
            "n": "http://foo\nbar",
            "ok": _ANDROID_URI,
        }
    )
    assert out == {"ok": _ANDROID_URI}


def test_sanitize_drops_uri_with_lxml_special_chars() -> None:
    """URI 含 lxml 另行拒收的可见 ASCII（'<' '>' '|' '^' '[' ']' '{' '}' '`' '"'）→ 丢弃。

    回归：原实现用手搓字符黑名单（仅白空格 + 控制符），漏掉这些字符 → 加固壳换个投毒字符
    即可再次绕过、让 etree.Element 抛 'Invalid namespace URI'，修复失效。净化须以 lxml 实判为准。
    """
    out = _sanitize_nsmap(
        {
            "p": "http://foo|bar",
            "q": "http://foo<bar",
            "r": "http://foo^bar",
            "s": "http://foo{bar}",
            "ok": _ANDROID_URI,
        }
    )
    assert out == {"ok": _ANDROID_URI}


def test_sanitize_drops_non_ascii_uri() -> None:
    """URI 含非 ASCII（如 'é'，0xA0-0xFF）→ lxml 拒收 → 丢弃（黑名单实现会漏）。"""
    out = _sanitize_nsmap({"p": "http://foé/x", "ok": _ANDROID_URI})
    assert out == {"ok": _ANDROID_URI}


def test_sanitize_keeps_valid_android_ns() -> None:
    """合法 android NS 原样保留（净化不误伤）。"""
    out = _sanitize_nsmap({"android": _ANDROID_URI})
    assert out == {"android": _ANDROID_URI}


def test_sanitize_keeps_none_prefix() -> None:
    """None 前缀（默认命名空间）合法，原样保留。"""
    out = _sanitize_nsmap({None: _ANDROID_URI})
    assert out == {None: _ANDROID_URI}


def test_sanitize_empty_prefix_normalized_to_none() -> None:
    """空串前缀 '' 是坏前缀（lxml 拒收），规整成 None（默认命名空间），不丢、不保留 ''。"""
    out = _sanitize_nsmap({"": _ANDROID_URI})
    assert out == {None: _ANDROID_URI}


def test_sanitize_drops_bad_prefix() -> None:
    """无法安全规整的坏前缀（含 '<!--'/空格/冒号/数字开头）→ 整对丢弃。"""
    out = _sanitize_nsmap(
        {
            "<!--": _ANDROID_URI,
            "and roid": "http://foo/a",
            "a:b": "http://foo/b",
            "1ns": "http://foo/c",
            "android": _ANDROID_URI,
        }
    )
    assert out == {"android": _ANDROID_URI}


def test_sanitize_keeps_ncname_with_dot() -> None:
    """点在 NCName 中合法，前缀 'a.b' 保留。"""
    out = _sanitize_nsmap({"a.b": _ANDROID_URI})
    assert out == {"a.b": _ANDROID_URI}


def test_sanitize_empty_uri_is_valid_but_empty_prefix_normalized() -> None:
    """空串 URI '' 对 lxml 合法（不抛），应保留；其空串前缀同时规整为 None。"""
    out = _sanitize_nsmap({"": ""})
    assert out == {None: ""}
    # 非空合法前缀 + 空 URI 也保留
    assert _sanitize_nsmap({"foo": ""}) == {"foo": ""}


def test_sanitize_dedup_after_normalization() -> None:
    """规整后出现重复 key（多个空前缀都→None）→ 保留首个、丢后续，保证幂等。"""
    out = _sanitize_nsmap({"": _ANDROID_URI, None: "http://other/y"})
    # 两个都映射到 key None："" 在前 → 保留首个出现的 _ANDROID_URI（钉死"保留首个"）。
    assert list(out.keys()) == [None]
    assert out[None] == _ANDROID_URI


def test_sanitize_is_pure_idempotent() -> None:
    """幂等：sanitize(sanitize(x)) == sanitize(x)；且绝不原地改入参。"""
    raw = {
        "android": _ANDROID_URI,
        "bad": "http://bad uri/x",
        "": "http://foo/empty",
        "<!--": "http://foo/comment",
    }
    raw_copy = copy.deepcopy(raw)
    once = _sanitize_nsmap(raw)
    twice = _sanitize_nsmap(once)
    assert twice == once
    # 入参未被 mutate
    assert raw == raw_copy


def test_sanitized_dict_accepted_by_lxml() -> None:
    """最终目的固化：净化结果直接喂 etree.Element(nsmap=...) 不抛 ValueError。"""
    raw = {
        "android": _ANDROID_URI,
        "bad": "http://bad uri/x",
        "ctrl": "http://foo\x01bar",
        "": "http://foo/empty",
        "<!--": "http://foo/comment",
        None: _ANDROID_URI + "/default",
    }
    clean = _sanitize_nsmap(raw)
    # 不抛即通过
    el = etree.Element("{%s}manifest" % _ANDROID_URI, nsmap=clean)
    assert el is not None


# ======================================================================
# B. 幂等 shim 行为
# ======================================================================


def _inject_raw_nsmap_and_install(
    monkeypatch: pytest.MonkeyPatch, raw_value: dict
) -> type:
    """给真实 AXMLParser 类临时换一个返回 raw_value 的底层 nsmap property，再装 shim。

    流程模拟真实链路：底层 nsmap property（这里用 raw_value 替身模拟「逐 chunk 解析出的
    原始映射」）→ shim 包装它 → 返回净化值。为让 shim 包到「注入的替身」而非 androguard
    原 property，安装前把模块级幂等标记复位（monkeypatch.setattr 会在测试结束自动还原标记
    与 property，不污染其它测试）。

    返回 AXMLParser 类，调用方读 instance.nsmap 验证净化生效。
    """
    import apkscan.core.apk as apk_mod
    from androguard.core.axml import AXMLParser

    # 1) 注入「底层」property（替身），模拟被加固壳投毒的原始 nsmap。
    monkeypatch.setattr(
        AXMLParser,
        "nsmap",
        property(lambda self: dict(raw_value)),
        raising=True,
    )
    # 2) 复位幂等标记，使本次安装包住步骤 1 注入的替身（结束后由 monkeypatch 还原）。
    monkeypatch.setattr(apk_mod, "_AXML_NSMAP_PATCHED", False, raising=True)
    _install_axml_nsmap_shim()
    return AXMLParser


def test_shim_sanitizes_axmlparser_nsmap(monkeypatch: pytest.MonkeyPatch) -> None:
    """装 shim 后，读 AXMLParser 实例的 .nsmap 得到净化值（坏 URI 没了、好映射在）。"""
    raw = {"android": _ANDROID_URI, "bad": "http://bad uri/x"}
    cls = _inject_raw_nsmap_and_install(monkeypatch, raw)

    inst = cls.__new__(cls)  # 不走 __init__，仅取 property
    assert inst.nsmap == {"android": _ANDROID_URI}


def test_install_shim_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """重复安装：.nsmap 仍只过一层净化、结果稳定、不抛（防 property 套娃）。"""
    raw = {"android": _ANDROID_URI, "bad": "http://bad uri/x", "": _ANDROID_URI}
    cls = _inject_raw_nsmap_and_install(monkeypatch, raw)
    # 复位后已装一层；再调两次（不复位标记）必须是 no-op，不得再包一层。
    _install_axml_nsmap_shim()
    _install_axml_nsmap_shim()

    inst = cls.__new__(cls)
    once = _sanitize_nsmap(raw)
    assert inst.nsmap == once  # 只过一层净化，未套娃


def test_shim_preserves_clean_nsmap(monkeypatch: pytest.MonkeyPatch) -> None:
    """底层本就干净的 nsmap，装 shim 后逐键不变（不回归正常 APK）。"""
    raw = {"android": _ANDROID_URI}
    cls = _inject_raw_nsmap_and_install(monkeypatch, raw)

    inst = cls.__new__(cls)
    assert inst.nsmap == {"android": _ANDROID_URI}


# ======================================================================
# C2. 端到端：AXMLPrinter.get_xml_obj() 不再因坏 URI fail-fast
#     无二进制 fixture，通过 monkeypatch 注入坏 URI nsmap 复现根因并验证修复。
# ======================================================================


def test_loadapk_path_no_longer_raises_on_bad_uri_nsmap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """复现根因 + 验证修复（端到端，无二进制 fixture）：

    构造一个最小的合法二进制 AXML，但把底层 AXMLParser.nsmap 强制注入含坏 URI 的映射，
    模拟加固壳投毒。AXMLPrinter 构造期即解析到 START_TAG 调 etree.Element(tag, nsmap=...)：
    - 装 shim 前：坏 URI 落 androguard 的 else: raise（不在 'Invalid namespace prefix' 分支），
      AXMLPrinter(raw) 直接抛 ValueError('Invalid namespace URI ...') —— 这正是 load_apk 里
      APK() 构造崩、整体 fail-fast 的根因复现。
    - 装 shim 后：nsmap 被净化（坏 URI 剔除），不再抛，解析出 root（对齐 apktool 宽容降级）。
    """
    import apkscan.core.apk as apk_mod
    from androguard.core.axml import AXMLParser, AXMLPrinter

    raw_axml = _minimal_axml_or_skip()
    poisoned = {"android": _ANDROID_URI, "bad": "http://bad uri/x"}

    # 注入被投毒的底层 nsmap（替身），模拟加固壳的非法 URI。
    monkeypatch.setattr(
        AXMLParser, "nsmap", property(lambda self: dict(poisoned)), raising=True
    )

    # --- 装 shim 前：构造期解析到 START_TAG 即抛 ValueError(Invalid namespace URI) ---
    with pytest.raises(ValueError, match="Invalid namespace URI"):
        AXMLPrinter(raw_axml)

    # --- 装 shim（复位幂等标记使其包住注入的替身）：净化后不再抛，root 非 None ---
    monkeypatch.setattr(apk_mod, "_AXML_NSMAP_PATCHED", False, raising=True)
    _install_axml_nsmap_shim()
    printer_after = AXMLPrinter(raw_axml)
    root = printer_after.get_xml_obj()
    assert root is not None
    # 净化只剔坏项，合法 android 映射仍在（序列化能写出 xmlns:android）。
    assert root.nsmap.get("android") == _ANDROID_URI


def _minimal_axml_or_skip() -> bytes:
    """造一个能被 AXMLPrinter 解析到 START_TAG 的最小二进制 AXML；造不出则 skip。

    仓库无 AXML fixture，手搓字节脆弱。优先尝试：若本地 androguard 版本能从一段最小
    AXML 解析出 START_TAG，则用之；否则 skip（CI 无样本不挂，核心覆盖由 A/B 组背书）。
    """
    import struct

    # RES_XML_TYPE 文件头 + UTF-8 string pool（3 串：android URI、'android' 前缀、tag 名
    # 'manifest'）+ START_NAMESPACE + START_TAG。字段布局严格对齐 androguard AXMLParser
    # ._do_next：公共头(8) + lineNumber(4) + comment(4) 后，各 chunk 再读自身字段。
    # 手搓极易碎，任何 struct/对齐/解析问题直接 skip（A/B 组已覆盖核心）。
    try:
        strings = ["http://schemas.android.com/apk/res/android", "android", "manifest"]
        # ---- UTF-8 string pool ----
        # UTF8_FLAG 下每条目：u8 字符数 + u8 字节数（<128 用单字节）+ utf8 字节 + NUL。
        encoded = []
        for s in strings:
            b = s.encode("utf-8")
            encoded.append(bytes([len(s) & 0x7F, len(b) & 0x7F]) + b + b"\x00")
        pool_data = b"".join(encoded)
        offsets = []
        off = 0
        for e in encoded:
            offsets.append(off)
            off += len(e)
        pad = (4 - (len(pool_data) % 4)) % 4
        pool_data += b"\x00" * pad

        string_count = len(strings)
        offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
        sp_header_size = 0x1C
        flags = 0x100  # UTF8_FLAG
        strings_start = sp_header_size + len(offsets_blob)
        sp_body = struct.pack("<IIIII", string_count, 0, flags, strings_start, 0)
        sp_chunk_size = sp_header_size + len(offsets_blob) + len(pool_data)
        string_pool = (
            struct.pack("<HHI", 0x0001, sp_header_size, sp_chunk_size)
            + sp_body
            + offsets_blob
            + pool_data
        )

        # ---- START_NAMESPACE (0x0100) ----
        # header(8) + lineNumber(4) + comment(4) + prefix(4) + uri(4) = 24
        start_ns = struct.pack(
            "<HHIIIII", 0x0100, 0x0010, 24, 1, 0xFFFFFFFF, 1, 0
        )

        # ---- START_ELEMENT (0x0102) ----
        # header(8)+lineNumber(4)+comment(4)+nsUri(4)+name(4)+at_start(2)+at_size(2)
        #   +attrCount(4)+classAttr(4) = 36，无属性。nsUri=0xFFFFFFFF(无)，name=2('manifest')。
        start_tag = struct.pack(
            "<HHIIIIIHHII",
            0x0102,
            0x0010,
            36,
            1,  # lineNumber
            0xFFFFFFFF,  # comment
            0xFFFFFFFF,  # nsUri = -1（标签无命名空间）
            2,  # name idx -> 'manifest'
            20,  # at_start
            20,  # at_size
            0,  # attributeCount
            0xFFFFFFFF,  # classAttribute（无）
        )

        body = string_pool + start_ns + start_tag
        total = 8 + len(body)
        header = struct.pack("<HHI", 0x0003, 8, total)  # RES_XML_TYPE
        raw = header + body

        # 自检：能否被 AXMLPrinter 走到 START_TAG（不装 shim、不投毒时应能拿到 root）
        from androguard.core.axml import AXMLPrinter

        printer = AXMLPrinter(raw)
        obj = printer.get_xml_obj()
        if obj is None:
            pytest.skip("最小 AXML 未解析出 root，跳过端到端（A/B 组已覆盖核心）")
        return raw
    except Exception as exc:  # noqa: BLE001 - 手搓 AXML 脆弱，造不出就 skip
        pytest.skip(f"无法构造最小 AXML fixture（{type(exc).__name__}: {exc}），A/B 组已覆盖")
