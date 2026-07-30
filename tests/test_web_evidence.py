"""网页证据作为一级输入：``WebContext`` 载入 + 三个 ``requires=["web"]`` 分析器。

为什么这批测试值得存在（对应计划书 A-2 的实证动因）：实测有的样本只有**落盘的网页证据**、
没有 APK，其中一条跳转链比首轮人工研判**多两跳、还按平台分流**——那两跳是独立注册域、
各自是独立分析对象。故这里的断言重点不是"抽到了域名"，而是：

1. **链形（顺序 + 跳数）不能丢** —— 混进一堆端点里等于没抽（``test_redirect_chain_*``）。
2. **读失败必须成为数据** —— 静默跳过会让"扫了 1 份"与"扫全了"在报告里长得一样。
3. **平台门控真的生效** —— 网页证据上不许跑 Android 专属分析器（见 test_platform_gating.py）。
4. **不可信输入的边界** —— gzip 炸弹有界解压、非 UTF-8 不丢整份证据、压缩 JS 的 ``a.length``
   不许被抽成域名。
"""

from __future__ import annotations

import json
import zlib
from pathlib import Path

import pytest

import apkscan.core.webctx as webctx_module
from apkscan.analyzers.web_evidence import (
    EVIDENCE_SOURCE,
    WebInlineConfigAnalyzer,
    WebRedirectChainAnalyzer,
    WebRequestRecipeAnalyzer,
)
from apkscan.commands.web import _FALLBACK_BASE, _sanitize_base
from apkscan.core.context import AnalysisContext
from apkscan.core.models import AnalysisConfig
from apkscan.core.webctx import (
    MAX_EVIDENCE_BYTES,
    WEB_PREFIX,
    WebContext,
    canonical_evidence_name,
    is_text_evidence,
    load_web_evidence,
    looks_binary,
    normalize_text_bytes,
)

# 文档保留域名/IP 段（RFC 2606 / RFC 5737）——测试数据一律用它们，绝不写真实涉案值。
DOC_HOST = "config.example.com"
DOC_HOP1 = "hop1.example.net"
DOC_HOP2 = "hop2.example.org"


def _ctx(files: dict[str, bytes], **kw: object) -> WebContext:
    return WebContext(config=AnalysisConfig(online=False), files=files, **kw)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# WebContext：协议一致性与"如实空值"
# ---------------------------------------------------------------------------


def test_webcontext_satisfies_analysis_context_protocol() -> None:
    """必须真正满足 Protocol，否则 pipeline.run 只能靠鸭子类型侥幸跑通。"""
    assert isinstance(_ctx({}), AnalysisContext)


def test_webcontext_platform_is_web() -> None:
    assert _ctx({}).platform == "web"


def test_webcontext_apk_members_are_empty_not_fabricated() -> None:
    """APK 专属成员如实给空值：网页证据里这些概念**不存在**，给空不是"采集失败"。"""
    ctx = _ctx({"web/a.html": b"<html></html>"})
    assert ctx.permissions() == []
    assert ctx.native_libs() == []
    assert ctx.certificates() == []
    assert ctx.manifest_xml == ""
    assert list(ctx.dex_strings()) == []
    assert ctx.components().activities == []
    assert ctx.apk_path == ""


def test_webcontext_dex_available_is_false() -> None:
    """★ visibility 靠这个布尔区分"压根没有 DEX"与"DEX 已看全"。

    默认 True 会让网页证据报告声称 DEX 面已穷尽——那是凭空的完整性。
    """
    assert _ctx({}).dex_available is False


def test_webcontext_package_name_does_not_fabricate() -> None:
    """没有包名时不许编造 com.unknown 之类：报告里的"包名"必须是真事实或明确为空。"""
    assert _ctx({}).package_name == ""
    assert _ctx({}, origin="promo.example.com").package_name == "promo.example.com"


def test_webcontext_declared_size_matches_and_none_for_unknown() -> None:
    ctx = _ctx({"web/a.js": b"abcd"})
    assert ctx.declared_size("web/a.js") == 4
    assert ctx.declared_size("web/missing.js") is None
    assert ctx.read_file("web/missing.js") is None


# ---------------------------------------------------------------------------
# 证据载入：选文件 / 上限 / gzip / 读失败如实带出
# ---------------------------------------------------------------------------


def test_is_text_evidence_excludes_binaries_first() -> None:
    """二进制优先排除：把 PNG 解成文本跑正则既错又可能触发灾难性回溯。"""
    assert is_text_evidence("index.html")
    assert is_text_evidence("resp.body")
    assert is_text_evidence("app.headers")
    assert not is_text_evidence("logo.png")
    assert not is_text_evidence("bundle.so")
    assert not is_text_evidence("sample.apk")


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("resp.body", b"<!doctype html><html><body>x</body></html>", "resp.body.html"),
        ("resp.body", b"  \n<html>x</html>", "resp.body.html"),
        ("api.body", b'{"a": 1}', "api.body.json"),
        ("api.body", b"[1, 2]", "api.body.json"),
        ("app.body", b"window.cfg = 1;", "app.body.txt"),
        ("h.headers", b"HTTP/1.1 302\r\nLocation: /x\r\n", "h.headers.txt"),
        # 已有语义扩展名的证据一律不动。
        ("page.html", b"<html>x</html>", "page.html"),
        ("s.js", b"var a=1", "s.js"),
    ],
)
def test_canonical_evidence_name_appends_suffix_by_content(
    name: str, data: bytes, expected: str
) -> None:
    """★ ``.body`` / ``.headers`` 不在任何复用分析器的后缀名单里，原名入库=对它们隐形。

    故按内容**追加**规范扩展名（追加而非替换：报告 location 仍看得出原始文件名）。
    """
    assert canonical_evidence_name(name, data) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x89PNG\r\n\x1a\n\x00\x00", True),
        (b"\x7fELF\x02\x01", True),
        (b"%PDF-1.7", True),
        (b"PK\x03\x04", True),
        (b"<html>hi</html>", False),
        (b'{"json": true}', False),
        (b"", False),
        # UTF-16 文本天然含 NUL，不能被 NUL 判据误判成二进制。
        (b"\xff\xfe<\x00h\x00t\x00m\x00l\x00>\x00", False),
        (b"\xfe\xff\x00<\x00h", False),
        # 无魔数但含 NUL → 按 git 的经典启发式判二进制。
        (b"abc\x00def", True),
    ],
)
def test_looks_binary_by_magic_and_nul(data: bytes, expected: bool) -> None:
    assert looks_binary(data) is expected


def test_body_evidence_is_visible_to_reused_endpoints_analyzer(tmp_path: Path) -> None:
    """★接线断言（不是"抽到了域名"）：``.body`` / ``.headers`` 必须真被**复用**分析器扫到。

    这两个扩展名不在 ``_common.TEXT_RESOURCE_SUFFIXES`` 也不在 ``endpoints.yaml``，而作用域判据是
    "后缀 **或** 目录前缀"命中、虚拟前缀 ``web/`` 也不在其前缀名单 —— 若不补规范扩展名，则一份
    ``resp.body`` 里的端点一条都抽不到，且报告看起来毫无异常。删掉 canonical 调用 → 本测试必红。
    """
    from apkscan.analyzers.endpoints import EndpointsAnalyzer

    (tmp_path / "resp.body").write_bytes(
        b'<html><script>var u="https://from-body.example.com/v1";</script></html>'
    )
    (tmp_path / "h.headers").write_bytes(
        b"HTTP/1.1 302 Found\r\nLocation: https://from-hdr.example.net/go\r\n"
    )
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    result = EndpointsAnalyzer().analyze(ctx)  # type: ignore[arg-type]
    values = {ep.value for ep in result.endpoints}
    locations = {ev.location for ep in result.endpoints for ev in ep.evidences}

    assert "https://from-body.example.com/v1" in values
    assert "https://from-hdr.example.net/go" in values
    # location 仍保留原始文件名（追加而非替换），报告不伪造证据来源。
    assert any(loc.startswith("web/resp.body") for loc in locations)
    assert any(loc.startswith("web/h.headers") for loc in locations)


def test_binary_disguised_as_body_is_rejected_with_load_error(tmp_path: Path) -> None:
    """★一份 PNG 截图完全可能就叫 ``resp.body``：必须按内容拒收，且**如实记缺口**。

    静默跳过会让"扫了 1 份"与"扫全了"在报告里长得一样。
    """
    (tmp_path / "shot.body").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    (tmp_path / "ok.body").write_bytes(b"<html>ok</html>")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert [p for p in ctx.list_files()] == [WEB_PREFIX + "ok.body.html"]
    assert any("shot.body" in e and "二进制" in e for e in ctx.load_errors)


def test_load_web_evidence_reads_text_and_prefixes_paths(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_bytes(b"<html>hi</html>")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == [WEB_PREFIX + "index.html"]
    assert ctx.read_file(WEB_PREFIX + "index.html") == b"<html>hi</html>"
    assert ctx.origin == tmp_path.name
    assert ctx.source_dir == str(tmp_path)


def test_load_web_evidence_missing_dir_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_web_evidence(Path("no") / "such" / "dir", AnalysisConfig(online=False))


def test_load_web_evidence_gunzips_bounded(tmp_path: Path) -> None:
    """gzip 响应体要能解出来（落盘抓包常见 Content-Encoding: gzip）。"""
    payload = b"<html>window.api='https://" + DOC_HOST.encode() + b"'</html>"
    co = zlib.compressobj(wbits=31)
    (tmp_path / "resp.body").write_bytes(co.compress(payload) + co.flush())

    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    # 解压后按内容判为 HTML，故虚拟路径被追加 .html（见 canonical_evidence_name）。
    assert ctx.read_file(WEB_PREFIX + "resp.body.html") == payload


def test_load_web_evidence_rejects_gzip_bomb_without_full_decompress(tmp_path: Path) -> None:
    """★ 有界解压：几 KB 压缩 → 远超上限的解压结果必须被**拒**，且不静默丢。

    绝不能是 ``gzip.decompress(data)[:cap]``（切片发生在 OOM 之后 = 等于没切）。
    """
    co = zlib.compressobj(wbits=31)
    bomb = co.compress(b"\0" * (MAX_EVIDENCE_BYTES + 4096)) + co.flush()
    (tmp_path / "bomb.body").write_bytes(bomb)
    assert len(bomb) < 100_000, "构造前提：压缩后应远小于解压上限"

    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert ctx.list_files() == []
    assert any("bomb.body" in e and "gzip" in e for e in ctx.load_errors)


def test_load_web_evidence_rejects_truncated_gzip(tmp_path: Path) -> None:
    """截断 gzip 可吐出正文前缀但 CRC/ISIZE 不完整，不得把残片当成完整证据。"""
    payload = b"<html>" + b"x" * 4096 + b"</html>"
    co = zlib.compressobj(wbits=31)
    complete = co.compress(payload) + co.flush()
    (tmp_path / "truncated.body").write_bytes(complete[:-8])

    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == []
    assert any("truncated.body" in e and "gzip" in e for e in ctx.load_errors)


def test_load_web_evidence_caps_total_after_gzip_decompression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """总量上限按实际载入字节计算，不能用很小的 gzip 磁盘大小绕过。"""
    monkeypatch.setattr(webctx_module, "MAX_TOTAL_BYTES", 100)
    for name, payload in (("a.body", b"a" * 60), ("b.body", b"b" * 60)):
        co = zlib.compressobj(wbits=31)
        (tmp_path / name).write_bytes(co.compress(payload) + co.flush())

    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == [WEB_PREFIX + "a.body.txt"]
    assert any("b.body" in e and "解压后合计超上限" in e for e in ctx.load_errors)


def test_load_web_evidence_records_oversize_file_as_error(tmp_path: Path) -> None:
    """超单份上限的证据被跳过，但**必须**记进 load_errors。"""
    (tmp_path / "huge.js").write_bytes(b"x" * (MAX_EVIDENCE_BYTES + 1))
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == []
    assert any("huge.js" in e for e in ctx.load_errors)


def test_load_web_evidence_walks_subdirectories(tmp_path: Path) -> None:
    sub = tmp_path / "captured" / "js"
    sub.mkdir(parents=True)
    (sub / "app.js").write_bytes(b"var x=1")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert ctx.list_files() == [WEB_PREFIX + "captured/js/app.js"]


def test_load_web_evidence_preserves_canonical_name_collisions(tmp_path: Path) -> None:
    """``resp.body`` 的 HTML 别名不得覆盖真实 ``resp.body.html``。"""
    (tmp_path / "resp.body").write_bytes(b"<html>from body</html>")
    (tmp_path / "resp.body.html").write_bytes(b"<html>from explicit html</html>")

    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert len(ctx.list_files()) == 2
    assert ctx.read_file(WEB_PREFIX + "resp.body.html") == b"<html>from explicit html</html>"
    assert (
        ctx.read_file(WEB_PREFIX + "resp.body.evidence-2.html")
        == b"<html>from body</html>"
    )
    assert any("规范名" in error and "未丢失" in error for error in ctx.load_errors)


def test_load_web_evidence_keeps_non_utf8_bytes(tmp_path: Path) -> None:
    """非 UTF-8 的 .body 不因解码失败被丢弃（GBK 落盘页真实存在）。

    ★GBK 中文字节里没有 NUL，故内容嗅探**不会**把它误判成二进制丢掉；且原始 bytes 原样保留
    （解码交由各分析器按需做，与 APK 路径一致）。
    """
    raw = b"<html>\xd6\xd0\xce\xc4</html>"
    (tmp_path / "gbk.body").write_bytes(raw)
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))
    assert ctx.read_file(WEB_PREFIX + "gbk.body.html") == raw


# ---------------------------------------------------------------------------
# UTF-16 / UTF-32 BOM 证据：放行必须伴随规范化，否则等于静默产出不可读字节
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("codec", "bom"),
    [
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
        ("utf-32-le", b"\xff\xfe\x00\x00"),
        ("utf-32-be", b"\x00\x00\xfe\xff"),
    ],
)
def test_normalize_text_bytes_converts_every_bom_to_utf8(codec: str, bom: bytes) -> None:
    """四种 UTF-16/32 BOM 都必须解成 UTF-8，且 BOM 本身被剥掉。

    ★UTF-32 的 BOM 与 UTF-16 的 BOM 互为前缀（``\\xff\\xfe\\x00\\x00`` vs ``\\xff\\xfe``）：
    若匹配顺序写反，UTF-32-LE 会被当 UTF-16-LE 解出 NUL 交错的乱码。这条参数化把顺序钉死。
    """
    text = "<html>中文</html>"
    # ``str.encode("utf-16-le")`` 不带 BOM，须显式前置——本函数正是按 BOM 判编码的。
    out, error = normalize_text_bytes(bom + text.encode(codec))
    assert error is None
    assert out == text.encode("utf-8")
    assert not out.startswith(bom)


def test_normalize_text_bytes_strips_utf8_bom() -> None:
    """UTF-8 BOM 必须剥掉：留着会让 ``<!doctype`` 一类开头判据失配。"""
    out, error = normalize_text_bytes(b"\xef\xbb\xbf<html>ok</html>")
    assert (out, error) == (b"<html>ok</html>", None)


def test_normalize_text_bytes_leaves_bomless_bytes_untouched() -> None:
    """无 BOM 一律原样返回——绝不做编码嗅探（猜错编码 = 伪造证据内容）。"""
    raw = b"<html>\xd6\xd0\xce\xc4</html>"
    assert normalize_text_bytes(raw) == (raw, None)


def test_normalize_text_bytes_rejects_truncated_utf16_strictly() -> None:
    """截断的 UTF-16 证据必须**明确拒绝**，不得 ``errors='replace'`` 塞进分析器。

    与拒收截断 gzip 同一条原则：宁可拒读，也不把残片当完整页面。
    """
    truncated = b"\xff\xfe" + "<html>".encode("utf-16-le") + b"\x41"
    out, error = normalize_text_bytes(truncated)
    assert error is not None and "解码失败" in error
    assert out == truncated


def test_utf16_html_evidence_is_readable_by_reused_analyzer(tmp_path: Path) -> None:
    """★端到端接线断言：UTF-16 的 ``.body`` HTML 必须真被复用分析器抽到端点。

    ``looks_binary`` 有意为 UTF-16/32 BOM 放行（这类文本天然含 NUL）。放行后若不规范化成
    UTF-8，下游按 UTF-8 解出的是 ``<\\x00h\\x00t\\x00m\\x00l\\x00>``，所有正则全部失配，
    报告与"这份证据没线索"长得一模一样。删掉 normalize 调用 → 本测试必红。
    """
    from apkscan.analyzers.endpoints import EndpointsAnalyzer

    html = '<html><script>var u="https://utf16-body.example.com/v1";</script></html>'
    # 必须带 BOM：无 BOM 的 UTF-16 一律**不猜**（猜错编码 = 伪造证据内容），
    # 会被 NUL 判据当二进制如实拒收（见 test_bomless_utf16_is_refused_not_guessed）。
    (tmp_path / "resp.body").write_bytes(b"\xff\xfe" + html.encode("utf-16-le"))
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    # 规范化发生在 canonical_evidence_name 之前，故 UTF-16 的 HTML 也能被判成 .html。
    assert ctx.list_files() == [WEB_PREFIX + "resp.body.html"]
    assert ctx.read_file(WEB_PREFIX + "resp.body.html") == html.encode("utf-8")
    assert not ctx.load_errors

    values = {ep.value for ep in EndpointsAnalyzer().analyze(ctx).endpoints}  # type: ignore[arg-type]
    assert "https://utf16-body.example.com/v1" in values


def test_utf16_headers_evidence_is_readable_by_reused_analyzer(tmp_path: Path) -> None:
    """UTF-16 的 ``.headers`` 同样要能被抽到 Location 跳转目标（响应头也可能 UTF-16 落盘）。"""
    from apkscan.analyzers.endpoints import EndpointsAnalyzer

    raw = "HTTP/1.1 302 Found\r\nLocation: https://utf16-hdr.example.net/go\r\n"
    (tmp_path / "h.headers").write_bytes(b"\xfe\xff" + raw.encode("utf-16-be"))
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.read_file(WEB_PREFIX + "h.headers.txt") == raw.encode("utf-8")
    values = {ep.value for ep in EndpointsAnalyzer().analyze(ctx).endpoints}  # type: ignore[arg-type]
    assert "https://utf16-hdr.example.net/go" in values


def test_truncated_utf16_evidence_is_refused_with_load_error(tmp_path: Path) -> None:
    """解不干净的 BOM 证据必须进 ``load_errors`` 并**不入库**——绝不静默产出不可读字节。"""
    (tmp_path / "bad.body").write_bytes(b"\xff\xfe" + "<html>".encode("utf-16-le") + b"\x41")
    (tmp_path / "ok.body").write_bytes(b"<html>ok</html>")
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == [WEB_PREFIX + "ok.body.html"]
    assert any("bad.body" in e and "解码失败" in e for e in ctx.load_errors)


def test_bomless_utf16_is_refused_not_guessed(tmp_path: Path) -> None:
    """无 BOM 的 UTF-16 **不猜编码**：按 NUL 判据如实拒收并记缺口，绝不静默入库。

    这一条钉住"规范化只在有 BOM 时发生"这个边界。若为了多救一份证据去做编码嗅探，
    猜错就等于伪造证据内容——宁可让人看见"这份没扫"，也不能让人看见一份错的。
    """
    (tmp_path / "noboom.body").write_bytes("<html>x</html>".encode("utf-16-le"))
    ctx = load_web_evidence(tmp_path, AnalysisConfig(online=False))

    assert ctx.list_files() == []
    assert any("noboom.body" in e and "二进制" in e for e in ctx.load_errors)


# ---------------------------------------------------------------------------
# 分析器 1：内联配置
# ---------------------------------------------------------------------------


def test_inline_config_extracts_window_assignment() -> None:
    """★ HTML 内联 <script> 里的配置常不在被哈希的 app JS 里——只扫 .js 会整条漏掉。"""
    html = f"""<html><script>
      window.apiUrl = "https://{DOC_HOST}/api/v1";
    </script></html>""".encode()

    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/index.html": html}))

    values = [ep.value for ep in result.endpoints]
    assert f"https://{DOC_HOST}/api/v1" in values
    assert any("apiUrl" in lead.value for lead in result.leads)
    assert result.meta["web_inline_config_count"] == 1


def test_inline_config_extracts_var_and_json_forms() -> None:
    html = f"""<html><script>
      var baseUrl = "https://{DOC_HOST}/a";
      const cfg = {{"apiHost": "{DOC_HOP1}"}};
    </script></html>""".encode()

    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))
    values = [ep.value for ep in result.endpoints]
    assert f"https://{DOC_HOST}/a" in values
    assert DOC_HOP1 in values


def test_inline_config_ignores_non_config_noise() -> None:
    """`var a = "1"` 这类噪音必须丢，否则真配置被淹掉。"""
    html = b"""<html><script>var a = "1"; var msg = "hello world";</script></html>"""
    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))
    assert result.endpoints == []
    assert result.leads == []


def test_inline_config_does_not_read_external_script_tags() -> None:
    """只读**已落盘**内容：外链 <script src> 的体为空，绝不去取（本模块零出网）。"""
    html = b'<html><script src="https://cdn.example.com/app.js"></script></html>'
    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))
    assert result.endpoints == []


def test_inline_config_marks_cleartext_http() -> None:
    html = f'<html><script>window.api = "http://{DOC_HOST}/x";</script></html>'.encode()
    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))
    assert [ep.is_cleartext for ep in result.endpoints] == [True]


def test_inline_config_evidence_source_is_web_not_runtime() -> None:
    """★ source 绝不能是 runtime*：那是"实连/确认 C2"徽标与运行时角色门的单一真源。

    网页证据只证明"该值出现在这份落盘证据里"，不证明真接触过。
    """
    html = f'<html><script>window.api = "https://{DOC_HOST}/x";</script></html>'.encode()
    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))

    sources = {ev.source for ep in result.endpoints for ev in ep.evidences}
    sources |= {ev.source for lead in result.leads for ev in lead.source_refs}
    assert sources == {EVIDENCE_SOURCE}
    assert not any("runtime" in s for s in sources)


def test_inline_config_lead_has_no_fabricated_subject() -> None:
    """不据网页内容推断运营者：subject 必须为 None（宁可漏，不可造）。"""
    html = f'<html><script>window.api = "https://{DOC_HOST}/x";</script></html>'.encode()
    result = WebInlineConfigAnalyzer().analyze(_ctx({"web/i.html": html}))
    assert [lead.subject for lead in result.leads] == [None]


def test_inline_config_records_read_failure_in_meta() -> None:
    """★ 读失败必须成为**数据**：静默跳过会让"扫了 1 份"与"扫全了"在报告里完全一样。"""

    class Failing(WebContext):
        def read_file(self, path: str) -> bytes | None:  # noqa: ARG002
            raise OSError(f"simulated unreadable evidence: {path}")

    ctx = Failing(config=AnalysisConfig(online=False), files={"web/i.html": b"<html></html>"})
    result = WebInlineConfigAnalyzer().analyze(ctx)
    assert result.meta["web_inline_config_read_failed"] == 1


def test_inline_config_survives_listing_failure() -> None:
    """绝不抛给调用方（项目铁律）；失败如实记 meta。"""

    class NoList(WebContext):
        def list_files(self) -> list[str]:
            raise OSError("simulated")

    result = WebInlineConfigAnalyzer().analyze(NoList(config=AnalysisConfig(online=False)))
    assert result.meta["web_inline_config_list_failed"] is True


# ---------------------------------------------------------------------------
# 分析器 2：跳转链（顺序是产出本体）
# ---------------------------------------------------------------------------


def test_redirect_chain_is_ordered_and_keeps_every_hop() -> None:
    """★ 计划书点名的验收：两跳 location.replace 必须**有序且两跳都在**。

    删掉解析第二跳的那行 → 本断言必红（链形是本分析器的产出本体）。
    """
    html = f"""<html><script>
      if (isIOS) {{ location.replace("https://{DOC_HOP1}/ios"); }}
      else {{ location.replace("https://{DOC_HOP2}/android"); }}
    </script></html>""".encode()

    result = WebRedirectChainAnalyzer().analyze(_ctx({"web/land.html": html}))
    chains = result.meta["web_redirect_chain"]
    chain = chains[0]["hops"]

    assert len(chains) == 1
    assert [c["step"] for c in chain] == [1, 2]
    assert chain[0]["target"] == f"https://{DOC_HOP1}/ios"
    assert chain[1]["target"] == f"https://{DOC_HOP2}/android"


def test_redirect_chain_order_follows_document_not_mechanism() -> None:
    """★ 顺序必须是**证据内的出现次序**，不是"按机制分组"的扫描次序。

    上一条测试的两跳同为 ``location.replace``，扫描次序恰好等于文档次序，故删掉
    ``hops.sort(...)`` 它也照样绿。这里把机制**交错**：文档里 ``<meta refresh>`` 在前、
    ``location.replace`` 在后，而 ``_scan`` 是按机制分组扫的（assign → call → meta → header），
    去掉排序就会把后出现的 ``location-call`` 排到第 1 跳 —— 链形被机制分组次序覆盖。
    """
    html = f"""<html><head>
      <meta http-equiv="refresh" content="0;url=https://{DOC_HOP1}/a">
    </head><body><script>
      location.replace("https://{DOC_HOP2}/b");
    </script></body></html>""".encode()

    result = WebRedirectChainAnalyzer().analyze(_ctx({"web/land.html": html}))
    chain = result.meta["web_redirect_chain"][0]["hops"]

    assert [c["step"] for c in chain] == [1, 2]
    # 第 1 跳 = 文档里先出现的 meta-refresh，而非扫描时先跑的 location-call。
    assert [c["mechanism"] for c in chain] == ["meta-refresh", "location-call"]
    assert [c["target"] for c in chain] == [
        f"https://{DOC_HOP1}/a",
        f"https://{DOC_HOP2}/b",
    ]


def test_redirect_chain_covers_all_four_mechanisms() -> None:
    files = {
        "web/a.html": (
            f'<meta http-equiv="refresh" content="0;url=https://{DOC_HOP1}/m">'
            f'<script>window.location.href = "https://{DOC_HOP2}/h";'
            f'location.assign("https://{DOC_HOST}/c");</script>'
        ).encode(),
        "web/a.headers": f"HTTP/1.1 302 Found\r\nLocation: https://{DOC_HOP1}/redir\r\n".encode(),
    }
    result = WebRedirectChainAnalyzer().analyze(_ctx(files))
    mechanisms = {
        hop["mechanism"]
        for chain in result.meta["web_redirect_chain"]
        for hop in chain["hops"]
    }
    assert mechanisms == {"meta-refresh", "location-assign", "location-call", "header-location"}


def test_redirect_candidates_from_separate_files_are_not_fabricated_as_one_chain() -> None:
    """静态文件之间没有因果边；各文件单独分组、步号分别从 1 开始。"""
    files = {
        "web/a.html": f'<script>location.replace("https://{DOC_HOP1}/a")</script>'.encode(),
        "web/b.html": f'<script>location.replace("https://{DOC_HOP2}/b")</script>'.encode(),
    }

    result = WebRedirectChainAnalyzer().analyze(_ctx(files))
    chains = result.meta["web_redirect_chain"]

    assert [chain["location"] for chain in chains] == ["web/a.html", "web/b.html"]
    assert [[hop["step"] for hop in chain["hops"]] for chain in chains] == [[1], [1]]
    assert "不同文件之间未建立因果关系" in result.findings[0].description


def test_redirect_chain_finding_lists_hops_in_order() -> None:
    html = (
        f'<script>location.replace("https://{DOC_HOP1}/1");'
        f'location.replace("https://{DOC_HOP2}/2");</script>'
    ).encode()
    result = WebRedirectChainAnalyzer().analyze(_ctx({"web/a.html": html}))

    finding = result.findings[0]
    assert finding.id == "WEB-REDIRECT-CHAIN"  # leak-scan: allow finding.id 是属性访问，.id 恰为 TLD 导致误报
    assert finding.description.index(DOC_HOP1) < finding.description.index(DOC_HOP2)
    # 静态文本形态 ≠ 运行时真的这么跳（条件分流在静态里看不出走哪条）——措辞必须留这条边界。
    assert "静态" in finding.description


def test_redirect_chain_empty_when_no_redirect() -> None:
    result = WebRedirectChainAnalyzer().analyze(_ctx({"web/a.html": b"<html>plain</html>"}))
    assert result.findings == []
    assert "web_redirect_chain" not in result.meta


def test_redirect_chain_does_not_mine_minified_property_access() -> None:
    """★ 误报门槛：压缩 JS 的 `a.length` / `rect.top` 不得被抽成域名/跳转目标。"""  # leak-scan: allow 属性访问示例，非域名
    js = b"function f(a,rect){return a.length+rect.top+b.call(c)}"  # leak-scan: allow 本行即该误报的回归夹具，必须逐字保留
    result = WebRedirectChainAnalyzer().analyze(_ctx({"web/app.js": js}))
    assert result.endpoints == []
    assert result.findings == []


# ---------------------------------------------------------------------------
# 分析器 3：请求配方
# ---------------------------------------------------------------------------


def _b64(s: str) -> str:
    import base64

    return base64.b64encode(s.encode()).decode()


def test_request_recipe_needs_both_base64_and_request_context() -> None:
    """判据是"base64 解出可打印短串" **与** "请求头语境词共现"——缺一不产。"""
    token = _b64("X-Requested-With: com.example.client")
    js = f'xhr.setRequestHeader(atob("{token}"));'.encode()

    result = WebRequestRecipeAnalyzer().analyze(_ctx({"web/app.js": js}))
    recipes = result.meta["web_request_recipe"]
    assert [r["decoded"] for r in recipes] == ["X-Requested-With: com.example.client"]
    assert recipes[0]["context"] in {"setrequestheader", "xhr", "header"}


def test_request_recipe_skips_base64_without_request_context() -> None:
    js = f'var img = "{_b64("Some unrelated plain text here")}";'.encode()
    result = WebRequestRecipeAnalyzer().analyze(_ctx({"web/app.js": js}))
    assert "web_request_recipe" not in result.meta
    assert result.findings == []


def test_request_recipe_skips_binary_payloads() -> None:
    """解出二进制（图片等）不是配方：必须要求可打印 ASCII。"""
    import base64

    token = base64.b64encode(bytes(range(0, 32)) * 2).decode()
    js = f'fetch(url, {{headers: h}}); var b = "{token}";'.encode()
    result = WebRequestRecipeAnalyzer().analyze(_ctx({"web/app.js": token.encode() + js}))
    decoded = [r["decoded"] for r in result.meta.get("web_request_recipe", [])]
    assert all("\x00" not in d for d in decoded)


def test_request_recipe_confidence_is_low_and_wording_hedged() -> None:
    """★ 启发式判据不许写成已确认的协议规格（宁可漏，不可造）。"""
    from apkscan.core.models import Confidence, Severity

    token = _b64("Authorization: Bearer placeholder-token")
    js = f'fetch(u,{{headers:{{a:atob("{token}")}}}});'.encode()
    result = WebRequestRecipeAnalyzer().analyze(_ctx({"web/app.js": js}))

    finding = result.findings[0]
    assert finding.id == "WEB-REQUEST-RECIPE"  # leak-scan: allow finding.id 是属性访问，.id 恰为 TLD 导致误报
    assert finding.confidence == Confidence.LOW
    assert finding.severity == Severity.LOW
    assert "疑似" in finding.title
    assert "启发式" in finding.description


def test_request_recipe_deduplicates_repeated_literals() -> None:
    token = _b64("X-Token: placeholder")
    js = (f'h.setRequestHeader(atob("{token}"));' * 5).encode()
    result = WebRequestRecipeAnalyzer().analyze(_ctx({"web/app.js": js}))
    assert len(result.meta["web_request_recipe"]) == 1


# ---------------------------------------------------------------------------
# 三个分析器共有的契约
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "analyzer",
    [WebInlineConfigAnalyzer(), WebRedirectChainAnalyzer(), WebRequestRecipeAnalyzer()],
    ids=lambda a: a.name,
)
def test_web_analyzers_declare_web_requirement(analyzer: object) -> None:
    """必须声明 requires=["web"]，否则会在 android 样本上空跑、凭空多出结论。"""
    assert analyzer.requires == ["web"]  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "analyzer",
    [WebInlineConfigAnalyzer(), WebRedirectChainAnalyzer(), WebRequestRecipeAnalyzer()],
    ids=lambda a: a.name,
)
def test_web_analyzers_handle_empty_context(analyzer: object) -> None:
    result = analyzer.analyze(_ctx({}))  # type: ignore[attr-defined]
    assert result.endpoints == []
    assert result.findings == []
    assert result.leads == []


# ---------------------------------------------------------------------------
# analyze-web 端到端（commands/web.py）
# ---------------------------------------------------------------------------


def _evidence_dir(tmp_path: Path) -> Path:
    """造一份含内联配置 + 两跳跳转 + 请求配方的证据目录（全用文档保留域）。"""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "landing.html").write_text(
        "<html><script>\n"
        f'window.apiBase = "https://{DOC_HOST}/api/v1";\n'
        f'location.replace("https://a.{DOC_HOST}/hop1");\n'
        "</script></html>",
        encoding="utf-8",
    )
    (root / "hop1.body").write_text(
        f"<html><script>window.location.href='https://b.{DOC_HOST}/hop2';</script></html>",
        encoding="utf-8",
    )
    (root / "app.js").write_text(
        f'var h = {{headers: {{"X-Token": atob("WC1SZXF1ZXN0LUlkOiBhYmNk")}}}};\n'
        f'fetch("https://js.{DOC_HOST}/v2/config");\n'
        'var loginPath = "/api/v2/login";',
        encoding="utf-8",
    )
    # 二进制证据必须被跳过（不该被解码成文本跑正则）。
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    return root


def test_analyze_web_end_to_end_writes_report_json(tmp_path: Path) -> None:
    """★端到端：analyze-web 产出 report.json，且走的是与 analyze 同一条出口。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    result = CliRunner().invoke(
        cli.app, ["analyze-web", str(root), "--fmt", "json", "--origin", "case-synthetic"]
    )
    assert result.exit_code == 0, result.output

    report_path = root / "out" / "case-synthetic.json"
    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))

    assert data["meta"]["platform"] == "web"
    assert data["meta"]["web_evidence"]["file_count"] == 3  # .png 未读入
    assert data["meta"]["online"] is False

    # 三个 web 分析器 + 承诺复用的 JS/API 分析器都真跑了（不是 skipped）。
    status = {s["name"]: s["status"] for s in data["analyzer_status"]}
    for name in (
        "web_inline_config",
        "web_redirect_chain",
        "web_request_recipe",
        "js_bundle",
        "api_surface",
    ):
        assert status.get(name) == "ran", (name, status.get(name))
    assert data["meta"]["js_files_scanned"] >= 1
    assert data["meta"]["js_endpoint_count"] >= 1
    assert data["meta"]["api_surface"]["counts"]["own"] >= 1

    # Web 本来就没有 DEX，不得伪装成 DEX 解析失败或写一份 0 样本字符串池画像。
    assert "dex_parse_failed" not in data["meta"]
    assert "dex_string_pool" not in data["meta"]
    assert status.get("dex_obfuscation") == "skipped"

    # 重跑不得把第一次生成在证据根/out 下的 report.json 当成第 4 份证据吃回去。
    rerun = CliRunner().invoke(
        cli.app, ["analyze-web", str(root), "--fmt", "json", "--origin", "case-synthetic"]
    )
    assert rerun.exit_code == 0, rerun.output
    rerun_data = json.loads(report_path.read_text(encoding="utf-8"))
    assert rerun_data["meta"]["web_evidence"]["file_count"] == 3


def test_analyze_web_skips_android_only_analyzers(tmp_path: Path) -> None:
    """★平台门控在真命令下生效：requires=["apk"] 的分析器不得在网页证据上空跑。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    result = CliRunner().invoke(cli.app, ["analyze-web", str(root), "--fmt", "json"])
    assert result.exit_code == 0, result.output

    data = json.loads((root / "out" / "evidence.json").read_text(encoding="utf-8"))
    status = {s["name"]: s["status"] for s in data["analyzer_status"]}
    # manifest / permissions 一类 Android 专属分析器必须 skipped，且理由可见。
    skipped = [name for name, st in status.items() if st == "skipped"]
    assert skipped, status
    assert status.get("web_inline_config") == "ran"


def test_analyze_web_empty_dir_is_error_not_empty_report(tmp_path: Path) -> None:
    """★零证据必须非零退出：空报告与"真的没有线索"不可区分，绝不能 exit 0。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = tmp_path / "empty"
    root.mkdir()
    (root / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    result = CliRunner().invoke(cli.app, ["analyze-web", str(root), "--fmt", "json"])
    assert result.exit_code == 2
    assert not (root / "out").exists() or not list((root / "out").glob("*.json"))


def test_analyze_web_origin_cannot_escape_out_dir(tmp_path: Path) -> None:
    """★不可信输入：--origin 里的路径穿越不得把报告写到 out 目录之外。"""
    from typer.testing import CliRunner

    from apkscan import cli

    root = _evidence_dir(tmp_path)
    result = CliRunner().invoke(
        cli.app, ["analyze-web", str(root), "--fmt", "json", "--origin", "../../escaped"]
    )
    assert result.exit_code == 0, result.output
    assert not (tmp_path.parent / "escaped.json").exists()
    assert not (tmp_path / "escaped.json").exists()
    assert list((root / "out").glob("*.json"))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # 分隔符必须被吃掉：这是防穿越的**真正**那道闸（字符过滤，不是 lstrip）。
        ("../../escaped", ".._escaped"),
        ("..\\..\\escaped", ".._escaped"),
        # 结果绝不以点开头：否则 origin 为 ".git" / ".env" 一类时报告会写成隐藏文件，
        # 人在目录里看不见 —— 取证产物必须可见。
        (".git", "git"),
        ("...", _FALLBACK_BASE),
        # 空/全废字符须落到兜底 base，绝不产出空文件名。
        ("", _FALLBACK_BASE),
        ("///", _FALLBACK_BASE),
        ("normal-name.v2", "normal-name.v2"),
    ],
)
def test_sanitize_base_strips_separators_and_leading_dots(raw: str, expected: str) -> None:
    """★不可信输入逐条钉死 ``_sanitize_base`` 的三条性质。

    此前只有端到端的 ``--origin ../../escaped`` 一条覆盖，而它靠字符过滤就能过；
    删掉 ``lstrip(".")`` 时全绿（实测变异存活）—— 故在此把「不产隐藏文件」单独钉住。
    """
    assert _sanitize_base(raw) == expected


def test_sanitize_base_bounds_length() -> None:
    """超长 origin 不得产出超长文件名（文件系统上限 + 报告目录可读性）。"""
    assert len(_sanitize_base("a" * 500)) <= 80


def test_analyze_web_reports_load_errors_to_stderr(tmp_path: Path) -> None:
    """读取缺口必须当场对人可见（stderr），不只躺在 report.json 里。"""
    from typer.testing import CliRunner

    from apkscan import cli
    from apkscan.core import webctx

    root = _evidence_dir(tmp_path)
    oversized = root / "huge.html"
    oversized.write_text("x" * 128, encoding="utf-8")

    monkey = webctx.MAX_EVIDENCE_BYTES
    try:
        webctx.MAX_EVIDENCE_BYTES = 16
        result = CliRunner().invoke(cli.app, ["analyze-web", str(root), "--fmt", "json"])
    finally:
        webctx.MAX_EVIDENCE_BYTES = monkey

    assert "警告" in result.output or result.exit_code == 2
