"""网页证据上下文：把**已落盘**的网页证据当一级输入喂进同一条分析流水线。

为什么需要它：实测有的样本压根没有 APK、只有 URL 与落盘的网页证据（``.body`` / ``.headers.txt`` /
``.html`` / ``.js``），当前 ``analyze`` 吃不进去 —— 那些证据里的分发链、内联配置、跳转跳板全靠人工挖。
本模块让这类证据走 :func:`apkscan.core.pipeline.run` 同一条出口（同样的 Lead/Finding/report.json），
不另建一套并行管线。

★ 纯离线：只读已落盘文件，**绝不联网**、绝不抓取。本模块没有任何出网调用；主动获取一律不在此实现
  （见 AGENTS.md 主被动硬隔离）。

★ 平台门控是硬前置：本类 ``platform="web"``，故 registry 只放行 ``requires=[]`` 与 ``requires=["web"]``
  的分析器，30 个 ``requires=["apk"]`` 的 Android 专属分析器自动 skip（不在网页证据上空跑）。

实现 :class:`apkscan.core.context.AnalysisContext` 协议。APK 专属成员按协议如实给空值：
``dex_strings()`` 空迭代、``native_libs()`` / ``certificates()`` / ``permissions()`` 空列表、
``manifest_xml`` 空串 —— 网页证据里这些概念**不存在**，给空值不是"采集失败"。故本类另置
``dex_available = False``（供 :mod:`apkscan.core.visibility` 判"DEX 面无从谈起"，
而不是让它按默认 ``True`` 把"压根没有 DEX"读成"DEX 已看全"）。
"""

from __future__ import annotations

import logging
import os
import posixpath
import zlib
from collections.abc import Iterable
from pathlib import Path

from apkscan.core.models import AnalysisConfig, CertInfo, ComponentSet

logger = logging.getLogger(__name__)

#: 单份证据文件读入上限（网页证据应很小；防单个巨文件拖垮分析）。
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
#: 全部证据合计上限（防"一目录几百 MB"把内存吃干）。
MAX_TOTAL_BYTES = 96 * 1024 * 1024
#: 证据文件数上限（真正**读入**的文本证据份数）。
MAX_EVIDENCE_FILES = 2000

#: 目录遍历时**发现**的普通文件数硬上限（含二进制/不支持后缀的文件）。
#: ★与 :data:`MAX_EVIDENCE_FILES` 是两件事：后者只数读入的文本证据，一个塞满 ``.png`` 的目录
#: 一份都不计入，却能让遍历清单无界增长。上限落在发现数上，遍历本身才真正有界。
#: 取 :data:`MAX_EVIDENCE_FILES` 的 20 倍：正常证据目录混杂截图/字体属常态，
#: 留足冗余的同时封住"几十万份文件"这类输入。
MAX_DISCOVERED_FILES = MAX_EVIDENCE_FILES * 20

#: 遍历时允许**遇到**的目录项总数硬上限——普通文件、子目录、符号链接、其他类型一律计数。
#: ★为什么普通文件数封顶不够：:data:`MAX_DISCOVERED_FILES` 只在"决定收下一个普通文件"时才
#: 生效，于是三类输入能整体绕过它——
#:   ①一个塞了几十万条符号链接的目录：每条只 ``errors.append`` 不增 ``len(out)``；
#:   ②几十万个空目录：一个普通文件都没有，却每层都要被 scandir 一遍；
#:   ③单目录海量条目：旧实现由 ``os.walk`` **先把该目录的 filenames 整份物化**、``sorted``
#:     再复制一份，两份列表都在"文件数检查"之前就已在内存里。
#: 计在**目录项**上，这三条才一起被封住：本函数从 ``os.scandir`` 拉条目时逐条计数，budget
#: 一到即停止拉取，海量目录项从不会被整份物化。
MAX_DISCOVERED_ENTRIES = MAX_DISCOVERED_FILES * 2

#: 遍历阶段写进 ``load_errors`` 的条目数上限。★符号链接/取类型失败每项一条 error，海量
#: 输入下 ``errors`` 自己就是无界增长的那个列表。超出后不再逐条记，改记一条汇总（条数如实）。
MAX_TRAVERSAL_ERRORS = 100

#: 虚拟路径前缀：证据在上下文里一律挂到 ``web/`` 下，与 APK 内路径（``assets/`` 等）不混淆。
WEB_PREFIX = "web/"

#: 视作文本证据的扩展名。``.body`` / ``.headers`` 是抓包落盘的惯例命名（无扩展名的响应体/响应头）。
TEXT_EVIDENCE_SUFFIXES: tuple[str, ...] = (
    ".html", ".htm", ".js", ".mjs", ".cjs", ".json", ".txt", ".body", ".headers",
    ".css", ".xml", ".csv", ".har", ".log", ".md",
)

#: 无语义扩展名：抓包工具落盘的响应体/响应头惯例命名，**不在**任何复用分析器的后缀名单里
#: （``_common.TEXT_RESOURCE_SUFFIXES`` / ``endpoints.yaml:resource_extensions`` 都没有它们）。
#: 原名直接入库 → 这些证据对全部复用分析器**隐形**，见 :func:`canonical_evidence_name`。
ALIAS_EVIDENCE_SUFFIXES: tuple[str, ...] = (".body", ".headers")

#: 明确不读的二进制证据（截图/字体/媒体等）。把它们解码成文本跑正则既错又可能触发灾难性回溯
#: （与 :mod:`apkscan.analyzers._common` 的 ``BINARY_RESOURCE_SUFFIXES`` 同一教训）。
BINARY_EVIDENCE_SUFFIXES: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svgz",
    ".otf", ".ttf", ".woff", ".woff2", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi", ".mov", ".mkv",
    ".zip", ".gz", ".br", ".7z", ".rar", ".apk", ".ipa", ".so", ".dex", ".pdf",
)


def _gunzip_bounded(data: bytes) -> bytes | None:
    """★有界解压 gzip：增量解压、超上限即拒 —— 防 gzip 炸弹（几 KB 压缩 → 数 GB 解压）。

    绝不用 ``gzip.decompress(data)[:cap]``：那是**先全量解压进内存再切片**，切片发生在 OOM 之后
    = 等于没切。写法与 :func:`apkscan.config.decode._gunzip` 一致（同一个已修过的 OOM 面）。

    ★**必须按 member 循环**：gzip 规范（RFC 1952 §2.2）允许多个成员直接拼接，
    ``gzip.compress(a) + gzip.compress(b)`` 是完全合法的一份 gzip 文件，抓包落盘的分块响应体
    正是这个形态。单次 ``decompressobj().decompress()`` 只解**第一个**成员，剩下的落进
    ``unused_data`` —— 直接返回第一段等于把**部分**响应体当完整页面入库：后半截里的域名/端点
    一条都抽不到，而报告长得跟"这份证据没线索"一模一样。宁可拒读也不能静默截断
    （与本函数拒收截断流、:func:`normalize_text_bytes` 拒收解不干净的 UTF-16 同一条原则）。

    尾随垃圾（非 gzip 魔数的残留字节）→ 返回 ``None`` 明确拒收，由调用方写 ``load_error``。
    总解压量上限仍是**单文件**上限 :data:`MAX_EVIDENCE_BYTES`（所有成员合计），不是每成员各一份。
    """
    chunks: list[bytes] = []
    total = 0
    remaining = data
    while remaining:
        if not _looks_gzip(remaining):
            # 尾随垃圾/截断的下一成员头：已解出的部分是**不完整**证据，整份拒收。
            return None
        try:
            decompressor = zlib.decompressobj(wbits=31)
            out = decompressor.decompress(remaining, MAX_EVIDENCE_BYTES + 1 - total)
        except (OSError, EOFError, zlib.error):
            return None
        # ``decompress()`` 对截断流可能返回一个看似正常的前缀而不抛异常；只有 eof=True
        # 才证明该成员尾部（含 CRC/ISIZE）完整。证据输入宁可拒读，也不能把残片当完整页面。
        if not decompressor.eof:
            return None
        total += len(out)
        if total > MAX_EVIDENCE_BYTES:
            return None
        chunks.append(out)
        # ★用 unused_data 前进到下一成员；它只在 eof 后才有意义（上面已断言 eof）。
        next_remaining = decompressor.unused_data
        if len(next_remaining) >= len(remaining):
            # 理论不可达；防御性兜底，避免任何情况下的死循环。
            return None
        remaining = next_remaining
    if not chunks:
        return None
    return b"".join(chunks)


def _looks_gzip(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B


#: 内容嗅探取样长度（只看开头，够判魔数与 NUL 密度）。
_SNIFF_BYTES = 8192

#: UTF-16/32 BOM：这类**文本**天然含 NUL 字节，不能被 NUL 判据误判成二进制。
_TEXT_BOMS: tuple[bytes, ...] = (
    b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff",
)

#: 常见二进制内容魔数。``.body`` 一类**无语义扩展名**的响应体可能压根不是文本
#: （截图/字体/媒体/压缩包直接落盘成 ``resp.body``），靠扩展名判不出来。
_BINARY_MAGICS: tuple[bytes, ...] = (
    b"\x89PNG\r\n\x1a\n",           # PNG
    b"\xff\xd8\xff",                 # JPEG
    b"GIF87a", b"GIF89a",            # GIF
    b"RIFF",                         # WebP / WAV / AVI
    b"\x00\x00\x01\x00",             # ICO
    b"OTTO", b"\x00\x01\x00\x00", b"ttcf",  # 字体
    b"wOFF", b"wOF2",                # WOFF/WOFF2
    b"PK\x03\x04",                   # ZIP/APK/JAR
    b"Rar!\x1a\x07",                 # RAR
    b"7z\xbc\xaf\x27\x1c",           # 7z
    b"%PDF-",                        # PDF
    b"dex\n",                        # DEX
    b"\x7fELF",                      # ELF/.so
    b"\x1f\x8b",                     # gzip（解压失败后仍是二进制）
    b"ID3", b"\xff\xfb",             # MP3
    b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x20ftyp",  # MP4
)


def looks_binary(data: bytes) -> bool:
    """内容是否是二进制（魔数 或 取样段含 NUL 字节）。

    ★为什么必须按内容判而不只看扩展名：``.body`` / ``.headers`` 是抓包落盘的**无语义命名**，
    一份 PNG 截图完全可能就叫 ``resp.body``。把它解码成文本跑正则既错（在字体/图片里"找域名"）
    又可能触发灾难性回溯——与 :mod:`apkscan.analyzers._common` 的 ``BINARY_RESOURCE_SUFFIXES``
    同一个已付过代价的教训（曾因把 .otf 当文本喂给 email 正则卡死 4.6 分钟）。

    NUL 判据用 git 的经典启发式（取样段含 ``\\x00`` 即二进制），但 **UTF-16/32 文本天然含 NUL**，
    故 BOM 优先放行，避免把 UTF-16 的 HTML 响应体判成二进制丢掉。
    """
    if not data:
        return False
    if data.startswith(_TEXT_BOMS):
        return False
    if data.startswith(_BINARY_MAGICS):
        return True
    return b"\x00" in data[:_SNIFF_BYTES]


#: BOM → 编解码器名。顺序要紧：4 字节的 UTF-32 BOM 必须先于 2 字节的 UTF-16 BOM 匹配，
#: 否则 ``\xff\xfe\x00\x00``（UTF-32-LE）会被 ``\xff\xfe``（UTF-16-LE）抢先命中，
#: 解出一串以 NUL 交错的乱码。
_BOM_CODECS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)


def normalize_text_bytes(data: bytes) -> tuple[bytes, str | None]:
    """把带 UTF-16/32 BOM 的证据**严格**转成 UTF-8 字节；返回 ``(字节, 失败原因或 None)``。

    ★为什么必须做而不能原样入库：:func:`looks_binary` 有意为 UTF-16/32 BOM 开了放行口
    （这类文本天然含 NUL，否则会被 NUL 判据当二进制丢掉）。放行之后如果**原样**存进
    ``ctx.files``，下游每个分析器都会按 UTF-8 解它 —— 一份 UTF-16-LE 的 ``<html>`` 在
    ``errors="replace"`` 下变成 ``<�h�t�m�l�>``：所有正则全部失配，
    报告里长得跟"这份证据没线索"一模一样。**放行但不规范化 = 静默产出不可读字节**，
    比一开始就判二进制更坏（后者至少会进 ``load_errors``）。

    严格解码（``errors="strict"``）：解不干净就**不猜、不替换**，返回原字节 + 失败原因，
    由调用方记入 ``load_errors`` 明确拒收。截断的 UTF-16 证据宁可拒读，也不能把残片
    当完整页面喂进分析器 —— 与 :func:`_gunzip_bounded` 拒收截断 gzip 同一条原则。

    UTF-8 BOM 一并剥掉：它对 UTF-8 解码无意义，留着会让 ``<!doctype`` 这类开头判据失配。
    无 BOM 的字节原样返回（不做编码嗅探——猜错编码就是伪造证据内容）。
    """
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:], None
    for bom, codec in _BOM_CODECS:
        if not data.startswith(bom):
            continue
        try:
            text = data[len(bom) :].decode(codec, errors="strict")
        except (UnicodeDecodeError, LookupError) as exc:
            return data, f"{codec} BOM 证据解码失败（{type(exc).__name__}），未读入"
        return text.encode("utf-8"), None
    return data, None


def canonical_evidence_name(name: str, data: bytes) -> str:
    """给无语义扩展名的证据**追加**一个规范扩展名，否则它对全部复用分析器隐形。

    ★为什么必须做：``.body`` / ``.headers`` 不在 ``_common.TEXT_RESOURCE_SUFFIXES``，也不在
    ``endpoints.yaml:resource_extensions``。而这些分析器的作用域判据（``is_text_resource`` /
    ``_is_resource_target``）是"后缀命中 **或** 目录前缀命中"，本模块的虚拟前缀 ``web/`` 又不在
    它们的前缀名单（``assets/`` / ``res/`` …）里 —— 两个条件都不满足，于是一份 ``resp.body``
    里的端点/凭据/后台路径**一条都不会被抽到**。这正是「提取出信号但没接线」那类缺陷。

    做法是**追加**而非替换（``resp.body`` → ``resp.body.html``）：报告里的 location 仍能看出
    原始文件名，不伪造证据来源。``.headers`` → ``.headers.txt`` 恰好就是抓包落盘的常见写法。

    只按内容判，不猜：HTML 与 JSON 有可靠的开头特征，各给对应扩展名；**判不出来的一律
    ``.txt``**（保守）。刻意不猜 JS —— 裸 JS 没有可靠魔数，猜错会把响应体喂进 JS 专属判据；
    ``.txt`` 已足够让 ``endpoints`` / ``_common`` 系分析器看见它。
    """
    low = name.lower()
    if not low.endswith(ALIAS_EVIDENCE_SUFFIXES):
        return name
    head = data[:_SNIFF_BYTES].lstrip()
    if head.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        head = head[3:].lstrip()
    sample = head[:512].lower()
    if sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<!--")) or (
        b"<html" in sample or b"<script" in sample
    ):
        return f"{name}.html"
    if head.startswith((b"{", b"[")):
        return f"{name}.json"
    return f"{name}.txt"


def is_text_evidence(name: str) -> bool:
    """该文件名是否值得按文本证据读入（二进制后缀优先排除）。"""
    low = name.lower()
    if low.endswith(BINARY_EVIDENCE_SUFFIXES):
        return False
    return low.endswith(TEXT_EVIDENCE_SUFFIXES)


class WebContext:
    """网页证据上下文（实现 ``AnalysisContext`` 协议，``platform="web"``）。

    Args:
        config:     分析配置（沿用 APK 路径同一份 :class:`AnalysisConfig`）。
        files:      ``{虚拟路径: 内容字节}``。虚拟路径一律以 :data:`WEB_PREFIX` 开头。
        origin:     证据来源标识（URL 或目录名），只作报告标注，不参与任何请求。
        source_dir: 证据目录真实路径（作溯源记录；可空）。
        load_errors: 读取失败的文件清单 —— **必须如实带出**，见下。

    ★ ``load_errors`` 为什么是构造参数而非内部日志：读失败被静默跳过时，"扫了 1 份"与"扫全了"
      在数据上完全一样，报告就会以「网页证据已穷尽」签发一份漏读了关键证据的分析。
    """

    #: 网页证据无 DEX 面。显式 False 让 visibility 判"无从谈起"，而非按默认 True 当"已看全"。
    dex_available: bool = False

    def __init__(
        self,
        config: AnalysisConfig,
        files: dict[str, bytes] | None = None,
        origin: str = "",
        source_dir: str = "",
        load_errors: list[str] | None = None,
    ) -> None:
        self.config = config
        self.apk_path = ""  # 无 APK：jadx/unpack 等增强器据此自然不启用
        # 同理：Web 证据面没有 DEX，脱壳回灌路径在此恒为空（协议要求该字段存在）。
        self.extra_dex_paths: list[str] = []
        # 同理：无 jadx 面，持久索引在 Web 证据上恒不启用（协议要求该字段存在）。
        self.jadx_cache_root: str | None = None
        self._files: dict[str, bytes] = dict(files or {})
        self.origin = origin
        self.source_dir = source_dir
        self.load_errors: list[str] = list(load_errors or [])

    # ---- AnalysisContext 协议：包标识 ------------------------------------

    @property
    def platform(self) -> str:
        return "web"

    @property
    def package_name(self) -> str:
        """网页证据没有包名。返回 ``origin`` 作人可读标识（空则空串）。

        不编造 ``com.unknown`` 之类的假包名 —— 报告里的"包名"必须是真事实或明确为空。
        """
        return self.origin

    @property
    def manifest_xml(self) -> str:
        return ""  # 网页无 AndroidManifest

    # ---- AnalysisContext 协议：APK 专属成员（如实空值）-------------------

    def permissions(self) -> list[str]:
        return []

    def components(self) -> ComponentSet:
        return ComponentSet()

    def dex_strings(self):
        """网页证据无 DEX 字符串池 —— 空迭代（不是"遍历失败"）。"""
        return iter(())

    def native_libs(self) -> list[str]:
        return []

    def certificates(self) -> list[CertInfo]:
        return []

    # ---- AnalysisContext 协议：文件访问 ----------------------------------

    def list_files(self) -> list[str]:
        return list(self._files.keys())

    def read_file(self, path: str) -> bytes | None:
        return self._files.get(path)

    def declared_size(self, path: str) -> int | None:
        """证据已全部读进内存，实际长度即声明长度；未知路径 → None。"""
        data = self._files.get(path)
        return len(data) if data is not None else None


def load_web_evidence(
    evidence_dir: str | Path,
    config: AnalysisConfig,
    origin: str = "",
    exclude_dirs: Iterable[str | Path] = (),
) -> WebContext:
    """从**已落盘**的证据目录构造 :class:`WebContext`。只读文件、绝不联网。

    行为：递归遍历目录，按 :func:`is_text_evidence` 选文本证据；gzip 响应体有界解压；
    一律 ``errors="replace"`` 之前保留原始 bytes（解码交由各分析器按需做，与 APK 路径一致）。
    读失败与被跳过的超限文件**记入** ``ctx.load_errors``，不静默丢。

    Raises:
        FileNotFoundError: 目录不存在或不是目录（调用方应转成用户可读错误 + 非零退出）。
    """
    root = Path(evidence_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"网页证据目录不存在或不是目录：{root}")

    files: dict[str, bytes] = {}
    errors: list[str] = []
    total = 0
    excluded = {Path(path).resolve(strict=False) for path in exclude_dirs}

    evidence_files = sorted(_iter_files(root, errors, excluded))
    source_names: set[str] = set()
    for real in evidence_files:
        try:
            source_names.add(real.relative_to(root).as_posix())
        except ValueError:  # pragma: no cover — _iter_files 保证在 root 下
            continue

    for real in evidence_files:
        if len(files) >= MAX_EVIDENCE_FILES:
            errors.append(f"证据文件数超过上限 {MAX_EVIDENCE_FILES}，其余未读入")
            break
        try:
            rel = real.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover — _iter_files 保证在 root 下
            continue
        if not is_text_evidence(rel):
            continue

        try:
            size = real.stat().st_size
        except OSError as exc:
            errors.append(f"{rel}: 取文件大小失败（{type(exc).__name__}）")
            continue
        if size > MAX_EVIDENCE_BYTES:
            errors.append(f"{rel}: 超单份上限 {MAX_EVIDENCE_BYTES} 字节，未读入")
            continue
        if total + size > MAX_TOTAL_BYTES:
            errors.append(f"{rel}: 合计超上限 {MAX_TOTAL_BYTES} 字节，未读入")
            continue

        try:
            data = real.read_bytes()
        except OSError as exc:
            # 不静默跳过：读不出来是本次分析的实测缺口，必须让报告看得见。
            errors.append(f"{rel}: 读取失败（{type(exc).__name__}）")
            continue

        if _looks_gzip(data):
            plain = _gunzip_bounded(data)
            if plain is None:
                errors.append(f"{rel}: gzip 解压失败或超上限，未读入")
                continue
            data = plain

        # ★UTF-16/32 BOM 证据必须在入库前规范成 UTF-8：looks_binary 有意放行这类含 NUL 的文本，
        #   若原样入库，下游按 UTF-8 解出的是 ``<�h�t�m�l�>`` 这类不可读字节，
        #   全部正则失配却与"这份证据没线索"长得一样。解不干净则明确拒收并记入 load_errors。
        data, decode_error = normalize_text_bytes(data)
        if decode_error is not None:
            errors.append(f"{rel}: {decode_error}")
            continue

        # ★扩展名放行后仍须按内容复核：``.body`` / ``.headers`` 是抓包落盘的无语义命名，
        #   一份 PNG 截图完全可能就叫 ``resp.body``。判为二进制则不读入，且**如实记入
        #   load_errors**——静默跳过会让"这份证据没线索"与"这份证据没被扫"在报告里长得一样。
        if looks_binary(data):
            errors.append(f"{rel}: 内容为二进制（按扩展名收作文本证据），未读入")
            continue

        # gzip 的磁盘大小远小于解压后大小；上面的预检只能避免无谓读取，最终总量必须按
        # 实际载入内存的证据字节复核，否则多份合法压缩响应可以绕过 MAX_TOTAL_BYTES。
        if total + len(data) > MAX_TOTAL_BYTES:
            errors.append(f"{rel}: 解压后合计超上限 {MAX_TOTAL_BYTES} 字节，未读入")
            continue

        canonical = canonical_evidence_name(rel, data)
        key = WEB_PREFIX + canonical
        # ``resp.body``(HTML) 会规范成 ``resp.body.html``，可能与真实同名文件碰撞。
        # 绝不能 dict 覆盖静默丢证据；真实源名优先保留，别名确定性加序号。
        if key in files or (canonical != rel and canonical in source_names):
            stem, suffix = posixpath.splitext(canonical)
            index = 2
            while f"{WEB_PREFIX}{stem}.evidence-{index}{suffix}" in files:
                index += 1
            remapped = f"{stem}.evidence-{index}{suffix}"
            errors.append(f"{rel}: 规范名与现有证据冲突，已保留为 {remapped}（未丢失）")
            key = WEB_PREFIX + remapped
        files[key] = data
        total += len(data)

    logger.info(
        "[webctx] 载入网页证据：%d 份、合计 %d 字节、跳过/失败 %d 项（目录 %s）",
        len(files), total, len(errors), root,
    )
    return WebContext(
        config=config,
        files=files,
        origin=origin or root.name,
        source_dir=str(root),
        load_errors=errors,
    )


def _iter_files(root: Path, errors: list[str], excluded: set[Path] | None = None) -> list[Path]:
    """递归收集普通文件，**目录项**与**普通文件**两道硬边界都在物化之前施加。

    ★不跟随符号链接目录：证据目录可能来自不可信打包，避免跳出 root。链接**文件**也不读
    （同一理由：链接目标可以指到 root 外的任意路径）。

    ★为什么上限必须落在**发现数**而不只是读入数：调用方的 ``MAX_EVIDENCE_FILES`` 只数
    ``len(files)``（真正载入的文本证据）。一个塞了几十万个 ``.png`` / ``.bin`` 的目录，
    每个都被本函数收进 ``out``，却一个都不计入 ``len(files)`` —— 于是文件数上限形同没有，
    **遍历清单本身**（每项一个 Path 对象）就先把内存吃干。

    ★为什么还要 :data:`MAX_DISCOVERED_ENTRIES` 这道**目录项**边界：普通文件数那道只在"收下
    一个普通文件"时才生效，有三类输入整体绕过它 ——
      ①海量符号链接：每条只写 error、不增 ``len(out)``，计数与 ``errors`` 双双无界；
      ②海量空目录：一个普通文件都没有，遍历工作量却照样线性增长；
      ③单目录海量条目：旧实现用 ``os.walk``，它**先把该目录的 filenames 整份物化**，随后
        ``sorted()`` 再复制一份，两份列表都早于"文件数检查"存在。
    故改为自持栈 + ``os.scandir`` **流式**拉条目，逐条计入 budget，budget 一到立刻停止拉取：
    海量目录项在任何时刻都不会被整份读进内存。

    确定性：``scandir`` 的枚举顺序随文件系统而变，故每层**先按名排序再消费**。

    ★但"排序"本身**不足以**给出确定性，这里有一个曾经真实存在的缺陷：目录项 budget 若在
    某一层拉到一半时用尽，那一层进 ``batch`` 的就是一个**依枚举顺序而定的任意前缀**，事后
    再排序也只是把那个任意子集排了序 —— 同一份证据目录在两台机器上会保留**不同**的证据
    集合（一台留 ``a``/``b``，另一台留 ``a``/``c``），而两边的输出都长得像"正常截断"。
    取证结论因此不可复现，这比少读几份文件严重得多。

    故本函数在目录项 budget 用尽时**fail closed**：把该层已收集的 partial batch **整份丢弃**
    （一份都不采纳），并停止继续遍历。保留下来的集合于是只由"完整枚举过的那些目录"组成，
    与枚举顺序无关。内存仍有硬上限：``batch`` 最多 :data:`MAX_DISCOVERED_ENTRIES` 条，
    且 budget 一到立刻停止从 ``scandir`` 拉取，海量目录项从不会被整份物化。

    errors 也有硬上限（:data:`MAX_TRAVERSAL_ERRORS`）：超出后不再逐条记、改记一条如实汇总，
    否则 ``errors`` 就是下一个无界列表。截断一律写进 ``errors``，少扫了绝不与扫全了长得一样。
    """
    out: list[Path] = []
    excluded = excluded or set()
    file_truncated = False
    entry_truncated = False
    entries_seen = 0
    suppressed_errors = 0
    truncated_directory = "."

    def _record(message: str) -> None:
        """写一条遍历期 error，超上限只累计条数（避免 errors 自己无界增长）。"""
        nonlocal suppressed_errors
        if len(errors) < MAX_TRAVERSAL_ERRORS:
            errors.append(message)
        else:
            suppressed_errors += 1

    stack: list[Path] = [root]
    while stack and not file_truncated and not entry_truncated:
        current = stack.pop()
        # ★逐条拉、逐条计数：budget 用尽即 break，绝不先把整个目录的条目物化再检查。
        # 每项 ``(名字, 路径, 种类)``；种类 ∈ {"dir", "file", "link", "other"}。
        batch: list[tuple[str, Path, str]] = []
        directory_errors: list[str] = []
        directory_suppressed = 0

        def _record_directory(message: str) -> None:
            """暂存本目录错误；只有完整枚举后才允许提交到全局 errors。"""
            nonlocal directory_suppressed
            if len(directory_errors) < MAX_TRAVERSAL_ERRORS:
                directory_errors.append(message)
            else:
                directory_suppressed += 1

        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entries_seen >= MAX_DISCOVERED_ENTRIES:
                        entry_truncated = True
                        break
                    entries_seen += 1
                    try:
                        # ★follow_symlinks=False：判的是链接**本身**的类型，不看目标——
                        #   故指向目录的链接不会被当成目录递归进去（不跟随、不跳出 root）。
                        if entry.is_symlink():
                            kind = "link"
                        elif entry.is_dir(follow_symlinks=False):
                            kind = "dir"
                        elif entry.is_file(follow_symlinks=False):
                            kind = "file"
                        else:
                            kind = "other"  # fifo / socket / 设备节点——不是证据
                    except OSError as exc:
                        _record_directory(
                            f"{entry.name}: 取条目类型失败（{type(exc).__name__}），未读入"
                        )
                        continue
                    batch.append((entry.name, Path(entry.path), kind))
        except OSError as exc:
            _record(f"{current.name or root.name}: 目录遍历失败（{type(exc).__name__}）")
            continue

        if entry_truncated:
            # ★fail closed：这一层只枚举了一个**依枚举顺序而定的任意前缀**，采纳它会让
            #   "保留了哪几份证据"随文件系统枚举顺序而变（同一目录在两台机器上留下不同集合，
            #   而两边看起来都像正常截断）。整份丢弃，不采纳其中任何一条。
            try:
                truncated_directory = current.relative_to(root).as_posix() or "."
            except ValueError:
                truncated_directory = current.name or "."
            break

        # 目录已完整枚举，局部结果才原子提交。排序让多个类型错误的顺序不依赖 scandir。
        for message in sorted(directory_errors):
            _record(message)
        suppressed_errors += directory_suppressed

        dirs: list[Path] = []
        for name, path, kind in sorted(batch, key=lambda item: item[0]):
            if kind == "dir":
                if path.resolve(strict=False) in excluded:
                    continue
                dirs.append(path)
                continue
            if kind == "link":
                _record(f"{name}: 是符号链接，未读入")
                continue
            if kind != "file":
                continue
            if len(out) >= MAX_DISCOVERED_FILES:
                file_truncated = True
                break
            out.append(path)
        # 逆序压栈，配合 pop() 得到按名递增的确定性遍历顺序。
        stack.extend(reversed(dirs))

    if file_truncated:
        errors.append(
            f"证据目录内普通文件数超过遍历上限 {MAX_DISCOVERED_FILES}，其余未遍历（清单已截断）"
        )
    if entry_truncated:
        errors.append(
            f"{truncated_directory}: 证据目录内条目数超过遍历上限 {MAX_DISCOVERED_ENTRIES}"
            "（含子目录/符号链接），其余未遍历（清单已截断）"
        )
    if suppressed_errors:
        errors.append(f"遍历期另有 {suppressed_errors} 项跳过/失败未逐条记录（已达 error 上限）")
    return out


__all__ = [
    "WebContext",
    "load_web_evidence",
    "is_text_evidence",
    "WEB_PREFIX",
    "MAX_EVIDENCE_BYTES",
    "MAX_TOTAL_BYTES",
    "MAX_EVIDENCE_FILES",
    "MAX_DISCOVERED_FILES",
    "MAX_DISCOVERED_ENTRIES",
    "MAX_TRAVERSAL_ERRORS",
    "TEXT_EVIDENCE_SUFFIXES",
    "BINARY_EVIDENCE_SUFFIXES",
    "ALIAS_EVIDENCE_SUFFIXES",
    "canonical_evidence_name",
    "looks_binary",
]
