"""网页证据分析器（三个，均 ``requires=["web"]``）：内联配置 / 跳转链 / 请求配方。

数据源一律是 :class:`apkscan.core.webctx.WebContext` 已读入的**落盘证据**（``.html`` / ``.body`` /
``.js`` / ``.headers``）。★纯离线：本模块只读上下文里的字节，绝不联网、绝不抓取。

为什么这三个而不是复用现成分析器就够了：

- ``web_inline_config``：HTML 内联 ``<script>`` 里的 ``window.X = ...`` 配置**常不在**被哈希的 app JS
  里，只扫 ``.js`` 会整条漏掉。
- ``web_redirect_chain``：分发链的价值在**顺序**与跳数（实测某条链在末跳之前还有两跳、还按平台分流，
  那两跳是独立注册域、需各自单独核实）。既有分析器只会把这些域名混在一堆端点里、丢掉链形。
- ``web_request_recipe``：链路要求特定请求头（少了就拿不到真响应）——这是"怎么复现"的关键，
  不是又一个端点。

三者产出都走同一条出口（Endpoint 交 pipeline 统一富化建 Lead；链形/配方另记 Finding + meta），
不另建并行管线。

约束（项目铁律）：绝不抛异常给调用方（单源失败 try/except + logging）、绝不 print、全量 type hints。
★不可信输入：网页 body 是外部内容，snippet 一律截断后交既有转义通路（letters ``_md_safe`` /
HTML 模板自动转义），本模块不自行拼 HTML/Markdown。
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apkscan.analyzers._common import EndpointCollector, snippet_around, truncate
from apkscan.core import infra
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer
from apkscan.core.textutil import (
    host_from_url,
    host_is_private,
    ip_is_private,
    is_noise_bare_ip,
    parse_ipv4,
    valid_url_host,
)

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 通用上限（网页证据应很小；这些闸门防单份巨文件/超多文件拖垮分析）
# ---------------------------------------------------------------------------

#: 单份证据参与扫描的最大字符数（超出截断，并如实记 meta 截断标记）。
MAX_SCAN_CHARS = 4_000_000
#: 单个分析器扫描的最大文件数。
MAX_FILES = 500
#: 单条 snippet 截断长度。
SNIPPET_MAX = 200
#: 单类产出上限（防构造出的证据刷出上万条噪音）。
MAX_ITEMS = 200

#: Evidence.source 取值：网页证据是**静态落盘内容**，不是运行时观测。
#: ★绝不能用 ``runtime`` / ``runtime-pcap``：那两个是 ``OBSERVED_CONTACT_SOURCES``（"实连/确认 C2"
#: 徽标与归属运行时角色门的单一真源）。网页证据只证明"该值出现在这份落盘证据里"，不证明真接触。
EVIDENCE_SOURCE = "web"

_HTML_SUFFIXES: tuple[str, ...] = (".html", ".htm", ".body")
_SCRIPT_SUFFIXES: tuple[str, ...] = (".js", ".mjs", ".cjs")
_HEADER_SUFFIXES: tuple[str, ...] = (".headers", ".headers.txt")


# ---------------------------------------------------------------------------
# 共享读取
# ---------------------------------------------------------------------------


def _iter_text(
    ctx: "AnalysisContext",
    analyzer: str,
    suffixes: tuple[str, ...],
    result: AnalyzerResult,
) -> list[tuple[str, str]]:
    """读上下文里命中后缀的证据为文本。绝不抛；读失败/截断如实记 meta。

    编码一律 ``errors="replace"``：``.body`` 可能非 UTF-8，**不因解码失败丢整份证据**。
    """
    out: list[tuple[str, str]] = []
    try:
        paths = [p for p in ctx.list_files() if isinstance(p, str)]
    except Exception:
        logger.exception("[%s] 列举证据文件失败", analyzer)
        result.meta[f"{analyzer}_list_failed"] = True
        return out

    failed = 0
    truncated = False
    for path in sorted(paths):
        if len(out) >= MAX_FILES:
            result.meta[f"{analyzer}_files_truncated"] = True
            break
        if not path.lower().endswith(suffixes):
            continue
        try:
            data = ctx.read_file(path)
        except Exception:
            logger.exception("[%s] 读取证据失败：%s", analyzer, path)
            failed += 1
            continue
        if not isinstance(data, (bytes, bytearray)):
            if data is not None:
                failed += 1
            continue
        text = bytes(data).decode("utf-8", errors="replace")
        if len(text) > MAX_SCAN_CHARS:
            text = text[:MAX_SCAN_CHARS]
            truncated = True
        out.append((path, text))

    # 读失败必须成为**数据**而非只是一行日志：否则"扫了 1 份"与"扫全了"在报告里完全一样。
    if failed:
        result.meta[f"{analyzer}_read_failed"] = failed
    if truncated:
        result.meta[f"{analyzer}_content_truncated"] = True
    return out


def _add_endpoint(collector: EndpointCollector, raw: str, path: str, snippet: str) -> None:
    """把一个 URL / 域名收进端点表（形态校验后），标明文/私网 + 来源可信度档。非法形态静默丢。

    ★来源档（tier）必须在这里打：网页证据里混着第三方 vendor bundle，它们的常量
      不该与站点自身的配置同档。此前本函数只 ``add`` 不 ``mark_tier``，于是 web 侧
      整条链路都没有降噪机制——``leads`` 的 tier 降档判据形同虚设。
      ``raw_len`` 传 0 是有意的：网页证据的 snippet 已被截断，长度代表不了原字面量，
      拿它去判 bulk-string 会误判；这里只让**路径 glob** 那一条生效。

      ★``context="web"`` 同样是有意的、且是必须的：整张 glob 表的先验是「APK 内部路径」。
      网页语境下站点**自己的**业务代码几乎必然压缩过（``main.min.js``），资源路径又常含
      ``/dist/``——照搬 APK 的表会把涉诈站自有的后端域名整批降成待核，不发函、不进闭环、
      不做 ICP/WHOIS 富化，是漏报方向的误伤。判据分歧见 ``infra.domain_source_tier``。
    """
    value = raw.strip().strip("'\"")
    if not value or len(value) > 2048:
        return
    low = value.lower()
    evidence = Evidence(source=EVIDENCE_SOURCE, location=path, snippet=truncate(snippet, SNIPPET_MAX))
    tier = infra.domain_source_tier(path, 0, context="web")
    if low.startswith(("http://", "https://", "ws://", "wss://")):
        host = host_from_url(value)
        if not host or not valid_url_host(host):
            return
        collector.add(
            value,
            "url",
            evidence,
            is_cleartext=low.startswith(("http://", "ws://")),
            is_private=host_is_private(host),
        )
        collector.mark_tier(value, tier)
        # ★URL 的 host 必须另收一条 domain/ip 端点，否则**只以完整 URL 形态出现**的后端
        #   整类漏掉：URL 端点不直接产 Lead（见 leads 模块首段），也不进富化目标，于是形如
        #   ``window.config={api:"https://x.com/api"}`` 的真后端既不发函也不进闭环。
        #   与 endpoints.py 的 URL-host 通道同口径。
        _add_host_endpoint(collector, host, evidence, tier, bare=False)
        return
    # 裸域名 / 裸 IP：必须过既有形态校验（避免把 a.length / rect.top 之类代码当域名）。  # leak-scan: allow 注释里的 rect.top 是属性访问示例，非域名
    if valid_url_host(value) and "." in value:
        _add_host_endpoint(collector, value, evidence, tier, bare=True)


def _add_host_endpoint(
    collector: EndpointCollector, host: str, evidence: Evidence, tier: str, *, bare: bool
) -> None:
    """把一个 host 收成 domain 或 ip 端点（按形态分流），并标来源档。

    ★按形态分 kind、不一律当 domain：``kind`` 决定走哪套判据与文书模板——IP 走
      ``classify_ip`` + ASN/IDC 调证路径，域名走 ``classify_domain`` + ICP/WHOIS 注册人路径。
      把裸 IP 收成 domain，会拿域名模板去套一个 IP，且完全绕开 IP 侧的形态判据
      （公共解析器、低段位版本号、bogon 这些一个都不生效）。

    ``bare`` 区分来源语义，**IP 侧的过滤强度按它分档**（与 ``endpoints.py`` 同口径）：

    - ``bare=True``（裸四段字面）：过 ``is_noise_bare_ip``——末段为 0、bogon、占位/版本号形态
      在裸字面里绝大多数不是地址。
    - ``bare=False``（来自完整 URL 的 host）：**不过**那条形态判据。写在 URL 里的 host 是
      **强地址性证据**——``http://<末段为0的IP>/x`` 里那个值就是当地址用的，按"疑似网络地址"
      删掉是纯漏报。私网 URL 也留证（标 ``is_private``），它至少是运营入口。
      ``is_noise_bare_ip`` 的 docstring 本就写明「仅作用于裸 IP」。
    """
    ip_obj = parse_ipv4(host)
    if ip_obj is not None:
        if bare and is_noise_bare_ip(host):
            return
        collector.add(host, "ip", evidence, is_private=ip_is_private(ip_obj))
    else:
        collector.add(host, "domain", evidence, is_private=host_is_private(host))
    collector.mark_tier(host, tier)


# ---------------------------------------------------------------------------
# 分析器 1：HTML 内联 <script> 配置
# ---------------------------------------------------------------------------

# 内联 <script> 块（非贪婪；不含 src= 的外链脚本体本就为空，无需另判）。
_SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)

# window.X = "..." / globalThis.X = '...'（值限单行、有界长度，防灾难性回溯）。
_WINDOW_ASSIGN_RE = re.compile(
    r"""(?:window|globalThis|self)\.([A-Za-z_$][\w$]{0,64})\s*=\s*(['"])([^'"\r\n]{1,2048})\2"""
)

# var/let/const X = "..."
_VAR_ASSIGN_RE = re.compile(
    r"""\b(?:var|let|const)\s+([A-Za-z_$][\w$]{0,64})\s*=\s*(['"])([^'"\r\n]{1,2048})\2"""
)

# JSON 风格键值："apiUrl": "https://..."
_JSON_ASSIGN_RE = re.compile(
    r"""["']([A-Za-z_$][\w$-]{0,64})["']\s*:\s*(['"])([^'"\r\n]{1,2048})\2"""
)

#: 值里含这些才算"配置"（否则 `var a = "1"` 这类噪音会淹掉产出）。
_CONFIG_VALUE_HINTS: tuple[str, ...] = ("http://", "https://", "ws://", "wss://", "//")

#: 键名含这些词 → 即便值不是 URL 也当配置收（域名/主机/网关这类裸值）。
_CONFIG_KEY_HINTS: frozenset[str] = frozenset(
    {
        "api", "apiurl", "apihost", "apibase", "baseurl", "base_url", "host", "hosts",
        "domain", "domains", "server", "servers", "gateway", "endpoint", "endpoints",
        "upload", "download", "cdn", "ws", "wss", "socket", "im", "appid", "appkey",
        "channel", "agent", "line", "lines", "backup", "config", "configurl",
    }
)


@dataclass
class _ConfigHit:
    """一条内联配置命中。"""

    key: str
    value: str
    path: str
    snippet: str


class WebInlineConfigAnalyzer(BaseAnalyzer):
    """抽 HTML 内联 ``<script>`` 里的配置赋值（``window.X = ...`` / ``var X = "https://..."``）。

    ★为什么单列一个分析器：这类配置常**不在**被哈希的 app JS 里，只扫 ``.js`` 会整条漏掉。
    """

    name: str = "web_inline_config"
    requires: list[str] = ["web"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        collector = EndpointCollector()
        hits: list[_ConfigHit] = []

        for path, text in _iter_text(ctx, self.name, _HTML_SUFFIXES, result):
            try:
                for block in _SCRIPT_BLOCK_RE.finditer(text):
                    body = block.group(1)
                    if not body.strip():
                        continue
                    hits.extend(self._scan_block(body, path))
            except Exception:
                logger.exception("[%s] 扫描内联脚本失败：%s", self.name, path)

        seen: set[tuple[str, str]] = set()
        for hit in hits[:MAX_ITEMS]:
            key = (hit.key, hit.value)
            if key in seen:
                continue
            seen.add(key)
            _add_endpoint(collector, hit.value, hit.path, hit.snippet)
            result.leads.append(self._lead(hit))

        result.endpoints = collector.endpoints({"url": 0, "domain": 1, "ip": 2})
        if hits:
            result.meta["web_inline_config_count"] = len(seen)
        logger.info("[%s] 内联配置命中 %d 条、端点 %d 个", self.name, len(seen), len(result.endpoints))
        return result

    def _scan_block(self, body: str, path: str) -> list[_ConfigHit]:
        out: list[_ConfigHit] = []
        for regex in (_WINDOW_ASSIGN_RE, _VAR_ASSIGN_RE, _JSON_ASSIGN_RE):
            for m in regex.finditer(body):
                key = m.group(1)
                value = m.group(3)
                if not self._is_config(key, value):
                    continue
                out.append(
                    _ConfigHit(
                        key=key,
                        value=value,
                        path=path,
                        snippet=snippet_around(body, m, radius=60),
                    )
                )
        return out

    @staticmethod
    def _is_config(key: str, value: str) -> bool:
        """值像端点，或键名像配置键且值含点分主机 —— 否则丢（压噪音）。"""
        low_val = value.lower()
        if low_val.startswith(_CONFIG_VALUE_HINTS):
            return True
        if key.lower().replace("_", "") in _CONFIG_KEY_HINTS and "." in value:
            return True
        return False

    def _lead(self, hit: _ConfigHit) -> Lead:
        return Lead(
            category=LeadCategory.CONFIG_KEY,
            value=f"{hit.key}={truncate(hit.value, 200)}",
            subject=None,  # 归属未知：不据网页内容推断运营者
            where_to_request="按该配置指向的域名/IP 另行落地（见本报告端点线索）",
            evidence_to_obtain=["该配置指向的服务器归属与访问日志"],
            notes=(
                "来自网页证据的 HTML 内联脚本配置（静态落盘内容，非运行时观测）。"
                "内联配置常不在 app JS 里，是易漏面。"
            ),
            confidence=Confidence.MEDIUM,
            source_refs=[
                Evidence(
                    source=EVIDENCE_SOURCE,
                    location=hit.path,
                    snippet=truncate(hit.snippet, SNIPPET_MAX),
                )
            ],
        )


# ---------------------------------------------------------------------------
# 分析器 2：跳转链（有序）
# ---------------------------------------------------------------------------

# location = "..." / window.location.href = "..."
_LOCATION_ASSIGN_RE = re.compile(
    r"""(?:window\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*(['"])([^'"\r\n]{1,2048})\1"""
)

# location.replace("...") / location.assign("...")
_LOCATION_CALL_RE = re.compile(
    r"""location\s*\.\s*(?:replace|assign)\s*\(\s*(['"])([^'"\r\n]{1,2048})\1"""
)

# <meta http-equiv="refresh" content="0;url=https://...">
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]*?http-equiv\s*=\s*['"]?refresh['"]?[^>]*?>""",
    re.IGNORECASE,
)
_META_URL_RE = re.compile(r"""url\s*=\s*['"]?([^'"\s>;]{1,2048})""", re.IGNORECASE)

# 响应头里的 Location:（.headers 落盘证据；行首匹配）
_HEADER_LOCATION_RE = re.compile(r"""^\s*location\s*:\s*(\S{1,2048})\s*$""", re.IGNORECASE | re.MULTILINE)


@dataclass
class _Hop:
    """跳转链一跳。``order`` 是在证据内的出现次序（链形的核心，不能丢）。"""

    order: int
    target: str
    mechanism: str
    path: str
    snippet: str


class WebRedirectChainAnalyzer(BaseAnalyzer):
    """抽**有序**跳转链：``location=`` / ``location.replace|assign`` / ``<meta refresh>`` / 响应头 ``Location:``。

    ★顺序与跳数是本分析器的产出本体：实测某条分发链在末跳之前还有两跳、还按平台分流（iOS 一条、
      Android 中转一条），那两跳是独立注册域、需各自单独核实。把它们混进一堆端点里就等于丢掉链形。
    """

    name: str = "web_redirect_chain"
    requires: list[str] = ["web"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        collector = EndpointCollector()

        suffixes = _HTML_SUFFIXES + _SCRIPT_SUFFIXES + _HEADER_SUFFIXES
        hops: list[_Hop] = []
        for path, text in _iter_text(ctx, self.name, suffixes, result):
            try:
                hops.extend(self._scan(text, path))
            except Exception:
                logger.exception("[%s] 扫描跳转失败：%s", self.name, path)

        # 稳定排序：先按证据路径，再按出现位置 —— 同一份证据内的先后即链内先后。
        hops.sort(key=lambda h: (h.path, h.order))
        hops = hops[:MAX_ITEMS]

        grouped: dict[str, list[_Hop]] = {}
        for hop in hops:
            _add_endpoint(collector, hop.target, hop.path, hop.snippet)
            grouped.setdefault(hop.path, []).append(hop)

        # 不把互不相关的证据文件首尾相接成一条“实测链”。静态文件之间没有因果边；
        # 每份证据只保留自身的出现顺序，跨文件关联留给运行时观测或人工核验。
        chains: list[dict[str, object]] = []
        for chain_id, (path, path_hops) in enumerate(grouped.items(), start=1):
            chains.append(
                {
                    "chain_id": chain_id,
                    "location": path,
                    "hops": [
                        {
                            "step": idx,
                            "target": truncate(hop.target, 500),
                            "mechanism": hop.mechanism,
                            "location": hop.path,
                        }
                        for idx, hop in enumerate(path_hops, start=1)
                    ],
                }
            )

        result.endpoints = collector.endpoints({"url": 0, "domain": 1, "ip": 2})
        if chains:
            result.meta["web_redirect_chain"] = chains
            result.findings.append(self._finding(chains, hops))
        logger.info(
            "[%s] 跳转候选 %d 个、证据组 %d 个、端点 %d 个",
            self.name,
            len(hops),
            len(chains),
            len(result.endpoints),
        )
        return result

    def _scan(self, text: str, path: str) -> list[_Hop]:
        out: list[_Hop] = []
        for m in _LOCATION_ASSIGN_RE.finditer(text):
            out.append(self._hop(m.start(), m.group(2), "location-assign", path, text, m))
        for m in _LOCATION_CALL_RE.finditer(text):
            out.append(self._hop(m.start(), m.group(2), "location-call", path, text, m))
        for m in _META_REFRESH_RE.finditer(text):
            url = _META_URL_RE.search(m.group(0))
            if url is not None:
                out.append(self._hop(m.start(), url.group(1), "meta-refresh", path, text, m))
        for m in _HEADER_LOCATION_RE.finditer(text):
            out.append(self._hop(m.start(), m.group(1), "header-location", path, text, m))
        return out

    @staticmethod
    def _hop(
        order: int, target: str, mechanism: str, path: str, text: str, m: re.Match
    ) -> _Hop:
        return _Hop(
            order=order,
            target=target.strip(),
            mechanism=mechanism,
            path=path,
            snippet=snippet_around(text, m, radius=60),
        )

    def _finding(self, chains: list[dict[str, object]], hops: list[_Hop]) -> Finding:
        sections: list[str] = []
        for chain in chains:
            chain_hops = chain["hops"]
            assert isinstance(chain_hops, list)
            steps = " → ".join(
                f"[{c['step']}] {truncate(str(c['target']), 120)}"
                for c in chain_hops
                if isinstance(c, dict)
            )
            sections.append(f"- {chain['location']}：{steps}")
        sequences = "\n".join(sections)
        return Finding(
            id="WEB-REDIRECT-CHAIN",
            title=f"网页证据含 {len(hops)} 个静态跳转候选（{len(chains)} 个证据组）",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="distribution",
            description=(
                f"按每份证据内出现次序分组的跳转候选：\n{sequences}\n\n"
                "★候选中的每一跳都可能是**独立注册**的域名，需各自单独核实（实测有分发链在末跳之前"
                "还有两跳、且按平台分流：iOS 一条、Android 走中转一条）。\n"
                "★这些分组来自**静态落盘证据**的文本形态（脚本赋值 / meta refresh / 响应头）；"
                "不同文件之间未建立因果关系，同一文件内也可能存在互斥条件分支，均不代表运行时真的按此顺序"
                "跳转完。真实走向须由运行时观测确认。"
            ),
            recommendation=(
                "按链上每一跳分别落地（注册人/解析历史/承载 IP），不要只查最后一跳的落地页；"
                "如需确认真实走向，转运行时观测（按不同 UA/平台各跑一次）。"
            ),
            evidences=[
                Evidence(
                    source=EVIDENCE_SOURCE,
                    location=hop.path,
                    snippet=truncate(hop.snippet, SNIPPET_MAX),
                )
                for hop in hops[:20]
            ],
        )


# ---------------------------------------------------------------------------
# 分析器 3：请求配方（特定请求头）
# ---------------------------------------------------------------------------

_BASE64_LITERAL_RE = re.compile(r"""(?<![\w+/=])([A-Za-z0-9+/]{16,512}={0,2})(?![\w+/=])""")

#: base64 命中点附近出现这些词，才认为解出的串与"请求头/请求构造"有关。
_REQUEST_CONTEXT_WORDS: tuple[str, ...] = (
    "header", "headers", "setrequestheader", "fetch", "xmlhttprequest", "xhr",
    "ajax", "axios", "authorization", "token", "referer", "referrer",
    "user-agent", "useragent", "content-type", "cookie", "x-requested-with",
)

#: 上下文窗口（字符）：命中点前后各取这么多字符判语境。
_CONTEXT_RADIUS = 200

#: 解出串必须是可打印 ASCII 且长度在此区间（太短没信息、太长多为二进制/图片载荷）。
_MIN_PLAIN = 4
_MAX_PLAIN = 200


@dataclass
class _Recipe:
    """一条请求配方命中：base64 字面量 → 解出的可打印短串 + 语境词。"""

    decoded: str
    context_word: str
    path: str
    snippet: str


class WebRequestRecipeAnalyzer(BaseAnalyzer):
    """base64 字面量解出可打印 ASCII 短串、且出现在请求头/请求构造语境附近 → 产"链路要求特定请求头"。

    ★为什么重要：这类链路少了指定头就拿不到真响应（返回空/伪装页），"怎么复现"是取证的一部分。
    ★判据是**启发式**：confidence 固定 LOW，措辞只说"疑似要求"，不写成已确认的协议规格。
    """

    name: str = "web_request_recipe"
    requires: list[str] = ["web"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        suffixes = _HTML_SUFFIXES + _SCRIPT_SUFFIXES
        recipes: list[_Recipe] = []

        for path, text in _iter_text(ctx, self.name, suffixes, result):
            try:
                recipes.extend(self._scan(text, path))
            except Exception:
                logger.exception("[%s] 扫描请求配方失败：%s", self.name, path)

        seen: set[str] = set()
        unique: list[_Recipe] = []
        for r in recipes:
            if r.decoded in seen:
                continue
            seen.add(r.decoded)
            unique.append(r)
            if len(unique) >= MAX_ITEMS:
                break

        if unique:
            result.meta["web_request_recipe"] = [
                {"decoded": truncate(r.decoded, 200), "context": r.context_word, "location": r.path}
                for r in unique
            ]
            result.findings.append(self._finding(unique))
        logger.info("[%s] 请求配方命中 %d 条", self.name, len(unique))
        return result

    def _scan(self, text: str, path: str) -> list[_Recipe]:
        out: list[_Recipe] = []
        low = text.lower()
        for m in _BASE64_LITERAL_RE.finditer(text):
            token = m.group(1)
            if len(token) % 4 != 0:
                continue
            plain = self._decode(token)
            if plain is None:
                continue
            start = max(0, m.start() - _CONTEXT_RADIUS)
            end = min(len(text), m.end() + _CONTEXT_RADIUS)
            window = low[start:end]
            word = next((w for w in _REQUEST_CONTEXT_WORDS if w in window), None)
            if word is None:
                continue
            out.append(
                _Recipe(
                    decoded=plain,
                    context_word=word,
                    path=path,
                    snippet=snippet_around(text, m, radius=60),
                )
            )
        return out

    @staticmethod
    def _decode(token: str) -> str | None:
        """解 base64 → 要求是可打印 ASCII 短串；否则 None（二进制/图片载荷不是配方）。"""
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            return None
        if not (_MIN_PLAIN <= len(raw) <= _MAX_PLAIN):
            return None
        try:
            plain = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(32 <= ord(c) <= 126 for c in plain):
            return None
        # 至少含一个字母：纯符号/纯数字解码结果多是巧合（base64 误判）。
        if not any(c.isalpha() for c in plain):
            return None
        return plain

    def _finding(self, recipes: list[_Recipe]) -> Finding:
        listed = "\n".join(
            f"- `{truncate(r.decoded, 120)}`（语境词：{r.context_word}，位置：{r.path}）"
            for r in recipes[:20]
        )
        return Finding(
            id="WEB-REQUEST-RECIPE",
            title=f"网页证据疑似要求特定请求头（{len(recipes)} 项）",
            severity=Severity.LOW,
            confidence=Confidence.LOW,  # 启发式：base64 + 语境词共现，非协议规格
            category="request_recipe",
            description=(
                "以下 base64 字面量解出可打印短串，且出现在请求头 / 请求构造语境附近，"
                f"疑似该链路要求随请求带上特定头部：\n{listed}\n\n"
                "★启发式判据（base64 与语境词共现），**不是**已确认的协议规格：混淆过的普通"
                "字符串常量亦可能命中。"
            ),
            recommendation=(
                "复现该链路时按上列头部构造请求（缺头常返回空响应或伪装页，会被读成'链路已失效'）；"
                "以运行时实际请求为准核对本判据。"
            ),
            evidences=[
                Evidence(
                    source=EVIDENCE_SOURCE,
                    location=r.path,
                    snippet=truncate(r.snippet, SNIPPET_MAX),
                )
                for r in recipes[:20]
            ],
        )


__all__ = [
    "WebInlineConfigAnalyzer",
    "WebRedirectChainAnalyzer",
    "WebRequestRecipeAnalyzer",
    "EVIDENCE_SOURCE",
]
