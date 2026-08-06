"""提交前泄漏扫描：在**新增内容**里查不该进公开仓库的字面值。

本模块是**仓库卫生护栏**，不参与样本分析流水线。它防的是一类**不可撤销**的错误——
一旦真实地址/密钥推上远端，改写历史也删不掉缓存副本，唯一可靠的办法是源头不写进去。

设计要点
--------

1. **只看新增行**。判据施加在 unified diff 的 ``+`` 行上，而不是整棵工作树。
   仓库里已有大量正常文字、合成夹具与历史记录；对全树施压只会产生海量误报，
   而误报多到一定程度，人就会习惯性加豁免，护栏随之失效。
   （:func:`scan_paths` 提供全树审计模式，但那是**人工盘点**用的，不做门禁。）

2. **判据分两档**。``ip`` / ``secret`` 判据精确，默认阻断；``domain`` / ``context``
   判据天生噪音大（合成域名、属性访问 ``logger.info``、中文说明文字都会撞），
   默认只报告不阻断，用 ``strict=True`` 升级为阻断。
   两档都**如实产出 finding**，差别只在是否让门禁变红——先观察一轮再收紧。

3. **豁免必须写理由，且不许批量按**。行内注释 ``leak-scan: allow <理由>`` 放行整行。
   只写 ``leak-scan: allow`` 而不给理由本身就是一条 finding：没有理由的豁免等于没有护栏。
   理由**成不成立**机器判不了，能判的是动作形态：同一条理由被复制到大量新增行
   （见 :data:`_BULK_EXEMPTION_THRESHOLD`）即判 ``bulk_exemption``——那是"报了几十条阻断，
   于是用脚本把同一句话贴满每一行"的形态，与逐条豁免必须区别对待。

4. **判据可命名、可解释**。每条 finding 都带 ``rule`` 与 ``detail``，说明为什么判它，
   而不是给一个不可复核的分数。

已知盲点（有意接受，写在此处以便复核）
------------------------------------

- IPv4 判据会跳过若干 X.509/PKIX **OID 弧前缀**（见 :data:`OID_ARC_PREFIXES`）：
  ``2.5.4.3`` / ``1.3.6.1`` 这类 OID 与合法 IPv4 字面同形，不跳过则证书解析代码
  永远误报。代价是这几个真实网段里的地址查不出来，须靠人工复核兜底。
- ``domain`` 判据用的是**常见 TLD 白名单**，不是完整 IANA 表；名单外的 TLD 查不出来。
  ``info`` 有意不在名单里——仓库里 ``logger.info`` / ``severity.info`` 数以百计，
  收进来会把这条判据淹掉。
"""

from __future__ import annotations

import ipaddress
import io
import logging
import re
import token
import tokenize
from dataclasses import dataclass
from pathlib import Path

from apkscan.network.fingerprints import (
    AUTHORITATIVE_DNS_HOSTS,
    KNOWN_INTERCEPT_IPS,
    PUBLIC_DNS_RESOLVERS,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ALLOWED_DOMAINS",
    "ALLOWED_DOMAIN_SUFFIXES",
    "BLOCKING_RULES",
    "CONTEXT_TERMS",
    "Finding",
    "OID_ARC_PREFIXES",
    "RESERVED_DOC_NETWORKS",
    "RULES",
    "blocking",
    "expand_paths",
    "format_findings",
    "iter_added_lines",
    "iter_exemptions",
    "scan_diff",
    "scan_paths",
    "scan_text",
    "tracked_files",
]


# ---------------------------------------------------------------------------
# 判据标识
# ---------------------------------------------------------------------------

#: 全部判据名（稳定标识，进 finding.rule / CLI 输出 / 测试断言）。
RULES: tuple[str, ...] = (
    "ip", "secret", "domain", "context", "name", "exemption", "bulk_exemption",
)

#: 默认阻断的判据。``ip`` / ``secret`` 判据精确，误报可控，直接当门禁；
#: ``domain`` / ``context`` / ``name`` 噪音大，默认只报告（``strict=True`` 时全部阻断）。
#: ``exemption``（豁免没写理由）与 ``bulk_exemption``（同一条理由被复制到大量新增行）恒阻断：
#: 二者都是护栏**自身**的完整性检查，不允许静默削弱。
BLOCKING_RULES: frozenset[str] = frozenset({"ip", "secret", "exemption", "bulk_exemption"})

#: 一次改动里，同一条豁免理由最多可出现在多少个新增行上。
#:
#: 为什么要有这条：豁免只校验"有没有写理由"，不校验理由**成不成立**——写一句听着合理的话
#: 就能把该行的全部判据关掉。真实发生过的形态是：门禁报了几十条阻断，于是用脚本把**同一句**
#: 理由批量贴到每一行，再跑就绿了。那句理由是假的，而门禁看不出批量按掉与逐条豁免的区别。
#:
#: 阈值取 20 的由来：本仓历史上一次改动里合法新增的同理由豁免最多 17 条（一批公共解析器
#: 名单夹具，判据要求全球可路由字面、换合成值即失去被测形态）；而那次批量按掉护栏是 30 条以上。
#: 取 20 让前者照常通过、后者必红。数值可调，但**调高前请先确认那批豁免逐条都成立**。
#:
#: ★只在**增量**（diff）模式下判：全树模式看到的是历史累积（单文件已有 45 条同理由的合法
#:   夹具），对它施压只会逼人把理由改花，护栏反而更弱。
_BULK_EXEMPTION_THRESHOLD = 20


@dataclass(frozen=True)
class Finding:
    """一条泄漏嫌疑。``rule`` 说明命中哪条判据，``detail`` 说明为什么判它。"""

    rule: str
    path: str
    line_no: int
    value: str
    detail: str

    @property
    def blocking(self) -> bool:
        """本条在**默认**档下是否阻断（``strict`` 下所有 finding 都阻断）。"""
        return self.rule in BLOCKING_RULES


# ---------------------------------------------------------------------------
# 豁免
# ---------------------------------------------------------------------------

#: 行内豁免：``leak-scan: allow <理由>``。理由必须非空——无理由的豁免等于没有护栏，
#: 故单独产一条 ``exemption`` finding（且恒阻断），而不是静默放行。
_EXEMPT_RE = re.compile(r"leak-scan:\s*allow(?P<reason>[^\r\n]*)")


def _exemption(line: str) -> tuple[bool, str | None]:
    """返回 ``(是否出现豁免标记, 理由)``；理由为 None 表示标记在但没写理由。"""
    match = _EXEMPT_RE.search(line)
    if match is None:
        return False, None
    reason = match.group("reason").strip(" \t:-—#\"'")
    return True, reason or None


# ---------------------------------------------------------------------------
# 判据 1：IP 字面
# ---------------------------------------------------------------------------

#: 文档/测试保留段。测试夹具**只能**用这些段（RFC 5737 / RFC 3849 + 私网 / 回环 / 链路本地）。
#: 说明用；实际判定走 ``ipaddress`` 的 ``is_global``，它已覆盖这些段与全部私有/保留段。
RESERVED_DOC_NETWORKS: tuple[str, ...] = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",
)

#: 与合法 IPv4 字面同形的 X.509 / PKIX OID 弧前缀。见模块文档「已知盲点」。
OID_ARC_PREFIXES: tuple[str, ...] = (
    "0.9.",
    "1.2.840.",
    "1.3.6.",
    "1.3.14.",
    "1.3.36.",
    "1.3.101.",
    "1.3.132.",
    "2.5.4.",
    "2.5.29.",
)

def _rule_noise_ips() -> frozenset[str]:
    """读 ``rules/endpoints.yaml`` 的 ``noise_ips``（公认占位 IP + 被误当 IP 的版本号串）。

    ★复用仓库既有判断、不另立一份名单：那张表已经把「``1.2.3.4`` 是占位」「``13.3.3.7``
      其实是 SDK 版本号」这些结论写下来了，本护栏再抄一遍必然漂移。读不到就退化为空集
      （只影响误报多少，不影响正确性）。
    """
    try:
        from apkscan.core.registry import load_rules

        data = load_rules("endpoints")
        values = data.get("noise_ips") if isinstance(data, dict) else None
        if not isinstance(values, list):
            return frozenset()
        return frozenset(v.strip() for v in values if isinstance(v, str) and v.strip())
    except Exception:  # noqa: BLE001 — 护栏读不到规则也要能跑（退化为多报几条，不静默漏）
        logger.warning("[leakscan] 读不到 rules/endpoints.yaml 的 noise_ips，占位 IP 将被误报")
        return frozenset()


#: 公知基础设施 / 占位地址：公共递归解析器 + 托管商权威 NS + 已知拦截节点 + 规则表里的
#: 占位与版本号串。四份来源全部**复用**既有名单（``network.fingerprints`` 与
#: ``rules/endpoints.yaml``），不另立一份——两份名单一定会漂移。这些地址写进代码是
#: **功能需要**，不是泄漏。
_INFRA_IPS: frozenset[str] = (
    PUBLIC_DNS_RESOLVERS | AUTHORITATIVE_DNS_HOSTS | KNOWN_INTERCEPT_IPS | _rule_noise_ips()
)

#: 前后不许接 ``\w`` 或 ``.``：既排掉版本号/OID 这类更长的点分序列（``1.3.101.112.1``
#: 整体不产生匹配），也排掉 ``sha1.2.3.4`` 这类嵌在标识符里的巧合。
_IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")

#: IPv6 需要至少两个 ``:``；随后交给 ``ipaddress`` 做真正的合法性判定。
#: 前后同样不许接 ``\w`` / ``:`` / ``.``，避免咬进 ``host:port:extra`` 或时间戳。
_IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z]+)?)(?![\w:.])")


def _ipv4_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _IPV4_RE.finditer(line):
        raw = match.group(1)
        if raw.startswith(OID_ARC_PREFIXES):
            continue  # OID 弧，不是地址（见模块文档「已知盲点」）
        try:
            addr = ipaddress.IPv4Address(raw)
        except ValueError:
            continue  # 某段 >255，本就不是 IPv4
        if not addr.is_global:
            continue  # 文档保留段 / 私网 / 回环 / 链路本地 —— 允许
        if raw in _INFRA_IPS:
            continue  # 公共解析器 / 拦截节点名单，写进代码是功能需要
        out.append((raw, "公网 IPv4 字面；测试与文档只能用保留段 " + "、".join(RESERVED_DOC_NETWORKS)))
    return out


def _ipv6_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _IPV6_RE.finditer(line):
        raw = match.group(1)
        if raw.count(":") < 2:
            continue
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        if not addr.is_global:
            continue
        mapped = addr.ipv4_mapped
        if mapped is not None and (not mapped.is_global or str(mapped) in _INFRA_IPS):
            continue
        if addr.compressed in _INFRA_IPS:
            continue
        out.append((raw, "公网 IPv6 字面；测试与文档只能用保留段 2001:db8::/32"))
    return out


# ---------------------------------------------------------------------------
# 判据 2：疑似密钥
# ---------------------------------------------------------------------------

#: ``key = "…"`` 形态的硬编码凭据。只认赋值/键值语法（``=`` 或 ``:``），
#: 故 ``os.environ.get("FXAPK_FOFA_KEY")`` 这类**读环境变量**的写法不会命中。
_SECRET_RE = re.compile(
    r"""(?ix)
    (?<![a-z0-9_])
    (?P<name>(?:[a-z0-9]+[_-])*
       (?:api[_-]?key|apikey|access[_-]?key|secret|token
          |password|passwd|pwd|credential|bearer|key))
    \s*[:=]\s*
    (?:(?P<wrapper>[A-Za-z0-9_.\-]{1,24})\()?
    (?P<quote>["'])
    (?P<value>[A-Za-z0-9_\-./+]{12,})
    (?P=quote)
    """
)

#: 从环境读取的包裹函数——**这是唯一的豁免依据**。
#:
#: ★不要改回"按值的长相豁免"（如"全大写下划线就当变量名"）：扫描器无法从
#:   字符串长相分辨它是环境变量索引还是硬编码值，形如 ``REAL_SECRET_VALUE_7Q9K``
#:   的真凭据会被整类放过。判断必须落在**语法位置**上。
_ENV_READER_RE = re.compile(r"(?i)(?:^|\.)(?:environ\.get|getenv)\Z")
# ★两处覆盖面说明：
#   - name 含裸 ``key``：凭据未必以 api_key/secret_key 这类复合名出现。
#     ``(?<![a-z0-9_])`` 是词首边界，挡住 monkey / hotkey / _key_of 这类。
#   - 允许值被一层函数包住（``key=SomeCodec("…")``）：赋值右侧不一定紧跟引号。
#   ★不收 ``iv`` / ``mask``：加密测试向量的固定 IV、协议位掩码都是合规写法，
#     收进来误伤远大于收益。

#: 明显占位值：命中即不算泄漏。真实凭据不会自称 synthetic/placeholder。
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "synthetic",
    "example",
    "placeholder",
    "dummy",
    "fake",
    "sample",
    "redacted",
    "changeme",
    "change-me",
    "your",
    "todo",
    "xxxx",
    "deadbeef",
    "notreal",
    "not-real",
    "invalid",
    "unset",
    "<",
)

#: **标识符形态**的值：枚举成员、Finding ID、字段名、meta 键名长这样，不是凭据。
#:   ``DEX_TRUNCATED_META_KEY = "dex_truncated_meta"``
#:   ``RUNTIME_CREDENTIAL = "RUNTIME_CREDENTIAL"``
#:   ``FINDING_SECRET = "JS-HARDCODED-SECRET"``
#:
#: 两种收：全小写分段（可含数字），或全大写分段且**每段纯字母**。
#:
#: ★判据落在**值**上而不是常量名上：``API_KEY = "<真凭据>"`` 仍须被拦，
#:   所以不能按"名字全大写就当常量定义"放行。
#: ★大写侧要求每段纯字母，正是为了把 ``REAL_SECRET_VALUE_7Q9K`` 这类留在拦截面内：
#:   它有 ``7Q9K`` 这样的字母数字混合段，是随机凭据的特征，而枚举名不会长这样。
_IDENT_VALUE_RE = re.compile(
    r"(?:[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+|[A-Z]+(?:[_-][A-Z]+)+)\Z"
)

#: 连续序列片段：出现即说明这串是人手敲的占位（``0123456789abcdef…``），不是随机凭据。
_SEQUENTIAL_RUNS: tuple[str, ...] = (
    "0123456789",
    "abcdefgh",
    "abcdef012",
    "123456789",
    "qwerty",
)

def _has_repeated_block(value: str) -> bool:
    """整串是否为某个子串的整数次重复（``0123456789abcdef`` × 2 这类手敲占位）。"""
    n = len(value)
    for size in range(1, n // 2 + 1):
        if n % size == 0 and value == value[:size] * (n // size):
            return True
    return False


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    if any(run in low for run in _SEQUENTIAL_RUNS):
        return True
    if _has_repeated_block(value):
        return True
    if _IDENT_VALUE_RE.match(value):
        return True
    stripped = low.strip("-_./+")
    return len(set(stripped)) <= 2  # "aaaaaaaaaaaa" / "000000000000" 之类


def _secret_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _SECRET_RE.finditer(line):
        # 值裹在环境读取调用里（``os.environ.get("X")``）＝这是变量名不是值，放行。
        # 只认这一种语法位置，不看值长什么样。
        if _ENV_READER_RE.search(match.group("wrapper") or ""):
            continue
        value = match.group("value")
        if _looks_placeholder(value):
            continue
        name = match.group("name")
        out.append((
            f"{name}=<{len(value)} 字符>",
            f"疑似硬编码凭据（{name}）；凭据一律走环境变量 / .env，测试请用明显无效的占位值",
        ))
    return out


# ---------------------------------------------------------------------------
# 判据 3：域名字面
# ---------------------------------------------------------------------------

#: 保留 TLD（RFC 2606 / RFC 6761）——测试与文档的合法取值。
_RESERVED_TLDS: frozenset[str] = frozenset({"test", "invalid", "example", "localhost", "local"})

#: 允许的具体域名。``example.com`` 三兄弟 + 各 API 提供方官方域：
#: 后者写进富化器源码是**功能需要**，若被自家扫描器拦下，护栏就没法用了。
ALLOWED_DOMAINS: frozenset[str] = frozenset({
    "example.com",
    "example.net",
    "example.org",
    # OSINT / 资产库 / 注册数据提供方
    "abuseipdb.com",
    "censys.io",
    "crt.sh",
    "daydaymap.com",
    "fofa.info",
    "hunter.how",
    "hunter.qianxin.com",
    "ip-api.com",
    "ipinfo.io",
    "otx.alienvault.com",
    "quake.360.net",
    "rdap.org",
    "ripe.net",
    "shodan.io",
    "stat.ripe.net",
    "urlscan.io",
    "virustotal.com",
    "zoomeye.org",
    # 备案 / 注册局 / 标准与工具站
    "beian.miit.gov.cn",
    "iana.org",
    "ietf.org",
    "rfc-editor.org",
    "python.org",
    "pypi.org",
    "github.com",
    "githubusercontent.com",
    "github.io",
    "shields.io",
    "developer.android.com",
    "android.com",
    "w3.org",
    "apache.org",
})

#: 允许的域名后缀（含其全部子域）。★提供方的 API 子域（``api.abuseipdb.com`` /
#: ``www.virustotal.com`` 等）必须由后缀覆盖：只列裸域会把富化器源码里真正请求的那个
#: 子域拦下来——本仓自己的测试就是这么抓到这条缺口的。
ALLOWED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".example.com",
    ".example.net",
    ".example.org",
    ".ripe.net",
    ".shodan.io",
    ".virustotal.com",
    ".alienvault.com",
    ".qianxin.com",
    ".360.net",
    ".abuseipdb.com",
    ".censys.io",
    ".daydaymap.com",
    ".fofa.info",
    ".hunter.how",
    ".ip-api.com",
    ".ipinfo.io",
    ".rdap.org",
    ".urlscan.io",
    ".zoomeye.org",
    ".miit.gov.cn",
    ".github.com",
    ".github.io",
    ".githubusercontent.com",
    ".android.com",
    ".w3.org",
    ".apache.org",
    ".ietf.org",
    ".iana.org",
    ".python.org",
    ".pypi.org",
)

#: 常见 TLD 白名单。名单外的 TLD 不判为域名——这既压掉 ``foo.py`` / ``libx.so`` /
#: ``report.json`` 这类文件名，也压掉属性访问。``info`` 有意不收（见模块文档「已知盲点」）。
_COMMON_TLDS: frozenset[str] = frozenset({
    "com", "net", "org", "cn", "io", "co", "top", "xyz", "vip", "shop", "cc", "me",
    "biz", "tv", "online", "site", "club", "live", "pro", "asia", "us", "uk", "ru",
    "jp", "kr", "de", "fr", "it", "nl", "es", "se", "no", "pl", "tr", "br", "mx",
    "ca", "au", "nz", "hk", "tw", "sg", "my", "th", "vn", "ph", "id", "in", "ir",
    "ua", "cloud", "space", "website", "store", "tech", "fun", "icu", "wang", "ltd",
})

#: 反向域名（Java 包名）常见首段。``com.test.app`` 这类**不是**域名。
_REVERSE_DNS_HEADS: frozenset[str] = frozenset({
    "com", "cn", "net", "org", "io", "de", "me", "eu", "uk", "tv", "cc",
})

_DOMAIN_RE = re.compile(
    r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,})(?![\w-])"
)


def _domain_allowed(domain: str) -> bool:
    if domain in ALLOWED_DOMAINS:
        return True
    return domain.endswith(ALLOWED_DOMAIN_SUFFIXES)


def _domain_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _DOMAIN_RE.finditer(line):
        raw = match.group(1)
        domain = raw.lower().rstrip(".")
        labels = domain.split(".")
        if len(labels) < 2:
            continue
        if labels[-1] in _RESERVED_TLDS:
            continue  # .test / .invalid / .example / .localhost —— 合法占位
        if labels[0] in _REVERSE_DNS_HEADS and len(labels) >= 3:
            continue  # 反向域名（Java 包名），不是域名
        if labels[-1] not in _COMMON_TLDS:
            continue  # TLD 不在名单 → 大概率是文件名 / 属性访问，不判
        if _domain_allowed(domain):
            continue
        out.append((
            domain,
            "域名字面不在允许清单；测试与文档请用 example.com 或 .test / .invalid",
        ))
    return out


# ---------------------------------------------------------------------------
# 判据 4：语境框架词
# ---------------------------------------------------------------------------

#: 不进公开仓库可见文本的语境框架词。判据只施加在**新增行**上；
#: 仓库既有文本不在扫描范围内（另有清理计划，不由本护栏代劳）。
#: ★本判据的**词表自身**必须豁免：不豁免则本模块与其测试永远自我命中，
#: 而"护栏自己过不了自己"会逼人整体关掉这条判据。
CONTEXT_TERMS: tuple[str, ...] = (
    "涉诈", "诈骗", "执法", "公安", "警方",  # leak-scan: allow 本判据的词表定义自身
    "受害人", "受害者", "团伙", "办案", "调证", "案件",  # leak-scan: allow 本判据的词表定义自身
)


def _context_findings(line: str) -> list[tuple[str, str]]:
    return [
        (term, "语境框架词；公开可见文本只留纯技术描述")
        for term in CONTEXT_TERMS
        if term in line
    ]


#: 「中文姓名 + 案」形态——取证语境里个案按当事人姓名命名（「张三案」），  # leak-scan: allow name 判据自身的说明示例
#: 真实姓名绝不能进公开仓库。这条判据**多次实战失守**：注释与 commit 里写「实测某某案  # leak-scan: allow name 判据自身的说明示例
#: 33 个节点」当具体锚点，三关 + 其它 leak-scan 判据全绿却照样把当事人姓名带进 GitHub。
#: leak-scan 原本只扫 IP / 域名 / 密钥 / 语境词，**中文人名是判据盲区**，本条补上。
#:
#: ★形态而非名单：只认「案」字前 2–3 个汉字的结构，不内置任何真实姓名（人名名单本身是敏感值，
#:   不能进 git）。中文没有词边界，姓名前后都可能紧跟别的汉字（「实测某某案」「某某案的」），  # leak-scan: allow name 判据自身的说明示例
#:   所以**不能**用 lookbehind/lookahead 卡边界——那会把真名一起挡掉（实测这条踩过）。
#:   改成扫「案」字、回看前缀，再用三道排除收敛误报：
#:     · 案前不足 2 字（本案 / 该案 / 串案 / 涉案 / 方案）→ 跳过；
#:     · 案后紧跟成词字（案+件 / 案+例 / 案+由 / 案+发 / 案+子）→ 跳过；
#:     · 前缀末字构成「X案」词（方案 / 档案 / 答案 / 命案……）或前缀是高频非姓名词 → 跳过。
#:   默认只提示、strict 阻断——中文歧义大，宁可偶尔误提示让人扫一眼，也好过又把真名推上去。
_CASE_NAME_MAX_PREFIX = 3

#: 「案X」里 X 让「案」成词的字（案后紧跟这些 → 不是「姓名+案」）。
_CASE_TAIL_WORD_CHARS: frozenset[str] = frozenset("件例由发情卷宗底号犯值务头子")

#: 前缀末字构成「X案」词的字（方案 / 档案 / 答案 / 文案 / 命案……→ 匹配跨了词边界，跳过）。
_CASE_WORD_HEAD_CHARS: frozenset[str] = frozenset("方档答备预草议提个悬血惨命要专积结立办破审翻铁冤错旧新文")

#: 案前 2–3 字里不是人名的高频词（这类 / 两个 / 关于……）。
_CASE_NAME_STOPWORDS: frozenset[str] = frozenset({
    "两个", "这个", "那个", "几个", "多个", "整个", "一个", "各个", "每个", "同个",
    "关于", "对于", "上述", "前述", "该批", "本批", "同批", "这批", "那批",
    "此类", "这类", "那类", "同类", "各类", "本类", "这起", "那起", "本起", "同起",
    "这宗", "那宗", "本宗", "同宗", "串并", "并串", "历史", "跨案", "并案", "串案",
})


def _is_cjk(ch: str) -> bool:
    return "一" <= ch <= "龥"


def _name_findings(line: str) -> list[tuple[str, str]]:
    """疑似当事人姓名（中文姓名 + 案）。命中即报，理由要人把真名换成中性表述。"""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, ch in enumerate(line):
        if ch != "案":
            continue
        if i + 1 < len(line) and line[i + 1] in _CASE_TAIL_WORD_CHARS:
            continue  # 案+件 / 案+例 / 案+子…… 成词，不是姓名
        j = i
        # 姓名里不含「案」字，回看遇到「案」就停——否则「跨案并案」会把中间的案吞进前缀。  # leak-scan: allow name 判据自身的说明示例
        while j > 0 and i - j < _CASE_NAME_MAX_PREFIX and _is_cjk(line[j - 1]) and line[j - 1] != "案":
            j -= 1
        name = line[j:i]
        if len(name) < 2 or name in _CASE_NAME_STOPWORDS:
            continue  # 本案 / 方案（前缀 1 字）、这类 / 两个（停用词）
        if name[-1] in _CASE_WORD_HEAD_CHARS:
            continue  # 前缀末字构成「X案」词（解决方案 → 决方案 → 末字「方」）
        token = f"{name}案"
        if token in seen:
            continue
        seen.add(token)
        out.append((
            token,
            "疑似当事人姓名（中文姓名+案）；公开仓库禁出现真名，"
            "请改中性表述（如「某真实样本」「某案」），误报可加行内豁免",
        ))
    return out


# ---------------------------------------------------------------------------
# 扫描入口
# ---------------------------------------------------------------------------

_DETECTORS: tuple[tuple[str, "object"], ...] = (
    ("ip", _ipv4_findings),
    ("ip", _ipv6_findings),
    ("secret", _secret_findings),
    ("domain", _domain_findings),
    ("context", _context_findings),
    ("name", _name_findings),
)


def _python_domain_text_by_line(text: str) -> "dict[int, str] | None":
    """提取 Python 文字 token 的逐行文本；解析失败返回 ``None`` 触发保守回退。"""
    lines = text.splitlines()
    masks = [[" " for _char in line] for line in lines]
    text_token_types = {token.STRING, token.COMMENT}
    fstring_middle_type = getattr(token, "FSTRING_MIDDLE", None)
    # Python 3.12+ 会把 f-string 拆成专用 token；旧版本没有这些常量。
    for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
        value = getattr(token, name, None)
        if isinstance(value, int):
            text_token_types.add(value)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for item in tokens:
            if item.type not in text_token_types:
                continue
            start_line, start_col = item.start
            end_line, end_col = item.end
            for line_no in range(start_line, end_line + 1):
                if not 1 <= line_no <= len(lines):
                    continue
                left = start_col if line_no == start_line else 0
                right = end_col if line_no == end_line else len(lines[line_no - 1])
                source = lines[line_no - 1]
                masks[line_no - 1][left:right] = source[left:right]
                # Python 3.12+ 会把插值后面的域名字面部分切成
                # 以 ``.`` 开头的 FSTRING_MIDDLE。这个点是 tokenizer 制造的片段边界，
                # 不是更长域名的左侧字符；改成分隔符后让片段内完整 apex 正常命中。
                if (
                    item.type == fstring_middle_type
                    and line_no == start_line
                    and left < right
                    and source[left] == "."
                ):
                    masks[line_no - 1][left] = "/"
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    except Exception:  # pragma: no cover - tokenizer 失效时宁可多报，不可漏报
        logger.exception("[leakscan] Python tokenize 异常，回退逐行 domain 正则")
        return None
    out: dict[int, str] = {}
    for i, chars in enumerate(masks):
        masked = "".join(chars)
        # Python 3.11 把整个 f-string 作为 STRING；插值后的点会挡住域名正则的左边界。
        # 只在文字 token 掩码内把 ``{expr}.host`` 的插值段改成分隔符。
        out[i + 1] = masked.replace("}.", "/")
    return out


def scan_text(text: str, path: str = "<text>", *, first_line: int = 1) -> list[Finding]:
    """逐行扫描一段文本；Python 域名只看字符串与注释 token。"""
    findings: list[Finding] = []
    domain_lines = _python_domain_text_by_line(text) if path.lower().endswith(".py") else None
    for offset, line in enumerate(text.splitlines()):
        domain_text = None if domain_lines is None else domain_lines.get(offset + 1, "")
        findings.extend(_scan_line(line, path, first_line + offset, domain_text=domain_text))
    return findings


def _scan_line(
    line: str, path: str, line_no: int, *, domain_text: "str | None" = None
) -> list[Finding]:
    marked, reason = _exemption(line)
    if marked and reason is None:
        return [Finding(
            rule="exemption",
            path=path,
            line_no=line_no,
            value="leak-scan: allow",
            detail="豁免必须写理由（leak-scan: allow <理由>）——无理由的豁免等于没有护栏",
        )]
    if marked:
        return []
    findings: list[Finding] = []
    for rule, detector in _DETECTORS:
        detector_text = domain_text if rule == "domain" and domain_text is not None else line
        for value, detail in detector(detector_text):  # type: ignore[operator]
            findings.append(
                Finding(rule=rule, path=path, line_no=line_no, value=value, detail=detail)
            )
    return findings


_DIFF_TARGET_RE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+?)(?:\t.*)?$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")

#: 不扫的路径后缀：二进制 / 锁文件 / 快照，逐行判据对它们没有意义且噪音大。
_SKIP_SUFFIXES: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".apk", ".dex",
    ".so", ".jar", ".bin", ".pcap", ".pcapng", ".keystore", ".jks", ".woff", ".woff2",
)


def iter_added_lines(diff_text: str) -> "list[tuple[str, int, str]]":
    """从 unified diff 里取出全部新增行，返回 ``[(路径, 新文件行号, 行内容)]``。

    只认 ``+`` 行（``+++`` 文件头除外）。行号按 hunk 头 ``@@ -a,b +c,d @@`` 的新侧起点
    递推：上下文行与 ``+`` 行都推进新侧行号，``-`` 行不推进。
    """
    added: list[tuple[str, int, str]] = []
    path = "<unknown>"
    new_line = 0
    skip = False
    for raw in diff_text.splitlines():
        target = _DIFF_TARGET_RE.match(raw)
        if target is not None:
            path = target.group("path")
            skip = path == "/dev/null" or path.lower().endswith(_SKIP_SUFFIXES)
            new_line = 0
            continue
        if raw.startswith("--- "):
            continue
        hunk = _HUNK_RE.match(raw)
        if hunk is not None:
            new_line = int(hunk.group("start"))
            continue
        if new_line <= 0:
            continue  # 还没进 hunk（diff 头部的 index/mode 行）
        if raw.startswith("+"):
            if not skip:
                added.append((path, new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue  # 删除行 / "\ No newline" 不占新侧行号
        else:
            new_line += 1  # 上下文行
    return added


def iter_exemptions(diff_text: str) -> "list[tuple[str, int, str]]":
    """取出 diff 新增行里的全部行内豁免，返回 ``[(路径, 行号, 理由)]``。

    供调用方**如实呈现**"这次改动按掉了多少护栏"。此前这件事完全不可见：一次加 1 条豁免
    与一次加 30 条，在门禁输出里同形，review 时也不会被顶到眼前。
    """
    out: list[tuple[str, int, str]] = []
    for path, line_no, line in iter_added_lines(diff_text):
        marked, reason = _exemption(line)
        if marked and reason:
            out.append((path, line_no, reason))
    return out


def _bulk_exemption_findings(entries: "list[tuple[str, int, str]]") -> list[Finding]:
    """同一条理由被复制到 ≥ 阈值 个新增行 → 一条 ``bulk_exemption``。

    判的是**批量按掉护栏**这个动作本身，不是豁免的对错（理由成不成立机器判不了）。
    要么逐条给出各自成立的理由，要么改用合成值让判据根本不触发。
    """
    by_reason: dict[str, list[tuple[str, int]]] = {}
    for path, line_no, reason in entries:
        by_reason.setdefault(" ".join(reason.split()), []).append((path, line_no))

    findings: list[Finding] = []
    for reason, spots in sorted(by_reason.items()):
        if len(spots) < _BULK_EXEMPTION_THRESHOLD:
            continue
        path, line_no = sorted(spots)[0]
        files = len({p for p, _ in spots})
        findings.append(Finding(
            rule="bulk_exemption",
            path=path,
            line_no=line_no,
            value=reason[:80],
            detail=(
                f"同一条豁免理由出现在本次改动的 {len(spots)} 个新增行上（跨 {files} 个文件），"
                f"超过阈值 {_BULK_EXEMPTION_THRESHOLD}——这是批量按掉护栏的形态。"
                "请逐条给出各自成立的理由，或改用合成值使判据不再触发"
            ),
        ))
    return findings


def scan_diff(diff_text: str, *, source_root: "Path | None" = None) -> list[Finding]:
    """扫描 unified diff 新增行；给出 ``source_root`` 时用完整 Python 文件映射 token。"""
    findings: list[Finding] = []
    source_cache: dict[str, "tuple[list[str], dict[int, str]] | None"] = {}
    for path, line_no, line in iter_added_lines(diff_text):
        domain_text: str | None = None
        if path.lower().endswith(".py"):
            if source_root is not None:
                if path not in source_cache:
                    root = source_root.resolve()
                    candidate = (root / path).resolve()
                    try:
                        candidate.relative_to(root)
                        source = candidate.read_bytes().decode("utf-8", errors="replace")
                    except (OSError, ValueError):
                        source_cache[path] = None
                    else:
                        tokenized = _python_domain_text_by_line(source)
                        source_cache[path] = (
                            source.splitlines(), tokenized
                        ) if tokenized is not None else None
                cached = source_cache[path]
                # 行号和内容必须同时吻合；工作树与 diff 错位时回退原正则，绝不套错掩码。
                if cached is not None and 1 <= line_no <= len(cached[0]):
                    if cached[0][line_no - 1] == line:
                        domain_text = cached[1].get(line_no, "")
            else:
                # 库函数兼容无工作树调用；残片失败时同样回退原始行正则。
                fragment = line.lstrip()
                tokenized = _python_domain_text_by_line(fragment)
                domain_text = None if tokenized is None else tokenized.get(1, "")
        findings.extend(_scan_line(line, path, line_no, domain_text=domain_text))
    findings.extend(_bulk_exemption_findings(iter_exemptions(diff_text)))
    return findings


#: 递归全树扫描时整个跳过的目录名（编译缓存 / 虚拟环境 / 构建产物，全是派生物）。
_SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {"__pycache__", ".git", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache",
     "build", "dist", ".eggs"}
)


def _is_skipped_file(path: Path) -> bool:
    """二进制/派生文件后缀：逐行判据对它们没有意义。"""
    return path.name.lower().endswith((*_SKIP_SUFFIXES, ".pyc", ".pyo"))


def expand_paths(
    paths: "list[str] | list[Path]", errors: "list[str] | None" = None
) -> list[Path]:
    """把输入路径展开成**确定性排序**的待扫文件清单。

    ★为什么必须有这个函数：此前 :func:`scan_paths` 把目录当"读不动的文件"一并
    ``continue`` 掉，于是 ``leak-scan --path apkscan --path tests`` 会**静默跳过整棵树**
    并输出"未发现泄漏嫌疑" + exit 0 —— 一个永远为绿的假门禁，比没有门禁更坏：
    它让人以为全树被扫过了。

    路径不存在 / 目录读不动 / 文件读不动，一律**如实记入** ``errors``，由调用方决定
    是否变红（CLI 侧 exit 2）。"少扫了"绝不与"扫全了"长得一样。
    """
    out: list[Path] = []
    seen: set[Path] = set()

    def _fail(message: str) -> None:
        if errors is not None:
            errors.append(message)
        logger.warning("[leakscan] %s", message)

    for raw in paths:
        path = Path(raw)
        if not path.exists():
            _fail(f"输入路径不存在，未扫描：{path}")
            continue
        if path.is_dir():
            try:
                candidates = sorted(
                    p for p in path.rglob("*")
                    if p.is_file()
                    and not _is_skipped_file(p)
                    and not (_SKIP_DIR_NAMES & {part for part in p.parts})
                )
            except OSError as exc:
                _fail(f"目录展开失败（{type(exc).__name__}），未扫描：{path}")
                continue
            for candidate in candidates:
                if candidate not in seen:
                    seen.add(candidate)
                    out.append(candidate)
            continue
        if _is_skipped_file(path):
            continue
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def scan_paths(
    paths: "list[str] | list[Path]", errors: "list[str] | None" = None
) -> list[Finding]:
    """全树/多文件审计模式。目录**递归展开**；读不到的路径记入 ``errors``。

    ``errors`` 省略时行为与旧版兼容（只告警不上报），但门禁调用方**必须**传入并检查它，
    否则"扫不到"会伪装成"没问题"。
    """
    findings: list[Finding] = []
    for path in expand_paths(paths, errors):
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            message = f"读不到文件（{type(exc).__name__}），未扫描：{path}"
            if errors is not None:
                errors.append(message)
            logger.warning("[leakscan] %s", message)
            continue
        findings.extend(scan_text(text, path.as_posix()))
    return findings


def tracked_files(
    roots: "list[str] | list[Path]",
    *,
    repo_root: "Path | None" = None,
    errors: "list[str] | None" = None,
) -> list[Path]:
    """用 ``git ls-files`` 枚举 ``roots`` 下**已跟踪**的文件（确定性排序）。

    只认已跟踪文件：未跟踪的临时产物（本地实验脚本、抓包中间件）不属于"仓库内容"，
    把它们算进门禁会让门禁随工作目录状态漂移。枚举失败如实记入 ``errors``——
    取不到清单时**绝不**返回空列表冒充"全树干净"。

    ★**每个 root 独立查询**。合并成一次 ``git ls-files -- A B`` 会让"A 有文件"掩盖
    "B 根本不存在"：``tracked_files(["apkscan", "typo_xyz"])`` 曾返回 apkscan 的两百个
    文件且 ``errors=[]``，于是门禁在**扫漏了一整棵树**的情况下报绿。凡有任一 root
    不存在 / 无跟踪匹配 / 不可读，都必须各自记一条错误（调用方据此 exit 2）。
    """
    import subprocess

    base = Path(repo_root) if repo_root is not None else Path.cwd()

    def _fail(message: str) -> None:
        if errors is not None:
            errors.append(message)
        logger.warning("[leakscan] %s", message)

    collected: set[Path] = set()
    for root in roots:
        root_str = str(root)
        cmd = ["git", "-C", str(base), "ls-files", "-z", "--", root_str]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            _fail(
                f"git ls-files 执行失败（{type(exc).__name__}），"
                f"无法枚举已跟踪文件：{root_str}"
            )
            continue
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            _fail(f"git ls-files 退出码 {proc.returncode}（{root_str}）：{detail}")
            continue

        names = [
            n for n in proc.stdout.decode("utf-8", errors="replace").split("\0") if n
        ]
        if not names:
            _fail(f"git ls-files 在 {root_str} 下没有枚举到任何已跟踪文件")
            continue

        kept = 0
        for name in names:
            candidate = base / name
            if _is_skipped_file(candidate):
                continue
            if _SKIP_DIR_NAMES & set(Path(name).parts):
                continue
            collected.add(candidate)
            kept += 1
        if kept == 0:
            # 该 root 下的跟踪文件全被"二进制/派生物"过滤掉了。这与"root 不存在"性质不同，
            # 但对门禁同样是"这棵树一个字节都没扫"，故也如实上报而不是静默当成 0 条。
            _fail(f"{root_str} 下的已跟踪文件全部被跳过（二进制/派生物），未扫描任何内容")

    return sorted(collected)


def blocking(findings: "list[Finding]", *, strict: bool = False) -> list[Finding]:
    """挑出让门禁变红的 finding。``strict=True`` 时全部 finding 都阻断。"""
    return list(findings) if strict else [f for f in findings if f.blocking]


def format_findings(findings: "list[Finding]", *, strict: bool = False) -> str:
    """把 finding 排成稳定可读的报告（按 路径→行号→判据→值 排序）。"""
    if not findings:
        return "leak-scan: 未发现泄漏嫌疑。"
    ordered = sorted(findings, key=lambda f: (f.path, f.line_no, f.rule, f.value))
    blocked = {id(f) for f in blocking(ordered, strict=strict)}
    lines = [f"leak-scan: {len(ordered)} 条嫌疑（其中 {len(blocked)} 条阻断）"]
    for f in ordered:
        flag = "阻断" if id(f) in blocked else "提示"
        lines.append(f"  [{flag}] {f.path}:{f.line_no} ({f.rule}) {f.value} — {f.detail}")
    lines.append("  放行某行请加行内注释：leak-scan: allow <理由>")
    return "\n".join(lines)
