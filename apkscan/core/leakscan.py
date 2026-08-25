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

5. **案件值判据的 finding 值一律脱敏**（``person_name`` / ``contact`` / ``package``）。
   公开仓库的 CI 日志同样公开：护栏把真名、QQ 号原样打进 Actions 输出，等于把泄漏面
   从源码挪到日志。这三条只报"哪一行、命中了什么**形态**"，具体字面由人打开文件看。
   ``ip`` / ``domain`` 判据仍打原值——那两类需要"看一眼就知道是不是保留段"，
   且它们判的本就是"不该写进来的公开地址"，性质与案件值不同。

已知盲点（有意接受，写在此处以便复核）
------------------------------------

- IPv4 判据会跳过若干 X.509/PKIX **OID 弧前缀**（见 :data:`OID_ARC_PREFIXES`）：
  ``2.5.4.3`` / ``1.3.6.1`` 这类 OID 与合法 IPv4 字面同形，不跳过则证书解析代码
  永远误报。代价是这几个真实网段里的地址查不出来，须靠人工复核兜底。
- ``domain`` 判据用的是**常见 TLD 白名单**，不是完整 IANA 表；名单外的 TLD 查不出来。
  ``info`` 有意不在名单里——仓库里 ``logger.info`` / ``severity.info`` 数以百计，
  收进来会把这条判据淹掉。
- ``person_name`` **只认「姓名 + 案(件)」这一种形态**（见 :data:`SURNAME_CHARS`）。
  曾试过第二形态「行内有强语境词（案件 / 嫌疑人 / 事主…）时扫全部姓名候选」，
  全树实测 7 条命中里 **6 条是误报**——"向量""成员""高敏""方向锁"里的
  向 / 成 / 高 / 方 都是姓氏字。召回换来的噪音会把这条判据淹掉，故不收。
  代价：不带「案」字的真名（"嫌疑人<真名>的手机"）查不出来，须靠人工复核兜底。
- ``person_name`` 有一类**确定性漏报**：姓名末字与「案」连成常见词时（"<某>方案"
  "<某>文案"），判据分不开「何方 + 案」与「解决 + 方案」——人看字面也分不开。
  这几个字（见 :data:`_NON_NAME_TAIL_CHARS`）已收到最窄，但无法清零。
- ``package`` 判据靠**段内最长辅音串**识别随机化的二开包名段，识别不了可读性好的
  改名（``im.telegramx.messenger`` 这类）。它只压住"随机串"这一种最常见形态。
  同理，``y`` 按元音计（见 :data:`_PSEUDO_VOWELS`），插 y 稀释辅音串能绕过——
  那是**主动规避**，而主动规避本来就有行内豁免这条正门，护栏不为它牺牲 38 处误报。
- ``contact`` 判据**不收邮箱**：邮箱形态在源码里满地都是（库作者邮箱、``noreply@``、
  资源引用），而域名部分已由 ``domain`` 判据覆盖。数字型 QQ 邮箱是例外，
  规则表的 QQ 形态本来就直接匹配它的本地部分。
- ``package`` 判据在 ``.py`` 文件里只看字符串与注释 token（见 :data:`_TEXT_TOKEN_RULES`），
  故 ``from im.<随机段>.x import y`` 这种写法看不见。这是理论盲点：Android 包名不是
  可 import 的 Python 模块，真实文件里不会出现。
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
    "OPAQUE_SEGMENT_MIN_CONSONANT_RUN",
    "OPAQUE_SEGMENT_MIN_LEN",
    "PACKAGE_HEADS",
    "RESERVED_DOC_NETWORKS",
    "RULES",
    "SURNAME_CHARS",
    "blocking",
    "expand_paths",
    "format_findings",
    "iter_added_lines",
    "iter_exemptions",
    "scan_diff",
    "scan_paths",
    "scan_text",
    "tracked_files",
    "uncommitted_paths",
]


# ---------------------------------------------------------------------------
# 判据标识
# ---------------------------------------------------------------------------

#: 全部判据名（稳定标识，进 finding.rule / CLI 输出 / 测试断言）。
RULES: tuple[str, ...] = (
    "ip", "secret", "domain", "context", "person_name", "contact", "package",
    "exemption", "bulk_exemption",
)

#: 默认阻断的判据。``ip`` / ``secret`` 判据精确，误报可控，直接当门禁；
#: ``domain`` / ``context`` 噪音大，默认只报告（``strict=True`` 时全部阻断）。
#: ``exemption``（豁免没写理由）与 ``bulk_exemption``（同一条理由被复制到大量新增行）恒阻断：
#: 二者都是护栏**自身**的完整性检查，不允许静默削弱。
#:
#: ★``person_name`` / ``contact`` / ``package`` 三条**案件值**判据同样默认阻断。
#:   它们判的是本仓最硬的红线（真名、QQ/微信/Telegram 账号、样本包名），一旦推上远端
#:   改写历史也删不掉缓存副本；而落到默认档的前提——"误报可控"——是**实测**过的：
#:   在 528 个已跟踪文件、22 万行上，``person_name`` 与 ``package`` 各 **0 条**命中，
#:   ``contact`` 命中的 15 行全部是 ``tests/`` 里的合成夹具（已逐条加带理由的行内豁免）。
#:   分档不是拍脑袋定的，改判据参数前请重跑那一轮全树实测。
BLOCKING_RULES: frozenset[str] = frozenset({
    "ip", "secret", "person_name", "contact", "package", "exemption", "bulk_exemption",
})

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
    "spamhaus.org",
    "www.spamhaus.org",  # DROP 清单的实际下载端点带 www，匹配是精确的（同 ripe.net / stat.ripe.net）
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

#: Framing terms that must not appear in publicly visible text.
#: Applies to added lines only; pre-existing text is out of scope for this gate.
#:
#: NOTE: this rule's own term list must carry inline exemptions. Without them the
#: module and its tests would self-match forever, and a gate that cannot pass itself
#: is a gate people switch off entirely.
#:
#: ★两个词曾在表内、已**有意移除**（勿加回）：它们是本工具的领域词而非语境框架词——
#: 包简介（``pyproject.toml`` 的 ``description``）、``digest`` 的 advice 取值
#: （``_ADVICE_RANK`` 的键）、HTML 报告模板标题都在用，``apkscan/`` 下逾百个文件命中。
#: 判据留着它们只会逼人在正常技术文本上贴大量豁免，而**大量豁免正是护栏失效的起点**。
#: 真正的红线由 ``ip`` / ``secret`` / ``domain`` 判据覆盖：具体端点、凭据与真实域名字面。
CONTEXT_TERMS: tuple[str, ...] = (
    "涉诈", "诈骗", "执法", "公安", "警方",  # leak-scan: allow 本判据的词表定义自身
    "受害人", "受害者", "团伙", "办案",  # leak-scan: allow 本判据的词表定义自身
)


def _context_findings(line: str) -> list[tuple[str, str]]:
    return [
        (term, "语境框架词；公开可见文本只留纯技术描述")
        for term in CONTEXT_TERMS
        if term in line
    ]


# ---------------------------------------------------------------------------
# 判据 5：中文人名（「姓名 + 案」形态）
# ---------------------------------------------------------------------------
#
# 起因：一份 frida 探针的头部注释写着「对应<真名>案：<QQ 号>触发…」，本模块当时只报了
# 同一行的两个公网 IP，真名与 QQ **一条都没报**，靠人工复核才拦下。真名是本仓最硬的红线，
# 却是唯一一类此前完全没有机器判据的值。
#
# 判据形态刻意窄：**姓氏字 + 1~2 个汉字（+ 可选的日期数字）+「案」**。
# 只认这一种是因为中文里 2~3 字的正常词组俯拾皆是，宽一点就会把判据淹掉
# （第二形态的实测数字见模块文档「已知盲点」）。

#: 常见汉族姓氏用字（覆盖率优先，不求全）。只收单姓常见字；复姓（欧阳 / 上官…）由其
#: **第二**个字落在表内间接覆盖（「欧阳」的「阳」在表里），报的位置一样对，只是脱敏值里
#: 的字数少一个。
SURNAME_CHARS: str = (
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔"
    "钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤常温康施文牛樊"
    "葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁"
    "甄滕巫司蒲车宫景屠连商冀国代管路项祁邬蔺阳苍闻辛鞠储靳边扈桑咸练蓬岑薄禄阙巩闵解应鄂"
)

#: **与「案」连成常见词**的字，即不可能出现在人名末位的那一类。
#:
#: ★这是本判据的主要降噪手段，也是它能落到默认阻断档的原因。姓氏字大量兼任虚词与动词，
#:   而汉语没有词边界，于是「用**于串案**索引」会被读成 于(姓)+串+案、「当**成并案**依据」
#:   被读成 成(姓)+并+案——全树实测的误报**全部**是这一形态。它们的共同点是「案」前那个字
#:   （串 / 并 / 逐 / 每）绝不会出现在人名末位，据此一刀切干净。
#:
#: ★这张表**刻意只收与「案」高频成词的字**，不收"看着像虚词"的字。每多收一个字就多一份
#:   确定性漏报：曾把 新 / 原 / 旧 / 民 / 行 / 成 / 真 收进来，代价是名字以这几个字收尾的
#:   人（<姓> + 成、<姓> + 民、<姓> + 新…）整类查不出来，而它们与「案」成词的频率并不高。
#:   收窄后全树误报仍是 0——多收的那几个字换不来任何误报收益，只换来漏报。
#:
#: 判的是**位置**（人名末字）而不是「这个词是不是常见词」：后者需要词典，前者只需一张
#: 几十字的表，且新增误报时该往哪加是自明的。**这张表是活的**，扩它不需要重新论证判据——
#: 但每次扩之前请先问：这个字能不能作人名末字？能，就别加。
_NON_NAME_TAIL_CHARS: frozenset[str] = frozenset(
    # 「案X」构成普通词的修饰字：方案 / 预案 / 档案 / 草案 / 议案 / 提案 / 教案 / 图案…
    "方预档草议提教图公答悬疑文"
    # 公文动词：立案 / 查案 / 结案 / 破案…（本仓一句「等于替办 + 案 + 人」曾被读成人名）
    "办立结备报销翻破定查审涉专"
    # 量词 / 指代 / 范围词：串案 / 并案 / 逐案 / 每案 / 本案 / 该案 / 个案…
    "串并逐每本该此全个积同类起多关联"
    # 与「案」成词的性质词：重案 / 要案 / 大案 / 血案 / 命案 / 惨案 / 刑案
    "重要大血命惨刑"
)

#: 只在「姓名 + **案件**」这条更宽的形态上使用的**全字**表（末字表 + 虚词 / 形容词 / 指代）。
#:
#: ★为什么要分两张表：放开「案件」是必要的（「<真名>案件」是自然写法，只挡「<真名>案」
#:   等于留了一条一改措辞就能绕过的缝），但「案件」在技术文本里是高频词，
#:   「当**成当前案件**证据」「不是任何**真实案件**的值」这类句子会被读成 成+当前+案件、
#:   何+真实+案件。对这条形态改用**全字**检查（姓名候选里任何一个字落表即弃）正好分开：
#:   真名（张三 / 刘超泉）的每个字都不在表里，而上面那些巧合总有一个虚词字命中。
#:
#: 这张表只在「案件」形态生效，故收字可以放开——它挡掉的是"疑似"，不会造成
#: 「<真名>案」主形态的漏报。
_NON_NAME_ANY_CHARS: frozenset[str] = _NON_NAME_TAIL_CHARS | frozenset(
    "当前是实真历新原旧民行成受验核批督指参复经承在其某各这那些样种"
    "被将把从对与和了的地得也都还就只即另因所如若则由为于向到过来去"
)

#: 「案」后紧跟这些字时，「案X」自身是普通词（案例 / 案卷 / 案由 / 案子…），不判。
#: **「件」有意不在表内**——见 :data:`_NON_NAME_ANY_CHARS`，那条形态改用更严的全字检查。
_CASE_COMPOUND_TAILS = "例卷由情底宗头值语标子"

_PERSON_NAME_RE = re.compile(
    rf"(?P<name>[{SURNAME_CHARS}][一-鿿]{{1,2}})"
    rf"\s*(?:\d{{2,8}})?\s*案(?![{_CASE_COMPOUND_TAILS}])"
)


def _person_name_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _PERSON_NAME_RE.finditer(line):
        name = match.group("name")
        # 「<候选>案件」：技术文本里「案件」是高频词，改用全字检查（见 _NON_NAME_ANY_CHARS）。
        # 「<候选>案」：只查末字，好让 <姓> + 成 / 民 / 新 这类真名不被误挡。
        if line[match.end():match.end() + 1] == "件":
            if set(name) & _NON_NAME_ANY_CHARS:
                continue
        elif name[-1] in _NON_NAME_TAIL_CHARS:
            continue  # 跨词边界的巧合（"用于串案" / "当成并案"），不是人名
        out.append((
            f"<中文姓名 {len(name)} 字>案",  # 脱敏：CI 日志在公开仓库里同样公开
            "疑似「真名 + 案」语境；案件当事人姓名一律不进公开仓库，"
            "技术描述请去掉案件指代（同一事实写成「某样本」即可）",
        ))
    return out


# ---------------------------------------------------------------------------
# 判据 6：联系方式（QQ / 微信 / Telegram）
# ---------------------------------------------------------------------------


def _contact_patterns() -> tuple[tuple[str, "re.Pattern[str]", tuple[str, ...]], ...]:
    """读 ``rules/contacts.yaml`` 里已实证调优的 QQ / 微信 / Telegram 形态。

    ★复用而不另写一份：那张表是**本工具从样本里提取联系方式**用的，已经踩过并写下了
      "裸 weixin/wechat 触发词会撞 ``weixinJSBridge``""手机号 12/12 全是误报所以整类移除"
      这些结论。护栏与提取器共用一个口径，语义上也正好成立——**分析器能从样本里认出来的
      联系方式形态，就是不该写进公开仓库的形态**；另立一份必然漂移。

    只取 qq / wechat / telegram / telegram_bot 四类。有意**不取 email**：邮箱形态在源码里
    满地都是（作者邮箱、``noreply@``、资源引用），而域名部分已由 ``domain`` 判据覆盖。
    """
    kinds = {"qq", "wechat", "telegram", "telegram_bot"}
    out: list[tuple[str, "re.Pattern[str]", tuple[str, ...]]] = []
    try:
        from apkscan.core.registry import load_rules

        data = load_rules("contacts")
        types = data.get("types") if isinstance(data, dict) else None
        for entry in types or []:
            if not isinstance(entry, dict) or entry.get("kind") not in kinds:
                continue
            kind = str(entry["kind"])
            black = tuple(
                str(b).lower() for b in (entry.get("blacklist") or []) if isinstance(b, str)
            )
            for pattern in entry.get("patterns") or []:
                if isinstance(pattern, str):
                    out.append((kind, re.compile(pattern, re.IGNORECASE), black))
    except Exception:  # noqa: BLE001 — 规则表坏了也不许让护栏静默消失，见下方兜底
        logger.exception("[leakscan] 读 rules/contacts.yaml 失败，contact 判据退回内置兜底集")
    # ★兜底**按 kind 合并**，不是"整表读不到才用"。规则表仍可解析、只是某一类被删掉时，
    #   那一类判据会静默消失——护栏不允许有"看起来正常运行、实际少了一条"的状态。
    covered = {kind for kind, _pattern, _black in out}
    for kind, pattern, black in _CONTACT_FALLBACK:
        if kind not in covered:
            logger.warning(
                "[leakscan] rules/contacts.yaml 没有可用的 %s 形态，该类退回内置兜底", kind
            )
            out.append((kind, pattern, black))
    return tuple(out)


#: 读不到规则表时的兜底形态。**刻意窄于规则表**，只保证护栏不整个消失——
#: 这两条（QQ 号、微信内部 id）是形态最硬、误报最低的两种。
#:
#: ★为什么必须有兜底：其余"读不到规则就退化为空"的地方（如 :func:`_rule_noise_ips`）
#:   退化方向是**多报**，安全；而 contact 判据退化为空集是**漏报**，那正是本判据要防的事。
_CONTACT_FALLBACK: tuple[tuple[str, "re.Pattern[str]", tuple[str, ...]], ...] = (
    ("qq", re.compile(r"(?i)(?:QQ|扣扣|企鹅)[号码群:：＠@\s]{0,3}(\d{5,11})"), ()),
    ("wechat", re.compile(r"(?i)(wxid_[a-zA-Z0-9]{6,20})"), ()),
)

_CONTACT_PATTERNS = _contact_patterns()

#: 命中值 → 人话（进 finding.detail）。
_CONTACT_LABELS: dict[str, str] = {
    "qq": "QQ 号",
    "wechat": "微信号",
    "telegram": "Telegram 账号",
    "telegram_bot": "Telegram bot token",
}


def _contact_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, pattern, blacklist in _CONTACT_PATTERNS:
        for match in pattern.finditer(line):
            whole = match.group(0)
            low = whole.lower()
            if any(bad in low for bad in blacklist):
                continue
            # 脱敏：只报形态与长度。真值原样进 CI 日志＝把泄漏面从源码挪到公开的 Actions 输出。
            value = f"{kind}=<{len(whole)} 字符>"
            if value in seen:
                continue  # 同一行被多条 pattern 命中（如「微信：x」与 wxid_ 各一条）只报一次
            seen.add(value)
            label = _CONTACT_LABELS.get(kind, kind)
            out.append((
                value,
                f"疑似{label}字面；账号是可直接落地的案件值，一律不进公开仓库。"
                "测试夹具请用明显合成的值并加带理由的行内豁免",
            ))
    return out


# ---------------------------------------------------------------------------
# 判据 7：二开 / 改包样本包名
# ---------------------------------------------------------------------------
#
# 真实二开 IM（Telegram fork 之类）的包名里总有一段是**随机化的无意义串**：
# ``im.<随机段>.messenger``。这类包名是样本身份，属于侦查积累，不进公开仓库。
# 而正常代码里的第三方库包名（``org.telegram.messenger`` / ``com.android.*`` /
# ``net.sqlcipher.*``）是公开事实，写进规则表是功能需要。判据要分开这两者。

#: 反向域名的合法首段。以 :data:`_REVERSE_DNS_HEADS`（``domain`` 判据用它**排除**包名）
#: 为基底反向使用——同一份事实，两条判据方向相反：那边"首段像 TLD ⇒ 不是域名"，
#: 这边"首段像 TLD ⇒ 是包名"。补上 IM 二开惯用的 ``im`` 与几个新通用顶级段。
#:
#: ★首段限定是这条判据的主要降噪手段：没有它，``apkscan.core.leakscan`` /
#:   ``importlib.util.find_spec`` 这类**Python 模块路径**会整片命中（全树实测 15 处）。
PACKAGE_HEADS: frozenset[str] = _REVERSE_DNS_HEADS | frozenset({
    "im", "app", "top", "xyz", "vip", "pro", "biz", "mobi", "dev", "co", "us", "in",
    "ru", "fr", "jp", "kr", "site", "club", "shop", "one", "ai",
})

#: "不透明段"的判定阈值：段长 ≥ 8 **且** 段内最长连续辅音串 ≥ 5。
#:
#: 两个数是**实测**定出来的，不是估的。全树 528 个文件上，辅音串门槛取 4 会命中 107 处
#: （``sqlcipher`` / ``tendcloud`` / ``chinamworld`` 这类真实库名、银行包名全撞上），
#: 取 6 则漏掉目标形态之一（``rightkinghts`` 的最长辅音串正好是 5）。取 5 两头都成立：
#: 目标形态全中，全树误报 0。调这两个数前请重跑那一轮全树实测。
OPAQUE_SEGMENT_MIN_LEN = 8
OPAQUE_SEGMENT_MIN_CONSONANT_RUN = 5

#: 判辅音时 ``y`` **算元音**。
#:
#: ★这是个实测过的取舍，不是疏忽。把 y 也算辅音（或"两种口径取大"）确实能堵住"插几个 y
#:   稀释辅音串"的绕过，但代价实测是全树 **38 处**误报——其中 37 处是本仓的标准合成包名
#:   ``com.example.synthetic``（``synth`` 五个字母在 y 算辅音时连成一串），还有 AOSP 的
#:   ``com.android.org.conscrypt``。护栏防的是**无意**把案件值写进来，不防主动规避
#:   （真要规避，行内豁免本来就能关掉一切判据）。用 38 处误报换一条主动绕过路径不划算。
_PSEUDO_VOWELS: frozenset[str] = frozenset("aeiouy")

#: ★段数下限是 **2**（``im.<随机段>`` 这种两段包名也要认）。放宽到 2 段实测不引入任何
#:   误报——首段限定与"不透明段"两道门已经把属性链挡在外面。
_PACKAGE_RE = re.compile(
    r"(?<![A-Za-z0-9_.$-])((?:[a-z][a-z0-9_]*)(?:\.[a-z][a-z0-9_]*){1,})(?![A-Za-z0-9_$-])"
)


def _max_consonant_run(segment: str) -> int:
    """段内最长连续辅音串长度。数字与其他非字母字符断开计数，不计入串长。"""
    best = current = 0
    for char in segment:
        if char.isalpha() and char not in _PSEUDO_VOWELS:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _is_opaque_segment(segment: str) -> bool:
    """该段是否像随机化的无意义串（而不是英文词或缩写）。

    ★允许段内带数字（``zxcvbnm123`` 这类）：随机化的包名段常混数字，只认纯字母等于留了
      一条"加个数字就绕过"的缝。纯数字段不算——那是版本号 / 序号，不是名字。
    """
    return (
        len(segment) >= OPAQUE_SEGMENT_MIN_LEN
        and segment.isalnum()
        and not segment.isdigit()
        and _max_consonant_run(segment) >= OPAQUE_SEGMENT_MIN_CONSONANT_RUN
    )


def _known_packages() -> frozenset[str]:
    """规则表里登记的公开第三方包名（银行/支付 app + SDK 的 DEX 类前缀）。

    ★同样是**复用既有判断**：这两张表记的就是"本工具认得的公开第三方包名"，与本判据要
      放行的集合语义完全一致。复用还顺带解决了维护问题——往 ``bank_packages.yaml`` 新增
      一个银行包名时，扫的是工作树里的当前文件，白名单自动跟着那一行一起生效，不会因为
      新增的包名撞上辅音串启发而把 PR 门禁卡红。

    ★**规则表项一律按原样取，绝不 ``lower()``**。这条不是风格问题，是堵一条真实的绕过：
      :data:`_PACKAGE_RE` 只匹配小写包名，若白名单把 ``IM.ZXCVBNMQWR.MESSENGER`` 折成小写
      收进来，那行 YAML 自己因为是大写**不会**被本判据命中，却把源码里的小写同名包名放行了
      ——一次改动就能给任意包名开一张免检票。不折叠大小写后，想加白名单就必须在规则表里写
      小写包名，而那一行会被本判据自己命中，形成闭环（要么它确实是公开库、判据不该报它，
      要么审查者会在 diff 里看到一条 package finding）。

    读不到就退化为空集：方向是**多报**（正常库名可能被误判），安全。
    """
    known: set[str] = set()
    skipped: list[str] = []

    def _take(raw: object) -> None:
        if not isinstance(raw, str):
            return
        value = raw.strip().rstrip(".")
        if not value:
            return
        if value != value.lower():
            skipped.append(value)  # 见上：不折叠大小写，非小写项一律不进白名单
            return
        known.add(value)

    try:
        from apkscan.core.registry import load_rules

        banks = load_rules("bank_packages")
        packages = banks.get("packages") if isinstance(banks, dict) else None
        if isinstance(packages, dict):
            for package in packages:
                _take(package)
        sdks = load_rules("sdks")
        rules = sdks.get("sdks") if isinstance(sdks, dict) else None
        for rule in rules or []:
            if not isinstance(rule, dict):
                continue
            for prefix in rule.get("dex_prefixes") or []:
                _take(prefix)
    except Exception:  # noqa: BLE001 — 读不到规则表只影响误报多少，不影响正确性
        logger.warning("[leakscan] 读不到 bank_packages / sdks 规则表，已知第三方包名将被误报")
    if skipped:
        # 只记 debug：规则表里确有几个合法的大写包名（``com.bankcomm.Bankcomm`` 这类，
        # Android 包名允许大写），它们**本来就不在** _PACKAGE_RE 的匹配面内（该正则只认
        # 小写），跳过不会造成任何误报。每次 import 打 warning 只会把日志吵掉。
        logger.debug(
            "[leakscan] 规则表里 %d 个非小写包名项未进白名单（判据只匹配小写包名，无影响）：%s",
            len(skipped), ", ".join(sorted(skipped)[:5]),
        )
    return frozenset(known)


_KNOWN_PACKAGES = _known_packages()


def _package_findings(line: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for match in _PACKAGE_RE.finditer(line):
        package = match.group(1)
        labels = package.split(".")
        if labels[0] not in PACKAGE_HEADS:
            continue  # 不是反向域名形态（Python 模块路径 / 属性链）
        if labels[-1] in _COMMON_TLDS or labels[-1] in _RESERVED_TLDS:
            continue  # 末段是 TLD ⇒ 这是域名，归 domain 判据管
        if any(package == known or package.startswith(known + ".") for known in _KNOWN_PACKAGES):
            continue  # 规则表登记过的公开第三方包名，写进代码是功能需要
        opaque = [label for label in labels if _is_opaque_segment(label)]
        if not opaque:
            continue
        # 脱敏：只报被判为随机串的那一段有多长，不回显包名本身（它是样本身份）。
        masked = ".".join(f"<{len(x)} 字符不透明段>" if x in opaque else x for x in labels)
        out.append((
            masked,
            "疑似二开 / 改包样本的包名（含随机化的无意义段）；样本包名是案件值，"
            "不进公开仓库。真是公开第三方库请登记进 rules/ 对应规则表",
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
    ("person_name", _person_name_findings),
    ("contact", _contact_findings),
    ("package", _package_findings),
)

#: 走 Python 文字 token 掩码的判据：只看字符串与注释，不看可执行代码。
#: ``package`` 与 ``domain`` 同列——``importlib.util.find_spec`` 这类属性链与包名同形，
#: 不掩码就会整片误报（首段限定挡掉了大部分，掩码把剩下的清零）。
_TEXT_TOKEN_RULES: frozenset[str] = frozenset({"domain", "package"})


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
        use_masked = rule in _TEXT_TOKEN_RULES and domain_text is not None
        detector_text = domain_text if use_masked else line
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


def uncommitted_paths(*, repo_root: "Path | None" = None) -> list[str]:
    """工作树里未提交的改动路径（含已暂存与未暂存、含未跟踪）。取不到时返回空列表。

    用途只有一个：``leak-scan --base X`` 走的是 ``git diff X...HEAD``（**三点**），
    只比已提交的 commit。改完不提交就跑本地校验，看到的是与改动前**一模一样**的结果——
    很容易读成「豁免没生效」或「判据有 bug」，实际是那些行根本没进 diff。
    调用方据此打一行提示，把「没扫到」和「扫了没问题」区分开。

    ★取不到清单时返回空列表（不打提示）而**不是**抛错：这只是一句提示，
    不该因为 git 不可用就让整个扫描失败——扫描本身的完整性由 diff 那条路径自己保证。
    """
    import subprocess

    base = Path(repo_root) if repo_root is not None else Path.cwd()
    cmd = ["git", "-C", str(base), "status", "--porcelain", "-z"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("[leakscan] git status 执行失败（%s），跳过未提交改动提示",
                       type(exc).__name__)
        return []
    if proc.returncode != 0:
        logger.warning("[leakscan] git status 退出码 %s，跳过未提交改动提示", proc.returncode)
        return []

    out: list[str] = []
    # porcelain -z 每段形如 ``XY<空格>path``，合法段最短 4 字符（末尾 split 还会多出一个空段）。
    # ★重命名/复制（X 或 Y 位为 R/C，见 git-status(1)）占**两段**：``R  new\0old``——
    #   旧路径紧跟其后单独成段、**没有 XY 前缀**，长度照样能 ≥4，上面的长度门滤不掉
    #   （实测字节：b'R  newname.py\0longoldname.py\0'）。曾把旧路径段也按普通段削首
    #   3 个字符混进结果，一次重命名还被计成 2 条，故必须按状态位有状态地消费。
    segments = iter(proc.stdout.decode("utf-8", errors="replace").split("\0"))
    for entry in segments:
        if not entry or len(entry) < 4:
            continue
        out.append(entry[3:])
        if entry[0] in "RC" or entry[1] in "RC":
            # 旧路径段消费掉、不入结果：改动内容如今活在新路径上，扫旧路径没有意义。
            # next 的 None 默认值兜住输出异常截断（R/C 段后旧路径缺失）——本函数只是
            # 一句提示，宁可少算一段也不抛 StopIteration。
            next(segments, None)
    return out


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
