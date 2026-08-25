"""高敏值脱敏（隐私安全）。

fxapk 会提取个人隐私数据 / 钱包私钥助记词 / 后端凭据 / 运行时登录态等**高敏值**。

``digest`` **默认脱敏**（`fxapk digest <报告>` 不带参数即已脱敏）；要明文原值须显式
`--no-redact`。明文始终在本地完整 report.json 里，不受这个开关影响。脱敏后消费方仍看得到
「存在哪类高敏线索 + 后续去向」，只是拿不到原值。

★**保护范围仅限 digest**——别以为「装了脱敏」就等于整个工具的输出都安全了：

- 受本开关保护：``fxapk digest``；
- **不受保护、原样输出**：``fxapk jsonl`` / ``fxapk diff`` / ``fxapk lead show|restore|replay`` /
  ``fxapk corpus events|ls|seen|shared-config|shared-native|shared-build-env|link-candidates`` /
  ``fxapk corpus link-discover|link-explain|link-groups --evidence-values raw`` /
  ``fxapk probe-leads`` /
  ``fxapk pcap-leads``（都明确面向 agent 消费，各自在运行时打一行提醒；权威名单以
  :data:`UNREDACTED_AGENT_COMMANDS` 为准，corpus 那几条经台账的 ``key_iocs`` 带出线索原值，
  而那份台账不按类别过滤高敏）、``fxapk export`` 的 CSV、HTML / PDF 报告、``letters`` 文书、
  ``corpus add`` 的存证、``case close`` 的回写、以及 ``report.json`` 本身。这些多半就该是
  本地证据载体，但把它们贴给第三方服务时**没有任何东西替你挡着**。

★脱敏是**尽力而为**，不是完整的 DLP。确切的保证只有两条：

  1. 高敏类别（见 :data:`SENSITIVE_CATEGORIES`）的 ``value`` 按类别 mask；
  2. **lead 自身**的若干自由文本字段（见 ``report.digest._compact_lead``）里，邮箱 / 国内手机号
     / 身份证号 / 长数字串这几类**有固定形态**的东西被 :func:`scrub_pii` 抹掉。

  这两条之外一律原样，包括：``findings[].title``、``visibility`` 的 notes 与 next_actions、
  ``closure`` 的 gaps / next_actions / source_summary、以及整个 ``overseas_targets``。
  姓名、地址、护照号、境外号码这类没有稳定形态的东西任何位置都抹不掉。
  把覆盖面铺到 digest 的全部字符串叶节点是待办，**在那之前别把它当成「输出已净化」**。
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit
import sys

#: 会把线索原值打到 stdout、且**不做任何脱敏**的命令。它们不受 ``digest`` 那个开关保护——
#: 只写 docstring 挡不住任何人，故各自在运行时真打一行。
#:
#: ★**这份名单是人工维护的，必然滞后**。复审里连着三轮各补出一批（先是 jsonl，再是 diff 与
#:   corpus events，再是 corpus ls/seen 与三条 lead 子命令）——每次都是「以为列全了」。
#:   新增命令时**别指望有人记得回来加**：判断方法是问一句「它的 stdout 里会不会出现
#:   ``Lead.value`` 或台账的 ``key_iocs``」，会就加进来。
#:   真正的出路是反过来做——让输出线索的命令默认走脱敏、显式声明才给明文，那是另一刀。
UNREDACTED_AGENT_COMMANDS: frozenset[str] = frozenset(
    {
        # 直接输出报告里的 Lead.value
        "jsonl", "diff", "lead show", "lead restore", "lead replay",
        # 输出 corpus 里的 lead
        "corpus events",
        # 经台账的 key_iocs 带出线索原值（那份台账不按类别过滤高敏）
        "corpus ls", "corpus seen", "corpus shared-config", "corpus shared-native",
        "corpus shared-build-env", "corpus link-candidates",
        # 标签引导发现默认 omit 安全；只有显式 raw 会带出家族标识和技术锚原值
        "corpus link-discover --evidence-values raw",
        "corpus link-explain --evidence-values raw",
        "corpus link-groups --evidence-values raw",
        # 无 -o 时把新生成的线索台账直接打到 stdout
        "probe-leads", "pcap-leads",
    }
)


def warn_unredacted_agent_output(command: str, *, safe_alternative: str | None = None) -> None:
    """往 **stderr** 打一行「本命令不脱敏」的警告。

    ★必须走 stderr：这些命令的 stdout 是给机器解析的数据流（JSONL / JSON），掺一行非数据进去
      会把下游的 ``| jq`` 打坏。走 stderr 则管道里干干净净，而人在终端上照样看得见。
    """
    alternative = (
        f"可改用 `{safe_alternative}` 输出不含原始标识符的聚合结果。"
        if safe_alternative
        else "本命令暂无等价安全导出，原始输出不要直接交给第三方服务。"
    )
    print(
        f"⚠ {command} 不做脱敏：输出里**若含**高敏值（钱包私钥/助记词、后端凭据、个人隐私数据），"
        "会原样带出。`fxapk digest` 只处理报告摘要，不能替代本命令的输出；"
        + alternative,
        file=sys.stderr,
    )


#: 高敏类别：其 value 在 agent 摘要里默认脱敏（明文只留本地完整报告）。
#: ★ 须与 models.LeadCategory 的高敏类目**同步维护**：新增「可直接控资金 / 登录 / 含受害人 PII /
#: 可解全部流量」的类别时务必加进来，否则会绕过 digest 脱敏。
SENSITIVE_CATEGORIES = frozenset(
    {
        "WALLET_SECRET",  # 钱包私钥 / 助记词
        "BACKEND_CREDENTIAL",  # 后端 / 管理凭据
        "RUNTIME_CREDENTIAL",  # 运行时登录态 / 凭据
        "VICTIM_DATA",  # 受害人物证（PII）
        "CRYPTO_RECIPE",  # 应用层加密配方（含 key/iv，凭此可解全部加密流量）
        "REMOTE_CONTROL",  # 无障碍远控劫持的被害人银行/支付 app（含被害人关联；动态侧已标高敏，须同步脱敏）
    }
)


def mask(value: str) -> str:
    """中间脱敏：保留首尾少量字符与长度信息，不泄露明文。"""
    s = str(value or "")
    if not s:
        return s
    if len(s) <= 8:
        return "***（已脱敏）"
    return f"{s[:3]}***{s[-2:]}（已脱敏，{len(s)} 字符）"


def redact_value(category: object, value: object) -> object:
    """高敏类别的 value → 脱敏；其余原样返回。

    非字符串高敏 value（如携带 key/iv 的 dict/list、数字）先 str() 再脱敏——否则会绕过
    脱敏把明文带进可能经云端模型处理的 agent 上下文。value 为 None 时原样放行（非敏感物证）。
    """
    if str(category or "") in SENSITIVE_CATEGORIES and value is not None:
        return mask(value if isinstance(value, str) else str(value))
    return value


#: 结构化 PII 模式（用于自由文本兜底脱敏）：邮箱 / 中国手机号 / 18 位身份证 / 银行卡等长数字串。
#: ★顺序有意：先邮箱，再身份证(18)，再手机(11)，最后泛长数字(13-19)——避免长数字规则先吞掉身份证/卡号的语义。
_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),        # email
    re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),        # 18 位身份证
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),         # 中国大陆手机号
    re.compile(r"(?<!\d)\d{13,19}(?!\d)"),           # 银行卡 / 其它长数字串
)
_PII_MASK = "***（PII已脱敏）"


def scrub_pii(text: object) -> tuple[str, bool]:
    """从**自由文本**里抹除结构化 PII（邮箱/手机号/身份证/银行卡长数字），返回 ``(脱敏后文本, 是否命中)``。

    用于 digest --redact 对 subject/notes/where_to_request/evidence_to_obtain 等自由文本兜底——
    这些字段不经 value 的类别脱敏，动态侧一旦把受害人手机号/证件号写进去，会绕过脱敏带进云端 agent。
    ★局限（如实标注）：只抹**结构化**模式；姓名、地址等非模式化 PII 无法可靠正则识别，须靠上游不写入明文。
    """
    s = str(text or "")
    if not s:
        return s, False
    hit = False
    for pat in _PII_PATTERNS:
        s, n = pat.subn(_PII_MASK, s)
        if n:
            hit = True
    return s, hit


_URL_TOKEN_RE = re.compile(
    r"""(?ix)
    \b
    (?:
        https?|wss?|ftp
    )
    ://
    [^\s<>"'\]\[(){}]+
    """
)

_URL_HASH_LENGTH = 12
_REDACTED_URL = "<redacted-url>"
_REDACTED_QUERY = "***"
_REDACTED_FRAGMENT = "***"


def _url_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[
        :_URL_HASH_LENGTH
    ]


def _safe_netloc(parts: SplitResult) -> str:
    """Build a netloc without URL userinfo."""
    hostname = parts.hostname
    if not hostname:
        return ""

    # urlsplit().hostname removes IPv6 brackets.
    host = f"[{hostname}]" if ":" in hostname else hostname

    try:
        port = parts.port
    except ValueError:
        # An invalid port makes the URL unsafe to reproduce in logs.
        return ""

    return f"{host}:{port}" if port is not None else host


def redact_url(value: object, *, include_fingerprint: bool = True) -> str:
    """Return a stable URL representation safe for logs and error artifacts.

    The representation removes userinfo and replaces query and fragment
    contents. It never returns the original value when parsing fails.
    """
    raw = value if isinstance(value, str) else str(value)
    fingerprint = _url_fingerprint(raw)

    try:
        parts = urlsplit(raw)
        netloc = _safe_netloc(parts)

        if not parts.scheme or not netloc:
            rendered = _REDACTED_URL
        else:
            rendered = urlunsplit(
                (
                    parts.scheme.lower(),
                    netloc,
                    parts.path,
                    _REDACTED_QUERY if parts.query else "",
                    _REDACTED_FRAGMENT if parts.fragment else "",
                )
            )
    except (TypeError, ValueError, UnicodeError):
        rendered = _REDACTED_URL

    if include_fingerprint:
        return f"{rendered} [url:{fingerprint}]"
    return rendered


def scrub_urls(text: object) -> tuple[str, bool]:
    """Redact absolute URLs embedded in free text."""
    raw = text if isinstance(text, str) else str(text)
    changed = False

    def replace(match: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return redact_url(match.group(0))

    return _URL_TOKEN_RE.sub(replace, raw), changed


def safe_exception_text(
    exc: BaseException,
    *,
    include_message: bool = False,
) -> str:
    """Return an exception representation safe for logs and artifacts.

    Type-only output is the default because URL redaction cannot prove that
    arbitrary exception text contains no other credentials.
    """
    exception_type = type(exc).__name__
    if not include_message:
        return exception_type

    message, _ = scrub_urls(str(exc))
    message, _ = scrub_pii(message)
    message = message.strip()
    return f"{exception_type}: {message}" if message else exception_type
