"""config-chain 层②：方法作用域内的启发式 ``string→decrypt→sink`` 绑定（在 jadx 反编译的 Java 源码文本上）。

把「硬编码密文候选串 → 解密调用 → 下游 sink」绑成一条链，回答「哪个方法把某个密文解开、疑似流向哪里」。

★这是**启发式共现绑定，不是数据流 taint**（诚实边界）：
- 靠 jadx 反编译出的**真实方法边界**（括号配对、跳字符串/注释划作用域）在**同一方法体内**共现三要素——比
  ``crypto_recipe`` 的定长字符盲窗强在用真方法作用域（同方法≈真实 def-use 局部性），但**不追值传播**。
- 没有字节码/IR、androguard 被禁、apk 侧连 xref 图都不建（``core/apk.py``）→ 精确 taint 在本项目根本无底层
  数据可做，绝不伪装。产物是**人工复核线索**：「该方法里密文 X 疑似解密后流向 sink Y」，非证明级。
- 由 jadx 分析器在其**单次**反编译扫描里调用（不双跑 jadx）；缺 jadx 则整分析器被能力门控跳过。

纯函数、绝不抛（坏输入 → 空）。产 ``StringChain`` 数据（无 Finding 依赖，便于独立测），Finding 由调用方构造。
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from apkscan.core import infra

# Java 字符串字面量（含转义）。
_STR_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# 方法定义起点：``name(params) {``，name 非控制关键字（排除 if/for/while… 的块）。params 不含 ;{}() 括号，
# 故不跨语句、不吃嵌套泛型参数（少数复杂签名漏掉，可接受——启发式）。在**掩码文本**上匹配（见 _mask）。
_BLOCK_START_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*(?:throws[^{;]*)?\{")
_CONTROL_KW = frozenset({
    "if", "for", "while", "switch", "catch", "synchronized", "try", "do", "else", "return",
})
# 前邻 ``new`` → 匿名类体（``new X(){...}``），不当方法作用域（其内部真方法各自成体，不误并兄弟方法）。
_NEW_PREFIX_RE = re.compile(r"\bnew\s+$")

# 解密调用（Java crypto API + 通用 decrypt/base64 解码）。★不含裸 ``AES/`` transformation 串——那是常量非
# 调用（``Cipher.getInstance("AES/…")`` 已由 Cipher.getInstance 覆盖真解密点），单列它会把常量表方法误判有解密。
_DECRYPT_RE = re.compile(
    r"Cipher\.getInstance|\.doFinal\s*\(|Base64\.(?:decode|getDecoder)|SecretKeySpec"
    r"|IvParameterSpec|GCMParameterSpec|\.decrypt\s*\(",
    re.IGNORECASE,
)

# 无歧义**非密文**的 base64/PEM 前缀（免疫，避免内嵌证书/公钥/图片/cert-pin 与 Base64.decode 共现成假链）：
#   MII/MIG = DER ASN.1 SEQUENCE 的 base64（X.509 证书 / RSA·PKCS8 公私钥）；iVBORw0KGgo = PNG 头；sha256/ = OkHttp cert pin。
_NON_CIPHERTEXT_PREFIXES = ("MII", "MIG", "iVBORw0KGgo", "sha256/")
# 下游 sink（解出内容疑似流向：网络/加载/执行）。
_SINK_RE = re.compile(
    r"new\s+URL\s*\(|openConnection\s*\(|HttpURLConnection|OkHttpClient|Request\.Builder"
    r"|\.loadUrl\s*\(|\.newCall\s*\(|Runtime\.getRuntime|\.baseUrl\s*\(|Retrofit",
    re.IGNORECASE,
)

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")
_HEX_RE = re.compile(r"^[A-Fa-f0-9]{32,}$")

# 密文字面量**被直接当函数调用实参**：``ident("<密文>")``——覆盖**改名的解密 helper**（重度混淆样本里
# 解密函数被 jadx 改成 m1136x 之类，认不出标准 crypto API，但"密文被传进某函数"这一事实是确定的）。
_CONSUMER_RE = re.compile(r"(\w+)\s*\(\s*$")
# 明显非解密的常见方法名（密文传进这些多是存储/比较/日志，非解密）——降 AI 解密线索误报。混淆改名的
# helper 不在此列、照样命中（交 AI 试解密收敛）。
_CONSUMER_DENY = frozenset({  # 全小写（比对时 name.lower()）
    "equals", "contains", "startswith", "endswith", "indexof", "valueof", "println", "print",
    "format", "length", "hashcode", "compareto", "split", "replace", "matches", "put", "add",
    "get", "append", "log", "d", "e", "w", "i", "v",
})

_MAX_SECRETS_PER_METHOD = 8
_MAX_CHAINS_PER_FILE = 200
_MAX_TEXT_BYTES = 4 * 1024 * 1024  # 与 jadx.py 单文件上限一致
_MAX_SECRET_LEN = 2048  # 保留完整密文供 AI 解密（大多数配置密文 <2KB；仅防畸形超长字面量）


@dataclass(frozen=True)
class StringChain:
    """一条方法内共现链：某方法体里硬编码密文候选串 + 解密调用/被消费 (+ 下游 sink) 同现。启发式、非证明。

    两档：``decrypt_calls`` 非空 = 识别到标准解密 API（较强）；仅 ``consumer`` 非空 = 密文被传进某函数（疑似
    改名的解密 helper，弱，作 **AI 辅助解密线索**）。``secret`` 保留较完整密文供下游 AI/appcrypto 尝试解密。
    """

    secret: str  # 密文候选串（保留至 _MAX_SECRET_LEN 供解密）
    method: str  # 所在方法名（best-effort）
    decrypt_calls: tuple[str, ...]  # 命中的**标准**解密调用形态（可空）
    sinks: tuple[str, ...]  # 同方法内的下游 sink（可空）
    location: str  # 源文件相对路径
    consumer: str | None = None  # 密文被直接传进的函数名（疑似改名的解密 helper；None=未被直接消费）


def scan_java_source(text: str, location: str) -> list[StringChain]:
    """扫一份 Java 源码文本，产方法作用域内的 密文→解密/消费(→sink) 共现链。绝不抛。

    绑链门（二档，均在**同一方法体内**——方法级作用域，跨方法不误绑）：某密文候选串字面量满足其一即绑——
      ①方法内识别到**标准解密 API**（Cipher/doFinal/Base64.decode…，较强）；或
      ②该密文**被直接当函数调用实参** ``ident("<密文>")``（弱，疑似**改名的解密 helper**，作 AI 辅助解密线索）。
    只是**存着**没被消费、也没识别到解密的密文 → 不绑（避免纯常量误报）。sink 为可选上下文。
    """
    if not isinstance(text, str) or not text:
        return []
    if len(text) > _MAX_TEXT_BYTES:
        text = text[:_MAX_TEXT_BYTES]
    chains: list[StringChain] = []
    seen: set[tuple[str, str]] = set()
    for name, body in _extract_methods(text):
        candidates = [
            (lit, _consumer_before(body, m.start()) or _consumer_via_var(body, m.start()))
            for m in _STR_LIT_RE.finditer(body)
            if _looks_ciphertext(lit := m.group(1))
        ]
        if not candidates:
            continue
        decrypts = tuple(sorted({m.group(0).strip() for m in _DECRYPT_RE.finditer(body)}))
        sinks = tuple(sorted({m.group(0).strip() for m in _SINK_RE.finditer(body)}))
        for secret, consumer in candidates[:_MAX_SECRETS_PER_METHOD]:
            if not decrypts and consumer is None:  # 既无标准解密、又没被消费 → 不绑
                continue
            key = (name, secret[:64])
            if key in seen:
                continue
            seen.add(key)
            chains.append(StringChain(
                secret=secret[:_MAX_SECRET_LEN], method=name, decrypt_calls=decrypts,
                sinks=sinks, location=location, consumer=consumer,
            ))
            if len(chains) >= _MAX_CHAINS_PER_FILE:
                return chains
    return chains


def _consumer_before(body: str, quote_pos: int) -> str | None:
    """密文字面量若被**直接当函数实参**（``ident("…"``），返回被调函数名；否则 None。

    有界回看（引号前 64 字符内匹配 ``ident(``）；命中控制关键字或明显非解密的常见方法名（存储/比较/日志）→
    None（降误报）。改名的解密 helper（m1136x 之类）不在 denylist、照常返回，作 AI 解密线索。
    """
    match = _CONSUMER_RE.search(body[max(0, quote_pos - 64):quote_pos])
    if match is None:
        return None
    name = match.group(1)
    if name in _CONTROL_KW or name.lower() in _CONSUMER_DENY:
        return None
    return name


# 密文被**先赋值给局部变量、再解密**：``var = "<密文>"; … helper(var)``——混淆代码最常见写法（比直接实参更常见）。
# 方法内轻量 def-use（非全 taint）：抓赋值目标变量名，再看它是否作某调用的实参。单个 ``=`` 才算赋值（``==`` 因
# 尾随第二个 ``=`` 破坏 ``\s*$`` 天然不匹配）。
_ASSIGN_RE = re.compile(r"(\w+)\s*=\s*$")
_CALL_ARGS_RE = re.compile(r"(\w+)\s*\(([^;{}]*)\)")


def _consumer_via_var(body: str, quote_pos: int) -> str | None:
    """密文字面量若 ``var = "…"`` 赋给局部变量、且该变量随后被当某调用实参，返回被调函数名；否则 None。"""
    assign = _ASSIGN_RE.search(body[max(0, quote_pos - 48):quote_pos])
    if assign is None:
        return None
    var = assign.group(1)
    if var in _CONTROL_KW:
        return None
    var_re = re.compile(r"\b" + re.escape(var) + r"\b")
    for call in _CALL_ARGS_RE.finditer(body):
        callee = call.group(1)
        if callee in _CONTROL_KW or callee.lower() in _CONSUMER_DENY:
            continue
        if var_re.search(call.group(2)):  # 该变量出现在这个调用的实参里
            return callee
    return None


def _looks_ciphertext(value: str) -> bool:
    """字符串是否像硬编码密文/编码载荷：base64/hex 定长且够熵，或高熵编码串。

    收紧防误报：排除 URL（含 ``://``）与无歧义非密文前缀（证书/公钥/图片/cert-pin）；含 ``/`` 的 base64/hex
    命中补香农熵下限，杀掉类路径/文件路径（如 ``com/google/android/gms/common`` 熵低）而保留真密文（熵高）。
    """
    s = value.strip()
    if not (16 <= len(s) <= 4096):
        return False
    if "://" in s or s.startswith(_NON_CIPHERTEXT_PREFIXES):
        return False
    if _B64_RE.match(s) or _HEX_RE.match(s):
        # 含 '/' 的（类路径/文件路径也落 base64 字符类）须熵够高才算密文；不含 '/' 的定长 hex/base64 直接算。
        return "/" not in s or _entropy(s) >= 4.0
    return bool(infra.looks_like_encoding(s))


def _entropy(s: str) -> float:
    """字符串的香农熵（bit/char）。空串 → 0。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _extract_methods(text: str) -> list[tuple[str, str]]:
    """把源码切成 [(方法名, 方法体文本)]。

    ★先 _mask 出等长掩码文本（注释/字符串内容置空），在**掩码文本**上定位方法起点与括号配对——从根上封死
    「注释里的 ``name(){`` 被当方法起点」「字符串里的花括号破坏配对」两类跨方法误绑；方法体则从**原文**按同一
    下标切出（保留字符串里的密文内容供后续提取）。前邻 ``new`` 的匿名类体不当方法作用域；控制关键字块排除；
    配对失败（不平衡）的块跳过。
    """
    masked = _mask(text)
    methods: list[tuple[str, str]] = []
    for match in _BLOCK_START_RE.finditer(masked):
        if match.group(1) in _CONTROL_KW:
            continue
        if _NEW_PREFIX_RE.search(masked[max(0, match.start() - 16):match.start()]):
            continue  # ``new X(){...}`` 匿名类体：不当方法（内部真方法各自成体）
        open_idx = match.end() - 1  # 指向 '{'（掩码与原文同下标）
        end_idx = _match_block(masked, open_idx)
        if end_idx is not None:
            methods.append((match.group(1), text[open_idx + 1:end_idx]))  # body 从原文切，保留密文内容
    return methods


def _mask(text: str) -> str:
    """产**等长**掩码文本：注释（``//`` 行 / ``/* */`` 块）与字符串/字符字面量的**内容**置为空格（换行保留、
    引号定界符保留），代码原样。用于在无字符串/注释干扰下定位方法边界与配对花括号，下标与原文一一对齐。
    """
    chars = list(text)
    n = len(chars)
    state = 0  # 0=code 1=string(") 2=char(') 3=line-comment 4=block-comment
    i = 0
    while i < n:
        ch = chars[i]
        if ch == "\n":
            if state == 3:  # 行注释在换行处结束
                state = 0
            i += 1
            continue
        if state == 0:
            if ch == '"':
                state = 1
            elif ch == "'":
                state = 2
            elif ch == "/" and i + 1 < n and chars[i + 1] == "/":
                state = 3
                chars[i] = " "
            elif ch == "/" and i + 1 < n and chars[i + 1] == "*":
                state = 4
                chars[i] = " "
        elif state in (1, 2):
            if ch == "\\" and i + 1 < n:  # 转义：本字符与下一字符都掩掉（换行保留）
                chars[i] = " "
                if chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if (ch == '"' and state == 1) or (ch == "'" and state == 2):
                state = 0  # 闭定界符保留
            else:
                chars[i] = " "
        elif state == 4:
            if ch == "*" and i + 1 < n and chars[i + 1] == "/":
                chars[i] = " "
                chars[i + 1] = " "
                state = 0
                i += 2
                continue
            chars[i] = " "
        else:  # state == 3 行注释体
            chars[i] = " "
        i += 1
    return "".join(chars)


def _match_block(text: str, open_idx: int) -> int | None:
    """从 ``text[open_idx] == '{'`` 起做括号配对，返回配对 ``}`` 的下标；跳过字符串/字符字面量与行/块注释。

    不平衡（到文本尾仍未闭合）→ None。这是 def-use 作用域的**词法近似**，非编译级解析。
    """
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"' or ch == "'":
            i = _skip_string(text, i, ch)
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i = text.find("\n", i + 2)
                if i < 0:
                    return None
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                if end < 0:
                    return None
                i = end + 2
                continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _skip_string(text: str, i: int, quote: str) -> int:
    """从开引号 ``text[i] == quote`` 起跳到闭引号之后；处理 ``\\`` 转义。未闭合 → 文本尾。"""
    i += 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return n


__all__ = ["StringChain", "scan_java_source"]
