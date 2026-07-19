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
from dataclasses import dataclass, replace


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
# 类/枚举/接口体：额外当一个作用域扫——**字段常量密文召回**（``static K="密文"`` 在方法体外、``decrypt(K)`` 在
# 某方法里，两者同在类体内 → 复用"赋值再消费"逻辑绑上；同串在方法内已绑的按密文去重、不重复）。
_CLASS_START_RE = re.compile(r"\b(?:class|interface|enum)\s+(\w+)[^{;]*\{")

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
# 兜底档只受理**整串 token 形**（base64/base64url/hex 的字符集，无点、无空白、无括号冒号）。密文是编码后的
# 字节串，不会长成点分限定名（``a.b.C.KEY``）、含空格的句子（jadx 的 ``Method not decompiled: …`` 占位串）
# 或路径。★这一条是把「域名用的 looks_like_encoding」从密文判据里摘掉后的替代——后者按 ``.`` 切标签、只看
# 单个标签，于是整串含空格冒号也不设防，长 camelCase 类名（熵 4.0-4.2）必然过门。
_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
# base64 标准/URL-safe 字母表常量（codec 类里必有）：**满熵**（恰 6.0 bit/char）是字母表的特征、不是密文的
# 特征——熵下限护栏对它数学上不可能生效，只能显式排除。两种字母表共享这 62 字符前缀。
_B64_ALPHABET_RUN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# 多段路径（``/okhttp3/internal/publicsuffix/`` 熵 4.07）会擦过通用 4.0 下限；真 base64 密文实测 5.5+。
_PATH_SLASH_MIN = 2
_PATH_ENTROPY_MIN = 4.5
# 兜底档（收 ``_``/``-``）无 base64 标记时的熵下限：常量名实测 4.1-4.3、无填充 base64url 载荷 5.0+。
_TOKEN_ENTROPY_MIN = 4.5
# 字符两两不同的最短长度：短串偶然全不重复很常见，32 起才是"表"而非巧合。
_ALPHABET_MIN_LEN = 32
# 算法 transformation 串（``AES/CBC/PKCS5Padding`` / ``RSA/ECB/OAEPWithSHA-1AndMGF1Padding``）：常量非密文。
# ★形状 + 首段算法名双重锚定：只匹配整串形状会误伤——无填充的 base64 载荷恰有 ~20% 落在 ``词/词`` 形状里
# （3 的倍数字节、含 ``/``、不含 ``+``）。JCE transformation 恒以**算法名整段打头**（``AES/…``、``RSA/…``），
# 故要求首段精确等于已知算法名——随机 base64 首段恰等于 ``AES`` 的概率极低，误命中降到 0%。
_TRANSFORMATION_SHAPE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:/[A-Za-z][A-Za-z0-9-]*){1,3}$")
_TRANSFORMATION_ALGOS: frozenset[str] = frozenset({
    "AES", "DES", "DESEDE", "RSA", "BLOWFISH", "RC2", "RC4", "ARCFOUR",
    "CHACHA20", "SM2", "SM4", "TWOFISH", "IDEA", "CAST5", "CAST6", "SEED", "ARIA",
})

# ---------------------------------------------------------------------------
# 压制：实测噪音高度聚集于两类**可机械识别**的来源，且都不是 App 自有配置。
#
# ★压制 = **打标不丢弃**（``StringChain.suppressed``），由调用方决定是否呈现。两条规则的 key 都落在
#   **样本可控的输入**上（源文件路径由包名决定、hex 常量条数由字面量决定），静默返回 [] 会让"样本作者
#   把自有解密类重定位进 com/google/android/gms/internal/"或"往真密文的方法里掺 5 条裸 hex"直接换来
#   检测器对整个文件失明，且失明本身不留痕。打标后压制量可计数、可复核，规避手法至少是**可见**的。
# ---------------------------------------------------------------------------
#: 压制原因（``StringChain.suppressed`` 取值）。
SUPPRESSION_THIRD_PARTY = "third-party"
SUPPRESSION_PARAM_TABLE = "param-table"

# ① 第三方库路径：SDK 自带的混淆串（遥测地址、内置常量），非涉案主体资产。
_THIRD_PARTY_PREFIXES: tuple[str, ...] = (
    "io/dcloud/", "okhttp3/", "androidx/", "android/support/", "kotlin/", "kotlinx/",
    "com/google/", "com/android/", "org/bouncycastle/", "org/slf4j/", "org/apache/",
    "com/squareup/", "io/reactivex/", "com/tencent/", "com/alibaba/", "retrofit2/",
    "com/networkbench/", "org/json/", "javax/", "java/",
)
# ② 密码学参数表文件：单文件聚集多条纯 hex 常量 = 曲线参数/素数表（RFC3526、NIST/SM2 曲线、测试向量）。
#    ★按**文件**判条数、但**只标 hex 那些链**：混淆器会把 BouncyCastle 的包名也改成随机串，路径认不出来，
#    但"一个类里躺着几十条定长 hex 常量"这个形态改不掉——参数表按定义全是 hex，同文件里的 base64 密文链
#    不在"表"里，没有理由跟着一起压制（否则往真密文的方法掺 5 条裸 hex 就能整文件失明）。
_PARAM_TABLE_HEX_MIN = 5

# 第三方路径文件的**廉价预筛**：全文连一点标准解密 API 的影子都没有 → 不可能是"被重定位进第三方包名下的
# 自有解密类"，直接早退省掉整轮扫描。子串判比 _DECRYPT_RE 便宜 ~200 倍（实测 0.28 vs 54 ms/100KB），而
# 第三方目录在真实 APK 里占绝大多数文件，早退是这条路径的性能前提。
# ★去掉首字符 = 同时覆盖大小写两种写法（``Cipher``/``cipher``），与 _DECRYPT_RE 的 IGNORECASE 对齐；宁松勿紧
# （多放进来的只是多扫一遍，漏掉才是失明）。仅是预筛，判定仍由 _DECRYPT_RE 做。
_DECRYPT_HINTS: tuple[str, ...] = ("ipher", "oFinal", "ase64", "ecrypt", "ecretKeySpec", "arameterSpec")


def _is_third_party(location: str) -> bool:
    """源文件是否位于已知第三方库包路径下。"""
    low = location.replace("\\", "/").lower()
    return any(("/" + p.lower()) in ("/" + low) for p in _THIRD_PARTY_PREFIXES)


def _has_decrypt_hint(text: str) -> bool:
    """全文是否有标准解密 API 的迹象（廉价子串预筛，见 :data:`_DECRYPT_HINTS`）。"""
    return any(h in text for h in _DECRYPT_HINTS)

# 密文字面量**被直接当函数调用实参**：``ident("<密文>")``——覆盖**改名的解密 helper**（重度混淆样本里
# 解密函数被 jadx 改成 m1136x 之类，认不出标准 crypto API，但"密文被传进某函数"这一事实是确定的）。
_CONSUMER_RE = re.compile(r"(\w+)\s*\(\s*$")
# 明显非解密的常见方法名（密文传进这些多是存储/比较/日志，非解密）——降 AI 解密线索误报。混淆改名的
# helper 不在此列、照样命中（交 AI 试解密收敛）。
_CONSUMER_DENY = frozenset({  # 全小写（比对时 name.lower()）
    "equals", "contains", "startswith", "endswith", "indexof", "valueof", "println", "print",
    "format", "length", "hashcode", "compareto", "split", "replace", "matches", "put", "add",
    "get", "append", "log", "d", "e", "w", "i", "v",
    "remove", "forname",  # Map/Bundle 删键、Class.forName 反射加载——都不是解密
})
# 框架访问器形态（``getInt`` / ``putCharSequence`` / ``setTitle``）：存取而非解密。★混淆改名的解密 helper
# 实测是 1-3 字符（真实样本里两条真密文的 consumer 都是 ``x``），不长成 getXxx，故此规则不误伤它们。
_FRAMEWORK_ACCESSOR_RE = re.compile(r"^(?:get|put|set)[A-Z]")

_MAX_SECRETS_PER_METHOD = 8
_MAX_CHAINS_PER_FILE = 200
_MAX_TEXT_BYTES = 4 * 1024 * 1024  # 与 jadx.py 单文件上限一致
_MAX_SECRET_LEN = 2048  # 保留完整密文供 AI 解密（大多数配置密文 <2KB；仅防畸形超长字面量）


@dataclass(frozen=True)
class StringChain:
    """一条方法内共现链：某方法体里硬编码密文候选串 + 解密调用/被消费 (+ 下游 sink) 同现。启发式、非证明。

    两档：``decrypt_calls`` 非空 = 识别到标准解密 API（较强）；仅 ``consumer`` 非空 = 密文被传进某函数（疑似
    改名的解密 helper，弱，作 **AI 辅助解密线索**）。``secret`` 保留较完整密文供下游 AI/appcrypto 尝试解密。

    ``suppressed`` 非 None = 命中降噪规则（见模块内"压制"一节），调用方**默认不应呈现**，但拿得到条数与
    原因——压制是可计数、可复核的，不是静默丢弃。
    """

    secret: str  # 密文候选串（保留至 _MAX_SECRET_LEN 供解密）
    method: str  # 所在方法名（best-effort）
    decrypt_calls: tuple[str, ...]  # 命中的**标准**解密调用形态（可空）
    sinks: tuple[str, ...]  # 同方法内的下游 sink（可空）
    location: str  # 源文件相对路径
    consumer: str | None = None  # 密文被直接传进的函数名（疑似改名的解密 helper；None=未被直接消费）
    suppressed: str | None = None  # 压制原因（SUPPRESSION_*）；None=正常候选


def scan_java_source(text: str, location: str) -> list[StringChain]:
    """扫一份 Java 源码文本，产方法作用域内的 密文→解密/消费(→sink) 共现链。绝不抛。

    绑链门（二档，均在**同一方法体内**——方法级作用域，跨方法不误绑）：某密文候选串字面量满足其一即绑——
      ①方法内识别到**标准解密 API**（Cipher/doFinal/Base64.decode…，较强）；或
      ②该密文**被直接当函数调用实参** ``ident("<密文>")``（弱，疑似**改名的解密 helper**，作 AI 辅助解密线索）。
    只是**存着**没被消费、也没识别到解密的密文 → 不绑（避免纯常量误报）。sink 为可选上下文。

    两道降噪规则（见模块内"压制"一节）：第三方库路径下的命中、以及密码学参数表里的 hex 常量，产出时打
    ``suppressed`` 标而**不丢弃**——实测这两类占噪音的绝大部分且都非 App 自有资产，但两条规则的 key 都在
    样本可控的输入上，静默丢弃等于给规避手法留一条无痕通道。调用方默认不呈现 ``suppressed`` 非空的链。

    ★唯一的真早退：第三方路径**且**全文无任何标准解密 API 迹象（:func:`_has_decrypt_hint`）——这类文件既
    藏不住"标准解密绑定的密文"，又占真实 APK 文件数的绝大多数，扫它们纯是浪费。代价是这些文件里仅靠
    ``consumer`` 成立的**弱档**链不再被计数（那一档本就是噪音主源），换来第三方目录不必全量扫。
    """
    if not isinstance(text, str) or not text:
        return []
    third_party = _is_third_party(location)
    if third_party and not _has_decrypt_hint(text):
        return []
    if len(text) > _MAX_TEXT_BYTES:
        text = text[:_MAX_TEXT_BYTES]
    chains: list[StringChain] = []
    seen: set[str] = set()  # 按**密文**去重（本文件内）：嵌套方法/匿名类里的同串只出一条（外层方法先命中即保留）
    for name, body, is_class in _extract_scopes(text):
        candidates = [
            (lit, _consumer_before(body, m.start()) or _consumer_via_var(body, m.start()))
            for m in _STR_LIT_RE.finditer(body)
            if _looks_ciphertext(lit := m.group(1))
        ]
        if not candidates:
            continue
        # ★类作用域（is_class）**不看类级 decrypts / sinks**（太粗、会跨方法误绑）——只走"该密文被 consumer 消费"档。
        decrypts = () if is_class else tuple(sorted({m.group(0).strip() for m in _DECRYPT_RE.finditer(body)}))
        sinks = () if is_class else tuple(sorted({m.group(0).strip() for m in _SINK_RE.finditer(body)}))
        for secret, consumer in candidates[:_MAX_SECRETS_PER_METHOD]:
            if not decrypts and consumer is None:  # 既无标准解密、又没被消费 → 不绑
                continue
            key = secret[:64]
            if key in seen:
                continue
            seen.add(key)
            chains.append(StringChain(
                secret=secret[:_MAX_SECRET_LEN], method=name, decrypt_calls=decrypts,
                sinks=sinks, location=location, consumer=consumer,
                suppressed=SUPPRESSION_THIRD_PARTY if third_party else None,
            ))
            if len(chains) >= _MAX_CHAINS_PER_FILE:
                return _mark_param_table(chains)
    return _mark_param_table(chains)


def _mark_param_table(chains: list[StringChain]) -> list[StringChain]:
    """本文件若是密码学参数表（聚集 ≥``_PARAM_TABLE_HEX_MIN`` 条纯 hex 常量）→ 给**那些 hex 链**打压制标。

    真实样本里 BouncyCastle 被混淆器改了包名后路径认不出，但"一个类里躺着几十条定长 hex 常量"的形态
    改不掉——那是 RFC3526 素数 / NIST·SM2 曲线参数 / 测试向量，公开常量，不是 App 自有密文。
    ★条数按**文件**数、标记只落在 **hex 链**上：参数表按定义全是 hex，同文件里的 base64 密文不属于这张表。
    整文件压制会让"往真密文所在的方法里掺 5 条裸 hex 常量"直接换来该文件失明——阈值 key 在样本可控输入上，
    压制范围就必须收窄到规则真正解释得了的那部分。已有压制原因（第三方路径）的链保持原因不变。
    """
    if sum(1 for c in chains if _HEX_RE.match(c.secret)) < _PARAM_TABLE_HEX_MIN:
        return chains
    return [
        replace(c, suppressed=SUPPRESSION_PARAM_TABLE)
        if c.suppressed is None and _HEX_RE.match(c.secret)
        else c
        for c in chains
    ]


def _consumer_before(body: str, quote_pos: int) -> str | None:
    """密文字面量若被**直接当函数实参**（``ident("…"``），返回被调函数名；否则 None。

    有界回看（引号前 64 字符内匹配 ``ident(``）；命中控制关键字、明显非解密的常见方法名（存储/比较/日志）、
    框架访问器或**构造器**→ None（降误报）。改名的解密 helper（m1136x 之类）不在 denylist、照常返回，作
    AI 解密线索。

    ★构造器排除是纵深：jadx 对反编译失败的方法吐 ``throw new UnsupportedOperationException("Method not
    decompiled: …")``，密文侧与 consumer 侧同源自这一行错误，自己跟自己成链。
    """
    window = body[max(0, quote_pos - 64):quote_pos]
    match = _CONSUMER_RE.search(window)
    if match is None:
        return None
    name = match.group(1)
    if _is_non_decrypt_consumer(name) or _NEW_PREFIX_RE.search(window[:match.start()]):
        return None
    return name


def _is_non_decrypt_consumer(name: str) -> bool:
    """被调函数名是否明显不是解密 helper（控制关键字 / denylist / 框架访问器 / 异常构造器）。"""
    return (
        name in _CONTROL_KW
        or name.lower() in _CONSUMER_DENY
        or bool(_FRAMEWORK_ACCESSOR_RE.match(name))
        or name.endswith(("Exception", "Error"))
    )


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
        if _is_non_decrypt_consumer(callee):
            continue
        if var_re.search(call.group(2)):  # 该变量出现在这个调用的实参里
            return callee
    return None


def _looks_ciphertext(value: str) -> bool:
    """字符串是否像硬编码密文/编码载荷：base64/hex 定长且够熵，或高熵编码串。

    收紧防误报：排除 URL（含 ``://``）、无歧义非密文前缀（证书/公钥/图片/cert-pin）与 base64 字母表常量；
    含 ``/`` 的 base64/hex 命中补香农熵下限，杀掉类路径/文件路径（如 ``com/google/android/gms/common`` 熵低）
    而保留真密文（熵高）；兜底档只受理整串 token 形（见 :data:`_TOKEN_RE`）。
    """
    s = value.strip()
    if not (16 <= len(s) <= 4096):
        return False
    if "://" in s or s.startswith(_NON_CIPHERTEXT_PREFIXES):
        return False
    if _B64_ALPHABET_RUN in s or _looks_alphabet_table(s):
        return False  # 字母表/查找表常量（满熵，熵护栏数学上拦不住）
    if _is_transformation(s):
        return False  # ``RSA/ECB/OAEPWithSHA-1AndMGF1Padding`` 这类算法 transformation 串是常量非密文
    if _looks_sequential_bytes(s):
        return False  # ``000102…1E1F`` 这类顺序字节 = 标准测试向量
    if _HEX_RE.match(s):
        return True  # 定长 hex 串是二进制/密文；标识符不会全 hex
    if _B64_RE.match(s):
        if s.count("/") >= _PATH_SLASH_MIN and _entropy(s) < _PATH_ENTROPY_MIN:
            return False  # 多段 classpath/资源路径：落 base64 字母表但熵不够
        return _has_binary_hint(s)
    # 兜底：整串 token 形才判。★不再转发 infra.looks_like_encoding——那是「点分域名逐 label 找编码伪域名」
    # 的启发式，用在任意 Java 字面量上属语义误用。
    if not _TOKEN_RE.match(s):
        return False
    if not _has_binary_hint(s):
        return False
    # 兜底档比 _B64_RE 档宽（收 ``_`` ``-``，即 base64url 与各种常量名），故再加一道：要么带 base64 标记
    # （``=`` 填充 / ``+`` / ``/``），要么熵够高。实测这两类恰好分得开——真密文 z3G2E…zw== 熵仅 4.08 但有
    # ``=``；EGL_EXT_gl_colorspace_bt2020_hlg / TEMORARILY_DISABLE_… 这类常量名熵 4.1-4.3 且无标记；无填充的
    # 真 base64url 载荷熵 5.0+。只卡熵会连真密文一起杀，只看标记会放过无填充载荷，两者取或。
    return _has_b64_marker(s) or _entropy(s) >= _TOKEN_ENTROPY_MIN


def _has_b64_marker(s: str) -> bool:
    """含 base64 专属字符（``=`` 填充 / ``+`` / ``/``）——标识符常量不会有。"""
    return any(c in s for c in "=+/")


def _looks_alphabet_table(s: str) -> bool:
    """字母表/查找表常量：够长且**字符两两不同**。

    ★这是密文的反面特征：随机字节编码出的串必然重复字符（64 字符全不重复的概率趋近 0），而 base64 /
    base62 / 自定义置换表按定义每个字符恰好出现一次。比枚举具体字母表更通用（覆盖任意顺序与自定义表）。
    """
    return len(s) >= _ALPHABET_MIN_LEN and len(set(s)) == len(s)


def _is_transformation(s: str) -> bool:
    """整串像 ``算法/模式[/填充]`` 且**首段是已知 JCE 算法名**——常量非密文。

    首段锚定见 :data:`_TRANSFORMATION_ALGOS` 上方注释：只看形状会误伤 ~20% 的无填充 base64 载荷；
    要求首段精确等于算法名后误命中降到 0%（transformation 恒以算法名整段打头）。
    """
    if not _TRANSFORMATION_SHAPE.match(s):
        return False
    return s.split("/", 1)[0].upper() in _TRANSFORMATION_ALGOS


def _looks_sequential_bytes(s: str) -> bool:
    """顺序字节的 hex（``000102…1E1F``）= 标准测试向量/填充表，非密文。"""
    if not _HEX_RE.match(s) or len(s) % 2:
        return False
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return False
    if len(raw) < 8:
        return False
    return all((raw[i] - raw[i - 1]) % 256 == 1 for i in range(1, len(raw)))


def _has_binary_hint(s: str) -> bool:
    """真 base64/编码密文=随机字节编码，几乎必含**数字或 +/=** 且熵够高。

    纯字母 camelCase 标识符（``getUserDisplayNameAVChatKit``）、类路径、资源名（``config_showMenu…``）落在
    base64 字母表内但无此特征、熵也偏低——两道一起排除。
    """
    has_hint = any(c.isdigit() for c in s) or "+" in s or "=" in s
    return has_hint and _entropy(s) >= 4.0


def _entropy(s: str) -> float:
    """字符串的香农熵（bit/char）。空串 → 0。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _extract_scopes(text: str) -> list[tuple[str, str, bool]]:
    """把源码切成 ``[(作用域名, 体文本, is_class)]``——方法体（is_class=False）+ 类/枚举/接口体（is_class=True）。

    ★先 _mask 出等长掩码文本（注释/字符串内容置空），在**掩码文本**上定位起点与括号配对——从根上封死「注释里的
    ``name(){`` 被当方法起点」「字符串里的花括号破坏配对」两类误绑；体则从**原文**按同一下标切出（保留密文内容）。
    前邻 ``new`` 的匿名类体不当方法作用域；控制关键字块排除；配对失败（不平衡）的块跳过。类体额外成域用于字段常量召回。
    """
    masked = _mask(text)
    scopes: list[tuple[str, str, bool]] = []  # (作用域名, 体文本, is_class)
    for match in _BLOCK_START_RE.finditer(masked):
        if match.group(1) in _CONTROL_KW:
            continue
        if _NEW_PREFIX_RE.search(masked[max(0, match.start() - 16):match.start()]):
            continue  # ``new X(){...}`` 匿名类体：不当方法（内部真方法各自成体）
        open_idx = match.end() - 1  # 指向 '{'（掩码与原文同下标）
        end_idx = _match_block(masked, open_idx)
        if end_idx is not None:
            scopes.append((match.group(1), text[open_idx + 1:end_idx], False))  # body 从原文切、保留密文内容
    # 类/枚举/接口体也各成一个作用域（is_class=True）：召回"字段常量密文 + 方法内解密"（方法作用域切不到的类级
    # 字段）。★类作用域**只走"该密文被某调用消费"档**、不走"类里有某解密"档——否则类里任一 decrypt 会把无关密文
    # 全绑上（盲窗在类粒度复活、跨方法误绑）。放在方法之后 → 方法内已绑的同串按密文去重先保留（标签更精确）。
    for match in _CLASS_START_RE.finditer(masked):
        open_idx = match.end() - 1
        end_idx = _match_block(masked, open_idx)
        if end_idx is not None:
            scopes.append((f"class:{match.group(1)}", text[open_idx + 1:end_idx], True))
    return scopes


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


__all__ = [
    "SUPPRESSION_PARAM_TABLE",
    "SUPPRESSION_THIRD_PARTY",
    "StringChain",
    "scan_java_source",
]
