"""api_surface 分析器：提取后端 HTTP **接口路径**并做功能语义标注。

为什么做接口面（而不是从代码行为反推）：**接口名自证后端功能**。一条 ``/api/home/getContactList``
直接说明后端有「取通讯录」的服务端逻辑，比从字节码里反推「这段代码在读联系人」可靠得多——反推会被
混淆/反射/native 化打断，而路径字符串是后端与客户端的硬约定、藏不住。实测一个 Flutter 样本的
``libapp.so`` 暴露 163 条接口，直接读出通讯录窃取 / 域名存活上报 / 远程配置下发 / R2 对象存储 /
博彩 / 资金充提 / AI 换脸等功能。

★ 三层误报过滤（判据来自实测，非拍脑袋；每层注释注明标定拦截量）：
  1. 路径任一段大写开头 = Java 类/包描述符（DEX 里 ``Lcom/…/api/CommonStatusCodes;`` 被切出
     ``/api/CommonStatusCodes``），不是 HTTP 接口——实测拦下 42484 次原始命中。
  2. ``zza/zzb/zaa/zab`` 形态 = R8 / Play Services 混淆占位类名（``/api/accounttransfer/zza``）。
  3. **单样本内无法用「跨样本 ≥5 次 = 通用第三方库」这条频次判据**（见 ``_SDK_FIRST_SEGMENTS``
     注释：单样本看不到别的样本、无从统计频次），改用等价的「已知第三方 SDK 命名空间首段」清单。
  三层过滤后：779 条候选 → 547 条自有接口（实测）。

不产 Lead（务必守住）：**URL path 不是可发函的调证对象**——发函对象是域名 / IP（向注册商 / 云厂商
调证），一条接口路径既不对应一个可归属的主体、也无处发函。故本分析器只写 Finding + meta，``leads``
恒空。接口路径的价值在于**功能自证**与**给下游拼 URL**（见 ``config_endpoints``），不进调证线索流。

★ 关键设计：带「远程配置下发」语义的路径**单列** ``meta['api_surface']['config_endpoints']``，
因为下游 config-chain（APK→配置 URL→加密配置→动态域名/IP 池）要用它拼配置 URL 做主动探测。

约束：只依赖 AnalysisContext 公开接口（dex_strings / native_libs / list_files / read_file /
declared_size）；单源扫描 try/except + logging，绝不把异常抛给调用方；单文件 size 上限 + 累计预算
（对齐 native_obfuscation 的有界读范式）；全程 type hints。
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    app_so_paths,
    collect_dex_strings,
    is_text_resource,
)
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Finding, Severity
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# --- 提取正则 ---------------------------------------------------------------
# 只认带「接口命名空间」首段的路径：api / v1~v9 / app / client / mobile / gateway / open。
# 要求前缀段**整段**紧跟 `/`（`/apixyz/…` 不会误命中），且其后 ≥1 个业务段。段字符限
# `[A-Za-z0-9_.-]`——天然在 `?`/`;`/`"`/空格 处停下（自动切掉 query 串与 DEX 描述符尾 `;`）。
# str 与 bytes 两版同源（.so 里直接按字节找，省一次全量解码）。
_PREFIX_ALT = r"(?:api|v[1-9]|app|client|mobile|gateway|open)"
_PATH_RE = re.compile(r"/" + _PREFIX_ALT + r"(?:/[A-Za-z0-9_.\-]+)+")
_PATH_RE_BYTES = re.compile(rb"/(?:api|v[1-9]|app|client|mobile|gateway|open)(?:/[A-Za-z0-9_.\-]+)+")

# 第 2 层：R8 / Play Services 混淆占位类名（zza/zzb/zaa/zab/zzc…）。minifier 生成的 2~5 字符
# 占位名，真实接口动作名不会长这样。限 `z` + {a,b,z} + 1~3 小写，避免误伤长真词。
_R8_OBFUSCATED = re.compile(r"^z[abz][a-z]{1,3}$")

# 第 3 层：已知第三方 SDK 的命名空间**首段**（紧跟 api/前缀的那一段）。
# ★为何不用任务原判据「跨样本出现 ≥5 次 = 通用第三方库」：那需要**跨样本视角**，而分析器每次只看
#   **一个**样本、看不到别的样本，无从统计频次。等价替代 = 一份「已知第三方 SDK 命名空间首段」清单：
#   这些段由 DEX 类描述符 `com.google.android.gms.<pkg>.api.<seg>` / firebase 等经本正则切出
#   `/api/<seg>/…`，是库自带、非本样本团伙自有。
# ★只匹配**首段**（gms 家族的 SDK 段恒在 `.api.` 后的首位），不匹配任意段——否则会误伤把这些词
#   用作**叶子动作**的真接口（如 `/api/home/signin` 的 signin 在叶子、`/api/user/identity` 的
#   identity 在叶子，均属真业务，不该当 SDK 弃）。
# ★刻意**不含** auth/common/pay/wallet/billing 等歧义词：它们既是 SDK 词也是常见真接口段
#   （`/api/auth/login`、`/api/wallet/withdraw`）；这些词的 SDK 形态（`…api.CommonStatusCodes`、
#   `billingclient.api.BillingClient`）叶子恒大写、已被第 1 层拦截，无需再入本清单。
_SDK_FIRST_SEGMENTS: frozenset[str] = frozenset(
    {
        "accounttransfer", "credentials", "signin", "internal", "sharedpreferences",
        "gms", "firebase", "firebaseinstallations", "firebaseinstanceid",
        "measurement", "wearable", "safetynet", "recaptcha", "phenotype",
        "clearcut", "instantapps", "tapandpay", "fido", "identity",
    }
)

# 第 4 层：叶子是**编译型语言源码/头文件**——那是被编进 .so 的 `__FILE__` 断言串与调试路径
# （WebRTC 的 `/api/audio/audio_frame.cc`、`/client/basic_port_allocator.cc`），不是后端接口。
# 段字符集含 `.`，正则天然吃得下扩展名，故必须在此显式排除。
# ★只列**编译型**扩展：`.php`/`.jsp`/`.do`/`.action`/`.aspx` 是真实后端接口形态，绝不能进；
#   `.py`/`.js`/`.ts` 两可（既可能是源码路径也可能是真实 web 路由），取召回不排除。
_SOURCE_FILE_EXTS: frozenset[str] = frozenset(
    {
        ".c", ".cc", ".cpp", ".cxx", ".c++",
        ".h", ".hh", ".hpp", ".hxx", ".h++", ".inc", ".ipp",
        ".m", ".mm", ".java", ".kt", ".kts", ".go", ".rs", ".swift",
        ".s", ".asm", ".proto", ".pb", ".idl", ".aidl",
    }
)

# 第 5 层：段内含 `.` 的**代码符号**（Go/Java 符号表被当接口路径）。实测多份真样本 .so 里
# gomobile 的绑定层符号 `golang.org/x/mobile/bind` 整片被收录成 `/mobile/bind/seq.Delete`、
# `/mobile/bind/java.setContext` —— 命中 `mobile` 前缀但根本不是后端接口。
# ★不能按 `/mobile/bind/` 前缀一刀切：`/mobile/bind/card`（绑卡）是完全可能的真实接口。
#   判据落在**点后串的形态**上：真实 web 路径的扩展名恒为小写字母（php/jsp/do/json/html），
#   而代码符号的点后是导出名（含大写）、编译器生成后缀或序号。
_GO_GENERATED_SUFFIX = re.compile(r"^(?:init|func|deferwrap|gowrap|glob|stub)\d*$")


def _looks_like_code_symbol(seg: str) -> bool:
    """段形如 ``pkg.Symbol`` / ``pkg.`` / ``pkg.init.0`` → 代码符号而非接口路径段。"""
    dot = seg.rfind(".")
    if dot < 0:
        return False
    tail = seg[dot + 1:]
    if not tail:                       # 尾点：字符串表边界截断产物（`seq.`）
        return True
    if tail.isdigit():                 # `seq.init.0`
        return True
    if any("A" <= c <= "Z" for c in tail):   # 导出名 / 驼峰（Delete、setContext、countedObj）
        return True
    return bool(_GO_GENERATED_SUFFIX.match(tail))

# --- 读取上限 / 预算（对齐 native_obfuscation 范式）--------------------------
_MAX_LIBS = 60
_MAX_SO_BYTES = 64 * 1024 * 1024          # 单 .so 读入上限（.so 可合法较大）
_MAX_TOTAL_SO_BYTES = 256 * 1024 * 1024   # 全部 .so 累计预算
_MAX_ASSET_BYTES = 4 * 1024 * 1024        # 单 asset 读入上限（配置类小文件）
_MAX_TOTAL_ASSET_BYTES = 64 * 1024 * 1024 # 全部 asset 累计预算
_MAX_ASSETS = 500                          # 扫描 asset 数上限

_MAX_EVIDENCE = 12

# --- 功能语义标注 -----------------------------------------------------------
# 只对**强特征**下判断（宁可不标不误标）。判据子串取自实测接口名，均为**具体动作词/组合**而非
# 泛化词——不用裸 `sms`/`contact`/`report`（会把 OTP 下发、客服联系、埋点误标成窃取），只认
# getContactList / uploadSms / domainCheckReport 这类无歧义组合。匹配在 squashed 形（小写去所有
# 非字母数字）上做，对分隔符风格（r2upload_info vs r2uploadInfo）鲁棒。
SEM_CONTACT = "通讯录窃取"
SEM_SMS = "短信窃取"
SEM_DOMAIN = "域名存活上报"
SEM_CONFIG = "远程配置下发"
SEM_STORAGE = "对象存储上传"
SEM_FINANCE = "资金充提兑换"
SEM_GAMBLING = "博彩彩票"
SEM_FACE = "AI换脸"
SEM_AUTH = "账号认证"
SEM_TELEMETRY = "埋点回传"
SEM_DEVICE = "设备指纹"
SEM_LOCATION = "位置采集"

_CONTACT_MARKERS = (
    "getcontactlist", "contactlist", "uploadcontact", "uploadcontacts",
    "addressbook", "readcontact", "synccontact", "allcontact", "phonecontact",
)
_SMS_MARKERS = ("smslist", "uploadsms", "getsms", "readsms", "smsrecord", "smsupload", "mmslist")
_DOMAIN_MARKERS = (
    "domaincheck", "checkdomain", "domainreport", "domainstatus",
    "reportdomain", "domainalive", "domainping", "domainlist",
)
_STORAGE_MARKERS = (
    "r2upload", "ossupload", "s3upload", "cosupload", "uploadtoken",
    "ststoken", "storagetoken", "ossconfig", "getuploadinfo",
)
_FINANCE_MARKERS = ("recharge", "withdraw", "deposit", "topup", "cashout", "payout", "exchange")
_GAMBLING_MARKERS = ("lottery", "caipiao", "casino", "gamble", "gambl", "sabong", "betting")
_FACE_MARKERS = ("changeface", "faceswap", "swapface", "myface", "aiface", "facechange")
_AUTH_MARKERS = ("login", "register", "sendcode", "verifycode", "getcode", "resetpassword", "logout")
_TELEMETRY_MARKERS = (
    "buriedpoint", "datareport", "eventreport", "uploadlog", "logreport",
    "statreport", "trackevent", "reportevent", "collectlog",
)
_DEVICE_MARKERS = (
    "deviceinfo", "fingerprint", "deviceid", "devicefinger", "collectdevice",
    "reportdevice", "devicefp",
)
_LOCATION_MARKERS = (
    "getlocation", "uploadlocation", "reportlocation", "geolocation",
    "gpsinfo", "latlng", "locationreport",
)
# 远程配置下发：叶子恰为配置名，或 squashed 含拉配置动作。叶子精确匹配比子串更稳
# （避免 `configinfo` 之类进 config_endpoints 又不影响真拉配置接口的召回）。
_CONFIG_LEAVES: frozenset[str] = frozenset(
    {
        "config", "getconfig", "appconfig", "initconfig", "sysconfig", "systemconfig",
        "remoteconfig", "configinfo", "clientconfig", "mobileconfig", "baseconfig",
        "commonconfig", "getappconfig", "getsysconfig", "loadconfig", "pullconfig",
    }
)
_CONFIG_MARKERS = (
    "getconfig", "appconfig", "remoteconfig", "initconfig", "systemconfig",
    "commonconfig", "loadconfig", "pullconfig",
)

# 强语义（每个另产一条独立 Finding），固定顺序 → Finding 产出稳定可回归。
_STRONG_SEMANTICS: tuple[str, ...] = (
    SEM_CONTACT, SEM_SMS, SEM_DOMAIN, SEM_CONFIG, SEM_STORAGE, SEM_FINANCE, SEM_GAMBLING, SEM_FACE,
)

# 强语义 → (Finding id, 严重度, category, 单句「为什么重要」)。
_SEMANTIC_META: dict[str, tuple[str, Severity, str, str]] = {
    SEM_CONTACT: (
        "API-SEMANTIC-CONTACT-THEFT", Severity.HIGH, "data_exfiltration",
        "接口自证后端有「取通讯录」服务端逻辑——通讯录窃取的**直接证据**，是受害人被精准诈骗/"
        "催收骚扰的源头，取证应据此向后端调取上传记录。",
    ),
    SEM_SMS: (
        "API-SEMANTIC-SMS-THEFT", Severity.HIGH, "data_exfiltration",
        "接口自证后端有「取/传短信」逻辑——短信（含验证码）窃取，是 OTP 接管、盗刷的基础设施。",
    ),
    SEM_DOMAIN: (
        "API-SEMANTIC-DOMAIN-ROTATION", Severity.HIGH, "backend_surface",
        "接口自证后端维护**域名存活探测/上报**逻辑 → 后端有**域名轮换池**（域名被封即换新），"
        "是持续监控与主动下载的重要锚点：轮换池里的备用域名往往是尚未曝光的落地资产。",
    ),
    SEM_CONFIG: (
        "API-SEMANTIC-REMOTE-CONFIG", Severity.MEDIUM, "backend_surface",
        "远程配置下发接口 = config-chain 入口：App 运行时据此拉取（多为加密的）配置，内含动态"
        "域名/IP 池、OSS/R2 对象地址。★该路径已单列 meta['api_surface']['config_endpoints']，"
        "供下游拼配置 URL 做（授权）主动探测。",
    ),
    SEM_STORAGE: (
        "API-SEMANTIC-OBJECT-STORAGE", Severity.MEDIUM, "backend_surface",
        "接口自证后端使用对象存储（R2/OSS/COS/S3）承载上传件——受害人物证（人脸/证件/通讯录导出）"
        "常落在此，是向云存储厂商调取对象与访问日志的锚点。",
    ),
    SEM_FINANCE: (
        "API-SEMANTIC-FINANCE", Severity.MEDIUM, "fraud_business",
        "接口自证后端有充值/提现/兑换资金动作——诈骗资金流的业务面，用于重建资金链路。",
    ),
    SEM_GAMBLING: (
        "API-SEMANTIC-GAMBLING", Severity.MEDIUM, "fraud_business",
        "接口自证后端含博彩/彩票业务——定性该 App 涉赌的功能证据。",
    ),
    SEM_FACE: (
        "API-SEMANTIC-FACE-SWAP", Severity.HIGH, "fraud_business",
        "接口自证后端有 AI 换脸功能——用于伪造人脸过活体/KYC 或制作诈骗素材，高危。",
    ),
}


#: 驼峰切分点：小写/数字→大写（``uploadContact``），或大写连缀后接大写+小写（``getSMSList``）。
#: 在 lower() **之前**切，否则驼峰边界丢失、词边界判据会把 ``uploadContactList`` 误判成一个词。
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _squash_with_word_bounds(path: str) -> tuple[str, frozenset[int], frozenset[int]]:
    """把路径压成 squashed 形，并给出**词首/词尾**在 squashed 中的下标集合。

    词 = 按 ``/``、``_``、``-``、``.`` 等非字母数字分隔，外加驼峰边界切出的片段。
    返回 ``(squashed, 词首下标集, 词尾下标集)``。

    为什么需要它：marker 此前在 squashed 上做**裸子串**搜索，会跨词粘出假词——实测
    ``/api/rtc_event_log_output_file.cc`` 压成 ``…logoutputfile…``，``logout`` 落在
    ``log`` 尾 + ``output`` 头之间，被标成「账号认证」。要求 marker 的起点是某词词首、
    终点是某词词尾，即可整类消除跨词粘连，且对 ``upload_contact_list`` /
    ``uploadContactList`` 这类**真**跨词组合零损召回（它们的起止本就落在词边界上）。
    """
    marked = _CAMEL_BOUNDARY.sub("\x00", path).lower()
    out: list[str] = []
    starts: set[int] = set()
    ends: set[int] = set()
    at_word_start = True
    for ch in marked:
        if ch.isascii() and (ch.isalpha() or ch.isdigit()):
            if at_word_start:
                starts.add(len(out))
                at_word_start = False
            out.append(ch)
        else:
            if not at_word_start:
                ends.add(len(out) - 1)
            at_word_start = True
    if not at_word_start and out:
        ends.add(len(out) - 1)
    return "".join(out), frozenset(starts), frozenset(ends)


def semantics_for(path: str) -> list[str]:
    """对一条接口路径做功能语义标注，返回命中的中文标签列表（可空；纯函数便于单测）。

    只对**强特征**下判断（宁可不标不误标）：判据均为具体动作词/组合，不用裸 sms/contact/report。
    marker 须**整词对齐**（起点是词首、终点是词尾），不接受跨词粘出来的子串。
    """
    low = path.lower()
    segs = [s for s in low.split("/") if s]
    leaf = segs[-1] if segs else ""
    squashed, word_starts, word_ends = _squash_with_word_bounds(path)

    def hit(markers: tuple[str, ...]) -> bool:
        for m in markers:
            start = squashed.find(m)
            while start != -1:
                if start in word_starts and (start + len(m) - 1) in word_ends:
                    return True
                start = squashed.find(m, start + 1)
        return False

    out: list[str] = []
    if hit(_CONTACT_MARKERS):
        out.append(SEM_CONTACT)
    if hit(_SMS_MARKERS):
        out.append(SEM_SMS)
    if hit(_DOMAIN_MARKERS):
        out.append(SEM_DOMAIN)
    if leaf in _CONFIG_LEAVES or hit(_CONFIG_MARKERS):
        out.append(SEM_CONFIG)
    if hit(_STORAGE_MARKERS):
        out.append(SEM_STORAGE)
    if hit(_FINANCE_MARKERS):
        out.append(SEM_FINANCE)
    if hit(_GAMBLING_MARKERS):
        out.append(SEM_GAMBLING)
    if hit(_FACE_MARKERS):
        out.append(SEM_FACE)
    if hit(_AUTH_MARKERS):
        out.append(SEM_AUTH)
    if hit(_TELEMETRY_MARKERS):
        out.append(SEM_TELEMETRY)
    if hit(_DEVICE_MARKERS):
        out.append(SEM_DEVICE)
    if hit(_LOCATION_MARKERS):
        out.append(SEM_LOCATION)
    return out


def rejection_reason(path: str) -> str | None:
    """四层误报过滤：返回弃用原因（``class_name`` / ``obfuscated`` / ``sdk`` / ``source_file``），
    保留则 ``None``。

    多层可同时命中时按 class_name → obfuscated → sdk → source_file 的顺序归因（首个命中层记账）。
    纯函数便于单测。
    """
    segs = [s for s in path.split("/") if s]
    if len(segs) < 2:
        # 只有前缀无业务段（防御性；本模块正则已保证 ≥2 段，此路不可达）。
        return "class_name"
    rest = segs[1:]

    # 第 1 层：任一段以大写字母开头 = Java 类/包描述符（`Lcom/…/api/CommonStatusCodes;`）。
    # 真实后端接口段守 REST 惯例全小写/小写驼峰（getContactList、domainCheckReport、config），
    # 故「任一段大写开头即弃」对真接口零误伤；代价是 ASP.NET 式 PascalCase 控制器（/api/User/Login）
    # 会被误弃——实测该形态在涉诈语料里不出现，取精确率。标定：实测拦下 42484 次原始命中。
    for s in segs:
        if "A" <= s[0] <= "Z":
            return "class_name"

    # 第 2 层：任一业务段是 R8 混淆占位类名（zza/zzb/zaa/zab…）。
    for s in rest:
        if _R8_OBFUSCATED.match(s):
            return "obfuscated"

    # 第 3 层：紧跟前缀的首段是已知第三方 SDK 命名空间（gms/firebase 等库自带、非团伙自有）。
    if rest[0].lower() in _SDK_FIRST_SEGMENTS:
        return "sdk"

    # 第 4 层：叶子是编译型语言源码/头文件 = .so 里的 __FILE__ 调试串，不是后端接口。
    leaf = segs[-1].lower()
    dot = leaf.rfind(".")
    if dot > 0 and leaf[dot:] in _SOURCE_FILE_EXTS:
        return "source_file"

    # 第 5 层：任一段是代码符号形态（Go/Java 符号表被当路径收进来）。
    if any(_looks_like_code_symbol(s) for s in segs):
        return "code_symbol"

    return None


def _canonical_source(sources: str) -> str:
    """把多源标记归一到单个 Evidence.source（native 优先，其次 dex，最后资源）。"""
    if "native" in sources:
        return "native"
    if "dex" in sources:
        return "dex"
    return "resource"


class ApiSurfaceAnalyzer(BaseAnalyzer):
    """提取后端接口路径、三层过滤误报、按接口名做功能语义标注（只产 Finding + meta，不产 Lead）。"""

    name: str = "api_surface"
    meta_key_categories = {
        'api_surface': 'signal',
        'dex_strings_truncated': 'coverage',
    }
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = []  # Android 扫 dex/.so/assets；Web 只扫已落盘文本证据

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        # path -> 出现过的来源集合（dex/native/asset）。先聚合去重，再统一分类计数。
        raw: dict[str, set[str]] = {}
        for scan, label in (
            (self._scan_dex, "dex 字符串"),
            (self._scan_native, "native .so"),
            (self._scan_assets, "assets"),
        ):
            try:
                # 三个扫描器统一签名 (ctx, raw, result)：result 只被 _scan_dex 用来上报截断，
                # 但签名一致才能这样循环分派，也免得将来加源时忘了传。
                scan(ctx, raw, result)
            except Exception:
                logger.exception("[%s] 扫描 %s 失败，跳过该源", self.name, label)

        # 数值计数用独立 int 变量（避免混类型 dict 上的类型体操）；最终组装进 meta。
        counts: dict[str, int] = {
            "candidates": len(raw),
            "own": 0,
            "filtered_class_name": 0,
            "filtered_obfuscated": 0,
            "filtered_sdk": 0,
            "filtered_source_file": 0,
            "filtered_code_symbol": 0,
        }
        endpoints: list[dict] = []
        config_endpoints: list[str] = []
        by_semantic: dict[str, int] = {}
        strong_map: dict[str, list[dict]] = {}

        for path in sorted(raw):
            reason = rejection_reason(path)
            if reason == "class_name":
                counts["filtered_class_name"] += 1
                continue
            if reason == "obfuscated":
                counts["filtered_obfuscated"] += 1
                continue
            if reason == "sdk":
                counts["filtered_sdk"] += 1
                continue
            if reason == "source_file":
                counts["filtered_source_file"] += 1
                continue
            if reason == "code_symbol":
                counts["filtered_code_symbol"] += 1
                continue

            sems = semantics_for(path)
            ep = {"path": path, "semantics": sems, "source": ",".join(sorted(raw[path]))}
            endpoints.append(ep)
            counts["own"] += 1
            for s in sems:
                by_semantic[s] = by_semantic.get(s, 0) + 1
                if s in _STRONG_SEMANTICS:
                    strong_map.setdefault(s, []).append(ep)
            if SEM_CONFIG in sems:
                config_endpoints.append(path)

        meta_counts: dict[str, object] = dict(counts)
        meta_counts["by_semantic"] = by_semantic
        result.meta["api_surface"] = {
            "endpoints": endpoints,
            "config_endpoints": config_endpoints,  # ★下游拼配置 URL 做主动探测的入口，单列
            "counts": meta_counts,
        }

        if not endpoints:
            logger.info("[%s] 未提取到自有后端接口（候选 %d 条全被三层过滤或无命中）", self.name, len(raw))
            return result

        result.findings.append(
            self._overview_finding(endpoints, counts, by_semantic, config_endpoints)
        )
        # 强语义各产一条独立 Finding，按 _STRONG_SEMANTICS 固定顺序（可回归）。
        for sem in _STRONG_SEMANTICS:
            eps = strong_map.get(sem)
            if eps:
                result.findings.append(self._semantic_finding(sem, eps))
        return result

    # ------------------------------------------------------------------
    # 提取源
    # ------------------------------------------------------------------

    def _scan_dex(
        self, ctx: "AnalysisContext", raw: dict[str, set[str]], result: AnalyzerResult
    ) -> None:
        """DEX 字符串池：含类型描述符（`Lcom/…;`）——第 1 层过滤即为此而设。

        ★传 ``result`` 让截断可被观察到：本分析器提的是后端接口面，截断意味着可能漏掉接口，
        而"没提到某接口"与"没扫到那段"对读报告的人是完全不同的两件事。
        """
        _ok, strings = collect_dex_strings(ctx, self.name, result=result)
        for s in strings:
            for m in _PATH_RE.findall(s):
                raw.setdefault(m, set()).add("dex")

    def _scan_native(
        self, ctx: "AnalysisContext", raw: dict[str, set[str]], result: AnalyzerResult
    ) -> None:
        """App 自有 ``.so``：**整库读**后按字节找路径。（``result`` 未用，仅为统一分派签名。）

        ★为何整库读、不用共享的 head/mid/tail 采样助手：Flutter 的 ``libapp.so``（Dart AOT 快照）
        是接口富矿，接口串**散布全库**、大量在中段；采样窗只覆盖头/中/尾各 256KB，会漏掉绝大多数——
        对「提全接口面」而言漏检是硬伤。改为整库读，用**单文件上限**（``_MAX_SO_BYTES``）+ **累计预算**
        （``_MAX_TOTAL_SO_BYTES``）+ 读前查声明大小 三重有界，防超大/zip-bomb .so 撑爆内存。
        直接在字节上跑路径正则（不先抽全部 ASCII 串），只产出路径本身、内存 O(命中数)。
        """
        budget = _MAX_TOTAL_SO_BYTES
        for path in app_so_paths(ctx, self.name, max_libs=_MAX_LIBS):
            if budget <= 0:
                logger.info("[%s] .so 累计读入达上限，剩余库未扫——本次未命中不等于样本无此接口", self.name)
                break
            try:
                declared = ctx.declared_size(path)
            except Exception:
                logger.debug("[%s] 查声明大小失败：%s", self.name, path, exc_info=True)
                declared = None
            if declared is not None and declared > _MAX_SO_BYTES:
                continue  # 超大库不读、不膨胀进内存
            try:
                data = ctx.read_file(path)
            except Exception:
                logger.debug("[%s] 读 .so 失败，跳过：%s", self.name, path, exc_info=True)
                continue
            if not data or len(data) > _MAX_SO_BYTES:
                continue
            budget -= len(data)
            for m in _PATH_RE_BYTES.findall(data):
                try:
                    raw.setdefault(m.decode("ascii"), set()).add("native")
                except UnicodeDecodeError:
                    continue  # 段字符类限 ASCII，理论不至；防御性跳过

    def _scan_assets(
        self, ctx: "AnalysisContext", raw: dict[str, set[str]], result: AnalyzerResult
    ) -> None:
        """assets 等文本小文件（配置/JS/JSON 常内嵌接口串）。二进制资源由 is_text_resource 排除。

        （``result`` 未用，仅为统一分派签名。）
        """
        try:
            files = ctx.list_files()
        except Exception:
            logger.exception("[%s] list_files 失败，跳过 assets 扫描", self.name)
            return
        budget = _MAX_TOTAL_ASSET_BYTES
        scanned = 0
        for path in files:
            if not isinstance(path, str):
                continue
            if scanned >= _MAX_ASSETS or budget <= 0:
                break
            is_web_text = (
                getattr(ctx, "platform", "android") == "web"
                and path.replace("\\", "/").lower().startswith("web/")
                and path.lower().endswith(TEXT_RESOURCE_SUFFIXES)
            )
            if not is_web_text and not is_text_resource(
                path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
            ):
                continue
            try:
                declared = ctx.declared_size(path)
            except Exception:
                declared = None
            if declared is not None and declared > _MAX_ASSET_BYTES:
                continue
            try:
                data = ctx.read_file(path)
            except Exception:
                logger.debug("[%s] 读 asset 失败，跳过：%s", self.name, path, exc_info=True)
                continue
            if not data or len(data) > _MAX_ASSET_BYTES:
                continue
            budget -= len(data)
            scanned += 1
            text = data.decode("utf-8", "ignore")
            for m in _PATH_RE.findall(text):
                raw.setdefault(m, set()).add("asset")

    # ------------------------------------------------------------------
    # Finding 组装
    # ------------------------------------------------------------------

    def _overview_finding(
        self,
        endpoints: list[dict],
        counts: dict[str, int],
        by_semantic: dict[str, int],
        config_endpoints: list[str],
    ) -> Finding:
        sem_summary = (
            "、".join(f"{k}×{v}" for k, v in by_semantic.items()) if by_semantic else "无强语义命中"
        )
        tagged = [e for e in endpoints if e["semantics"]]
        sample = (tagged or endpoints)[:_MAX_EVIDENCE]
        lines = "\n".join(
            f"  · {e['path']}" + (f"（{'/'.join(e['semantics'])}）" if e["semantics"] else "")
            for e in sample
        )
        config_note = (
            f"\n★ 其中远程配置下发接口 {len(config_endpoints)} 条已单列 "
            "meta['api_surface']['config_endpoints']，供下游拼配置 URL 做（授权）主动探测。"
            if config_endpoints
            else ""
        )
        return Finding(
            id="API-SURFACE-OVERVIEW",
            title=f"后端接口面：{counts['own']} 条自有接口（三层过滤后）",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="backend_surface",
            description=(
                f"从 DEX / native .so / assets 提取到 {counts['candidates']} 条候选接口路径，经三层误报"
                f"过滤（类名 {counts['filtered_class_name']} / 混淆 {counts['filtered_obfuscated']} / "
                f"第三方 SDK {counts['filtered_sdk']}）后得 {counts['own']} 条**自有**后端接口。"
                f"功能语义分布：{sem_summary}。\n接口名自证后端功能（比从代码行为反推可靠）：\n"
                + lines
                + config_note
            ),
            recommendation=(
                "把接口名当后端功能清单读：带窃取/资金/换脸语义的接口是取证重点；域名存活上报接口"
                "指示后端有域名轮换池、远程配置接口是 config-chain 入口。注意 URL 路径本身不发函"
                "（发函对象是域名/IP），本清单用于研判后端功能与拼配置 URL。"
            ),
            evidences=[
                Evidence(source=_canonical_source(e["source"]), location=e["path"], snippet=e["path"])
                for e in sample
            ],
        )

    def _semantic_finding(self, semantic: str, eps: list[dict]) -> Finding:
        fid, severity, category, why = _SEMANTIC_META[semantic]
        paths = [e["path"] for e in eps]
        shown = "、".join(paths[:_MAX_EVIDENCE])
        return Finding(
            id=fid,
            title=f"后端接口暴露「{semantic}」功能（{len(paths)} 条）",
            severity=severity,
            confidence=Confidence.MEDIUM,
            category=category,
            description=f"命中接口：{shown}。\n{why}",
            recommendation=(
                "以接口名为线索，jadx 跟踪该接口的调用点核实数据流；结合运行时抓包看实际请求/响应，"
                "确认功能落地后据此向后端服务器（域名/IP 归属方）依法调取相关记录。"
            ),
            evidences=[
                Evidence(source=_canonical_source(e["source"]), location=e["path"], snippet=e["path"])
                for e in eps[:_MAX_EVIDENCE]
            ],
        )


__all__ = ["ApiSurfaceAnalyzer", "semantics_for", "rejection_reason"]
