"""apkscan.dynamic.cryptohook — 运行时密钥 hook（P0）：Frida 抓活体 AES key/明文。

取证定位：对取证样本自身在分析机上做运行时观测，产出密钥/端点/独特串等可落地线索；
仅作用于样本自身进程，不面向、不接触任何第三方基础设施。

为什么需要它（补 C5a 静态配方之不足）：
  C5a（``analyzers/crypto_recipe.py``）从打包 JS 静态反查加密配方，但当 **key 在运行时
  计算/服务端下发**（而非硬编码）时，静态拿不到真实 key。本模块在真机抓包时用 Frida
  hook ``javax.crypto.Cipher``（init/doFinal）+ ``SecretKeySpec``/``IvParameterSpec`` +
  ``Mac`` + WebView 内 CryptoJS，把**活体 key / iv / 明文 / 密文**经 ``send()`` 回传
  Python，再由 merge 用「运行时实测配方优先」对抓到的 ``{data,timestamp}`` 信封解密。

职责边界（贴合现有架构、不另起炉灶）：
  - 本模块只做**纯逻辑**：持有 Frida JS 常量、解析 ``send()`` 消息、从活体事件反推
    ``crypto_recipe`` meta（喂回 ``appcrypto.CryptoRecipe.from_meta``）、抽冒充品牌线索。
  - 真机编排（建会话/注入/收尾）在 ``capture.py``；本模块无 I/O 副作用（除 logging），
    便于无设备全 mock 单测。
  - **不新增 LeadCategory**：运行时实测只是把 CRYPTO_RECIPE 从「静态推定」升级为
    「活体实证」（merge 侧体现），避免模型契约漂移。

设计铁律（与 dynamic 一致）：
  - 绝不把异常抛给调用方（on_message 在 Frida 回调线程触发，抛了会炸会话）。
  - 不静默吞错：每个 except 必 logging。
  - 全程 type hints。
  - 二进制一律 hex/base64 字符串（JS 侧已转），绝不裸塞 JSON（否则 UTF-8 损坏）。
"""

from __future__ import annotations

import base64
import binascii
import importlib.resources
import json
import logging
import re
from collections.abc import Callable
from typing import Any

from apkscan.core import chainaddr

logger = logging.getLogger(__name__)


def _load_frida_js(filename: str) -> str:
    """读取内置 Frida JS（``apkscan/dynamic/frida_js/<filename>``）为字符串。

    JS 脚本是**数据资源**（非 Python 代码），用 ``importlib.resources`` 锚包 ``apkscan.dynamic``
    定位，PyInstaller onefile / zip 安装下同样可读（与 report/registry 的资源加载同范式）。
    按 bytes 读取后 UTF-8 解码 —— **绝不做换行翻译**，保证拿到的 JS 文本与源文件逐字一致。
    读失败直接抛（缺内置脚本 = 打包缺陷，宁可炸也不静默给半截脚本注入真机）。
    """
    res = importlib.resources.files("apkscan.dynamic") / "frida_js" / filename
    return res.read_bytes().decode("utf-8")


#: ``send()`` payload 的通道判别值（JS 与 Python 两端约定）。
CRYPTO_MSG_TYPE = "apkscan-crypto"
#: P1 运行时 JS-bridge 追踪通道（hook WebView.addJavascriptInterface + 暴露方法调用）。
JSBRIDGE_MSG_TYPE = "apkscan-jsbridge"
#: P1 运行时敏感 API 追踪通道（hook TelephonyManager/SmsManager/… 实际调用）。
SENSITIVE_API_MSG_TYPE = "apkscan-api"
#: P3 取证运行时兼容通道：中和样本对 root/模拟器/frida 的自我检测（使加固样本能在取证机上运行被观测），
#: 同时把样本每次自我检测尝试作为反取证/反分析研判信号上报（对样本自身进程，不接触任何第三方）。
#: ★ 符号名与消息 type 值保持不变（JS↔Py 契约）。
ANTIDETECT_MSG_TYPE = "apkscan-antidetect"
#: 第二波：运行时登录态/明文凭据采集通道（OkHttp 加密前明文 dump + SharedPrefs 落地凭据）。
CREDENTIAL_MSG_TYPE = "apkscan-credential"
#: 第二波：运行时 SQLCipher/SQLite 落地库导出通道（库路径 + key + 明文导出库路径）。
SQLCIPHER_MSG_TYPE = "apkscan-sqlcipher"
#: 第二波：运行时剪贴板链上地址采集通道（资金流起点·受害人复制转账入口）。
#: ★ JS 侧回传剪贴板**实际文本**，Python 侧 normalize 立刻抽出校验通过的链上地址、丢弃全文
#: （隐私护栏）——runtime_report.json 只落抽出的地址，绝不落剪贴板全文。
CLIPBOARD_MSG_TYPE = "apkscan-clipboard"
#: 第二波（最后）：无障碍远控指令与目标银行清单采集通道（REMOTE_CONTROL 行为物证 + C2）。
#: hook AccessibilityService.onAccessibilityEvent（记被操作 app 包名 = 目标清单）、
#: dispatchGesture/performGlobalAction（记下发手势 = 远控指令）、
#: MediaProjectionManager.createVirtualDisplay（屏幕录制开启）。
#: ★ 边界：无障碍远控逻辑绝大多数要诱导真人操作才走，launch-only 抓不到（见各 normalize/merge 标注）。
ACCESSIBILITY_MSG_TYPE = "apkscan-accessibility"

#: sink 累积上限：高频加密（每帧/每请求）会刷爆，超限丢弃 + 记一次 warning。
_SINK_CAP = 4000

#: 明文/密文回传字符上限（JS 侧已截断，Python 侧再兜底防御）。
_MAX_FIELD_CHARS = 64 * 1024

#: 冒充对象常出现在明文 JSON 的这些键里（反诈视角：还原"冒充谁"）。
_BRAND_KEYS: tuple[str, ...] = (
    "webname",
    "appname",
    "platformname",
    "sitename",
    "companyname",
    "brand",
    "title",
    "name",
    "company",
)

#: 冒充对象常含这些行业词（值里命中即视为品牌线索候选）。
_BRAND_HINT_TOKENS: tuple[str, ...] = (
    "证券",
    "银行",
    "基金",
    "交易所",
    "钱包",
    "理财",
    "投资",
    "资管",
    "金融",
    "期货",
    "信托",
    "保险",
)


# ---------------------------------------------------------------------------
# Frida JS：javax.crypto.Cipher / Mac / SecretKeySpec / IvParameterSpec + WebView CryptoJS
# ---------------------------------------------------------------------------
#
# 与 capture.FRIDA_UNPINNING_JS 拼接成单一脚本（session.create_script）。所有 hook 各自
# try/catch，单点失败不影响 unpinning 与其它 hook（沿用 capture 的 best-effort 风格）。
# 二进制一律 b2hex/Base64 转字符串塞 payload；按 (src,transformation,key_hex,iv_hex) 去重
# init、按计数上限封顶 doFinal，避免刷爆 send 通道。
FRIDA_CRYPTO_HOOK_JS: str = _load_frida_js("crypto_hook.js")


# ---------------------------------------------------------------------------
# P1：运行时 JS-bridge 追踪 —— hook WebView.addJavascriptInterface 列暴露接口 + 调用
# ---------------------------------------------------------------------------
FRIDA_JSBRIDGE_HOOK_JS: str = _load_frida_js("jsbridge_hook.js")


# ---------------------------------------------------------------------------
# P1：运行时敏感 API 追踪 —— hook TelephonyManager/SmsManager/… 实际调用
# ---------------------------------------------------------------------------
FRIDA_SENSITIVE_API_HOOK_JS: str = _load_frida_js("sensitive_api_hook.js")


# ---------------------------------------------------------------------------
# P3：取证运行时兼容层 —— 中和样本对 root/模拟器/frida 的自我检测，使其在取证机上运行被观测
# ---------------------------------------------------------------------------
#
# 取证用途（对取证样本自身在分析机上做运行时观测，不接触任何第三方基础设施）：
# ① 中和让检测 MuMu/root/frida 的涉诈样本仍能正常运行（否则秒退、观测不到任何行为）；
# ② 样本的自我检测尝试本身就是「反取证/反分析」行为（正经 app 极少探测 su/qemu/frida），作为涉诈/
# 木马的研判信号上报（kind=root|emulator|frida，probe=被检测的具体特征）。每个 hook best-effort
# 独立 try/catch，单点失败不影响其它，绝不因兼容逻辑炸 app（中和失败顶多样本照常秒退）。
FRIDA_ANTIDETECT_JS: str = _load_frida_js("sample_runtime_compat.js")


# ---------------------------------------------------------------------------
# 第二波：OkHttp interceptor-before 明文 dump —— 拿加密前明文 + 真实业务后端 host
# ---------------------------------------------------------------------------
#
# 价值（补抓包/cryptohook 之不足）：抓包拿到的是 app 自己的签名/加密 interceptor **之后**
# 的密文请求；本 hook 在 OkHttp 调用链最外层（RealCall.execute/enqueue、RealInterceptorChain
# .proceed 的首个 request）dump **加密前的明文** request —— 真实业务后端 host、Authorization/
# Bearer/JWT token、登录账号/手机号，直接定位「向谁登录、带的什么凭据」。
#
# R8 混淆护栏：OkHttp 类名随版本（3.x/4.x okhttp3.* vs internal.http.*）与混淆而变，需多
# fallback 类名 + best-effort 跳过（hook 不到只 console.log、绝不崩）。每个 hook 独立 try/catch。
# 高敏值（token/手机号）在 JS 侧先截断回传（Python 侧 normalize 再脱敏兜底），不留全文。
FRIDA_OKHTTP_HOOK_JS: str = _load_frida_js("okhttp_hook.js")


# ---------------------------------------------------------------------------
# 第二波：SQLCipher/SQLite 落地库导出 —— hook openDatabase 抓库路径+key，导明文库回传
# ---------------------------------------------------------------------------
#
# 物证价值（全工程最高之一）：诈骗 app 本地落地库（SQLCipher 加密）藏 IM 聊天/话术剧本、
# 通讯录、account/会员表、订单/入金缓存——导成明文 = 受害人名单 + 话术 + 上下线对接人。
#
# 机制：hook net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase（SQLCipher 加密库）
# 与 android.database.sqlite.SQLiteDatabase.openDatabase（普通 SQLite），抓**库路径 + password/
# raw key**；对 SQLCipher 库随即用 rawExecSQL 注入
#   ATTACH DATABASE '<tmp>/<name>.plain.db' AS plain KEY ''; SELECT sqlcipher_export('plain'); DETACH plain;
# 把明文库导到设备临时目录，send() 回传 {plain_path, db_path, key}。
#
# v3/v4 KDF 适配（核验坑）：SQLCipher v3/v4 默认 KDF 迭代数不同，导出前先按 v4 默认尝试，
# 失败则 `PRAGMA cipher_compatibility = 3` 再试。导出失败必降级（event=key_only，仅回传
# key + 原库路径，由 merge 写人工解密 playbook 进 Lead.notes），**不崩、不假成功**。
#
# 时序依赖（核验坑）：sqlcipher_export 需库**已被 app 打开**——hook 在 openDatabase 回调里
# 即时导出（库此刻已开），但 launch-only 抓不全未触发打开的库。merge/文档侧诚实标注。
#
# R8 混淆护栏：SQLCipher 类名随版本/混淆而变，多 fallback 类名 + 每步 try/catch，hook 不到
# 只 console.log、绝不崩。
FRIDA_SQLCIPHER_HOOK_JS: str = _load_frida_js("sqlcipher_hook.js")


# ---------------------------------------------------------------------------
# 第二波：剪贴板链上地址采集 —— hook ClipboardManager 抓实际剪贴板文本回传
# ---------------------------------------------------------------------------
#
# 资金流价值（资金流起点·运行时确认）：杀猪盘/跑分引导受害人「复制这个地址转账」——剪贴板里
# 就是真实收款钱包地址。运行时抓到 = is_runtime_seen 的铁证（比静态硬编码可信度更高，且能拿到
# 服务端运行时下发、静态抠不到的地址）。
#
# ★ 隐私护栏（关键）：剪贴板含验证码/密码/聊天等隐私。JS 侧只负责把剪贴板**实际文本**回传，
# Python 侧 normalize_clipboard_event 收到后**立即** chainaddr.find_addresses 抽出通过校验的
# 地址、只保留地址列表、丢弃原文——runtime_report.json 只落抽出的地址，绝不落剪贴板全文。
# （全文从设备出来后只在 normalize 内存里走一遭、立刻被抽地址替换，不写任何 sink/磁盘。）
#
# 机制：hook android.content.ClipboardManager 的 getPrimaryClip（取回 ClipData → getItemAt(0)
# .coerceToText / getText）与 getText（旧 API），把剪贴板实际文本经 send() 回传。文本上限截断
# （地址不长，截断不影响抽取，且兜底防超大体刷爆通道）。best-effort 每个 hook 独立 try/catch，
# hook 不到只 console.log、绝不崩。
FRIDA_CLIPBOARD_HOOK_JS: str = _load_frida_js("clipboard_hook.js")


# ---------------------------------------------------------------------------
# 第二波（最后）：无障碍远控指令与目标银行清单 —— hook AccessibilityService 回调 + 手势 + 屏幕录制
# ---------------------------------------------------------------------------
#
# 反诈价值：无障碍远控木马劫持银行/支付 app 自动转账。运行时能抓到：
#   ① 被劫持的目标 app 包名清单（onAccessibilityEvent 的 event.getPackageName）——证明针对性
#      盗刷、指明向哪些银行调被害人流水（merge 侧映射机构主体产 REMOTE_CONTROL Lead）。
#   ② 下发的远控手势/全局动作（dispatchGesture / performGlobalAction）= 远控指令（行为定性证据）。
#   ③ 屏幕录制开启（MediaProjectionManager.createVirtualDisplay）= 操盘端可视化远控的活体确认。
#
# ★ 边界（务必照做）：无障碍远控逻辑**绝大多数要诱导真人操作才走，launch-only 抓不到**——本段
#   hook best-effort 武装，能不能抓到取决于是否有引导式人工动态（merge/Lead/Finding 诚实标注）。
#
# 抽象类护栏：android.accessibilityservice.AccessibilityService 是**抽象类**，无障碍服务子类才
#   实现 onAccessibilityEvent。Frida 对抽象基类方法 hook 仅 best-effort（部分 ROM/版本能命中基类
#   分发，部分需子类）——hook 不到只 console.log、绝不崩；另对 AccessibilityNodeInfo.getPackageName
#   做补充面，覆盖 hook 不到回调时仍能从控件树拿目标包名。
#
# 限流（核验坑）：dispatchGesture 在自动操作时**高频**触发（每个手势一次），不限流会刷爆 send
#   通道。JS 侧按总计数封顶（_CAP）+ 手势按采样计数，超限丢弃，避免拖垮抓包。
FRIDA_ACCESSIBILITY_HOOK_JS: str = _load_frida_js("accessibility_hook.js")


# ---------------------------------------------------------------------------
# on_message handler：把 Frida send() 的 crypto 事件规范化进 sink
# ---------------------------------------------------------------------------


def make_message_handler(sink: list[dict[str, Any]]) -> Callable[[dict[str, Any], Any], None]:
    """构造 Frida ``script.on('message', handler)`` 回调，把 crypto 事件存进 ``sink``。

    handler 只认 ``message['type']=='send'`` 且 ``payload['type']==CRYPTO_MSG_TYPE`` 的消息；
    其它（非本通道 send / error）忽略。``message['type']=='error'`` 记 warning（JS 异常诊断）。

    **绝不抛**：on_message 在 Frida 回调线程触发，抛异常会炸整个会话。

    Args:
        sink: 共享列表（CPython ``list.append`` 原子，无需锁）；收尾时由 capture 读取落盘。

    Returns:
        ``handler(message, _data)``。第二参是 send 的 ArrayBuffer→bytes；本设计二进制都走
        payload 字符串，该参一般为 None，留参（``_data``）以符合 Frida 回调签名。
    """

    def handler(message: Any, _data: Any = None) -> None:
        try:
            if not isinstance(message, dict):
                return
            mtype = message.get("type")
            if mtype == "error":
                logger.warning(
                    "[cryptohook] Frida JS 异常：%s",
                    message.get("description") or message.get("stack") or message,
                )
                return
            if mtype != "send":
                return
            payload = message.get("payload")
            if not isinstance(payload, dict) or payload.get("type") != CRYPTO_MSG_TYPE:
                return
            event = normalize_crypto_event(payload)
            if event is None:
                return
            if len(sink) >= _SINK_CAP:
                if len(sink) == _SINK_CAP:
                    logger.warning("[cryptohook] crypto 事件达上限 %d，后续丢弃", _SINK_CAP)
                    sink.append({"_capped": True})  # 触发一次性 warning 后停
                return
            sink.append(event)
        except Exception:  # noqa: BLE001 — 回调绝不抛（否则炸 Frida 会话）
            logger.exception("[cryptohook] 处理 Frida 消息异常（已忽略该条）")

    return handler


def make_typed_handler(
    sink: list[dict[str, Any]],
    msg_type: str,
    normalizer: Callable[[Any], dict[str, Any] | None],
) -> Callable[[dict[str, Any], Any], None]:
    """通用 on_message 工厂：只收 ``payload['type']==msg_type`` 的 send 消息进 ``sink``。

    与 ``make_message_handler`` 同范式（绝不抛、sink 封顶），但通道/规范化可参数化，供
    crypto/jsbridge/sensitive_api 三通道复用。本工厂**不记 error 日志**（避免多 handler
    重复刷；error 由 crypto 通道的 make_message_handler 统一记一次）。
    """

    def handler(message: Any, _data: Any = None) -> None:
        try:
            if not isinstance(message, dict) or message.get("type") != "send":
                return
            payload = message.get("payload")
            if not isinstance(payload, dict) or payload.get("type") != msg_type:
                return
            event = normalizer(payload)
            if event is None:
                return
            if len(sink) >= _SINK_CAP:
                if len(sink) == _SINK_CAP:
                    logger.warning("[cryptohook] %s 事件达上限 %d，后续丢弃", msg_type, _SINK_CAP)
                    sink.append({"_capped": True})
                return
            sink.append(event)
        except Exception:  # noqa: BLE001 — 回调绝不抛
            logger.exception("[cryptohook] 处理 %s 消息异常（已忽略该条）", msg_type)

    return handler


def normalize_crypto_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧 crypto payload 规范化为稳定 schema 条目；非 dict/非法 → None。

    **crypto_event 权威 schema**（producer=Frida JS、本函数=normalizer、consumer=recipe_from_events
    /brand_hints/merge 三方共识的单一定义；落进 runtime_report.json['crypto_events']）：

    - ``src``: ``cipher|secretkeyspec|ivspec|mac|cryptojs`` —— 来源 hook。
    - ``event``: ``init|doFinal|encrypt|decrypt``。
    - ``transformation``: 如 ``AES/CFB/PKCS5Padding``（Java=完整串；CryptoJS=algo）。
    - ``opmode``: ``1=ENCRYPT 2=DECRYPT 0=未知`` —— **取证元数据**，JS 侧据此判定 doFinal
      的入/出哪个是明文（决定 plaintext_b64 的取向）；Python 侧目前不消费，留作研判线索。
    - ``key_hex`` / ``iv_hex``: 小写 hex 串或 None（非合法 hex 一律 None）。
    - ``plaintext_b64``: 明文 base64；``ciphertext_hex``: 密文 hex（均可能 None）。
    - ``ts``: JS Date.now()（int 或 None），仅排序/去重，不参与 iv 派生。

    所有字符串字段截断到 ``_MAX_FIELD_CHARS``；类型不符的字段置 None。
    """
    if not isinstance(payload, dict):
        return None
    src = _as_clean_str(payload.get("src"))
    event = _as_clean_str(payload.get("event"))
    if not src or not event:
        return None
    return {
        "src": src,
        "event": event,
        "transformation": _as_clean_str(payload.get("transformation")) or "",
        "opmode": payload.get("opmode") if isinstance(payload.get("opmode"), int) else 0,
        "key_hex": _as_hex_str(payload.get("key_hex")),
        "iv_hex": _as_hex_str(payload.get("iv_hex")),
        "plaintext_b64": _as_clean_str(payload.get("plaintext_b64"), _MAX_FIELD_CHARS),
        "ciphertext_hex": _as_clean_str(payload.get("ciphertext_hex"), _MAX_FIELD_CHARS),
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _as_clean_str(value: Any, limit: int = 4096) -> str | None:
    """把字段转成截断后的字符串；None/空/非 str→None（数字会被拒，保持字段语义纯净）。"""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:limit]


def _as_hex_str(value: Any) -> str | None:
    """把 key_hex/iv_hex 字段规整为小写 hex 串；非合法 hex→None。"""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    try:
        bytes.fromhex(text)
    except ValueError:
        return None
    return text


def normalize_jsbridge_event(payload: Any) -> dict[str, Any] | None:
    """规范化 JS-bridge 事件：register（暴露接口+方法）/ call（H5 实际调用）。"""
    if not isinstance(payload, dict):
        return None
    event = _as_clean_str(payload.get("event"))
    iface = _as_clean_str(payload.get("iface"))
    if not event or not iface:
        return None
    return {
        "event": event,  # register | call
        "iface": iface,
        "object_class": _as_clean_str(payload.get("object_class")) or "",
        "methods": _as_clean_str(payload.get("methods")) or "",
        "method": _as_clean_str(payload.get("method")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def normalize_sensitive_api_event(payload: Any) -> dict[str, Any] | None:
    """规范化敏感 API 调用事件：api（<类>.<方法>）+ 结果摘要。"""
    if not isinstance(payload, dict):
        return None
    api = _as_clean_str(payload.get("api"))
    if not api:
        return None
    return {
        "event": _as_clean_str(payload.get("event")) or "call",
        "api": api,
        "result_summary": _as_clean_str(payload.get("result_summary")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def normalize_antidetect_event(payload: Any) -> dict[str, Any] | None:
    """规范化样本自我检测事件：kind（root|emulator|frida|debugger）+ probe（被检测的特征）。

    取证用途：记录样本对取证环境的自我检测尝试，作为反取证/反分析研判信号（对样本自身的观测）。
    """
    if not isinstance(payload, dict):
        return None
    kind = _as_clean_str(payload.get("kind"))
    probe = _as_clean_str(payload.get("probe"))
    if not kind or not probe:
        return None
    return {
        "kind": kind,
        "probe": probe,
        "bypassed": bool(payload.get("bypassed", False)),
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


# ---------------------------------------------------------------------------
# 第二波：运行时凭据规范化 —— 高敏个人信息脱敏/截断 + token 形态闸
# ---------------------------------------------------------------------------
#
# 合规护栏（横切硬要求）：token / 账号 / 手机号是受害人/高敏个人信息，回传与落盘必须截断、
# 不留全文；手机号中间打码、token 只留前后几位。本模块的规范化与抽取统一执行这一脱敏口径。

#: 凭据来源（与 JS 侧约定）：okhttp=加密前明文请求；sharedprefs=落地凭据 xml。
_CREDENTIAL_SOURCES: frozenset[str] = frozenset({"okhttp", "sharedprefs"})

#: 高敏 header 名（命中即整值脱敏，只留前后片段）。
_SENSITIVE_HEADER_KEYS: frozenset[str] = frozenset(
    {"authorization", "cookie", "token", "access-token", "x-token", "x-auth-token", "x-access-token"}
)

#: SharedPrefs 里视为「登录态/凭据」的敏感键名子串（小写匹配；命中即抠出）。
_SHAREDPREFS_SENSITIVE_KEYS: tuple[str, ...] = (
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "session",
    "sessionid",
    "auth",
    "jwt",
    "ticket",
    "merchant",      # 商户号
    "merchant_no",
    "mch_id",
    "invite",        # 邀请码
    "invite_code",
    "invitecode",
    "mobile",        # 登录手机号
    "phone",
    "account",
    "username",
    "uid",
    "userid",
    "login_status",  # 登录态
    "is_login",
    "islogin",
    "logined",
)

#: SharedPrefs xml 中 <string name="...">value</string> 的提取正则。
_PREFS_STRING_RE = re.compile(
    r'<string\s+name="([^"]+)"\s*>(.*?)</string>', re.IGNORECASE | re.DOTALL
)
#: <int/long/boolean name="..." value="..." /> 形态（登录态多为 int/boolean）。
_PREFS_SCALAR_RE = re.compile(
    r'<(?:int|long|boolean)\s+name="([^"]+)"\s+value="([^"]*)"\s*/>', re.IGNORECASE
)

#: 手机号（中国大陆 11 位）打码用：保留前 3 后 4，中间 ****。
_PHONE_RE = re.compile(r"(?<!\d)(1\d{2})(\d{4})(\d{4})(?!\d)")

#: 高敏值回传/落盘的截断上限（远小于全文，确保不留全凭据）。
_CRED_VALUE_HEAD = 6
_CRED_VALUE_TAIL = 4
_CRED_VALUE_MAX = 24

# 形态闸规则惰性缓存（避免每条事件重读 rules/secrets.yaml）。
_SECRET_RULES_CACHE: Any = None


def _secret_rules() -> Any:
    """惰性加载 secrets 形态闸规则（与 js_bundle/jadx 同口径）；加载失败 → 兜底规则。"""
    global _SECRET_RULES_CACHE
    if _SECRET_RULES_CACHE is not None:
        return _SECRET_RULES_CACHE
    try:
        from apkscan.core.secrets import load_secret_rules

        _SECRET_RULES_CACHE = load_secret_rules()
    except Exception:  # noqa: BLE001 — 规则不可用不阻断，用兜底 SecretRules
        logger.exception("[credential] 加载 secrets 形态闸规则失败，用兜底")
        from apkscan.core.secrets import SecretRules

        _SECRET_RULES_CACHE = SecretRules()
    return _SECRET_RULES_CACHE


def _looks_like_credential(value: str) -> bool:
    """value 是否像真实凭据形态（复用 secrets 形态/熵闸，过滤占位/常量名）。绝不抛。"""
    try:
        from apkscan.core.secrets import looks_like_secret_value

        return looks_like_secret_value(value, _secret_rules())
    except Exception:  # noqa: BLE001 — 形态闸异常按"非凭据"保守处理（不泄明文）
        logger.exception("[credential] 形态闸判定异常，按非凭据处理")
        return False


def _mask_phone_numbers(text: str) -> str:
    """把文本里的手机号中间四位打码（前 3 后 4 保留）。绝不抛。"""
    try:
        return _PHONE_RE.sub(lambda m: f"{m.group(1)}****{m.group(3)}", text)
    except Exception:  # noqa: BLE001
        logger.exception("[credential] 手机号打码异常")
        return text


def _truncate_secret(value: str) -> str:
    """高敏凭据值截断：只留前 ``_CRED_VALUE_HEAD`` 后 ``_CRED_VALUE_TAIL`` 位，中间省略号。

    短值（<= head+tail）整体保留（本就不含全文风险）；长值截断不留全文。
    """
    v = value.strip()
    if len(v) <= _CRED_VALUE_HEAD + _CRED_VALUE_TAIL:
        return v[:_CRED_VALUE_MAX]
    return f"{v[:_CRED_VALUE_HEAD]}…{v[-_CRED_VALUE_TAIL:]}"


def _desensitize_header(name: str, value: str) -> str:
    """header 值脱敏：高敏头（Authorization/Cookie/token 类）整值截断；其余仅手机号打码。

    Authorization 形如 ``Bearer <token>``：保留方案前缀（Bearer/Basic）+ token 前后几位。
    """
    if not isinstance(value, str):
        return ""
    low = name.strip().lower()
    if low in _SENSITIVE_HEADER_KEYS:
        parts = value.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token", "jwt"):
            return f"{parts[0]} {_truncate_secret(parts[1])}"
        return _truncate_secret(value)
    return _mask_phone_numbers(value)[:512]


def normalize_credential_event(payload: Any) -> dict[str, Any] | None:
    """把 JS/SharedPrefs 侧 credential payload 规范化为稳定 schema；非法 → None（绝不抛）。

    **credential_event 权威 schema**（producer=Frida OkHttp JS / SharedPrefs 抽取，
    consumer=merge_runtime_credentials；落进 runtime_report.json['credential_events']）：

    - ``source``: ``okhttp`` | ``sharedprefs``（区分加密前明文请求 / 落地凭据）。
    - okhttp：``url`` / ``method`` / ``headers``（dict，高敏头脱敏）/ ``body``（手机号打码、截断）。
    - sharedprefs：``name``（键名）/ ``value``（经形态闸 + 截断）/ ``file``（来源 xml）。
    - ``ts``: JS Date.now()（int 或 None）。

    合规护栏：所有高敏值（token/手机号/账号）一律脱敏或截断，绝不回传/落盘全文。
    """
    if not isinstance(payload, dict):
        return None
    source = _as_clean_str(payload.get("source"))
    if source not in _CREDENTIAL_SOURCES:
        return None

    if source == "okhttp":
        return _normalize_okhttp_credential(payload)
    return _normalize_sharedprefs_credential(payload)


def _normalize_okhttp_credential(payload: dict[str, Any]) -> dict[str, Any] | None:
    """规范化 OkHttp 明文请求事件：url 必有；headers 高敏脱敏、body 手机号打码 + 截断。"""
    url = _as_clean_str(payload.get("url"))
    if not url:
        return None  # 无 url 的 okhttp 事件无取证价值

    headers_raw = payload.get("headers")
    headers: dict[str, str] = {}
    if isinstance(headers_raw, dict):
        for k, v in headers_raw.items():
            key = str(k)
            headers[key] = _desensitize_header(key, str(v) if v is not None else "")

    body_raw = _as_clean_str(payload.get("body"), 8192)
    body = _mask_phone_numbers(body_raw) if body_raw else ""

    return {
        "source": "okhttp",
        "url": url,
        "method": _as_clean_str(payload.get("method")) or "",
        "headers": headers,
        "body": body,
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _normalize_sharedprefs_credential(payload: dict[str, Any]) -> dict[str, Any] | None:
    """规范化 SharedPrefs 落地凭据：name 必有；value 经形态闸（占位→占位标记）+ 截断/打码。"""
    name = _as_clean_str(payload.get("name"))
    if not name:
        return None
    raw_value = payload.get("value")
    value = _gate_and_mask_value(name, str(raw_value) if raw_value is not None else "")
    return {
        "source": "sharedprefs",
        "name": name,
        "value": value,
        "file": _as_clean_str(payload.get("file")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _gate_and_mask_value(name: str, value: str) -> str:
    """对 SharedPrefs 值施加形态闸 + 脱敏：

    - 登录态布尔/小整数（如 login_status=1）：直接保留（非个人信息、是状态量）。
    - 手机号/账号形态：打码后截断。
    - token 类长值：先过形态闸——像真凭据 → 截断保留前后位；不像（占位/常量名）→ 占位标记
      （``<非凭据形态>``，不回传非凭据明文，也避免把 deviceToken 之类当真 token）。
    """
    v = value.strip()
    if not v:
        return ""
    # 状态量（登录态）：短布尔/数字直接留（是状态、非高敏个人信息）。
    low_name = name.lower()
    if any(tok in low_name for tok in ("login", "status", "is_login", "logined")):
        if v.lower() in ("0", "1", "true", "false", "yes", "no") or (v.isdigit() and len(v) <= 4):
            return v
    # 手机号/账号：打码后截断。
    masked = _mask_phone_numbers(v)
    if masked != v:
        return masked[:_CRED_VALUE_MAX]
    # token/secret 类：形态闸过占位。
    if _looks_like_credential(v):
        return _truncate_secret(v)
    # 不像凭据（占位/SDK 常量名 deviceToken 等）→ 占位标记，不回传非凭据明文。
    return "<非凭据形态>"


def extract_sharedprefs_credentials(xml_text: str, file_name: str) -> list[dict[str, Any]]:
    """从单个 shared_prefs xml 文本抠出敏感键（token/商户号/邀请码/手机号/登录态）。绝不抛。

    返回 ``[{"source":"sharedprefs","name":..,"value":..(脱敏/截断),"file":file_name}]``。
    供 capture 收尾对 adb pull 回的每个 xml 调用、产 credential_events；merge 侧据此产 Lead。
    """
    creds: list[dict[str, Any]] = []
    if not isinstance(xml_text, str) or not xml_text.strip():
        return creds
    seen: set[str] = set()
    try:
        pairs: list[tuple[str, str]] = []
        pairs.extend(_PREFS_STRING_RE.findall(xml_text))
        pairs.extend(_PREFS_SCALAR_RE.findall(xml_text))
        for name, value in pairs:
            name = name.strip()
            low = name.lower()
            if not any(tok in low for tok in _SHAREDPREFS_SENSITIVE_KEYS):
                continue
            if name in seen:
                continue
            seen.add(name)
            ev = _normalize_sharedprefs_credential(
                {"source": "sharedprefs", "name": name, "value": value, "file": file_name}
            )
            if ev is not None:
                creds.append(ev)
    except Exception:  # noqa: BLE001 — 单个 xml 解析失败不影响其它，绝不抛
        logger.exception("[credential] 解析 shared_prefs xml 失败（已忽略）：%s", file_name)
    return creds


# ---------------------------------------------------------------------------
# 第二波：SQLCipher/SQLite 落地库导出事件规范化（key 截断 + 路径校形）
# ---------------------------------------------------------------------------
#
# 合规护栏：db key 是高敏（凭它可解全库受害人物证），回传/落盘截断不留全文（与 token 同口径）。

#: 落地库事件类型（与 JS 侧约定）：exported=已导出明文库；key_only=导出失败降级仅 key+路径。
_SQLCIPHER_EVENTS: frozenset[str] = frozenset({"exported", "key_only"})


def normalize_sqlcipher_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧 SQLCipher/SQLite 落地库事件规范化为稳定 schema；非法 → None（绝不抛）。

    **sqlcipher_event 权威 schema**（producer=Frida FRIDA_SQLCIPHER_HOOK_JS，
    consumer=merge_runtime_databases；落进 runtime_report.json['sqlcipher_events']）：

    - ``event``: ``exported``（已导出明文 .plain.db）| ``key_only``（导出失败降级，仅 key+路径）。
    - ``db_path``: 设备上原加密库路径（必有，否则无取证价值 → None）。
    - ``plain_path``: 导出的明文库设备路径（exported 才有；key_only 为空）。
    - ``key``: 库密钥（**高敏**，截断不留全文，凭它可人工解密原库）。
    - ``where``: 来源 hook 标记。
    - ``ts``: JS Date.now()（int 或 None）。

    合规护栏：key 截断/脱敏，绝不回传/落盘全文。
    """
    if not isinstance(payload, dict):
        return None
    db_path = _as_clean_str(payload.get("db_path"), 1024)
    if not db_path:
        return None  # 无原库路径的事件无取证价值

    event = _as_clean_str(payload.get("event"))
    if event not in _SQLCIPHER_EVENTS:
        event = "exported" if _as_clean_str(payload.get("plain_path")) else "key_only"

    plain_path = _as_clean_str(payload.get("plain_path"), 1024)
    raw_key = payload.get("key")
    key = _truncate_secret(str(raw_key)) if isinstance(raw_key, str) and raw_key.strip() else ""

    return {
        "event": event,
        "db_path": db_path,
        "plain_path": plain_path or "",
        "key": key,
        "where": _as_clean_str(payload.get("where")) or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


# ---------------------------------------------------------------------------
# 第二波：剪贴板事件规范化 —— ★ 隐私护栏：抽地址、丢全文
# ---------------------------------------------------------------------------


def normalize_clipboard_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧剪贴板文本 payload 规范化为「只含校验通过的链上地址」的事件；无地址 → None。

    **★ 隐私护栏（本函数的核心职责，必须照做）**：剪贴板含验证码/密码/聊天等隐私。本函数收到
    剪贴板文本后**立即** :func:`apkscan.core.chainaddr.find_addresses` 抽出过校验和 + 判链的
    地址，**只保留地址列表、丢弃原文**——返回的事件**绝不含**剪贴板全文或任何隐私串，落进
    ``runtime_report.json['clipboard_events']`` 的也只有抽出的地址。文本里没有合法地址 → 返回
    None（该事件为空、不留任何内容）。

    **clipboard_event 权威 schema**（producer=Frida FRIDA_CLIPBOARD_HOOK_JS 回传文本，
    本函数=normalizer 抽地址丢全文，consumer=merge_runtime_clipboard）：

    - ``addresses``: ``[{"value": 地址, "chain": TRON|EVM|BTC, "checksum_verified": bool}, ...]``
      —— 去重保序、全部过 chainaddr 校验（随机串/隐私文本被滤掉）。
    - ``ts``: JS Date.now()（int 或 None），仅排序/去重。

    绝不抛（on_message 在 Frida 回调线程触发）。
    """
    if not isinstance(payload, dict):
        return None
    text = payload.get("text")
    if not isinstance(text, str) or not text:
        return None
    # ★ 立刻抽地址、丢全文：text 只在此函数内存里走一遭，下面只把抽出的地址放进事件。
    try:
        found = chainaddr.find_addresses(text)
    except Exception:  # noqa: BLE001 — 抽取异常按「无地址」保守处理（绝不泄全文）
        logger.exception("[clipboard] 链上地址抽取异常，按无地址处理（不泄全文）")
        return None
    # text 在此之后不再被引用——全文不进任何返回值/sink/磁盘（隐私护栏）。
    if not found:
        return None
    addresses = [
        {"value": a.value, "chain": a.chain, "checksum_verified": a.checksum_verified}
        for a in found
    ]
    return {
        "addresses": addresses,
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def clipboard_addresses_from_events(
    events: list[dict[str, Any]],
) -> list[tuple[str, str, bool]]:
    """从规范化剪贴板事件抽出 ``(value, chain, checksum_verified)`` 链上地址，去重保序。

    供 merge 把运行时剪贴板抓到的地址产成 PAYMENT 类 Lead。坏/空事件被跳过；地址缺 value 跳过。
    """
    out: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        addrs = ev.get("addresses")
        if not isinstance(addrs, list):
            continue
        for a in addrs:
            if not isinstance(a, dict):
                continue
            value = a.get("value")
            if not isinstance(value, str) or not value or value in seen:
                continue
            seen.add(value)
            chain = a.get("chain")
            chain_str = chain if isinstance(chain, str) and chain else "?"
            out.append((value, chain_str, bool(a.get("checksum_verified", False))))
    return out


# ---------------------------------------------------------------------------
# 第二波（最后）：无障碍远控事件规范化 —— 目标包名 / 远控指令 / 屏幕录制 / 回传 host
# ---------------------------------------------------------------------------
#
# ★ 边界（务必照做）：无障碍远控逻辑绝大多数要诱导真人操作才走，launch-only 抓不到——本规范化
#   只做纯逻辑（不抛、限流由 JS 侧封顶），抓没抓到取决于是否有引导式人工动态（merge/Lead 标注）。

#: 远控事件的合法 event 取值（与 JS 侧约定）。
_REMOTE_CONTROL_EVENTS: frozenset[str] = frozenset(
    {"accessibility_event", "gesture", "screencapture", "screen_upload"}
)


def normalize_remote_control_event(payload: Any) -> dict[str, Any] | None:
    """把 JS 侧无障碍远控 payload 规范化为稳定 schema；非法/空 → None（绝不抛）。

    **remote_control_event 权威 schema**（producer=Frida FRIDA_ACCESSIBILITY_HOOK_JS，
    consumer=merge_runtime_remote_control；落进 runtime_report.json['remote_control_events']）：

    - ``event``: ``accessibility_event``（被操作 app 包名）| ``gesture``（下发手势/全局动作 =
      远控指令）| ``screencapture``（MediaProjection 屏幕录制开启）| ``screen_upload``（屏幕/
      控件树回传 host）。
    - ``target_package``: 被劫持的目标 app 包名（accessibility_event 才有；映射机构主体的依据）。
    - ``action``: 远控指令动作（gesture/screencapture：dispatchGesture / performGlobalAction:N /
      createVirtualDisplay）。
    - ``host``: 屏幕/控件树回传服务器 host（screen_upload 才有；并入端点走 infra 分级）。
    - ``ts``: JS Date.now()（int 或 None）。

    判别（容缺，JS 侧字段名 ``package`` → 本侧 ``target_package``）：必须至少带 target_package /
    action / host 之一，否则视为空事件 → None（不留无物证价值的空壳）。
    """
    if not isinstance(payload, dict):
        return None
    event = _as_clean_str(payload.get("event")) or ""
    # JS 侧回传 package；规范化为 target_package（merge 侧亦可直接喂 target_package）。
    target_package = _as_clean_str(payload.get("target_package"), 256) or _as_clean_str(
        payload.get("package"), 256
    )
    action = _as_clean_str(payload.get("action"), 256)
    host = _normalize_host(payload.get("host"))

    if not target_package and not action and not host:
        return None  # 无任何远控物证字段 → 空事件，丢弃

    # event 兜底：未给/非法时按携带的字段推断，确保下游分流稳定。
    if event not in _REMOTE_CONTROL_EVENTS:
        if target_package:
            event = "accessibility_event"
        elif host:
            event = "screen_upload"
        else:
            event = "gesture"

    return {
        "event": event,
        "target_package": target_package or "",
        "action": action or "",
        "host": host or "",
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else None,
    }


def _normalize_host(value: Any) -> str | None:
    """把回传 host 规整为小写域名串；非 str/空/无点（非 FQDN）→ None。"""
    if not isinstance(value, str):
        return None
    h = value.strip().lower().rstrip(".")
    if not h or "." not in h:
        return None
    return h[:256]


# ---------------------------------------------------------------------------
# 从活体事件反推 crypto_recipe meta（喂回 appcrypto.CryptoRecipe.from_meta）
# ---------------------------------------------------------------------------


def recipe_from_events(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """从运行时 crypto 事件反推「实测配方」meta dict（供 merge 用作解密首选）。

    核心价值：拿到**权威 key**（静态可能逆错/逆不到）。返回 dict 只含**有把握**的字段，
    由 merge 浅合并到静态配方上（实测覆盖、缺省回退静态），避免无依据地改写静态推断。

    iv 处理（关键，见 risk）：
      - 实测 iv **恒定且可表示** → ``iv_derive='fixed'`` + ``iv_value``（仅此一招对所有信封成立）。
      - 实测 iv **变化**（如 md5(key+ts) 每请求不同）→ **不设 fixed**：仅反哺 key，iv 仍交
        静态推导（``md5(key+ts)[:16]``）；否则把单次 iv 当 fixed 会解错其它信封。

    Args:
        events: ``make_message_handler`` 收集的事件列表。

    Returns:
        实测配方 meta dict（键与 ``appcrypto.CryptoRecipe.from_meta`` 兼容）；无可用 key → None。
    """
    if not isinstance(events, list) or not events:
        return None

    key_hex = _dominant_key_hex(events)
    if not key_hex:
        logger.info("[cryptohook] 运行时事件无可用 key，跳过实测配方反推")
        return None

    recipe: dict[str, Any] = {}

    # key + key_encoding：key bytes 若是可见 ASCII（CryptoJS enc.Utf8.parse 口径）→ utf8 串；
    # 否则 hex。与 appcrypto._build_key 的两种解析口径对齐。
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        return None
    if _bytes_printable_ascii(key_bytes):
        recipe["key"] = key_bytes.decode("ascii")
        recipe["key_encoding"] = "utf8"
    else:
        recipe["key"] = key_hex
        recipe["key_encoding"] = "hex"

    # algo/mode/padding：从 transformation 解析（取首个非空 cipher transformation）。
    transformation = _dominant_transformation(events)
    if transformation:
        algo, mode, padding = transformation_parts(transformation)
        if algo:
            recipe["algo"] = algo
        if mode:
            recipe["mode"] = mode
        if padding:
            recipe["padding"] = padding

    # iv：仅在恒定且可按 key_encoding 表示时设 fixed（否则交静态推导）。
    iv_value = _constant_iv_value(events, recipe["key_encoding"])
    if iv_value is not None:
        recipe["iv_derive"] = "fixed"
        recipe["iv_value"] = iv_value

    return recipe


def _dominant_key_hex(events: list[dict[str, Any]]) -> str:
    """取出现最多的 key_hex（优先 cipher/secretkeyspec 来源；Mac 的 HMAC key 仅兜底）。"""
    counts: dict[str, int] = {}
    mac_counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kh = ev.get("key_hex")
        if not isinstance(kh, str) or not kh:
            continue
        if ev.get("src") == "mac":
            mac_counts[kh] = mac_counts.get(kh, 0) + 1
        else:
            counts[kh] = counts.get(kh, 0) + 1
    pool = counts or mac_counts
    if not pool:
        return ""
    # 出现次数降序、长度降序（偏好更长 key，如 AES-256 32B），稳定。
    return sorted(pool.items(), key=lambda kv: (-kv[1], -len(kv[0])))[0][0]


def _dominant_transformation(events: list[dict[str, Any]]) -> str:
    """取 cipher 事件里出现最多的非空 transformation。"""
    counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict) or ev.get("src") != "cipher":
            continue
        t = ev.get("transformation")
        if isinstance(t, str) and t:
            counts[t] = counts.get(t, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _constant_iv_value(events: list[dict[str, Any]], key_encoding: str) -> str | None:
    """实测 iv 恒定且可按 key_encoding 表示时返回 iv_value 串；变化/不可表示/无 → None。

    - key_encoding=='hex'：iv_value 直接用 hex 串（appcrypto fixed 分支按 hex 解析）。
    - key_encoding=='utf8'：仅当 iv bytes 是可见 ASCII 才用 ascii 串；否则不可表示 → None。
    """
    ivs: set[str] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        iv = ev.get("iv_hex")
        if isinstance(iv, str) and iv:
            ivs.add(iv)
    if len(ivs) != 1:
        return None  # 0=无 iv；>1=变化（如 md5(key+ts)），都不设 fixed
    iv_hex = next(iter(ivs))
    if key_encoding == "hex":
        return iv_hex
    # utf8：iv 须可见 ASCII 才能按 utf8 串表示（appcrypto fixed+utf8 走 .encode('utf-8')）。
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError:
        return None
    if _bytes_printable_ascii(iv_bytes):
        return iv_bytes.decode("ascii")
    return None


def transformation_parts(transformation: str) -> tuple[str, str, str]:
    """把 ``AES/CFB/PKCS5Padding`` 拆成 (algo, mode, padding)，规整成 appcrypto 口径。

    单段（如 ``AES``）→ 只有 algo，mode/padding 空（交静态/默认补）。未知值原样上抛大写。
    """
    if not transformation:
        return "", "", ""
    parts = [p.strip() for p in transformation.split("/")]
    algo = _norm_algo(parts[0]) if parts and parts[0] else ""
    mode = _norm_mode(parts[1]) if len(parts) > 1 and parts[1] else ""
    padding = _norm_padding(parts[2]) if len(parts) > 2 and parts[2] else ""
    return algo, mode, padding


def _norm_algo(raw: str) -> str:
    low = raw.strip().lower()
    if low == "aes":
        return "AES"
    if low in ("desede", "tripledes", "3des", "des3"):
        return "3DES"
    if low == "des":
        return "DES"
    return raw.strip().upper()


def _norm_mode(raw: str) -> str:
    low = raw.strip().lower()
    for mode in ("cfb", "cbc", "ecb", "ctr", "ofb", "gcm"):
        if low.startswith(mode):
            return mode.upper()
    return raw.strip().upper()


def _norm_padding(raw: str) -> str:
    low = raw.strip().lower()
    if low in ("pkcs5padding", "pkcs7padding", "pkcs5", "pkcs7"):
        return "Pkcs7"
    if low in ("nopadding", "none", ""):
        return "NoPadding"
    return raw.strip()


def _bytes_printable_ascii(data: bytes) -> bool:
    """非空且全为可见 ASCII（0x20..0x7e）→ True（用于判 key/iv 是否 utf8 文本口径）。"""
    return len(data) > 0 and all(0x20 <= c <= 0x7e for c in data)


# ---------------------------------------------------------------------------
# 从活体明文抽冒充品牌线索（反诈视角）
# ---------------------------------------------------------------------------


def brand_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从 doFinal 捕获的明文里抽冒充对象（webName/品牌名/行业词），去重保序。

    解 ``plaintext_b64`` → UTF-8 文本 → 若是 JSON 取 _BRAND_KEYS 的值；并对所有字符串值
    扫 _BRAND_HINT_TOKENS（证券/银行/…）命中即收。任何一步失败只跳过该条，绝不抛。
    """
    hints: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        v = value.strip()
        if v and v not in seen and len(v) <= 80:
            seen.add(v)
            hints.append(v)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        text = _plaintext_of(ev)
        if not text:
            continue
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            obj = None
        if obj is not None:
            for key, val in _walk_strings(obj):
                if key.lower() in _BRAND_KEYS:
                    _add(val)
                if any(tok in val for tok in _BRAND_HINT_TOKENS):
                    _add(val)
        else:
            if any(tok in text for tok in _BRAND_HINT_TOKENS):
                # 非 JSON 明文：截一段含行业词的上下文。
                _add(text[:80])
    return hints


def _plaintext_of(event: dict[str, Any]) -> str:
    """把事件的 plaintext_b64 解成 UTF-8 文本；缺/坏 → 空串（不抛）。"""
    b64 = event.get("plaintext_b64")
    if not isinstance(b64, str) or not b64:
        return ""
    try:
        raw = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8", errors="ignore")


def _walk_strings(obj: Any, key: str = "") -> list[tuple[str, str]]:
    """递归收集 JSON 里的 (key, str_value) 对（与 merge._walk_json_strings 同范式）。"""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, str(k)))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_strings(item, key))
    elif isinstance(obj, str):
        out.append((key, obj))
    return out


def jsbridge_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从 JS-bridge 事件抽「接口名（+方法）」线索，去重保序。

    register → ``<iface>``（及暴露方法概览）；call → ``<iface>.<method>``。供 merge 把
    运行时实际暴露/调用的桥接面并回报告（确认静态 webview_jsbridge 的桥接面）。
    """
    hints: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        v = value.strip()
        if v and v not in seen and len(v) <= 120:
            seen.add(v)
            hints.append(v)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        iface = str(ev.get("iface", "")).strip()
        if not iface:
            continue
        if ev.get("event") == "call" and ev.get("method"):
            _add(f"{iface}.{str(ev.get('method')).strip()}")
        else:
            _add(iface)
    return hints


def sensitive_api_hints_from_events(events: list[dict[str, Any]]) -> list[str]:
    """从敏感 API 事件抽「<类>.<方法>」清单，去重保序（供 merge 确认静态 sensitive_api）。"""
    hints: list[str] = []
    seen: set[str] = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        api = str(ev.get("api", "")).strip()
        if api and api not in seen:
            seen.add(api)
            hints.append(api)
    return hints


def antidetect_kinds_from_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """统计样本自我检测的种类计数（root/emulator/frida/…），供报告呈现反取证/反分析行为画像。"""
    counts: dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("kind", "")).strip()
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


__all__ = [
    "FRIDA_CRYPTO_HOOK_JS",
    "FRIDA_JSBRIDGE_HOOK_JS",
    "FRIDA_SENSITIVE_API_HOOK_JS",
    "FRIDA_ANTIDETECT_JS",
    "FRIDA_OKHTTP_HOOK_JS",
    "FRIDA_SQLCIPHER_HOOK_JS",
    "FRIDA_CLIPBOARD_HOOK_JS",
    "FRIDA_ACCESSIBILITY_HOOK_JS",
    "CRYPTO_MSG_TYPE",
    "JSBRIDGE_MSG_TYPE",
    "SENSITIVE_API_MSG_TYPE",
    "ANTIDETECT_MSG_TYPE",
    "CREDENTIAL_MSG_TYPE",
    "SQLCIPHER_MSG_TYPE",
    "CLIPBOARD_MSG_TYPE",
    "ACCESSIBILITY_MSG_TYPE",
    "make_message_handler",
    "make_typed_handler",
    "normalize_crypto_event",
    "normalize_jsbridge_event",
    "normalize_sensitive_api_event",
    "normalize_antidetect_event",
    "normalize_credential_event",
    "normalize_sqlcipher_event",
    "normalize_clipboard_event",
    "normalize_remote_control_event",
    "clipboard_addresses_from_events",
    "extract_sharedprefs_credentials",
    "recipe_from_events",
    "brand_hints_from_events",
    "jsbridge_hints_from_events",
    "sensitive_api_hints_from_events",
    "antidetect_kinds_from_events",
    "transformation_parts",
]
