"""apkscan.dynamic.probe_ingest — 独立 frida 探针(`-l` 注入)散点输出 → 调证台账 / report.leads。

取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。

frida 探针(**本仓库不提供、需自备**)是手注 `-l` 工具，各自往 console 吐 `[tag][LEAD-...]` 标记的线索，
散落在 `frida -o probe.log` 的文本里。本模块把这些散点**解析→按 LeadCategory 分类→去重→聚成
调证台账(md/json)**，并可**追加进已有 report.json 的 leads 数组**——补上路线图「编排输出层」缺的
那截「设备探针日志 → report.leads 的 Python 回灌解析器」。

设计铁律（与 dynamic 一致）：纯逻辑、结构化返回、**绝不把异常抛给调用方**（内部 try/except +
logging）、不静默吞错、全量 type hints。:func:`parse_probe_log` 是纯函数，便于单测。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from apkscan.core import infra
from apkscan.core import runtime_inventory as _inv
from apkscan.core.atomic import atomic_write_text
from apkscan.core.models import (
    Confidence,
    Evidence,
    Lead,
    LeadCategory,
    merge_runtime_into_lead_dict,
)
from apkscan.core.restore import restore_index, strip_restored_downgrades
from apkscan.core.textutil import (
    host_from_url,
    host_is_private,
    is_noise_bare_ip,
    parse_ipv4,
    valid_url_host,
)

logger = logging.getLogger(__name__)

# 探针线索来源标记（与 merge.py 一致：source 以 runtime 开头 → Lead.is_runtime_seen=True）。
_RUNTIME_SOURCE = "runtime-probe"

# 探针 tag → (LeadCategory, where_to_request)。tag 即各探针 console.log 的 `[xxx]` 前缀。
_TAG_MAP: dict[str, tuple[LeadCategory, str]] = {
    "pay": (LeadCategory.PAYMENT, "凭商户号/seller_id/partnerId 向支付宝(蚂蚁)/财付通(微信)/银联调实名结算账户与资金流水。"),
    "sms": (LeadCategory.SMS_FORWARDING, "凭转发目标号码向运营商/短信平台调机主实名与接收记录(OTP 接管基础设施)。"),
    "push-c2": (LeadCategory.SELF_HOSTED_IM, "C2 域名向云厂商/IDC 调服务器归属与信道日志；凭 regId/appKey 向推送厂商调注册主体实名。"),
    "sens": (LeadCategory.VICTIM_DATA, "固证 App 窃取的受害人数据(通讯录/短信/位置/剪贴板/IMEI)，按合规留存处置。"),
    "a11y": (LeadCategory.REMOTE_CONTROL, "无障碍远控操控物证；映射被劫持的银行/支付 app，指明向哪些机构调被害人流水。"),
    "nfc": (LeadCategory.CARD_MERCHANT, "凭 SELECT AID 向卡组织/发卡行调订单与收款方(NFC 中继盗刷)。"),
    "ks": (LeadCategory.CRYPTO_RECIPE, "解密 key→脱机解密缴获流量/落地库(凭此可解全部加密通信与物证库)。"),
    "mmkv": (LeadCategory.CRYPTO_RECIPE, "MMKV/Realm/WCDB 加密 key→脱机解密整库(IM/转账记录)。"),
    "key": (LeadCategory.CRYPTO_RECIPE, "native 对称 key+iv→离线解密缴获流量/配置。"),
    "cipher": (LeadCategory.CRYPTO_RECIPE, "应用层加密 key/iv/算法→离线解密配置与流量。"),
    "sign": (LeadCategory.CRYPTO_RECIPE, "被签明文+算法+HMAC key→离线自造签名/复现请求。"),
    "sdk": (LeadCategory.CHANNEL, "凭 appKey/租户标识向 SDK 服务商(OpenInstall/友盟等)调开发者账户实名+渠道/安装日志(分发链定人)。"),
    "objstore": (LeadCategory.CONFIG_KEY, "凭对象存储 bucket 名/账户向云厂商(阿里OSS/百度BOS/天翼ZOS)调创建者实名+上传/访问日志。"),
    "coldstart": (LeadCategory.CONFIG_KEY, "冷启动配置端点/疑似后端向注册商/云厂商调归属。"),
    "tg": (LeadCategory.SELF_HOSTED_IM, "Telegram/MTProto 接入节点向云厂商调主机租户实名+连接日志；登录账号/聊天明文作物证。"),
    "rtc": (LeadCategory.CHANNEL, "凭 appId/sdkAppId 向声网/腾讯TRTC/即构调实名；channel/room 绑受害人与话务员(裸聊物证)。"),
    "mqtt": (LeadCategory.SELF_HOSTED_IM, "MQTT/XMPP broker host:port 向云厂商/IDC 调归属；userName/password 作凭据。"),
    "ws": (LeadCategory.SELF_HOSTED_IM, "WebSocket 聊天网关向云厂商调服务器归属与信道日志。"),
    "prefs": (LeadCategory.RUNTIME_CREDENTIAL, "本地落地凭据/租户ID；凭手机号向运营商、凭 token 向平台调登录态。"),
    "sqlcipher": (LeadCategory.VICTIM_DATA, "落地库受害人物证(IM 账号/手机号/订单/商户号/话术)，按合规留存处置。"),
    "netstat": (LeadCategory.IP, "native 接入节点 IP:port 向云厂商调主机租户实名+入站连接日志。"),
    "socket": (LeadCategory.IP, "裸 socket 对端 IP:port 向云厂商调主机归属。"),
    "http": (LeadCategory.DOMAIN, "出站域名向注册商/云厂商调注册实名与服务器归属。"),
    "okint": (LeadCategory.DOMAIN, "请求-响应真后端域名向注册商/云厂商调归属。"),
    "cronet": (LeadCategory.DOMAIN, "Cronet(QUIC) 真后端域名向注册商/云厂商调归属。"),
    "dns": (LeadCategory.DOMAIN, "域名→IP 解析目标向注册商/云厂商调归属。"),
    "rn-bridge": (LeadCategory.DOMAIN, "RN 业务参数里的 baseURL/真后端向注册商/云厂商调归属。"),
    "wvinject": (LeadCategory.DOMAIN, "H5 渲染层真实后端端点向注册商/云厂商调归属。"),
    "webview": (LeadCategory.DOMAIN, "WebView 端点向注册商/云厂商调归属。"),
    "ssl": (LeadCategory.IP, "TLS 五元组/SNI 真实对端 IP:port 向云厂商调归属。"),
}

# 行内关键词二次修正（优先级高于 tag 默认，处理同一探针多语义/跨探针铁证）。
_KEYWORD_CATEGORY: list[tuple[re.Pattern[str], LeadCategory]] = [
    (re.compile(r"钱包|助记词|私钥|mnemonic|wallet[_ ]?(key|secret|seed)", re.I), LeadCategory.WALLET_SECRET),
    (re.compile(r"商户号|seller_id|partnerId|mch[_ ]?id", re.I), LeadCategory.PAYMENT),
]

# 未知 tag 的兜底分类。
_DEFAULT: tuple[LeadCategory, str] = (
    LeadCategory.CONFIG_KEY,
    "运行时探针捕获的线索，结合上下文研判后向对应服务商/平台调证。",
)

# 含受害人/高敏个人信息的类别 → Lead.notes 附合规提示。
_SENSITIVE_CATS = {
    LeadCategory.VICTIM_DATA,
    LeadCategory.REMOTE_CONTROL,
    LeadCategory.RUNTIME_CREDENTIAL,
    LeadCategory.WALLET_SECRET,
}
_COMPLIANCE_NOTE = (
    "运行时探针实测捕获，含受害人/高敏个人信息，已截断；按办案合规要求留存处置，不得外泄全文。"
)

# 纯导航/定位/脱壳辅助探针，不产调证锚点 → 解析时跳过（avoid noise）。
_SKIP_TAGS = {
    "nav", "acts", "goto", "frag", "wipe", "self-wipe", "multiopen", "register-natives",
    "dexload", "memdex", "loadlib", "exec", "unpin", "anti", "anti-native", "tenant", "native",
}

# 三类调证价值轴 → 命中即覆盖的 LeadCategory（取证完备性诊断用）。
_AXIS_CATS: dict[str, set[LeadCategory]] = {
    "定人(锚定自然人/账户)": {
        LeadCategory.PAYMENT, LeadCategory.CHANNEL, LeadCategory.SMS_FORWARDING,
        LeadCategory.CARD_MERCHANT, LeadCategory.RUNTIME_CREDENTIAL, LeadCategory.CONTACT,
        LeadCategory.CONFIG_KEY, LeadCategory.SDK_SERVICE,
    },
    "穿透(逼出真源站/接入节点)": {
        LeadCategory.DOMAIN, LeadCategory.IP, LeadCategory.SELF_HOSTED_IM, LeadCategory.ADMIN_PANEL,
    },
    "固证(受害人物证/远控/解密)": {
        LeadCategory.VICTIM_DATA, LeadCategory.REMOTE_CONTROL, LeadCategory.WALLET_SECRET,
        LeadCategory.CRYPTO_RECIPE, LeadCategory.FOURTH_PARTY_PAYMENT,
    },
}
# 某轴未覆盖时的补跑建议（指向具体探针）。
_AXIS_SUGGEST: dict[str, str] = {
    "定人(锚定自然人/账户)": "补跑 pay-sdk / sdk-appkey / sms-forward-outbound / sharedprefs 抓商户号/appKey/转发号/落地凭据。",
    "穿透(逼出真源站/接入节点)": "补跑 http-url / okhttp-interceptor / cronet-quic-http3 / native-ssl / netstat / coldstart-config 抓真后端域名/native 接入节点。",
    "固证(受害人物证/远控/解密)": "补跑 sensitive-data-access / sqlite(SQLCipher) / accessibility-abuse / keystore-alias-tracer 抓受害人数据/落地库/远控/解密 key。",
}

_TAG_RE = re.compile(r"^\s*\[([a-z0-9][a-z0-9_-]*)\]")
#: 探针标记 ``[xxx]``。★否定先行断言把 **IPv6 字面量**排除在外：``[2001:db8::1]`` 与探针标记
#: 同形，无条件抹掉会把 ``http://[2001:db8::1]:8443/x`` 削成 ``http:// :8443/x`` ——
#: 于是公网 IPv6 端点在 :func:`probe_address_values` 里连正则都匹配不到，v6 通道恒为空。
#: 判据：方括号内含 ``:`` 且只有十六进制/冒号/点/百分号（v6 与 v6+zone 的字符集），即视为地址。
_BRACKET_RE = re.compile(r"\[(?![0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*\])[^\]]*\]")
_WS_RE = re.compile(r"\s+")
# 行首 ISO-8601 时间戳（logcat/frida 常见前缀），如 "2026-07-02 10:30:00" / "…10:30:00.123"。
# 分组 1 = 时间串，分组 2 = 行首时间戳后的剩余内容（交给 tag/value 解析）。
_TS_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.*)$"
)


def _split_leading_ts(line: str) -> tuple[float | None, str]:
    """剥离行首 ISO 时间戳，返回 ``(epoch 秒 | None, 去时间戳后的行)``。

    解析失败（无时间戳 / 格式非法）时返回 ``(None, 原行)``——观测时间是可选富化，缺失不影响线索。
    """
    m = _TS_RE.match(line)
    if not m:
        return None, line
    raw_ts, rest = m.group(1), m.group(2)
    try:
        dt = datetime.fromisoformat(raw_ts.replace(" ", "T"))
    except ValueError:
        logger.debug("[probe_ingest] 行首时间戳解析失败，忽略：%r", raw_ts)
        return None, line
    return dt.timestamp(), rest


@dataclass
class ProbeLead:
    """一条由探针日志解析出的调证线索。"""

    category: LeadCategory
    value: str
    probe: str  # 探针 tag（如 pay/sms/ks）
    raw: str  # 原始日志行（证据留痕）
    where_to_request: str = ""
    observed_at: float | None = None  # 行首时间戳（Unix epoch 秒），日志无时间前缀则 None


def _first_tag(line: str) -> str | None:
    """取行首第一个 `[xxx]`（探针 tag），无则 None。"""
    m = _TAG_RE.match(line)
    return m.group(1) if m else None


def _extract_value(line: str) -> str:
    """去掉所有 `[..]` 标记 + 折叠空白，留下真锚点内容（IP/商户号/域名/字段值）。"""
    v = _BRACKET_RE.sub(" ", line)
    v = _WS_RE.sub(" ", v).strip(" \t·>=-—←")
    return v


def _classify(tag: str, line: str) -> tuple[LeadCategory, str]:
    """tag → (category, where)，行内关键词命中则覆盖 category（保留 tag 的 where）。"""
    base = _TAG_MAP.get(tag, _DEFAULT)
    for pat, cat in _KEYWORD_CATEGORY:
        if pat.search(line):
            return cat, base[1]
    return base


def parse_probe_log(text: str) -> list[ProbeLead]:
    """解析 frida 探针日志，抽出含 `[LEAD` 的行为结构化线索。纯函数，绝不抛。

    - 只取含 `[LEAD` 标记的行（探针对高价值锚点的显式标注）。
    - 行首 tag 在 :data:`_SKIP_TAGS`（导航/定位/脱壳辅助）→ 跳过。
    - value 去掉方括号标记后的真锚点内容；空则丢。
    """
    out: list[ProbeLead] = []
    if not text:
        return out
    for line in text.splitlines():
        if "[LEAD" not in line:
            continue
        try:
            # 剥离行首时间戳后再做 tag/value 解析（时间戳不在方括号内，否则会污染 value）；
            # raw 仍留原始整行作证据。
            observed_at, body = _split_leading_ts(line)
            tag = _first_tag(body)
            if tag is None or tag in _SKIP_TAGS:
                continue
            cat, where = _classify(tag, body)
            value = _extract_value(body)
            if not value:
                continue
            out.append(
                ProbeLead(
                    category=cat,
                    value=value,
                    probe=tag,
                    raw=line.strip(),
                    where_to_request=where,
                    observed_at=observed_at,
                )
            )
        except Exception:  # noqa: BLE001 - 单行解析失败不影响其余
            logger.exception("[probe_ingest] 解析行失败，跳过：%r", line)
    return out


def dedup(leads: list[ProbeLead]) -> list[ProbeLead]:
    """按 (category, value) 去重，保持首现顺序。"""
    seen: set[tuple[str, str]] = set()
    out: list[ProbeLead] = []
    for pl in leads:
        key = (pl.category.value, pl.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(pl)
    return out


def _network_target(value: str) -> tuple[str, str] | None:
    """从线索值里提取网络标的，返回 ``("domain"|"ip", 标的)``；值里没有网络标的则 ``None``。

    ★**按形态提取，不按 category 猜**。这是本函数存在的全部理由：探针的 category 是**业务
      语义**（谁该被追问：支付、短信转发、自建 IM…），而「这个值是不是网络标的」是**形态
      问题**。两者不重合——`push-c2` 这个 tag 映射到的是 :attr:`LeadCategory.SELF_HOSTED_IM`
      而不是 DOMAIN，可它的值恰恰就是域名或 wss:// URL。按 category 分流会漏掉它，而它正是
      厂商推送域被判最高档那条事故路径本身。

    识别的形态：带 scheme 的 URL（取 host）、``host:<数字端口>``（剥端口）、裸 IP、裸域名。
    商户号、密钥、手机号、描述串这些提取不到标的，返回 ``None`` 由调用方按类别语义处置。

    ★主机名走**严格** DNS 校验（每标签 1–63 字符、仅字母数字与连字符、不以连字符开头结尾），
      不能用 ``valid_url_host``——那个只查「含点 + 末段是 2–24 位字母」，于是
      ``key=<长串>.ab`` 这类点分密钥、签名串会被当成域名交给判据链。探针的值里本来就混着
      密钥、token、描述串，这道校验是它们与真标的之间唯一的分界。

    ★端口必须是**数字**才剥。``_strip_port_suffix`` 对 ``host:任意后缀`` 一律剥，于是
      ``<厂商域>:not-a-port`` 这种描述串会被剥出一个厂商域来、进而被压档。
    """
    raw = str(value).strip()
    if not raw:
        return None
    explicit_shape = "://" in raw  # 有 scheme：形态明确是网络标的，host 允许单标签
    if explicit_shape:
        host = str(host_from_url(raw) or "").strip()
    else:
        host, sep, tail = raw.rpartition(":")
        if sep and host and not host.endswith(":") and tail.isdigit() and 1 <= int(tail) <= 65535:
            # host:<合法端口>：形态明确。★端口要在合法范围内——``token:0`` / ``key:000000``
            #   这种「冒号后跟一串数字」的非网络值不该凭此拿到单标签放行。
            explicit_shape = True
        else:
            host = raw
    host = host.strip().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return ("ip", host)
    if not _is_strict_hostname(host, allow_single_label=explicit_shape):
        return None
    return ("domain", host)


#: 合法 DNS 标签：1–63 字符，字母数字与连字符，不以连字符开头或结尾。
_DNS_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)\Z")


def _is_strict_hostname(host: str, *, allow_single_label: bool) -> bool:
    """严格主机名校验。``allow_single_label`` 只在形态已明确（有 scheme 或数字端口）时为真。

    裸值必须多标签：单标签的裸字符串（``key``、``token``、随便一个词）与主机名无法区分，
    按主机名处理就是在替一堆非网络值找判据。
    """
    if not host or len(host) > 253 or " " in host:
        return False
    labels = host.split(".")
    if not allow_single_label and len(labels) < 2:
        return False
    return all(_DNS_LABEL_RE.match(label) for label in labels)


def _network_advice(kind: str, target: str) -> tuple[str, str]:
    """网络标的的档位：**走判据链**，但保底待核、绝不落 SKIP。返回 (档位, 说明)。

    ★为什么不能沿用「探针捕到的一律最高档」：那是只看 category、不看值本身的赋值，等于主张
      「凡是探针见过的名字，其持有方都值得被追问」。可是探针照样会捕到已知第三方基础设施
      （推送接入段、IP 回显服务这些）——它们的持有方与本次分析无关，把它们放进最高档就是
      本项目定义中最重的那类误判。旧行为没在 letters 上酿成事故，只是因为探针 Lead 恰好没填
      ``evidence_to_obtain``、被 :func:`report.letters._is_actionable` 的条件 2 挡下——那是
      运气不是设计：谁哪天给探针 Lead 补上取证路径，闸门就无声打开了。

    ★为什么保底待核、不落 SKIP：探针是**进程内**的，捕到的是这个 App 自己的行为，不像整机
      pcap 那样存在「别的 App 的流量」的归因问题。「该 App 的代码真的碰了这个值」这一事实
      比静态字符串强得多。而 SKIP 是判据链结论、不走抑制账本，``fxapk lead restore`` 够不着
      ——一旦落进去就再也捞不回来。真 C2 借宿在厂商域下（非租户桶形态）时，保底待核是唯一
      还留得住这条观测的档位：关掉自动出口，但留在清单里供人核。

    ★IP 走 :func:`infra.classify_ip` 而不是域名判据链——公共递归 DNS / 权威 DNS / 非全球地址
      / 低段位形态这些判据全在 IP 侧，拿域名判据去判 IP 会整套绕过去（公共 DNS 的 IP 尤其会
      一路落到最高档）。

    ★``classify_ip`` 的 ``runtime_observed`` **有意传默认的 False**：它是用来豁免「低段位裸 IP
      疑似版本号」那类形态怀疑的，传 True 会让一部分 IP 从待核**升**到最高档。本刀是收紧刀，
      不夹带任何新的升档路径；何况该参数与 vendor_sdk_binary 的排序本身尚未定论，另案再议。

    ★★**只认判据链里的「身份判定」，不认「形态怀疑」**——这是本函数最要紧的一条。

      判据链里两类结论混在一起：一类回答「这个标的的持有方是谁」（命中已知第三方基础设施、
      库内置站点、协议标识符、公网 IP 回显服务、公共递归 DNS…），另一类回答「这个字面像不像
      真域名」（长高熵串疑似编码、单个常见词、保留测试域、行情代码…）。

      对探针捕获的值，**只有前一类成立**。后一类的前提是「这串东西可能压根不是域名，只是被
      当成域名切出来的字符串」——而探针看到的是 App 运行时真的在用的值，它像不像域名不影响
      「它的持有方是不是无关第三方」这个问题。更要紧的是，探针的值里本来就混着密钥、token、
      签名串：让形态怀疑参与压档，等于让 ``CRYPTO_RECIPE`` / ``RUNTIME_CREDENTIAL`` 这些本该
      最高档的线索，因为值的偶然形态（点分 base64 恰好像域名）被压下去。

      所以这里只把 :data:`infra.ADVICE_SKIP` 这一档（身份判定的出口）连同两条**出口是待核、
      但实质属身份判定**的分支当成压档依据；判据链给出的其它「待核」一律不采纳，档位交回
      类别语义。那两条是：

      - **公网 IP 回显服务**：这类域的持有方与本次分析无关；
      - **RFC/IANA 特殊用途域**（``.test`` / ``.example`` / ``.localhost`` / ``.local`` …）：
        标准机制各不相同（测试保留域 / 回环语义 / mDNS 链路本地），但在本函数关心的那个维度上
        结论一致——**不是公共 DNS 里可注册的域，不存在可向注册商查询的注册人**。这不是「看起来
        不像域名」：它像不像无关紧要，重点是标准保证了没有持有方可查。把它当形态怀疑放行，
        就会让一个明知查无此人的域进最高档、进而进文书出口。
    """
    try:
        if kind == "ip":
            advice, reason = infra.classify_ip(target)
            identity_review = ""
        else:
            advice, reason = infra.classify_domain(target)
            echo = infra._public_ip_echo_service(target)
            reserved = infra._reserved_domain_match(target)
            if echo is not None:
                identity_review = f"公网 IP 回显 / 地理查询服务（{echo}），非自有后端"
            elif reserved is not None:
                identity_review = (
                    f"标准保留的文档/测试域（{reserved}，RFC 2606/6761/6762 明令不可注册）"
                    "——不存在可查的注册人"
                )
            else:
                identity_review = ""
    except Exception:  # noqa: BLE001 - 判据失败不阻断回灌，退回保底档
        logger.warning("探针线索 %r 的档位判据失败，退回保底待核", target[:80])
        return infra.ADVICE_REVIEW, "档位判据失败，保底待核"
    if advice == infra.ADVICE_SKIP:
        return infra.ADVICE_REVIEW, f"判据链判「无需再核」（{reason}），但进程内探针实测捕获，保底待核"
    if identity_review:
        return infra.ADVICE_REVIEW, identity_review
    # 形态怀疑类的「待核」不采纳——见上面那条。返回空档位，由调用方回落到类别语义。
    return "", ""


def to_report_leads(leads: list[ProbeLead]) -> list[Lead]:
    """把 ProbeLead 转成 report 的 :class:`Lead`（source=runtime-probe，含合规提示）。

    advice 的定法，按**值的形态**而不是 category：值里提取得到网络标的（域名 / IP，含 URL 与
    ``host:port`` 形态）的，走 :func:`_network_advice` 的判据链 + 保底待核；提取不到的按类别
    语义——CARD_MERCHANT（情报研判）待核，其余最高档，它们的标的是商户号 / 密钥 / 被劫持的
    机构这类东西，域名判据链管不着，本来就该由人去核。

    ★为什么不按 category 分流：``push-c2`` 这个 tag 映射到的是 ``SELF_HOSTED_IM`` 而不是
      ``DOMAIN``，它的值却恰恰是域名或 ``wss://`` URL——按 category 分流会整条漏掉，而它正是
      厂商推送域被判最高档那条路径本身。category 是「谁该被追问」的业务语义，
      「这个值是不是网络标的」是形态问题，两者不重合。
    """
    out: list[Lead] = []
    for pl in dedup(leads):
        advice, advice_reason = "", ""
        target = _network_target(pl.value)
        if target is not None:
            advice, advice_reason = _network_advice(*target)
        if not advice:  # 没有网络标的，或判据链只给出「形态怀疑」——回落到类别语义
            advice = (
                infra.ADVICE_REVIEW if pl.category == LeadCategory.CARD_MERCHANT
                else infra.ADVICE_INVESTIGATE
            )
        notes = _COMPLIANCE_NOTE if pl.category in _SENSITIVE_CATS else "运行时探针实测捕获。"
        if advice_reason:
            notes = f"{notes}（{advice_reason}）"
        out.append(
            Lead(
                category=pl.category,
                value=pl.value[:200],
                where_to_request=pl.where_to_request or None,
                confidence=Confidence.HIGH,
                advice=advice,
                # ★同时封存 base_advice：这是判据链（含保底规则）的结论，探针路径此前完全没接
                #   可撤销抑制机制——base 为 None 意味着将来任何一次降档都撤不回来。
                base_advice=advice,
                source_refs=[
                    Evidence(
                        source=_RUNTIME_SOURCE,
                        location="frida-probe:" + pl.probe,
                        snippet=pl.raw[:200],
                        observed_at=pl.observed_at,
                    )
                ],
                notes=notes,
            )
        )
    return out


def coverage_axes(leads: list[ProbeLead]) -> dict[str, dict[str, object]]:
    """诊断三类调证价值轴（定人/穿透/固证）的覆盖情况 + 未覆盖轴的补跑建议。

    Returns:
        ``{轴名: {"covered": bool, "categories": [命中的 category.value], "suggestion": str}}``。
        covered 轴 suggestion 为空串；未覆盖轴给指向具体探针的补跑建议。
    """
    present = {pl.category for pl in dedup(leads)}
    out: dict[str, dict[str, object]] = {}
    for axis, cats in _AXIS_CATS.items():
        hit = sorted(c.value for c in (present & cats))
        out[axis] = {
            "covered": bool(hit),
            "categories": hit,
            "suggestion": "" if hit else _AXIS_SUGGEST[axis],
        }
    return out


# markdown 台账里嵌样本可控字段（探针 value/probe 抽自 Frida console，样本可影响其文本）前必转义：
# 折叠空白（堵"值里塞换行伪造新标题/字段行"）+ 转义 markdown 结构/行内语法字符（含反引号——堵逃逸
# inline-code 注入原始 HTML/链接）。主 HTML 报告另走 Jinja 自动转义、不受此路径影响。
_MD_SPECIAL_CHARS = re.compile(r"([\\`*_{}\[\]()#+\-.!|>&<~])")
_MD_WS_RUN = re.compile(r"\s+")


def _md_escape(value: object) -> str:
    """把样本可控字段转成安全内嵌 markdown 文本（只对攻击者可控字段调用；固定文案无需转义）。"""
    return _MD_SPECIAL_CHARS.sub(r"\\\1", _MD_WS_RUN.sub(" ", str(value)).strip())


def build_ledger_md(leads: list[ProbeLead]) -> str:
    """把线索聚成调证台账（markdown），按 LeadCategory 分组、每组带 where_to_request，
    末尾附「取证完备性」三轴诊断（定人/穿透/固证覆盖 + 缺轴补跑建议）。
    """
    deduped = dedup(leads)
    by_cat: dict[LeadCategory, list[ProbeLead]] = {}
    for pl in deduped:
        by_cat.setdefault(pl.category, []).append(pl)
    lines: list[str] = [
        "# 调证台账（frida 探针线索聚合）",
        "",
        f"共 {len(deduped)} 条去重线索，{len(by_cat)} 类。来源：独立探针 `-l` 注入的 console 输出。",
        "",
    ]
    for cat in sorted(by_cat, key=lambda c: c.value):
        items = by_cat[cat]
        lines.append(f"## {cat.value}（{len(items)} 条）")
        where = items[0].where_to_request
        if where:
            lines.append(f"> 调证落点：{where}")
        lines.append("")
        for pl in items:
            # value/probe 样本可控 → 转义（含反引号）后作纯文本嵌入，绝不裸包 inline-code 让载荷逃逸注入。
            lines.append(f"- {_md_escape(pl.value)}  ← 探针 {_md_escape(pl.probe)}")
        lines.append("")

    # 取证完备性：三类调证价值轴的覆盖诊断（闭环——告诉办案人还差哪类、补跑什么）。
    lines.append("## 取证完备性（三类调证价值）")
    lines.append("")
    for axis, info in coverage_axes(deduped).items():
        if info["covered"]:
            cats = "、".join(info["categories"]) if isinstance(info["categories"], list) else ""
            lines.append(f"- ✓ **{axis}**：已覆盖（{cats}）")
        else:
            lines.append(f"- ✗ **{axis}**：未覆盖 → {info['suggestion']}")
    lines.append("")
    return "\n".join(lines)


def to_ledger_dict(leads: list[ProbeLead]) -> dict[str, object]:
    """把线索聚成 JSON 台账（程序化消费/入图用）。"""
    deduped = dedup(leads)
    by_cat: dict[str, list[dict[str, str]]] = {}
    for pl in deduped:
        by_cat.setdefault(pl.category.value, []).append(
            {"value": pl.value, "probe": pl.probe, "where_to_request": pl.where_to_request, "raw": pl.raw}
        )
    return {"total": len(deduped), "categories": len(by_cat), "by_category": by_cat}


# --- 回灌清单：本路径贡献了哪些「可富化的地址」 -------------------------------

#: 从探针行里保守抽 IP:port / host 的两条正则。★为什么必须抽而不能直接用 ``lead.value``：
#: ``lead.value`` 是**整条去标记后的日志行**（如 ``connect -> 198.51.100.7:7158``、
#: ``POST https://api.example.test/v1/login``），不是干净地址。直接拿它计数会有两个后果：
#: ①与 pcap 路径记的干净地址在并集里**重复计数**（同一个后端两种写法各算一个）；
#: ②闭环 ``business_candidate_count`` 被日志文本撑大 —— 凭空长出观测强度。
_ADDR_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_ADDR_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")

#: ``[IPv6]`` / ``[IPv6]:port`` 形态。socket / ssl / netstat 标签里的对端惯例这么写
#: （``[2001:db8::1]:443 ESTABLISHED``），而它既不是 URL 也没有点分四段，
#: 上面两条正则一条都不匹配 —— 实测的公网 v6 后端因此**静默丢失**。
#: 只抓方括号里的内容，端口不入值（端口另有通道，混进地址会污染富化对象）。
_ADDR_IPV6_BRACKETED_RE = re.compile(r"\[([0-9A-Fa-f:.]{2,45})\]")

#: **裸** IPv6 形态（``2001:db8::1 ESTABLISHED``，无方括号无 scheme）。
#:
#: ★为什么写得这么保守：日志里 ``12:34:56``（时间戳）、``a1:b2:c3:d4:e5:f6``（MAC）都长得像
#: 冒号分隔的十六进制。故本正则只做**候选粗筛**，是否真是地址一律交
#: :class:`ipaddress.IPv6Address` 严格判定（时间戳/MAC 都会被它拒掉）——判据不写在正则里。
#: 要求至少 3 个冒号分隔段，从而 ``443:`` / ``12:34`` 这类不进候选；
#: 段数与总长都有硬上限（``{2,7}`` / ``{0,4}`` / ``{0,3}``），无嵌套量词、无回溯风险。
#: 前后用 negative lookaround 卡边界，避免从更长的十六进制串中间截一段出来。
_ADDR_IPV6_BARE_RE = re.compile(
    r"(?<![0-9A-Za-z:.\[])"
    r"([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})"
    r"(?![0-9A-Za-z:.])"
)
_ADDR_HOST_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)\b")


#: 特殊用途命名空间：**永远**不是可上报的公网对象，故连域名候选都不该进。
#: ★为什么必须显式列：:func:`host_is_private` 只判 ``localhost`` / ``localhost.localdomain``
#: 两个**精确**值加 ``.local`` / ``.lan`` / ``.internal`` 三个后缀，于是
#: ``foo.localhost``（RFC 6761 §6.3 规定整棵子树都解析到回环）与 ``device.home.arpa``
#: （RFC 8375 家庭网络专用域）双双漏过 → 被当业务候选并进 ``endpoints``、成为外部富化对象、
#: 撑大闭环 ``business_candidate_count``。反向映射区（``in-addr.arpa`` / ``ip6.arpa``）同理：
#: 那是 PTR 查询的区名，不是一个可上报的业务域名。
#:
#: 有意**不**收 RFC 6761 的 ``.test`` / ``.example`` / ``.invalid``：本仓库夹具正是用
#: ``*.example.test`` 当"合成公网域名"（写真实域名才是泄漏），把它们拒掉等于把自己的
#: 测试数据判成不可上报，公网分支再也测不到。
_SPECIAL_USE_SUFFIXES: tuple[str, ...] = (
    "localhost",
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
    "local",
    "lan",
    "internal",
    "localdomain",
)


def _normalize_host(host: str) -> str:
    """归一化 URL/日志里的 host：去空白、去 IPv6 方括号、去尾点、转小写。取不到返回空。

    ★方括号必须在这里剥掉：``host_from_url`` 对 IPv6 字面量**带括号原样返回**
    （``[2001:db8::1]``），而 ``valid_url_host`` 判它"不像主机名"直接拒 ——
    于是公网 IPv6 端点整条通道产出为空，实测的 v6 后端一个都进不了 ``endpoints``。
    """
    cleaned = host.strip().rstrip(".").lower()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def parse_ip_literal(host: str) -> "ipaddress.IPv4Address | ipaddress.IPv6Address | None":
    """把 host 当 IP 字面量解析（v4/v6 统一走 :func:`ipaddress.ip_address`）。不是 IP 返回 None。

    ★统一入口的意义：此前只有 :func:`parse_ipv4` 一条路，IPv6 既判不出"是 IP"、也就走不到
    公网判据，最终被当域名或被整条丢弃。判"是不是 IP"与判"公不公网"必须覆盖同样的地址族，
    否则 v6 端点在每一道闸上的行为都是偶然的。
    """
    cleaned = _normalize_host(host)
    if not cleaned:
        return None
    # ipaddress 接受 "1.2" / "16909060" 这类简写并当 IPv4，日志里那都不是地址；
    # 四段点分形态仍交给 parse_ipv4 严格判，与裸 IP 通道同口径。
    if ":" not in cleaned:
        return parse_ipv4(cleaned)
    try:
        return ipaddress.IPv6Address(cleaned.split("%", 1)[0])
    except ValueError:
        return None


def _ipv6_is_reportable(addr: "ipaddress.IPv6Address") -> bool:
    """公网 IPv6 才可上报。口径与 pcap 侧 ``_ip_public`` 一致（并集口径不许漂移）。

    ``ipv4_mapped`` / 6to4 / Teredo 内嵌的 v4 地址要按**内嵌那个 v4** 复判：
    ``::ffff:192.168.1.9`` 是私网地址换了个写法，放行它等于给私网开后门。
    ``addr.teredo`` 是 ``(服务器, 客户端)`` 元组，取客户端那一侧（真正的对端）。
    """
    teredo = addr.teredo
    embedded = addr.ipv4_mapped or addr.sixtofour or (teredo[1] if teredo else None)
    if embedded is not None:
        return not is_noise_bare_ip(str(embedded))
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or addr.is_site_local
    )


def url_host_is_reportable(host: str) -> bool:
    """URL 的 host 是否是**可上报的公网对象**——私网/回环/本机别名/特殊用途域一律拒。

    ★为什么 URL 通道也必须过这道闸：裸 IP 早就走 :func:`is_noise_bare_ip` 过滤了，但
    ``http://127.0.0.1:8080/`` / ``http://192.168.1.9/cfg`` / ``http://localhost/api``
    这类探针自查行以前只过 :func:`valid_url_host`（它只判"长得像主机名"，明确放行
    ``localhost`` 与任意 IPv4 字面量），于是会被当成业务候选：
      ①并进 ``endpoints`` 后被下游当可富化对象，向外部源查一个本机地址；
      ②撑大闭环的 ``business_candidate_count``，凭空长出观测强度。
    探针跑在分析机上，日志里出现本机/私网地址是**常态**，不是线索。

    ★IPv4 字面量刻意复用 :func:`is_noise_bare_ip`（**而不是**另写一套 ``ip_is_private``
    判断）：URL 通道与裸 IP 通道必须是**同一个**判据函数，否则两条通道会各自漂移——
    同一个地址在裸 IP 形式下被拒、在 URL 形式下被收，正是"口径不同 = 同一后端算两次"
    那类缺陷。IPv6 走 :func:`_ipv6_is_reportable`（同口径的 v6 版）。

    ★主机名除 :func:`host_is_private` 外**还要**过 :data:`_SPECIAL_USE_SUFFIXES`：前者
    只认 ``localhost`` 精确值，``foo.localhost`` / ``device.home.arpa`` 会整棵子树漏过。
    """
    cleaned = _normalize_host(host)
    if not cleaned:
        return False
    addr = parse_ip_literal(cleaned)
    if addr is not None:
        if isinstance(addr, ipaddress.IPv6Address):
            return _ipv6_is_reportable(addr)
        return not is_noise_bare_ip(str(addr))
    if host_is_private(cleaned):
        return False
    # 尾点与大小写已由 _normalize_host 抹平，故 ``FOO.Localhost.`` 与 ``foo.localhost`` 同判。
    return not any(
        cleaned == suffix or cleaned.endswith("." + suffix) for suffix in _SPECIAL_USE_SUFFIXES
    )


#: 单条线索文本里每条通道最多接受多少个候选。★为什么每条通道都要有：候选此前用
#: ``re.findall`` 取，它会把**全部**匹配一次性物化成列表——一条被写坏的超长日志行（或刻意
#: 构造的证据文件）能产出海量候选，既吃内存又要逐个过一次地址解析。上限只截**候选数**，
#: 不改判据：正常一条日志行里的对端地址是个位数，64 已经宽得离谱。
#:
#: ★四条通道各自独立计数，因为它们抽的是不同形态（URL / 点分四段 / v6 / 主机名），
#: 一条通道被刷爆不该让其余通道跟着失效。唯一的例外见 :data:`MAX_IPV6_CANDIDATES_PER_LEAD`。
MAX_URL_CANDIDATES_PER_LEAD = 64
MAX_IPV4_CANDIDATES_PER_LEAD = 64
MAX_HOST_CANDIDATES_PER_LEAD = 64

#: IPv6 候选的**共享**预算：``[v6]`` / ``[v6]:port`` / 裸 v6 / URL 里的 v6 **全部**从这一个
#: 额度里扣。★为什么必须共享而不是每种形态各给 64：URL 分支曾自己解析并直接 ``ips.add()``，
#: 于是 192 个 ``https://[v6]/`` 能全部进集合、绕过本上限——「每条 lead 的 v6 候选有界」这个
#: 不变量在最容易被刷的那条通道上恰好不成立。现在 URL 里的 v6 一律不在 URL 分支入集合，
#: 统一由方括号通道在这个共享预算内处理（URL 语法要求 v6 必须带方括号，故不会漏）。
MAX_IPV6_CANDIDATES_PER_LEAD = 64


def _bounded_findall(pattern: "re.Pattern[str]", text: str, limit: int) -> list[str]:
    """按 ``limit`` 截断地取匹配组，**绝不** ``findall()``。

    ``findall()`` 会一次性物化全部匹配；本函数用 ``finditer()`` 惰性推进，取满即停，
    故峰值内存由 ``limit`` 而不是输入长度决定。
    """
    out: list[str] = []
    for match in pattern.finditer(text):
        out.append(match.group(1) if match.groups() else match.group(0))
        if len(out) >= limit:
            break
    return out


def _reportable_ipv6_value(candidate: str) -> str | None:
    """把一个 IPv6 候选串判成"可上报的规范值"，不可上报/不是地址则返回 ``None``。

    ★返回值刻意做**规范化**而不是原样回抛：``2001:DB8::0:1`` 与 ``2001:db8::1`` 是同一个
    地址的两种写法，原样入集合会让同一后端在闭环里算两次（与 pcap 路径取并集时更明显）。

    ★内嵌 v4 的形态（ipv4-mapped / 6to4 / Teredo）返回**内嵌的那个 v4**：
    ``::ffff:203.0.113.5`` 与 ``203.0.113.5`` 是同一台主机，而 v4 通道本来就会从同一行文本里
    抽出后者 —— 不归一到同一个值，同一个后端会以两种形态各计一次。
    """
    addr = parse_ip_literal(candidate)
    if not isinstance(addr, ipaddress.IPv6Address):
        return None
    if not _ipv6_is_reportable(addr):
        return None
    teredo = addr.teredo
    embedded = addr.ipv4_mapped or addr.sixtofour or (teredo[1] if teredo else None)
    if embedded is not None:
        # ★这里**不**再判一次噪音：上面的 _ipv6_is_reportable 对内嵌 v4 的形态已经按内嵌那个
        #   v4 走同一个 is_noise_bare_ip 复判过了（``::ffff:192.168.1.9`` 到不了这一行）。
        #   把同一个条件写两遍的害处不是多跑一次：第二遍永远不成立，于是它既测不出来、也让
        #   读代码的人以为"删了它就会漏私网"，实际漏私网的判据在上面那一处。
        return str(embedded)
    return addr.compressed


def _iter_ipv6_candidates(text: str) -> "list[str]":
    """从一行日志文本里粗筛 IPv6 候选（``[v6]`` / ``[v6]:port`` / 裸 v6），有界。

    只做粗筛：是不是真地址、能不能上报，一律交 :func:`_reportable_ipv6_value` 判。

    ★方括号形态**同时覆盖 URL 里的 v6**：URL 语法（RFC 3986 §3.2.2）要求 v6 字面量必须写在
    方括号里，故 ``https://[2001:db8::1]:443/x`` 的地址部分本就会被方括号正则抓到。URL 分支
    因此不再自己解析 v6 —— 所有 v6 都从这一个共享预算里扣，且只经
    :func:`_reportable_ipv6_value` 一个出口产值（见 :data:`MAX_IPV6_CANDIDATES_PER_LEAD`）。
    """
    found: list[str] = []
    for pattern in (_ADDR_IPV6_BRACKETED_RE, _ADDR_IPV6_BARE_RE):
        remaining = MAX_IPV6_CANDIDATES_PER_LEAD - len(found)
        if remaining <= 0:
            break
        found.extend(_bounded_findall(pattern, text, remaining))
    return found


def probe_address_values(leads: "list[ProbeLead]") -> tuple[set[str], set[str]]:
    """从探针线索里保守抽出 ``(IP 集合, 域名集合)`` —— 只认真的地址，抽不出就不计。

    ★口径必须与 pcap 路径一致（裸 IP / 裸域名），因为两条路径的贡献集合会取**并集**：
      口径不同 = 同一个后端被算两次。抽不出地址的线索（商户号、加密 key、用户个人数据）
      **一条都不计** —— 那些不是可富化的地址，混进去会污染闭环的业务候选计数与外部富化对象。

    绝不抛：单条抽取异常跳过，返回已抽到的部分。
    """
    ips: set[str] = set()
    domains: set[str] = set()
    for lead in leads:
        if lead.category not in (LeadCategory.IP, LeadCategory.DOMAIN):
            continue
        text = lead.value or ""
        try:
            for url in _bounded_findall(_ADDR_URL_RE, text, MAX_URL_CANDIDATES_PER_LEAD):
                host = _normalize_host(host_from_url(url))
                if not host:
                    continue
                # ★IP 字面量先判、且判在 valid_url_host 之前：后者只认四段点分与"含点且末段
                #   为字母"，IPv6 剥括号后既没有点、末段也不是字母 —— 让它先过一遍，公网 v6
                #   端点整条通道产出恒为空（实测的 v6 后端一个都进不了 endpoints）。
                addr = parse_ip_literal(host)
                if addr is not None:
                    # ★v6 在这里**只跳过、不入集合**：URL 里的 v6 必须写在方括号里，故
                    #   _iter_ipv6_candidates 的方括号通道已经会抓到同一个地址。让 URL 分支
                    #   自己 add 有两处害：①它绕过 MAX_IPV6_CANDIDATES_PER_LEAD（192 个 URL v6
                    #   能全部进来）；②它 add 的是 addr.compressed 而非
                    #   _reportable_ipv6_value()，于是 ipv4-mapped / 6to4 / Teredo 会以
                    #   "::ffff:203.0.113.5" 与 "203.0.113.5" 两种写法同时留在集合里 ——
                    #   同一台主机算两次。两条缺陷的根因都是"v6 有第二个产值出口"。
                    if isinstance(addr, ipaddress.IPv6Address):
                        continue
                    # 私网/回环/链路本地/保留一律不入端点：探针跑在分析机上，日志里的本机
                    # 地址是常态而非线索。v4 与裸 IP 通道共用 is_noise_bare_ip，口径不漂移。
                    if url_host_is_reportable(host):
                        ips.add(addr.compressed)
                    continue
                if valid_url_host(host) and url_host_is_reportable(host):
                    domains.add(host)
            for raw_ip in _bounded_findall(_ADDR_IPV4_RE, text, MAX_IPV4_CANDIDATES_PER_LEAD):
                # is_noise_bare_ip：私网/回环/链路本地/网络地址等无上报价值的裸 IP 不计。
                # 与 pcap 路径「只收公网业务候选」的口径一致，否则闭环的候选数口径会漂移。
                if parse_ipv4(raw_ip) is not None and not is_noise_bare_ip(raw_ip):
                    ips.add(raw_ip)
            # ★裸 IPv6 / ``[v6]:port`` / URL 里的 v6 全走这一条通道（共享 64 个预算、单一
            #   规范化出口）：URL 通道只处理带 scheme 的，v4 通道只认点分四段，于是
            #   ``[2001:db8::1]:443 ESTABLISHED`` 这类 socket/ssl/netstat 标签里的对端
            #   在两条通道上都不匹配 —— 实测的公网 v6 后端**静默丢失**（既不入 endpoints、
            #   也不计入闭环候选，报告长得跟"没观测到 v6"一模一样）。
            for candidate in _iter_ipv6_candidates(text):
                value = _reportable_ipv6_value(candidate)
                if value is not None:
                    ips.add(value)
            for host in _bounded_findall(_ADDR_HOST_RE, text, MAX_HOST_CANDIDATES_PER_LEAD):
                low = _normalize_host(host)
                # 纯 IP 字面量已由上面两条通道处理；这里只收看起来像主机名的（末段 2+ 字母）。
                # 同样过公网闸：``localhost.localdomain`` / ``foo.localhost`` /
                # ``device.home.arpa`` / ``*.local`` / ``*.lan`` / ``*.internal`` 都含点故能
                # 匹配本正则，必须与 URL 通道同口径拒掉（见 url_host_is_reportable）。
                if (
                    parse_ip_literal(low) is None
                    and valid_url_host(low)
                    and url_host_is_reportable(low)
                ):
                    domains.add(low)
        except Exception:  # noqa: BLE001 - 单条抽不出不影响其余
            logger.debug("[probe_ingest] 地址抽取跳过一条：%r", text, exc_info=True)
    return ips, domains


def merge_into_report_json(report_json_path: str, leads: list[ProbeLead]) -> int:
    """把探针线索合并进已有 report.json 的 ``leads`` 数组。

    轻量原地修改（不重建 Report 对象）：load → 合并 lead dict → 原子落盘。新 lead 用 report.json
    同款序列化（含 is_c2/is_runtime_seen/evidence_id），与静态 leads 同构。绝不抛，失败返 0。

    - 新键 → append（计入返回值）；
    - 命中已存在键（静态已有同 (category,value)）→ 不丢弃，把 runtime 探针证据并进原 lead、
      升为 ``is_runtime_seen``（不计入返回值）；
    - 落盘走 :func:`atomic_write_text`，写中途失败不留半截坏 JSON。

    Returns:
        新增条数（命中既有 leads 而被合并的不计）。
    """
    try:
        from apkscan.report import json as report_json

        path = Path(report_json_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            logger.warning("[probe_ingest] report.json 顶层非 dict，跳过：%s", path)
            return 0
        existing = payload.get("leads")
        if not isinstance(existing, list):
            existing = []
            payload["leads"] = existing
        existing_by_key: dict[tuple[str, str], dict] = {
            (str(item.get("category")), str(item.get("value"))): item
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        confirmed = 0
        # 人工恢复凭据：命中的来源不复压（与 pcap 回灌同口径）。
        restored_index = restore_index(payload.get("meta"))
        for lead in to_report_leads(leads):
            key = (lead.category.value, lead.value)
            lead_dict = report_json._to_jsonable(lead)
            hit = existing_by_key.get(key)
            if hit is not None:
                # 命中已存在键：不丢弃——把 runtime 探针证据并进原 lead、升为活体确认。
                # ★confirmed 只计**证据**并入；仅抑制账本变化不是「确认」（与 pcap 侧同口径）。
                ev_merged, _ledger = merge_runtime_into_lead_dict(
                    hit, lead_dict, restored=restored_index
                )
                if ev_merged:
                    confirmed += 1
                continue
            # ★首次引入也要认墓碑（与 pcap 回灌同口径，理由见那里）。
            strip_restored_downgrades(lead_dict, restored_index)
            existing_by_key[key] = lead_dict
            existing.append(lead_dict)
            added += 1

        # ★meta 面：此前本函数**只**动 leads。同一份报告的三个消费面各读各的（letters 出口读 leads、
        #   闭环排序读 endpoints、可见性与采集质量读 meta），只更新第一面就会出现
        #   「Lead 标着 runtime 实测、可见性却说未做运行时观测、闭环还判 failed」——
        #   三处自相矛盾，而每一处单看都自洽。pcap 路径早已补齐（见 pcap_ingest 同名函数的说明），
        #   probe 路径一直缺这一步。
        #
        # Lead.value 是整行日志，不能直接塞 endpoints；但 probe_address_values 已保守抽出了
        # 干净 IP/域名。三面必须一致：inventory 说有业务候选时，endpoints 也要有可富化对象。
        probe_ips, probe_domains = probe_address_values(leads)
        if probe_ips or probe_domains:
            from apkscan.dynamic.pcap_ingest import _merge_runtime_endpoint_dicts

            fresh_endpoints = [
                {
                    "value": value,
                    "kind": kind,
                    "is_private": False,
                    "evidences": [
                        {
                            "source": "runtime-probe",
                            "location": "probe-log",
                            "snippet": f"进程内探针抽取：{value}",
                            "observed_at": None,
                        }
                    ],
                    # 只证明进程内观测到了地址，不编造端口、字节数、双向载荷或 UID/socket 归因。
                    "enrichment": {"runtime": {"observed_by": "probe"}},
                }
                for kind, values in (("ip", sorted(probe_ips)), ("domain", sorted(probe_domains)))
                for value in values
            ]
            _merge_runtime_endpoint_dicts(payload, fresh_endpoints)

        observed = bool(added or confirmed or probe_ips or probe_domains)
        if observed:
            meta = payload.get("meta")
            if not isinstance(meta, dict):
                meta = {}
                payload["meta"] = meta
            meta["runtime_merged"] = True
            # ★``uid_attributed=False``：探针日志是**进程内** hook 产出的，本就归属目标进程；
            #   但这里没有设备侧 socket 快照做五元组归因，拿不到闭环要的「同一端点上归因 + 双向载荷」
            #   那份证据。如实记 False → 闭环封顶 partial，绝不抬成 complete。
            meta[_inv.INVENTORY_META_KEY] = _inv.build_inventory(
                meta,
                source="probe",
                endpoint_values=probe_ips,
                domain_values=probe_domains,
                parse_status="ok",
                uid_attributed=False,
            )
            for _stale in _inv.INVENTORY_META_ALIASES:
                meta.pop(_stale, None)

        # ★与 pcap 回灌同理：往 meta 写了 runtime_merged / inventory，就必须重算派生视图，
        #   否则落盘的是 analyze 期那份「纯静态」旧快照——报告一边有探针线索、一边说
        #   「未做运行时观测」。这条路径此前漏了（本模块曾只写 leads，加 meta 之后没跟上刷新）。
        #   延迟导入：closure.sources 反向懒引 dynamic 侧模块，模块级互引会成环。
        from apkscan.core.closure import refresh_visibility_snapshot

        refresh_visibility_snapshot(meta)

        atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
        logger.info("[probe_ingest] 追加 %d 条、runtime 确认 %d 条探针线索进 %s", added, confirmed, path)
        return added
    except (OSError, ValueError):
        logger.exception("[probe_ingest] 读取/解析 report.json 失败：%s", report_json_path)
        return 0
    except Exception:  # noqa: BLE001 - 追加失败不得抛给调用方
        logger.exception("[probe_ingest] 追加进 report.json 异常：%s", report_json_path)
        return 0
