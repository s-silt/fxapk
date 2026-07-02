"""apkscan.dynamic.probe_ingest — 独立 frida 探针(`-l` 注入)散点输出 → 调证台账 / report.leads。

反诈 frida 探针库(46 个)是**手注 `-l` 工具**，各自往 console 吐 `[tag][LEAD-...]` 标记的线索，
散落在 `frida -o probe.log` 的文本里。本模块把这些散点**解析→按 LeadCategory 分类→去重→聚成
调证台账(md/json)**，并可**追加进已有 report.json 的 leads 数组**——补上路线图「编排输出层」缺的
那截「设备探针日志 → report.leads 的 Python 回灌解析器」。

设计铁律（与 dynamic 一致）：纯逻辑、结构化返回、**绝不把异常抛给调用方**（内部 try/except +
logging）、不静默吞错、全量 type hints。:func:`parse_probe_log` 是纯函数，便于单测。
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from apkscan.core.atomic import atomic_write_text
from apkscan.core.models import (
    Confidence,
    Evidence,
    Lead,
    LeadCategory,
    merge_runtime_into_lead_dict,
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
_BRACKET_RE = re.compile(r"\[[^\]]*\]")
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


def to_report_leads(leads: list[ProbeLead]) -> list[Lead]:
    """把 ProbeLead 转成 report 的 :class:`Lead`（source=runtime-probe，含合规提示）。

    advice：除 CARD_MERCHANT（情报研判、默认待核）外，运行时实测线索给「建议调证」。
    """
    out: list[Lead] = []
    for pl in dedup(leads):
        advice = "待核" if pl.category == LeadCategory.CARD_MERCHANT else "建议调证"
        notes = _COMPLIANCE_NOTE if pl.category in _SENSITIVE_CATS else "运行时探针实测捕获。"
        out.append(
            Lead(
                category=pl.category,
                value=pl.value[:200],
                where_to_request=pl.where_to_request or None,
                confidence=Confidence.HIGH,
                advice=advice,
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
            lines.append(f"- `{pl.value}`  ← 探针 [{pl.probe}]")
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
        for lead in to_report_leads(leads):
            key = (lead.category.value, lead.value)
            lead_dict = report_json._to_jsonable(lead)
            hit = existing_by_key.get(key)
            if hit is not None:
                # 命中已存在键：不丢弃——把 runtime 探针证据并进原 lead、升为活体确认。
                if merge_runtime_into_lead_dict(hit, lead_dict):
                    confirmed += 1
                continue
            existing_by_key[key] = lead_dict
            existing.append(lead_dict)
            added += 1
        atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
        logger.info("[probe_ingest] 追加 %d 条、runtime 确认 %d 条探针线索进 %s", added, confirmed, path)
        return added
    except (OSError, ValueError):
        logger.exception("[probe_ingest] 读取/解析 report.json 失败：%s", report_json_path)
        return 0
    except Exception:  # noqa: BLE001 - 追加失败不得抛给调用方
        logger.exception("[probe_ingest] 追加进 report.json 异常：%s", report_json_path)
        return 0
