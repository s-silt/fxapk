"""联系方式分析器 — QQ / 微信 / Telegram / 邮箱 / 手机号 → CONTACT 调证线索。

职责（见设计文档 §4 contacts 行）：
- 从 ctx.dex_strings() + 文本资源 + manifest_xml 用正则抽取联系方式。
- 规则来自 apkscan/rules/contacts.yaml（每类含 patterns / blacklist / 归属 / 可调取证据）。
- 每个**去重后的联系方式值** → Lead(category=CONTACT, value=联系方式, subject=平台,
  where_to_request, evidence_to_obtain, confidence, source_refs=Evidence)。
- meta["contacts"] 记录按类型计数，供报告/调试。

误报控制：手机号用前后非数字边界；QQ/微信要求上下文关键字（写在正则里）；
邮箱黑名单排除 @drawable/@string 等资源引用。

约束：
- 只依赖 AnalysisContext 公开接口，禁止 import androguard。
- 单点解析异常 try/except + logging，不让单条规则/单个数据源炸掉整个 analyze；不静默 pass。
- 全程 type hints。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES as _TEXT_PREFIXES,
)
from apkscan.analyzers._common import (
    TEXT_RESOURCE_SUFFIXES as _TEXT_SUFFIXES,
)
from apkscan.analyzers._common import (
    as_str_list as _as_str_list,
)
from apkscan.analyzers._common import (
    is_text_resource as _is_text_resource_shared,
)
from apkscan.analyzers._common import (
    nonempty_str as _nonempty_str,
)
from apkscan.analyzers._common import (
    parse_confidence as _parse_confidence,
)
from apkscan.analyzers._common import (
    snippet_around as _snippet_around_shared,
)
from apkscan.analyzers._common import (
    str_or_empty as _str_or_empty,
)
from apkscan.analyzers._common import (
    truncate as _truncate_shared,
)
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Lead,
    LeadCategory,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "contacts"

_DEFAULT_EVIDENCE_TO_OBTAIN: tuple[str, ...] = (
    "账号实名注册信息",
    "绑定手机号 / 邮箱",
    "登录 IP 与设备信息",
)

_MAX_DEX_STRINGS = 200_000
_MAX_RESOURCE_FILES = 2_000
_MAX_RESOURCE_BYTES = 512 * 1024
# 每个类型最多产出的联系方式 Lead 数（防止极端样本刷屏）。
_MAX_LEADS_PER_TYPE = 200
_MAX_EVIDENCES = 5
_SNIPPET_MAX = 160

# IM 回传通道 kind 标识（CHANNEL 类）。
_KIND_TELEGRAM_BOT = "telegram_bot"
_KIND_WEBHOOK = "im_webhook"

# Telegram getMe 在线验证超时（秒）；仅在 online 能力下才会真的发请求。
_GETME_TIMEOUT = 8


@dataclass
class _ContactType:
    name: str
    kind: str
    subject: str = ""
    where_to_request: str = ""
    confidence: Confidence = Confidence.MEDIUM
    patterns: list[re.Pattern] = field(default_factory=list)
    blacklist: list[str] = field(default_factory=list)
    evidence_to_obtain: list[str] = field(default_factory=list)
    note: str = ""
    # 占位/测试手机号显式 denylist（仅 phone 类用；缺失走内置兜底）。
    placeholder_numbers: set[str] = field(default_factory=set)
    # Lead 分类：联系方式默认 CONTACT；IM 回传通道（telegram_bot/im_webhook）声明 channel
    # → 走 CHANNEL（value 用裸 token/webhook，不带类型前缀）。
    category: LeadCategory = LeadCategory.CONTACT


@dataclass
class _ContactHit:
    value: str
    evidences: list[Evidence] = field(default_factory=list)
    # 弱置信：命中"疑似 vanity/占位"启发式但未在显式 denylist 中——保留但降为 LOW（C3 评审）。
    low_confidence: bool = False
    low_confidence_note: str = ""


class ContactsAnalyzer(BaseAnalyzer):
    """提取 QQ/微信/Telegram/邮箱/手机号，产出 CONTACT 调证线索。"""

    name: str = "contacts"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        types, default_evidence = self._load_rules()
        if not types:
            logger.info("[%s] 无可用联系方式规则，跳过识别", self.name)
            result.meta["contacts"] = {}
            return result

        corpus = self._build_corpus(ctx)
        counts: dict[str, int] = {}
        telegram_bot_tokens: list[str] = []

        for ctype in types:
            try:
                hits = self._match_type(ctype, corpus)
            except Exception:
                logger.exception("[%s] 联系方式类型匹配失败，跳过：%s", self.name, ctype.name)
                continue
            if not hits:
                continue
            counts[ctype.kind] = len(hits)
            for hit in hits:
                if ctype.kind == _KIND_TELEGRAM_BOT:
                    telegram_bot_tokens.append(hit.value)
                result.leads.append(self._lead(ctype, hit, default_evidence, ctx))

        result.meta["contacts"] = counts
        # IM 回传通道：Telegram bot token 列表写 meta，供后续团伙聚类（接料人归并）。
        result.meta["telegram_bot_tokens"] = telegram_bot_tokens
        total = sum(counts.values())
        if total:
            logger.info("[%s] 提取到 %d 条联系方式线索：%s", self.name, total, counts)
        else:
            logger.info("[%s] 未提取到联系方式线索", self.name)
        return result

    # ------------------------------------------------------------------
    # 语料
    # ------------------------------------------------------------------

    def _build_corpus(self, ctx: "AnalysisContext") -> list[tuple[str, str, str]]:
        """[(source, location, text)]：dex 字符串 + manifest + 文本资源。"""
        corpus: list[tuple[str, str, str]] = []

        # dex 字符串
        try:
            for idx, s in enumerate(ctx.dex_strings()):
                if idx >= _MAX_DEX_STRINGS:
                    logger.warning("[%s] DEX 字符串超过上限 %d，截断扫描", self.name, _MAX_DEX_STRINGS)
                    break
                if isinstance(s, str) and s:
                    corpus.append(("dex", _truncate(s), s))
        except Exception:
            logger.exception("[%s] 遍历 dex_strings 失败", self.name)

        # manifest
        try:
            mf = ctx.manifest_xml
            if isinstance(mf, str) and mf:
                corpus.append(("manifest", "AndroidManifest.xml", mf))
        except Exception:
            logger.exception("[%s] 读取 manifest_xml 失败", self.name)

        # 文本资源
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            files = []
        scanned = 0
        for path in files:
            if scanned >= _MAX_RESOURCE_FILES:
                logger.warning("[%s] 文本资源数超过上限 %d，截断扫描", self.name, _MAX_RESOURCE_FILES)
                break
            if not self._is_text_resource(path):
                continue
            try:
                raw = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取资源失败，跳过：%s", self.name, path)
                continue
            if not raw:
                continue
            if not isinstance(raw, (bytes, bytearray)):
                logger.warning("[%s] read_file 返回非 bytes，跳过：%s", self.name, path)
                continue
            try:
                text = bytes(raw[:_MAX_RESOURCE_BYTES]).decode("utf-8", errors="replace")
            except Exception:
                logger.exception("[%s] 解码资源失败，跳过：%s", self.name, path)
                continue
            scanned += 1
            corpus.append(("resource", path, text))
        return corpus

    @staticmethod
    def _is_text_resource(path: str) -> bool:
        return _is_text_resource_shared(
            path, suffixes=_TEXT_SUFFIXES, prefixes=_TEXT_PREFIXES
        )

    # ------------------------------------------------------------------
    # 匹配
    # ------------------------------------------------------------------

    def _match_type(
        self, ctype: _ContactType, corpus: list[tuple[str, str, str]]
    ) -> list[_ContactHit]:
        """对一个类型扫全语料，按线索值去重聚合证据。"""
        by_value: dict[str, _ContactHit] = {}
        for rx in ctype.patterns:
            for source, location, text in corpus:
                for m in rx.finditer(text):
                    value = _match_value(m)
                    if not value:
                        continue
                    if _is_blacklisted(value, ctype.blacklist) or _is_blacklisted(
                        m.group(0), ctype.blacklist
                    ):
                        continue
                    if not _valid_for_kind(ctype.kind, value):
                        continue
                    low_conf = False
                    low_conf_note = ""
                    if ctype.kind == "phone":
                        verdict = _classify_phone(value, ctype.placeholder_numbers)
                        if verdict == _PHONE_DROP:
                            continue  # 显式占位 denylist → drop（13800138000 等）。
                        if verdict == _PHONE_SUSPECT:
                            # vanity/长重复-run（18888888888 等）：保留但降 LOW（评审 C3，
                            # 杀猪盘客服常用靓号，不可一票误杀）。
                            low_conf = True
                            low_conf_note = "疑似 vanity/占位号（长重复数字段）；保留待人工核实。"
                    hit = by_value.get(value)
                    if hit is None:
                        if len(by_value) >= _MAX_LEADS_PER_TYPE:
                            logger.warning(
                                "[%s] 类型 %s 命中超过上限 %d，截断",
                                self.name,
                                ctype.kind,
                                _MAX_LEADS_PER_TYPE,
                            )
                            return list(by_value.values())
                        hit = _ContactHit(
                            value=value,
                            low_confidence=low_conf,
                            low_confidence_note=low_conf_note,
                        )
                        by_value[value] = hit
                    if len(hit.evidences) < _MAX_EVIDENCES:
                        hit.evidences.append(
                            Evidence(
                                source=source,
                                location=location,
                                snippet=_snippet_around(text, m),
                            )
                        )
        return list(by_value.values())

    def _lead(
        self,
        ctype: _ContactType,
        hit: _ContactHit,
        default_evidence: list[str],
        ctx: "AnalysisContext",
    ) -> Lead:
        if ctype.category is LeadCategory.CHANNEL:
            return self._channel_lead(ctype, hit, default_evidence, ctx)

        evidence_to_obtain = (
            list(ctype.evidence_to_obtain) if ctype.evidence_to_obtain else list(default_evidence)
        )
        note = f"类型：{ctype.name}。" + (ctype.note or "")
        confidence = ctype.confidence
        if hit.low_confidence:
            confidence = Confidence.LOW
            if hit.low_confidence_note:
                note = f"{note} {hit.low_confidence_note}"
        return Lead(
            category=LeadCategory.CONTACT,
            value=f"{ctype.name}：{hit.value}",
            subject=ctype.subject or None,
            where_to_request=ctype.where_to_request or None,
            evidence_to_obtain=evidence_to_obtain,
            confidence=confidence,
            source_refs=list(hit.evidences),
            notes=note.strip(),
        )

    def _channel_lead(
        self,
        ctype: _ContactType,
        hit: _ContactHit,
        default_evidence: list[str],
        ctx: "AnalysisContext",
    ) -> Lead:
        """IM 回传通道 → CHANNEL Lead。

        与 CONTACT 的差异：
        - value 用**裸 token/webhook**（不带"类型："前缀），供后续团伙聚类直接比对。
        - webhook 按命中 URL 域名重新归属厂商主体（钉钉→阿里 / 企微→腾讯 / 飞书→字节），
          覆盖规则里的通用 subject。
        - Telegram bot token：默认离线**不**发 getMe（见 _maybe_getme 告警），notes 标未验证；
          仅在 online 能力下才尝试在线验证并把 bot username 写进 notes。
        """
        evidence_to_obtain = (
            list(ctype.evidence_to_obtain) if ctype.evidence_to_obtain else list(default_evidence)
        )
        subject = ctype.subject or None
        note = f"类型：{ctype.name}。" + (ctype.note or "")

        if ctype.kind == _KIND_WEBHOOK:
            vendor = _webhook_vendor(hit.value)
            if vendor:
                subject = vendor
        elif ctype.kind == _KIND_TELEGRAM_BOT:
            note = f"{note} {self._maybe_getme(hit.value, ctx)}"

        return Lead(
            category=LeadCategory.CHANNEL,
            value=hit.value,
            subject=subject,
            where_to_request=ctype.where_to_request or None,
            evidence_to_obtain=evidence_to_obtain,
            confidence=ctype.confidence,
            source_refs=list(hit.evidences),
            notes=note.strip(),
        )

    def _maybe_getme(self, token: str, ctx: "AnalysisContext") -> str:
        """Telegram bot token 在线验证（getMe）—— **默认 OFF**。

        默认离线不发：主动打 api.telegram.org 会暴露侦查意图、可能惊动接料人致 token 失效
        （对照 enrichers/asn.py 对明文 ip-api 的告警范式）。仅当 analyzer 具备 online 能力
        （ctx.config.online 为真）时才尝试发 getMe；失败（token 失效 / 无网）优雅降级、保留
        静态 token 线索不丢。返回写入 Lead.notes 的告警 / 验证结果片段。
        """
        if not _ctx_online(ctx):
            return (
                "未验证：默认离线未发 getMe（主动打 api.telegram.org 会暴露侦查意图、"
                "可能惊动接料人致 token 失效）；如需在线核验请显式启用 online 能力。"
            )
        username = self._getme_username(token)
        if username:
            return f"getMe 在线验证通过：bot @{username}。"
        return "getMe 在线验证失败（token 可能已失效 / 无网）；保留静态 token 线索待人工核实。"

    def _getme_username(self, token: str) -> str | None:
        """实际调 https://api.telegram.org/bot<token>/getMe 拿 bot username。

        全异常吞掉（不抛、不静默——记 warning），失败返回 None。仅在 online 能力下被调用。
        """
        try:
            import requests

            resp = requests.get(
                f"https://api.telegram.org/bot{token}/getMe", timeout=_GETME_TIMEOUT
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001 — getMe 失败不得炸主流程
            logger.warning("[%s] Telegram getMe 失败（保留静态线索）：%s", self.name, exc)
            return None
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        result = payload.get("result")
        if isinstance(result, dict):
            username = result.get("username")
            if isinstance(username, str) and username:
                return username
        return None

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_ContactType], list[str]]:
        data = load_rules(_RULES_NAME)
        default_evidence = list(_DEFAULT_EVIDENCE_TO_OBTAIN)

        if not isinstance(data, dict):
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；无规则可用", self.name, type(data).__name__
            )
            return [], default_evidence

        meta = data.get("meta")
        if isinstance(meta, dict):
            ev = _as_str_list(meta.get("evidence_to_obtain"))
            if ev:
                default_evidence = ev

        raw_types = data.get("types")
        if not isinstance(raw_types, list):
            logger.warning("[%s] types 字段应为 list，实际 %s", self.name, type(raw_types).__name__)
            return [], default_evidence

        types: list[_ContactType] = []
        for entry in raw_types:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            kind = entry.get("kind")
            if not _nonempty_str(name) or not _nonempty_str(kind):
                logger.warning("[%s] 跳过缺少 name/kind 的联系方式规则：%r", self.name, entry)
                continue
            patterns = self._compile_patterns(_as_str_list(entry.get("patterns")), name)
            if not patterns:
                logger.warning("[%s] 跳过无有效正则的联系方式规则：%s", self.name, name)
                continue
            types.append(
                _ContactType(
                    name=name.strip(),
                    kind=kind.strip(),
                    subject=_str_or_empty(entry.get("subject")),
                    where_to_request=_str_or_empty(entry.get("where_to_request")),
                    confidence=_parse_confidence(entry.get("confidence")) or Confidence.MEDIUM,
                    patterns=patterns,
                    blacklist=[b.lower() for b in _as_str_list(entry.get("blacklist"))],
                    evidence_to_obtain=_as_str_list(entry.get("evidence_to_obtain")),
                    note=_str_or_empty(entry.get("note")),
                    placeholder_numbers={
                        n.strip() for n in _as_str_list(entry.get("placeholder_numbers"))
                    },
                    category=_parse_category(entry.get("category")),
                )
            )
        return types, default_evidence

    def _compile_patterns(self, patterns: list[str], type_name: str) -> list[re.Pattern]:
        compiled: list[re.Pattern] = []
        for pat in patterns:
            try:
                compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                logger.warning("[%s] 类型 %s 的正则非法，跳过：%r", self.name, type_name, pat)
        return compiled


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------


def _match_value(m: re.Match) -> str:
    """取线索值：有捕获组用首个非空组，否则用整段匹配。"""
    if m.groups():
        for g in m.groups():
            if g:
                return g.strip()
    return m.group(0).strip()


def _is_blacklisted(text: str, blacklist: list[str]) -> bool:
    if not blacklist:
        return False
    low = text.lower()
    return any(b in low for b in blacklist)


def _parse_category(value: object) -> LeadCategory:
    """规则 category 字段 → LeadCategory；缺省 / 未知 → CONTACT（联系方式默认）。

    目前只识别 "channel"（IM 回传通道）；其余一律按联系方式 CONTACT 处理，保证旧规则零影响。
    """
    if isinstance(value, str) and value.strip().lower() == "channel":
        return LeadCategory.CHANNEL
    return LeadCategory.CONTACT


# Telegram bot token 形态闸：冒号前 8-10 位纯数字，冒号后正好 35 位 base64url。
# 用独立 fullmatch 二次校验（不依赖松正则），剔除被误命中的长冒号分隔串。
_BOT_TOKEN_RE = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")


def _is_valid_bot_token(value: str) -> bool:
    """严格校验 Telegram bot token 形态：冒号前 8-10 位纯数字、冒号后正好 35 位 [A-Za-z0-9_-]。"""
    return bool(_BOT_TOKEN_RE.fullmatch(value))


# IM webhook 域名 → 厂商主体（接收方平台主体）。按域名子串归属。
_WEBHOOK_VENDORS: tuple[tuple[str, str], ...] = (
    ("oapi.dingtalk.com", "钉钉群机器人（阿里巴巴 / 钉钉，接料通道）"),
    ("qyapi.weixin.qq.com", "企业微信群机器人（腾讯，接料通道）"),
    ("open.feishu.cn", "飞书群机器人（字节跳动 / 飞书，接料通道）"),
)


def _webhook_vendor(url: str) -> str | None:
    """按 webhook URL 域名归属接收方厂商主体；未知域名返回 None（保留规则通用 subject）。"""
    low = url.lower()
    for domain, vendor in _WEBHOOK_VENDORS:
        if domain in low:
            return vendor
    return None


def _ctx_online(ctx: "AnalysisContext") -> bool:
    """analyzer 是否具备 online 能力（用于门控 getMe 在线验证）。

    读 ctx.config.online（与 pipeline 的 online 能力门控一致）；读不到一律视为离线（保守）。
    """
    try:
        return bool(getattr(ctx.config, "online", False))
    except Exception:
        logger.debug("[contacts] 读取 ctx.config.online 失败，按离线处理", exc_info=True)
        return False


# 邮箱后缀白名单：邮箱必须以真实 TLD 结尾，否则多为代码误报
# （如 Kotlin `this@AbstractTypeConstructor.builtIns` / `x@y.type` / `@a.parameters`）。
_EMAIL_TLDS: frozenset[str] = frozenset(
    {
        "com", "cn", "net", "org", "gov", "edu", "io", "co", "me", "info",
        "biz", "vip", "top", "xyz", "club", "shop", "site", "cc", "tv",
        "hk", "tw", "mo", "jp", "kr", "sg", "us", "uk", "ru", "de", "fr",
        "qq", "163", "126", "gmail", "outlook", "hotmail", "foxmail",
        "mobi", "pro", "live", "icloud", "yeah", "sina", "sohu", "aliyun",
    }
)


def _valid_for_kind(kind: str, value: str) -> bool:
    """按类型做额外有效性校验，剔除代码误报。

    email：取 @ 后域名的末段（TLD），必须是真实 TLD（小写、在白名单）。
           这能杀掉 Kotlin `this@Class.prop` / `x@y.type` 这类被邮箱正则误命中的代码。
    telegram_bot：形态闸——冒号前 8-10 位纯数字、冒号后正好 35 位 [A-Za-z0-9_-]，
                  剔除被松正则误命中的长冒号分隔串。
    其它类型：不额外限制。
    """
    if kind == _KIND_TELEGRAM_BOT:
        return _is_valid_bot_token(value)
    if kind != "email":
        return True
    at = value.rfind("@")
    if at < 0:
        return False
    domain = value[at + 1:]
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    return tld.isalpha() and tld.lower() in _EMAIL_TLDS


# 占位手机号内置兜底（规则缺失时仍过滤最常见占位号）。
_FALLBACK_PLACEHOLDER_PHONES: frozenset[str] = frozenset({"13800138000", "13888888801"})

# 重复-run 阈值：最长连续相同数字 ≥ 此值视为"疑似 vanity/占位"（C3）。
# 实测：13666666666 run=9、13700000000 run=8、18888888888 run=10、13966666660 run=7 命中；
# 真号 13912345678 run=1、18612349999 run=4 不命中。
# ★评审 C3 修复：run 启发式只"降可信"不"drop"——杀猪盘客服/引流常用靓号（连号/豹子号），
#   一票误杀会丢真线索。真占位仍靠显式 denylist drop（13800138000 run 仅 3，无法靠 run 识别）。
_MAX_REPEAT_RUN = 6

# 手机号判定三态结果。
_PHONE_KEEP = "keep"        # 正常保留（原 confidence）。
_PHONE_SUSPECT = "suspect"  # 疑似 vanity/占位：保留但降 LOW。
_PHONE_DROP = "drop"        # 显式占位 denylist：drop。


def _longest_repeat_run(value: str) -> int:
    """返回字符串中最长连续相同字符的长度。"""
    if not value:
        return 0
    longest = 1
    cur = 1
    for prev, ch in zip(value, value[1:]):
        if ch == prev:
            cur += 1
            longest = max(longest, cur)
        else:
            cur = 1
    return longest


def _classify_phone(value: str, placeholders: set[str]) -> str:
    """手机号三态判定（C3 降噪，no-false-kill）：

    - value ∈ placeholders（YAML denylist，缺失走内置兜底）→ _PHONE_DROP（确认占位，如
      13800138000 run 仅 3，必须靠显式 denylist）。
    - 最长连续相同数字 ≥ _MAX_REPEAT_RUN → _PHONE_SUSPECT（疑似 vanity/占位，**保留**但降
      LOW；杀猪盘靓号客服号不可一票误杀）。
    - 其它 → _PHONE_KEEP（真号 13912345678 run=1、18612349999 run=4 原样保留）。
    """
    deny = placeholders or _FALLBACK_PLACEHOLDER_PHONES
    if value in deny:
        return _PHONE_DROP
    if _longest_repeat_run(value) >= _MAX_REPEAT_RUN:
        return _PHONE_SUSPECT
    return _PHONE_KEEP


def _snippet_around(text: str, m: re.Match, radius: int = 40) -> str:
    """联系方式命中片段：复用共享实现，半径默认 40（与原行为一致）。"""
    return _snippet_around_shared(text, m, radius)


def _truncate(text: str, limit: int = _SNIPPET_MAX) -> str:
    return _truncate_shared(text, limit)
