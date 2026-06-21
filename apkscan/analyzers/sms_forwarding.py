"""sms_forwarding 分析器：识别**短信 / 验证码转发**服务（OTP 转发窃取基础设施）。

OTP（短信验证码）转发是接管受害人账户的关键基础设施——团伙在受害人设备上拦截
``SMS_RECEIVED`` 广播、抽取短信正文，再把验证码上传 / 转发到自己的接收端（Telegram bot、
webhook、接收手机号）。一旦验证码被转走，团伙即可完成异地登录、改密、转账，是「资金盗取链」
里资金被划走前的最后一道闸。recon 阶段命中即标 HIGH。

本分析器从 dex 字符串与文本资源里按三类强证据 + 一类弱证据识别（当前覆盖 Telegram bot /
webhook 转发模式）：
  - 强证据 A：中文转发关键词（短信转发 / 验证码转发 / 拦截短信 / 转发到…）；
  - 强证据 B：短信接收 + 上传/转发组合（dex 方法引用 ``SMS_RECEIVED`` /
    ``createFromPdu`` / ``getMessageBody`` 与 HTTP 上报 / 转发目标 webhook 共现）；
  - 强证据 C：短信转发配置（转发目标手机号 / forward webhook URL / Telegram bot token + chat_id）；
  - 弱证据：仅单关键词 或 仅短信接收（无上传/转发） → 待核。

FP 收敛（宁缺毋滥）：
  - 白名单排除正规短信**发送** SDK（阿里云 dysms / 腾讯云短信 / Twilio / 容联云 / Mob 等）作为
    「发送方」的合法用法——聚焦「接收并转发上传」的窃取模式，而非业务发短信；
  - dex 方法 token 一律用 sensitive_api 的标识符**词边界**匹配，避免同名子串误命中；
  - webhook 转发目标 host 经 ``infra.classify_domain`` 排除已知 SDK / CDN / 基础设施。

置信分级：强证据 → HIGH·建议调证；弱证据 → MEDIUM·待核。

约束：只用 AnalysisContext 公开接口（dex_strings / list_files / read_file），规则数据化
（rules/sms_forwarding.yaml + load_rules），正则一律字符类 / 定长（无 ReDoS），单点异常
try/except + logging，不静默 pass、不炸 analyze，全程 type hints。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    present_tokens,
    str_or_empty,
    truncate,
)
from apkscan.core import infra
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer, load_rules
from apkscan.core.textutil import as_str_list, host_from_url, host_is_private, strip_url_tail

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "sms_forwarding"
_MAX_DEX_STRINGS = 200_000
# 单个文本资源读取上限（避免极端大文件拖慢 / 撑内存）。
_MAX_RESOURCE_BYTES = 4_000_000
# 文本资源扫描总字节预算（超出即停，防大样本拖慢）。
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000

# 有界 URL 提取正则（字符类、无嵌套量词 → 线性、无 ReDoS）。
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}\\]+", re.IGNORECASE)

# 转发目标手机号（中国大陆 11 位，1 开头；定长、无回溯）。
_PHONE_RE = re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])")

_DEFAULT_WHERE = "短信转发平台 / 接收手机号归属运营商 / 转发目标平台"

# 证据档位（与 admin_panel 一致：high → HIGH·建议调证；review → MEDIUM·待核）。
_TIER_HIGH = "high"
_TIER_REVIEW = "review"


@dataclass
class _KeywordRule:
    """单条转发关键词规则（在文本里按子串出现即命中）。"""

    id: str
    title: str
    tier: str  # "high" | "review"
    keywords: list[str] = field(default_factory=list)


@dataclass
class _ComboRule:
    """短信接收 + 上传/转发组合规则（dex 方法 token 词边界匹配；两组都命中才触发）。"""

    id: str
    title: str
    receive_tokens: list[str] = field(default_factory=list)  # 任一命中 = 命中"接收短信"
    forward_tokens: list[str] = field(default_factory=list)  # 任一命中 = 命中"上传/转发"


@dataclass
class _Rules:
    """规整后的规则集合 + 配置。"""

    keywords: list[_KeywordRule] = field(default_factory=list)
    combos: list[_ComboRule] = field(default_factory=list)
    webhook_host_re: re.Pattern[str] | None = None  # forward webhook host 指纹（如 telegram）
    webhook_path_re: re.Pattern[str] | None = None  # forward webhook path 指纹（如 /bot<token>/sendMessage）
    sender_whitelist: list[str] = field(default_factory=list)  # 正规短信发送 SDK 标识（FP 排除）
    evidence_to_obtain: list[str] = field(default_factory=list)
    where_to_request: str = _DEFAULT_WHERE


@dataclass
class _Findings:
    """扫描累积：命中标题集合、最佳档位、代表性证据。"""

    titles: set[str] = field(default_factory=set)
    best_tier: str = _TIER_REVIEW
    sample_source: str = "dex"
    sample_location: str = ""
    sample_snippet: str = ""
    receive_hit: bool = False
    forward_hit: bool = False

    def record(self, title: str, tier: str, source: str, location: str, snippet: str) -> None:
        self.titles.add(title)
        if tier == _TIER_HIGH and self.best_tier != _TIER_HIGH:
            # 升 high 时换更有力的样本作证据。
            self.best_tier = _TIER_HIGH
            self.sample_source, self.sample_location, self.sample_snippet = source, location, snippet
        elif not self.sample_snippet:
            self.sample_source, self.sample_location, self.sample_snippet = source, location, snippet


class SmsForwardingAnalyzer(BaseAnalyzer):
    """识别短信 / 验证码转发服务，产出 category=SMS_FORWARDING 的调证线索。"""

    name: str = "sms_forwarding"
    # 既扫 dex 方法引用（组合证据，Android 专属）也扫文本资源，故声明 apk。
    requires: list[str] = ["apk"]

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        rules = self._load_rules()
        if not rules.keywords and not rules.combos and rules.webhook_host_re is None:
            logger.info("[%s] 无可用短信转发识别规则，跳过", self.name)
            result.meta["sms_forwarding_count"] = 0
            return result

        findings = _Findings()

        # 1) DEX 字符串（代码内关键词 / 方法引用 / 转发配置）。
        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS)

        # FP 收敛：若样本仅含正规短信"发送" SDK 标识且无任何转发/接收信号，整体放弃。
        sender_only = self._is_sender_sdk_present(dex_strings, rules)

        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", rules, findings)
        self._scan_dex_combo(dex_strings, rules, findings)

        # 2) 文本资源（H5 / JS / json / xml 里的转发配置、关键词）。
        self._scan_resources(ctx, rules, findings)

        lead = self._build_lead(findings, rules, sender_only)
        if lead is not None:
            result.leads.append(lead)

        result.meta["sms_forwarding_count"] = len(result.leads)
        if result.leads:
            logger.info(
                "[%s] 识别短信/验证码转发线索：%s（档位=%s）",
                self.name,
                "、".join(sorted(findings.titles)),
                findings.best_tier,
            )
        return result

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------

    def _scan_text(
        self,
        text: str,
        source: str,
        location: str,
        rules: _Rules,
        findings: _Findings,
    ) -> None:
        """扫一段文本：中文关键词 / 转发目标手机号 / forward webhook URL。绝不抛。"""
        if not text:
            return
        try:
            # a) 中文转发关键词（子串匹配；keywords 为定长字符串，无回溯）。
            for kw_rule in rules.keywords:
                for kw in kw_rule.keywords:
                    if kw and kw in text:
                        findings.record(
                            kw_rule.title, kw_rule.tier, source, location, truncate(text, 160)
                        )
                        break  # 同一条规则命中一次即可

            # b) forward webhook URL（host/path 指纹，如 Telegram bot sendMessage）。
            if "://" in text and (rules.webhook_host_re is not None or rules.webhook_path_re is not None):
                self._scan_webhook(text, source, location, rules, findings)

            # c) 转发目标手机号 + 转发上下文（避免裸手机号误报：须与转发关键词共现，
            #    由 keywords 命中提供上下文；此处仅在已有关键词命中时补强证据）。
            if findings.titles and _PHONE_RE.search(text):
                findings.record(
                    "转发目标手机号", _TIER_HIGH, source, location, truncate(text, 160)
                )
        except Exception:
            logger.exception("[%s] 扫描文本失败：%s", self.name, location)

    def _scan_webhook(
        self,
        text: str,
        source: str,
        location: str,
        rules: _Rules,
        findings: _Findings,
    ) -> None:
        """从文本里抽 URL → 命中 forward webhook 指纹（排除已知基础设施）则记强证据。"""
        for m in _URL_RE.finditer(text):
            url = strip_url_tail(m.group(0))
            host = host_from_url(url)
            if not host or host_is_private(host):
                continue
            path = self._path_of(url)
            host_hit = rules.webhook_host_re is not None and rules.webhook_host_re.search(host)
            path_hit = (
                rules.webhook_path_re is not None and bool(path) and rules.webhook_path_re.search(path)
            )
            if not host_hit and not path_hit:
                continue
            # webhook 目标 host 若为已知正规基础设施则跳过（非转发窃取落点）。
            advice, _reason = infra.classify_domain(host)
            if advice == infra.ADVICE_SKIP:
                continue
            findings.record(
                "短信转发 webhook（转发目标）",
                _TIER_HIGH,
                source,
                location,
                truncate(url, 160),
            )

    def _scan_dex_combo(
        self, dex_strings: list[str], rules: _Rules, findings: _Findings
    ) -> None:
        """短信接收 + 上传/转发组合：两组方法 token 都命中 → 强证据；仅接收 → 弱证据。"""
        if not rules.combos:
            return
        try:
            # 性能：一次扫描收齐全部组合 token 的存在性（替代每 token 各自全量扫 dex）。
            all_tokens = {
                t for c in rules.combos for t in (*c.receive_tokens, *c.forward_tokens) if t
            }
            present = present_tokens(all_tokens, dex_strings)
            for combo in rules.combos:
                receive = any(t in present for t in combo.receive_tokens)
                forward = any(t in present for t in combo.forward_tokens)
                if receive and forward:
                    findings.receive_hit = True
                    findings.forward_hit = True
                    findings.record(
                        combo.title, _TIER_HIGH, "dex", "dex_strings",
                        f"接收短信广播 + 上传/转发方法共现：{combo.id}",
                    )
                elif receive:
                    findings.receive_hit = True
                    findings.record(
                        "仅检测到短信接收（未见上传/转发）",
                        _TIER_REVIEW,
                        "dex",
                        "dex_strings",
                        f"接收短信方法命中：{combo.id}",
                    )
        except Exception:
            logger.exception("[%s] 扫描短信接收/转发组合失败", self.name)

    def _scan_resources(self, ctx: "AnalysisContext", rules: _Rules, findings: _Findings) -> None:
        """扫描 APK 内文本资源（H5/JS/json/xml）里的关键词 / 转发配置。绝不抛。"""
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return

        total = 0
        for path in files:
            if total >= _MAX_TOTAL_RESOURCE_BYTES:
                logger.warning("[%s] 文本资源扫描达总预算，停止", self.name)
                break
            if not is_text_resource(
                path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
            ):
                continue
            try:
                data = ctx.read_file(path)
            except Exception:
                logger.exception("[%s] 读取资源失败：%s", self.name, path)
                continue
            if not data or len(data) > _MAX_RESOURCE_BYTES:
                continue
            total += len(data)
            text = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )
            self._scan_text(text, "resource", path, rules, findings)

    def _is_sender_sdk_present(self, dex_strings: list[str], rules: _Rules) -> bool:
        """样本是否命中正规短信发送 SDK 标识（用于 FP 收敛的辅助标志）。"""
        if not rules.sender_whitelist:
            return False
        try:
            for marker in rules.sender_whitelist:
                if marker and any(marker in s for s in dex_strings):
                    return True
        except Exception:
            logger.exception("[%s] 检查短信发送 SDK 白名单失败", self.name)
        return False

    @staticmethod
    def _path_of(url: str) -> str:
        """取 URL 中 host 之后的 path（含起始 ``/``）；无 path → 空串。"""
        after = url.split("://", 1)[-1]
        slash = after.find("/")
        return after[slash:] if slash >= 0 else ""

    # ------------------------------------------------------------------
    # 出线索
    # ------------------------------------------------------------------

    def _build_lead(
        self, findings: _Findings, rules: _Rules, sender_only: bool
    ) -> Lead | None:
        if not findings.titles:
            return None

        # FP 收敛：命中正规短信发送 SDK 且非强档即不出弱线索（区分业务发短信 vs 接收转发窃取）。
        if sender_only and findings.best_tier != _TIER_HIGH:
            logger.debug("[%s] 命中正规短信发送 SDK 且非强档，FP 收敛跳过", self.name)
            return None

        if findings.best_tier == _TIER_HIGH:
            confidence = Confidence.HIGH
            advice = infra.ADVICE_INVESTIGATE
        else:
            confidence = Confidence.MEDIUM
            advice = infra.ADVICE_REVIEW

        ev = Evidence(
            source=findings.sample_source,
            location=findings.sample_location,
            snippet=findings.sample_snippet,
        )
        return Lead(
            category=LeadCategory.SMS_FORWARDING,
            value="短信 / 验证码转发服务",
            subject=None,
            where_to_request=rules.where_to_request,
            evidence_to_obtain=list(rules.evidence_to_obtain),
            confidence=confidence,
            source_refs=[ev],
            notes="转发特征：" + "、".join(sorted(findings.titles)),
            advice=advice,
        )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> _Rules:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning("[%s] 规则顶层应为 dict，实际 %s", self.name, type(data).__name__)
            return _Rules()

        rules = _Rules(
            evidence_to_obtain=as_str_list(data.get("evidence_to_obtain")),
            where_to_request=str_or_empty(data.get("where_to_request")) or _DEFAULT_WHERE,
            sender_whitelist=as_str_list(data.get("sender_sdk_whitelist")),
            webhook_host_re=self._compile(data.get("webhook_host_regex"), "webhook_host_regex"),
            webhook_path_re=self._compile(data.get("webhook_path_regex"), "webhook_path_regex"),
        )

        rules.keywords = self._parse_keywords(data.get("keyword_patterns"))
        rules.combos = self._parse_combos(data.get("combo_patterns"))
        return rules

    def _parse_keywords(self, raw: object) -> list[_KeywordRule]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning("[%s] keyword_patterns 应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        out: list[_KeywordRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("id")
            if not isinstance(pid, str) or not pid.strip():
                logger.warning("[%s] 跳过缺 id 的 keyword 规则：%r", self.name, entry)
                continue
            keywords = as_str_list(entry.get("keywords"))
            if not keywords:
                logger.warning("[%s] 跳过无 keywords 的规则：%s", self.name, pid)
                continue
            tier = _TIER_HIGH if str_or_empty(entry.get("tier")).lower() == _TIER_HIGH else _TIER_REVIEW
            out.append(
                _KeywordRule(
                    id=pid.strip(),
                    title=str_or_empty(entry.get("title")) or pid.strip(),
                    tier=tier,
                    keywords=keywords,
                )
            )
        return out

    def _parse_combos(self, raw: object) -> list[_ComboRule]:
        if not isinstance(raw, list):
            if raw is not None:
                logger.warning("[%s] combo_patterns 应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        out: list[_ComboRule] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            pid = entry.get("id")
            if not isinstance(pid, str) or not pid.strip():
                logger.warning("[%s] 跳过缺 id 的 combo 规则：%r", self.name, entry)
                continue
            receive = as_str_list(entry.get("receive_tokens"))
            forward = as_str_list(entry.get("forward_tokens"))
            if not receive or not forward:
                logger.warning(
                    "[%s] 跳过缺 receive_tokens/forward_tokens 的 combo 规则：%s", self.name, pid
                )
                continue
            out.append(
                _ComboRule(
                    id=pid.strip(),
                    title=str_or_empty(entry.get("title")) or pid.strip(),
                    receive_tokens=receive,
                    forward_tokens=forward,
                )
            )
        return out

    def _compile(self, pattern: object, field_name: str) -> re.Pattern[str] | None:
        if not isinstance(pattern, str) or not pattern.strip():
            return None
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            logger.warning("[%s] 规则正则编译失败，跳过：%s", self.name, field_name)
            return None
