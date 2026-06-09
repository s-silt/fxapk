"""webview_jsbridge 分析器：WebView/JS-bridge 攻击面审查 → Finding + 桥接对象 Lead。

反诈意义：样本多为 uni-app/H5 混合应用，H5 前端（常服务端下发、可控）经 WebView 的
JS-bridge（``addJavascriptInterface`` 暴露的 ``@JavascriptInterface`` Java 方法）驱动原生
能力。把「H5 能调用哪些原生能力」「WebView 是否开了 file:// + JS 提权」作为攻击面产出。

与现有分析器互补、不重复：
  - components 只看导出组件（谁能被外部触发），不看 WebView 内 JS→Java 桥接；
  - js_bundle 只在字符串字面量内抽端点/密钥，不识别 addJavascriptInterface 桥接面；
  - 本分析器专审 WebView 桥接面与危险 WebSettings，并把桥接框架→可调证厂商。

检测信号（数据化，apkscan/rules/webview_jsbridge.yaml）：
  - addJavascriptInterface（暴露 @JavascriptInterface 方法给任意 H5，强信号 HIGH）。
  - setJavaScriptEnabled + setAllowFileAccessFromFileURLs/setAllowUniversalAccessFromFileURLs
    共现（file:// + JS 提权，HIGH）。
  - evaluateJavascript / loadUrl("javascript:")（JS 注入面，MEDIUM）。
  - H5 侧 window.<bridge>./webkit.messageHandlers/uni.postMessage（assets/www JS，确认桥接在用）。
  - 桥接框架（X5 com.tencent.smtt / UC com.uc.webview / DSBridge / JSBridge）→ Lead(CONFIG_KEY)。

约束（与 sdk_fingerprint/permissions 一致）：
  - 只依赖 AnalysisContext 公开接口（dex_strings/list_files/read_file），禁止 import androguard。
  - 误报收敛：addJavascriptInterface 等本身正常 app 也用，故只产「攻击面 Finding」不直接定罪，
    advice 由 pipeline 默认处理；桥接 Lead 复用 CONFIG_KEY、不新增枚举。
  - 单点解析异常 try/except + logging，不静默 pass、不炸 analyze。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apkscan.analyzers._common import as_str_list as _as_str_list
from apkscan.analyzers._common import collect_dex_strings as _collect_dex_strings
from apkscan.analyzers._common import collect_file_paths as _collect_file_paths
from apkscan.analyzers._common import str_or_empty as _str_or_empty
from apkscan.analyzers._common import truncate as _truncate
from apkscan.core.models import (
    AnalyzerResult,
    Confidence,
    Evidence,
    Finding,
    Lead,
    LeadCategory,
    Severity,
)
from apkscan.core.registry import BaseAnalyzer, load_rules

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_RULES_NAME = "webview_jsbridge"
_MAX_DEX_STRINGS = 200_000

# 资源扫描上限：避免极端样本读太多/太大文件。
_MAX_RESOURCE_FILES = 500
_MAX_RESOURCE_BYTES = 4 * 1024 * 1024
_RESOURCE_SUFFIXES = (".js", ".html", ".htm")
_SNIPPET_MAX = 200

_SEVERITY_BY_NAME = {s.name: s for s in Severity}


def _severity_from(value: Any, fallback: Severity) -> Severity:
    name = str(value).strip().upper()
    return _SEVERITY_BY_NAME.get(name, fallback)


def _is_h5_resource(path: str) -> bool:
    """assets/ 或 /www/ 下的 .js/.html（uni-app/H5 前端代码）。"""
    low = path.replace("\\", "/").lower()
    if not low.endswith(_RESOURCE_SUFFIXES):
        return False
    return low.startswith("assets/") or "/www/" in low


@dataclass
class _Signal:
    """单条 WebView 桥接信号规则。"""

    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    dex_tokens: list[str] = field(default_factory=list)  # 任一命中（dex）
    all_tokens: list[str] = field(default_factory=list)  # 全部命中（dex 组合，如危险 WebSettings）
    resource_tokens: list[str] = field(default_factory=list)  # 任一命中（assets/www JS）
    description: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)


class WebViewJsBridgeAnalyzer(BaseAnalyzer):
    """审查 WebView/JS-bridge 攻击面，产 category=\"webview\" Finding + 桥接 CONFIG_KEY Lead。"""

    name: str = "webview_jsbridge"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        signals, bridge_hints = self._load_rules()
        if not signals and not bridge_hints:
            logger.info("[%s] 无可用 WebView 规则，跳过", self.name)
            result.meta["webview_signals"] = []
            return result

        dex_ok, dex_strings = _collect_dex_strings(
            ctx, self.name, max_strings=_MAX_DEX_STRINGS
        )
        result.meta["dex_scanned"] = dex_ok

        # 仅当存在需要扫资源的信号时才读 H5 文本（省 IO）。
        need_resources = any(sig.resource_tokens for sig in signals)
        resource_texts = self._collect_resource_texts(ctx) if need_resources else []

        matched: list[str] = []
        for sig in signals:
            try:
                finding = self._match_signal(sig, dex_strings, resource_texts)
            except Exception:  # noqa: BLE001 — 单条信号失败不影响其余
                logger.exception("[%s] 信号匹配失败，跳过：%s", self.name, sig.id)
                continue
            if finding is not None:
                result.findings.append(finding)
                matched.append(sig.id)

        try:
            self._emit_bridge_leads(bridge_hints, dex_strings, result)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] 桥接框架 Lead 生成失败", self.name)

        result.meta["webview_signals"] = matched
        result.meta["webview_signal_count"] = len(matched)
        if matched:
            logger.info("[%s] 命中 WebView 桥接信号 %d 项：%s", self.name, len(matched), "、".join(matched))
        return result

    # ------------------------------------------------------------------
    # 数据源
    # ------------------------------------------------------------------

    def _collect_resource_texts(self, ctx: "AnalysisContext") -> list[tuple[str, str]]:
        """读 assets/www 下 .js/.html 文本（带文件数/大小上限）。失败/缺失 → []，不抛。"""
        out: list[tuple[str, str]] = []
        paths = [p for p in _collect_file_paths(ctx, self.name) if _is_h5_resource(p)]
        for path in paths[:_MAX_RESOURCE_FILES]:
            try:
                raw = ctx.read_file(path)
            except Exception:  # noqa: BLE001 — 单文件读取失败不影响其余
                logger.exception("[%s] 读取资源失败，跳过：%s", self.name, path)
                continue
            if not isinstance(raw, (bytes, bytearray)) or not raw:
                continue
            if len(raw) > _MAX_RESOURCE_BYTES:
                logger.debug(
                    "[%s] 资源超 %d 字节，截断前段扫描（尾部桥接调用可能漏）：%s",
                    self.name,
                    _MAX_RESOURCE_BYTES,
                    path,
                )
                raw = bytes(raw[:_MAX_RESOURCE_BYTES])
            try:
                out.append((path, bytes(raw).decode("utf-8", errors="ignore")))
            except Exception:  # noqa: BLE001 — errors=ignore 几乎不抛，仅防御
                logger.exception("[%s] 资源解码失败，跳过：%s", self.name, path)
        return out

    # ------------------------------------------------------------------
    # 单信号匹配
    # ------------------------------------------------------------------

    def _match_signal(
        self,
        sig: _Signal,
        dex_strings: list[str],
        resource_texts: list[tuple[str, str]],
    ) -> Finding | None:
        """任一匹配组（dex any / dex all / resource any）满足即产 Finding。"""
        evidences: list[Evidence] = []

        tok = self._first_dex_hit(sig.dex_tokens, dex_strings)
        if tok is not None:
            evidences.append(Evidence(source="dex", location=tok, snippet=f"dex token：{tok}"))

        if sig.all_tokens and all(self._dex_has(t, dex_strings) for t in sig.all_tokens):
            evidences.append(
                Evidence(
                    source="dex",
                    location="+".join(sig.all_tokens),
                    snippet="组合命中：" + "、".join(sig.all_tokens),
                )
            )

        res_ev = self._first_resource_hit(sig.resource_tokens, resource_texts)
        if res_ev is not None:
            evidences.append(res_ev)

        if not evidences:
            return None

        return Finding(
            id=sig.id,
            title=sig.title,
            severity=sig.severity,
            category="webview",
            description=sig.description,
            recommendation=sig.recommendation,
            evidences=evidences,
            references=list(sig.references),
        )

    @staticmethod
    def _dex_has(token: str, dex_strings: list[str]) -> bool:
        return bool(token) and any(token in s for s in dex_strings)

    def _first_dex_hit(self, tokens: list[str], dex_strings: list[str]) -> str | None:
        for tok in tokens:
            if self._dex_has(tok, dex_strings):
                return tok
        return None

    @staticmethod
    def _first_resource_hit(
        tokens: list[str], resource_texts: list[tuple[str, str]]
    ) -> Evidence | None:
        for tok in tokens:
            if not tok:
                continue
            for path, text in resource_texts:
                idx = text.find(tok)
                if idx >= 0:
                    seg = text[max(0, idx - 20): idx + 80].replace("\n", " ").strip()
                    return Evidence(source="resource", location=path, snippet=_truncate(seg, _SNIPPET_MAX))
        return None

    # ------------------------------------------------------------------
    # 桥接框架 → CONFIG_KEY Lead
    # ------------------------------------------------------------------

    def _emit_bridge_leads(
        self,
        bridge_hints: dict[str, str],
        dex_strings: list[str],
        result: AnalyzerResult,
    ) -> None:
        """已知桥接框架/对象名命中 → Lead(CONFIG_KEY, value="JSBridge:<框架>", subject=厂商)。"""
        seen: set[str] = set()
        for token, vendor in bridge_hints.items():
            if not token or token in seen:
                continue
            if not self._dex_has(token, dex_strings):
                continue
            seen.add(token)
            # 桥接 hint token 本身即框架包名/对象名（如 com.tencent.smtt），整体作为标识保留
            # （不取 basename——基于 '/' 分割对点分包名无意义）。
            name = token.strip(".") or token
            result.leads.append(
                Lead(
                    category=LeadCategory.CONFIG_KEY,
                    value=f"JSBridge:{name}",
                    subject=vendor or None,
                    confidence=Confidence.HIGH,
                    source_refs=[
                        Evidence(source="dex", location=token, snippet=f"WebView 桥接框架：{token}")
                    ],
                    notes=(
                        f"WebView JS-bridge 框架 {name}"
                        + (f"（{vendor}）" if vendor else "")
                        + "：H5 前端可经此桥调用原生能力。结合 H5 调用面研判可被服务端下发内容驱动的原生攻击面。"
                    ),
                )
            )

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def _load_rules(self) -> tuple[list[_Signal], dict[str, str]]:
        data = load_rules(_RULES_NAME)
        if not isinstance(data, dict):
            if data:
                logger.warning(
                    "[%s] 规则顶层应为 dict，实际 %s；无规则可用",
                    self.name,
                    type(data).__name__,
                )
            return [], {}

        signals = self._parse_signals(data.get("signals", []))

        bridge_hints: dict[str, str] = {}
        raw_hints = data.get("bridge_object_hints", {})
        if isinstance(raw_hints, dict):
            for token, vendor in raw_hints.items():
                if isinstance(token, str) and token.strip():
                    bridge_hints[token.strip()] = _str_or_empty(vendor)
        elif raw_hints:
            logger.warning("[%s] bridge_object_hints 应为 dict，实际 %s", self.name, type(raw_hints).__name__)

        return signals, bridge_hints

    def _parse_signals(self, raw: object) -> list[_Signal]:
        if not isinstance(raw, list):
            if raw:
                logger.warning("[%s] signals 应为 list，实际 %s", self.name, type(raw).__name__)
            return []
        signals: list[_Signal] = []
        for entry in raw:
            if not isinstance(entry, dict):
                logger.warning("[%s] 跳过非 dict 信号条目：%r", self.name, entry)
                continue
            sig_id = entry.get("id")
            if not isinstance(sig_id, str) or not sig_id.strip():
                logger.warning("[%s] 跳过缺 id 的信号条目：%r", self.name, entry)
                continue
            dex_tokens = _as_str_list(entry.get("dex_tokens"))
            all_tokens = _as_str_list(entry.get("all_tokens"))
            resource_tokens = _as_str_list(entry.get("resource_tokens"))
            if not (dex_tokens or all_tokens or resource_tokens):
                logger.warning("[%s] 跳过无任何 token 的信号条目：%s", self.name, sig_id)
                continue
            signals.append(
                _Signal(
                    id=sig_id.strip(),
                    title=_str_or_empty(entry.get("title")) or sig_id.strip(),
                    severity=_severity_from(entry.get("severity"), Severity.MEDIUM),
                    dex_tokens=dex_tokens,
                    all_tokens=all_tokens,
                    resource_tokens=resource_tokens,
                    description=_str_or_empty(entry.get("description")),
                    recommendation=_str_or_empty(entry.get("recommendation")),
                    references=_as_str_list(entry.get("references")),
                )
            )
        return signals
