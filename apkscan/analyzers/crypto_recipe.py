"""crypto_recipe 分析器（C5a）：识别打包 JS 里的应用层加密信封 + 抽出解密配方。

为什么单独做一个分析器（不塞进 crypto.py / js_bundle.py）：
  - crypto.py 是弱算法/硬编码密钥的 Finding 检测，职责不同。
  - js_bundle.py 负责端点 + 硬编码密钥 Finding，把配方推断耦合进去会让两者都变脏。
  本分析器专做「从加密调用上下文反查出一整套解密配方」——产一条高价值调证线索
  （凭此可离线解密全部 {data,timestamp} 信封流量、还原资金流/冒充对象），并把结构化
  配方写进 meta["crypto_recipe"]，作为 C5a→C5b 的接线契约（pipeline 把 analyzer.meta
  并入 report.meta，merge 阶段据此自动解密抓到的流量）。

检测 4 类信号（全部数据化正则；具体值不硬编码进产品逻辑）：
  1. CryptoJS 存在性（CryptoJS / crypto-js / .enc.Utf8.parse / .AES.encrypt 等 token）。
  2. algo/mode/padding（从 AES.encrypt/decrypt 附近窗口抓 mode:X.mode.CFB / padding:X.pad.Pkcs7）。
  3. 硬编码 key（短变量 = 16/24/32 长 hex/可见字符常量，且出现在 enc.parse / AES.crypt 上下文；
     由 enc.Utf8.parse vs enc.Hex.parse 决定 key_encoding）。
  4. iv 推导式（MD5(...).toString().substring(0,16) + key 与 timestamp 的拼接 → md5(key+ts)[:16]；
     固定 iv 常量 → fixed；iv 同 key → same_as_key）。
  5. 信封字段（加/解密周围对象字面量键 data/timestamp/sign/nonce 共现）。

约束（与 js_bundle 一致）：
  - 只依赖 AnalysisContext 公开接口（list_files / read_file），禁止 import androguard。
  - 复用 js_bundle 的目标收集口径（assets/ 或 /www/ 下 .js/.html + index.android.bundle），
    单文件 <=8MB、文件数 <=3000，逐文件 try/except + logging，不静默 pass。
  - 规则可选经 load_rules("crypto_recipe") 覆盖/扩展，缺失走内置兜底。
  - 误报收敛：key 常量必须与 enc.parse/AES.crypt 上下文共现；confidence 标注；宁少勿乱。
  - 全程 type hints。
"""

from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from apkscan.analyzers._common import as_str_list as _as_str_list
from apkscan.analyzers._common import truncate as _short
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

_RULES_NAME = "crypto_recipe"

# 与 js_bundle 同口径：单文件上限 8MB、文件数 3000。
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_FILES = 3000
_DEFAULT_SNIPPET_MAX = 200

_RN_BUNDLE_NAME = "index.android.bundle"

# Finding id（稳定，供报告/测试引用）。
FINDING_RECIPE = "CRYPTO-RECIPE-AES"

# ---------------------------------------------------------------------------
# 内置兜底（规则缺失时用）
# ---------------------------------------------------------------------------

_FALLBACK_CRYPTOJS_TOKENS: tuple[str, ...] = (
    "CryptoJS",
    "crypto-js",
    ".enc.Utf8.parse",
    ".enc.Hex.parse",
    ".AES.encrypt",
    ".AES.decrypt",
    ".DES.encrypt",
    ".DES.decrypt",
    "TripleDES",
    ".mode.CFB",
    ".mode.CBC",
    ".mode.ECB",
    ".pad.Pkcs7",
)
_FALLBACK_MODE_ALIASES: tuple[str, ...] = ("CFB", "CBC", "ECB", "CTR", "OFB")
_FALLBACK_PADDING_ALIASES: tuple[str, ...] = (
    "Pkcs7",
    "NoPadding",
    "Iso97971",
    "ZeroPadding",
    "AnsiX923",
    "Iso10126",
)
_FALLBACK_ENVELOPE_FIELDS: tuple[str, ...] = ("data", "timestamp", "sign", "nonce")

# ---------------------------------------------------------------------------
# 正则（数据化检测；具体值不硬编码）
# ---------------------------------------------------------------------------

# CryptoJS AES/DES enc/dec 调用：捕获算法名（AES/DES/TripleDES）+ encrypt|decrypt。
_CRYPTO_CALL_RE = re.compile(
    r"\b(?:CryptoJS\s*\.\s*)?(?P<algo>AES|TripleDES|DES)\s*\.\s*(?P<op>encrypt|decrypt)\s*\(",
    re.IGNORECASE,
)

# mode:X.mode.<NAME>（窗口内）。
_MODE_RE = re.compile(r"mode\s*:\s*\w+\s*\.\s*mode\s*\.\s*(?P<mode>\w+)", re.IGNORECASE)
# padding:X.pad.<NAME>（窗口内）。
_PADDING_RE = re.compile(r"padding\s*:\s*\w+\s*\.\s*pad\s*\.\s*(?P<pad>\w+)", re.IGNORECASE)

# 硬编码 key 常量：变量名(1..32) = "16..64 长可见字符常量"。
# 变量名放宽到 32 字符以覆盖未/半混淆 bundle（myKey/secretKey/encryptKey…）；
# 误报由 `_key_var_in_context` 两段式上下文确认收敛（必须出现在 enc.parse/AES.crypt 实参）。
_KEY_CONST_RE = re.compile(
    r"""(?P<var>\b[A-Za-z_$][\w$]{0,31})\s*=\s*["'](?P<val>[0-9a-zA-Z+/=]{16,64})["']"""
)

# enc.Utf8.parse(<var>) / enc.Hex.parse(<var>)：捕获编码 + 变量名。
_ENC_PARSE_RE = re.compile(
    r"""\.\s*enc\s*\.\s*(?P<enc>Utf8|Hex)\s*\.\s*parse\s*\(\s*(?P<var>\w+)\s*\)""",
    re.IGNORECASE,
)

# iv 推导：MD5(...).toString().substring(0,16) 形态（CryptoJS 常见 hex[:16] 写法）。
_IV_MD5_SUBSTR_RE = re.compile(
    r"""MD5\s*\([^()]*\)\s*\.\s*toString\s*\(\s*\)\s*\.\s*substr(?:ing)?\s*\(\s*0\s*,\s*16\s*\)""",
    re.IGNORECASE,
)

# iv 同 key：iv 实参与 key 用同一变量经同一 enc.parse 包裹（{iv:enc.X.parse(<keyvar>) …}）。
# 由 _find_iv_derive 用 key 变量名动态构造，无需独立常量正则。

# 固定 iv 常量：iv:enc.X.parse("<16..64 可见字符常量>")（直接字面量，非变量）。
_IV_FIXED_LITERAL_RE = re.compile(
    r"""iv\s*:\s*\w+\s*\.\s*enc\s*\.\s*(?P<enc>Utf8|Hex)\s*\.\s*parse\s*\(\s*["'](?P<val>[0-9a-zA-Z+/=]{8,64})["']\s*\)""",
    re.IGNORECASE,
)

# 信封对象字面量：含 timestamp/data/sign/nonce 任一键的 {...}（无嵌套）。
_ENVELOPE_OBJ_RE = re.compile(
    r"""\{[^{}]*\b(?:timestamp|data|sign|nonce)\b[^{}]*\}""",
    re.IGNORECASE,
)
_OBJ_KEY_RE = re.compile(r"""["']?\b(?P<key>timestamp|data|sign|nonce)\b["']?\s*:""", re.IGNORECASE)

# 时间戳形态 token（用于确认 md5(key+ts)：拼接里出现 timestamp / ts / Date.getTime / +n 等）。
_TS_HINT_RE = re.compile(
    r"timestamp|getTime\s*\(\)|\bts\b|\.now\s*\(\)", re.IGNORECASE
)

# AES/DES 调用附近窗口（字符）。
_CALL_WINDOW = 400


# ---------------------------------------------------------------------------
# 规则模型
# ---------------------------------------------------------------------------


@dataclass
class _Rules:
    cryptojs_tokens: tuple[str, ...] = ()
    mode_aliases: tuple[str, ...] = ()
    padding_aliases: tuple[str, ...] = ()
    envelope_fields: tuple[str, ...] = ()
    snippet_max: int = _DEFAULT_SNIPPET_MAX


@dataclass
class _RecipeCandidate:
    """单文件聚合出的配方候选。"""

    algo: str = ""
    mode: str = ""
    padding: str = ""
    key: str = ""
    key_encoding: str = ""  # utf8|hex
    iv_derive: str = ""  # md5(key+ts)[:16]|fixed|same_as_key
    iv_value: str | None = None
    envelope_fields: list[str] = field(default_factory=list)
    source: str = ""
    crypto_call_snippet: str = ""

    def is_usable(self) -> bool:
        """至少要有算法 + key（否则无法据此解密，不产配方）。"""
        return bool(self.algo and self.key)


class CryptoRecipeAnalyzer(BaseAnalyzer):
    """从打包 JS 反查应用层加密配方（算法/key/iv 推导/信封字段）。"""

    name: str = "crypto_recipe"
    requires: list[str] = []  # 纯静态，永远可用

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        rules = self._load_rules()

        try:
            all_files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:  # noqa: BLE001 — list_files 失败不应炸掉 analyze
            logger.exception("[%s] 读取 list_files 失败", self.name)
            all_files = []

        targets = self._collect_targets(all_files)

        best: _RecipeCandidate | None = None
        scanned = 0
        for path in targets:
            if scanned >= _MAX_FILES:
                logger.warning("[%s] JS 文件数超过上限 %d，截断扫描", self.name, _MAX_FILES)
                break
            text = self._read_text(ctx, path)
            if text is None:
                continue
            scanned += 1
            try:
                cand = self._scan_file(text, path, rules)
            except Exception:  # noqa: BLE001 — 单文件失败不影响其余
                logger.exception("[%s] 扫描 JS 文件失败，跳过：%s", self.name, path)
                continue
            if cand is not None and cand.is_usable():
                best = self._prefer(best, cand)

        if best is not None:
            result.leads.append(self._build_lead(best, rules))
            result.findings.append(self._build_finding(best, rules))
            result.meta["crypto_recipe"] = self._to_meta(best)
            result.meta["crypto_recipe_count"] = 1
            logger.info(
                "[%s] 提取到加密配方：%s-%s/%s key(%s,%dB) iv=%s 来源=%s",
                self.name,
                best.algo,
                best.mode or "?",
                best.padding or "?",
                best.key_encoding or "?",
                len(best.key),
                best.iv_derive or "?",
                best.source,
            )
        else:
            logger.info("[%s] 扫描 %d 文件，未发现应用层加密配方", self.name, scanned)

        result.meta["crypto_recipe_files_scanned"] = scanned
        return result

    # ------------------------------------------------------------------
    # 目标文件收集（复用 js_bundle 口径）
    # ------------------------------------------------------------------

    def _collect_targets(self, files: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for path in files:
            if path in seen:
                continue
            if self._is_target(path):
                seen.add(path)
                out.append(path)
        return out

    @staticmethod
    def _is_target(path: str) -> bool:
        low = path.replace("\\", "/").lower()
        base = posixpath.basename(low)
        if base == _RN_BUNDLE_NAME:
            return True
        in_scope = low.startswith("assets/") or "/www/" in low
        if not in_scope:
            return False
        return low.endswith(".js") or low.endswith(".html") or low.endswith(".htm")

    # ------------------------------------------------------------------
    # 单文件扫描 → 配方候选
    # ------------------------------------------------------------------

    def _scan_file(self, text: str, path: str, rules: _Rules) -> _RecipeCandidate | None:
        """在单文件里聚合配方信号。无 CryptoJS 形态 / 无加密调用 → None。"""
        # 1) CryptoJS 存在性：无任一 token → 直接不是配方文件。
        if not any(tok in text for tok in rules.cryptojs_tokens):
            return None

        # 2) 找加密/解密调用（algo + mode + padding，取附近窗口）。
        call = self._find_crypto_call(text, rules)
        if call is None:
            return None
        algo, mode, padding, call_pos, call_snippet = call

        cand = _RecipeCandidate(
            algo=algo,
            mode=mode,
            padding=padding,
            source=path,
            crypto_call_snippet=call_snippet,
        )

        # 3) 硬编码 key + key_encoding（必须与 enc.parse / AES.crypt 上下文共现）。
        key, key_encoding = self._find_hardcoded_key(text)
        if key:
            cand.key = key
            cand.key_encoding = key_encoding or "utf8"

        # 4) iv 推导式。
        iv_derive, iv_value = self._find_iv_derive(text, key)
        cand.iv_derive = iv_derive
        cand.iv_value = iv_value

        # 5) 信封字段（在加密调用附近窗口找对象字面量）。
        cand.envelope_fields = self._find_envelope_fields(text, call_pos)

        return cand

    def _find_crypto_call(
        self, text: str, rules: _Rules
    ) -> tuple[str, str, str, int, str] | None:
        """找首个带 mode/padding 的 AES/DES 加解密调用，返回 (algo, mode, padding, pos, snippet)。

        优先返回窗口内能同时抓到 mode 的调用；都没有则返回首个调用（mode/padding 留空）。
        """
        fallback: tuple[str, str, str, int, str] | None = None
        for m in _CRYPTO_CALL_RE.finditer(text):
            algo_raw = m.group("algo")
            algo = self._normalize_algo(algo_raw)
            start = m.start()
            window = text[start : start + _CALL_WINDOW]
            mode = self._match_alias(_MODE_RE, window, "mode", rules.mode_aliases)
            padding = self._match_alias(_PADDING_RE, window, "pad", rules.padding_aliases)
            snippet = _short(text[max(0, start - 20) : start + 160], rules.snippet_max)
            hit = (algo, mode, padding, start, snippet)
            if mode:
                return hit
            if fallback is None:
                fallback = hit
        return fallback

    @staticmethod
    def _normalize_algo(raw: str) -> str:
        low = raw.lower()
        if low == "aes":
            return "AES"
        if low in ("tripledes", "des3"):
            return "3DES"
        if low == "des":
            return "DES"
        return raw.upper()

    @staticmethod
    def _match_alias(
        pattern: re.Pattern[str], window: str, group: str, aliases: tuple[str, ...]
    ) -> str:
        m = pattern.search(window)
        if m is None:
            return ""
        val = m.group(group)
        low = val.lower()
        for alias in aliases:
            if alias.lower() == low:
                return alias
        return val  # 别名表外仍返回原值（数据化，不硬限）。

    def _find_hardcoded_key(self, text: str) -> tuple[str, str]:
        """找硬编码 key 常量 + 解析方式（utf8/hex）。

        两段式收敛误报：
          1) 抓候选 key 常量 `<var>="<16..64 可见字符>"`；
          2) 确认 <var>（或承接它的形参）出现在 enc.Utf8/Hex.parse(...) 或 AES.(en|de)crypt 上下文。
        key_encoding 由包裹该变量的 enc.Utf8.parse / enc.Hex.parse 决定。
        """
        # 先收集所有 enc.parse(var) 的 (var -> encoding)。
        enc_by_var: dict[str, str] = {}
        for m in _ENC_PARSE_RE.finditer(text):
            var = m.group("var")
            enc = m.group("enc").lower()
            enc_by_var.setdefault(var, "utf8" if enc == "utf8" else "hex")

        # 文件级的主 key 编码（多数场景全局一致）：取出现最多的 enc.parse 编码。
        global_encoding = self._dominant_encoding(text)

        candidates: list[tuple[str, str]] = []
        for m in _KEY_CONST_RE.finditer(text):
            var = m.group("var")
            val = m.group("val")
            # 上下文确认：该常量变量须用于 enc.parse 或 AES.crypt 的 key 位置，
            # 或文件里存在 enc.parse（真样本形态：常量经形参传入 enc.Utf8.parse(t)）。
            if not self._key_var_in_context(text, var):
                continue
            encoding = enc_by_var.get(var) or global_encoding or "utf8"
            candidates.append((val, encoding))

        if not candidates:
            return "", ""
        # 优先 32 长（AES-256，真样本形态），其次 24/16。
        candidates.sort(key=lambda c: (-_aes_len_rank(len(c[0])), len(c[0])))
        return candidates[0]

    @staticmethod
    def _dominant_encoding(text: str) -> str:
        utf8 = len(re.findall(r"\.\s*enc\s*\.\s*Utf8\s*\.\s*parse", text, re.IGNORECASE))
        hexn = len(re.findall(r"\.\s*enc\s*\.\s*Hex\s*\.\s*parse", text, re.IGNORECASE))
        if utf8 == 0 and hexn == 0:
            return ""
        return "utf8" if utf8 >= hexn else "hex"

    @staticmethod
    def _key_var_in_context(text: str, var: str) -> bool:
        """该 key 变量是否出现在加密相关上下文（enc.parse / AES.crypt 的实参）。"""
        v = re.escape(var)
        # 直接 enc.parse(var) / AES.encrypt(_, var) / vu(var+...) / decrypt(_, var,
        patterns = (
            rf"enc\s*\.\s*(?:Utf8|Hex)\s*\.\s*parse\s*\(\s*{v}\s*\)",
            rf"(?:AES|DES|TripleDES)\s*\.\s*(?:en|de)crypt\s*\([^,()]+,\s*{v}\b",
            rf"\b\w+\s*\(\s*{v}\s*\+",  # vu(wl+ts) 形态：key 变量参与 iv 派生拼接
            rf",\s*{v}\s*\)",  # yu(e.data.data, wl) / parse(_, wl) 形态
        )
        return any(re.search(p, text) for p in patterns)

    def _find_iv_derive(self, text: str, key: str) -> tuple[str, str | None]:
        """识别 iv 推导式（真识别四态，不再对任意样本伪造 md5 派生）。

        优先级（按 CryptoJS 实际写法判别）：
          1. MD5(...).toString().substring(0,16)（+ timestamp 拼接） → ``md5(key+ts)[:16]``。
          2. iv 实参是字面量字符串经 enc.X.parse 包裹 → ``fixed``（带 iv_value）。
          3. iv 与 key 用同一变量 → ``same_as_key``。
          4. 都不匹配 → ``unknown``（不伪造推导式；C5b 据此解密会失败但安全降级，
             notes 标注由人复核——避免把 fixed/same_as_key 样本错标成 md5 派生）。
        """
        # 1) md5(key+ts)[:16]：substring(0,16) 形态，或 MD5 + timestamp 拼接。
        if _IV_MD5_SUBSTR_RE.search(text):
            return "md5(key+ts)[:16]", None
        if "MD5" in text and _TS_HINT_RE.search(text):
            return "md5(key+ts)[:16]", None

        # 2) 固定 iv：iv:enc.X.parse("<literal>")。
        m = _IV_FIXED_LITERAL_RE.search(text)
        if m is not None:
            return "fixed", m.group("val")

        # 3) iv 同 key：找出包裹 key 常量的变量名，若 iv 实参经同一 enc.parse(<keyvar>) 包裹。
        if key and self._iv_same_as_key(text, key):
            return "same_as_key", None

        # 4) 未识别 → unknown（由人复核，不伪造）。
        return "unknown", None

    @staticmethod
    def _iv_same_as_key(text: str, key: str) -> bool:
        """iv 是否与 key 用同一变量（{iv:enc.X.parse(<v>) …} 且 <v>="<key>"）。"""
        # 找所有 <var>="<key>" 的变量名。
        key_vars = {
            m.group("var")
            for m in _KEY_CONST_RE.finditer(text)
            if m.group("val") == key
        }
        if not key_vars:
            return False
        for m in re.finditer(
            r"""iv\s*:\s*\w+\s*\.\s*enc\s*\.\s*(?:Utf8|Hex)\s*\.\s*parse\s*\(\s*(?P<v>\w+)\s*\)""",
            text,
            re.IGNORECASE,
        ):
            if m.group("v") in key_vars:
                return True
        return False

    def _find_envelope_fields(self, text: str, call_pos: int) -> list[str]:
        """在加密调用附近窗口找信封对象字面量的键（data/timestamp/sign/nonce）。"""
        lo = max(0, call_pos - _CALL_WINDOW)
        hi = min(len(text), call_pos + _CALL_WINDOW)
        window = text[lo:hi]
        found: list[str] = []
        for obj_m in _ENVELOPE_OBJ_RE.finditer(window):
            obj = obj_m.group(0)
            for key_m in _OBJ_KEY_RE.finditer(obj):
                k = key_m.group("key").lower()
                if k not in found:
                    found.append(k)
        # 稳定输出顺序：data,timestamp 在前。
        order = {"data": 0, "timestamp": 1, "sign": 2, "nonce": 3}
        found.sort(key=lambda k: order.get(k, 9))
        return found

    @staticmethod
    def _prefer(best: _RecipeCandidate | None, cand: _RecipeCandidate) -> _RecipeCandidate:
        """多文件命中时择优：信息更全（有 mode + 信封字段 + iv）的优先。"""
        if best is None:
            return cand

        def score(c: _RecipeCandidate) -> int:
            return (
                (2 if c.mode else 0)
                + (1 if c.padding else 0)
                + (2 if c.envelope_fields else 0)
                + (1 if c.iv_derive else 0)
                + (1 if len(c.key) == 32 else 0)
            )

        return cand if score(cand) > score(best) else best

    # ------------------------------------------------------------------
    # 产出：Lead / Finding / meta
    # ------------------------------------------------------------------

    def _build_lead(self, cand: _RecipeCandidate, rules: _Rules) -> Lead:
        mode = cand.mode or "?"
        padding = cand.padding or "?"
        key_tail = cand.key[:4] + "…" + cand.key[-4:] if len(cand.key) >= 8 else cand.key
        value = (
            f"{cand.algo}-{mode}/{padding} "
            f"key({cand.key_encoding or '?'},{len(cand.key)}B)={key_tail} "
            f"iv={cand.iv_derive or '?'}"
        )
        envelope = "、".join(cand.envelope_fields) if cand.envelope_fields else "data/timestamp（推定）"
        notes = (
            "自 JS 逆出的应用层加密配方：算法/模式/填充、硬编码 key、iv 推导式、信封字段。"
            f"信封字段：{envelope}。凭此可离线解密全部加密流量，还原接口契约与冒充对象。"
        )
        return Lead(
            category=LeadCategory.CRYPTO_RECIPE,
            value=value,
            subject=None,
            where_to_request="（解密配方，非调证对象）凭此可离线解密全部 {data,timestamp} 信封流量",
            evidence_to_obtain=[
                "用本配方对设备抓包得到的 {data,timestamp} 信封逐条解密，还原 "
                "register/login/webConfig/产品/入金/客服等接口契约与冒充对象(webName)",
            ],
            confidence=Confidence.HIGH,
            advice="建议调证",
            source_refs=[
                Evidence(
                    source="js",
                    location=cand.source,
                    snippet=_short(cand.crypto_call_snippet, rules.snippet_max),
                )
            ],
            notes=notes,
        )

    def _build_finding(self, cand: _RecipeCandidate, rules: _Rules) -> Finding:
        """额外产 Finding 记录硬编码 key 本身（与 js_bundle 的 JS-HARDCODED-AES-KEY 互补：
        这里是从加密调用上下文反查，能抓到裸常量赋值 wl="…"）。"""
        return Finding(
            id=FINDING_RECIPE,
            title="应用层加密配方（硬编码 key + AES 信封）",
            severity=Severity.HIGH,
            category="crypto",
            description=(
                f"JS 中发现应用层加密配方：{cand.algo}-{cand.mode or '?'}/{cand.padding or '?'}，"
                f"硬编码 key（{cand.key_encoding or '?'}，{len(cand.key)} 字节），"
                f"iv 推导 {cand.iv_derive or '?'}。请求/响应以信封 {{data,timestamp}} 传输密文，"
                "凭此配方可离线解密全部加密流量。"
            ),
            recommendation=(
                "研判：用本配方对抓包得到的密文信封解密，还原接口契约（注册/登录/配置/产品/"
                "入金/客服）与冒充对象(webName)；作为还原资金流与冒充关系的关键证据。"
            ),
            evidences=[
                Evidence(
                    source="js",
                    location=cand.source,
                    snippet=_short(cand.crypto_call_snippet, rules.snippet_max),
                )
            ],
            references=["CWE-798", "CWE-321"],
        )

    @staticmethod
    def _to_meta(cand: _RecipeCandidate) -> dict:
        """结构化配方落 meta，供 C5b（appcrypto.CryptoRecipe.from_meta）自动解密。"""
        return {
            "algo": cand.algo,
            "mode": cand.mode or "CFB",
            "padding": cand.padding or "Pkcs7",
            "segment_size": 128,  # CryptoJS CFB 默认 128，JS 读不出，记默认留扩展位。
            "key": cand.key,
            "key_encoding": cand.key_encoding or "utf8",
            # iv_derive 忠实落 cand 值（含 unknown/fixed/same_as_key）——不再无脑兜成 md5，
            # 避免把 fixed/same_as_key/未识别样本错标成 md5 派生导致 C5b 误解密。
            "iv_derive": cand.iv_derive or "unknown",
            "iv_value": cand.iv_value,
            "envelope_fields": list(cand.envelope_fields) or ["data", "timestamp"],
            "payload_encoding": "base64",  # 裸 base64（无 Salted__ 前缀）；C5b auto 兜底也试 hex。
            "source": cand.source,
        }

    # ------------------------------------------------------------------
    # IO / 规则加载（与 js_bundle 同范式）
    # ------------------------------------------------------------------

    def _read_text(self, ctx: "AnalysisContext", path: str) -> str | None:
        try:
            raw = ctx.read_file(path)
        except Exception:  # noqa: BLE001 — 单文件读取失败不影响其余
            logger.exception("[%s] 读取文件失败，跳过：%s", self.name, path)
            return None
        if raw is None:
            return None
        if not isinstance(raw, (bytes, bytearray)):
            logger.warning("[%s] read_file 返回非 bytes，跳过：%s", self.name, path)
            return None
        if not raw:
            return None
        if len(raw) > _MAX_FILE_BYTES:
            logger.warning(
                "[%s] 文件超过上限 %d 字节，仅扫前段：%s", self.name, _MAX_FILE_BYTES, path
            )
            raw = bytes(raw[:_MAX_FILE_BYTES])
        try:
            return bytes(raw).decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001 — utf-8 errors=ignore 几乎不抛，仅防御
            logger.exception("[%s] utf-8 解码失败，跳过：%s", self.name, path)
            return None

    def _load_rules(self) -> _Rules:
        data = load_rules(_RULES_NAME)

        tokens: list[str] = list(_FALLBACK_CRYPTOJS_TOKENS)
        modes: list[str] = list(_FALLBACK_MODE_ALIASES)
        paddings: list[str] = list(_FALLBACK_PADDING_ALIASES)
        envelope: list[str] = list(_FALLBACK_ENVELOPE_FIELDS)
        snippet_max = _DEFAULT_SNIPPET_MAX

        if isinstance(data, dict):
            t = _as_str_list(data.get("cryptojs_tokens"))
            if t:
                tokens = t
            m = _as_str_list(data.get("mode_aliases"))
            if m:
                modes = m
            p = _as_str_list(data.get("padding_aliases"))
            if p:
                paddings = p
            e = _as_str_list(data.get("envelope_fields"))
            if e:
                envelope = e
            sm = data.get("snippet_max")
            if isinstance(sm, int) and sm > 0:
                snippet_max = sm
        elif data:
            logger.warning(
                "[%s] 规则顶层应为 dict，实际 %s；使用内置兜底",
                self.name,
                type(data).__name__,
            )

        return _Rules(
            cryptojs_tokens=tuple(tokens),
            mode_aliases=tuple(modes),
            padding_aliases=tuple(paddings),
            envelope_fields=tuple(envelope),
            snippet_max=snippet_max,
        )


# ---------------------------------------------------------------------------
# 模块级工具
# ---------------------------------------------------------------------------


def _aes_len_rank(n: int) -> int:
    """AES key 长度优先级（32 最优，其次 24/16）。非典型长度排最后。"""
    return {32: 3, 24: 2, 16: 1}.get(n, 0)
