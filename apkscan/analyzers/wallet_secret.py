"""wallet_secret 分析器：从 dex / 资源里挖**钱包私钥 / 助记词**（直接掌控资金的最高价值物证）。

与 payment 的链上地址互补：地址是「钱往哪去」，私钥 / 助记词是「直接能动钱」——掌握即可
转移 / 冻结资金、派生全部地址上链回溯。检测全部走**校验和**（BIP-39 / Base58Check），
误报近零（见 core/walletsecret）。EVM 裸私钥（0x+64hex）与哈希同形，**须近邻上下文关键词
门控**才采信，避免把普通哈希误判私钥。

约束（与其它分析器一致）：只用 AnalysisContext 公开接口、规则/词表数据化、资源扫描带上限、
never-throw try/except + logging、全 type hints、宁缺毋滥。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    collect_dex_strings,
    is_text_resource,
    truncate,
)
from apkscan.core import walletsecret
from apkscan.core.models import AnalyzerResult, Confidence, Evidence, Lead, LeadCategory
from apkscan.core.registry import BaseAnalyzer

if TYPE_CHECKING:
    from apkscan.core.context import AnalysisContext

logger = logging.getLogger(__name__)

_MAX_DEX_STRINGS = 200_000
_MAX_RESOURCE_BYTES = 4_000_000
_MAX_TOTAL_RESOURCE_BYTES = 64_000_000
# EVM 裸私钥上下文门控：候选前后此窗口内须出现钱包凭据关键词才采信。
_CTX_WINDOW = 80
_CTX_KEYWORDS = (
    "私钥", "助记词", "钱包", "密钥", "种子",
    "privatekey", "private_key", "privkey", "mnemonic", "seed",
    "secret", "keystore", "wallet", "walletconnect",
)

_WHERE = "无直接调证对象（链上追踪 / 资金控制用）"
_EVIDENCE = (
    "据该凭据派生的全部钱包地址（多链）",
    "链上资金流向与归集点（TronScan / Etherscan 等）",
    "对接交易所 / Tether 冻结与调取 KYC",
)
_KIND_LABEL = {
    "mnemonic": "助记词（BIP-39 钱包恢复短语）",
    "wif": "WIF 比特币私钥",
    "evm_privkey": "EVM 裸私钥",
}


class WalletSecretAnalyzer(BaseAnalyzer):
    """检测钱包私钥 / 助记词，产出 category=WALLET_SECRET 的高敏调证线索。"""

    name: str = "wallet_secret"
    meta_key_categories = {
        'dex_strings_truncated': 'coverage',
        'wallet_secret_count': 'record',
        # 资源面覆盖缺口：让 count=0 能区分「确实没有」与「没扫全」。
        'wallet_secret_list_failed': 'coverage',
        'wallet_secret_read_failed': 'coverage',
        'wallet_secret_oversize_skipped': 'coverage',
        'wallet_secret_budget_exhausted': 'coverage',
    }
    meta_keys = frozenset(meta_key_categories)
    requires: list[str] = []

    def analyze(self, ctx: "AnalysisContext") -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        # value -> (kind, source, location)
        hits: dict[str, tuple[str, str, str]] = {}

        _ok, dex_strings = collect_dex_strings(ctx, self.name, max_strings=_MAX_DEX_STRINGS, result=result)
        for s in dex_strings:
            self._scan_text(s, "dex", "dex_strings", hits)
        resource_coverage = self._scan_resources(ctx, hits)
        # 只写实际发生的覆盖缺口；缺失键即「没发生过这类缺口」（见 core/coverage.py 的约定）。
        # ★键名写成字面量而非 coverage_meta_key(self.name, ...) 动态拼：meta_scan 契约要求
        #   「声明的键」与「代码里静态可见的写入」双向对齐，动态拼键会让扫描器只看到 <dynamic>、
        #   等于绕过整套契约。字面量虽啰嗦，但护栏能核。
        for suffix, value in resource_coverage.items():
            if suffix == "list_failed":
                result.meta["wallet_secret_list_failed"] = value
            elif suffix == "read_failed":
                result.meta["wallet_secret_read_failed"] = value
            elif suffix == "oversize_skipped":
                result.meta["wallet_secret_oversize_skipped"] = value
            elif suffix == "budget_exhausted":
                result.meta["wallet_secret_budget_exhausted"] = value

        for value, (kind, source, location) in sorted(hits.items()):
            try:
                result.leads.append(self._build_lead(value, kind, source, location))
            except Exception:
                logger.exception("[%s] 构建线索失败（已跳过）：%s", self.name, kind)

        result.meta["wallet_secret_count"] = len(result.leads)
        if result.leads:
            kinds = sorted({k for k, _s, _l in hits.values()})
            logger.info("[%s] 命中钱包凭据 %d 条（%s）", self.name, len(result.leads), "、".join(kinds))
        return result

    def _scan_text(
        self, text: str, source: str, location: str, hits: dict[str, tuple[str, str, str]]
    ) -> None:
        """从一段文本抽助记词 / WIF / 上下文门控的 EVM 私钥，累积去重。绝不抛。"""
        if not text:
            return
        try:
            for sec in walletsecret.find_mnemonics(text):
                hits.setdefault(sec.value, ("mnemonic", source, location))
            for sec in walletsecret.find_wif_keys(text):
                hits.setdefault(sec.value, ("wif", source, location))
            lowered = text.lower()
            for value, start, end in walletsecret.find_evm_privkey_candidates(text):
                lo = max(0, start - _CTX_WINDOW)
                hi = min(len(text), end + _CTX_WINDOW)
                window = lowered[lo:hi]
                if any(kw in window for kw in _CTX_KEYWORDS):
                    hits.setdefault(value, ("evm_privkey", source, location))
        except Exception:
            logger.exception("[%s] 扫描文本失败：%s", self.name, location)

    def _scan_resources(self, ctx: "AnalysisContext", hits: dict[str, tuple[str, str, str]]) -> dict[str, int]:
        """扫描 APK 内文本资源（H5/JS/json 配置里的助记词 / 私钥）。绝不抛。"""
        try:
            files = [p for p in ctx.list_files() if isinstance(p, str)]
        except Exception:
            logger.exception("[%s] 读取 list_files 失败", self.name)
            return {"list_failed": 1}
        total = 0
        read_failed = 0
        oversize = 0
        budget_hit = False
        for path in files:
            if total >= _MAX_TOTAL_RESOURCE_BYTES:
                # 达到总预算＝剩余资源根本没看，必须向下游暴露这个缺口。
                budget_hit = True
                logger.warning("[%s] 文本资源扫描达总预算，停止", self.name)
                break
            if not is_text_resource(
                path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
            ):
                continue
            try:
                data = ctx.read_file(path)
            except Exception:
                # 单个资源读失败不中断扫描，但要计数——读不到 ≠ 里面没有。
                read_failed += 1
                logger.exception("[%s] 读取资源失败：%s", self.name, path)
                continue
            if not data:
                continue  # 空文件不是覆盖缺口，静默跳过
            if len(data) > _MAX_RESOURCE_BYTES:
                # 超大资源被整个跳过，是覆盖缺口而非「未命中」。
                oversize += 1
                continue
            total += len(data)
            text = (
                data.decode("utf-8", errors="replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )
            self._scan_text(text, "resource", path, hits)

        return {
            key: value
            for key, value in {
                "read_failed": read_failed,
                "oversize_skipped": oversize,
                "budget_exhausted": int(budget_hit),
            }.items()
            if value
        }

    def _build_lead(self, value: str, kind: str, source: str, location: str) -> Lead:
        # 校验和 / 上下文门控通过 → 近乎确定，HIGH·建议调证。
        ev = Evidence(source=source, location=location, snippet=truncate(value, 120))
        return Lead(
            category=LeadCategory.WALLET_SECRET,
            value=value,
            subject=None,
            where_to_request=_WHERE,
            evidence_to_obtain=list(_EVIDENCE),
            confidence=Confidence.HIGH,
            source_refs=[ev],
            notes=f"高敏：{_KIND_LABEL.get(kind, kind)}，掌握即可转移 / 冻结资金并上链回溯派生地址",
            advice="建议调证",
        )
