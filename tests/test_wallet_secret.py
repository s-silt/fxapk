"""wallet_secret 分析器测试：BIP-39 助记词 / WIF / 上下文门控 EVM 私钥 → WALLET_SECRET 线索。

校验和 / 上下文门控让误报近零：随机 12 词、损坏 WIF、无上下文的 64hex 均不产线索。
"""

from __future__ import annotations

from apkscan.analyzers.wallet_secret import WalletSecretAnalyzer
from apkscan.core.models import Confidence, LeadCategory

# 标准 BIP-39 测试向量（合法 12 词，9 个互异词 → 过 2/3 互异度护栏）。
# 不用全零熵向量（abandon×11+about，仅 2 互异词）——它会被互异度护栏当 FP 滤掉（真钱包从不用）。
_M12 = "legal winner thank year wave sausage worth useful legal winner thank yellow"
# 校验和不合法的 12 词。
_BAD12 = "zone zoo zero year wrong write world work word wood wolf wish"
# 知名合法 WIF 私钥测试向量。
_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


class _Ctx:
    def __init__(self, dex=None, files=None, contents=None) -> None:
        self._dex = dex or []
        self._files = files or []
        self._contents = contents or {}

    def dex_strings(self):
        return list(self._dex)

    def list_files(self):
        return list(self._files)

    def read_file(self, path: str):
        return self._contents.get(path)


def _leads(ctx: _Ctx):
    return WalletSecretAnalyzer().analyze(ctx).leads


def test_mnemonic_detected_high() -> None:
    leads = _leads(_Ctx(dex=[f"backup seed = {_M12} ;"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.WALLET_SECRET
    assert lead.value == _M12
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == "建议调证"
    assert lead.evidence_to_obtain  # 非空


def test_random_words_no_lead() -> None:
    assert _leads(_Ctx(dex=[f"ui strings: {_BAD12}"])) == []


def test_low_distinctness_css_words_no_lead() -> None:
    # 真样本(HuaCai uni-app)误报根因：CSS/常见英文词(day/color/top/left,皆在 BIP-39 词表)凑出过
    # 校验和的 12 词窗口，但只有 3-4 个互异词 → 互异度护栏滤掉，不产假助记词。
    assert _leads(_Ctx(dex=["day color day color this day color day color this day color"])) == []
    assert _leads(_Ctx(dex=["top left left top top right right top bottom left left bottom"])) == []


def test_wif_detected_and_corrupted_rejected() -> None:
    good = _leads(_Ctx(dex=[f"privkey:{_WIF}"]))
    assert len(good) == 1
    assert good[0].value == _WIF
    # 改最后 3 位 → 校验和失败 → 不产线索。
    assert _leads(_Ctx(dex=[f"privkey:{_WIF[:-3]}AAA"])) == []


def test_evm_privkey_requires_context() -> None:
    pk = "0x" + "a" * 64
    # 有上下文关键词 → 采信。
    with_ctx = _leads(_Ctx(dex=[f"私钥 = {pk}"]))
    assert len(with_ctx) == 1
    assert with_ctx[0].value == pk
    # 无上下文（与哈希同形）→ 不采信。
    assert _leads(_Ctx(dex=[f"sha256 digest {pk} done"])) == []


def test_resource_scan_detects_mnemonic() -> None:
    ctx = _Ctx(
        files=["assets/www/config.js", "res/raw/icon.png"],
        contents={
            "assets/www/config.js": f'var w="{_M12}";'.encode(),
            "res/raw/icon.png": b"\x89PNG binary",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].source_refs[0].source == "resource"


def test_embedded_wordlist_asset_no_false_mnemonic() -> None:
    # APK 自带 BIP-39 词表（2048 连续词）→ run 护栏整段跳过，不产误报（亦防性能放大）。
    from apkscan.core.walletsecret import load_wordlist

    index, _wordset = load_wordlist()
    wordlist_text = " ".join(index)  # 2048 个连续 BIP-39 词
    assert _leads(_Ctx(dex=[wordlist_text])) == []


def test_dedup_same_secret_across_sources() -> None:
    ctx = _Ctx(
        dex=[f"a={_M12}", f"b={_M12}"],
        files=["assets/x.json"],
        contents={"assets/x.json": f'{{"m":"{_M12}"}}'.encode()},
    )
    leads = _leads(ctx)
    assert len(leads) == 1  # 同助记词跨来源仅一条
