"""DEX 字符串池不透明度（可信度信号）：命中/不命中与假阳防线。

零真实样本：全部合成字符串。★ 重点覆盖「中文 App 不得被误判」这条头号假阳线。
"""
from __future__ import annotations

import random

from apkscan.analyzers.dex_obfuscation import DexObfuscationAnalyzer, assess_string_pool
from tests.conftest import FakeContext

_FINDING = "DEX-STRING-POOL-OPAQUE"


def _analyze(strings: list[str]):
    return DexObfuscationAnalyzer().analyze(FakeContext(dex_strings=strings))


def _finding_ids(result) -> list[str]:
    return [f.id for f in result.findings]


# --- 正常 App：不得命中 ----------------------------------------------------


def test_normal_english_app_not_flagged() -> None:
    strings = [f"user_profile_item_{i}" for i in range(400)]
    strings += ["https://api.example-synthetic.test/v1/login", "Content-Type", "application/json"]
    result = _analyze(strings)
    assert _FINDING not in _finding_ids(result)
    assert result.meta["dex_string_pool"]["suspicious"] is False


def test_chinese_app_not_flagged() -> None:
    """★头号假阳线（无修复即失败）：中文 App 字符串大量非 ASCII 但**完全可读**，绝不能判混淆。

    若把「非 ASCII」当不可读，这批全部会被误判成加密串 → 报告污蔑一个正常中文 App 用了字符串混淆。
    """
    zh = ["登录失败，请稍后重试", "网络连接超时", "请输入手机号码", "确认支付金额",
          "订单已提交成功", "正在加载中，请稍候", "账户余额不足", "验证码已发送"]
    strings = [f"{z}{i}" for i in range(60) for z in zh]  # 480 条中文串
    result = _analyze(strings)
    assert _FINDING not in _finding_ids(result)
    stats = result.meta["dex_string_pool"]
    assert stats["suspicious"] is False
    assert stats["readable_ratio"] > 0.9  # 中文被正确识别为「可读」


def test_mixed_cjk_and_latin_not_flagged() -> None:
    """中英混排 + 日文/俄文同样算可读内容。"""
    strings = [f"ログイン失敗 {i}" for i in range(150)]
    strings += [f"Ошибка сети {i}" for i in range(150)]
    strings += [f"errorCode={i}" for i in range(150)]
    result = _analyze(strings)
    assert _FINDING not in _finding_ids(result)


def test_small_pool_never_flagged() -> None:
    """★样本量不足（< _MIN_SAMPLE）→ 一律不给结论（少量样本任何比例都不稳）。"""
    opaque = ["".join(chr(random.Random(i).randrange(0xE000, 0xF8FF)) for _ in range(20))
              for i in range(50)]
    stats = assess_string_pool(opaque)
    assert stats["opaque_ratio"] > 0.9      # 形态上确实全不透明
    assert stats["suspicious"] is False     # 但样本太少 → 不下结论


# --- 混淆样本：应命中 ------------------------------------------------------


def _pua_strings(n: int, seed: int = 7) -> list[str]:
    """合成「私用区码位」加密串——字符串混淆器常见形态之一。"""
    rnd = random.Random(seed)
    return ["".join(chr(rnd.randrange(0xE000, 0xF8FF)) for _ in range(24)) for _ in range(n)]


def test_obfuscated_pool_flagged() -> None:
    """★无修复即失败：池中成规模的不可读串 + 几乎无可读内容 → 产 Finding 并明示可能失明。"""
    strings = _pua_strings(500)
    strings += ["Landroid/app/Activity;", "()V", "[B"]  # 描述符恒在，不该稀释判定
    result = _analyze(strings)
    assert _FINDING in _finding_ids(result)
    f = next(f for f in result.findings if f.id == _FINDING)
    assert f.category == "anti_analysis"
    assert "不可解读为" in f.description   # 明确否定「未发现=不存在」
    assert f.evidences and len(f.evidences) <= 3


def test_control_char_payloads_flagged() -> None:
    """控制字符载荷（另一种常见加密串形态）同样识别。"""
    rnd = random.Random(11)
    strings = ["".join(chr(rnd.randrange(1, 0x20)) for _ in range(20)) for _ in range(400)]
    assert assess_string_pool(strings)["suspicious"] is True


def test_descriptors_excluded_from_stats() -> None:
    """★类型描述符/签名不随字符串混淆消失，若计入统计会稀释比例、掩盖失明 → 必须排除。"""
    descriptors = ["Landroid/app/Activity;", "Ljava/lang/String;", "()Ljava/lang/Object;", "[I"] * 200
    stats = assess_string_pool(descriptors)
    assert stats["sampled"] == 0  # 全被排除，不参与任何比例计算


def test_partial_obfuscation_below_threshold_not_flagged() -> None:
    """少量加密串（如仅几个内嵌密钥）+ 大量正常串 → 不命中（那是正常 App 的常见形态）。"""
    strings = [f"activity_main_layout_{i}" for i in range(400)] + _pua_strings(20)
    result = _analyze(strings)
    assert _FINDING not in _finding_ids(result)


# --- 稳健性 ----------------------------------------------------------------


def test_empty_and_garbage_input() -> None:
    assert assess_string_pool([])["suspicious"] is False
    assert assess_string_pool(["", "ab", "x"])["sampled"] == 0
    result = _analyze([])
    assert _FINDING not in _finding_ids(result)


def test_analyzer_always_records_metrics() -> None:
    """无论是否命中，画像都写进 meta——让「我们看到了多少」本身可复核。"""
    result = _analyze([f"normal_string_{i}" for i in range(400)])
    stats = result.meta["dex_string_pool"]
    assert set(stats) >= {"sampled", "opaque", "readable", "opaque_ratio", "readable_ratio", "suspicious"}
