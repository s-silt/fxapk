"""Epic A 分析器大输入耗时回归（ReDoS / O(n²) 守护）。

不是微基准: 用 pathological 大输入(2MB 单字符 run + 上千 URL / 海量关键词)跑各分析器,
断言秒级完成。线性实现下实测各 <0.3s; 若日后引入灾难性回溯 / O(n²)(如就近窗口退化、
正则无界量词)会飙到数十秒~分钟而触发预算失败。预算给得宽松(避免慢 CI 抖动), 只抓真退化。
"""

from __future__ import annotations

import time

from apkscan.core.registry import discover_analyzers

# 宽松预算: 实测各分析器 <0.3s; 仅用于捕获 ReDoS / O(n²) 量级退化, 非性能门禁。
_BUDGET_SECONDS = 20.0

_EPIC_A = (
    "admin_panel",
    "fourth_party_payment",
    "sms_forwarding",
    "card_merchant",
    "self_hosted_im",
)


class _Ctx:
    """最小 AnalysisContext 替身（喂大输入）。"""

    def __init__(self, dex, files=None, contents=None) -> None:
        self._dex = dex
        self._files = files or []
        self._contents = contents or {}

    def dex_strings(self):
        return list(self._dex)

    def list_files(self):
        return list(self._files)

    def read_file(self, path: str):
        return self._contents.get(path)

    def native_libs(self):
        return []


def _big_ctx() -> _Ctx:
    big_run = "a" * 2_000_000  # 长单字符 run：触发任何无界 / 嵌套量词的灾难性回溯
    urls = [f"https://h{i}.evilbackend.com/api/admin/login?x={i}" for i in range(1500)]
    kw = "跑分 代收代付 聚合支付 短信转发 验证码转发 卡商 卡密 四件套 " * 1500
    dex = (
        urls
        + ["跑分代收代付卡商"] * 1500
        + ["ws://evilbroker.com:1883"] * 200
        + [big_run]
    )
    h5 = ("var a='https://manage.evilbackend.com/api/admin/list';" + kw + big_run).encode()
    return _Ctx(
        dex,
        files=["assets/www/app.js", "res/raw/x.png"],
        contents={"assets/www/app.js": h5},
    )


def test_epic_a_analyzers_large_input_is_fast() -> None:
    ctx = _big_ctx()
    az = {a.name: a for a in discover_analyzers() if a.name in _EPIC_A}
    assert set(az) == set(_EPIC_A), f"缺分析器：{set(_EPIC_A) - set(az)}"
    for name, analyzer in az.items():
        start = time.perf_counter()
        result = analyzer.analyze(ctx)
        elapsed = time.perf_counter() - start
        assert result is not None
        assert elapsed < _BUDGET_SECONDS, (
            f"{name} 大输入耗时 {elapsed:.1f}s 超预算 {_BUDGET_SECONDS}s（疑 ReDoS / O(n²) 退化）"
        )
