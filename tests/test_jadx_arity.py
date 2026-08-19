"""P1-A：方法 arity 的泛型感知计数（schema 1.3）。

旧实现按 `split(",")` 数参数，泛型实参里的逗号被当成参数分隔符——
`Map<String, String> m` 算成 2。方法身份是 `cls#name/arity`，算错即令
callpath 按真实 arity 查假阴性、ownership 与 baseline 对不齐。

畸形输入（不配对的 `>`）在混淆与截断产物里是常态，只要求不抛且非负：
畸形输入没有唯一正确答案，钉死具体值等于把实现细节写成契约。
"""

from __future__ import annotations

import pytest

from apkscan.core.jadx_index import _declared_arity


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ("", 0),
        ("   ", 0),
        ("String a", 1),
        ("String a, int b", 2),
        ("Map<String, String> m", 1),
        ("List<Map<String, Integer>> x, int y", 2),
        ("Map<String, String> a, List<Integer> b, int c", 3),
        ("Function<A, B> f", 1),
        ("int[] a, String... b", 2),
        ("Map<String, ? super Integer> m", 1),
        ("int a,", 1),
    ],
)
def test_declared_arity_counts_top_level_commas(params: str, expected: int) -> None:
    assert _declared_arity(params) == expected


@pytest.mark.parametrize(
    "params",
    [
        "Map<String, String m",
        "a > b, c",
        ">>>",
        "<<<",
    ],
)
def test_declared_arity_survives_unbalanced_angle_brackets(params: str) -> None:
    assert _declared_arity(params) >= 0
