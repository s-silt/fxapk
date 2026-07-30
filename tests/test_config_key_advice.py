"""配置键线索按**值**分档，不再不看值一律判「建议核查」。

来源：2026-07-30 对网页证据的重跑。`CONFIG_KEY` 的类别兜底原先无条件给「建议核查」，于是
`baseURL=https://localhost:60267`（前端 HTML 内联脚本里一行**被注释掉**的调试配置）也进了
出口——本机地址不存在可查询的对象，名额却被它占着。

★两条边界都必须钉住：
- 只降**待核**，不判无需核查：开发者本机调试端口残留是构建环境痕迹，有情报价值。
- 值里取不出 host 的配置键行为**逐字不变**——`com.openinstall.APP_KEY=REDACTED-KEY` 这类
  是真线索，判据放宽一点就会把它一起降掉。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra
from apkscan.core.leads import _apply_default_advice, _config_value_unroutable_host
from apkscan.core.models import Lead, LeadCategory

_INV = infra.ADVICE_INVESTIGATE
_REVIEW = infra.ADVICE_REVIEW
_SKIP = infra.ADVICE_SKIP


def _config_lead(value: str) -> Lead:
    return Lead(category=LeadCategory.CONFIG_KEY, value=value)


@pytest.mark.parametrize("value", [
    "baseURL=https://localhost:60267",
    "baseURL=http://127.0.0.1:8080/api",
    "api_base=https://10.0.2.2:3000",
    "host=192.168.1.7:9000",
    "endpoint=http://[::1]:5000/v1",
    "debugHost=localhost",
    # 文档保留段（TEST-NET-3）同样非全球可路由：没有注册人可查，与本机同一档。
    "host=203.0.113.9:8443",
])
def test_local_config_values_drop_to_review(value: str) -> None:
    """值指向本机/私网 → 待核，且理由写明「无对外查询对象」。"""
    lead = _config_lead(value)
    _apply_default_advice([lead])
    assert lead.advice == _REVIEW, f"{value} 仍判 {lead.advice}"
    assert "不可对外查询" in (lead.notes or "")


def test_local_config_values_are_never_skipped() -> None:
    """★不判无需核查：本机调试端口残留是构建环境痕迹，得留在清单上。"""
    lead = _config_lead("baseURL=https://localhost:60267")
    _apply_default_advice([lead])
    assert lead.advice != _SKIP


@pytest.mark.parametrize("value", [
    "com.openinstall.APP_KEY=REDACTED-KEY",       # 每案不同的真线索
    "GETUI_APPID=abc123",
    "AES_KEY=0123456789abcdef",
    "debug=true",
    "baseURL=https://api.attacker-backend.example/v1",   # 公网形态 host —— 照旧进出口
    "host=8.210.13.45:30147",               # leak-scan: allow 判据夹具：公网地址形态，验其未被降档
])
def test_non_local_config_values_keep_their_advice(value: str) -> None:
    """取不出本机/私网 host 的配置键，行为逐字不变。"""
    lead = _config_lead(value)
    _apply_default_advice([lead])
    assert lead.advice == _INV, f"{value} 被误降为 {lead.advice}"


def test_existing_advice_is_never_overwritten() -> None:
    """分析器已研判过的不动——兜底就是兜底。"""
    lead = _config_lead("baseURL=https://localhost:60267")
    lead.advice = _INV
    _apply_default_advice([lead])
    assert lead.advice == _INV


def test_host_extractor_only_accepts_the_two_documented_shapes() -> None:
    """判据只认 ``key=<scheme>://host[:port]`` 与 ``key=host:port``；别的取不出 host。"""
    assert _config_value_unroutable_host("baseURL=https://localhost:60267") == "localhost"
    assert _config_value_unroutable_host("host=127.0.0.1") == "127.0.0.1"
    # 没有 `=` 的、或 host 位置是公网名字的，都不该命中。
    assert _config_value_unroutable_host("localhost:60267") == ""
    assert _config_value_unroutable_host("baseURL=https://example.com") == ""
    assert _config_value_unroutable_host("") == ""
