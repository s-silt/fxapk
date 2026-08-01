"""档位的可撤销抑制来源：`base_advice` + `downgrades` → 物化出 `advice`。

**要解决的根因**：档位此前是被多个机制**依次改写**出来的结果，谁也不知道「是谁降的」。
于是任一机制想撤销自己那次降档时，既不知道该恢复到哪一档，也会把别人的降档一起冲掉。
实测发生过：伪装 SNI 解除时把重打包隔离冲没了，被仿冒厂商的域名重新进了文书出口——那正是
本项目最重的一类错误。

本文件锁的是这一层的**代数**：
- 有任何来源就压着，来源清空才回到初始档；
- 每条来源可**独立**增删，撤销一条不影响其余；
- `advice` 是物化缓存，任何绕过 helper 直接写它的地方都会被一致性断言逮住；
- 旧报告（来源不可考）保持原样，绝不凭空推断初始档。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra
from apkscan.core.models import (
    DOWNGRADE_REPACK_IDENTITY,
    DOWNGRADE_SNI_MASQUERADE,
    DOWNGRADE_SOURCE_TIER,
    Lead,
    LeadCategory,
    advice_is_consistent,
    apply_downgrade,
    effective_advice,
    lift_downgrade,
    recompute_advice,
)

_INV = infra.ADVICE_INVESTIGATE
_REVIEW = infra.ADVICE_REVIEW
_SKIP = infra.ADVICE_SKIP


def _lead(base: str | None = _INV, **kwargs) -> Lead:
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", **kwargs)
    lead.base_advice = base
    recompute_advice(lead)
    return lead


# ---------------------------------------------------------------------------
# effective_advice：纯函数的全部分支
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("base", "downgrades", "expected"), [
    (_INV, {}, _INV),                                   # 无抑制 → 原样
    (_INV, {DOWNGRADE_SOURCE_TIER: "x"}, _REVIEW),      # 有抑制 → 压到待核
    (_INV, {"a": "x", "b": "y"}, _REVIEW),              # 多条抑制 → 仍是待核（不会更低）
    (_REVIEW, {}, _REVIEW),                             # 本就待核 → 不变
    (_REVIEW, {DOWNGRADE_SOURCE_TIER: "x"}, _REVIEW),   # 待核 + 抑制 → 不变
    (_SKIP, {}, _SKIP),                                 # 无需核查不受抑制影响
    (_SKIP, {DOWNGRADE_REPACK_IDENTITY: "x"}, _SKIP),   # ★同上：那是判据结论，不是"暂时压着"
])
def test_effective_advice_table(base: str, downgrades: dict, expected: str) -> None:
    assert effective_advice(base, downgrades) == expected


def test_effective_advice_returns_empty_when_base_unknown() -> None:
    """★初始档不可考（旧报告）→ 返回空串，由调用方沿用报告里既有的 advice。

    绝不替它推断一个初始档：旧报告里的「待核」可能出自分析器初判、来源档降级、重打包隔离、
    伪装 SNI……来源已不可逆地丢失。凭空补一个 base 会让将来的自动撤销把本该压着的线索放出去。
    """
    assert effective_advice(None, {}) == ""
    assert effective_advice(None, {DOWNGRADE_SNI_MASQUERADE: "x"}) == ""
    assert effective_advice("", {}) == ""


# ---------------------------------------------------------------------------
# apply / lift：每条来源可独立增删
# ---------------------------------------------------------------------------


def test_apply_then_lift_restores_base() -> None:
    lead = _lead()
    assert lead.advice == _INV

    assert apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "只在非标端口作 SNI 出现") is True
    assert lead.advice == _REVIEW

    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is True
    assert lead.advice == _INV, "唯一的抑制来源撤掉后应回到初始档"
    assert lead.downgrades == {}


def test_lifting_one_source_keeps_the_others() -> None:
    """★这条是整个机制存在的理由：撤销一条不得把别的机制的抑制一起冲掉。

    实测踩过的那次就是这个形状——伪装解除时整体重算 Lead，重打包隔离随之消失，
    被仿冒厂商的域名重新进了文书出口。
    """
    lead = _lead()
    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "样本判为正版重打包件")
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "只在非标端口作 SNI 出现")
    assert lead.advice == _REVIEW

    lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE)

    assert lead.advice == _REVIEW, "重打包隔离还在，档位必须继续压着"
    assert list(lead.downgrades) == [DOWNGRADE_REPACK_IDENTITY]

    lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY)
    assert lead.advice == _INV, "最后一条撤掉后才回到初始档"


def test_apply_is_idempotent_and_updates_note() -> None:
    lead = _lead()
    assert apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "第一版说明") is True
    assert apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "更新后的说明") is False, "同 id 不重复计"
    assert lead.downgrades[DOWNGRADE_SOURCE_TIER] == "更新后的说明"
    assert lead.advice == _REVIEW


def test_lift_unknown_source_is_a_noop() -> None:
    lead = _lead()
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is False, "没记过的来源撤不掉"
    assert lead.advice == _REVIEW, "别的来源还在，档位不动"


def test_apply_records_even_when_already_downgraded() -> None:
    """★命中就记，哪怕当前档位已经是待核——档位相同不代表来源相同。

    若因为「反正已经是待核了」而不记，将来另一条来源被撤销时，本条不在字典里，档位会错误地
    弹回最高档。这正是本机制要防的那件事。
    """
    lead = _lead()
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "仅见于第三方库文件")
    assert lead.advice == _REVIEW

    # 此时档位已是待核，重打包隔离仍须把自己记下来。
    assert apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "样本判为正版重打包件") is True

    lift_downgrade(lead, DOWNGRADE_SOURCE_TIER)
    assert lead.advice == _REVIEW, "tier 撤了，但重打包那条记着，档位应继续压着"


def test_skip_base_is_never_lifted_into_investigate() -> None:
    """「无需核查」是判据结论，不是被压着——加了抑制再撤掉，仍是「无需核查」。"""
    lead = _lead(base=_SKIP)
    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "x")
    assert lead.advice == _SKIP
    lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY)
    assert lead.advice == _SKIP


def test_unknown_base_still_downgrades_from_the_top_tier() -> None:
    """★★最危险的那个场景：旧报告里档位是最高档，新证据说该压。

    「存在抑制来源」这个事实是明确的，所以**必须压档**——哪怕算不出初始档。
    若只把来源记进字典却不动档位，字典看着像「抑制已生效」，线索却照旧走到文书出口，
    是最典型的静默失败。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    assert lead.base_advice is None, "旧报告没有初始档"

    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "样本判为正版重打包件")

    assert lead.advice == _REVIEW, "初始档不可考也必须压档，否则线索仍会进文书出口"
    assert lead.downgrades == {DOWNGRADE_REPACK_IDENTITY: "样本判为正版重打包件"}


def test_unknown_base_refuses_to_lift() -> None:
    """★旧报告的抑制**不可撤销**：算不出该恢复到哪一档，硬撤只能靠猜。

    猜错的方向是把本该压着的线索放进文书出口，所以宁可留着不撤。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")
    assert lead.advice == _REVIEW

    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is False, "无初始档时必须拒绝撤销"
    assert lead.downgrades == {DOWNGRADE_SNI_MASQUERADE: "x"}, "拒绝撤销时字典不得被动过"
    assert lead.advice == _REVIEW, "档位保持压着"


def test_unknown_base_with_already_review_advice_is_unchanged() -> None:
    """旧报告本就在待核档：记下来源，档位不动。"""
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_REVIEW)

    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")

    assert lead.advice == _REVIEW


# ---------------------------------------------------------------------------
# advice 是物化缓存：一致性不变量
# ---------------------------------------------------------------------------


def test_consistency_holds_after_helper_operations() -> None:
    lead = _lead()
    assert advice_is_consistent(lead)
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert advice_is_consistent(lead)
    lift_downgrade(lead, DOWNGRADE_SOURCE_TIER)
    assert advice_is_consistent(lead)


def test_consistency_catches_a_bypassing_write() -> None:
    """★绕过 helper 直接写 advice → 一致性断言必须逮住。

    `advice` 是 `base_advice` 与 `downgrades` 的物化缓存，不是第三个独立真源。
    """
    lead = _lead()
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert advice_is_consistent(lead)

    lead.advice = _INV  # 有人直接改了档位，却没动来源

    assert not advice_is_consistent(lead), "绕过 helper 的写入没被逮住"


def test_unknown_base_is_always_consistent() -> None:
    """旧数据无从校验 —— 视为一致，不制造假红。"""
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_REVIEW)
    assert advice_is_consistent(lead)


# ---------------------------------------------------------------------------
# report.json 往返
# ---------------------------------------------------------------------------


def test_downgrades_survive_report_roundtrip() -> None:
    """两个新字段必须往返：丢了就等于抑制来源在下一次读盘时全部失忆。"""
    import json

    from apkscan.core import report_io
    from apkscan.report import json as report_json

    lead = _lead()
    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "样本判为正版重打包件")
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "只在非标端口作 SNI 出现")

    payload = {"leads": [json.loads(json.dumps(report_json._to_jsonable(lead)))]}
    revived = report_io.report_from_dict(payload).leads[0]

    assert revived.base_advice == _INV
    assert revived.downgrades == {
        DOWNGRADE_REPACK_IDENTITY: "样本判为正版重打包件",
        DOWNGRADE_SNI_MASQUERADE: "只在非标端口作 SNI 出现",
    }
    assert revived.advice == _REVIEW
    assert advice_is_consistent(revived)

    # 往返之后仍能独立撤销——这才是往返的意义所在。
    lift_downgrade(revived, DOWNGRADE_SNI_MASQUERADE)
    assert revived.advice == _REVIEW, "重打包那条还在"


def test_legacy_report_without_new_fields_is_unchanged() -> None:
    """★旧报告读进来行为逐字不变，且**不**被伪装成拥有可靠来源。"""
    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com",
        "advice": _REVIEW, "confidence": "LOW", "notes": "旧报告没有新字段",
    }]}
    revived = report_io.report_from_dict(payload).leads[0]

    assert revived.advice == _REVIEW, "档位原样沿用"
    assert revived.base_advice is None, "初始档必须如实标为不可考，不能回落成当前档"
    assert revived.downgrades == {}


@pytest.mark.parametrize("bad", [
    None, [], "x", 42,
    {"": "空键"},
    {1: "非字符串键"},
    {"ok": {"nested": 1}},   # ★值是嵌套对象：不得被 str() 硬转成 "{'nested': 1}" 混进判定输入
    {"ok": ["列表"]},
    {"ok": None},
    {"ok": 42},
])
def test_bad_downgrades_payload_is_dropped(bad: object) -> None:
    """坏形状一律丢弃、绝不抛：这份数据来自磁盘，可能被手改或被别的工具写坏。"""
    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com",
        "advice": _INV, "downgrades": bad,
    }]}
    revived = report_io.report_from_dict(payload).leads[0]
    assert revived.downgrades == {}


@pytest.mark.parametrize("bad", [
    "乱码", "{'bad': 1}", "", "   ", 42, [], {}, True, None,
])
def test_illegal_base_advice_is_treated_as_unknown(bad: object) -> None:
    """★非法初始档一律当「来源不可考」，绝不原样收下。

    收下的后果：一个没人认识的字符串会被 `recompute_advice` 当成档位写进 `advice`，
    而一致性校验还判它自洽——凭空造出一个下游谁也不认的档位。
    退回「不可考」是安全的：档位原样沿用报告里的 advice，行为等同旧报告。
    """
    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com",
        "advice": _INV, "base_advice": bad,
    }]}
    revived = report_io.report_from_dict(payload).leads[0]

    assert revived.base_advice is None
    assert revived.advice == _INV, "档位原样沿用，不被非法初始档改写"


@pytest.mark.parametrize("good", [_INV, _REVIEW, _SKIP])
def test_legal_base_advice_survives_roundtrip(good: str) -> None:
    """反向：三个合法档位都要能原样读回来（收严不能把合法值一起挡掉）。"""
    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com",
        "advice": good, "base_advice": good,
    }]}
    revived = report_io.report_from_dict(payload).leads[0]
    assert revived.base_advice == good
