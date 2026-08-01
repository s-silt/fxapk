"""档位的可撤销抑制来源：`base_advice` + `downgrades` → 物化出 `advice`。

**要解决的根因**：档位此前是被多个机制**依次改写**出来的结果，谁也不知道「是谁降的」。
于是任一机制想撤销自己那次降档时，既不知道该恢复到哪一档，也会把别人的降档一起冲掉。
实测发生过：伪装 SNI 解除时把重打包隔离冲没了，被仿冒厂商的域名重新进了文书出口——那正是
本项目最重的一类错误。

本文件锁的是这一层的**代数**：
- 有任何来源就压着，来源清空才回到初始档；
- 每条来源可**独立**增删，撤销一条不影响其余；
- `advice` 是物化缓存，绕过 helper 直接写它会与锚点失配——**在有锚点的前提下**能被
  `advice_is_consistent` 算出来（两个锚点都没有时它恒判一致，那是无从查起、不是查过了）；
- 旧报告（来源不可考）保持原样，绝不凭空推断初始档；被本机制第一次抑制时拍一张迁移快照，
  这样它此后**仍然撤得掉**，撤销的落点是「被碰之前的既成状态」。
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


def test_legacy_snapshot_makes_old_report_revocable() -> None:
    """★旧报告被第一次抑制时拍下迁移快照，此后**仍然撤得掉**。

    这是「保守压档 + 永久锁死」与本方案的分界：没有快照，第二刀一旦对旧报告 apply 一次，
    新证据来了也撤不掉，等于线索被永久埋掉。有快照则撤销的落点是「被碰之前的既成状态」，
    不比原状态更松，也就不产生新的暴露面。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    assert lead.base_advice is None, "旧报告：判据链结论不可考"

    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")
    assert lead.legacy_effective_advice == _INV, "压档前的实际档位必须被拍下来"
    assert lead.advice == _REVIEW, "照样压档：存在抑制来源这个事实是明确的"

    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is True, "有快照就撤得掉"
    assert lead.downgrades == {}
    assert lead.advice == _INV, "恢复到快照，不多不少"
    assert lead.legacy_effective_advice == _INV, "撤空账本后快照仍留着（审计痕迹 + 再次抑制的锚点）"


def test_legacy_snapshot_is_write_once() -> None:
    """★快照 write-once：第二次抑制绝不覆写。

    覆写的话第二次拍到的是自己压过的档，恢复点一路往下滑（棘轮），最后恢复到的比原状态还低。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")
    assert lead.legacy_effective_advice == _INV
    assert lead.advice == _REVIEW

    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "y")
    assert lead.legacy_effective_advice == _INV, "第二次抑制时快照不得被压过的档覆盖"

    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is True
    assert lead.advice == _REVIEW, "另一条来源还在，档位照旧压着"
    assert lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY) is True
    assert lead.advice == _INV, "全部撤掉才回到快照，且回到的是最初那张"


def test_legacy_snapshot_survives_emptying_the_ledger() -> None:
    """★撤空账本之后再次抑制，用的仍是最初那张快照。

    `lift_downgrade` 的注释承诺了「撤空后不删快照」，这条把承诺锁住：防止将来有人在撤空时
    顺手「清理」快照，或把拍快照的条件简化成只看账本空不空——那样第二轮会拍到已被压过的档，
    恢复点每轮下滑一级，最后恢复到的比原始状态还低。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)

    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "第一轮")
    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is True
    assert lead.downgrades == {}, "账本已撤空"
    assert lead.legacy_effective_advice == _INV, "快照留着——审计痕迹 + 再次抑制的锚点"
    assert lead.advice == _INV

    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "第二轮")
    assert lead.legacy_effective_advice == _INV, "第二轮不得重新拍快照"
    assert lead.advice == _REVIEW

    assert lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY) is True
    assert lead.advice == _INV, "仍恢复到最初那张快照，没有逐轮下滑"


def test_legacy_snapshot_not_recaptured_after_external_advice_change() -> None:
    """★write-once 真正防的那件事：撤空账本后 advice 被外部改过，再次抑制**不得**重拍快照。

    恢复点的语义是「本机制**第一次**接管前的状态」，不是「最近一次接管前」。上一条测试
    （撤空后原样再抑制）抓不到这个退化——那时 advice 已经恢复成快照值，重拍拍到的是同一个值，
    删掉 write-once 条件也照样绿。必须让撤空后的 advice 与快照**不同**，退化才现形。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "第一轮")
    assert lead.legacy_effective_advice == _INV
    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is True

    # 撤空之后，档位被本机制之外的东西改了（人工研判、或某个还没迁过来的直写位点）。
    lead.advice = _SKIP

    apply_downgrade(lead, DOWNGRADE_REPACK_IDENTITY, "第二轮")
    assert lead.legacy_effective_advice == _INV, "快照必须还是最初那张，不能被改过的档位覆盖"

    assert lift_downgrade(lead, DOWNGRADE_REPACK_IDENTITY) is True
    assert lead.advice == _INV, "撤销回到最初的恢复点，而不是中途那个更低的档"


def test_legacy_snapshot_of_review_lifts_without_raising_advice() -> None:
    """★返回 ``True`` 只表示「来源已移除」，不等于档位回升。

    快照本身就是待核时，撤光全部来源后档位仍是待核。别拿返回值当档位信号。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_REVIEW)
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert lead.legacy_effective_advice == _REVIEW
    assert lead.advice == _REVIEW

    assert lift_downgrade(lead, DOWNGRADE_SOURCE_TIER) is True, "来源确实被移除了"
    assert lead.advice == _REVIEW, "但档位不回升——快照就是待核"


def test_double_unknown_refuses_to_lift() -> None:
    """★两个锚点都没有时仍**拒绝撤销**——原测试的保守性在畸形态上原样保留。

    这里构造的是畸形态：``downgrades`` 已经非空却没有 ``base_advice``（磁盘数据被手改、
    或有人跳过 helper 直写了字典）。此时 advice 已不知被谁动过，给它拍快照等于给一个来路
    不明的值发**恢复凭证**，撤光之后线索就凭这张凭证进了文书出口。宁可维持不可撤销。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    lead.downgrades[DOWNGRADE_SOURCE_TIER] = "直写进来的，没走 helper"

    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")
    assert lead.legacy_effective_advice is None, "畸形态不立恢复点"
    assert lead.advice == _REVIEW, "但照样压档"

    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is False, "两个锚点都没有时必须拒绝撤销"
    assert lead.downgrades == {
        DOWNGRADE_SOURCE_TIER: "直写进来的，没走 helper",
        DOWNGRADE_SNI_MASQUERADE: "x",
    }, "拒绝撤销时字典不得被动过"
    assert lead.advice == _REVIEW, "档位保持压着"


@pytest.mark.parametrize("bad_advice", ["", "   ", "查一下", "{'bad': 1}"])
def test_unsnapshottable_advice_refuses_to_lift(bad_advice: str) -> None:
    """★advice 是空串（未研判）或乱码时不拍快照——拍了只会造出没人认识的恢复点。

    行为退回「保守压档 + 不可撤销」，是安全的兜底。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=bad_advice)
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")

    assert lead.legacy_effective_advice is None, "非法档位不得进快照"
    assert lead.advice == bad_advice, "既不是最高档，压档分支也不该动它"
    assert lift_downgrade(lead, DOWNGRADE_SNI_MASQUERADE) is False
    assert lead.downgrades == {DOWNGRADE_SNI_MASQUERADE: "x"}


def test_legacy_snapshot_never_raises_lowest_tier() -> None:
    """★方向锁：最低档的线索不因为「有抑制来源」反被**抬**成待核。

    这是 :func:`effective_advice` 最后那条 ``return anchor`` 的意义。把它简化成「有 downgrades
    就返回待核」，方向就正好反了。
    """
    assert effective_advice(None, {DOWNGRADE_SOURCE_TIER: "x"}, _SKIP) == _SKIP

    lead = Lead(category=LeadCategory.DOMAIN, value="cdn.example.com", advice=_SKIP)
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert lead.legacy_effective_advice == _SKIP
    assert lead.advice == _SKIP, "最低档不受抑制影响，更不能被抬高"


def test_base_advice_wins_over_legacy_snapshot() -> None:
    """★锚点优先级：判据链结论 > 迁移快照。两者并存时（数据被手改）以前者为准。"""
    assert effective_advice(_SKIP, {DOWNGRADE_SOURCE_TIER: "x"}, _INV) == _SKIP, "base 说最低档就是最低档"

    lead = _lead(base=_INV)
    lead.legacy_effective_advice = _SKIP
    apply_downgrade(lead, DOWNGRADE_SOURCE_TIER, "x")
    assert lead.advice == _REVIEW, "按 base 算，不按快照算"


def test_consistency_check_covers_legacy_snapshot() -> None:
    """★一致性校验必须把迁移快照也算进锚点，否则旧数据上的直写永远查不出来。

    只按 ``base_advice`` 算的话，这条 lead（base 为 None）的期望值恒为空串、恒判一致——
    绕过 helper 把压着的档位偷偷放回最高档也照样「自洽」。
    """
    lead = Lead(category=LeadCategory.DOMAIN, value="api.example.com", advice=_INV)
    apply_downgrade(lead, DOWNGRADE_SNI_MASQUERADE, "x")
    assert lead.base_advice is None and lead.legacy_effective_advice == _INV
    assert advice_is_consistent(lead), "走完 helper 应当自洽"

    lead.advice = _INV  # 绕过 helper 直写：把压着的线索放回最高档
    assert not advice_is_consistent(lead), "带快照时的直写必须被算出来"


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


def test_new_fields_survive_real_disk_roundtrip(tmp_path) -> None:
    """★真实落盘往返：`write_report` 写文件 → `load_report` 读回来，不走内存 `_to_jsonable`。

    上一条用的是内存往返，绕过了「真正写进磁盘文件再解析回来」那一段。三个字段全靠
    `dataclasses.asdict` 自动落盘、靠 loader 手写的分支读回，两边任一处漏掉都只有真实
    文件往返才看得出来。
    """
    from apkscan.core.models import Report
    from apkscan.core.report_io import load_report, write_report

    old = Lead(category=LeadCategory.DOMAIN, value="old.example.com", advice=_INV)
    apply_downgrade(old, DOWNGRADE_SNI_MASQUERADE, "只在非标端口作 SNI 出现")

    fresh = _lead()
    apply_downgrade(fresh, DOWNGRADE_REPACK_IDENTITY, "样本判为正版重打包件")

    path = tmp_path / "report.json"
    write_report(
        Report(
            package_name="com.example.app",
            meta={}, leads=[old, fresh], endpoints=[], findings=[], analyzer_status=[],
        ),
        path,
        render_existing_html=False,
    )
    revived_old, revived_fresh = load_report(path).leads

    # 旧报告那条：快照真的进了文件、读得回来，且往返之后**仍然撤得掉**。
    assert revived_old.base_advice is None
    assert revived_old.legacy_effective_advice == _INV, "快照没落盘的话这里就是 None"
    assert revived_old.advice == _REVIEW
    assert lift_downgrade(revived_old, DOWNGRADE_SNI_MASQUERADE) is True, "往返后仍可撤销"
    assert revived_old.advice == _INV

    # 有判据结论那条：不该被盖上迁移快照——那是旧数据专用的。
    assert revived_fresh.base_advice == _INV
    assert revived_fresh.legacy_effective_advice is None
    assert revived_fresh.downgrades == {DOWNGRADE_REPACK_IDENTITY: "样本判为正版重打包件"}
    assert advice_is_consistent(revived_fresh)


#: 最高档加个尾随空格：这条**不是**非法值，loader 会 strip 后认出来。放进同一组参数里，是为了
#: 锁住「合法值不因为形态不规整而被误丢」——只锁非法值的话，一个过严的实现照样全绿。
_PADDED_VALID = _INV + " "


@pytest.mark.parametrize(
    "bad",
    [None, "", "   ", "查一下", _PADDED_VALID, 123, [], {}, {"a": 1}, True],
)
def test_illegal_legacy_snapshot_on_disk_is_dropped(bad: object) -> None:
    """★磁盘上的快照字段是非法值时按「不可考」处理，绝不回落成当前 advice。

    回落的话等于凭空给一条来路不明的数据发**恢复凭证**：撤光来源后它就凭这张凭证进了出口。
    """
    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com", "advice": _REVIEW,
        "legacy_effective_advice": bad,
        "downgrades": {DOWNGRADE_SNI_MASQUERADE: "x"},
    }]}
    revived = report_io.report_from_dict(payload).leads[0]

    expected = _INV if bad == _PADDED_VALID else None
    assert revived.legacy_effective_advice == expected
    if expected is None:
        assert lift_downgrade(revived, DOWNGRADE_SNI_MASQUERADE) is False, "无锚点必须拒绝撤销"


def test_both_anchors_on_disk_warns_and_keeps_snapshot(caplog) -> None:
    """★两个锚点并存（数据被手改）：出 warning、按 base 算档位、**快照原样留档**。

    loader 不销毁数据——留着才能让人事后核对这条是怎么变成这样的。
    """
    import logging

    from apkscan.core import report_io

    payload = {"leads": [{
        "category": "DOMAIN", "value": "api.example.com", "advice": _REVIEW,
        "base_advice": _SKIP, "legacy_effective_advice": _INV,
        "downgrades": {DOWNGRADE_SOURCE_TIER: "x"},
    }]}
    with caplog.at_level(logging.WARNING, logger="apkscan.core.report_io"):
        revived = report_io.report_from_dict(payload).leads[0]

    assert any("同时带 base_advice" in r.getMessage() for r in caplog.records), "并存必须留下 warning"
    assert revived.base_advice == _SKIP
    assert revived.legacy_effective_advice == _INV, "快照不得被丢弃"
    recompute_advice(revived)
    assert revived.advice == _SKIP, "按 base 算，最低档不因抑制来源被抬高"


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
