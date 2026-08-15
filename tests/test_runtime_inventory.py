"""运行时回灌清单（``core.runtime_inventory``）的 schema、迁移、以及**接线**。

清单曾经整块没有任何生产消费方：写方与测试之外零个读者。于是「只走 pcap/probe 回灌」的报告
在闭环里 ``business_candidate_count=0`` → 动态判 **failed**，而报告里明明有已观测的业务候选端点。
本套测试因此分三层：

1. schema 与迁移（键改名不丢历史、丢弃的键不得偷偷回来）；
2. 派生消费方 ``derive_capture_quality`` 的口径（尤其**上限 partial**、绝不抬成 complete）；
3. 端到端接线（``evaluate_closure`` 真读到了它）。

零真实数据：IP 全取 RFC 5737/3849 文档保留段与合成公网段，域名全用 ``.test``。
"""

from __future__ import annotations

import pytest

from apkscan.core import runtime_inventory as inv
from apkscan.core.closure import (
    CLOSURE_COMPLETE,
    CLOSURE_FAILED,
    CLOSURE_PARTIAL,
    assemble_target_closure,
    evaluate_capture_quality,
    evaluate_closure,
)
from apkscan.core.models import Confidence, Endpoint, Evidence, Lead, LeadCategory, Report


# ---------------------------------------------------------------------------
# 1. schema 与迁移
# ---------------------------------------------------------------------------


def test_every_field_names_its_reader() -> None:
    """★本模块的准入条件：填不出「谁读它」的字段不该存在。

    清单整块无人读正是这条规则缺位的后果。字段表里留空 reader 就等于把那段历史再走一遍。
    """
    assert inv.INVENTORY_FIELDS, "字段表不能为空"
    for field in inv.INVENTORY_FIELDS:
        assert field.reader.strip(), f"{field.name} 没写清楚谁读它"


def test_dropped_fields_state_a_reason_and_do_not_come_back() -> None:
    """★删字段与加字段一样要留痕：旧报告里真有这些键，读到时按表跳过。"""
    assert inv.DROPPED_FIELDS, "丢弃表不能为空（flows_merged 就是被丢弃的）"
    live = {f.name for f in inv.INVENTORY_FIELDS}
    aliases = {a for f in inv.INVENTORY_FIELDS for a in f.aliases}
    for name, reason in inv.DROPPED_FIELDS.items():
        assert reason.strip(), f"{name} 没写丢弃理由"
        assert name not in live, f"{name} 已声明丢弃却又出现在字段表里"
        assert name not in aliases, f"{name} 已声明丢弃却又被当作别名迁移"


def test_dropped_field_is_not_rebuilt_from_an_old_report() -> None:
    """旧报告带着 ``flows_merged`` 也不得让它回到新清单里（否则等于没删）。"""
    meta = {inv.INVENTORY_META_KEY: {"flows_merged": 9, "flows": 7, "remote_endpoints": 3}}
    built = inv.build_inventory(
        meta, source="pcap", endpoint_values=[], domain_values=[], parse_status="ok")
    assert "flows_merged" not in built and "flows" not in built
    assert built["remote_endpoints"] == 3, "该迁移的历史计数反而丢了"


@pytest.mark.parametrize("field", [f for f in inv.INVENTORY_FIELDS if f.aliases])
def test_every_aliased_field_migrates_exhaustively(field: inv._Field) -> None:
    """★穷尽迁移：**按表驱动**逐个别名验证，而不是只验证撞见的那一个键。

    同一个元错误犯过三次——改名时只给撞见的键写迁移、漏掉结构相同的兄弟。参数化到字段表上，
    将来给某个键加了别名却忘了迁移，这条会直接变红。按 ``kind`` 分派：计数键迁数值，
    列表键（``sources``）迁的是「旧名里那个来源不能丢」。
    """
    for alias in field.aliases:
        if field.kind == "list":
            meta = {inv.INVENTORY_META_KEY: {alias: "pcap"}}
            built = inv.build_inventory(
                meta, source="probe", endpoint_values=[], domain_values=[], parse_status="ok")
            assert built[field.name] == ["pcap", "probe"], f"{field.name} 丢了旧名 {alias} 的来源"
        else:
            meta = {inv.INVENTORY_META_KEY: {alias: 5}}
            built = inv.build_inventory(
                meta, source="pcap", endpoint_values=[], domain_values=[], parse_status="ok")
            assert built[field.name] == 5, f"{field.name} 没从旧名 {alias} 迁移过来"
        assert alias not in built, f"旧名 {alias} 没被清掉，两套形状会长期并存"


def test_inventory_key_itself_migrates_from_the_old_name() -> None:
    """清单**自己**的键名也改过（``runtime_pcap_inventory`` → 新名），同样要迁移。"""
    for alias in inv.INVENTORY_META_ALIASES:
        assert inv.read_inventory({alias: {"remote_endpoints": 4}})["remote_endpoints"] == 4
    # 新旧键并存时取新键，绝不合并（合并会让迁移期的报告双计）
    both = inv.read_inventory({
        inv.INVENTORY_META_KEY: {"remote_endpoints": 1},
        inv.INVENTORY_META_ALIASES[0]: {"remote_endpoints": 9},
    })
    assert both["remote_endpoints"] == 1


def test_parse_failure_history_survives_a_missing_new_key() -> None:
    """旧报告只有 ``parse_status``、没有后加的 ``parse_degraded`` → 降级历史不得被抹掉。"""
    meta = {inv.INVENTORY_META_KEY: {"parse_status": "parse_error"}}
    built = inv.build_inventory(
        meta, source="pcap", endpoint_values=[], domain_values=[], parse_status="ok")
    assert built["parse_status"] == "ok", "最近一次确实成功"
    assert built["parse_degraded"] is True, "曾经解析失败被后一次成功抹掉了"


def test_counts_are_a_union_across_paths_not_a_sum() -> None:
    """★两条回灌路径并进同一份报告：计数取**并集**。

    只算自己那本账会漏报；把两本账相加又会把两条路径都观测到的同一个端点算两遍。

    注意调用约定：``build_inventory`` 只把**贡献集合**写回 ``meta``，清单本身是返回值，
    要由调用方自己落到 ``meta[INVENTORY_META_KEY]``——不落回去，下一次合并就读不到 prev。
    """
    meta: dict = {}
    meta[inv.INVENTORY_META_KEY] = inv.build_inventory(
        meta, source="pcap", endpoint_values=["198.51.100.7"],
        domain_values=["a.example.test"], parse_status="ok")
    built = inv.build_inventory(meta, source="probe",
                               endpoint_values=["198.51.100.7", "198.51.100.8"],
                               domain_values=["a.example.test"], parse_status="ok")
    assert built["remote_endpoints"] == 2, "重叠的那个端点被算了两遍或漏了新端点"
    assert built["domain_leads"] == 1, "两条路径观测到同一个域名，应算一个"
    assert built["sources"] == ["pcap", "probe"], "来源要累计，不能被后一条覆盖"


def test_source_list_migrates_from_the_old_scalar() -> None:
    """旧报告写的是标量 ``source``——迁成列表，且不得丢掉原来那个名字。"""
    meta = {inv.INVENTORY_META_KEY: {"source": "pcap"}}
    built = inv.build_inventory(
        meta, source="probe", endpoint_values=[], domain_values=[], parse_status="ok")
    assert built["sources"] == ["pcap", "probe"]


def test_build_never_raises_on_garbage() -> None:
    """坏类型/负数/bool 一律归 0，绝不抛（取证工具不能因为一份坏报告整条链断掉）。"""
    meta = {inv.INVENTORY_META_KEY: {
        "remote_endpoints": -5, "domain_leads": True, "parse_degraded": "yes",
        "sources": "not-a-list",
    }}
    built = inv.build_inventory(
        meta, source="pcap", endpoint_values=[], domain_values=[], parse_status="ok")
    assert built["remote_endpoints"] == 0 and built["domain_leads"] == 0
    assert built["sources"] == ["pcap"]
    assert inv.read_inventory({inv.INVENTORY_META_KEY: "not-a-dict"}) == {}


# ---------------------------------------------------------------------------
# 2. 派生消费方的口径
# ---------------------------------------------------------------------------


def test_derive_is_empty_only_when_the_inventory_is_absent() -> None:
    """★「没有清单」与「清单存在但计数为 0」必须区分开。

    闭环用 ``bool(_capture_meta(report))`` 决定「这份报告是否需要动态证据」：

    - 清单**缺失** → 必须返回空 dict，否则每一份纯静态报告都会突然被要求动态证据、进而判 failed；
    - 清单**存在但全 0** → 必须返回非空 dict。回灌确实跑过、只是什么都没并进来，
      这时判 failed 是如实结论；返回空 dict 会把它伪装成「压根没跑动态」而豁免掉。
    """
    assert inv.derive_capture_quality({}) == {}
    ran_but_empty = inv.derive_capture_quality({"remote_endpoints": 0, "domain_leads": 0})
    assert ran_but_empty, "回灌跑过却没并进东西，不能装作没跑过"
    assert evaluate_capture_quality(ran_but_empty)["dynamic_status"] == CLOSURE_FAILED


def test_derive_caps_at_partial_even_when_uid_attribution_is_claimed() -> None:
    """★★上限 partial：回灌路径拿不到双向载荷证据，所以永远够不到 complete。

    天花板在于：派生一律**不补** ``bidirectional_*``，而门控只在同一端点上既归因又双向时
    才判 complete，缺失按 0 处理（fail-closed）。所以这里断言的是「不补双向字段」+
    「结论止于 partial」。

    ★``uid_attributed=True`` 只说明**做过归因**，说明不了**几个属目标**——归因数取
      清单里真实的 ``target_attributed``。这条曾写成 ``endpoints if uid_attributed else 0``，
      即拿端点总数顶替，实测会把 33 个接入节点（其中 32 个是背景噪音）全报成已归因。
      没有那本账的输入按 fail-closed 记 0：宁可停在 partial，不虚报"已确认属目标"。
    """
    derived = inv.derive_capture_quality({"remote_endpoints": 3, "uid_attributed": True})
    assert derived["target_attributed_count"] == 0, (
        "做过归因但没有归目标的账 → 不知道几个属目标，不得拿端点总数顶替")
    assert derived["business_candidate_count"] == 3, "端点总数仍要如实报"
    # 双向载荷字段一律不补：缺失按 0 处理是既定的 fail-closed 语义，也正是 partial 的来源
    assert "bidirectional_target_count" not in derived
    assert "bidirectional_business_count" not in derived
    assert "bidirectional_floor_count" not in derived
    assert evaluate_capture_quality(derived)["dynamic_status"] == CLOSURE_PARTIAL


def test_attributed_count_never_borrows_the_endpoint_total() -> None:
    """★把「几个属目标」与「一共几个端点」钉死为两件事。

    3 个端点、只有 1 个归到目标 → 计数必须是 1。写成端点总数就是把无关第三方的
    接入节点计成"目标 app 已确认通信"，那是这套工具最不能犯的错。
    """
    derived = inv.derive_capture_quality(
        {"remote_endpoints": 3, "uid_attributed": True, "target_attributed": 1})
    assert derived["target_attributed_count"] == 1
    assert derived["business_candidate_count"] == 3
    assert evaluate_capture_quality(derived)["dynamic_status"] == CLOSURE_PARTIAL


def test_derive_carries_parse_degradation_into_the_gate() -> None:
    """解析降级过 → ``floor_parse_status`` 不得报 ok（空结果≠零流量，提示重抓而非结案）。"""
    derived = inv.derive_capture_quality(
        {"remote_endpoints": 0, "parse_status": "ok", "parse_degraded": True})
    assert derived["floor_parse_status"] != "ok"
    quality = evaluate_capture_quality(derived)
    assert quality["dynamic_status"] == CLOSURE_FAILED
    assert "parse failed" in str(quality["reason"]), "要说明是采集/解析失败，而不是真零流量"


def test_derive_keeps_domain_only_observation_visible() -> None:
    """只观测到域名、没有可达端点：结论仍是 failed，但域名数要看得见。

    否则「观测到域名但无可达端点」与「压根没流量」在读报告时长得一模一样。
    """
    derived = inv.derive_capture_quality({"remote_endpoints": 0, "domain_leads": 2})
    assert derived["runtime_domain_lead_count"] == 2
    assert evaluate_capture_quality(derived)["dynamic_status"] == CLOSURE_FAILED


# ---------------------------------------------------------------------------
# 3. 端到端接线
# ---------------------------------------------------------------------------


def _pcap_only_report(**inventory: object) -> Report:
    """一份「静态报告 + 只走回灌」的报告：有 runtime_merged 与清单，**没有** capture_quality。"""
    ep = Endpoint(
        value="cfg.example.test",
        kind="domain",
        evidences=[Evidence(source="runtime-pcap", location="pcap", snippet="合成")],
        is_suspicious=True,
    )
    payload: dict = {"remote_endpoints": 1, "domain_leads": 1, "parse_status": "ok",
                     "parse_degraded": False, "uid_attributed": False, "sources": ["pcap"]}
    payload.update(inventory)
    return Report(
        package_name="com.example.synthetic",
        meta={"runtime_merged": True, inv.INVENTORY_META_KEY: payload},
        leads=[Lead(category=LeadCategory.DOMAIN, value=ep.value, confidence=Confidence.HIGH,
                    source_refs=list(ep.evidences), advice="待核")],
        endpoints=[ep],
        findings=[],
        analyzer_status=[{"name": "manifest", "status": "ran"}],
    )


def _dynamic_check(closure: dict) -> dict:
    return next(c for c in closure["checks"] if c["id"] == "dynamic_evidence")


def _closure(report: Report) -> dict:
    """按真实调用形状求闭环：``targets`` 必须非空。

    ★为什么不能图省事传 ``[]``：空 targets 自身就会 ``fatal=True``（"no investigation target
      selected"），于是整份闭环恒为 failed，「动态这一维有没有把闭环拖下水」这个断言就永远
      测不出来——绿或红都与被测改动无关。
    """
    return evaluate_closure(
        report, [assemble_target_closure(report.endpoints[0])], require_dynamic=None
    )


def test_reingested_report_is_partial_not_failed() -> None:
    """★B-2a 的核心：只走回灌的报告，动态结论应是 partial（做不了唯一归因），不是 failed。

    此前 ``_capture_meta`` 从不读清单 → ``business_candidate_count=0`` → 动态判 failed，
    而 failed 会置 ``fatal=True``，把**整个闭环**从 partial 拖成 failed。
    """
    closure = _closure(_pcap_only_report())

    check = _dynamic_check(closure)
    assert check["status"] == "warn", "回灌报告被判成了动态失败"
    assert "attribution" in str(check["reason"]), "reason 应是「无唯一归因」而不是解析失败"
    assert "parse failed" not in str(check["reason"])
    # 动态这一维不再是致命项：闭环因五层未闭合停在 partial，而不是被动态拖成 failed。
    assert closure["status"] == CLOSURE_PARTIAL


def test_reingested_report_cannot_reach_complete() -> None:
    """★同一条路上的负面断言：回灌**永远**上不了 complete，哪怕清单自称已归因。

    ``uid_attributed=True`` 确实会让派生值给出 ``target_attributed_count>0``；上限来自
    派生**从不补** ``bidirectional_*``（缺失按 0 → fail-closed）。所以这里断言的是不变量
    本身「上不了 complete」，而不是某个中间字段必须为 0。
    """
    report = _pcap_only_report(uid_attributed=True, remote_endpoints=9)
    closure = _closure(report)
    assert _dynamic_check(closure)["status"] != "pass"
    assert closure["status"] != CLOSURE_COMPLETE


def test_real_capture_quality_wins_over_the_derived_one() -> None:
    """顺序不能反：真采集的统计口径更完整，有它就不该被回灌的派生值覆盖。"""
    report = _pcap_only_report(remote_endpoints=1)
    report.meta["capture_quality"] = {
        "channel_ready": True, "pcap_valid": True, "packet_count": 12,
        "business_candidate_count": 7, "target_attributed_count": 1,
        "bidirectional_target_count": 1,
    }
    closure = _closure(report)
    assert _dynamic_check(closure)["status"] == "pass", "真采集的 complete 被回灌派生值压掉了"


def test_static_only_report_does_not_suddenly_require_dynamic_evidence() -> None:
    """★★接线的反向风险：纯静态报告不得因为这次改动突然要求动态证据。

    ``dynamic_required`` 取 ``bool(runtime_merged or _capture_meta(report))``；派生函数对
    「没有清单」的报告若返回非空 dict，全仓每份静态报告都会被要求动态证据、然后判 failed。
    """
    report = _pcap_only_report()
    report.meta.clear()
    closure = _closure(report)
    check = _dynamic_check(closure)
    assert check["status"] == "not_applicable"
    # 更要紧的是它没被判 fail：动态维一旦 fail 就是致命项，会把整份闭环拖成 failed。
    assert check["status"] != "fail"


# ---------------------------------------------------------------------------
# UID 归因：按来源记账，不得被后并入的无归因路径擦除（Codex 复核 #2）
# ---------------------------------------------------------------------------


def _merge(meta: dict, source: str, *, uid: bool, endpoints: list[str],
           attributed: list[str] | None = None) -> dict:
    """按真实调用约定合并一次：清单是返回值，必须由调用方落回 meta。

    ``attributed``：本次真正归到目标 app 的端点值（``uid_attributed`` 只说明"做过归因"，
    说明不了"几个属目标"，两者必须分开传）。
    """
    built = inv.build_inventory(
        meta, source=source, endpoint_values=endpoints, domain_values=[],
        parse_status="ok", uid_attributed=uid,
        target_attributed_values=attributed or [])
    meta[inv.INVENTORY_META_KEY] = built
    return built


@pytest.mark.parametrize("order", [("pcap", "probe"), ("probe", "pcap")])
def test_uid_attribution_is_order_independent(order: tuple[str, str]) -> None:
    """★两条路径并进同一份报告，「能否归到目标进程」不得取决于合并顺序。

    此前后并入的无归因来源会把前一次的 ``uid_attributed=True`` 覆盖成 False，
    于是闭环质量取决于 pcap / probe 谁先跑——同一份证据两种结论。
    """
    attributed, plain = order[0], order[1]
    meta: dict = {}
    _merge(meta, attributed, uid=True, endpoints=["198.51.100.7"])
    built = _merge(meta, plain, uid=False, endpoints=["198.51.100.8"])
    assert built["uid_attributed"] is True, (
        f"{plain} 无归因合并把 {attributed} 的 UID 归因擦掉了")


def test_uid_attribution_never_erased_by_repeated_unattributed_merges() -> None:
    """单调性：反复并入无归因来源也不得把结论翻回 False。"""
    meta: dict = {}
    _merge(meta, "pcap", uid=True, endpoints=["198.51.100.7"])
    for _ in range(3):
        built = _merge(meta, "probe", uid=False, endpoints=["198.51.100.8"])
        assert built["uid_attributed"] is True


def test_uid_attribution_stays_false_when_no_source_ever_attributed() -> None:
    """★反向不变量：没有任何来源带来归因时**绝不**凭空抬成 True。

    这条守的是 ``target_attributed_count`` 恒 0 / 闭环上限 partial 那条纪律。
    """
    meta: dict = {}
    _merge(meta, "pcap", uid=False, endpoints=["198.51.100.7"])
    built = _merge(meta, "probe", uid=False, endpoints=["198.51.100.8"])
    assert built["uid_attributed"] is False


def test_uid_attribution_migrates_from_legacy_inventory_without_source_ledger() -> None:
    """旧报告只有布尔、没有来源记账键 → 历史归因不得在下次合并时静默清零。"""
    meta: dict = {inv.INVENTORY_META_KEY: {"uid_attributed": True, "sources": ["pcap"]}}
    built = _merge(meta, "probe", uid=False, endpoints=["198.51.100.8"])
    assert built["uid_attributed"] is True, "旧报告的归因结论被丢了"


def test_uid_source_ledger_survives_garbage() -> None:
    """坏类型的记账键不得让合并抛（取证工具不能因一份坏报告断链）。"""
    meta: dict = {inv.UID_ATTRIBUTED_SOURCES_KEY: "not-a-list"}
    built = _merge(meta, "pcap", uid=True, endpoints=[])
    assert built["uid_attributed"] is True
    assert isinstance(meta[inv.UID_ATTRIBUTED_SOURCES_KEY], list)


def test_derived_attributed_count_survives_a_later_unattributed_merge() -> None:
    """接线复核：先并入的归因结论，不得被后并入的无归因路径擦掉。

    ★与 ``uid_attributed`` 那本来源账同理：归目标的端点值也按路径分记、取并集，
      所以 pcap（有归因）→ probe（无归因）与反序结果一致，不取决于合并顺序。
    """
    meta: dict = {}
    _merge(meta, "pcap", uid=True, endpoints=["198.51.100.7"],
           attributed=["198.51.100.7"])
    built = _merge(meta, "probe", uid=False, endpoints=["198.51.100.7"])
    derived = inv.derive_capture_quality(built)
    assert built["target_attributed"] == 1, "归因结论被后一次无归因合并擦掉了"
    assert derived["target_attributed_count"] == 1


def test_attributed_values_are_a_union_not_a_sum() -> None:
    """同一个端点被两条路径都归因 → 算 1 个，不是 2 个。"""
    meta: dict = {}
    _merge(meta, "pcap", uid=True, endpoints=["198.51.100.7"], attributed=["198.51.100.7"])
    built = _merge(meta, "probe", uid=True, endpoints=["198.51.100.7"],
                   attributed=["198.51.100.7"])
    assert built["target_attributed"] == 1
