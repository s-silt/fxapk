"""P1-D ownership projection：无 baseline 恒 UNKNOWN、匹配才 INHERITED_OFFICIAL、
改动绝不标 suspect、ledger 只对匹配产观察。

先于实现编写（红态契约；导入 apkscan.core.jadx_ownership 在实现落地前收集即失败）。
设计见本地 docs/superpowers/specs/2026-08-16-p1d-ownership-projection-design.md（不入 git）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apkscan.core import judgment_ledger as jl
from apkscan.core import recognition_contract as rc
from apkscan.core.jadx_index import (
    DexInput,
    DexRole,
    IndexBuildResult,
    IndexBuildState,
    JadxIndexError,
    JadxIndexManifest,
    JadxIndexStore,
    Limits,
    LoadedIndex,
    build_key_material,
    derive_index_key,
    scan_java_sources,
    verify_dex_inputs,
)
from apkscan.core.jadx_index_ledger import (
    IndexQueryState,
    OwnershipQueryResult,
    append_jadx_ownership_projection,
    append_jadx_query_projection,
)
from apkscan.core.jadx_ownership import (
    OwnershipProjection,
    RegionOwnership,
    project_ownership,
)
from tests.recognition_fixtures import (
    FIXED_TIME,
    append_record,
    make_action_ledger,
    make_actor,
    make_authorization,
)

_OPTS = "sha256:" + "a" * 64

#: P1-D 的硬边界：任何路径都不得产出这三个值。
_FORBIDDEN = {
    rc.OwnershipValue.SUSPECT_FIRST_PARTY,
    rc.OwnershipValue.INHERITED_THIRD_PARTY,
    rc.OwnershipValue.SHARED_INFRASTRUCTURE,
}


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _java_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _build_index(
    tmp_path: Path,
    tag: str,
    files: dict[str, str],
    *,
    limits: Limits | None = None,
) -> LoadedIndex:
    base = tmp_path / tag
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    payload = f"dex-{tag}".encode()
    (src / "classes.dex").write_bytes(payload)
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest=_digest(payload),
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    manifest = JadxIndexManifest(
        index_key=derive_index_key(lineage, "1.5.2", _OPTS),
        key_material=build_key_material(lineage, "1.5.2", _OPTS),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=_OPTS,
    )
    out = base / "out"
    _java_tree(out, files)
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=limits or Limits())
    store = JadxIndexStore(base / "cache")
    result = store.build_index(src, manifest, scan=scan)
    assert isinstance(result, IndexBuildResult) and result.state == IndexBuildState.BUILT
    loaded = store.load_index(manifest.index_key)
    assert isinstance(loaded, LoadedIndex)
    return loaded


APP_JAVA = (
    "package com.a;\n"
    "\n"
    "public class App {\n"
    "    void boot() {\n"
    "        x = 1;\n"
    "    }\n"
    "\n"
    "    void tick() {\n"
    "        y = 2;\n"
    "    }\n"
    "}\n"
)

LIB_JAVA = "package com.b;\n\npublic class Lib {\n    void util() {\n    }\n}\n"


# ---------------------------------------------------------------------------
# 投影语义
# ---------------------------------------------------------------------------


def test_no_baseline_all_unknown(tmp_path: Path) -> None:
    """★缺官方 baseline → 一切 UNKNOWN，reason=no_official_baseline，不可下否定性结论。"""
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, None)
    assert isinstance(projection, OwnershipProjection)
    assert projection.subject_index_key == subject.manifest.index_key
    assert projection.baseline_index_key is None
    assert projection.baseline_coverage is None
    assert projection.absence_claimable is False
    assert len(projection.regions) == 2
    for item in projection.regions:
        assert isinstance(item, RegionOwnership)
        assert item.ownership is rc.OwnershipValue.UNKNOWN
        assert item.reason == "no_official_baseline"


def test_duplicate_names_align_by_path_against_baseline(tmp_path: Path) -> None:
    """★混淆锁（schema 1.2）：同名类按 (name, path) 对齐 baseline——同路径同 digest
    的那份 INHERITED_OFFICIAL，baseline 没有的那份 absent_from_baseline，
    绝不因同名互相污染（旧身份下 subject 侧直接 fail-closed，索引不可用）。"""
    shared = "class a {\n    void run() {\n        x = 1;\n    }\n}\n"
    extra = "class a {\n    void run() {\n        y = 1;\n    }\n}\n"
    subject = _build_index(tmp_path, "s", {"p000/a.java": shared, "p001/a.java": extra})
    baseline = _build_index(tmp_path, "b", {"p000/a.java": shared})
    projection = project_ownership(subject, baseline)
    assert len(projection.regions) == 2
    by_path = {item.region.path: item for item in projection.regions}
    assert by_path["p000/a.java"].ownership is rc.OwnershipValue.INHERITED_OFFICIAL
    assert by_path["p000/a.java"].reason == "matches_official_baseline"
    assert by_path["p001/a.java"].ownership is rc.OwnershipValue.UNKNOWN
    assert by_path["p001/a.java"].reason == "absent_from_baseline"


def test_full_match_inherited_official(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA, "com/b/Lib.java": LIB_JAVA})
    baseline = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA, "com/b/Lib.java": LIB_JAVA})
    projection = project_ownership(subject, baseline)
    assert projection.baseline_index_key == baseline.manifest.index_key
    assert projection.absence_claimable is True
    assert len(projection.regions) == 3
    for item in projection.regions:
        assert item.ownership is rc.OwnershipValue.INHERITED_OFFICIAL
        assert item.reason == "matches_official_baseline"


def test_modified_region_unknown_never_suspect(tmp_path: Path) -> None:
    """★与 baseline 不同 → UNKNOWN + modified_relative_to_baseline，绝不标 suspect。"""
    modified = APP_JAVA.replace("x = 1;", "x = 9;")
    subject = _build_index(tmp_path, "s", {"com/a/App.java": modified})
    baseline = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, baseline)

    by_method = {item.region.method: item for item in projection.regions}
    assert by_method["boot/0"].ownership is rc.OwnershipValue.UNKNOWN
    assert by_method["boot/0"].reason == "modified_relative_to_baseline"
    assert by_method["tick/0"].ownership is rc.OwnershipValue.INHERITED_OFFICIAL

    # 硬边界：全集绝无另外三个枚举值。
    assert not {item.ownership for item in projection.regions} & _FORBIDDEN


def test_absent_reason_depends_on_coverage(tmp_path: Path) -> None:
    """baseline 未观察到：双侧 complete → absent_from_baseline；partial → 归因覆盖缺口。"""
    extra = APP_JAVA.replace(
        "    void tick() {",
        "    void fresh() {\n        z = 3;\n    }\n\n    void tick() {",
    )
    subject = _build_index(tmp_path, "s", {"com/a/App.java": extra})
    baseline_full = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, baseline_full)
    assert projection.absence_claimable is True
    by_method = {item.region.method: item for item in projection.regions}
    assert by_method["fresh/0"].ownership is rc.OwnershipValue.UNKNOWN
    assert by_method["fresh/0"].reason == "absent_from_baseline"

    baseline_partial = _build_index(
        tmp_path,
        "bp",
        {"com/a/App.java": APP_JAVA, "com/b/Lib.java": LIB_JAVA},
        limits=Limits(max_files=1),
    )
    assert baseline_partial.coverage == "partial"
    projection2 = project_ownership(subject, baseline_partial)
    assert projection2.absence_claimable is False
    by_method2 = {item.region.method: item for item in projection2.regions}
    assert by_method2["fresh/0"].ownership is rc.OwnershipValue.UNKNOWN
    assert by_method2["fresh/0"].reason == "baseline_coverage_partial"


def test_projection_sorted_and_shard_order_independent(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA, "com/b/Lib.java": LIB_JAVA})
    baseline = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, baseline)
    keys = [
        (i.region.class_name, i.region.method, i.region.path, i.region.start_line)
        for i in projection.regions
    ]
    assert keys == sorted(keys)

    reversed_subject = LoadedIndex(
        manifest=subject.manifest,
        shard_locators=tuple(reversed(subject.shard_locators)),
        coverage=subject.coverage,
        shards=tuple(reversed(subject.shards)),
    )
    assert project_ownership(reversed_subject, baseline) == projection


def test_malformed_subject_fail_closed(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/b/Lib.java": LIB_JAVA})
    bad_shard = dict(subject.shards[0])
    bad_shard["structure"] = {"classes": [{"name": "com.x.Bad"}]}
    forged = LoadedIndex(
        manifest=subject.manifest,
        shard_locators=subject.shard_locators,
        coverage=subject.coverage,
        shards=(bad_shard,),
    )
    with pytest.raises(JadxIndexError) as exc:
        project_ownership(forged, None)
    assert exc.value.code == "malformed"


# ---------------------------------------------------------------------------
# ledger 投影
# ---------------------------------------------------------------------------


def _authorized_ledger(action_type: str) -> tuple[tuple[jl.LedgerEvent, ...], str]:
    events = make_action_ledger(action_type=action_type)
    action = events[-1].payload
    assert isinstance(action, rc.NextAction)
    events = append_record(
        events,
        jl.EventType.ACTION_AUTHORIZED,
        make_authorization(action_id=action.action_id),
    )
    return events, action.action_id


def _observation_count(events: tuple[jl.LedgerEvent, ...]) -> int:
    return sum(1 for e in events if e.event_type is jl.EventType.OBSERVATION_ADDED)


def _result(
    projection: OwnershipProjection,
    *,
    state: IndexQueryState = IndexQueryState.HIT,
    coverage: str | None = "complete",
    baseline_digest: str | None = "sha256:" + "c" * 64,
) -> OwnershipQueryResult:
    return OwnershipQueryResult(
        state=state,
        coverage=coverage,
        projection=projection,
        manifest_digest="sha256:" + "a" * 64,
        baseline_manifest_digest=baseline_digest,
        shard_digests=("sha256:" + "b" * 64,),
        reason_codes=("test",),
    )


def test_ownership_hit_projects_matches_only(tmp_path: Path) -> None:
    """★只有 INHERITED_OFFICIAL 匹配产观察；UNKNOWN 区域零观察。"""
    modified = APP_JAVA.replace("x = 1;", "x = 9;")
    subject = _build_index(tmp_path, "s", {"com/a/App.java": modified})
    baseline = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, baseline)
    matches = [
        item
        for item in projection.regions
        if item.ownership is rc.OwnershipValue.INHERITED_OFFICIAL
    ]
    assert len(matches) == 1  # tick 匹配、boot 改动

    events, action_id = _authorized_ledger("jadx-ownership-projection")
    before = _observation_count(events)
    out = append_jadx_ownership_projection(
        events,
        action_id=action_id,
        result=_result(projection),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    ledger_view = jl.replay(out)
    assert _observation_count(out) == before + 1
    (obs,) = [
        o for o in ledger_view.observations if o.observation_type == "jadx_ownership_match"
    ]
    assert obs.ownership is rc.OwnershipValue.INHERITED_OFFICIAL
    assert obs.strength is rc.ObservationStrength.OBSERVED
    match_region = matches[0].region
    (locator,) = obs.source_refs
    assert locator.kind is rc.LocatorKind.LINE_RANGE
    assert locator.value == match_region.path
    assert locator.start == match_region.start_line and locator.end == match_region.end_line
    categorical = obs.value.categorical
    assert categorical == match_region.body_digest.replace(":", ".", 1)
    # baseline manifest 锚在 anchors 里（可追溯 baseline 选择）。
    outcome = ledger_view.outcomes[-1]
    assert len(outcome.output_anchors) == 3  # subject manifest + baseline + 1 shard


def test_ownership_no_baseline_zero_observations(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, None)
    events, action_id = _authorized_ledger("jadx-ownership-projection")
    before = _observation_count(events)
    out = append_jadx_ownership_projection(
        events,
        action_id=action_id,
        result=_result(projection, baseline_digest=None),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before
    assert jl.replay(out).outcomes[-1].status is rc.OutcomeStatus.COMPLETE


def test_ownership_negative_state_zero_observations(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA})
    baseline = _build_index(tmp_path, "b", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, baseline)
    events, action_id = _authorized_ledger("jadx-ownership-projection")
    before = _observation_count(events)
    out = append_jadx_ownership_projection(
        events,
        action_id=action_id,
        result=_result(projection, state=IndexQueryState.FAILED, coverage=None),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before
    assert jl.replay(out).outcomes[-1].status is rc.OutcomeStatus.FAILED


def test_ownership_wrong_action_type_both_directions(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/a/App.java": APP_JAVA})
    projection = project_ownership(subject, None)

    usage_events, usage_action = _authorized_ledger("jadx-usage-query")
    with pytest.raises(JadxIndexError) as exc:
        append_jadx_ownership_projection(
            usage_events,
            action_id=usage_action,
            result=_result(projection, baseline_digest=None),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "wrong_action_type"

    own_events, own_action = _authorized_ledger("jadx-ownership-projection")
    from apkscan.core.jadx_index_ledger import IndexQueryResult

    with pytest.raises(JadxIndexError) as exc:
        append_jadx_query_projection(
            own_events,
            action_id=own_action,
            result=IndexQueryResult(state=IndexQueryState.HIT, coverage="complete", hits=()),
            actor=make_actor(),
            occurred_at=FIXED_TIME,
        )
    assert exc.value.code == "wrong_action_type"


def test_ownership_query_result_validates_projection() -> None:
    with pytest.raises(JadxIndexError) as exc:
        OwnershipQueryResult(
            state=IndexQueryState.HIT,
            coverage="complete",
            projection="not-a-projection",  # type: ignore[arg-type]
        )
    assert exc.value.code == "invalid_query_projection"


# ---------------------------------------------------------------------------
# codex 复审补锁：重复声明数量差异、TIMEOUT_PARTIAL 语义、malformed baseline
# ---------------------------------------------------------------------------

DUP_DECL = (
    "package com.u;\n"
    "\n"
    "public class U {\n"
    "    void go(int x) {\n"
    "        k = 1;\n"
    "    }\n"
    "\n"
    "    void go(int x) {\n"
    "        k = 1;\n"
    "    }\n"
    "}\n"
)

SINGLE_DECL = (
    "package com.u;\n"
    "\n"
    "public class U {\n"
    "    void go(int x) {\n"
    "        k = 1;\n"
    "    }\n"
    "}\n"
)


def test_declaration_count_mismatch_is_modified_not_match(tmp_path: Path) -> None:
    """★[A,A] vs [A] 与 [A] vs [A,A]：digest 相同但声明数不同 → 多重集不等 → UNKNOWN。"""
    subject_aa = _build_index(tmp_path, "saa", {"com/u/U.java": DUP_DECL})
    baseline_a = _build_index(tmp_path, "ba", {"com/u/U.java": SINGLE_DECL})
    projection = project_ownership(subject_aa, baseline_a)
    assert len(projection.regions) == 2
    for item in projection.regions:
        assert item.ownership is rc.OwnershipValue.UNKNOWN
        assert item.reason == "modified_relative_to_baseline"

    subject_a = _build_index(tmp_path, "sa", {"com/u/U.java": SINGLE_DECL})
    baseline_aa = _build_index(tmp_path, "baa", {"com/u/U.java": DUP_DECL})
    projection2 = project_ownership(subject_a, baseline_aa)
    (only,) = projection2.regions
    assert only.ownership is rc.OwnershipValue.UNKNOWN
    assert only.reason == "modified_relative_to_baseline"


def test_matched_identity_emits_one_observation_per_region(tmp_path: Path) -> None:
    """匹配身份有 N 个声明 → N 条观察（每个区域可独立定位）。"""
    subject = _build_index(tmp_path, "s", {"com/u/U.java": DUP_DECL})
    baseline = _build_index(tmp_path, "b", {"com/u/U.java": DUP_DECL})
    projection = project_ownership(subject, baseline)
    matches = [
        i for i in projection.regions if i.ownership is rc.OwnershipValue.INHERITED_OFFICIAL
    ]
    assert len(matches) == 2

    events, action_id = _authorized_ledger("jadx-ownership-projection")
    before = _observation_count(events)
    out = append_jadx_ownership_projection(
        events,
        action_id=action_id,
        result=_result(projection),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before + 2
    spans = {
        (o.source_refs[0].start, o.source_refs[0].end)
        for o in jl.replay(out).observations
        if o.observation_type == "jadx_ownership_match"
    }
    assert len(spans) == 2  # 两个区域各自定位


def test_timeout_partial_still_projects_qualified_matches(tmp_path: Path) -> None:
    """★语义锁定：TIMEOUT_PARTIAL 属阳性态——匹配观察照产，但 coverage 断言
    同时落 TIMEOUT 限定（观察被限定，而非被夸大）。与 usage/callpath 一致。"""
    subject = _build_index(tmp_path, "s", {"com/u/U.java": SINGLE_DECL})
    baseline = _build_index(tmp_path, "b", {"com/u/U.java": SINGLE_DECL})
    projection = project_ownership(subject, baseline)
    events, action_id = _authorized_ledger("jadx-ownership-projection")
    before = _observation_count(events)
    out = append_jadx_ownership_projection(
        events,
        action_id=action_id,
        result=_result(projection, state=IndexQueryState.TIMEOUT_PARTIAL, coverage="partial"),
        actor=make_actor(),
        occurred_at=FIXED_TIME,
    )
    assert _observation_count(out) == before + 1
    outcome = jl.replay(out).outcomes[-1]
    assert outcome.status is rc.OutcomeStatus.PARTIAL
    assert outcome.coverage_assertions[0].status is rc.CoverageStatus.TIMEOUT


def test_malformed_baseline_fail_closed(tmp_path: Path) -> None:
    subject = _build_index(tmp_path, "s", {"com/u/U.java": SINGLE_DECL})
    baseline = _build_index(tmp_path, "b", {"com/u/U.java": SINGLE_DECL})
    bad_shard = dict(baseline.shards[0])
    bad_shard["structure"] = {"classes": [{"name": "com.x.Bad"}]}
    forged = LoadedIndex(
        manifest=baseline.manifest,
        shard_locators=baseline.shard_locators,
        coverage=baseline.coverage,
        shards=(bad_shard,),
    )
    with pytest.raises(JadxIndexError) as exc:
        project_ownership(subject, forged)
    assert exc.value.code == "malformed"
