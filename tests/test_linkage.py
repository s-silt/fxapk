"""Deterministic, explainable corpus linkage baseline."""

from __future__ import annotations

import hashlib
import json

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus, linkage
from apkscan.core.linkage import collapse_manifest_entries, rank_link_candidates


_SIGN = "a" * 64
_NATIVE_A = "b" * 64
_NATIVE_B = "c" * 64
_CONFIG = "d" * 64


def _sample(label: str) -> str:
    if len(label) == 64:
        return label
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _entry(
    sample: str,
    *,
    cases: tuple[str, ...] = (),
    sign: object = None,
    native: object = None,
    builds: object = None,
    configs: object = None,
    iocs: object = None,
    findings: tuple[str, ...] = (),
    scope_indexed: bool = True,
    tool_version: str = "1.0.0",
    surface: str = "static",
    visibility: object = None,
    record_state: str | None = None,
    report_bytes_sha256: object = None,
    repack_verdict: object = "unknown",
) -> dict:
    entry = {
        "sample_sha256": _sample(sample),
        "sample_sha256_synthetic": False,
        "tool_version": tool_version,
        "ruleset_digest": "rules",
        "evidence_surface": surface,
        "case_ids": list(cases),
        "sign_sha256": sign,
        "native_lib_hashes": [] if native is None else native,
        "build_environments": [] if builds is None else builds,
        "remote_config_objects": [] if configs is None else configs,
        "key_iocs": [] if iocs is None else iocs,
        "finding_ids": list(findings),
        "case_ioc_scope_indexed": scope_indexed,
        "visibility": {} if visibility is None else visibility,
        "repack_identity_verdict": repack_verdict,
    }
    if record_state is not None:
        entry["record_state"] = record_state
    if report_bytes_sha256 is not None:
        entry["report_bytes_sha256"] = report_bytes_sha256
    return entry


def _native(sha: str, name: str = "libbusiness.so") -> dict:
    return {"name": name, "sha256": sha, "size": 123}


def _build(identifier: str = "build-root-1") -> dict:
    return {"identifier": identifier, "root": "/workspace/project"}


def test_collapses_revisions_without_self_pairs_and_is_order_independent() -> None:
    entries = [
        _entry("s1", native=[_native(_NATIVE_A)], builds=[_build()], tool_version="1.0"),
        _entry(
            "s1",
            native=[_native(_NATIVE_B)],
            builds=[_build()],
            tool_version="1.1",
            surface="unpacked",
        ),
        _entry("s2", native=[_native(_NATIVE_A), _native(_NATIVE_B)], builds=[_build()]),
    ]

    forward = rank_link_candidates(entries)
    backward = rank_link_candidates(list(reversed(entries)))

    assert forward == backward
    assert forward["input"]["record_count"] == 3
    assert forward["input"]["sample_count"] == 2
    assert forward["count"] == 1
    candidate = forward["candidates"][0]
    sides = {side["sample_sha256"]: side for side in (candidate["left"], candidate["right"])}
    assert sides[_sample("s1")]["revision_count"] == 2
    assert candidate["score"] == 82  # native family 52 + one build identifier 30


def test_result_contract_names_scores_versions_and_stable_candidate_identity() -> None:
    entries = [
        _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)], builds=[_build()]),
        _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)], builds=[_build()]),
    ]

    result = rank_link_candidates(entries, limit=None)
    candidate = result["candidates"][0]

    assert result["schema_version"] == "1.4"
    assert result["status"] == "complete"
    assert result["model"]["id"] == "fxapk-linkage-rules-v2"
    assert result["model"]["result_schema_version"] == "1.4"
    assert result["model"]["feature_schema_version"] == "1.3"
    assert result["model"]["normalization_version"] == "1.2"
    assert result["model"]["policy_status"] == "complete"
    assert result["model"]["policy_digest"] == (
        "c08ab9a3c742d2403e4642ca27131562ebbdf8dc704524f1be2ad75b692465f5"
    )
    assert candidate["candidate_id"].startswith("pair-")
    assert candidate["rank"] == 1
    assert candidate["review_priority_score"] == candidate["score"] == 100
    assert candidate["uncapped_score"] == 125
    assert candidate["raw_score"] == 100
    assert result == rank_link_candidates(list(reversed(entries)), limit=None)


def test_native_policy_load_failure_changes_digest_and_marks_result_partial(monkeypatch) -> None:
    monkeypatch.setattr(
        linkage,
        "native_anchor_policy_snapshot",
        lambda: {"version": "1.0", "status": "partial", "packer_so_names": []},
    )

    result = rank_link_candidates(
        [_entry("s1", builds=[_build()]), _entry("s2", builds=[_build()])]
    )

    assert result["status"] == "partial"
    assert result["model"]["policy_status"] == "partial"
    assert result["model"]["policy_digest"] != linkage.POLICY_DIGEST
    assert "policy inputs did not load" in result["candidate_generation"]["note"]


def test_single_anchor_level_is_named_as_review_not_strong_similarity() -> None:
    candidate = rank_link_candidates(
        [_entry("s1", native=[_native(_NATIVE_A)]), _entry("s2", native=[_native(_NATIVE_A)])]
    )["candidates"][0]

    assert candidate["review_priority_score"] == 50
    assert candidate["level"] == "single_anchor_review"


def test_invalid_sample_identity_is_excluded_and_marks_generation_partial() -> None:
    invalid = _entry("invalid")
    invalid["sample_sha256"] = "not-a-sha256"
    result = rank_link_candidates(
        [
            invalid,
            _entry("s1", builds=[_build()]),
            _entry("s2", builds=[_build()]),
        ]
    )

    assert result["status"] == "partial"
    assert result["input"]["invalid_sample_identity_record_count"] == 1
    assert result["input"]["sample_count"] == 2
    assert result["candidate_generation"]["generated_pair_count"] == 1


def test_legacy_manifest_without_repack_projection_requires_explicit_reindex() -> None:
    legacy = _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)])
    legacy.pop("repack_identity_verdict")
    result = rank_link_candidates(
        [legacy, _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)])]
    )

    assert result["status"] == "partial"
    assert result["input"]["legacy_repack_identity_record_count"] == 1
    assert result["migration"] == {
        "status": "required",
        "missing_manifest_fields": ["repack_identity_verdict"],
        "invalid_manifest_fields": [],
        "missing_record_count": 1,
        "invalid_record_count": 0,
        "legacy_record_count": 1,
        "next_action": (
            "fxapk corpus reindex --corpus <corpus-root>; if rows remain missing, invalid, "
            "or unassessed because legacy reports do not contain meta.repack_identity, "
            "re-analyze affected APKs with current fxapk (original APK required) to "
            "regenerate reports, then add/reindex them"
        ),
    }
    assert "corpus reindex" in result["candidate_generation"]["note"]
    assert "re-analyze" in result["candidate_generation"]["note"]


def test_invalid_repack_projection_is_counted_separately_and_fails_closed() -> None:
    missing = _entry("s1", sign=_SIGN)
    missing.pop("repack_identity_verdict")
    invalid = _entry("s2", sign=_SIGN, repack_verdict="future-verdict")

    result = rank_link_candidates([missing, invalid])

    assert result["status"] == "partial"
    assert result["input"]["missing_repack_identity_record_count"] == 1
    assert result["input"]["invalid_repack_identity_record_count"] == 1
    assert result["migration"]["status"] == "required"
    assert result["migration"]["missing_record_count"] == 1
    assert result["migration"]["invalid_record_count"] == 1
    assert result["migration"]["invalid_manifest_fields"] == [
        "repack_identity_verdict"
    ]
    assert "invalid repack_identity_verdict" in result["candidate_generation"]["note"]


def test_unhashable_repack_projection_is_invalid_instead_of_crashing() -> None:
    result = rank_link_candidates(
        [
            _entry("s1", sign=_SIGN, repack_verdict=["unknown"]),
            _entry("s2", sign=_SIGN),
        ]
    )

    assert result["status"] == "partial"
    assert result["input"]["invalid_repack_identity_record_count"] == 1


def test_synthetic_identity_uses_non_numeric_duplicate_relation() -> None:
    row = _entry("synthetic", cases=("case-a", "case-b"))
    row["sample_sha256"] = "nosha-0123456789abcdef"
    row["sample_sha256_synthetic"] = True

    link = rank_link_candidates([row])["same_sample_case_links"][0]

    assert link["relation"] == "possible_duplicate_report"
    assert "score" not in link


def test_synthetic_identities_never_enter_ordinary_pair_candidates() -> None:
    left = _entry("synthetic-left", native=[_native(_NATIVE_A)])
    left["sample_sha256"] = "nosha-0123456789abcdef"
    left["sample_sha256_synthetic"] = True
    right = _entry("synthetic-right", native=[_native(_NATIVE_A)])
    right["sample_sha256"] = "nosha-fedcba9876543210"
    right["sample_sha256_synthetic"] = True

    result = rank_link_candidates([left, right])

    assert result["candidates"] == []
    assert result["candidate_generation"]["generated_pair_count"] == 0
    assert result["input"]["real_sample_count"] == 0
    assert result["input"]["synthetic_sample_count"] == 2


def test_two_strong_families_rank_high_but_never_claim_same_operator() -> None:
    entries = [
        _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)]),
        _entry("s2", sign=_SIGN.upper(), native=[_native(_NATIVE_A)]),
    ]

    candidate = rank_link_candidates(entries)["candidates"][0]

    assert candidate["score"] == 95
    assert candidate["level"] == "multi_anchor_high_priority"
    assert candidate["strong_family_count"] == 2
    assert "不代表同一运营主体" in candidate["conclusion"]


def test_config_url_and_content_hash_share_one_family_cap() -> None:
    config = [{"url": "HTTPS://Config.Example/shared.dat", "sha256": _CONFIG}]
    result = rank_link_candidates([_entry("s1", configs=config), _entry("s2", configs=config)])
    candidate = result["candidates"][0]

    assert candidate["score"] == 60
    assert candidate["support_family_count"] == 1
    support = candidate["supporting_evidence"][0]
    assert support["family"] == "remote_config"
    assert support["match_count"] == 2
    assert support["weight"] == 60


def test_weak_native_and_ioc_cannot_generate_candidates_alone() -> None:
    weak = _native(_NATIVE_A, "libhermes.so")
    shared_ioc = ["https://api.example/shared"]
    entries = [
        _entry("s1", native=[weak], iocs=shared_ioc),
        _entry("s2", native=[weak], iocs=shared_ioc),
    ]

    assert rank_link_candidates(entries)["candidates"] == []


def test_weak_native_is_visible_but_adds_zero_when_another_anchor_generates_pair() -> None:
    weak = _native(_NATIVE_A, "libhermes.so")
    entries = [
        _entry("s1", native=[weak], builds=[_build()]),
        _entry("s2", native=[weak], builds=[_build()]),
    ]

    candidate = rank_link_candidates(entries)["candidates"][0]
    assert candidate["score"] == 30
    assert candidate["supporting_evidence"][0]["family"] == "build"
    assert candidate["excluded_evidence"] == [
        {
            "family": "native",
            "kind": "sha256",
            "value": _NATIVE_A,
            "weight": 0,
            "reason": "third-party-sdk",
        }
    ]


def test_config_url_echoed_in_iocs_scores_once_and_stays_visible() -> None:
    """★P1-1：同一 URL 既在 remote_config 又回声进 key_iocs，只许计一次分。

    修复前：回声把「仅 config」对从 40 分/1 家族抬到 52 分/2 家族（并把
    single_strong_family 封顶 69→89 解锁）、把「config+build」对从 70/2 抬到 82/3——
    同一份底层观测被数成了两个独立证据家族。
    """
    url = "https://config.example/app.json"
    config = [{"url": url}]

    plain = rank_link_candidates([_entry("s1", configs=config), _entry("s2", configs=config)])[
        "candidates"
    ][0]
    echoed = rank_link_candidates(
        [_entry("s1", configs=config, iocs=[url]), _entry("s2", configs=config, iocs=[url])]
    )["candidates"][0]

    assert (plain["score"], plain["support_family_count"]) == (40, 1)
    # 回声后必须与无回声同分同家族数；被剔除的回声在 excluded_evidence 里可见。
    assert (echoed["score"], echoed["support_family_count"]) == (40, 1)
    assert {
        "family": "ioc",
        "kind": "url",
        "value": url,
        "weight": 0,
        "reason": "remote-config-echo",
    } in echoed["excluded_evidence"]

    with_build = rank_link_candidates(
        [
            _entry("s1", configs=config, iocs=[url], builds=[_build()]),
            _entry("s2", configs=config, iocs=[url], builds=[_build()]),
        ]
    )["candidates"][0]
    assert (with_build["score"], with_build["support_family_count"]) == (70, 2)

    # 反向护栏：不是回声的 IOC（未被 config 家族命中）照常计分，不得被过度剔除。
    other = "https://other.example/beacon"
    independent = rank_link_candidates(
        [_entry("s1", configs=config, iocs=[other]), _entry("s2", configs=config, iocs=[other])]
    )["candidates"][0]
    assert (independent["score"], independent["support_family_count"]) == (52, 2)


def test_oversized_anchor_cluster_is_not_materialized_and_is_visible() -> None:
    """★P2-1：超大共享簇（如公用证书）不全量物化 C(k,2) 对，且截断显式可见。"""
    entries = [_entry(f"s{i:03d}", sign=_SIGN) for i in range(51)]
    entries.append(_entry("t1", native=[_native(_NATIVE_A)]))
    entries.append(_entry("t2", native=[_native(_NATIVE_A)]))

    result = rank_link_candidates(entries, limit=5000)

    # 51 > 50 的签名簇未展开：候选里只剩 native 那一对，而不是 C(51,2)=1275 + 1。
    assert result["total_before_limit"] == 1
    assert result["candidates"][0]["supporting_evidence"][0]["family"] == "native"
    assert len(result["truncated_anchors"]) == 1
    anchor = result["truncated_anchors"][0]
    assert anchor["kind"] == "sign_sha256"
    assert anchor["value"] == _SIGN
    assert anchor["sample_count"] == 51
    assert "未展开" in anchor["reason"]
    assert result["input"]["anchor_cluster_limit"] == 50
    assert result["status"] == "partial"
    assert result["candidate_generation"] == {
        "status": "partial",
        "generated_pair_count": 1,
        "overbroad_anchor_count": 1,
        "pair_budget_exhausted": False,
        "pair_budget_diagnostic": None,
        "note": "generated_pair_count excludes pairs reachable only through overbroad anchors",
    }

    # 阈值以内（恰好 50）照常展开——护栏只拦超限簇，不缩小既有覆盖。
    at_limit = rank_link_candidates(
        [_entry(f"s{i:03d}", sign=_SIGN) for i in range(50)], limit=5000
    )
    assert at_limit["truncated_anchors"] == []
    assert at_limit["status"] == "complete"
    assert at_limit["total_before_limit"] == 50 * 49 // 2


def test_global_candidate_pair_budget_fails_closed_without_leaking_anchor_values(
    monkeypatch,
) -> None:
    monkeypatch.setattr(linkage, "_MAX_CANDIDATE_PAIRS", 2)
    result = rank_link_candidates(
        [
            _entry("s1", native=[_native(_NATIVE_A)]),
            _entry("s2", native=[_native(_NATIVE_A)]),
            _entry("s3", native=[_native(_NATIVE_A)]),
        ],
        limit=None,
    )

    assert result["status"] == "partial"
    assert result["total_before_limit"] == 2
    assert result["input"]["candidate_pair_budget"] == 2
    assert result["candidate_generation"]["pair_budget_exhausted"] is True
    diagnostic = result["candidate_generation"]["pair_budget_diagnostic"]
    assert diagnostic == {
        "limit": 2,
        "reason": "global candidate pair budget exhausted",
    }
    assert _NATIVE_A not in json.dumps(diagnostic)


def test_debug_certificate_sign_anchor_is_demoted_but_visible() -> None:
    """★P2-2：公知调试/测试证书（debug-certificate finding）零分排除但保持可见。"""
    # 两侧都标记：仅共享 debug 证书不足以生成候选（与弱 native 同款语义）。
    both_flagged = [
        _entry("s1", sign=_SIGN, findings=("debug-certificate",)),
        _entry("s2", sign=_SIGN, findings=("debug-certificate",)),
    ]
    assert rank_link_candidates(both_flagged)["candidates"] == []

    # 有其它锚生成候选时：签名零分、excluded_evidence 可见；★任一侧标记即降档
    # （证书是同一颗，另一侧只是没跑过该规则——名字/标记是否齐全不该改变证书的公知性）。
    entries = [
        _entry("s1", sign=_SIGN, findings=("debug-certificate",), builds=[_build()]),
        _entry("s2", sign=_SIGN, builds=[_build()]),
    ]
    candidate = rank_link_candidates(entries)["candidates"][0]
    assert candidate["score"] == 30
    assert [row["family"] for row in candidate["supporting_evidence"]] == ["build"]
    assert {
        "family": "signing",
        "kind": "certificate_sha256",
        "value": _SIGN,
        "weight": 0,
        "reason": "debug-certificate",
    } in candidate["excluded_evidence"]

    # 对照：未被标记的共享签名仍是 45 分强锚——降档只凭正向标记，缺失不作反证。
    control = rank_link_candidates(
        [_entry("s1", sign=_SIGN, builds=[_build()]), _entry("s2", sign=_SIGN, builds=[_build()])]
    )["candidates"][0]
    assert control["score"] == 75


def test_weak_name_one_side_strong_name_other_side_native_is_excluded_not_silent() -> None:
    """★P2-3：同一 .so 一侧弱名一侧强名——不计分是对的，但必须进 excluded_evidence。

    .so 文件名是对手可控的：改个名就能让共享组件从输出里凭空消失，违反「标注而非删除」。
    """
    entries = [
        _entry("s1", native=[_native(_NATIVE_A, "libhermes.so")], builds=[_build()]),
        _entry("s2", native=[_native(_NATIVE_A, "libbusiness.so")], builds=[_build()]),
    ]
    candidate = rank_link_candidates(entries)["candidates"][0]
    assert candidate["score"] == 30  # 只有 build 计分：任一侧弱即弱
    assert candidate["excluded_evidence"] == [
        {
            "family": "native",
            "kind": "sha256",
            "value": _NATIVE_A,
            "weight": 0,
            "reason": "third-party-sdk",
        }
    ]


def test_same_native_sha_under_three_basenames_is_renamed_component_not_anchor() -> None:
    """同一字节组件被至少三次改名时降为弱锚；共享事实仍在排除证据中可见。"""
    entries = [
        _entry(
            "s1",
            native=[_native(_NATIVE_A, "lib/arm64-v8a/libalpha.so")],
            builds=[_build()],
        ),
        _entry(
            "s2",
            native=[_native(_NATIVE_A, "lib/arm64-v8a/libbravo.so")],
            builds=[_build()],
        ),
        _entry("s3", native=[_native(_NATIVE_A, "lib/arm64-v8a/libcharlie.so")]),
    ]

    result = rank_link_candidates(entries)

    # native 不再生成 s1-s3 / s2-s3；唯一候选由 s1-s2 的 build 锚生成。
    assert result["total_before_limit"] == 1
    candidate = result["candidates"][0]
    assert candidate["score"] == 30
    assert [row["family"] for row in candidate["supporting_evidence"]] == ["build"]
    assert candidate["excluded_evidence"] == [
        {
            "family": "native",
            "kind": "sha256",
            "value": _NATIVE_A,
            "weight": 0,
            "reason": "renamed-shared-component",
        }
    ]


def test_three_native_aliases_from_one_sample_do_not_demote_other_samples() -> None:
    """改名降权要求跨三个真实样本存在一对一的不同 basename 匹配。"""
    entries = [
        _entry("s1", native=[_native(_NATIVE_A, "libalpha.so")], surface="static"),
        _entry("s1", native=[_native(_NATIVE_A, "libbravo.so")], surface="unpacked"),
        _entry("s1", native=[_native(_NATIVE_A, "libcharlie.so")], surface="runtime"),
        _entry("s2", native=[_native(_NATIVE_A, "libalpha.so")]),
    ]

    candidate = rank_link_candidates(entries)["candidates"][0]

    assert candidate["review_priority_score"] == 50
    assert candidate["supporting_evidence"][0]["family"] == "native"
    assert candidate["excluded_evidence"] == []


def test_rename_detection_requires_a_distinct_sample_to_basename_matching() -> None:
    entries = [
        _entry(
            "s1",
            native=[
                _native(_NATIVE_A, "libalpha.so"),
                _native(_NATIVE_A, "libbravo.so"),
                _native(_NATIVE_A, "libcharlie.so"),
            ],
        ),
        _entry("s2", native=[_native(_NATIVE_A, "libalpha.so")]),
        _entry("s3", native=[_native(_NATIVE_A, "libalpha.so")]),
    ]

    result = rank_link_candidates(entries, limit=None)

    assert result["total_before_limit"] == 3
    assert all(
        candidate["supporting_evidence"][0]["family"] == "native"
        for candidate in result["candidates"]
    )


def test_synthetic_sample_does_not_count_toward_native_rename_matching() -> None:
    synthetic = _entry("synthetic", native=[_native(_NATIVE_A, "libcharlie.so")])
    synthetic["sample_sha256"] = "nosha-0123456789abcdef"
    synthetic["sample_sha256_synthetic"] = True
    result = rank_link_candidates(
        [
            _entry("s1", native=[_native(_NATIVE_A, "libalpha.so")]),
            _entry("s2", native=[_native(_NATIVE_A, "libbravo.so")]),
            synthetic,
        ]
    )

    assert result["total_before_limit"] == 1
    assert result["candidates"][0]["review_priority_score"] == 50


def test_preprocessing_context_can_be_fitted_once_and_reused_on_a_subset() -> None:
    entries = [
        _entry("s1", native=[_native(_NATIVE_A, "libalpha.so")], builds=[_build()]),
        _entry("s2", native=[_native(_NATIVE_A, "libbravo.so")], builds=[_build()]),
        _entry("s3", native=[_native(_NATIVE_A, "libcharlie.so")]),
    ]
    context = linkage.fit_linkage_preprocessing_context(entries)

    frozen = rank_link_candidates(entries[:2], preprocessing_context=context)
    default = rank_link_candidates(entries[:2])
    collapsed = {
        sample.sample_sha256: sample
        for sample in collapse_manifest_entries(
            entries[:2], preprocessing_context=context
        )
    }

    assert frozen["candidates"][0]["review_priority_score"] == 30
    assert frozen["candidates"][0]["excluded_evidence"][0]["reason"] == (
        "renamed-shared-component"
    )
    assert default["candidates"][0]["review_priority_score"] == 80
    assert dict(collapsed[_sample("s1")].weak_native)[_NATIVE_A] == (
        "renamed-shared-component"
    )


def test_same_native_sha_under_two_basenames_remains_a_strong_anchor() -> None:
    """形态阈值以下不降权；仅共享两个不同名字不能证明随机改名分发。"""
    result = rank_link_candidates(
        [
            _entry("s1", native=[_native(_NATIVE_A, "lib/arm64-v8a/libalpha.so")]),
            _entry("s2", native=[_native(_NATIVE_A, "lib/x86/libbravo.so")]),
        ]
    )

    assert result["total_before_limit"] == 1
    candidate = result["candidates"][0]
    assert candidate["score"] == 50
    [support] = candidate["supporting_evidence"]
    assert {
        key: support[key]
        for key in ("family", "strength", "weight", "match_count")
    } == {
        "family": "native",
        "strength": "strong",
        "weight": 50,
        "match_count": 1,
    }
    assert support["matches"][0]["kind"] == "sha256"
    assert support["matches"][0]["value"] == _NATIVE_A
    assert candidate["excluded_evidence"] == []


def test_unsupported_scheme_config_url_does_not_poison_unrelated_anchors() -> None:
    """★P3-1：oss:// 等不支持的 scheme 是「未参与匹配」，不是畸形数据，不触发 79 封顶。"""
    oss = [{"url": "oss://bucket.example/config.dat"}]
    entries = [
        _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)], configs=oss),
        _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)]),
    ]
    candidate = rank_link_candidates(entries)["candidates"][0]
    assert candidate["score"] == 95
    assert candidate["score_caps"] == []
    features = {row.sample_sha256: row for row in collapse_manifest_entries(entries)}
    # 观测到了（observed）但不产生锚——「未参与匹配」不等于「没观测」或「畸形」。
    assert features[_sample("s1")].coverage_dict()["remote_config_objects"] == "observed"
    assert features[_sample("s1")].config_urls == ()

    # 真畸形（http 却连主机都没有）仍 fail-closed 封顶——三态不塌缩。
    malformed = [{"url": "http://"}]
    poisoned = rank_link_candidates(
        [
            _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)], configs=malformed),
            _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)]),
        ]
    )["candidates"][0]
    assert poisoned["score"] == 79
    assert any(cap["code"] == "invalid_feature_fields" for cap in poisoned["score_caps"])


def test_url_trailing_dot_and_empty_path_normalize_to_same_anchor() -> None:
    """★P3-2：主机尾点（FQDN 根点）与空路径都要归一，否则同一端点裂成两个锚。"""
    dotted = rank_link_candidates(
        [
            _entry("s1", configs=[{"url": "https://config.example./app.json"}]),
            _entry("s2", configs=[{"url": "https://config.example/app.json"}]),
        ]
    )
    assert dotted["candidates"][0]["score"] == 40

    rooted = rank_link_candidates(
        [
            _entry("s1", configs=[{"url": "https://config.example"}]),
            _entry("s2", configs=[{"url": "https://config.example/"}]),
        ]
    )
    assert rooted["candidates"][0]["score"] == 40


def test_whitespace_only_case_filter_is_rejected() -> None:
    """★P3-4：纯空白 case 过滤是输入错误，不得静默退化成无过滤。"""
    with pytest.raises(ValueError, match="whitespace"):
        rank_link_candidates([_entry("s1")], case_id="   ")


def test_visibility_shape_never_caps_linkage_score() -> None:
    """★P3-5：visibility 不是关联特征，形状畸形不得触发 invalid_feature_fields 封顶。"""
    entries = [
        _entry("s1", sign=_SIGN, native=[_native(_NATIVE_A)], visibility="oops"),
        _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)]),
    ]
    candidate = rank_link_candidates(entries)["candidates"][0]
    assert candidate["score"] == 95
    assert candidate["score_caps"] == []
    # 但 coverage / coverage_gaps 仍如实标 invalid_only——不压分不等于吞信息。
    features = {row.sample_sha256: row for row in collapse_manifest_entries(entries)}
    assert features[_sample("s1")].coverage_dict()["visibility"] == "invalid_only"
    assert {
        "sample_sha256": _sample("s1"),
        "field": "visibility",
        "status": "invalid_only",
    } in candidate["coverage_gaps"]


def test_missing_empty_and_invalid_are_distinct_and_fail_closed() -> None:
    malformed = _entry("s1", sign={"bad": "shape"}, builds=[_build()], scope_indexed=False)
    malformed.pop("visibility")
    empty = _entry("s2", builds=[_build()])

    features = {row.sample_sha256: row for row in collapse_manifest_entries([malformed, empty])}
    coverage = features[_sample("s1")].coverage_dict()
    assert coverage["sign_sha256"] == "invalid_only"
    assert coverage["native_lib_hashes"] == "assessed_empty"
    assert coverage["remote_config_objects"] == "unknown"
    assert coverage["key_iocs"] == "unknown"
    assert coverage["visibility"] == "unknown"

    candidate = rank_link_candidates([malformed, empty])["candidates"][0]
    assert any(cap["code"] == "invalid_feature_fields" for cap in candidate["score_caps"])
    assert {gap["status"] for gap in candidate["coverage_gaps"]} == {
        "invalid_only",
        "unknown",
    }


def test_observed_with_invalid_siblings_is_distinct_and_keeps_valid_anchor() -> None:
    mixed = _entry("s1", native=[_native(_NATIVE_A), {"sha256": "bad"}])
    clean = _entry("s2", native=[_native(_NATIVE_A)])

    features = {row.sample_sha256: row for row in collapse_manifest_entries([mixed, clean])}
    assert (
        features[_sample("s1")].coverage_dict()["native_lib_hashes"]
        == "observed_with_invalid_siblings"
    )
    candidate = rank_link_candidates([mixed, clean])["candidates"][0]
    assert candidate["supporting_evidence"][0]["family"] == "native"
    assert any(
        gap["status"] == "observed_with_invalid_siblings"
        for gap in candidate["coverage_gaps"]
    )


def test_repack_suspected_survives_missing_revision_and_caps_high_priority() -> None:
    left_flagged = _entry("s1", sign=_SIGN, repack_verdict="repack_suspected")
    left_missing = _entry("s1", native=[_native(_NATIVE_A)], tool_version="1.1")
    right = _entry("s2", sign=_SIGN, native=[_native(_NATIVE_A)])

    candidate = rank_link_candidates([left_missing, right, left_flagged])["candidates"][0]

    assert candidate["uncapped_score"] == 95
    assert candidate["review_priority_score"] == 69
    assert candidate["ownership_unresolved"] is True
    assert candidate["level"] == "ownership_unresolved_review"
    assert any(cap["code"] == "repack_suspected" for cap in candidate["score_caps"])
    sides = {side["sample_sha256"]: side for side in (candidate["left"], candidate["right"])}
    assert sides[_sample("s1")]["ownership_unresolved"] is True


def test_quarantined_revision_marks_candidate_and_preserves_bilateral_provenance() -> None:
    left = _entry(
        "s1",
        sign=_SIGN,
        native=[_native(_NATIVE_A)],
        record_state="quarantined",
        report_bytes_sha256="1" * 64,
    )
    right = _entry(
        "s2",
        sign=_SIGN,
        native=[_native(_NATIVE_A)],
        record_state="active",
        report_bytes_sha256="2" * 64,
    )

    result = rank_link_candidates([right, left])
    candidate = result["candidates"][0]

    assert candidate["uncapped_score"] == 95
    assert candidate["review_priority_score"] == 69
    assert candidate["non_authoritative_input"] is True
    assert candidate["level"] == "non_authoritative_review"
    assert any(
        cap["code"] == "non_authoritative_input" for cap in candidate["score_caps"]
    )
    assert result["input"]["non_authoritative_sample_count"] == 1
    support = candidate["supporting_evidence"][0]
    s1_side = "left" if candidate["left"]["sample_sha256"] == _sample("s1") else "right"
    s2_side = "right" if s1_side == "left" else "left"
    assert support["provenance"][s1_side][0] == {
        "tool_version": "1.0.0",
        "ruleset_digest": "rules",
        "evidence_surface": "static",
        "record_state": "quarantined",
        "report_bytes_sha256": "1" * 64,
    }
    assert support["provenance"][s2_side][0]["record_state"] == "active"
    assert support["matches"][0]["provenance"] == support["provenance"]
    assert result == rank_link_candidates([left, right])


def test_missing_revision_provenance_is_explicit_and_safe() -> None:
    candidate = rank_link_candidates(
        [_entry("s1", native=[_native(_NATIVE_A)]), _entry("s2", native=[_native(_NATIVE_A)])]
    )["candidates"][0]

    revision = candidate["left"]["revisions"][0]
    assert revision["record_state"] == "unknown"
    assert revision["report_bytes_sha256"] is None


def test_same_sample_multiple_cases_is_reported_without_self_pair() -> None:
    result = rank_link_candidates(
        [_entry("same", cases=("case-b", "case-a"), native=[_native(_NATIVE_A)])]
    )

    assert result["candidates"] == []
    assert result["same_sample_case_links"] == [
        {
            "sample_sha256": _sample("same"),
            "case_ids": ["case-a", "case-b"],
            "relation": "exact_artifact_identity",
            "synthetic_identity": False,
            "ownership_unresolved": False,
            "non_authoritative_input": False,
            "conclusion": "同一 APK 样本 SHA-256 跨案件出现",
        }
    ]


def test_broad_shared_anchor_only_pair_is_demoted_with_distribution_facts() -> None:
    """★#20：全部支撑锚都是「跨案在互不相关样本群间流转」的广域件 → 降入低优先档。

    模拟公共第三方 SDK 栈：同一 .so + 同一内嵌构建路径被 5 个互不相关（无共享签名/
    配置）样本跨 5 案共享。证据照常展示计分（标注而非删除），cap 携带分布事实。
    """
    entries = [
        _entry(
            f"s{i}",
            cases=(f"case-{i}",),
            native=[_native(_NATIVE_A)],
            builds=[_build("sdk-embedded-root")],
        )
        for i in range(1, 6)
    ]

    result = rank_link_candidates(entries, limit=None)
    assert result["total_before_limit"] == 10
    candidate = result["candidates"][0]

    assert candidate["uncapped_score"] == 80  # native 50 + build 30，权重未被削
    assert candidate["review_priority_score"] == 49
    assert candidate["level"] == "review"
    caps = {cap["code"]: cap for cap in candidate["score_caps"]}
    # 广域 build 佐证不解锁 69→89。
    assert caps["single_strong_family"]["cap"] == 69
    broad = caps["broad_shared_anchor_only"]
    assert broad["cap"] == 49
    assert broad["anchors"] == [
        {
            "family": "native",
            "kind": "sha256",
            "value": _NATIVE_A,
            "sample_count": 5,
            "case_count": 5,
            "unrelated_group_count": 5,
        },
        {
            "family": "build",
            "kind": "environment_identifier",
            "value": "sdk-embedded-root",
            "sample_count": 5,
            "case_count": 5,
            "unrelated_group_count": 5,
        },
    ]
    # 证据本身完整可见：native/build 两个支撑家族、家族计数不变。
    assert candidate["support_family_count"] == 2
    assert candidate["strong_family_count"] == 1


def test_broad_anchor_needs_unrelated_groups_not_share_count() -> None:
    """★#20 与「绝不用统计阈值」的边界：判据是簇内**互不相关群数**，不是共享样本数。

    同一 .so 被 6 样本跨 6 案共享：若其中 4 个成员由共享签名证书连成一群（同族核心库
    形态），互不相关群数=3 < 4 → 不降档；抹掉该主体关联后（公共组件形态）→ 降档。
    共享频次两边完全相同——按频次判的实现会让本测试两臂同红或同绿。
    """

    def _corpus(family_cert: object) -> list[dict]:
        rows = []
        for i in range(1, 7):
            sign = family_cert if i <= 4 else None
            rows.append(
                _entry(f"s{i}", cases=(f"case-{i}",), sign=sign, native=[_native(_NATIVE_A)])
            )
        return rows

    def _pair(result: dict, left: str, right: str) -> dict:
        wanted = {_sample(left), _sample(right)}
        for row in result["candidates"]:
            if {row["left"]["sample_sha256"], row["right"]["sample_sha256"]} == wanted:
                return row
        raise AssertionError("pair not generated")

    coherent = _pair(rank_link_candidates(_corpus(_SIGN), limit=None), "s5", "s6")
    assert coherent["review_priority_score"] == 50
    assert all(cap["code"] != "broad_shared_anchor_only" for cap in coherent["score_caps"])

    scattered = _pair(rank_link_candidates(_corpus(None), limit=None), "s5", "s6")
    assert scattered["review_priority_score"] == 49
    assert any(cap["code"] == "broad_shared_anchor_only" for cap in scattered["score_caps"])


def test_broad_build_does_not_corroborate_but_narrow_build_still_does() -> None:
    """★#20：广域构建标识（商用 SDK 内嵌路径形态）不解锁 single_strong 69→89；
    非广域构建标识照常佐证——防止把佐证机制整个误删。"""

    def _corpus(spread: int) -> list[dict]:
        rows = [
            _entry(
                f"s{i}",
                cases=(f"case-{i}",),
                builds=[_build("sdk-root")],
                native=[_native(_NATIVE_B)] if i <= 2 else None,
            )
            for i in range(1, spread + 1)
        ]
        return rows

    def _native_pair(result: dict) -> dict:
        for row in result["candidates"]:
            if row["strong_family_count"] == 1 and row["support_family_count"] == 2:
                return row
        raise AssertionError("native+build pair not generated")

    broad_build = _native_pair(rank_link_candidates(_corpus(6), limit=None))
    assert broad_build["uncapped_score"] == 80
    assert broad_build["review_priority_score"] == 69
    caps = {cap["code"]: cap["cap"] for cap in broad_build["score_caps"]}
    assert caps["single_strong_family"] == 69
    assert "broad_shared_anchor_only" not in caps  # native 匹配非广域 → 不降档

    narrow_build = _native_pair(rank_link_candidates(_corpus(3), limit=None))
    assert narrow_build["uncapped_score"] == 80
    assert narrow_build["review_priority_score"] == 80
    narrow_caps = {cap["code"]: cap["cap"] for cap in narrow_build["score_caps"]}
    assert narrow_caps["single_strong_family"] == 89


def test_any_nonbroad_anchor_exempts_pair_from_broad_cap() -> None:
    """★#20：任一非广域锚（共享 IOC / 非广域 .so）豁免广域降档——降档只打
    「除公共件外一无所有」的对。"""
    base = [
        _entry(f"s{i}", cases=(f"case-{i}",), native=[_native(_NATIVE_A)])
        for i in range(3, 8)
    ]

    with_ioc = [
        _entry("s1", cases=("case-1",), native=[_native(_NATIVE_A)], iocs=["https://api.example/shared"]),
        _entry("s2", cases=("case-2",), native=[_native(_NATIVE_A)], iocs=["https://api.example/shared"]),
        *base,
    ]
    result = rank_link_candidates(with_ioc, limit=None)
    top = result["candidates"][0]
    assert top["support_family_count"] == 2  # native + ioc
    assert top["review_priority_score"] == 62
    assert all(cap["code"] != "broad_shared_anchor_only" for cap in top["score_caps"])

    with_private_native = [
        _entry("s1", cases=("case-1",), native=[_native(_NATIVE_A), _native(_NATIVE_B)]),
        _entry("s2", cases=("case-2",), native=[_native(_NATIVE_A), _native(_NATIVE_B)]),
        *base,
    ]
    result = rank_link_candidates(with_private_native, limit=None)
    top = result["candidates"][0]
    assert top["supporting_evidence"][0]["match_count"] == 2
    assert top["review_priority_score"] == 52
    assert all(cap["code"] != "broad_shared_anchor_only" for cap in top["score_caps"])


def _report(sample: str, build_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "analysis_status": "complete",
        "completeness": 1.0,
        "package_name": "com.example.fixture",
        "meta": {
            "sample_sha256": _sample(sample),
            "tool_version": "1.6.1",
            "ruleset_digest": "rules",
            "build_provenance": {
                "self_hosted": [
                    {"identifier": build_id, "root": "/workspace/project", "count": 3}
                ]
            },
        },
        "leads": [],
        "endpoints": [],
        "findings": [],
    }


def test_cli_case_filter_limit_and_unredacted_warning(tmp_path) -> None:
    corpus_dir = tmp_path / "corpus"
    for sample, case in (("s1", "alpha"), ("s2", "beta"), ("s3", "gamma")):
        report = _report(sample, "shared-build")
        raw = json.dumps(report)
        added = corpus.add_report(corpus_dir, report, raw, case_id=case)
        assert added["added"] is True

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "corpus",
            "link-candidates",
            "--case",
            "alpha",
            "--limit",
            "1",
            "--corpus",
            str(corpus_dir),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "不做脱敏" in result.stderr
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["total_before_limit"] == 2
    candidate = payload["candidates"][0]
    assert "alpha" in candidate["left"]["case_ids"] + candidate["right"]["case_ids"]

    absent = runner.invoke(
        cli.app,
        ["corpus", "link-candidates", "--case", "absent", "--corpus", str(corpus_dir)],
    )
    assert absent.exit_code == 0
    assert json.loads(absent.stdout)["count"] == 0

    invalid_limit = runner.invoke(
        cli.app,
        ["corpus", "link-candidates", "--limit", "0", "--corpus", str(corpus_dir)],
    )
    assert invalid_limit.exit_code == 2

    # ★P3-4：纯空白 --case 在 CLI 层被当参数错误拒绝（exit 2），不静默退化成无过滤。
    blank_case = runner.invoke(
        cli.app,
        ["corpus", "link-candidates", "--case", "   ", "--corpus", str(corpus_dir)],
    )
    assert blank_case.exit_code == 2


def test_cli_link_candidates_surfaces_broad_shared_anchor_cap(tmp_path) -> None:
    """★#20 接线锁（真入口）：广域共享锚降档与分布事实必须从 CLI 层输出可见。

    4 个互不相关样本跨 4 案共享同一 .so + 同一构建标识——恰好踩在 ≥4 阈值边界上，
    同时锁「≥ 而非 >」的边界语义。
    """
    corpus_dir = tmp_path / "corpus"
    for i in range(1, 5):
        report = _report(f"b{i}", "sdk-embedded-root")
        report["meta"]["native_lib_hashes"] = [
            {"name": "libbusiness.so", "sha256": _NATIVE_A, "size": 123}
        ]
        corpus.add_report(corpus_dir, report, json.dumps(report), case_id=f"case-{i}")

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["corpus", "link-candidates", "--limit", "50", "--corpus", str(corpus_dir)],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["count"] == 6
    top = payload["candidates"][0]
    assert top["review_priority_score"] == 49
    caps = {cap["code"]: cap for cap in top["score_caps"]}
    broad = caps["broad_shared_anchor_only"]
    assert broad["cap"] == 49
    assert {
        (a["family"], a["sample_count"], a["case_count"], a["unrelated_group_count"])
        for a in broad["anchors"]
    } == {("native", 4, 4, 4), ("build", 4, 4, 4)}
