"""Offline equivalence regressions for bounded-cost pure data processing."""
from __future__ import annotations

from dataclasses import fields
from itertools import combinations
import random

from apkscan.core.linkage import SampleFeatures, _broad_shared_anchors
from apkscan.core.linkage_review import _components
from apkscan.core.textutil import strip_url_tail


def _sample(number: int, **changes) -> SampleFeatures:
    values = {field.name: () for field in fields(SampleFeatures)}
    values.update(
        sample_sha256=f"{number:064x}", synthetic_identity=False,
        ownership_unresolved=False, non_authoritative_input=False,
        case_ids=(f"synthetic-case-{number}",),
    )
    values.update(changes)
    return SampleFeatures(**values)


def _reference_broad(samples: tuple[SampleFeatures, ...]) -> dict:
    """Small quadratic oracle, independent of the production inverted index."""
    buckets = {}
    for sample in samples:
        if sample.synthetic_identity:
            continue
        for family, values in (("native", sample.native_sha256),
                               ("build", sample.build_environments)):
            for value in values:
                buckets.setdefault((family, value), []).append(sample)
    result = {}
    for key, members in buckets.items():
        remaining = set(range(len(members)))
        groups = 0
        while remaining:
            groups += 1
            pending = [remaining.pop()]
            while pending:
                left = members[pending.pop()]
                related = {
                    index for index in remaining
                    if set(left.sign_sha256).intersection(members[index].sign_sha256)
                    or (set(left.config_sha256) | set(left.config_urls)).intersection(
                        set(members[index].config_sha256) | set(members[index].config_urls)
                    )
                }
                remaining.difference_update(related)
                pending.extend(related)
        cases = {case for sample in members for case in sample.case_ids}
        if groups >= 4 and len(cases) >= 4:
            result[key] = {"sample_count": len(members), "case_count": len(cases),
                           "unrelated_group_count": groups}
    return result


def test_broad_anchor_index_matches_pairwise_oracle() -> None:
    rng = random.Random(731)
    for _ in range(150):
        samples = tuple(
            _sample(
                number,
                synthetic_identity=rng.random() < 0.1,
                native_sha256=tuple(value for value in ("n1", "n2") if rng.random() < .8),
                build_environments=tuple(value for value in ("b1", "b2") if rng.random() < .6),
                sign_sha256=tuple(value for value in ("x", "y", "z") if rng.random() < .15),
                config_sha256=tuple(value for value in ("x", "y") if rng.random() < .1),
                config_urls=tuple(value for value in ("z", "w") if rng.random() < .1),
                case_ids=(f"synthetic-case-{rng.randrange(8)}",),
            ) for number in range(18)
        )
        assert _broad_shared_anchors(samples) == _reference_broad(samples)
        assert _broad_shared_anchors(tuple(reversed(samples))) == _reference_broad(samples)


def test_signing_and_configuration_namespaces_do_not_join() -> None:
    samples = tuple(_sample(i, native_sha256=("shared",),
                            sign_sha256=("same-token",) if i == 0 else (),
                            config_sha256=("same-token",) if i == 1 else ())
                    for i in range(4))
    assert _broad_shared_anchors(samples)[("native", "shared")]["unrelated_group_count"] == 4


def test_shared_key_transitive_chain_and_large_unrelated_bucket() -> None:
    samples = tuple(_sample(i, native_sha256=("shared",),
                            sign_sha256=(str(i), str(i + 1))) for i in range(5000))
    assert _broad_shared_anchors(samples) == {}
    unrelated = tuple(_sample(i, native_sha256=("shared",)) for i in range(5000))
    assert _broad_shared_anchors(unrelated)[("native", "shared")] == {
        "sample_count": 5000, "case_count": 5000, "unrelated_group_count": 5000,
    }


def test_dense_review_components_preserve_edges_order_and_identity() -> None:
    ids = tuple(f"{number:064x}" for number in range(80))
    edges = [{"left": {"sample_sha256": left}, "right": {"sample_sha256": right},
              "review_priority_score": (index % 100)}
             for index, (left, right) in enumerate(combinations(ids, 2))]
    before = repr(edges)
    result = _components(list(reversed(edges)))
    assert len(result) == 1 and result[0][0] == ids
    expected = sorted(edges, key=lambda edge: (-edge["review_priority_score"],
                      edge["left"]["sample_sha256"], edge["right"]["sample_sha256"]))
    assert result[0][1] == expected
    assert {id(edge) for edge in result[0][1]} == {id(edge) for edge in edges}
    assert repr(edges) == before


def _reference_strip(url: str) -> str:
    url = url.strip()
    while url and url[-1] in ".,;:'\")]}>”’、，。；":
        if url[-1] == ")" and url.count("(") > url.count(")"):
            break
        if url[-1] == "]" and url.count("[") > url.count("]"):
            break
        url = url[:-1]
    return url


def test_url_tail_scanner_matches_original_bracket_contract() -> None:
    rng = random.Random(2026)
    alphabet = "abc()[]{}>.,;:'\"”’、，。； \t\n"
    for _ in range(5000):
        value = "".join(rng.choices(alphabet, k=rng.randrange(100)))
        assert strip_url_tail(value) == _reference_strip(value)
    prefix = "https://example.invalid/path"
    assert strip_url_tail(prefix + ")];" * 100_000) == prefix
