"""Offline regressions for query coverage, alternate indexes and report handoff."""

import json
from pathlib import Path

import pytest

from apkscan import cli
from apkscan.core.jadx_index import JadxIndexStore
from apkscan.core.jadx_review import compare_structure, load_review_receipts, review_markdown
from apkscan.core.jadx_sources import capture_sources, query_sources
from tests import test_jadx_query_cli as fixture

SHA = "ab" * 32


def _source_index(tmp_path, monkeypatch):
    java = {"com/x/Alpha.java": fixture._JAVA["com/x/Alpha.java"].replace(
        "void target() {", 'void target() {\n        String k = "family_config_key";')}
    monkeypatch.setattr(fixture, "_JAVA", java)
    return fixture._build_index(tmp_path)


def _mapping(cache, key, *, alternate=None):
    data = {"records": [{"apk_sha256": SHA, "index_key": key,
                         "alternate_indexes": [{"index_key": alternate}] if alternate else []}]}
    (cache / "fxapk-jadx-index-map.json").write_text(json.dumps(data), encoding="utf-8")


def _invoke(cache, *args):
    result = fixture.runner.invoke(cli.app, ["jadx", *args, "--jadx-cache-root", str(cache)])
    assert result.exit_code == 0, (result.stdout, result.exception)
    return json.loads(result.stdout)


def test_existing_source_value_is_unknown_without_snapshot_and_found_with_it(tmp_path, monkeypatch):
    cache, key = _source_index(tmp_path, monkeypatch)
    before = {p.relative_to(cache): p.read_bytes() for p in cache.rglob("*") if p.is_file()}
    unknown = _invoke(cache, "usage", "family_config_key", "--jadx-index", key)
    assert unknown["hits"] == [] and unknown["query_coverage"] == "partial"
    assert "query_value_coverage_unknown" in unknown["reason_codes"]
    receipt = capture_sources(cache, key, tmp_path / "java", coverage="complete")
    found = _invoke(cache, "usage", "family_config_key", "--jadx-index", key)
    assert found["query_coverage"] == "complete"
    assert found["source_hits"][0]["path"] == "com/x/Alpha.java"
    assert found["source_hits"][0]["snapshot_sha256"] == receipt["sha256"]
    assert all((cache / p).read_bytes() == raw for p, raw in before.items())
    absent = _invoke(cache, "usage", "missing-value", "--jadx-index", key)
    assert not absent["source_hits"] and absent["query_coverage"] == "complete"
    assert absent["caveats"][0]["code"] == "empty_is_not_absence"


def test_corrupt_snapshot_does_not_hide_index_hits_or_claim_full_coverage(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    receipt = capture_sources(cache, key, tmp_path / "java", coverage="complete")
    (cache / receipt["locator"]).write_bytes(b"bad-gzip")
    found = _invoke(cache, "usage", fixture._NEEDLE, "--jadx-index", key)
    assert found["hits"] and found["query_coverage"] == "partial"
    assert "source_snapshot_invalid" in found["reason_codes"]


def test_source_binding_mismatch_is_rejected(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    capture_sources(cache, key, tmp_path / "java", coverage="complete")
    manifest = cache / key / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    data = query_sources(cache, key, fixture._NEEDLE)
    assert not data["hits"] and "source_snapshot_invalid" in data["reason_codes"]


def test_all_indexes_attempted_and_saved_receipt_bound_to_original_sha(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    _mapping(cache, key, alternate="ff" * 32)
    out = tmp_path / "query.json"
    data = _invoke(cache, "usage", fixture._NEEDLE, "--apk-sha256", SHA, "--out", str(out))
    assert data["index_count"] == 2 and data["status"] == "partial"
    assert data["results"][0]["hits"] and data["results"][1]["status"] == "miss"
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["query_inputs"] == [fixture._NEEDLE]
    assert "query_inputs" not in data  # stdout keeps the existing privacy contract
    assert saved["apk_sha256"] == SHA and saved["index_map_sha256"]
    review = load_review_receipts([out, out], {SHA})
    assert len(review["receipts"]) == 1
    markdown = "\n".join(review_markdown(review))
    assert key in markdown and "com/x/Alpha.java" in markdown
    wrong = load_review_receipts([out], {"cd" * 32})
    assert not wrong["receipts"] and wrong["gaps"][0]["reason"] == "receipt_sample_mismatch"


def test_callpath_all_indexes_have_binding_and_heuristic_limit(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    _mapping(cache, key)
    data = _invoke(cache, "callpath", "Alpha#start/0", "Alpha#target/0", "--apk-sha256", SHA)
    item = data["results"][0]
    assert item["paths"] and item["index_manifest_sha256"]
    assert any(c["code"] == "heuristic_not_method_binding" for c in item["caveats"])


def test_no_mapping_is_partial_not_negative(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    _mapping(cache, key)
    data = _invoke(cache, "usage", "x", "--apk-sha256", "fe" * 32)
    assert data["status"] == "partial" and data["index_count"] == 0


def test_short_value_projection_keeps_schema_keys(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    result = fixture.runner.invoke(
        cli.app, ["jadx", "usage", "e", "--jadx-index", key, "--jadx-cache-root", str(cache)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    # 'e' occurs inside schema keys (reason_codes): a whole-text redaction would
    # corrupt them. Keys must stay intact so stdout stays machine-parseable.
    assert data["status"] == "ok" and isinstance(data["reason_codes"], list)
    assert data["query_coverage"] in {"complete", "partial"}


def test_query_does_not_overwrite_different_receipt(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    out = tmp_path / "existing.json"
    out.write_text("unchanged")
    result = fixture.runner.invoke(cli.app, ["jadx", "usage", "x", "--jadx-index", key,
                                           "--jadx-cache-root", str(cache), "--out", str(out)])
    assert result.exit_code != 0 and out.read_text() == "unchanged"


def test_family_comparison_records_same_sample_and_does_not_assert_operator(tmp_path):
    cache, key = fixture._build_index(tmp_path)
    _mapping(cache, key)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"meta": {"sample_sha256": SHA}}))
    data = _invoke(cache, "compare", str(report), str(report))
    assert data["assessment"] == "same_sample_not_independent"
    assert data["operator_identity_asserted"] is False
    assert data["index_comparisons"][0]["comparison"]["shared_region_group_count"] > 0


def test_body_matching_survives_enclosing_class_and_path_rename(tmp_path, monkeypatch):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    cache_a, key_a = fixture._build_index(a)
    monkeypatch.setattr(fixture, "_JAVA", {"renamed/Beta.java": fixture._JAVA["com/x/Alpha.java"].replace("class Alpha", "class Beta")})
    cache_b, key_b = fixture._build_index(b)
    result = compare_structure(JadxIndexStore(cache_a).load_index(key_a), JadxIndexStore(cache_b).load_index(key_b))
    assert result["added_classes"] and result["removed_classes"]
    assert result["shared_regions_across_paths"]
    assert result["shared_regions_across_paths"][0]["left"][0]["path"] != result["shared_regions_across_paths"][0]["right"][0]["path"]


def test_partial_capture_preserves_query_limit(tmp_path, monkeypatch):
    from apkscan.core import jadx_sources
    cache, key = fixture._build_index(tmp_path)
    monkeypatch.setattr(jadx_sources, "MAX_FILE_BYTES", 10)
    captured = capture_sources(cache, key, tmp_path / "java", coverage="complete")
    assert captured["coverage"] == "partial"
    assert "source_byte_limit" in captured["reason_codes"]


def test_invalid_query_and_traversal_are_rejected(tmp_path):
    from apkscan.core.jadx_sources import contained
    with pytest.raises(ValueError):
        contained(tmp_path, "../outside")
    cache, key = fixture._build_index(tmp_path)
    result = fixture.runner.invoke(cli.app, ["jadx", "usage", "", "--jadx-index", key,
                                           "--jadx-cache-root", str(cache)])
    assert result.exit_code != 0


def test_analyzer_preserves_unknown_query_value_before_temp_cleanup(tmp_path, monkeypatch):
    from tests import test_jadx_index_wiring as wiring
    from apkscan.analyzers.jadx import JadxAnalyzer
    monkeypatch.setattr(wiring, "_JAVA_BODY", wiring._JAVA_BODY + '\n// later_family_key\n')
    wiring._patch(monkeypatch)
    monkeypatch.setattr(wiring.jadx.tools, "resolve_jadx", lambda: (["jadx"], {}))
    ctx = wiring._ctx(tmp_path)
    result = JadxAnalyzer().analyze(ctx)
    assert result.meta["jadx_query_sources"]["file_count"] > 0
    query = _invoke(Path(ctx.jadx_cache_root), "usage", "later_family_key", "--jadx-index",
                    result.meta["jadx_index_key"])
    assert query["source_hits"] and query["query_coverage"] == "complete"


def test_analyzer_query_snapshot_failure_keeps_static_findings(tmp_path, monkeypatch):
    from tests import test_jadx_index_wiring as wiring
    from apkscan.analyzers.jadx import JadxAnalyzer
    from apkscan.core import jadx_sources
    wiring._patch(monkeypatch)
    monkeypatch.setattr(wiring.jadx.tools, "resolve_jadx", lambda: (["jadx"], {}))
    def fail(*args, **kwargs):
        raise OSError("synthetic write failure")
    monkeypatch.setattr(jadx_sources, "capture_sources", fail)
    result = JadxAnalyzer().analyze(wiring._ctx(tmp_path))
    assert result.meta["jadx_index_status"] == "built"
    assert result.meta["jadx_endpoint_count"] > 0
    assert result.meta["jadx_query_sources"]["reason_codes"] == ["source_capture_failed"]

@pytest.mark.parametrize('kind,values', [
    ('usage', ('Alpha',)),
    ('callpath', ('Alpha#start/0', 'Alpha#target/0')),
])
def test_stdout_projects_query_literals_but_receipt_keeps_them(tmp_path, monkeypatch, kind, values):
    monkeypatch.setattr(fixture, '_NEEDLE', 'Alpha')
    cache, key = fixture._build_index(tmp_path)
    out = tmp_path / 'receipt.json'
    result = fixture.runner.invoke(cli.app, ['jadx', kind, *values, '--jadx-index', key,
        '--jadx-cache-root', str(cache), '--out', str(out)])
    assert result.exit_code == 0, result.exception
    saved = out.read_text(encoding='utf-8')
    for value in values:
        assert value not in result.stdout
        assert value in saved
    assert '<query-value-sha256:' in result.stdout
    assert json.loads(saved)['query_inputs'] == list(values)


@pytest.mark.parametrize('records', [None, {}, 'bad', [None], [42],
    [{'apk_sha256': SHA, 'index_key': 'ab' * 32, 'alternate_indexes': None}],
    [{'apk_sha256': SHA, 'index_key': 'ab' * 32, 'alternate_indexes': {}}],
    [{'apk_sha256': SHA, 'index_key': 'ab' * 32, 'alternate_indexes': [None]}],
    [{'apk_sha256': SHA, 'index_key': 'ab' * 32, 'alternate_indexes': [{}]}],
    [{'apk_sha256': 'ff' * 32, 'index_key': 'ab' * 32, 'alternate_indexes': [{}]}],
])
def test_malformed_mapping_is_invalid_not_missing(tmp_path, records):
    import typer
    from apkscan.commands.jadx_query import _selection
    mapping = tmp_path / 'mapping.json'
    mapping.write_text(json.dumps({'records': records}))
    with pytest.raises(typer.BadParameter, match='索引映射格式无效'):
        _selection(tmp_path, None, SHA, mapping)


@pytest.mark.parametrize('reasons,expected', [
    (None, ['upstream_coverage_partial']),
    (['jadx_run_degraded', 'dex_excluded', 'dex_excluded'], ['dex_excluded', 'jadx_run_degraded']),
])
def test_upstream_partial_reasons_survive_snapshot_query(tmp_path, reasons, expected):
    cache, key = fixture._build_index(tmp_path)
    receipt = capture_sources(cache, key, tmp_path / 'java', coverage='partial', coverage_reasons=reasons)
    assert receipt['coverage'] == 'partial'
    assert receipt['reason_codes'] == expected
    queried = query_sources(cache, key, fixture._NEEDLE)
    assert queried['coverage'] == 'partial'
    assert 'source_partial' in queried['reason_codes']
    import gzip
    snapshot = json.loads(gzip.decompress((cache / receipt['locator']).read_bytes()))
    assert snapshot['reason_codes'] == expected


def test_source_query_exception_preserves_index_hits(tmp_path, monkeypatch):
    from apkscan.commands import jadx_query
    cache, key = fixture._build_index(tmp_path)
    def fail(*args, **kwargs):
        raise OSError('synthetic source failure')
    monkeypatch.setattr(jadx_query, 'query_sources', fail)
    data = _invoke(cache, 'usage', fixture._NEEDLE, '--jadx-index', key)
    assert data['status'] == 'ok' and data['hits']
    assert data['query_coverage'] == 'partial'
    assert data['source_hits'] == data['source_snapshots'] == []
    assert data['reason_codes'] == ['source_query_failed']


def test_independent_comparisons_state_identity_limit(tmp_path):
    from apkscan.core.jadx_review import compare_report_features
    cache, key = fixture._build_index(tmp_path)
    loaded = JadxIndexStore(cache).load_index(key)
    structure = compare_structure(loaded, loaded)
    features = compare_report_features({}, {})
    assert structure['operator_identity_asserted'] is False
    assert features['operator_identity_asserted'] is False
    assert features['caveats'] == structure['caveats']
    review_markdown({'receipts': [{'receipt_sha256': SHA, 'data': {
        'schema': 'jadx-family-comparison-1', 'subject_sha256': SHA,
        'candidate_sha256': SHA, 'assessment': 'same_sample_not_independent',
        'features': features,
    }}]})

@pytest.mark.parametrize('exclude', [False, True])
def test_analyzer_passes_specific_upstream_coverage_reasons(tmp_path, monkeypatch, exclude):
    from tests import test_jadx_index_wiring as wiring
    from apkscan.analyzers.jadx import JadxAnalyzer
    wiring._patch(monkeypatch)
    monkeypatch.setattr(wiring.jadx.tools, 'resolve_jadx', lambda: (['jadx'], {}))
    def run(cmd, *, timeout, env=None):
        if '--version' in cmd:
            return wiring._owned(0, stdout='1.5.2\n')
        if exclude and any(str(arg).endswith('dump0.dex') for arg in cmd):
            return wiring._owned(1)
        output = Path(cmd[cmd.index('-d') + 1]) / 'sources' / 'C.java'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(wiring._JAVA_BODY, encoding='utf-8')
        return wiring._owned(0 if exclude else 1)
    monkeypatch.setattr(wiring.jadx.proctree, 'run_owned', run)
    ctx = wiring._ctx(tmp_path, extra=(b'junk-not-a-dex-at-all',) if exclude else ())
    result = JadxAnalyzer().analyze(ctx)
    receipt = result.meta['jadx_query_sources']
    assert receipt['coverage'] == 'partial'
    assert receipt['reason_codes'] == (['dex_excluded', 'jadx_run_degraded'] if exclude else ['jadx_run_degraded'])


def test_new_outputs_stable_across_hashseeds(tmp_path):
    import os
    import subprocess
    import sys
    cache, key = fixture._build_index(tmp_path)
    script = '''
import os, sys
from pathlib import Path
from apkscan.commands.jadx_query import _emit, _query_one
from apkscan.core.jadx_sources import capture_sources
from apkscan.core.jadx_review import compare_report_features
assert os.environ['PYTHONHASHSEED'] == sys.argv[3]
cache, key = Path(sys.argv[1]), sys.argv[2]
receipt = capture_sources(cache, key, cache.parent / 'java', coverage='partial',
    coverage_reasons=list({'jadx_run_degraded', 'dex_excluded'}))
_emit({'snapshot': receipt, 'features': compare_report_features({}, {}),
    'query': _query_one(cache, key, 'callpath', ('Alpha#start/0', 'Alpha#target/0'))},
    ('Alpha#start/0', 'Alpha#target/0'))
'''
    outputs = []
    for seed in ('0', '1'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONIOENCODING': 'utf-8'}
        proc = subprocess.run([sys.executable, '-c', script, str(cache), key, seed],
            env=env, capture_output=True, timeout=60, check=False)
        assert proc.returncode == 0, proc.stderr.decode('utf-8', 'replace')
        outputs.append(proc.stdout)
    assert outputs[0] and outputs[0] == outputs[1]
