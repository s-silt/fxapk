"""config-chain 层⑧：corpus 远程配置对象维度 + 跨样本串联测试。

覆盖：从下载产物 ∪ REMOTE_CONFIG 候选提取对象（url 去重、下载 sha 优先）、manifest_entry 带该维度、
find_by_config_object 按 url/sha 反查、shared_config_objects 按 url/sha 聚跨样本簇（含 url-only 回落）。
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core.corpus import (
    _remote_config_objects,
    find_by_config_object,
    manifest_entry,
    shared_config_objects,
)


def test_remote_config_objects_from_artifacts_and_leads() -> None:
    report = {
        "meta": {"remote_config_artifacts": [
            {"source_url": "https://b.oss-cn.aliyuncs.com/c.dat", "sha256": "ABC123", "decoded": True},
            {"decoded": False},  # 无 source_url → 跳过
        ]},
        "leads": [
            {"category": "REMOTE_CONFIG", "value": "https://b.oss-cn.aliyuncs.com/c.dat"},  # 与产物同 url
            {"category": "REMOTE_CONFIG", "value": "https://other.oss.com/x.json"},  # 仅候选（无下载）
            {"category": "DOMAIN", "value": "api.x.com"},  # 非 remote_config
        ],
    }
    objs = _remote_config_objects(report)
    by_url = {o["url"]: o for o in objs}
    assert len(objs) == 2  # 同 url 去重
    assert by_url["https://b.oss-cn.aliyuncs.com/c.dat"]["sha256"] == "abc123"  # 下载产物 sha 保留、小写
    assert by_url["https://other.oss.com/x.json"]["sha256"] is None  # 仅候选、无 sha


def test_remote_config_objects_empty() -> None:
    assert _remote_config_objects({}) == []
    assert _remote_config_objects({"meta": {}, "leads": []}) == []


def test_manifest_entry_includes_remote_config_objects() -> None:
    report = {"meta": {"sample_sha256": "s1",
                       "remote_config_artifacts": [{"source_url": "https://x/c.dat", "sha256": "aa"}]}}
    entry = manifest_entry(report)
    assert entry["remote_config_objects"] == [{"url": "https://x/c.dat", "sha256": "aa"}]


def test_find_by_config_object_url_and_sha() -> None:
    entries = [
        {"sample_sha256": "s1", "remote_config_objects": [{"url": "https://x/c.dat", "sha256": "aa11"}]},
        {"sample_sha256": "s2", "remote_config_objects": [{"url": "https://y/d.dat", "sha256": "bb22"}]},
    ]
    assert [e["sample_sha256"] for e in find_by_config_object(entries, "https://x/c.dat")] == ["s1"]
    assert [e["sample_sha256"] for e in find_by_config_object(entries, "AA11")] == ["s1"]  # sha 大小写归一
    assert find_by_config_object(entries, "nope") == []
    assert find_by_config_object(entries, "") == []


def test_shared_config_objects_clusters_by_url_and_sha() -> None:
    entries = [
        {"sample_sha256": "s1", "remote_config_objects": [{"url": "https://shared/c.dat", "sha256": "same"}]},
        {"sample_sha256": "s2", "remote_config_objects": [{"url": "https://shared/c.dat", "sha256": "same"}]},
        {"sample_sha256": "s3", "remote_config_objects": [{"url": "https://unique/x.dat", "sha256": "other"}]},
    ]
    clusters = shared_config_objects(entries)
    url_clusters = [c for c in clusters if c["key_type"] == "url"]
    sha_clusters = [c for c in clusters if c["key_type"] == "sha256"]
    assert len(url_clusters) == 1 and url_clusters[0]["samples"] == ["s1", "s2"]
    assert url_clusters[0]["key"] == "https://shared/c.dat"
    assert len(sha_clusters) == 1 and sha_clusters[0]["samples"] == ["s1", "s2"]  # 内容一致强锚
    assert all("s3" not in c["samples"] for c in clusters)  # 独有对象不成簇


def test_shared_config_objects_url_only_correlation() -> None:
    # s1 已下载（有 sha），s2 仅 passive 候选（无 sha）——仍按 url 串联；sha 簇因单样本不成立
    entries = [
        {"sample_sha256": "s1", "remote_config_objects": [{"url": "https://shared/c.dat", "sha256": "aa"}]},
        {"sample_sha256": "s2", "remote_config_objects": [{"url": "https://shared/c.dat", "sha256": None}]},
    ]
    clusters = shared_config_objects(entries)
    url_clusters = [c for c in clusters if c["key_type"] == "url"]
    assert url_clusters and url_clusters[0]["samples"] == ["s1", "s2"]
    assert not [c for c in clusters if c["key_type"] == "sha256"]


def test_shared_config_objects_no_self_cluster() -> None:
    # 单样本多次引用同一对象不成簇（须 ≥2 个不同样本）
    entries = [
        {"sample_sha256": "s1", "remote_config_objects": [
            {"url": "https://x/c.dat", "sha256": "aa"}, {"url": "https://x/c.dat", "sha256": "aa"}]},
    ]
    assert shared_config_objects(entries) == []


# --------------------------------------------------------------------------- #
# CLI 端到端：corpus shared-config / seen --by config-object
# --------------------------------------------------------------------------- #
def _report_with_config(sha: str, url: str, blob_sha: str) -> dict:
    return {
        "schema_version": "1.0", "analysis_status": "complete", "completeness": 1.0,
        "package_name": "com.x",
        "meta": {"sample_sha256": sha, "tool_version": "0.9.0", "ruleset_digest": "dd",
                 "remote_config_artifacts": [{"source_url": url, "sha256": blob_sha, "decoded": True}]},
        "leads": [], "endpoints": [], "findings": [],
    }


def test_cli_shared_config_and_seen(tmp_path) -> None:
    runner = CliRunner()
    corpus_dir = tmp_path / "corpus"
    for sha, name in (("s1", "r1.json"), ("s2", "r2.json")):
        rp = tmp_path / name
        rp.write_text(json.dumps(_report_with_config(sha, "https://shared/c.dat", "aa")), encoding="utf-8")
        add = runner.invoke(cli.app, ["corpus", "add", str(rp), "--case", "c1", "--corpus", str(corpus_dir)])
        assert add.exit_code == 0, add.stdout

    shared = runner.invoke(cli.app, ["corpus", "shared-config", "--corpus", str(corpus_dir)])
    assert shared.exit_code == 0
    clusters = json.loads(shared.stdout)["clusters"]
    url_cluster = next(c for c in clusters if c["key_type"] == "url")
    assert url_cluster["key"] == "https://shared/c.dat" and url_cluster["samples"] == ["s1", "s2"]

    seen = runner.invoke(
        cli.app, ["corpus", "seen", "https://shared/c.dat", "--by", "config-object", "--corpus", str(corpus_dir)])
    assert seen.exit_code == 0
    payload = json.loads(seen.stdout)
    assert payload["seen"] is True and payload["count"] == 2

    # seen --by config-object 也可按 blob sha256 反查
    by_sha = runner.invoke(
        cli.app, ["corpus", "seen", "AA", "--by", "config-object", "--corpus", str(corpus_dir)])
    assert json.loads(by_sha.stdout)["count"] == 2  # sha 大小写归一
