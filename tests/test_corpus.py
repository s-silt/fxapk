"""样本库（fxapk corpus）：core.corpus 纯逻辑 + CLI 端到端。"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import corpus


def _report(
    *,
    sha: str | None = "abc123",
    tool_version: str = "0.9.0",
    digest: str = "deadbeef",
    package: str = "com.fraud.app",
    leads=None,
    findings=None,
) -> dict:
    meta = {
        "package_name": package,
        "version_name": "2.0",
        "version_code": 20,
        "packer": "packer-x",
        "is_hardened": True,
        "sign_sha256": "CERT-SHA",
        "mode": "passive",
        "tool_version": tool_version,
        "ruleset_digest": digest,
        "app_classification": {"type": "fraud", "score": 88},
    }
    if sha is not None:
        meta["sample_sha256"] = sha
    return {
        "schema_version": "1.0",
        "analysis_status": "complete",
        "completeness": 1.0,
        "package_name": package,
        "meta": meta,
        "leads": leads if leads is not None else [
            {"category": "PAYMENT", "value": "pay.x.com", "advice": "建议调证", "is_c2": False},
            {"category": "C2", "value": "c2.x.com", "is_c2": True},
            {"category": "OTHER", "value": "noise.x.com", "advice": "仅参考", "is_c2": False},
        ],
        "endpoints": [{"value": "x.com", "kind": "domain"}],
        "findings": findings if findings is not None else [
            {"id": "JADX-HARDCODED-SECRET", "description": "k in A"},
            {"id": "NATIVE-OBFUSCATION-SUSPECTED", "description": "libx.so"},
        ],
    }


# --- manifest_entry 提取 -----------------------------------------------------


def test_manifest_entry_extracts_key_fields() -> None:
    e = corpus.manifest_entry(_report(), case_id="case-1")
    assert e["sample_sha256"] == "abc123"
    assert e["sample_sha256_synthetic"] is False
    assert e["tool_version"] == "0.9.0" and e["ruleset_digest"] == "deadbeef"
    assert e["package_name"] == "com.fraud.app"
    assert e["sign_sha256"] == "CERT-SHA"  # 共享证书串案强锚
    assert e["packer"] == "packer-x" and e["is_hardened"] is True
    assert e["app_type"] == "fraud" and e["app_score"] == 88
    assert e["mode"] == "passive" and e["analysis_status"] == "complete"
    assert e["case_id"] == "case-1"
    assert e["report_path"] == "reports/abc123/0.9.0_deadbeef.report.json"
    assert e["counts"] == {"leads": 3, "endpoints": 1, "findings": 2}
    assert e["finding_ids"] == ["JADX-HARDCODED-SECRET", "NATIVE-OBFUSCATION-SUSPECTED"]
    # key_iocs 只收 is_c2 或 advice=建议调证 的，噪声 lead 不收
    assert set(e["key_iocs"]) == {"pay.x.com", "c2.x.com"}


def test_upsert_warns_on_same_key_different_dep_versions(caplog) -> None:
    """★codex P1：同主键但依赖版本不同 → 幂等跳过但告警（不静默丢 dep 变体报告）。"""
    import logging

    base = corpus.manifest_entry(_report(), case_id="c1")
    base = {**base, "dependency_versions": {"androguard": "4.1.4"}}
    other = corpus.manifest_entry(_report(), case_id="c2")
    other = {**other, "dependency_versions": {"androguard": "4.1.9"}}  # 同主键、不同 androguard
    with caplog.at_level(logging.WARNING):
        merged, added = corpus.upsert([base], other)
    assert added is False and len(merged) == 1  # 主键相同 → 幂等跳过
    assert any("依赖版本不同" in r.message for r in caplog.records), "同主键不同依赖版本未告警"


def test_upsert_same_key_same_deps_no_warning(caplog) -> None:
    """同主键同依赖版本 → 幂等跳过、无告警（正常重复入库）。"""
    import logging

    e = {**corpus.manifest_entry(_report()), "dependency_versions": {"androguard": "4.1.4"}}
    with caplog.at_level(logging.WARNING):
        _merged, added = corpus.upsert([e], dict(e))
    assert added is False
    assert not any("依赖版本不同" in r.message for r in caplog.records)


def test_manifest_entry_records_dependency_versions() -> None:
    """依赖版本登记进 manifest（复现锚点，供 upsert 冲突检测）。"""
    rep = _report()
    rep["meta"]["dependency_versions"] = {"androguard": "4.1.4", "requests": "2.32.0"}
    e = corpus.manifest_entry(rep)
    assert e["dependency_versions"] == {"androguard": "4.1.4", "requests": "2.32.0"}


def test_manifest_entry_robust_to_junk() -> None:
    # 坏输入容错、绝不抛。
    e = corpus.manifest_entry({}, case_id=None)
    assert e["case_id"] is None
    assert e["counts"] == {"leads": 0, "endpoints": 0, "findings": 0}
    assert corpus.manifest_entry(None)["package_name"] is None  # type: ignore[arg-type]
    assert e["visibility"] is None, "无可见性求值必须是 None，不能是空 dict（那等于断言无受限主张）"


# --- 证据可见性投影 ---------------------------------------------------------


def _vis_report(**over) -> dict:
    r = _report()
    r.setdefault("meta", {})["visibility"] = {
        "sources": {"dex": {"visibility": "stub_only", "why": ["加固桩"]},
                    "native": {"visibility": "complete", "why": []}},
        "blocked_claims": ["static_endpoint_exhaustive"],
        "remediation": "not_attempted",
        "notes": ["人读文案"],
        "next_actions": ["先脱壳"],
        "degraded": True,
        **over,
    }
    return r


def test_visibility_summary_projects_structured_fields_only() -> None:
    """指纹只收方向可判的结构化字段；notes/why 等人读文案不入（否则措辞一改全库都标"有变化"）。"""
    s = corpus.visibility_summary(_vis_report())
    assert s is not None
    assert s["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert s["sources"]["dex"] == "stub_only"
    assert s["degraded"] is True
    assert s["remediation"] == "not_attempted"
    assert s["next_actions"] == 1, "next_actions 只记条数，不记文案"
    assert "notes" not in s and "why" not in json.dumps(s)


def test_visibility_summary_missing_is_none_not_empty() -> None:
    """★缺失 ≠ 无受限主张：没做求值必须返回 None，畸形值同样折到 None 而非静默吞成空。"""
    assert corpus.visibility_summary(_report()) is None
    assert corpus.visibility_summary({"meta": {"visibility": "坏值"}}) is None
    assert corpus.visibility_summary({"meta": {"visibility": ["坏值"]}}) is None
    assert corpus.visibility_summary(None) is None
    # 求过值、确实无受限主张 → dict（与上面的 None 严格区分）
    empty = corpus.visibility_summary(_vis_report(blocked_claims=[], degraded=False))
    assert empty is not None and empty["blocked_claims"] == []


def test_manifest_entry_carries_visibility() -> None:
    e = corpus.manifest_entry(_vis_report(), case_id="c1")
    assert e["visibility"]["blocked_claims"] == ["static_endpoint_exhaustive"]
    assert e["visibility"]["sources"]["dex"] == "stub_only"
    assert corpus.manifest_entry(_report())["visibility"] is None


# --- 样本身份（真哈希 vs 旧报告占位）----------------------------------------


def test_sample_identity_real_and_synthetic() -> None:
    sha, synthetic = corpus.sample_identity(_report(sha="deadc0de"))
    assert sha == "deadc0de" and synthetic is False

    # 旧报告无 sample_sha256 → 派生 nosha- 占位，确定且可复现
    old = _report(sha=None)
    s1, syn1 = corpus.sample_identity(old)
    s2, _ = corpus.sample_identity(_report(sha=None))
    assert syn1 is True and s1.startswith("nosha-") and s1 == s2


# --- add / upsert 幂等 -------------------------------------------------------


def test_add_report_idempotent(tmp_path: Path) -> None:
    r = _report()
    raw = json.dumps(r)
    first = corpus.add_report(tmp_path, r, raw, case_id="case-1")
    second = corpus.add_report(tmp_path, r, raw, case_id="case-1")
    assert first["added"] is True and second["added"] is False
    # 报告原样落盘 + manifest 只一条
    report_file = tmp_path / first["report_path"]
    assert report_file.exists() and report_file.read_text(encoding="utf-8") == raw
    assert len(corpus.load_manifest(tmp_path)) == 1


def test_add_same_sample_different_version_coexists(tmp_path: Path) -> None:
    # 同样本换 fxapk 版本 → 并存两份报告（回归对比的基线）
    corpus.add_report(tmp_path, _report(tool_version="0.9.0"), "{}", case_id="c1")
    corpus.add_report(tmp_path, _report(tool_version="1.0.0"), "{}", case_id="c1")
    assert len(corpus.load_manifest(tmp_path)) == 2


# --- 反查 / 过滤 -------------------------------------------------------------


def test_find_by_and_query(tmp_path: Path) -> None:
    corpus.add_report(tmp_path, _report(sha="s1", package="com.a"), "{}", case_id="c1")
    corpus.add_report(tmp_path, _report(sha="s2", package="com.b"), "{}", case_id="c2")
    entries = corpus.load_manifest(tmp_path)
    assert len(corpus.find_by(entries, "s1", by="sample_sha256")) == 1
    assert len(corpus.find_by(entries, "com.b", by="package_name")) == 1
    # 两样本共享同一签名证书 → 证书反查命中两条（串案强信号）
    assert len(corpus.find_by(entries, "CERT-SHA", by="sign_sha256")) == 2
    assert corpus.find_by(entries, "nope", by="sample_sha256") == []
    assert corpus.find_by(entries, "x", by="unknown_field") == []  # 不支持字段 → 空
    assert len(corpus.query(entries, case_id="c1")) == 1


def test_find_by_hash_case_insensitive(tmp_path: Path) -> None:
    """★哈希（sample_sha256/sign_sha256）十六进制大小写等价：反查大写/小写都命中，避免传大写 SHA256 假阴性；
    package_name 保持大小写敏感（com.Foo ≠ com.foo）。"""
    corpus.add_report(tmp_path, _report(sha="abc123def", package="com.Foo.Bar"), "{}", case_id="c1")
    entries = corpus.load_manifest(tmp_path)
    # sample_sha256：库内小写，大写/小写反查都命中
    assert len(corpus.find_by(entries, "ABC123DEF", by="sample_sha256")) == 1
    assert len(corpus.find_by(entries, "abc123def", by="sample_sha256")) == 1
    # sign_sha256：库内 "CERT-SHA"（含大写），小写反查也命中（双向归一）
    assert len(corpus.find_by(entries, "cert-sha", by="sign_sha256")) == 1
    # package_name：大小写敏感——变体不误命中，原样才命中
    assert corpus.find_by(entries, "com.foo.bar", by="package_name") == []
    assert len(corpus.find_by(entries, "com.Foo.Bar", by="package_name")) == 1


# --- reindex 重建 + 保 case_id ----------------------------------------------


def test_reindex_preserves_case_id_from_manifest(tmp_path: Path) -> None:
    corpus.add_report(tmp_path, _report(sha="s1"), json.dumps(_report(sha="s1")), case_id="case-9")
    # manifest 在场时 reindex 从报告重算，但从旧 manifest 继承人工 case_id（不因重建而丢）
    rebuilt = corpus.reindex(tmp_path)
    assert len(rebuilt) == 1 and rebuilt[0]["case_id"] == "case-9"


def test_reindex_rebuilds_from_reports_when_manifest_lost(tmp_path: Path) -> None:
    corpus.add_report(tmp_path, _report(sha="s1"), json.dumps(_report(sha="s1")), case_id="case-9")
    # 索引损坏/丢失：删掉 manifest，reindex 仍能从 reports/ 全量重建记录（report.json 是事实源）。
    # case_id 只活在 manifest，随之丢失属预期——报告是事实源，人工标注不是。
    corpus.manifest_path(tmp_path).unlink()
    rebuilt = corpus.reindex(tmp_path)
    assert len(rebuilt) == 1 and rebuilt[0]["sample_sha256"] == "s1"
    assert rebuilt[0]["case_id"] is None


# --- CLI 端到端：add → seen → reindex 幂等闭环 ------------------------------


def test_cli_add_seen_reindex_closed_loop(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    runner = CliRunner()

    res = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.output)["added"] == 1

    res = runner.invoke(cli.app, ["corpus", "seen", "abc123", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.stdout)["seen"] is True

    res = runner.invoke(cli.app, ["corpus", "reindex", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0 and json.loads(res.output)["reindexed"] == 1

    # 再入库幂等跳过
    res = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert json.loads(res.stdout)["skipped"] == 1


def test_cli_events_streams_jsonl(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    runner = CliRunner()
    runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])

    res = runner.invoke(cli.app, ["corpus", "events", "abc123", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]  # stdout：本命令往 stderr 打不脱敏提醒
    parsed = [json.loads(ln) for ln in lines]  # 每行合法 JSON
    assert parsed[0]["type"] == "meta"
    assert {e["type"] for e in parsed} == {"meta", "lead", "finding"}


def test_cli_nan_report_yields_strict_valid_jsonl(tmp_path: Path) -> None:
    # ★复审(codex 探查方向)：report 数值字段若为 NaN/Infinity（Python json 默认接受、但 RFC-8259
    #   非法），不得随 manifest.jsonl 或 events 输出泄漏为字面 NaN——那会让 jq / JS JSON.parse 崩。
    corpus_dir = tmp_path / "corpus"
    report_file = tmp_path / "r.json"
    r = _report(sha="nan-sample")
    r["completeness"] = float("nan")
    r["meta"]["app_classification"]["score"] = float("inf")
    report_file.write_text(json.dumps(r), encoding="utf-8")  # 默认写出字面 NaN/Infinity
    runner = CliRunner()

    add = runner.invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1", "--corpus", str(corpus_dir)])
    assert add.exit_code == 0
    # manifest.jsonl 每行严格合法（不含字面 NaN/Infinity token）
    manifest_text = corpus.manifest_path(corpus_dir).read_text(encoding="utf-8")
    assert "NaN" not in manifest_text and "Infinity" not in manifest_text

    ev = runner.invoke(cli.app, ["corpus", "events", "nan-sample", "--corpus", str(corpus_dir)])
    assert ev.exit_code == 0
    assert "NaN" not in ev.stdout and "Infinity" not in ev.stdout
    # 用严格解析器（禁 NaN/Infinity）逐行验证，模拟 jq / JS JSON.parse
    strict = json.JSONDecoder(parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    for line in ev.stdout.splitlines():
        if line.strip():
            strict.decode(line)  # 非法常量会抛 → 测试失败


def test_cli_events_missing_sample_exits_1(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    res = CliRunner().invoke(cli.app, ["corpus", "events", "ghost", "--corpus", str(corpus_dir)])
    assert res.exit_code == 1


# --- PII 硬防线：缺库路径拒跑 -----------------------------------------------


def test_cli_refuses_without_corpus_dir(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("FXAPK_CORPUS", raising=False)
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["corpus", "add", str(report_file)])
    assert res.exit_code == 2  # 既无 --corpus 又无环境变量 → 拒跑，绝不默认 ./corpus


def test_cli_uses_env_corpus(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    corpus_dir = tmp_path / "corpus"
    monkeypatch.setenv("FXAPK_CORPUS", str(corpus_dir))
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(cli.app, ["corpus", "add", str(report_file), "--case", "c1"])
    assert res.exit_code == 0 and json.loads(res.output)["added"] == 1


# --- 复审修复回归（Fable 对抗式复审确认的真问题）---------------------------


def test_add_report_collision_refuses_overwrite(tmp_path: Path) -> None:
    # #2/#3：不同主键净化后落同一路径（abc?123 / abc*123 → abc_123），第二次不得覆写第一份取证字节。
    r1 = _report(sha="abc?123")
    r2 = _report(sha="abc*123")
    raw1, raw2 = json.dumps(r1), json.dumps(r2) + " "  # 字节不同
    first = corpus.add_report(tmp_path, r1, raw1)
    second = corpus.add_report(tmp_path, r2, raw2)
    assert first["added"] is True
    assert second["added"] is False and second["collision"] is True
    # 第一份取证字节完好、未被销毁
    assert (tmp_path / first["report_path"]).read_bytes() == raw1.encode("utf-8")


def test_add_report_byte_fidelity_multiline(tmp_path: Path) -> None:
    # #4：多行(含 \n) raw 入库后逐字节等于原文，不被文本模式 CRLF 翻译污染。
    raw = json.dumps(_report(), indent=2)  # 多行
    res = corpus.add_report(tmp_path, _report(), raw)
    assert (tmp_path / res["report_path"]).read_bytes() == raw.encode("utf-8")


def test_sample_identity_rejects_forged_nosha_prefix() -> None:
    # #9：meta.sample_sha256 冒用保留前缀 nosha- → 不当真实身份，落派生分支置 synthetic。
    sha, synthetic = corpus.sample_identity(_report(sha="nosha-deadbeef"))
    assert synthetic is True and sha != "nosha-deadbeef"


def test_reindex_skips_non_utf8_report(tmp_path: Path) -> None:
    # #5：坏文件(非 UTF-8)不得让自愈工具崩，其它报告照常重建。
    corpus.add_report(tmp_path, _report(sha="good"), json.dumps(_report(sha="good")))
    bad = tmp_path / corpus.REPORTS_DIR / "bad" / "x.report.json"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_bytes(b"\xff\xfe not utf8 \x00")
    rebuilt = corpus.reindex(tmp_path)  # 不抛
    assert len(rebuilt) == 1 and rebuilt[0]["sample_sha256"] == "good"


def test_cli_seen_invalid_by_exits_2(tmp_path: Path) -> None:
    # #8：拼错 --by 字段不能静默假阴性（seen=false exit 0），必须拒跑。
    cd = tmp_path / "corpus"
    cd.mkdir()
    res = CliRunner().invoke(cli.app, ["corpus", "seen", "x", "--by", "sign_sha", "--corpus", str(cd)])
    assert res.exit_code == 2


def test_cli_events_path_traversal_refused(tmp_path: Path) -> None:
    # #10：manifest 里 report_path 越界/缺失 → 拒绝读库外文件、不 traceback。
    cd = tmp_path / "corpus"
    cd.mkdir()
    corpus.save_manifest(cd, [{
        "sample_sha256": "evil", "tool_version": "t", "ruleset_digest": "d",
        "report_path": "../../../etc/passwd",
    }])
    res = CliRunner().invoke(cli.app, ["corpus", "events", "evil", "--corpus", str(cd)])
    assert res.exit_code == 1


def test_cli_refuses_corpus_inside_git_worktree(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #1 加固：语料库落在 git 工作树内 → 拒跑（防真实案件数据随 git add 混进公开仓库）。
    monkeypatch.delenv("FXAPK_CORPUS", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(_report()), encoding="utf-8")
    res = CliRunner().invoke(
        cli.app, ["corpus", "add", str(report_file), "--corpus", str(repo / "corpus")]
    )
    assert res.exit_code == 2
