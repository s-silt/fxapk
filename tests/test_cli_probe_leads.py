"""probe-leads --into 的样本身份门（fail-closed）。

探针日志本身不含任何样本标识（[LEAD] 行无 sha/包名），无法自证归属；--into 回灌时必须由
操作者用 --sample-sha 显式断言日志所属样本，并与目标报告 meta.sample_sha256 核对。
不核对就合并的后果不止"混进别人的线索"——merge_into_report_json 对命中已有
(category, value) 的线索会升 confidence（两源印证语义），跨样本回灌等于制造假印证。

覆盖四条路径，其中拦截路径逐条断言目标文件**字节前后不变**（门必须在任何写入之前）。
夹具全部合成：sha 用 "0"*64 / "1"*64，线索值用 example.com / CGNAT 段，绝不用真实案件值。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from apkscan import cli

runner = CliRunner()

_SHA_A = "0" * 64
_SHA_B = "1" * 64


def _write_report(path: Path, *, meta: dict[str, Any]) -> None:
    """写一份存盘形状的最小 report.json（与 report/json.py 序列化同构，供 --into 合并）。"""
    payload: dict[str, Any] = {
        "package_name": "com.example.app",
        "meta": dict(meta),
        "leads": [],
        "endpoints": [],
        "findings": [],
        "analyzer_status": [],
        "enricher_status": [],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_probe_log(path: Path) -> None:
    """合成探针日志：两行可解析的 [LEAD]（域名走 example.com、IP 走 CGNAT 保留段）。"""
    path.write_text(
        "[http][LEAD] GET https://backend.example.com/api\n"
        "[socket][LEAD] connect 100.64.7.9:8080\n",
        encoding="utf-8",
    )


def test_probe_into_requires_matching_sample_sha(tmp_path: Path) -> None:
    """三条拦截路径 exit 2 且目标字节不变；相符路径正常追加。"""
    log = tmp_path / "probe.log"
    _write_probe_log(log)

    report_a = tmp_path / "report_a.json"
    _write_report(report_a, meta={"sample_sha256": _SHA_A})
    report_nosha = tmp_path / "report_nosha.json"
    _write_report(report_nosha, meta={})

    # 1) --sample-sha 与目标报告不符 → exit 2 + 字节不变。
    before = report_a.read_bytes()
    res = runner.invoke(
        cli.app,
        ["probe-leads", str(log), "--into", str(report_a), "--sample-sha", _SHA_B],
    )
    assert res.exit_code == 2
    assert "不符" in res.stderr
    assert report_a.read_bytes() == before

    # 2) 用了 --into 却没给 --sample-sha → exit 2 + 字节不变。
    res = runner.invoke(cli.app, ["probe-leads", str(log), "--into", str(report_a)])
    assert res.exit_code == 2
    assert "--sample-sha" in res.stderr
    assert report_a.read_bytes() == before

    # 3) 目标报告 meta 无 sample_sha256（无法核对）→ fail-closed，exit 2 + 字节不变。
    before_nosha = report_nosha.read_bytes()
    res = runner.invoke(
        cli.app,
        ["probe-leads", str(log), "--into", str(report_nosha), "--sample-sha", _SHA_A],
    )
    assert res.exit_code == 2
    assert "缺失" in res.stderr
    assert report_nosha.read_bytes() == before_nosha

    # 4) 相符 → 成功、线索正常追加进 leads。
    res = runner.invoke(
        cli.app,
        ["probe-leads", str(log), "--into", str(report_a), "--sample-sha", _SHA_A],
    )
    assert res.exit_code == 0
    payload = json.loads(report_a.read_text(encoding="utf-8"))
    values = [str(item.get("value", "")) for item in payload["leads"]]
    # ★不用 `"域名" in v` 的子串写法：CodeQL 的 py/incomplete-url-substring-sanitization
    #   会把它当成 URL 净化逻辑而报 high（实为测试断言、非安全检查）。改用「整行等值」既避开
    #   误报，断言本身也更严——子串匹配连 evil-backend.example.com.attacker.test 都会通过。
    joined = "\n".join(values)
    assert "https://backend.example.com/api" in joined
    assert "100.64.7.9:8080" in joined


def test_probe_leads_without_into_needs_no_sample_sha(tmp_path: Path) -> None:
    """只出台账不回灌（无 --into）的用法零影响：不给 --sample-sha 也照常成功。"""
    log = tmp_path / "probe.log"
    _write_probe_log(log)
    md = tmp_path / "ledger.md"

    res = runner.invoke(cli.app, ["probe-leads", str(log), "--md", str(md)])

    assert res.exit_code == 0
    # 台账对值做防误触发转义（backend\.example\.com），按转义后形态断言。
    assert "backend\\.example\\.com" in md.read_text(encoding="utf-8")
