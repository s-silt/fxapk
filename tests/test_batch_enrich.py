"""批量被动富化（``core/batch_enrich.py`` + ``commands/enrich.py``）的判据测试。

★两条最要紧的不变量，各配一条测试与一条变异验证：

1. ``--dry-run``（默认）**绝不发请求** —— 这是防误烧配额的闸门。用会抛的 stub 富化器
   验证：dry-run 下 stub 的请求计数必须为 0。
2. **续跑真的跳过** —— ``_PassiveLookupEnricher`` 那一支没有文件缓存，跳过必须由本层
   账本实现。第二次运行 stub 请求计数必须为 0。

夹具地址一律用文档保留段（``198.51.100.0/24`` / ``example.com``），不出现任何真实地址。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkscan import cli
from apkscan.core import batch_enrich
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher

runner = CliRunner()


class _CountingEnricher(BaseEnricher):
    """会计数的假富化源；``case_close_only`` 与真 key-gated 源一致。"""

    name = "counting_stub"
    applies_to = ["ip", "domain"]
    case_close_only = True
    active = False

    def __init__(self) -> None:
        self.calls: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls.append(ep.value)
        return EnrichmentResult(
            provider=self.name,
            ok=True,
            data={"observed": ep.value, "_source_status": "hit"},
        )


class _ExplodingEnricher(BaseEnricher):
    """被调用就**记账并**抛——用来证明"某条路径确实没发请求"。

    ★为什么必须记账、不能只抛：``enrich_targets`` 有意 per-target 吞掉异常（单个目标炸掉
    不连坐其余目标），所以异常**到不了**测试断言，只会变成一条 ``enrich_failed`` 记录。
    实测过：只靠抛异常时，"让 dry-run 照常调 enrich_targets"这条变异能存活。
    判据只能是 ``calls == []``。
    """

    name = "exploding_stub"
    applies_to = ["ip", "domain"]
    case_close_only = True
    active = False

    def __init__(self) -> None:
        self.calls: list[str] = []

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        self.calls.append(ep.value)
        raise AssertionError(f"这条路径不该发请求，却查了 {ep.kind}")


class _KeyGatedEnricher(BaseEnricher):
    name = "key_gated_stub"
    applies_to = ["ip"]
    case_close_only = True
    active = False
    required_env = ("FXAPK_SYNTHETIC_BATCH_KEY",)

    def enrich(self, ep: Endpoint) -> EnrichmentResult:
        return EnrichmentResult(provider=self.name, ok=True, data={"ip": ep.value})


# ---------------------------------------------------------------------------
# 目标解析
# ---------------------------------------------------------------------------


def test_classify_ip_and_domain() -> None:
    assert batch_enrich.classify_target("198.51.100.10") == batch_enrich.Target(
        value="198.51.100.10", kind="ip"
    )
    assert batch_enrich.classify_target("2001:db8::1") == batch_enrich.Target(
        value="2001:db8::1", kind="ip"
    )
    assert batch_enrich.classify_target("API.Example.COM") == batch_enrich.Target(
        value="api.example.com", kind="domain"
    )


def test_unclassifiable_lines_are_reported_not_guessed() -> None:
    """判不了型就如实记进 skipped，绝不猜测式拆解（URL/端口/路径）。"""
    targets, skipped = batch_enrich.parse_targets(
        "\n".join(
            [
                "198.51.100.10",
                "# 注释行",
                "// 另一种注释",
                "",
                "https://api.example.com/path",
                "not a target at all",
                "1.2.3",
            ]
        )
    )
    assert [t.value for t in targets] == ["198.51.100.10"]
    assert "https://api.example.com/path" in skipped
    assert "1.2.3" in skipped
    assert "# 注释行" not in skipped


def test_duplicate_targets_are_queried_once() -> None:
    targets, _ = batch_enrich.parse_targets(
        "198.51.100.10\n198.51.100.10\napi.example.com\nAPI.EXAMPLE.COM\n"
    )
    assert [t.value for t in targets] == ["198.51.100.10", "api.example.com"]


def test_parse_targets_tolerates_non_string() -> None:
    assert batch_enrich.parse_targets(None) == ([], [])


# ---------------------------------------------------------------------------
# 预算估算（dry-run 的全部实现）
# ---------------------------------------------------------------------------


def test_estimate_budget_never_calls_enrichers() -> None:
    """★估算只看 applies_to / required_env，物理上不碰富化器。"""
    targets, _ = batch_enrich.parse_targets("198.51.100.10\napi.example.com\n")
    exploding = _ExplodingEnricher()
    lines = batch_enrich.estimate_budget([*targets], [exploding], {})
    assert [line.status for line in lines] == ["would_query"]
    assert lines[0].targets == 2
    assert exploding.calls == []


def test_estimate_budget_marks_unconfigured_source_disabled() -> None:
    targets, _ = batch_enrich.parse_targets("198.51.100.10\n")
    lines = batch_enrich.estimate_budget([*targets], [_KeyGatedEnricher()], {})
    assert lines[0].status == "disabled"
    assert "FXAPK_SYNTHETIC_BATCH_KEY" in lines[0].reason
    assert batch_enrich.budget_total(lines) == 0


def test_estimate_budget_counts_only_applicable_kinds() -> None:
    targets, _ = batch_enrich.parse_targets("198.51.100.10\napi.example.com\n")
    lines = batch_enrich.estimate_budget(
        [*targets],
        [_KeyGatedEnricher()],
        {"FXAPK_SYNTHETIC_BATCH_KEY": "synthetic-not-a-real-key"},
    )
    # key_gated_stub 只吃 ip → 2 个目标里只算 1 个
    assert lines[0].status == "would_query"
    assert lines[0].targets == 1


def test_budget_lines_are_deterministically_ordered() -> None:
    targets, _ = batch_enrich.parse_targets("198.51.100.10\n")
    lines = batch_enrich.estimate_budget(
        [*targets], [_KeyGatedEnricher(), _CountingEnricher()], {}
    )
    assert [line.provider for line in lines] == ["counting_stub", "key_gated_stub"]


# ---------------------------------------------------------------------------
# 账本 / 续跑
# ---------------------------------------------------------------------------


def test_read_ledger_collects_completed_targets(tmp_path: Path) -> None:
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(
        json.dumps({"target": "198.51.100.10", "source_status": {"a": "hit"}})
        + "\n"
        + json.dumps({"target": "api.example.com", "source_status": {"b": "no_record"}})
        + "\n",
        encoding="utf-8",
    )
    assert batch_enrich.read_ledger(ledger) == {
        "198.51.100.10": {"a"},
        "api.example.com": {"b"},
    }


def test_read_ledger_retries_failed_disabled_and_skipped_sources(tmp_path: Path) -> None:
    """未成功的 source 不能永久封死目标；补 key 或瞬时故障恢复后要能重试。"""
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(
        json.dumps(
            {
                "target": "198.51.100.10",
                "source_status": {
                    "ok": "hit",
                    "failed": "failed",
                    "disabled": "disabled",
                    "skipped": "skipped",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert batch_enrich.read_ledger(ledger) == {"198.51.100.10": {"ok"}}


def test_read_ledger_accepts_canonical_object_source_status(tmp_path: Path) -> None:
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(
        json.dumps(
            {
                "target": "198.51.100.10",
                "source_status": {
                    "rdap": {"status": "hit"},
                    "fofa": {"status": "failed", "error_type": "timeout"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert batch_enrich.read_ledger(ledger) == {"198.51.100.10": {"rdap"}}


def test_read_ledger_tolerates_corruption(tmp_path: Path) -> None:
    """账本损坏最坏结果是重查一次，绝不能中断整轮。"""
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(
        "not json\n"
        + json.dumps({"no_target_key": 1})
        + "\n"
        + json.dumps({"target": "198.51.100.10", "source_status": {"a": "hit"}})
        + "\n",
        encoding="utf-8",
    )
    assert batch_enrich.read_ledger(ledger) == {"198.51.100.10": {"a"}}


def test_ledger_rejects_nonfinite_constants_and_overflowing_floats(tmp_path: Path) -> None:
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(
        '{"target":"198.51.100.10","source_status":{"a":"hit"}}\n'
        '{"target":"198.51.100.11","score":NaN,"source_status":{"b":"hit"}}\n'
        '{"target":"198.51.100.12","score":1e9999,"source_status":{"c":"hit"}}\n'
        '{"target":"198.51.100.13","source_status":{"d":"no_record"}}\n',
        encoding="utf-8",
    )

    records, bad_lines = batch_enrich.read_ledger_records(ledger)

    assert [record["target"] for record in records] == [
        "198.51.100.10",
        "198.51.100.13",
    ]
    assert bad_lines == 2


def test_ndjson_writer_refuses_nonfinite_values(tmp_path: Path) -> None:
    from apkscan.commands import enrich as enrich_cmd

    ledger = tmp_path / "enrich.ndjson"

    with pytest.raises(ValueError, match="JSON"):
        enrich_cmd._append_ndjson([{"target": "198.51.100.10", "score": float("nan")}], ledger)

    assert ledger.read_text(encoding="utf-8") == ""


def test_read_ledger_missing_file_is_empty(tmp_path: Path) -> None:
    assert batch_enrich.read_ledger(tmp_path / "nope.ndjson") == {}


# ---------------------------------------------------------------------------
# 富化调度与序列化
# ---------------------------------------------------------------------------


def test_enrich_targets_includes_case_close_sources() -> None:
    """★批量入口必须开 include_case_close，否则 key-gated 源根本不跑、入口失去意义。"""
    targets, _ = batch_enrich.parse_targets("198.51.100.10\n")
    stub = _CountingEnricher()
    records = batch_enrich.enrich_targets([*targets], [stub])
    assert stub.calls == ["198.51.100.10"]
    assert records[0]["target"] == "198.51.100.10"
    assert records[0]["source_status"]["counting_stub"] == {"status": "hit"}
    assert records[0]["enrichment"]["counting_stub"]["observed"] == "198.51.100.10"


def test_enrich_targets_outer_failure_records_typed_status_for_each_pending_provider(
    monkeypatch,
) -> None:  # noqa: ANN001
    targets, _ = batch_enrich.parse_targets("198.51.100.10\n")
    first = _CountingEnricher()
    first.name = "provider_a"
    second = _CountingEnricher()
    second.name = "provider_b"

    def explode(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("synthetic outer failure")

    monkeypatch.setattr("apkscan.core.enrichment.enrich_selected_targets", explode)

    records = batch_enrich.enrich_targets([*targets], [first, second])

    assert records[0]["source_status"] == {
        "provider_a": {"status": "failed", "error_type": "enrich_failed"},
        "provider_b": {"status": "failed", "error_type": "enrich_failed"},
    }
    assert records[0]["enrichment"] == {}


def test_resume_queries_only_providers_missing_from_ledger(tmp_path: Path) -> None:
    """补 key/新增源时只补该源，已完成的付费查询不重复烧配额。"""
    targets, _ = batch_enrich.parse_targets("198.51.100.10\n")
    first = _CountingEnricher()
    first.name = "provider_a"
    initial = batch_enrich.enrich_targets([*targets], [first])
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_text(json.dumps(initial[0]) + "\n", encoding="utf-8")

    provider_a = _CountingEnricher()
    provider_a.name = "provider_a"
    provider_b = _CountingEnricher()
    provider_b.name = "provider_b"
    records = batch_enrich.enrich_targets(
        [*targets],
        [provider_a, provider_b],
        completed=batch_enrich.read_ledger(ledger),
    )

    assert provider_a.calls == []
    assert provider_b.calls == ["198.51.100.10"]
    assert records[0]["source_status"] == {"provider_b": {"status": "hit"}}


def test_csv_has_one_column_per_source() -> None:
    records = [
        {
            "target": "198.51.100.10",
            "kind": "ip",
            "source_status": {"b_src": "hit", "a_src": "no_record"},
            "enrichment": {"b_src": {"asn": 64500}, "a_src": {}},
        },
        {
            "target": "api.example.com",
            "kind": "domain",
            "source_status": {"a_src": "hit"},
            "enrichment": {"a_src": {"org": "Synthetic Provider"}},
        },
    ]
    assert batch_enrich.csv_columns(records) == ["target", "kind", "a_src", "b_src"]
    rows = batch_enrich.records_to_csv_rows(records)
    assert json.loads(rows[0]["a_src"]) == {"status": "no_record", "data": {}}
    assert json.loads(rows[0]["b_src"]) == {"status": "hit", "data": {"asn": 64500}}
    # 该源没跑 → 空单元格，不编造状态
    assert rows[1]["b_src"] == ""


def test_csv_flattens_canonical_status_metadata_and_reads_legacy_strings() -> None:
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "198.51.100.10",
                "kind": "ip",
                "source_status": {
                    "legacy": "no_record",
                    "canonical": {
                        "status": "failed",
                        "error_type": "timeout",
                        "reason": "upstream unavailable",
                    },
                },
                "enrichment": {},
            }
        ]
    )

    assert json.loads(rows[0]["legacy"]) == {"status": "no_record", "data": None}
    assert json.loads(rows[0]["canonical"]) == {
        "status": "failed",
        "error_type": "timeout",
        "reason": "upstream unavailable",
        "data": None,
    }


def test_csv_never_emits_nonfinite_provider_json() -> None:
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "198.51.100.10",
                "kind": "ip",
                "source_status": {"provider": {"status": "hit"}},
                "enrichment": {"provider": {"score": float("nan")}},
            }
        ]
    )

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite constant: {value}")

    decoded = json.loads(rows[0]["provider"], parse_constant=reject_constant)
    assert decoded == {
        "status": "failed",
        "error_type": "invalid_payload",
        "reason": "provider payload is not strict JSON",
        "data": None,
    }


def test_csv_never_stringifies_arbitrary_provider_objects() -> None:
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "198.51.100.10",
                "kind": "ip",
                "source_status": {"provider": {"status": "hit"}},
                "enrichment": {"provider": {"opaque": object()}},
            }
        ]
    )

    assert json.loads(rows[0]["provider"]) == {
        "status": "failed",
        "error_type": "invalid_payload",
        "reason": "provider payload is not strict JSON",
        "data": None,
    }


def test_csv_rows_neutralize_formula_injection() -> None:
    """★CSV 值来自外部响应；``=``/``+``/``@`` 开头的单元格在 Excel 里会被当公式执行。"""
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "=cmd|'/c calc'!A1",
                "kind": "domain",
                "source_status": {"s": "hit"},
                "enrichment": {"s": {"value": "@SUM(1)"}},
            }
        ]
    )
    assert rows[0]["target"].startswith("'=")
    assert json.loads(rows[0]["s"])["data"]["value"] == "@SUM(1)"


def test_csv_merges_append_only_events_into_one_target_row() -> None:
    """A 先完成、B 后补跑时，CSV 应是一行两列，不是同一目标两行。"""
    records = [
        {
            "target": "198.51.100.10",
            "kind": "ip",
            "source_status": {"a": "hit"},
            "enrichment": {"a": {"asn": 64500}},
        },
        {
            "target": "198.51.100.10",
            "kind": "ip",
            "source_status": {"b": "no_record"},
            "enrichment": {"b": {}},
        },
    ]

    rows = batch_enrich.records_to_csv_rows(records)

    assert len(rows) == 1
    assert json.loads(rows[0]["a"])["data"] == {"asn": 64500}
    assert json.loads(rows[0]["b"])["status"] == "no_record"


# ---------------------------------------------------------------------------
# CLI 端到端
# ---------------------------------------------------------------------------


def _write_targets(tmp_path: Path) -> Path:
    listing = tmp_path / "targets.txt"
    listing.write_text("198.51.100.10\napi.example.com\n", encoding="utf-8")
    return listing


def test_cli_dry_run_is_the_default_and_sends_no_request(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """★不加参数就是 dry-run；用会抛的 stub 证明它真的没发请求。"""
    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(_write_targets(tmp_path)), "--out", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["resume_complete"] is True
    assert payload["safe_to_execute"] is True
    assert payload["budget_reliable"] is True
    assert payload["estimated_requests"] == 2
    # ★闸门本体：一个请求都没发。（不能靠 stub 抛异常来证明——见 _ExplodingEnricher 注释）
    assert exploding.calls == []
    # dry-run 不得落盘
    assert not (tmp_path / "enrich.csv").exists()
    assert not (tmp_path / "enrich.ndjson").exists()


def test_cli_real_run_writes_csv_and_ndjson(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        [
            "enrich",
            "batch",
            "--targets",
            str(_write_targets(tmp_path)),
            "--out",
            str(tmp_path),
            "--no-dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is False
    assert payload["processed"] == 2
    assert stub.calls == ["198.51.100.10", "api.example.com"]

    with open(tmp_path / "enrich.csv", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["target"] for row in rows] == ["198.51.100.10", "api.example.com"]
    assert json.loads(rows[0]["counting_stub"]) == {
        "status": "hit",
        "data": {"observed": "198.51.100.10"},
    }

    detail = [
        json.loads(line)
        for line in (tmp_path / "enrich.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [item["target"] for item in detail] == ["198.51.100.10", "api.example.com"]
    assert detail[0]["enrichment"]["counting_stub"]["observed"] == "198.51.100.10"


def test_cli_resume_skips_completed_targets(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """★第二次运行必须一个请求都不发（续跑账本生效）。"""
    listing = _write_targets(tmp_path)
    first = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [first])
    assert runner.invoke(
        cli.app, ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"]
    ).exit_code == 0
    assert len(first.calls) == 2

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])
    second = runner.invoke(
        cli.app, ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"]
    )

    assert second.exit_code == 0, second.output
    payload = json.loads(second.output)
    assert payload["already_done_skipped"] == 2
    assert payload["will_process"] == 0
    # ★续跑闸门本体：第二轮一个请求都没发
    assert exploding.calls == []
    # ★逐源状态不得把「查过了」报成「不吃这种目标」：二者都是本次 0 请求，含义却相反。
    #   曾经共用 `matched == 0` 一个分支，于是一个只吃 ip 的源、目标就是 IP、上轮刚查成功，
    #   却被标成 not_applicable「只吃 ip」——理由自己自相矛盾，读的人无从判断预算对不对。
    done = [b for b in payload["budget"] if b["status"] == "already_done"]
    assert done, "已完成的源没有 already_done 状态"
    for line in done:
        assert "已在续跑账本里完成" in line["reason"]
    assert not [
        b for b in payload["budget"]
        if b["status"] == "not_applicable" and "只吃 ip" in (b.get("reason") or "")
    ], "适用的 ip 源被错标成 not_applicable"


def test_cli_tolerates_corrupt_ledger_when_refreshing_csv(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """坏的历史行不能在请求完成后让 CSV 刷新失败、诱发下一轮重复查询。"""
    listing = _write_targets(tmp_path)
    (tmp_path / "enrich.ndjson").write_text("not-json\n", encoding="utf-8")
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ledger_bad_lines_skipped"] == 1
    assert (tmp_path / "enrich.csv").is_file()


def test_cli_no_resume_requeries(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    listing = _write_targets(tmp_path)
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])
    args = ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"]
    runner.invoke(cli.app, args)
    runner.invoke(cli.app, [*args, "--no-resume"])
    assert len(stub.calls) == 4


def test_cli_max_targets_caps_a_single_run(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """单次运行上限是多数源不自限频时唯一的兜底闸门。"""
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        [
            "enrich",
            "batch",
            "--targets",
            str(_write_targets(tmp_path)),
            "--out",
            str(tmp_path),
            "--no-dry-run",
            "--max-targets",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["will_process"] == 1
    assert payload["over_max_targets"] == 1
    assert len(stub.calls) == 1


def test_cli_max_targets_cannot_bypass_absolute_batch_cap(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        [
            "enrich",
            "batch",
            "--targets",
            str(_write_targets(tmp_path)),
            "--out",
            str(tmp_path),
            "--no-dry-run",
            "--max-targets",
            str(batch_enrich.DEFAULT_MAX_TARGETS + 1),
        ],
    )

    assert result.exit_code == 2
    assert stub.calls == []


def test_cli_active_enrichers_are_never_used(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """★批量入口只纳入 ``active=False`` 源；第三方查询披露边界由各源说明。"""

    class _ActiveEnricher(BaseEnricher):
        name = "active_stub"
        applies_to = ["ip", "domain"]
        active = True

        def enrich(self, ep: Endpoint) -> EnrichmentResult:
            raise AssertionError("主动源绝不能被批量入口调用")

    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [_ActiveEnricher()])

    result = runner.invoke(
        cli.app,
        [
            "enrich",
            "batch",
            "--targets",
            str(_write_targets(tmp_path)),
            "--out",
            str(tmp_path),
            "--no-dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["budget"] == []


def test_cli_missing_targets_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["enrich", "batch", "--targets", str(tmp_path / "nope.txt"), "--out", str(tmp_path)]
    )
    assert result.exit_code == 2


def test_cli_empty_target_list_exits_2(tmp_path: Path) -> None:
    listing = tmp_path / "targets.txt"
    listing.write_text("# 全是注释\n\n", encoding="utf-8")
    result = runner.invoke(
        cli.app, ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path)]
    )
    assert result.exit_code == 2


def test_enrich_subcommand_is_registered_on_the_main_app() -> None:
    """★信号必须接线：子命令真的挂在主 app 上，不是只写了个模块。"""
    names = {group.name for group in cli.app.registered_groups}
    assert "enrich" in names


def test_cli_rebuilds_csv_from_ledger_when_nothing_is_pending(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """★账本在、CSV 丢了 → 必须纯本地重建，且**一个请求都不发**。

    NDJSON 是 append-only 事件账本，CSV 只是它的当前快照。两者会失同步（上一轮写 CSV 时
    磁盘满、或人只拿到 NDJSON）。此前 ``capped`` 为空就直接 return，于是：账本里明明有数据、
    CSV 却永久缺失 —— 因为续跑逻辑会一直判"都已完成"，再也不会走到写 CSV 那一步。
    删掉 ``_rebuild_csv_from_ledger`` 调用 → 本测试必红。
    """
    listing = _write_targets(tmp_path)
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])
    args = ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"]
    assert runner.invoke(cli.app, args).exit_code == 0
    assert len(stub.calls) == 2

    # 模拟 CSV 丢失/未落盘，账本完好。
    (tmp_path / "enrich.csv").unlink()

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])
    result = runner.invoke(cli.app, args)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["will_process"] == 0
    assert payload["csv_rebuilt"] is True
    # ★零配额：重建是纯本地行为，不得借机重查。
    assert exploding.calls == []

    with open(tmp_path / "enrich.csv", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["target"] for row in rows] == ["198.51.100.10", "api.example.com"]


def test_cli_rebuild_skips_bad_ledger_lines_without_failing(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """重建路径必须容错坏行：坏行只被跳过并计数，好行照常进 CSV。"""
    listing = _write_targets(tmp_path)
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])
    args = ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"]
    assert runner.invoke(cli.app, args).exit_code == 0

    ledger = tmp_path / "enrich.ndjson"
    with open(ledger, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("{not-json\n")
        handle.write("[1,2,3]\n")  # 合法 JSON 但不是 dict，同样算坏行
    (tmp_path / "enrich.csv").unlink()

    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["csv_rebuilt"] is True
    assert payload["ledger_bad_lines_skipped"] == 2

    with open(tmp_path / "enrich.csv", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["target"] for row in rows] == ["198.51.100.10", "api.example.com"]


def test_cli_does_not_create_empty_csv_when_no_ledger_exists(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    """账本压根不存在时不得凭空造一份空表头 CSV（那会被误读成"查过、无结果"）。"""
    listing = tmp_path / "targets.txt"
    listing.write_text("198.51.100.10\n", encoding="utf-8")

    class _Unconfigured(_CountingEnricher):
        name = "needs_key_stub"
        required_env = ("APKSCAN_TEST_MISSING_KEY_FOR_BATCH",)

    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [_Unconfigured()])
    monkeypatch.delenv("APKSCAN_TEST_MISSING_KEY_FOR_BATCH", raising=False)

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["csv_rebuilt"] is False
    assert not (tmp_path / "enrich.csv").exists()


def test_csv_write_is_atomic_and_keeps_old_snapshot_on_failure(tmp_path: Path) -> None:
    """★写 CSV 中途失败：旧快照必须完好，且不留 ``.tmp`` 残骸。

    这份 CSV 是**全量重建**的（不是 append）。若直接 ``open(path,"w")``，写一半失败就把上一轮
    完整快照截成半截，而重建源里的 ``failed`` 记录下一轮会**重新花配额查**。
    做法用一个序列化时抛 OSError 的行来触发 DictWriter 写入中途失败。
    """
    from apkscan.commands import enrich as enrich_cmd

    csv_path = tmp_path / "enrich.csv"
    good = [{"target": "a"}, {"target": "b"}]
    enrich_cmd._write_csv(good, ["target"], csv_path)
    before = csv_path.read_bytes()

    class _Exploding:
        def __str__(self) -> str:
            raise OSError("disk full")

    with pytest.raises(OSError):
        enrich_cmd._write_csv(
            [{"target": "ok"}, {"target": _Exploding()}],  # type: ignore[list-item]
            ["target"],
            csv_path,
        )

    # 不变式：旧内容完整（未被截断），且同目录没有残留临时文件。
    assert csv_path.read_bytes() == before
    assert not list(tmp_path.glob("enrich.csv.*.tmp"))


def test_csv_rebuild_merges_provider_events_for_the_same_target(tmp_path: Path) -> None:
    """★同一 target 的多条 provider 事件必须合并成 CSV 里的**一行**。

    账本是 append-only：补一个新 key 后重跑，同一个 target 会再追加一条只含新 provider 的记录。
    若按行直出 CSV，同一个目标会出现多行、每行各缺一半列 —— 人工台账无法用。
    """
    from apkscan.commands import enrich as enrich_cmd

    ledger = tmp_path / "enrich.ndjson"
    csv_path = tmp_path / "enrich.csv"
    rows = [
        {"target": "api.example.com", "kind": "domain",
         "source_status": {"src_a": "hit"}, "enrichment": {"src_a": {"asn": "AS64496"}}},
        {"target": "api.example.com", "kind": "domain",
         "source_status": {"src_b": "no_record"}, "enrichment": {"src_b": {}}},
    ]
    with open(ledger, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    assert enrich_cmd._rebuild_csv_from_ledger(ledger, csv_path) == 0

    with open(csv_path, encoding="utf-8-sig", newline="") as handle:
        out = list(csv.DictReader(handle))
    assert len(out) == 1, "同一 target 的多条 provider 事件应合并为一行"
    assert out[0]["target"] == "api.example.com"
    assert json.loads(out[0]["src_a"])["status"] == "hit"
    assert json.loads(out[0]["src_b"])["status"] == "no_record"


# ---------------------------------------------------------------------------
# CSV 快照：provider 单元格必须成对取最后一次事件（Codex 复核 #1）
# ---------------------------------------------------------------------------


def test_csv_latest_event_replaces_status_and_data_together() -> None:
    """★``--no-resume`` 重查把 hit 覆盖成 no_record 时，旧 payload 必须一并清掉。

    分别 ``update`` status / enrichment 是错的：第二条事件的 ``enrichment`` 里压根没有该
    provider 键，旧 payload 于是留存，CSV 单元格成了「查无记录、却带着上一次的数据」——
    人工照它写进线索清单等于伪造证据。
    """
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "198.51.100.9",
                "kind": "ip",
                "source_status": {"src_a": "hit"},
                "enrichment": {"src_a": {"asn": "AS64496", "stale": True}},
            },
            {
                "target": "198.51.100.9",
                "kind": "ip",
                "source_status": {"src_a": "no_record"},
                "enrichment": {},
            },
        ]
    )
    assert len(rows) == 1
    cell = json.loads(rows[0]["src_a"])
    assert cell["status"] == "no_record"
    assert not cell["data"], f"查无记录却仍带上一次的 payload：{cell['data']!r}"


def test_csv_failed_event_clears_previous_payload() -> None:
    """failed / 无归一化响应同理：状态换了，数据不许留在格子里。"""
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "example.test",
                "kind": "domain",
                "source_status": {"src_a": "hit"},
                "enrichment": {"src_a": {"org": "OldOrg"}},
            },
            {
                "target": "example.test",
                "kind": "domain",
                "source_status": {"src_a": "failed"},
                "enrichment": {"src_a": None},
            },
        ]
    )
    cell = json.loads(rows[0]["src_a"])
    assert cell["status"] == "failed"
    assert cell["data"] is None, "失败事件不得沿用旧数据"


def test_csv_untouched_provider_keeps_its_completed_result() -> None:
    """★反向不变量：本次事件**没提到**的 provider 保持原样。

    补 key 后只跑缺失源，不能把已完成的其它源抹掉（否则续跑会白烧配额重查）。
    """
    rows = batch_enrich.records_to_csv_rows(
        [
            {
                "target": "198.51.100.10",
                "kind": "ip",
                "source_status": {"src_a": "hit"},
                "enrichment": {"src_a": {"asn": "AS64496"}},
            },
            {
                "target": "198.51.100.10",
                "kind": "ip",
                "source_status": {"src_b": "no_record"},
                "enrichment": {},
            },
        ]
    )
    assert json.loads(rows[0]["src_a"]) == {"status": "hit", "data": {"asn": "AS64496"}}
    assert json.loads(rows[0]["src_b"])["status"] == "no_record"


def test_csv_no_record_then_hit_adopts_the_new_payload() -> None:
    """另一个方向：先 no_record 后 hit（补了 key），必须采用新 payload。"""
    rows = batch_enrich.records_to_csv_rows(
        [
            {"target": "198.51.100.11", "kind": "ip",
             "source_status": {"src_a": "no_record"}, "enrichment": {}},
            {"target": "198.51.100.11", "kind": "ip",
             "source_status": {"src_a": "hit"}, "enrichment": {"src_a": {"asn": "AS64500"}}},
        ]
    )
    cell = json.loads(rows[0]["src_a"])
    assert cell["status"] == "hit" and cell["data"] == {"asn": "AS64500"}


# ---------------------------------------------------------------------------
# 账本有界读取：坏字节只毒它自己那一行 + 三道硬上限可见
# ---------------------------------------------------------------------------


def _ledger_line(target: str, provider: str, status: str = "hit") -> bytes:
    return (
        json.dumps({"target": target, "kind": "ip", "source_status": {provider: status}}).encode(
            "utf-8"
        )
        + b"\n"
    )


def test_invalid_utf8_line_does_not_wipe_the_whole_ledger(tmp_path: Path) -> None:
    """★最小复现（修复前必红）：``有效行 + 非法 UTF-8 行 + 有效行``。

    此前 ``read_text(encoding="utf-8")`` 整份解码失败 → ``records=[]、bad_lines=0``：
    两条**已完成**记录凭空消失、坏文件这件事还完全不可见，下一轮把所有 provider 重查一遍
    （真花配额），并继续往这份坏文件后面 append。现在坏字节只毒它自己那一行。
    """
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        _ledger_line("198.51.100.10", "fofa")
        + b'{"target": "\xff\xfe bad bytes", "source_status": {"x": "hit"}}\n'
        + _ledger_line("198.51.100.11", "otx")
    )

    records, bad = batch_enrich.read_ledger_records(ledger)

    assert [record["target"] for record in records] == ["198.51.100.10", "198.51.100.11"], (
        "一行非法 UTF-8 把整份账本的有效记录全带走了"
    )
    assert bad == 1, "非法 UTF-8 行必须如实计入坏行数，不能显示成『账本干净』"


def test_invalid_utf8_line_keeps_resume_state_so_no_requery(tmp_path: Path) -> None:
    """★配额面：坏字节之后，续跑判据仍要认得那些已完成的 provider。"""
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        _ledger_line("198.51.100.10", "fofa")
        + b"\xff\xfe\n"
        + _ledger_line("api.example.com", "otx", "no_record")
    )

    assert batch_enrich.read_ledger(ledger) == {
        "198.51.100.10": {"fofa"},
        "api.example.com": {"otx"},
    }


def test_bad_json_line_between_valid_lines_is_counted_and_skipped(tmp_path: Path) -> None:
    """坏 JSON（非法字节之外的另一种坏行）同样只毒自己那一行。"""
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        _ledger_line("198.51.100.10", "fofa")
        + b"{not json at all\n"
        + b"[1, 2, 3]\n"  # 合法 JSON 但不是 dict
        + _ledger_line("198.51.100.11", "otx")
    )

    records, bad = batch_enrich.read_ledger_records(ledger)

    assert [record["target"] for record in records] == ["198.51.100.10", "198.51.100.11"]
    assert bad == 2


def test_overlong_line_is_bounded_and_does_not_hide_valid_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★单行上限：一条被写坏/被拼接的巨行不得把整份账本拖垮，也不得吃掉有效行。

    阈值取 256：正常账本行 ~76 字节要**照常读回**，只有那条 4KB 巨行该被丢。设得比正常行
    还小就测不出"只丢巨行"这件事（全都成了超长行）。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_LINE_BYTES", 256)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        _ledger_line("198.51.100.10", "fofa")
        + b'{"target": "' + b"A" * 4096 + b'"}\n'
        + _ledger_line("198.51.100.11", "otx")
    )

    scan = batch_enrich.scan_ledger(ledger)

    assert [record["target"] for record in scan.records] == [
        "198.51.100.10",
        "198.51.100.11",
    ], "超长行把它后面的有效行也带走了"
    assert scan.bad_lines == 1, "超长行必须计坏行"
    assert any("行" in message for message in scan.limit_warnings), (
        "单行超限没有出现在告警里"
    )


def test_ledger_byte_cap_truncates_with_a_visible_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★总字节上限：超限要**截断并告警**，绝不能清空成"全部未完成"。

    截断保住前半截完成记录（少花配额），告警让"账本没读全"这件事看得见——两者缺一
    都会退化成静默失忆或静默重查。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_BYTES", 200)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(b"".join(_ledger_line(f"198.51.100.{i}", "fofa") for i in range(40)))

    scan = batch_enrich.scan_ledger(ledger)

    assert scan.records, "超限被读成空账本 → 下一轮所有 provider 全部重查"
    assert len(scan.records) < 40, "总字节上限没有真的封顶"
    assert any("上限" in message for message in scan.limit_warnings)
    # 截断是前缀截断，保序可复现（同一份账本两次读结果一致）。
    assert [r["target"] for r in scan.records] == [
        r["target"] for r in batch_enrich.scan_ledger(ledger).records
    ]


def test_ledger_record_cap_truncates_with_a_visible_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★记录数上限：对象数量这一维也要有闸门，且同样可见。"""
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 5)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(b"".join(_ledger_line(f"198.51.100.{i}", "fofa") for i in range(20)))

    scan = batch_enrich.scan_ledger(ledger)

    assert len(scan.records) == 5
    assert any("上限" in message for message in scan.limit_warnings)


def test_ledger_over_limit_is_visible_in_the_cli_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★超限必须走到人看得见的出口：CLI 摘要里要有 ``ledger_limit_warnings``。

    只在函数返回值里留告警等于没有——"怎么又查了一遍"是唯一症状，而它长得跟正常首轮一样。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 1)
    listing = _write_targets(tmp_path)
    (tmp_path / "enrich.ndjson").write_bytes(
        b"".join(_ledger_line(f"198.51.100.{i}", "counting_stub") for i in range(10))
    )
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload.get("ledger_limit_warnings"), "账本超限在 CLI 摘要里完全看不见"


def test_cli_recovers_from_bad_bytes_without_requerying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★端到端配额面：账本里混进非法字节后，已完成目标**一个请求都不许再发**。

    修复前这里会退化成"整份账本失忆 → 两个目标全部重查"，本断言必红。
    """
    listing = _write_targets(tmp_path)
    ledger = tmp_path / "enrich.ndjson"
    first = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [first])
    assert runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    ).exit_code == 0
    assert len(first.calls) == 2

    # 外部工具/写盘中断在账本尾部留下一行非法字节。
    with open(ledger, "ab") as handle:
        handle.write(b"\xff\xfe partial\n")

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])
    second = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )

    assert second.exit_code == 0, second.output
    payload = json.loads(second.output)
    assert payload["already_done_skipped"] == 2, "坏字节让已完成目标被判为未完成"
    assert exploding.calls == [], "坏字节导致重复烧配额"
    assert payload["ledger_bad_lines_skipped"] == 1, "坏行数没有如实上报"


# ---------------------------------------------------------------------------
# 账本读不全 → 联网前 fail closed（不许边告警边继续烧配额）
# ---------------------------------------------------------------------------


def test_scan_ledger_marks_resume_incomplete_only_when_records_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★``resume_incomplete`` 的语义边界：只有「后半段记录看不见」才置真。

    这三档必须区分开，否则 fail-closed 会拦错人：
    - 总字节 / 记录数上限 → 扫描**中途 break**，后面的完成记录集体不可见 → 真；
    - 超长**单行** → 只毒那一行，其余照常读完，续跑判据仍完整 → 假；
    - 正常账本 → 假。
    """
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(b"".join(_ledger_line(f"198.51.100.{i}", "fofa") for i in range(20)))
    assert batch_enrich.scan_ledger(ledger).resume_incomplete is False

    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 5)
    assert batch_enrich.scan_ledger(ledger).resume_incomplete is True
    monkeypatch.undo()

    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_BYTES", 200)
    assert batch_enrich.scan_ledger(ledger).resume_incomplete is True
    monkeypatch.undo()

    # 超长单行：坏行照常计数，但**不**置 resume_incomplete。
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_LINE_BYTES", 256)
    huge = tmp_path / "huge.ndjson"
    huge.write_bytes(
        _ledger_line("198.51.100.1", "fofa")
        + b'{"target":"' + b"A" * 4096 + b'"}\n'
        + _ledger_line("198.51.100.2", "fofa")
    )
    scan = batch_enrich.scan_ledger(huge)
    assert scan.bad_lines == 1
    assert scan.resume_incomplete is False, "超长单行不该触发 fail-closed（其余行读全了）"


def test_missing_ledger_is_a_first_run_not_an_incomplete_read(tmp_path: Path) -> None:
    """★账本不存在 = 首轮，绝不能置 ``resume_incomplete``。

    置真会让**每一次全新运行**都被 fail-closed 拦死（而首轮压根没有已完成记录可丢）。
    """
    scan = batch_enrich.scan_ledger(tmp_path / "never_written.ndjson")
    assert scan.records == []
    assert scan.resume_incomplete is False


def test_real_run_fails_closed_before_any_network_call_when_ledger_over_record_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★核心回归：非 dry-run + 账本记录数超限 → **零**请求、账本**零**追加、exit 2。

    修复前的行为：只塞一条告警进摘要，然后照常联网富化并 append。危害是**永久性**的——
    账本里看不见的那批 provider 每轮都被重查一遍，而新记录继续把账本推长，
    下一轮更早触发上限、重查得更多。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 3)
    listing = _write_targets(tmp_path)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        b"".join(_ledger_line(f"198.51.100.{i}", "counting_stub") for i in range(20))
    )
    before = ledger.read_bytes()

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )

    assert result.exit_code == 2, f"账本读不全必须 fail closed，实际 {result.exit_code}"
    assert exploding.calls == [], "★账本读不全却仍发了请求（重复烧配额）"
    assert ledger.read_bytes() == before, "fail-closed 路径不得追加账本"
    payload = json.loads(result.output)
    assert payload["resume_incomplete"] is True
    assert payload["error"], "必须给出清晰的中止原因"
    assert payload["recovery"], "必须给出可执行的恢复指引"
    recovery = "\n".join(payload["recovery"])
    assert "完成状态不可见" in recovery, "归档会丢失 resume 可见性，恢复文案必须明确警告"
    assert "可能重新查询" in recovery, "恢复文案必须明确警告可能重复消耗额度"
    assert "保留最新终态记录" in recovery, "必须给出安全离线压缩账本的原则"
    assert "resume_complete=true" in recovery, "真跑前必须要求 dry-run 确认账本可完整续跑"
    assert "被归档的完成记录不会丢" not in recovery, "不得承诺当前实现并不会读取的归档记录"


def test_real_run_fails_closed_when_ledger_over_byte_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★字节上限这一维同样必须 fail closed（两道上限各走一条 break 分支）。"""
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_BYTES", 200)
    listing = _write_targets(tmp_path)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        b"".join(_ledger_line(f"198.51.100.{i}", "counting_stub") for i in range(40))
    )
    before = ledger.read_bytes()

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )

    assert result.exit_code == 2
    assert exploding.calls == []
    assert ledger.read_bytes() == before


def test_dry_run_reports_over_limit_but_refuses_to_call_the_budget_trustworthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★dry-run 可以照常报告，但不得声称预算安全。

    账本没读全 → "已完成"集合残缺 → 估算出的请求数只会**偏低**。若此处仍打印
    "确认预算后加 --no-dry-run 真跑"，人会照着一个偏低的数字去授权真跑。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 2)
    listing = _write_targets(tmp_path)
    (tmp_path / "enrich.ndjson").write_bytes(
        b"".join(_ledger_line(f"198.51.100.{i}", "counting_stub") for i in range(20))
    )
    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])

    result = runner.invoke(
        cli.app, ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert exploding.calls == [], "dry-run 永远不许发请求"
    assert payload["resume_incomplete"] is True
    assert payload["resume_complete"] is False
    assert payload["safe_to_execute"] is False
    assert payload["budget_reliable"] is False
    assert payload["ledger_limit_warnings"]
    assert "确认预算后加" not in payload["note"], "账本读不全时不得声称预算可信"
    assert "不可信" in payload["note"]


def test_no_resume_is_the_documented_escape_hatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★``--no-resume`` 明确表示"我接受不跳过已完成目标"，故不被 fail-closed 拦。

    没有这条出路，超限账本会把命令彻底锁死（连"我知道会重花配额、就是要跑"都做不到）。
    """
    monkeypatch.setattr(batch_enrich, "MAX_LEDGER_RECORDS", 2)
    listing = _write_targets(tmp_path)
    (tmp_path / "enrich.ndjson").write_bytes(
        b"".join(_ledger_line(f"198.51.100.{i}", "counting_stub") for i in range(20))
    )
    stub = _CountingEnricher()
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [stub])

    result = runner.invoke(
        cli.app,
        [
            "enrich", "batch", "--targets", str(listing), "--out", str(tmp_path),
            "--no-dry-run", "--no-resume",
        ],
    )

    assert result.exit_code == 0, result.output
    assert stub.calls, "--no-resume 下应照常富化"


def test_healthy_ledger_still_skips_completed_targets_without_requerying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★fail-closed 不得误伤正常路径：坏行/坏 UTF-8 仍逐行容错，已完成记录不重查。"""
    listing = _write_targets(tmp_path)
    ledger = tmp_path / "enrich.ndjson"
    ledger.write_bytes(
        _ledger_line("198.51.100.10", "counting_stub")
        + b"{ not json at all\n"
        + b"\xff\xfe broken bytes\n"
        + _ledger_line("api.example.com", "counting_stub")
    )

    exploding = _ExplodingEnricher()
    exploding.name = "counting_stub"
    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", lambda: [exploding])

    result = runner.invoke(
        cli.app,
        ["enrich", "batch", "--targets", str(listing), "--out", str(tmp_path), "--no-dry-run"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload.get("resume_incomplete") is None, "正常坏行不该触发 fail-closed"
    assert payload["already_done_skipped"] == 2
    assert exploding.calls == [], "已完成目标被重查（烧配额）"
    assert payload["ledger_bad_lines_skipped"] == 2
