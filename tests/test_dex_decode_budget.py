from types import SimpleNamespace

from apkscan.core.dex_records import DecodeLimits, collect_dex_records


class Item:
    def __init__(self, value: bytes, offset: int = 123):
        self.data = value
        self.offset = offset
        self.calls = 0

    def get(self):
        self.calls += 1
        return self.data.decode()


def test_record_budget_precedes_decode_and_retains_partial_ledger():
    items = [Item(b"one"), Item(b"two")]
    records, ledger = collect_dex_records(
        [(SimpleNamespace(strings=items), {"member_path": "classes.dex"})],
        DecodeLimits(records=1),
    )
    assert [item.calls for item in items] == [1, 0]
    assert [record.value for record in records] == ["one"]
    assert records[0].locator == {"byte_offset": 123, "offset_unit": "dex-bytes"}
    assert ledger["status"] == "partial"
    assert ledger["members"][0]["reason_codes"] == ["record_count_budget"]


def test_oversized_item_never_calls_decoder():
    item = Item(b"x" * 10)
    records, ledger = collect_dex_records(
        [(SimpleNamespace(strings=[item]), {})], DecodeLimits(record_chars=50),
    )
    assert not records and item.calls == 0
    assert ledger["members"][0]["reason_codes"] == ["record_char_budget"]


def test_total_budget_precedes_decoder_and_exact_count_is_complete():
    items = [Item(b"one"), Item(b"two")]
    _, ledger = collect_dex_records(
        [(SimpleNamespace(strings=items), {})], DecodeLimits(total_chars=44),
    )
    assert [item.calls for item in items] == [1, 0]
    assert ledger["members"][0]["reason_codes"] == ["total_char_budget"]
    _, exact = collect_dex_records(
        [(SimpleNamespace(strings=[Item(b"one")]), {})], DecodeLimits(records=1),
    )
    assert exact["status"] == "complete"


def test_source_reordering_preserves_fair_schedule():
    sources = [
        (SimpleNamespace(strings=[Item(b"real")] * 3), {"member_path": "classes.dex"}),
        (SimpleNamespace(strings=[Item(b"decoy")] * 3), {"member_path": "classes2.dex"}),
    ]
    first, ledger = collect_dex_records(sources, DecodeLimits(records=2))
    second, _ = collect_dex_records(list(reversed(sources)), DecodeLimits(records=2))
    assert first == second
    assert {record.value for record in first} == {"real", "decoy"}
    assert ledger["status"] == "partial"


def test_iteration_failure_keeps_completed_records_and_reason():
    def items():
        yield Item(b"retained")
        raise ValueError("untrusted diagnostic text")

    records, ledger = collect_dex_records(
        [(SimpleNamespace(strings=items()), {})], DecodeLimits(),
    )
    assert records[0].value == "retained"
    row = ledger["members"][0]
    assert row["reason_codes"] == ["string_iteration_failed"]
    assert row["error_type"] == "ValueError"
    assert "untrusted diagnostic" not in str(ledger)
