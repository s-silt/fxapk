"""查询协议替身。不导入 ASC，也不把字节扫描称为 xref 引擎。

精确命中只转抄 dexgen 金标。找不到金标时不编造方法描述符。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tests.fixtures.dex_query.dexgen import ExpectedHit, build_dex, sample_classes, wide_classes

PINNED_VERSION = "0.1.1.post5"
PINNED_REVISION = "d3d75ab7a3c092345102d2ec66ab614ad4a6cc75"
PINNED_FINDREFS_SHA256 = "99f170737a2a9fb67e4a7a681b98fbc0f56d9e53601cb33f3125b37fd6487b7c"


def _hits_for(data_sha: str, queries: list[str]) -> tuple[ExpectedHit, ...]:
    candidates = [sample_classes(), wide_classes()]
    for query in queries:
        if query.startswith("api.") or query[:1].isdigit():
            candidates.append(sample_classes(query))
    for classes in candidates:
        built = build_dex(classes)
        if built.sha256 == data_sha:
            return built.hits
    return ()


def _result(op: str, **extra: object) -> None:
    payload = {
        "schema_version": "asc-worker-result/1",
        "provider": "asc",
        "provider_version": PINNED_VERSION,
        "provider_revision": PINNED_REVISION,
        "findrefs_sha256": PINNED_FINDREFS_SHA256,
        "op": op,
        # 替身不导入 mutf8。正式 worker 才实测 1.1.0 的 U+1F600。这里只满足核心要求的证明字段。
        "runtime_encoding": "mutf8-1.1.0",
    }
    payload.update(extra)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))


def main() -> None:
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    op = request.get("op")
    if op == "capabilities":
        _result("capabilities", engine_executed=False)
        return
    if op != "query":
        sys.exit(2)
    rows = []
    queries = [item for item in request.get("queries", []) if isinstance(item, str)]
    for member in request.get("members", []):
        data = Path(member["path"]).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        row = {
            "name": member.get("name"),
            "ordinal": member.get("ordinal"),
            "sha256": actual,
            "truncated": False,
            "hits": [],
        }
        if actual != member.get("sha256"):
            row.update(status="failed", reason="identity_mismatch", precision="unsupported")
        elif data.startswith(b"dex\n041"):
            row.update(status="unsupported", reason="dex_unsupported", precision="unsupported")
        elif not data.startswith(b"dex\n"):
            row.update(status="failed", reason="input_rejected", precision="unsupported")
        else:
            hits = []
            for hit in _hits_for(actual, queries):
                if hit.string not in queries:
                    continue
                hits.append({
                    "value_sha256": hashlib.sha256(hit.string.encode("utf-8")).hexdigest(),
                    "descriptor": hit.descriptor,
                    "offset": hit.code_unit_offset,
                    "offset_unit": "code_units",
                    "file_offset": hit.file_offset,
                    "precision": "exact",
                })
            row.update(
                status="hit" if hits else "no_match",
                reason=None if hits else "no_match",
                precision="exact",
                hits=hits,
            )
        rows.append(row)
    _result("query", engine_executed=True, members=rows)


if __name__ == "__main__":
    main()
