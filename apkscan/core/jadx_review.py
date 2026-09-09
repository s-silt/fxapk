"""Evidence summaries shared by CLI comparison and downstream case writing.

These functions report observations, differences and unavailable surfaces. They
do not turn similarity into a family or operator identity verdict.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from apkscan.core.corpus import manifest_entry, native_anchor_weakness
from apkscan.core.jadx_index import LoadedIndex
from apkscan.core.jadx_sources import digest_bytes
from apkscan.core.jadx_structure_diff import _read_structure, diff_index_structure


_COMPARISON_CAVEATS = (
        "Shared method text may be a public SDK, packer, copied code or common supplier.",
        "Changed names/obfuscation may prevent matching; unmatched regions do not exclude a family.",
        "Heuristic Java structure does not establish runtime execution, reflection or JNI targets.",
)


def compare_structure(left: LoadedIndex, right: LoadedIndex) -> dict[str, Any]:
    result = asdict(diff_index_structure(left, right))
    by_digest = []
    for index in (left, right):
        groups: dict[str, list[dict]] = defaultdict(list)
        for regions in _read_structure(index).values():
            for region in regions:
                groups[region.body_digest].append(asdict(region))
        by_digest.append(groups)
    # Match method regions even if the enclosing class/package/path changed.
    # Method text includes its declaration: obfuscated method renaming remains
    # an explicit limitation, never a negative family conclusion.
    shared = sorted(set(by_digest[0]) & set(by_digest[1]))
    result["shared_regions_across_paths"] = [
        {"body_digest": key, "left": by_digest[0][key][:50], "right": by_digest[1][key][:50],
         "left_count": len(by_digest[0][key]), "right_count": len(by_digest[1][key])}
        for key in shared[:500]
    ]
    result["shared_region_group_count"] = len(shared)
    result["comparison_truncated"] = len(shared) > 500 or any(
        len(side[key]) > 50 for side in by_digest for key in shared)
    result["operator_identity_asserted"] = False
    result["caveats"] = list(_COMPARISON_CAVEATS)
    return result


def compare_report_features(left: dict, right: dict) -> dict[str, Any]:
    entries = [manifest_entry(left), manifest_entry(right)]
    fields = ("sign_sha256", "native_lib_hashes", "build_environments", "remote_config_objects",
              "domains", "cname_edges")
    result: dict[str, Any] = {"operator_identity_asserted": False, "caveats": list(_COMPARISON_CAVEATS)}
    for field in fields:
        sets = []
        for entry in entries:
            value = entry.get(field)
            items = value if isinstance(value, list) else ([value] if value else [])
            sets.append({json.dumps(item, sort_keys=True, ensure_ascii=False) for item in items})
        result[field] = {"shared": [json.loads(v) for v in sorted(sets[0] & sets[1])],
                         "subject_only": [json.loads(v) for v in sorted(sets[0] - sets[1])],
                         "candidate_only": [json.loads(v) for v in sorted(sets[1] - sets[0])],
                         "coverage": "observed_report_fields_only"}
    native = []
    for entry in entries:
        groups: dict[str, list[dict]] = defaultdict(list)
        for item in entry.get("native_lib_hashes", []):
            if item.get("sha256"):
                groups[item["sha256"]].append(item)
        native.append(groups)
    result["native_sha256"] = {
        "shared": [{"sha256": sha, "subject": native[0][sha], "candidate": native[1][sha],
                    "weak_anchor_reasons": sorted({reason for item in native[0][sha] + native[1][sha]
                                                   if (reason := native_anchor_weakness(item.get("name", "")))})}
                   for sha in sorted(set(native[0]) & set(native[1]))],
        "subject_only": sorted(set(native[0]) - set(native[1])),
        "candidate_only": sorted(set(native[1]) - set(native[0])),
        "coverage": "observed_report_fields_only",
    }
    return result


def load_review_receipts(paths: list[Path], allowed_samples: set[str]) -> dict[str, Any]:
    """Consume exact, explicitly supplied receipts; never enumerate old cases."""
    receipts = []
    gaps = []
    seen: set[str] = set()
    for path in paths:
        try:
            with path.open("rb") as stream:
                raw = stream.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("receipt_size_limit")
            digest = digest_bytes(raw)
            if digest in seen:
                continue
            data = json.loads(raw)
            if data.get("schema") not in {"jadx-multi-query-1", "jadx-family-comparison-1"}:
                raise ValueError("receipt_schema_unsupported")
            sha = data.get("apk_sha256") or data.get("subject_sha256")
            if sha not in allowed_samples:
                raise ValueError("receipt_sample_mismatch")
            receipts.append({"receipt_sha256": digest, "data": data})
            seen.add(digest)
            if data.get("status") != "ok":
                gaps.append({"receipt_sha256": digest, "reason": "review_partial"})
            for item in data.get("results", []):
                if (item.get("status") != "ok" or item.get("query_coverage", item.get("coverage")) != "complete"
                        or item.get("reason_codes")):
                    gaps.append({"receipt_sha256": digest, "index_key": item.get("index_key"),
                                 "reason": "query_coverage_limited"})
        except (OSError, ValueError, AttributeError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and str(exc).startswith("receipt_") else "receipt_unreadable"
            gaps.append({"reason": reason})
    if not paths:
        gaps.append({"reason": "review_not_supplied"})
    return {"receipts": receipts, "gaps": gaps,
            "status": "ok" if receipts and not gaps else "partial"}


def review_markdown(review: dict) -> list[str]:
    """Facts and limitations for the existing draft, not a mandatory template."""
    lines = ["## JADX 查询与家族候选比较", ""]
    for receipt in review.get("receipts", []):
        data = receipt["data"]
        lines.append(f"- 回执 SHA-256：`{receipt['receipt_sha256']}`")
        if data.get("query_inputs"):
            lines.append("  查询输入（受控底稿）：" + json.dumps(data["query_inputs"], ensure_ascii=False))
        if data["schema"] == "jadx-multi-query-1":
            lines.append(f"  样本 `{data['apk_sha256']}`；查询类型 {data['query_type']}；索引数 {data['index_count']}。")
            for item in data["results"]:
                lines.append(f"  索引 `{item['index_key']}`：{item['status']}；"
                             f"索引命中 {len(item.get('hits', []))}、源码命中 {len(item.get('source_hits', []))}、"
                             f"路径 {len(item.get('paths', []))}；查询覆盖 {item.get('query_coverage', item.get('coverage', 'unknown'))}。")
                for hit in (item.get("hits", []) + item.get("source_hits", []))[:20]:
                    lines.append(f"  定位 `{hit['path']}:{hit['line']}:{hit['column']}`。")
                if len(item.get("hits", [])) + len(item.get("source_hits", [])) > 20:
                    lines.append("  其余定位见完整回执；此处仅摘录，不缩减证据范围。")
                if item.get("reason_codes") or item.get("reason"):
                    lines.append(f"  缺口：{item.get('reason_codes') or item.get('reason')}。")
        else:
            lines.append(f"  当前样本 `{data['subject_sha256']}`；候选 `{data['candidate_sha256']}`；{data['assessment']}。")
            for field, values in data["features"].items():
                if field in {"operator_identity_asserted", "caveats"}:
                    continue
                lines.append(f"  {field}：共同 {len(values['shared'])}、当前独有 {len(values['subject_only'])}、候选独有 {len(values['candidate_only'])}。")
                for label, name in (("共同", "shared"), ("当前独有", "subject_only"), ("候选独有", "candidate_only")):
                    for value in values[name][:10]:
                        lines.append(f"  {label}：{json.dumps(value, ensure_ascii=False, sort_keys=True)}")
                    if len(values[name]) > 10:
                        lines.append("  其余条目见完整回执。")
            for pair in data.get("index_comparisons", []):
                detail = pair.get("comparison", {})
                lines.append(f"  索引对 `{pair['subject_index_key']}` / `{pair['candidate_index_key']}`：{pair['status']}；"
                             f"共享方法区域组 {detail.get('shared_region_group_count', 'unknown')}。")
                for group in detail.get("shared_regions_across_paths", [])[:10]:
                    lines.append(f"  共同代码摘要 `{group['body_digest']}`："
                                 f"{json.dumps(group['left'], ensure_ascii=False)} ↔ {json.dumps(group['right'], ensure_ascii=False)}")
            lines.append("  以上是候选比较；需结合具体自有实现、差异与公共组件排除，不能据此认定同一运营者。")
    for gap in review.get("gaps", []):
        lines.append(f"- 待核：{gap['reason']}；仅限制依赖该材料的结论。")
    return lines + [""]
