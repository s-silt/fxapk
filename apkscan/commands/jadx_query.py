"""``fxapk jadx`` 只读查询子命令（P2-D1）：usage / callpath。

消费已建立的 JADX 持久索引，**绝不跑 jadx、绝不启动任何子进程**——纯 load + 内存查询。
输出一律 JSON：load 三态原样透出（ok/miss/unavailable，exit 0，机器可判）；参数语法
错误才非零退出。空结果显式输出并带「空≠不存在/不可达」caveat；reason 一律过稳定码
语法闸，路径与异常文本绝不进输出。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer

from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.jadx_sources import contained, digest_bytes, query_sources

from apkscan.core.jadx_callpath import CallPath, CallPathEdge, CallPathLimits, trace_callpath
from apkscan.core.jadx_index import (
    CacheMiss,
    CacheUnavailable,
    JadxIndexError,
    JadxIndexStore,
    LoadedIndex,
    UsageHit,
    find_value_usage,
)

_JADX_INDEX_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")

jadx_app = typer.Typer(
    add_completion=False,
    help="消费已建立的 JADX 持久索引，执行只读查询（绝不反编译）。",
)


def _stable_reason(value: object) -> str:
    """将缓存/异常原因收敛为不泄露路径和异常文本的稳定 code。"""
    if not isinstance(value, str):
        return "index_unavailable"
    lowered = value.lower()
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", lowered):
        return lowered
    return "index_unavailable"


def _reason_from_exception(exc: BaseException) -> str:
    """仅提取显式 code；绝不把异常文本透出到 CLI 输出。"""
    return _stable_reason(getattr(exc, "code", None))


def _validate_index_key(index_key: str) -> str:
    """key 语法校验必须早于 JadxIndexStore 构造——非法 key 不触碰文件系统。"""
    if not isinstance(index_key, str) or _JADX_INDEX_KEY_RE.fullmatch(index_key) is None:
        raise typer.BadParameter(
            "jadx index key 必须是 64 位小写十六进制",
            param_hint="--jadx-index",
        )
    return index_key


def _load_index(
    cache_root: Path, index_key: str
) -> tuple[LoadedIndex | None, dict[str, object] | None]:
    """加载索引并把非成功状态投影为 CLI JSON：(LoadedIndex, None) 或 (None, status 记录)。"""
    try:
        store = JadxIndexStore(cache_root)
        loaded = store.load_index(index_key)
    except JadxIndexError as exc:
        return None, {"status": "unavailable", "reason": _reason_from_exception(exc)}
    except Exception:  # noqa: BLE001 - 只读消费面，未知异常不泄露实现细节
        return None, {"status": "unavailable", "reason": "index_unavailable"}
    if isinstance(loaded, CacheMiss):
        return None, {"status": "miss", "reason": _stable_reason(loaded.reason)}
    if isinstance(loaded, CacheUnavailable):
        return None, {"status": "unavailable", "reason": _stable_reason(loaded.reason)}
    if not isinstance(loaded, LoadedIndex):
        return None, {"status": "unavailable", "reason": "index_unavailable"}
    return loaded, None


def _redact_values(obj: object, pattern: re.Pattern[str], token_for: dict[str, str]) -> object:
    """Redact input literals inside string values only; keys keep the schema so
    stdout stays machine-parseable even for one-character query values."""
    if isinstance(obj, str):
        return pattern.sub(lambda match: token_for[match.group()], obj)
    if isinstance(obj, dict):
        return {key: _redact_values(value, pattern, token_for) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_redact_values(item, pattern, token_for) for item in obj]
    return obj


def _emit(payload: dict[str, object], inputs: tuple[str, ...] = ()) -> None:
    projected: object = payload
    if inputs:
        # Longest first so overlapping inputs cannot resurface inside tokens.
        token_for = {
            value: f"<query-value-sha256:{digest_bytes(value.encode('utf-8'))[:12]}>"
            for value in inputs if value
        }
        if token_for:
            pattern = re.compile("|".join(
                re.escape(value) for value in sorted(token_for, key=lambda v: (-len(v), v))))
            projected = _redact_values(payload, pattern, token_for)
    typer.echo(json.dumps(projected, ensure_ascii=False, indent=2))


def _selection(cache: Path, key: str | None, apk_sha: str | None, mapping: Path | None):
    if bool(key) == bool(apk_sha):
        raise typer.BadParameter("指定 --jadx-index 或 --apk-sha256 二者之一")
    if key:
        if mapping:
            raise typer.BadParameter("--index-map 只用于 --apk-sha256")
        return [_validate_index_key(key)], {}
    assert apk_sha is not None
    if _JADX_INDEX_KEY_RE.fullmatch(apk_sha) is None:
        raise typer.BadParameter("--apk-sha256 必须是 64 位小写十六进制")
    path = mapping or cache / "fxapk-jadx-index-map.json"
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8-sig"))
        keys = []
        if not isinstance(data, dict) or not isinstance(data.get("records"), list):
            raise ValueError("invalid")
        for record in data["records"]:
            if not isinstance(record, dict):
                raise ValueError("invalid")
            alternates = record.get("alternate_indexes", [])
            if not isinstance(alternates, list) or any(
                not isinstance(item, dict) or "index_key" not in item for item in alternates
            ):
                raise ValueError("invalid")
            if record.get("apk_sha256") != apk_sha:
                continue
            keys.append(_validate_index_key(record["index_key"]))
            for alternate in record.get("alternate_indexes", []):
                keys.append(_validate_index_key(alternate["index_key"]))
        return list(dict.fromkeys(keys)), {"apk_sha256": apk_sha, "index_map_sha256": digest_bytes(raw)}
    except OSError as exc:
        raise typer.BadParameter("索引映射不可读或格式无效") from exc
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise typer.BadParameter("索引映射格式无效") from exc


def _save_emit(payload: dict, out: Path | None, inputs: tuple[str, ...] | None = None) -> None:
    if out is not None:
        saved = {**payload, "query_inputs": list(inputs)} if inputs is not None else payload
        raw = (json.dumps(saved, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if out.exists():
            if out.read_bytes() != raw:
                raise typer.BadParameter("输出已存在且内容不同；请为新查询指定新文件")
        elif not atomic_create_bytes(out, raw) and out.read_bytes() != raw:
            raise typer.BadParameter("输出已被另一操作写入；请指定新文件")
    _emit(payload, inputs or ())


def _query_one(cache: Path, key: str, kind: str, values: tuple[str, ...]) -> dict:
    binding: dict = {"schema": "jadx-query-receipt-1", "query_type": kind, "index_key": key,
               "query_input_sha256": digest_bytes(json.dumps(values, ensure_ascii=False).encode())}
    index, error = _load_index(cache, key)
    if error is not None or index is None:
        return {**binding, **(error or {"status": "unavailable"})}
    try:
        manifest = contained(cache, f"{key}/manifest.json").read_bytes()
        binding["index_manifest_sha256"] = digest_bytes(manifest)
        binding["dex_lineage"] = [item.to_record() for item in index.manifest.dex_lineage]
        if kind == "usage":
            records = [_usage_hit_record(hit) for hit in find_value_usage(index, values[0])]
            try:
                sources = query_sources(cache, key, values[0])
            except Exception:  # noqa: BLE001 - snapshot failure must preserve index hits
                sources = {"coverage": "partial", "hits": [], "snapshots": [],
                           "reason_codes": ["source_query_failed"]}
            reasons = sources["reason_codes"]
            return {**binding, "status": "ok", "coverage": index.coverage,
                    "query_coverage": sources["coverage"], "hits": records,
                    "source_hits": sources["hits"], "source_snapshots": sources["snapshots"],
                    "reason_codes": reasons,
                    "caveats": ([{"code": "empty_is_not_absence", "text": "空结果不证明不存在。"}]
                                if not records and not sources["hits"] else []) +
                               ([{"code": "query_value_coverage_unknown",
                                  "text": "旧索引仅覆盖建库时选定值；未覆盖值需查询源码快照或补充反编译。"}]
                                if not sources["snapshots"] else [])}
        limits = CallPathLimits()
        trace = trace_callpath(index, values[0], values[1], limits=limits)
        paths = [_path_record(path) for path in trace.paths]
        caveats = [{"code": "heuristic_not_method_binding",
                    "text": "name_unique 是简单名候选唯一，不证明方法绑定；反射、JNI 与动态分发需另核。"}]
        if not paths:
            caveats.append({"code": "no_path_is_not_unreachable", "text": "空路径不证明不可达。"})
        if any(edge.scope != "method" for path in trace.paths for edge in path.edges):
            caveats.append({"code": "nested_edge_is_not_direct_execution", "text": "嵌套体执行时机需另核。"})
        return {**binding, "status": "ok", "coverage": trace.coverage, "paths": paths,
                "gaps": [_edge_record(edge) for edge in trace.gaps],
                "reason_codes": list(trace.reason_codes),
                "limits": {name: getattr(limits, name) for name in
                           ("max_depth", "max_paths", "max_visited", "max_fanout", "max_gaps")},
                "caveats": caveats}
    except Exception as exc:  # noqa: BLE001 - keep other indexes queryable
        return {**binding, "status": "unavailable", "reason": _reason_from_exception(exc)}


def _query(cache: Path, key: str | None, apk_sha: str | None, mapping: Path | None,
           kind: str, values: tuple[str, ...], out: Path | None) -> None:
    if any(not value or len(value) > 8192 for value in values):
        raise typer.BadParameter("查询值不能为空或超过 8192 字符")
    keys, binding = _selection(cache, key, apk_sha, mapping)
    results = [_query_one(cache, item, kind, values) for item in keys]
    if key:
        payload = results[0]
    else:
        payload = {"schema": "jadx-multi-query-1", **binding, "query_type": kind,
                   "status": "ok" if results and all(r["status"] == "ok" for r in results) else "partial",
                   "index_count": len(keys), "results": results,
                   "reason_codes": [] if keys else ["apk_mapping_not_found"]}
    _save_emit(payload, out, inputs=values)


def _usage_hit_record(hit: UsageHit) -> dict[str, object]:
    """UsageHit → 输出形态（不用 asdict：避免未来新增字段被无审查地递归暴露）。"""
    return {
        "path": hit.relative_path,
        "line": hit.line,
        "column": hit.column,
        "value_digest": hit.value_digest,
        "lineage": hit.lineage.to_record(),
        "class_context": hit.class_context,
        "method_context": hit.method_context,
        "ownership": hit.ownership,
    }


def _edge_record(edge: CallPathEdge) -> dict[str, object]:
    return {
        "caller": edge.caller,
        "callee": edge.callee,
        "caller_path": edge.caller_path,
        "line": edge.line,
        "resolution": edge.resolution,
        "scope": edge.scope,
    }


def _path_record(path: CallPath) -> dict[str, object]:
    return {"nodes": list(path.nodes), "edges": [_edge_record(e) for e in path.edges]}


@jadx_app.command("usage")
def jadx_usage(
    value: str = typer.Argument(..., help="要查询的字符串值。"),
    jadx_cache_root: Path = typer.Option(..., "--jadx-cache-root"),
    jadx_index: str | None = typer.Option(None, "--jadx-index"),
    apk_sha256: str | None = typer.Option(None, "--apk-sha256", help="按原 APK SHA 查询主及全部备用索引。"),
    index_map: Path | None = typer.Option(None, "--index-map"),
    out: Path | None = typer.Option(None, "--out", help="保存不可覆盖的查询回执。"),
) -> None:
    """查询建库关注值及可用源码快照，分别报告查询覆盖。"""
    _query(jadx_cache_root, jadx_index, apk_sha256, index_map, "usage", (value,), out)


@jadx_app.command("callpath")
def jadx_callpath(
    source: str = typer.Argument(..., help="源端点，如 Alpha#start/0。"),
    target: str = typer.Argument(..., help="目标端点，如 Alpha#target/0。"),
    jadx_cache_root: Path = typer.Option(..., "--jadx-cache-root"),
    jadx_index: str | None = typer.Option(None, "--jadx-index"),
    apk_sha256: str | None = typer.Option(None, "--apk-sha256"),
    index_map: Path | None = typer.Option(None, "--index-map"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """查询已有索引中的有界启发式路径，保留每个索引的来源和缺口。"""
    _query(jadx_cache_root, jadx_index, apk_sha256, index_map, "callpath", (source, target), out)


@jadx_app.command("compare")
def jadx_compare(
    subject_report: Path = typer.Argument(..., exists=True),
    candidate_report: Path = typer.Argument(..., exists=True),
    jadx_cache_root: Path = typer.Option(..., "--jadx-cache-root"),
    index_map: Path | None = typer.Option(None, "--index-map"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """对照两份精确报告与主/备用索引；输出家族候选的共同点、差异和证据定位。"""
    from apkscan.core.corpus import sample_identity
    from apkscan.core.jadx_review import compare_report_features, compare_structure

    reports = []
    bindings = []
    keys = []
    for path in (subject_report, candidate_report):
        raw = path.read_bytes()
        report = json.loads(raw)
        sha, synthetic = sample_identity(report)
        if synthetic or _JADX_INDEX_KEY_RE.fullmatch(sha) is None:
            raise typer.BadParameter("比较报告必须含真实原 APK SHA-256")
        selected, binding = _selection(jadx_cache_root, None, sha, index_map)
        reports.append(report)
        bindings.append({**binding, "report_sha256": digest_bytes(raw)})
        keys.append(selected)
    pairs = []
    reasons = []
    # Preserve per-index failures; a broken alternate must not hide good data.
    for left in keys[0]:
        for right in keys[1]:
            if len(pairs) >= 64:
                if "comparison_pair_limit" not in reasons:
                    reasons.append("comparison_pair_limit")
                break
            item = {"subject_index_key": left, "candidate_index_key": right}
            a, a_error = _load_index(jadx_cache_root, left)
            b, b_error = _load_index(jadx_cache_root, right)
            if a is None or b is None:
                item.update(status="unavailable", errors=[a_error, b_error])
                reasons.append("comparison_index_unavailable")
            else:
                try:
                    comparison = compare_structure(a, b)
                    item.update(status="ok", comparison=comparison,
                                subject_manifest_sha256=digest_bytes(contained(jadx_cache_root, f"{left}/manifest.json").read_bytes()),
                                candidate_manifest_sha256=digest_bytes(contained(jadx_cache_root, f"{right}/manifest.json").read_bytes()))
                    if a.coverage != "complete" or b.coverage != "complete" or comparison["comparison_truncated"]:
                        reasons.append("comparison_partial")
                except (OSError, ValueError, JadxIndexError):
                    item.update(status="unavailable")
                    reasons.append("comparison_failed")
            pairs.append(item)
    if not pairs:
        reasons.append("comparison_indexes_missing")
    same = bindings[0]["apk_sha256"] == bindings[1]["apk_sha256"]
    payload = {"schema": "jadx-family-comparison-1",
               "subject_sha256": bindings[0]["apk_sha256"], "candidate_sha256": bindings[1]["apk_sha256"],
               "subject_binding": bindings[0], "candidate_binding": bindings[1],
               "status": "partial" if reasons else "ok", "reason_codes": sorted(set(reasons)),
               "assessment": "same_sample_not_independent" if same else "candidate_requires_interpretation",
               "features": compare_report_features(*reports), "index_comparisons": pairs,
               "alternative_explanations": ["public_sdk_or_packer", "repack_inheritance", "shared_supplier"],
               "operator_identity_asserted": False}
    _save_emit(payload, out)
