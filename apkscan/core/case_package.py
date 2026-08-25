"""公共两阶段交付契约：不可变 Phase-1 证据包与绑定精确哈希的 Phase-2 复核记录。

目录位置和执行者身份均不属于协议；同一人可以顺序执行两个阶段。状态彼此正交：包哈希验证、
分析健康、案件闭环、人工复核绝不互相推导。
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, cast

from apkscan.core.redact import PublicDiagnosticError, register_public_diagnostic
from apkscan.core import infra
from apkscan.core.atomic import atomic_create_bytes
from apkscan.core.case_identity import normalize_case_id
from apkscan.core.evidence_scope import project_serialized_closure
from apkscan.core.json_contract import (
    JsonContractError,
    parse_finite_json_float,
    reject_nonfinite_json_constant,
)
from apkscan.core.models import EvidenceScope, Report, has_case_evidence
from apkscan.core.report_io import load_report

CASE_PACKAGE_SCHEMA_VERSION = "1.0"
CASE_REVIEW_SCHEMA_VERSION = "1.0"
_REVIEW_STATUSES = frozenset({"accepted", "changes_requested"})
_ANALYSIS_STATUSES = frozenset({"complete", "partial", "failed"})
_CLOSURE_STATUSES = frozenset({"not_run", "complete", "partial", "failed"})
_CHUNK = 1 << 20
_MAX_TOOL_VERSION_LENGTH = 120


class CasePackageErrorCode(str, Enum):
    """证据包契约违例的稳定错误码（机器可读，不随文案改写变化）。"""

    INVALID_SAMPLE_SHA256 = "invalid_sample_sha256"
    INVALID_RULESET_DIGEST = "invalid_ruleset_digest"
    TOOL_VERSION_REQUIRED = "tool_version_required"
    TOOL_VERSION_NOT_NORMALIZED = "tool_version_not_normalized"
    TOOL_VERSION_LENGTH = "tool_version_length"
    TOOL_VERSION_FORBIDDEN_CONTROL = "tool_version_forbidden_control"
    CLOSURE_TARGETS_EMPTY = "closure_targets_empty"
    CLOSURE_TARGET_LACKS_EVIDENCE = "closure_target_lacks_evidence"
    IMMUTABLE_RECORD_EXISTS = "immutable_record_exists"
    ARTIFACT_OUTSIDE_PACKAGE_ROOT = "artifact_outside_package_root"
    ARTIFACT_NOT_READABLE = "artifact_not_readable"
    ARTIFACT_KIND_SCOPE_CONFLICT = "artifact_kind_scope_conflict"
    INVALID_CLOSURE_STATUS = "invalid_closure_status"
    CLOSURE_TARGET_NOT_OBJECT = "closure_target_not_object"
    CLOSURE_TARGET_INVALID = "closure_target_invalid"
    PRODUCER_REQUIRED = "producer_required"
    INVALID_ANALYSIS_STATUS = "invalid_analysis_status"
    JSON_RECORD_UNREADABLE = "json_record_unreadable"
    JSON_ROOT_NOT_OBJECT = "json_root_not_object"
    REVIEWER_REQUIRED = "reviewer_required"
    INVALID_REVIEW_STATUS = "invalid_review_status"
    REVIEW_REQUIRES_VERIFIED_INTEGRITY = "review_requires_verified_integrity"


#: 错误码 → **固定**公开文案。封闭集合：不含路径、原始 token、非法枚举原值、
#: 下游异常消息——这些是不可信输入或环境信息的回显面。
_CASE_PACKAGE_MESSAGES: dict[CasePackageErrorCode, str] = {
    CasePackageErrorCode.INVALID_SAMPLE_SHA256:
        "sample_sha256 must be exactly 64 hexadecimal characters",
    CasePackageErrorCode.INVALID_RULESET_DIGEST:
        "ruleset_digest must be exactly 16 hexadecimal characters",
    CasePackageErrorCode.TOOL_VERSION_REQUIRED: "tool_version is required",
    CasePackageErrorCode.TOOL_VERSION_NOT_NORMALIZED:
        "tool_version must already be NFC-normalized and trimmed",
    CasePackageErrorCode.TOOL_VERSION_LENGTH:
        f"tool_version must contain 1-{_MAX_TOOL_VERSION_LENGTH} characters",
    CasePackageErrorCode.TOOL_VERSION_FORBIDDEN_CONTROL:
        "tool_version contains a forbidden Unicode control character",
    CasePackageErrorCode.CLOSURE_TARGETS_EMPTY:
        "complete closure requires a non-empty closure targets inventory",
    CasePackageErrorCode.CLOSURE_TARGET_LACKS_EVIDENCE:
        "complete closure target lacks direct case evidence",
    CasePackageErrorCode.IMMUTABLE_RECORD_EXISTS: "immutable record already exists",
    CasePackageErrorCode.ARTIFACT_OUTSIDE_PACKAGE_ROOT: "artifact is outside package root",
    CasePackageErrorCode.ARTIFACT_NOT_READABLE: "artifact is not a readable file",
    CasePackageErrorCode.ARTIFACT_KIND_SCOPE_CONFLICT:
        "conflicting artifact kind/scope for the same path",
    CasePackageErrorCode.INVALID_CLOSURE_STATUS: "invalid closure status",
    CasePackageErrorCode.CLOSURE_TARGET_NOT_OBJECT: "closure target is not an object",
    CasePackageErrorCode.CLOSURE_TARGET_INVALID: "closure target has invalid kind/value",
    CasePackageErrorCode.PRODUCER_REQUIRED: "producer is required",
    CasePackageErrorCode.INVALID_ANALYSIS_STATUS: "invalid analysis status",
    CasePackageErrorCode.JSON_RECORD_UNREADABLE: "cannot read JSON record",
    CasePackageErrorCode.JSON_ROOT_NOT_OBJECT: "JSON record root must be an object",
    CasePackageErrorCode.REVIEWER_REQUIRED: "reviewer is required",
    CasePackageErrorCode.INVALID_REVIEW_STATUS: "invalid review status",
    CasePackageErrorCode.REVIEW_REQUIRES_VERIFIED_INTEGRITY:
        "cannot review package whose integrity is not verified",
}


class CasePackageError(ValueError, PublicDiagnosticError):
    """证据包/复核记录违反公共契约。

    **构造器只收本模块的枚举**（``type(code) is CasePackageErrorCode`` 精确判定，不接受
    与枚举值相等的裸字符串——``str, Enum`` 的 hash 与 str 相同，裸串会命中映射字典却在
    取 ``.value`` 时炸）。文案由 :func:`_render_case_package_message` 从**构造时校验过的**
    code 重新生成，不读 ``args``：事后改写 ``exc.args`` 影响不了公开文案。
    唯一允许的动态值是 ``index``（本地迭代序号，``type(index) is int`` 精确判定，
    排除 ``bool``——它是 int 子类）。
    """

    def __init__(self, code: CasePackageErrorCode, *, index: int | None = None) -> None:
        if type(code) is not CasePackageErrorCode:
            raise TypeError(f"code 必须是 CasePackageErrorCode，收到 {type(code).__name__}")
        if index is not None and type(index) is not int:
            raise TypeError(f"index 必须是 int，收到 {type(index).__name__}")
        self._code = code
        self._index = index
        super().__init__(_render_case_package_message(code, index))

    @property
    def code(self) -> CasePackageErrorCode:
        return self._code

    @property
    def index(self) -> int | None:
        return self._index

    @property
    def public_message(self) -> str:
        return _render_case_package_message(self._code, self._index)

    @property
    def diagnostic_code(self) -> str:
        return self._code.value


def _render_case_package_message(
    code: CasePackageErrorCode, index: int | None = None
) -> str:
    """由校验过的 code 重新生成固定文案（不读异常的 args）。"""
    message = _CASE_PACKAGE_MESSAGES[code]
    return f"{message} at index {index}" if index is not None else message


register_public_diagnostic(
    CasePackageError, lambda exc: cast(CasePackageError, exc).public_message
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_offset_timestamp(value: object) -> bool:
    """Accept an ISO/RFC3339-style timestamp only when its UTC offset is explicit."""
    if not isinstance(value, str):
        return False
    raw = value.strip()
    if not raw or "T" not in raw:
        return False
    parseable = f"{raw[:-1]}+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        parsed = datetime.fromisoformat(parseable)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _report_identity(values: Mapping[str, object]) -> tuple[str, str, str]:
    """Validate and normalize the reproducibility anchors for a Phase-1 package."""
    sample = values.get("sample_sha256")
    if not isinstance(sample, str) or len(sample) != 64 or any(
        char not in "0123456789abcdefABCDEF" for char in sample
    ):
        raise CasePackageError(CasePackageErrorCode.INVALID_SAMPLE_SHA256)

    rules = values.get("ruleset_digest")
    if not isinstance(rules, str) or len(rules) != 16 or any(
        char not in "0123456789abcdefABCDEF" for char in rules
    ):
        raise CasePackageError(CasePackageErrorCode.INVALID_RULESET_DIGEST)

    tool = values.get("tool_version")
    if not isinstance(tool, str):
        raise CasePackageError(CasePackageErrorCode.TOOL_VERSION_REQUIRED)
    normalized_tool = unicodedata.normalize("NFC", tool)
    if normalized_tool != tool or tool.strip() != tool:
        raise CasePackageError(CasePackageErrorCode.TOOL_VERSION_NOT_NORMALIZED)
    if not tool or len(tool) > _MAX_TOOL_VERSION_LENGTH:
        raise CasePackageError(CasePackageErrorCode.TOOL_VERSION_LENGTH)
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in tool):
        raise CasePackageError(CasePackageErrorCode.TOOL_VERSION_FORBIDDEN_CONTROL)
    return sample.lower(), tool, rules.lower()


def _require_raw_complete_claim_is_safe(payload: Mapping[str, object]) -> None:
    raw_meta = payload.get("meta")
    raw_closure = raw_meta.get("closure") if isinstance(raw_meta, Mapping) else None
    raw_status = raw_closure.get("status") if isinstance(raw_closure, Mapping) else None
    if not isinstance(raw_status, str) or raw_status.strip() != "complete":
        return
    projected = project_serialized_closure(payload)
    projected_status = projected.get("status")
    if projected_status == "complete":
        return
    if projected_status == "failed":
        raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGETS_EMPTY)
    # gaps 明细不进公开文案（可能带案件目标值）；缺口本身由 projected 的结构化字段承载。
    raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGET_LACKS_EVIDENCE)


def _write_new_json(path: Path, payload: Mapping[str, object]) -> None:
    raw = (
        json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    if not atomic_create_bytes(path, raw):
        raise CasePackageError(CasePackageErrorCode.IMMUTABLE_RECORD_EXISTS)


def _relative_artifact(path: Path, root: Path, *, kind: str, scope: EvidenceScope) -> dict[str, object]:
    resolved = path.resolve()
    package_root = root.resolve()
    if not resolved.is_relative_to(package_root):
        raise CasePackageError(CasePackageErrorCode.ARTIFACT_OUTSIDE_PACKAGE_ROOT)
    if not resolved.is_file():
        raise CasePackageError(CasePackageErrorCode.ARTIFACT_NOT_READABLE)
    return {
        "path": resolved.relative_to(package_root).as_posix(),
        "kind": kind,
        "scope": scope.value,
        "size": resolved.stat().st_size,
        "sha256": _sha256(resolved),
    }


def _closure_status(meta: object, *, strict: bool = False) -> str:
    if not isinstance(meta, Mapping):
        return "not_run"
    closure = meta.get("closure")
    if not isinstance(closure, Mapping):
        return "not_run"
    status = str(closure.get("status", "")).strip()
    if status in {"complete", "partial", "failed"}:
        return status
    if strict:
        raise CasePackageError(CasePackageErrorCode.INVALID_CLOSURE_STATUS)
    return "not_run"


def _direct_case_network_keys(report: Report) -> set[tuple[str, str]]:
    keys = {
        (endpoint.kind, infra.match_key(endpoint.kind, endpoint.value))
        for endpoint in report.endpoints
        if endpoint.kind in {"domain", "ip"} and has_case_evidence(endpoint.evidences)
    }
    keys.update(
        (lead.category.value.lower(), infra.match_key(lead.category.value, lead.value))
        for lead in report.leads
        if lead.category.value in {"DOMAIN", "IP"} and has_case_evidence(lead.source_refs)
    )
    return keys


def _complete_closure_targets(report: Report) -> list[tuple[str, str]]:
    closure = report.meta.get("closure")
    raw_targets = closure.get("targets") if isinstance(closure, Mapping) else None
    if not isinstance(raw_targets, list) or not raw_targets:
        raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGETS_EMPTY)
    targets: list[tuple[str, str]] = []
    for index, target in enumerate(raw_targets):
        if not isinstance(target, Mapping):
            raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGET_NOT_OBJECT, index=index)
        kind = str(target.get("kind", "")).strip().lower()
        value = str(target.get("value", "")).strip()
        if kind not in {"domain", "ip"} or not value:
            raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGET_INVALID, index=index)
        targets.append((kind, infra.match_key(kind, value)))
    return targets


def _require_complete_closure_evidence(report: Report, closure: str) -> None:
    if closure != "complete":
        return
    direct = _direct_case_network_keys(report)
    missing = [
        f"{kind}:{value}"
        for kind, value in _complete_closure_targets(report)
        if (kind, value) not in direct
    ]
    if missing:
        raise CasePackageError(CasePackageErrorCode.CLOSURE_TARGET_LACKS_EVIDENCE)


def create_case_package(
    report_path: str | Path,
    manifest_path: str | Path,
    *,
    case_id: str,
    producer: str,
    case_evidence: Iterable[str | Path] = (),
    batch_reference: Iterable[str | Path] = (),
) -> dict[str, object]:
    """生成不可变 Phase-1 manifest；所有被引用文件必须位于 manifest 目录树内。"""
    case = normalize_case_id(case_id)
    actor = str(producer).strip()
    if not actor:
        raise CasePackageError(CasePackageErrorCode.PRODUCER_REQUIRED)

    manifest = Path(manifest_path)
    root = manifest.parent
    report_file = Path(report_path)
    raw_report = _load_object(report_file)
    _require_raw_complete_claim_is_safe(raw_report)
    report = load_report(report_file)
    sample_sha256, tool_version, ruleset_digest = _report_identity(report.meta)
    if report.analysis_status not in _ANALYSIS_STATUSES:
        raise CasePackageError(CasePackageErrorCode.INVALID_ANALYSIS_STATUS)
    closure = _closure_status(report.meta, strict=True) if report.meta.get("closure") is not None else "not_run"
    _require_complete_closure_evidence(report, closure)

    artifacts: list[dict[str, object]] = []
    seen: dict[Path, tuple[str, EvidenceScope]] = {}

    def add(path: str | Path, *, kind: str, scope: EvidenceScope) -> None:
        resolved = Path(path).resolve()
        classification = (kind, scope)
        prior = seen.get(resolved)
        if prior == classification:
            return
        if prior is not None:
            raise CasePackageError(CasePackageErrorCode.ARTIFACT_KIND_SCOPE_CONFLICT)
        seen[resolved] = classification
        artifacts.append(_relative_artifact(resolved, root, kind=kind, scope=scope))

    add(report_file, kind="report", scope=EvidenceScope.CASE_EVIDENCE)
    for item in case_evidence:
        add(item, kind="evidence", scope=EvidenceScope.CASE_EVIDENCE)
    for item in batch_reference:
        add(item, kind="reference", scope=EvidenceScope.BATCH_REFERENCE)
    artifacts.sort(key=lambda item: (str(item["scope"]), str(item["path"])))

    body: dict[str, object] = {
        "schema_version": CASE_PACKAGE_SCHEMA_VERSION,
        "phase": "phase1",
        "case_id": case,
        "producer": actor,
        "created_at": _now(),
        "report_schema_version": report.schema_version,
        "sample_sha256": sample_sha256,
        "tool_version": tool_version,
        "ruleset_digest": ruleset_digest,
        "analysis_snapshot": report.analysis_status,
        "closure_snapshot": closure,
        "artifacts": artifacts,
    }
    payload = {**body, "package_id": _canonical_sha256(body)}
    _write_new_json(manifest, payload)
    return payload


def _load_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_nonfinite_json_constant,
            parse_float=parse_finite_json_float,
        )
    except JsonContractError:
        # 契约违例自带固定公开文案与错误码，直接上抛保住「哪条契约没过」这个区分；
        # 包成 JSON_RECORD_UNREADABLE 会把它和「文件读不了」塌缩成同一种。
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise CasePackageError(CasePackageErrorCode.JSON_RECORD_UNREADABLE) from exc
    if not isinstance(value, dict):
        raise CasePackageError(CasePackageErrorCode.JSON_ROOT_NOT_OBJECT)
    return value


def verify_case_package(manifest_path: str | Path) -> dict[str, object]:
    """校验 manifest 自身 package_id、路径边界和全部附件字节哈希；绝不把 READY 当完整性。"""
    manifest = Path(manifest_path)
    issues: list[str] = []
    try:
        payload = _load_object(manifest)
    except PublicDiagnosticError as exc:
        # 用契约基类兜：CasePackageError 与 JsonContractError 都承诺固定公开文案 + 稳定错误码。
        return {"status": "failed", "issues": [exc.public_message], "package_id": ""}

    if payload.get("schema_version") != CASE_PACKAGE_SCHEMA_VERSION:
        # 不回显 schema 原值：它来自待校验的包，是不可信输入。
        issues.append("unsupported package schema")
    if payload.get("phase") != "phase1":
        issues.append("record is not a phase1 package")
    case_id = payload.get("case_id")
    try:
        normalized_case_id = normalize_case_id(case_id)
        if normalized_case_id != case_id:
            issues.append("case_id is not normalized")
    except ValueError:
        issues.append("case_id is invalid")
    producer = payload.get("producer")
    if not isinstance(producer, str) or not producer.strip():
        issues.append("producer is required")
    if payload.get("analysis_snapshot") not in _ANALYSIS_STATUSES:
        issues.append("analysis_snapshot has invalid status")
    if payload.get("closure_snapshot") not in _CLOSURE_STATUSES:
        issues.append("closure_snapshot has invalid status")
    if not isinstance(payload.get("report_schema_version"), str) or not str(
        payload.get("report_schema_version")
    ).strip():
        issues.append("report_schema_version is required")
    try:
        package_identity = _report_identity(payload)
    except CasePackageError as exc:
        issues.append(exc.public_message)
        package_identity = None
    if not _is_offset_timestamp(payload.get("created_at")):
        issues.append("created_at must be a parseable timestamp with an explicit UTC offset")
    body = {key: value for key, value in payload.items() if key != "package_id"}
    expected_id = _canonical_sha256(body)
    package_id = str(payload.get("package_id", ""))
    if package_id != expected_id:
        issues.append("package_id mismatch")

    raw_artifacts = payload.get("artifacts")
    artifacts = raw_artifacts if isinstance(raw_artifacts, list) else []
    if not artifacts:
        issues.append("package has no artifacts")
    root = manifest.parent.resolve()
    report_count = 0
    report_artifact: Path | None = None
    seen_artifact_paths: set[Path] = set()
    for index, item in enumerate(artifacts):
        if not isinstance(item, Mapping):
            issues.append(f"artifact[{index}] is not an object")
            continue
        rel = str(item.get("path", ""))
        candidate = Path(rel)
        if not rel or candidate.is_absolute():
            issues.append(f"artifact[{index}] has unsafe path")
            continue
        resolved = (root / candidate).resolve()
        if not resolved.is_relative_to(root):
            issues.append(f"artifact[{index}] escapes package root")
            continue
        if resolved in seen_artifact_paths:
            issues.append(f"artifact[{index}] duplicates an earlier artifact path")
        else:
            seen_artifact_paths.add(resolved)
        kind = str(item.get("kind", ""))
        scope = str(item.get("scope", ""))
        if kind == "report":
            report_count += 1
            report_artifact = resolved
        if scope not in {
            EvidenceScope.CASE_EVIDENCE.value,
            EvidenceScope.BATCH_REFERENCE.value,
        }:
            issues.append(f"artifact[{index}] has invalid scope")
        expected_scope = {
            "report": EvidenceScope.CASE_EVIDENCE.value,
            "evidence": EvidenceScope.CASE_EVIDENCE.value,
            "reference": EvidenceScope.BATCH_REFERENCE.value,
        }.get(kind)
        if expected_scope is None:
            issues.append(f"artifact[{index}] has invalid kind")
        elif scope != expected_scope:
            issues.append(f"{kind} artifact[{index}] has invalid scope")
        try:
            if not resolved.is_file():
                issues.append(f"artifact[{index}] is missing")
                continue
            actual_hash = _sha256(resolved)
            actual_size = resolved.stat().st_size
        except OSError:
            # ``is_file`` is only a point-in-time observation.  Evidence can
            # disappear, become an offline OneDrive placeholder, or lose read
            # permission before hashing/stat.  Verification is a status
            # projection, so record the failed artifact instead of leaking an
            # OS exception through ``case status``.
            # 既不回显包内路径（来自待校验的包，是不可信输入），也不回显 OS 异常消息
            # （可能带绝对路径、挂载点、账户名）；用本地序号定位即可。
            issues.append(f"artifact[{index}] is unreadable")
            continue
        if actual_hash != str(item.get("sha256", "")):
            issues.append(f"artifact[{index}] hash mismatch")
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size != actual_size:
            issues.append(f"artifact[{index}] size mismatch")
    if report_count != 1:
        issues.append(f"package must contain exactly one report artifact (found {report_count})")
    elif report_artifact is not None and report_artifact.is_file():
        try:
            raw_report = _load_object(report_artifact)
            try:
                _require_raw_complete_claim_is_safe(raw_report)
            except CasePackageError as exc:
                issues.append(exc.public_message)
            report = load_report(report_artifact)
            try:
                expected_closure = (
                    _closure_status(report.meta, strict=True)
                    if report.meta.get("closure") is not None
                    else "not_run"
                )
            except CasePackageError as exc:
                issues.append(exc.public_message)
                expected_closure = "not_run"
            try:
                _require_complete_closure_evidence(report, expected_closure)
            except CasePackageError as exc:
                issues.append(exc.public_message)
            if payload.get("analysis_snapshot") != report.analysis_status:
                issues.append("analysis_snapshot does not match report")
            if payload.get("closure_snapshot") != expected_closure:
                issues.append("closure_snapshot does not match report")
            if payload.get("report_schema_version") != report.schema_version:
                issues.append("report_schema_version does not match report")
            try:
                report_identity = _report_identity(report.meta)
            except CasePackageError as exc:
                issues.append(f"report identity invalid: {exc.diagnostic_code}")
                report_identity = None
            if package_identity is not None and report_identity is not None:
                identity_fields = ("sample_sha256", "tool_version", "ruleset_digest")
                for field, packaged, reported in zip(
                    identity_fields, package_identity, report_identity, strict=True
                ):
                    if packaged != reported:
                        issues.append(f"{field} does not match report")
        except (OSError, ValueError, UnicodeError):
            issues.append("report artifact is not readable by current schema")
    return {
        "status": "failed" if issues else "verified",
        "issues": issues,
        "package_id": package_id,
    }


def create_case_review(
    manifest_path: str | Path,
    review_path: str | Path,
    *,
    reviewer: str,
    status: str,
    findings: Iterable[str] = (),
) -> dict[str, object]:
    """Phase-2 只写独立 review，不修改 Phase-1 包；同一执行者顺序担任两角色合法。"""
    actor = str(reviewer).strip()
    decision = str(status).strip()
    if not actor:
        raise CasePackageError(CasePackageErrorCode.REVIEWER_REQUIRED)
    if decision not in _REVIEW_STATUSES:
        raise CasePackageError(CasePackageErrorCode.INVALID_REVIEW_STATUS)
    manifest = Path(manifest_path)
    verified = verify_case_package(manifest)
    if verified["status"] != "verified":
        raise CasePackageError(CasePackageErrorCode.REVIEW_REQUIRES_VERIFIED_INTEGRITY)
    package = _load_object(manifest)
    payload: dict[str, object] = {
        "schema_version": CASE_REVIEW_SCHEMA_VERSION,
        "phase": "phase2",
        "package_id": package["package_id"],
        "manifest_sha256": _sha256(manifest),
        "reviewer": actor,
        "status": decision,
        "findings": [str(item) for item in findings if str(item).strip()],
        "reviewed_at": _now(),
    }
    _write_new_json(Path(review_path), payload)
    return payload


def _review_status(
    manifest: Path,
    package: Mapping[str, object],
    review_path: str | Path | None,
    *,
    integrity: str,
) -> str:
    if review_path is None:
        return "not_reviewed"
    if integrity != "verified":
        return "stale"
    try:
        review = _load_object(Path(review_path))
    except (CasePackageError, JsonContractError):
        # 两个可信具体类型：JsonContractError 现在会从 _load_object 穿透上来，
        # 只 catch CasePackageError 会让「包校验失败」退化成「命令崩溃」。
        return "stale"
    findings = review.get("findings")
    if (
        review.get("schema_version") != CASE_REVIEW_SCHEMA_VERSION
        or review.get("phase") != "phase2"
        or review.get("package_id") != package.get("package_id")
        or review.get("manifest_sha256") != _sha256(manifest)
        or not isinstance(review.get("reviewer"), str)
        or not str(review.get("reviewer")).strip()
        or not _is_offset_timestamp(review.get("reviewed_at"))
        or not isinstance(findings, list)
        or not all(isinstance(item, str) for item in findings)
    ):
        return "stale"
    decision = str(review.get("status", ""))
    return decision if decision in _REVIEW_STATUSES else "stale"


def project_case_status(
    target_path: str | Path,
    review_path: str | Path | None = None,
) -> dict[str, str]:
    """投影四个正交状态。目标可为 Phase-1 manifest，也可为裸 report（完整性=unverified）。"""
    target = Path(target_path)
    try:
        payload = _load_object(target)
    except (CasePackageError, JsonContractError):
        # 两个可信具体类型：JsonContractError 现在会从 _load_object 穿透上来，
        # 只 catch CasePackageError 会让「包校验失败」退化成「命令崩溃」。
        return {
            "package_integrity": "failed",
            "analysis": "failed",
            "closure": "not_run",
            "review": "stale" if review_path is not None else "not_reviewed",
        }
    if payload.get("phase") == "phase1":
        checked = verify_case_package(target)
        integrity = str(checked["status"])
        raw_analysis = payload.get("analysis_snapshot")
        raw_closure = payload.get("closure_snapshot")
        return {
            "package_integrity": integrity,
            "analysis": str(raw_analysis) if raw_analysis in _ANALYSIS_STATUSES else "failed",
            "closure": str(raw_closure) if raw_closure in _CLOSURE_STATUSES else "not_run",
            "review": _review_status(
                target, payload, review_path, integrity=integrity
            ),
        }

    # 裸 report：能读分析/闭环，但没有外部 hash manifest，绝不能称 package verified。
    try:
        report = load_report(target)
        analysis = report.analysis_status
        closure = _closure_status(report.meta)
    except (OSError, ValueError, UnicodeError):
        analysis, closure = "failed", "not_run"
    return {
        "package_integrity": "unverified",
        "analysis": analysis,
        "closure": closure,
        "review": "stale" if review_path is not None else "not_reviewed",
    }


__all__ = [
    "CASE_PACKAGE_SCHEMA_VERSION",
    "CASE_REVIEW_SCHEMA_VERSION",
    "CasePackageError",
    "create_case_package",
    "create_case_review",
    "project_case_status",
    "verify_case_package",
]
