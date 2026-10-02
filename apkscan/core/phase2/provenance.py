# -*- coding: utf-8 -*-
"""从已验签的 Phase1 包生成线索五元组。不读、不写案件台账。

五元组是 ``origin=phase1`` 线索必须带的出处：

``manifest_relpath`` / ``package_id`` / ``manifest_sha256`` /
``report_relpath`` / ``evidence_id``

``manifest_relpath`` 相对 ``FXAPK_HANDOFF_ROOT``。未配置即拒绝，不回退到仓库
或目录名。本模块不打开那个根下的台账、公司表或画像。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from apkscan.core.case_package import (
    ArtifactPathVerdict,
    resolve_package_artifact_path,
    verify_case_package,
)
from apkscan.core.integrity import sha256_file
from apkscan.core.phase2.chain import is_sha256

_EVIDENCE_ID = re.compile(r"[0-9a-f]{16}\Z")
HANDOFF_ROOT_ENV = "FXAPK_HANDOFF_ROOT"


class ProvenanceError(ValueError):
    """包未验过、路径越界，或五元组对不上已验包。"""


def handoff_root() -> Path:
    """案件材料根。未配置即拒绝，不回退到仓库或目录名。"""
    raw = os.environ.get(HANDOFF_ROOT_ENV, "").strip()
    if not raw:
        raise ProvenanceError(
            f"未配置 {HANDOFF_ROOT_ENV}：案件材料根必须在 git 工作树外"
        )
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise ProvenanceError(f"{HANDOFF_ROOT_ENV} 不是可读目录")
    return root


def _is_portable_relative(value: str) -> bool:
    """拒绝 Windows 上 ``Path.is_absolute()`` 认不出的伪相对路径。

    ``/foo``、``\\\\foo``、``C:foo``、反斜杠和 ``..`` 都不能当包内或材料根相对路径。
    单段文件名是合法包内路径。生成器和 ``from_dict`` 共用这一条。
    """
    if not value or "\\" in value:
        return False
    windows = PureWindowsPath(value)
    if windows.is_absolute() or windows.drive or windows.root:
        return False
    if PurePosixPath(value).is_absolute():
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _relative_to_root(path: Path, root: Path, *, field_name: str) -> str:
    resolved = path.resolve()
    root_resolved = root.resolve()
    if not resolved.is_relative_to(root_resolved):
        raise ProvenanceError(f"{field_name} 超出案件材料根")
    text = resolved.relative_to(root_resolved).as_posix()
    if not _is_portable_relative(text):
        raise ProvenanceError(f"{field_name} 必须是相对路径")
    return text


@dataclass(frozen=True)
class Phase1Provenance:
    """线索库五元组。字段集合固定，多一个少一个都拒。"""

    manifest_relpath: str
    package_id: str
    manifest_sha256: str
    report_relpath: str
    evidence_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "manifest_relpath": self.manifest_relpath,
            "package_id": self.package_id,
            "manifest_sha256": self.manifest_sha256,
            "report_relpath": self.report_relpath,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, payload: object) -> Phase1Provenance:
        if not isinstance(payload, dict):
            raise ProvenanceError("phase1_provenance 必须是对象")
        expected = {
            "manifest_relpath",
            "package_id",
            "manifest_sha256",
            "report_relpath",
            "evidence_id",
        }
        unknown = set(payload) - expected
        if unknown:
            raise ProvenanceError(f"phase1_provenance 含未知字段：{sorted(unknown)}")
        missing = expected - set(payload)
        if missing:
            raise ProvenanceError(f"phase1_provenance 缺字段：{sorted(missing)}")
        item = cls(
            manifest_relpath=str(payload["manifest_relpath"]),
            package_id=str(payload["package_id"]),
            manifest_sha256=str(payload["manifest_sha256"]),
            report_relpath=str(payload["report_relpath"]),
            evidence_id=str(payload["evidence_id"]),
        )
        item.validate_shape()
        return item

    def validate_shape(self) -> None:
        if not is_sha256(self.package_id) or not is_sha256(self.manifest_sha256):
            raise ProvenanceError("package_id 与 manifest_sha256 必须是 64 位小写十六进制")
        if _EVIDENCE_ID.fullmatch(self.evidence_id) is None:
            raise ProvenanceError("evidence_id 必须是 16 位小写十六进制")
        for field_name, value in (
            ("manifest_relpath", self.manifest_relpath),
            ("report_relpath", self.report_relpath),
        ):
            if not _is_portable_relative(value):
                raise ProvenanceError(f"{field_name} 必须是包内相对路径")
        if Path(self.manifest_relpath).name != "case-package.json":
            raise ProvenanceError("manifest_relpath 必须指向 case-package.json")


def _registered_report_relpath(manifest: Path) -> str:
    """已验包里 kind=report 的登记路径。不接受调用方另指一份报告。"""
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("已验包的 manifest 不可读") from exc
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(artifacts, list):
        raise ProvenanceError("已验包没有报告登记")
    registered = [
        item.get("path")
        for item in artifacts
        if isinstance(item, dict) and item.get("kind") == "report"
    ]
    if len(registered) != 1 or not isinstance(registered[0], str):
        raise ProvenanceError("已验包没有唯一的报告登记")
    relpath = registered[0]
    if not _is_portable_relative(relpath):
        raise ProvenanceError("report_relpath 必须是包内相对路径")
    verdict, _resolved = resolve_package_artifact_path(manifest.parent, relpath)
    if verdict is not ArtifactPathVerdict.INSIDE:
        raise ProvenanceError("report_relpath 越出包目录或文件不存在")
    return relpath


def _evidence_belongs_to_report(report: Path, evidence_id: str) -> bool:
    """evidence_id 必须出现在已验报告的 leads / endpoints / findings 里。"""
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("已验报告不可读") from exc
    if not isinstance(payload, dict):
        raise ProvenanceError("已验报告不是对象")
    for collection in ("leads", "endpoints", "findings"):
        parents = payload.get(collection)
        if not isinstance(parents, list):
            continue
        for parent in parents:
            if not isinstance(parent, dict):
                continue
            refs = parent.get("source_refs")
            evidences = parent.get("evidences")
            for bucket in (refs, evidences):
                if not isinstance(bucket, list):
                    continue
                if any(
                    isinstance(item, dict) and item.get("evidence_id") == evidence_id
                    for item in bucket
                ):
                    return True
    return False


def provenance_for_evidence(
    manifest_path: str | Path,
    evidence_id: str,
) -> Phase1Provenance:
    """对一个已验包里的 evidence_id 生成五元组。

    根只来自 ``FXAPK_HANDOFF_ROOT``。``evidence_id`` 必须出现在 manifest 登记的
    那份报告里；调用方不能另指报告或另给根。
    """
    if _EVIDENCE_ID.fullmatch(evidence_id) is None:
        raise ProvenanceError("evidence_id 必须是 16 位小写十六进制")
    root = handoff_root()
    manifest = Path(manifest_path)
    checked = verify_case_package(manifest)
    if checked.get("status") != "verified":
        raise ProvenanceError("case-package 未通过完整性校验，不能生成 provenance")
    package_id = checked.get("package_id")
    if not is_sha256(package_id):
        raise ProvenanceError("验包结果没有合法 package_id")
    report_relpath = _registered_report_relpath(manifest)
    verdict, report = resolve_package_artifact_path(manifest.parent, report_relpath)
    if verdict is not ArtifactPathVerdict.INSIDE or report is None or not report.is_file():
        raise ProvenanceError("report_relpath 越出包目录或文件不存在")
    if not _evidence_belongs_to_report(report, evidence_id):
        raise ProvenanceError("evidence_id 不在已验报告中")
    item = Phase1Provenance(
        manifest_relpath=_relative_to_root(manifest, root, field_name="manifest_relpath"),
        package_id=str(package_id),
        manifest_sha256=sha256_file(manifest),
        report_relpath=report_relpath,
        evidence_id=evidence_id,
    )
    item.validate_shape()
    return item


__all__ = [
    "HANDOFF_ROOT_ENV",
    "Phase1Provenance",
    "ProvenanceError",
    "handoff_root",
    "provenance_for_evidence",
]
