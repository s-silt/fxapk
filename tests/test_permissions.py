"""permissions 分析器单测：用 FakeContext 喂合成权限列表，断言 Finding / meta。

覆盖命中（单权限/组合/严重度/取证意义）与不命中（无害权限）两类用例，
含空列表、全限定名归一、去重、未知/自定义权限忽略等健壮性。
不依赖 androguard / 网络。
"""

from __future__ import annotations

from apkscan.analyzers.permissions import PermissionsAnalyzer
from apkscan.core.models import AnalyzerResult, Finding, Severity
from tests.conftest import FakeContext

_P = "android.permission."


def _run(permissions: list[str]) -> AnalyzerResult:
    ctx = FakeContext(package_name="com.fraud.app", permissions=permissions)
    return PermissionsAnalyzer().analyze(ctx)


def _ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def _by_id(findings: list[Finding], fid: str) -> Finding:
    matches = [f for f in findings if f.id == fid]
    assert len(matches) == 1, f"期望恰好 1 个 {fid}，实际 {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# 命中：单个危险权限
# ---------------------------------------------------------------------------


def test_read_sms_emits_high_finding() -> None:
    result = _run([_P + "READ_SMS"])
    assert result.analyzer == "permissions"
    assert result.error is None
    f = _by_id(result.findings, "PERM-READ-SMS")
    assert f.severity is Severity.HIGH
    assert f.category == "permission"
    # 取证意义并入 description。
    assert "可调取证据" in f.description
    assert "验证码" in f.description
    # 证据回填全限定名。
    assert f.evidences and f.evidences[0].source == "manifest"
    assert "READ_SMS" in f.evidences[0].snippet


def test_meta_counts_and_lists() -> None:
    perms = [_P + "READ_SMS", _P + "INTERNET", _P + "READ_CONTACTS"]
    result = _run(perms)
    assert result.meta["permission_count"] == 3
    assert result.meta["permissions"] == perms
    # 仅 READ_SMS / READ_CONTACTS 是危险权限；INTERNET 不计。
    assert result.meta["dangerous_count"] == 2
    assert set(result.meta["dangerous_matched"]) == {"READ_SMS", "READ_CONTACTS"}


def test_contacts_and_call_log_are_high() -> None:
    result = _run([_P + "READ_CONTACTS", _P + "READ_CALL_LOG"])
    assert _by_id(result.findings, "PERM-READ-CONTACTS").severity is Severity.HIGH
    assert _by_id(result.findings, "PERM-READ-CALL-LOG").severity is Severity.HIGH


def test_record_audio_camera_install_overlay_are_high() -> None:
    result = _run(
        [
            _P + "RECORD_AUDIO",
            _P + "CAMERA",
            _P + "REQUEST_INSTALL_PACKAGES",
            _P + "SYSTEM_ALERT_WINDOW",
        ]
    )
    for fid in (
        "PERM-RECORD-AUDIO",
        "PERM-CAMERA",
        "PERM-REQUEST-INSTALL-PACKAGES",
        "PERM-SYSTEM-ALERT-WINDOW",
    ):
        assert _by_id(result.findings, fid).severity is Severity.HIGH


def test_location_severity_split() -> None:
    result = _run([_P + "ACCESS_FINE_LOCATION", _P + "ACCESS_COARSE_LOCATION"])
    assert _by_id(result.findings, "PERM-ACCESS-FINE-LOCATION").severity is Severity.MEDIUM
    assert _by_id(result.findings, "PERM-ACCESS-COARSE-LOCATION").severity is Severity.LOW


def test_read_phone_state_is_medium() -> None:
    result = _run([_P + "READ_PHONE_STATE"])
    assert _by_id(result.findings, "PERM-READ-PHONE-STATE").severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# 命中：权限组合
# ---------------------------------------------------------------------------


def test_sms_intercept_combo() -> None:
    result = _run([_P + "READ_SMS", _P + "RECEIVE_SMS"])
    assert "PERM-COMBO-SMS-INTERCEPT" in _ids(result.findings)
    combo = _by_id(result.findings, "PERM-COMBO-SMS-INTERCEPT")
    assert combo.severity is Severity.HIGH
    assert combo.category == "permission"
    # 组合证据列出构成权限。
    assert "READ_SMS" in combo.evidences[0].snippet
    assert "RECEIVE_SMS" in combo.evidences[0].snippet


def test_personal_info_harvest_combo() -> None:
    result = _run(
        [_P + "READ_CONTACTS", _P + "READ_CALL_LOG", _P + "READ_SMS"]
    )
    assert "PERM-COMBO-PERSONAL-INFO-HARVEST" in _ids(result.findings)


def test_bank_overlay_combo() -> None:
    result = _run(
        [_P + "SYSTEM_ALERT_WINDOW", _P + "READ_SMS", _P + "QUERY_ALL_PACKAGES"]
    )
    assert "PERM-COMBO-BANK-OVERLAY" in _ids(result.findings)


def test_partial_combo_not_triggered() -> None:
    # 仅 READ_SMS（缺 RECEIVE_SMS）→ 不触发短信劫持组合。
    result = _run([_P + "READ_SMS"])
    assert "PERM-COMBO-SMS-INTERCEPT" not in _ids(result.findings)
    # 但单权限 Finding 仍在。
    assert "PERM-READ-SMS" in _ids(result.findings)


# ---------------------------------------------------------------------------
# 归一 / 去重 / 兼容
# ---------------------------------------------------------------------------


def test_short_name_without_prefix_matches() -> None:
    # 不带 android.permission. 前缀的裸短名也应命中。
    result = _run(["READ_SMS"])
    assert "PERM-READ-SMS" in _ids(result.findings)


def test_duplicate_permissions_deduped() -> None:
    result = _run([_P + "READ_SMS", _P + "READ_SMS", "READ_SMS"])
    # 去重后只剩一个权限、一个 Finding。
    assert result.meta["permission_count"] == 1
    assert len([f for f in result.findings if f.id == "PERM-READ-SMS"]) == 1


def test_vendor_permission_not_matched() -> None:
    # 厂商自定义权限短名恰好不在规则内 → 不报 Finding、不崩。
    result = _run(["com.huawei.permission.sec.MDM", _P + "INTERNET"])
    assert result.error is None
    assert result.findings == []
    assert result.meta["dangerous_count"] == 0


# ---------------------------------------------------------------------------
# 不命中：无害权限 / 空
# ---------------------------------------------------------------------------


def test_benign_permissions_no_findings() -> None:
    result = _run(
        [_P + "INTERNET", _P + "ACCESS_NETWORK_STATE", _P + "WAKE_LOCK"]
    )
    assert result.error is None
    assert result.findings == []
    assert result.meta["dangerous_count"] == 0
    assert result.meta["permission_count"] == 3


def test_empty_permissions_no_findings() -> None:
    result = _run([])
    assert result.error is None
    assert result.findings == []
    assert result.meta["permission_count"] == 0
    assert result.meta["dangerous_count"] == 0


# ---------------------------------------------------------------------------
# 健壮性：读取权限抛异常
# ---------------------------------------------------------------------------


def test_permissions_call_raises_records_error() -> None:
    class _Boom(FakeContext):
        def permissions(self) -> list[str]:
            raise RuntimeError("boom")

    ctx = _Boom(package_name="com.x")
    result = PermissionsAnalyzer().analyze(ctx)
    assert result.error is not None
    assert result.findings == []
    assert result.meta["permission_count"] == 0


# ---------------------------------------------------------------------------
# 与 conftest 夹具协同
# ---------------------------------------------------------------------------


def test_fixture_context_runs(fake_ctx: FakeContext) -> None:
    # fake_ctx 仅声明 INTERNET（无害）→ 无 Finding。
    result = PermissionsAnalyzer().analyze(fake_ctx)
    assert result.analyzer == "permissions"
    assert result.error is None
    assert result.findings == []
    assert result.meta["dangerous_count"] == 0
