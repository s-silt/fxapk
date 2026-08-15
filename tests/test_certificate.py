"""CertificateAnalyzer 的单测：用 conftest 的 FakeContext 喂合成证书。

覆盖：
- 正常 release 证书 → 一条 SIGNING Lead，无 debug Finding。
- is_debug=True → HIGH Finding。
- issuer 含 "Android Debug" → HIGH Finding（即便 is_debug=False）。
- 可疑占位主体 → MEDIUM Finding。
- 弱身份字段 → INFO Finding。
- 短有效期 → INFO Finding。
- 无证书 → 空产出（不命中）。
- 多证书：逐张产 Lead，单张异常不影响其余。
- ctx.certificates() 抛异常 → result.error 记录而非抛出。
"""

from __future__ import annotations

from apkscan.analyzers.certificate import CertificateAnalyzer
from apkscan.core.models import (
    AnalyzerResult,
    CertInfo,
    Confidence,
    LeadCategory,
    Severity,
)

from tests.conftest import FakeContext


def _analyze(certs: list[CertInfo]) -> AnalyzerResult:
    ctx = FakeContext(certificates=certs)
    return CertificateAnalyzer().analyze(ctx)


def _release_cert(**overrides: object) -> CertInfo:
    base = dict(
        subject="CN=Zhang San, O=Real Tech Co Ltd, C=CN",
        issuer="CN=Zhang San, O=Real Tech Co Ltd, C=CN",
        sha256="f" * 64,
        not_before="2020-01-01T00:00:00",
        not_after="2049-12-31T00:00:00",
        is_debug=False,
        schemes=["v1", "v2", "v3"],
    )
    base.update(overrides)
    return CertInfo(**base)  # type: ignore[arg-type]


# --- 基本属性 -------------------------------------------------------------


def test_analyzer_name_and_requires():
    analyzer = CertificateAnalyzer()
    assert analyzer.name == "certificate"
    assert analyzer.requires == ["apk"]


# --- SIGNING Lead 产出 -----------------------------------------------------


def test_release_cert_yields_signing_lead_no_debug_finding():
    cert = _release_cert()
    result = _analyze([cert])

    assert result.error is None
    assert result.meta["cert_count"] == 1
    assert len(result.leads) == 1

    lead = result.leads[0]
    assert lead.category == LeadCategory.SIGNING
    assert lead.value == "f" * 64  # value = sha256
    assert lead.subject == cert.subject
    assert lead.confidence == Confidence.HIGH
    assert lead.where_to_request == "证书指纹用于跨样本关联同一开发者；无直接调证对象"
    assert lead.evidence_to_obtain == ["相同签名指纹的其他涉诈App"]

    # source_refs: Evidence(source="cert", location=subject)
    assert lead.source_refs
    ev = lead.source_refs[0]
    assert ev.source == "cert"
    assert ev.location == cert.subject

    # 正常 release 证书不应产生任何 Finding
    assert result.findings == []


def test_signing_lead_endpoints_empty():
    # certificate 分析器不产 endpoints
    result = _analyze([_release_cert()])
    assert result.endpoints == []


# --- 调试证书 → HIGH Finding ----------------------------------------------


def test_debug_flag_yields_high_finding():
    cert = _release_cert(is_debug=True)
    result = _analyze([cert])

    debug = [f for f in result.findings if f.id.startswith("CERT-DEBUG")]
    assert len(debug) == 1
    assert debug[0].severity == Severity.HIGH
    assert debug[0].category == "signing"
    # Lead 仍照常产出
    assert any(l.category == LeadCategory.SIGNING for l in result.leads)


def test_android_debug_issuer_yields_high_finding_without_flag():
    cert = _release_cert(
        subject="CN=Android Debug, O=Android, C=US",
        issuer="CN=Android Debug, O=Android, C=US",
        is_debug=False,
    )
    result = _analyze([cert])

    debug = [f for f in result.findings if f.id.startswith("CERT-DEBUG")]
    assert len(debug) == 1
    assert debug[0].severity == Severity.HIGH


def test_debug_match_is_case_insensitive():
    cert = _release_cert(issuer="cn=android debug, o=android", is_debug=False)
    result = _analyze([cert])
    assert any(f.id.startswith("CERT-DEBUG") for f in result.findings)


# --- 可疑占位主体 → MEDIUM ------------------------------------------------


def test_suspicious_subject_yields_medium_finding():
    cert = _release_cert(
        subject="CN=Unknown, O=Unknown",
        issuer="CN=Unknown, O=Unknown",
    )
    result = _analyze([cert])

    suspicious = [f for f in result.findings if f.id.startswith("CERT-SUSPICIOUS")]
    assert len(suspicious) == 1
    assert suspicious[0].severity == Severity.MEDIUM


def test_apktool_subject_flagged_suspicious():
    cert = _release_cert(subject="CN=Apktool, O=Apktool")
    result = _analyze([cert])
    assert any(f.id.startswith("CERT-SUSPICIOUS") for f in result.findings)


# --- 短有效期 → INFO ------------------------------------------------------


def test_short_validity_yields_info_finding():
    cert = _release_cert(
        not_before="2024-01-01T00:00:00",
        not_after="2024-03-01T00:00:00",  # ~60 天
    )
    result = _analyze([cert])

    short = [f for f in result.findings if f.id.startswith("CERT-SHORTVALID")]
    assert len(short) == 1
    assert short[0].severity == Severity.INFO


def test_long_validity_no_short_finding():
    result = _analyze([_release_cert()])  # 2020~2049
    assert not any(f.id.startswith("CERT-SHORTVALID") for f in result.findings)


def test_unparsable_dates_no_short_finding_no_crash():
    cert = _release_cert(not_before="garbage", not_after="also-garbage")
    result = _analyze([cert])
    assert result.error is None
    assert not any(f.id.startswith("CERT-SHORTVALID") for f in result.findings)
    # Lead 仍产出
    assert len(result.leads) == 1


# --- 不命中 ---------------------------------------------------------------


def test_no_certificates_yields_empty():
    result = _analyze([])
    assert result.error is None
    assert result.leads == []
    assert result.findings == []
    assert result.meta["cert_count"] == 0


# --- 多证书 + 鲁棒性 ------------------------------------------------------


def test_multiple_certs_each_yield_lead():
    c1 = _release_cert(sha256="1" * 64, subject="CN=Dev A, O=A Co")
    c2 = _release_cert(sha256="2" * 64, subject="CN=Dev B, O=B Co", is_debug=True)
    result = _analyze([c1, c2])

    assert result.meta["cert_count"] == 2
    signing_leads = [l for l in result.leads if l.category == LeadCategory.SIGNING]
    assert {l.value for l in signing_leads} == {"1" * 64, "2" * 64}
    # 仅第二张是 debug
    debug = [f for f in result.findings if f.id.startswith("CERT-DEBUG")]
    assert len(debug) == 1
    assert debug[0].id == "CERT-DEBUG-1"


def test_certificates_call_failure_records_error():
    class _BoomCtx(FakeContext):
        def certificates(self):  # type: ignore[override]
            raise RuntimeError("cannot read certs")

    result = CertificateAnalyzer().analyze(_BoomCtx())
    assert result.error is not None
    assert "证书" in result.error
    assert result.leads == []
    assert result.findings == []


def test_meta_collects_schemes_union():
    c1 = _release_cert(sha256="1" * 64, schemes=["v1", "v2"])
    c2 = _release_cert(sha256="2" * 64, schemes=["v2", "v3"])
    result = _analyze([c1, c2])
    assert result.meta["schemes"] == ["v1", "v2", "v3"]


def test_lead_notes_marks_self_signed():
    cert = _release_cert()  # issuer == subject
    result = _analyze([cert])
    assert "自签名" in result.leads[0].notes


def test_empty_sha256_falls_back_to_index_value():
    cert = _release_cert(sha256="")
    result = _analyze([cert])
    lead = result.leads[0]
    assert lead.value == "cert[0]"
