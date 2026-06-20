"""backend_credential 分析器测试：从扣押 APK 静态抠后端/管理凭据（取证，非攻击）。

高精度结构化形态（Basic-Auth/DB DSN/JDBC/云AK），误报近零；非凭据文本不产线索。
凭据 Lead 为高敏、合规说明、letters 跳过（无直接受文机关，凭据供有权机关依法使用）。
"""

from __future__ import annotations

import base64

from apkscan.analyzers.backend_credential import BackendCredentialAnalyzer
from apkscan.core.models import Confidence, LeadCategory
from apkscan.report.letters import build_letters


class _Ctx:
    def __init__(self, dex=None, files=None, contents=None) -> None:
        self._dex = dex or []
        self._files = files or []
        self._contents = contents or {}

    def dex_strings(self):
        return list(self._dex)

    def list_files(self):
        return list(self._files)

    def read_file(self, path: str):
        return self._contents.get(path)


def _leads(ctx: _Ctx):
    return BackendCredentialAnalyzer().analyze(ctx).leads


def _basic(userpass: str) -> str:
    return "Authorization: Basic " + base64.b64encode(userpass.encode()).decode()


def test_basic_auth_decoded() -> None:
    leads = _leads(_Ctx(dex=[_basic("admin:s3cretP@ss")]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.BACKEND_CREDENTIAL
    assert lead.value == "Basic admin:s3cretP@ss"
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == "建议调证"
    assert "严禁未授权使用" in (lead.notes or "")


def test_basic_auth_invalid_no_lead() -> None:
    # 非合法 base64 / 解出无冒号 → 不是凭据。
    assert _leads(_Ctx(dex=["Authorization: Basic notbase64!!!"])) == []
    assert _leads(_Ctx(dex=["Authorization: Basic " + base64.b64encode(b"nocolon").decode()])) == []


def test_db_dsn() -> None:
    leads = _leads(_Ctx(dex=["db=mysql://root:pass123@db.evil.com:3306/app"]))
    assert len(leads) == 1
    assert "mysql://root:pass123@db.evil.com" in leads[0].value


def test_jdbc_password() -> None:
    leads = _leads(_Ctx(dex=["jdbc:mysql://10.0.0.1/app?user=adm&password=Qwer1234"]))
    assert len(leads) == 1
    assert "password=Qwer1234" in leads[0].value


def test_cloud_access_keys() -> None:
    aws = _leads(_Ctx(dex=["key=AKIAIOSFODNN7EXAMPLE end"]))
    assert any(lead.value == "AKIAIOSFODNN7EXAMPLE" for lead in aws)
    ali = _leads(_Ctx(dex=["ak: LTAI5t0Jq8s9d0f1g2h3 ;"]))
    assert any(lead.value == "LTAI5t0Jq8s9d0f1g2h3" for lead in ali)


def test_no_credential_no_lead() -> None:
    assert _leads(_Ctx(dex=["https://evil.com/api/login", "normal config string"])) == []


def test_access_key_word_boundary_no_false_positive() -> None:
    # 超长全大写串不应被误当 AWS/阿里云 AK（词边界护栏）。
    assert _leads(_Ctx(dex=["AKIA" + "B" * 25])) == []
    assert _leads(_Ctx(dex=["LTAI" + "C" * 40])) == []


def test_resource_scan() -> None:
    ctx = _Ctx(
        files=["assets/www/config.js", "res/raw/x.png"],
        contents={
            "assets/www/config.js": b"var db='mongodb://u:pw123@10.1.2.3:27017/d';",
            "res/raw/x.png": b"\x89PNG",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].source_refs[0].source == "resource"


def test_letters_skips_backend_credential() -> None:
    # 凭据无直接受文机关（供有权机关依法使用）→ letters 跳过、不套打协查函。
    lead = _leads(_Ctx(dex=[_basic("admin:pw")]))[0]
    report = {
        "leads": [
            {
                "category": lead.category.value,
                "value": lead.value,
                "where_to_request": lead.where_to_request,
                "evidence_to_obtain": lead.evidence_to_obtain,
                "advice": lead.advice,
                "subject": lead.subject,
            }
        ]
    }
    assert build_letters(report) == []
