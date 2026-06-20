"""admin_panel 分析器测试：从 URL 识别后台管理系统入口 → ADMIN_PANEL 调证线索。

零真机、零联网：用轻量 stub ctx 喂 dex 字符串 / 文本资源。host 研判走真实
infra.classify_domain（离线纯函数）：evilbackend.* → 建议调证、firebase → 无需调证。
"""

from __future__ import annotations

from apkscan.analyzers.admin_panel import AdminPanelAnalyzer
from apkscan.core import infra
from apkscan.core.models import Confidence, LeadCategory
from apkscan.report.letters import build_letters


class _Ctx:
    """最小 AnalysisContext 替身：仅实现 admin_panel 用到的三个接口。"""

    def __init__(
        self,
        dex: list[str] | None = None,
        files: list[str] | None = None,
        contents: dict[str, bytes] | None = None,
    ) -> None:
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
    return AdminPanelAnalyzer().analyze(ctx).leads


def test_admin_api_path_high() -> None:
    leads = _leads(_Ctx(dex=["base=https://api.evilbackend.com/api/admin/login"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.ADMIN_PANEL
    assert lead.value == "api.evilbackend.com"
    assert lead.confidence is Confidence.HIGH
    assert lead.advice == infra.ADVICE_INVESTIGATE


def test_admin_subdomain_host_high() -> None:
    leads = _leads(_Ctx(dex=["https://admin.evilbackend.com/home"]))
    assert len(leads) == 1
    assert leads[0].value == "admin.evilbackend.com"
    assert leads[0].confidence is Confidence.HIGH
    assert leads[0].advice == infra.ADVICE_INVESTIGATE


def test_generic_admin_path_is_review() -> None:
    leads = _leads(_Ctx(dex=["https://evilbackend.com/admin/"]))
    assert len(leads) == 1
    assert leads[0].confidence is Confidence.MEDIUM
    assert leads[0].advice == infra.ADVICE_REVIEW


def test_skip_known_infra_console() -> None:
    # console.firebase.google.com 是已知第三方基础设施的管理控制台 → 不产线索。
    leads = _leads(_Ctx(dex=["https://console.firebase.google.com/project/x/admin"]))
    assert leads == []


def test_skip_private_host() -> None:
    leads = _leads(_Ctx(dex=["http://192.168.1.1/admin/login"]))
    assert leads == []


def test_no_admin_pattern_no_lead() -> None:
    leads = _leads(_Ctx(dex=["https://evilbackend.com/home/index"]))
    assert leads == []


def test_dedup_per_host() -> None:
    # 同一 host 多个后台 URL → 仅一条线索（按 host 去重），强档优先。
    leads = _leads(
        _Ctx(
            dex=[
                "https://evilbackend.com/admin/",  # review
                "https://evilbackend.com/api/admin/users",  # high
            ]
        )
    )
    assert len(leads) == 1
    assert leads[0].value == "evilbackend.com"
    assert leads[0].confidence is Confidence.HIGH  # 强档把整 host 升 HIGH


def test_resource_scan_detects_h5_url() -> None:
    ctx = _Ctx(
        files=["assets/www/app-service.js", "res/raw/foo.png"],
        contents={
            "assets/www/app-service.js": b'var api="https://manage.evilbackend.com/api/admin/list";',
            "res/raw/foo.png": b"\x89PNG not-text",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].value == "manage.evilbackend.com"
    assert leads[0].source_refs[0].source == "resource"
    assert "app-service.js" in leads[0].source_refs[0].location


def test_lead_is_letter_ready() -> None:
    # ADMIN_PANEL 线索须可直接套打调证函：where_to_request 为真实受文机关 + evidence_to_obtain 非空。
    leads = _leads(_Ctx(dex=["https://api.evilbackend.com/api/admin/login"]))
    lead = leads[0]
    assert lead.evidence_to_obtain  # 非空
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
    drafts = build_letters(report)
    assert len(drafts) == 1
    assert drafts[0]["category"] == "ADMIN_PANEL"
