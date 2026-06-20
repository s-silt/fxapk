"""card_merchant 分析器测试：从 dex 字符串 / 文本资源识别卡商 / 料商关键词 → CARD_MERCHANT 线索。

零真机、零联网：用轻量 stub ctx 喂 dex 字符串 / 文本资源。本类信号 FP 高、无直接调证
对象，故**默认一律 MEDIUM·待核（advice=待核）**，绝不自动「建议调证」；命中多个高区分
关键词时 notes 标「重点」但仍待核。letters 据 where_to_request 占位文案跳过（预期）。
"""

from __future__ import annotations

from apkscan.analyzers.card_merchant import CardMerchantAnalyzer
from apkscan.core import infra
from apkscan.core.models import Confidence, LeadCategory
from apkscan.report.letters import build_letters


class _Ctx:
    """最小 AnalysisContext 替身：仅实现 card_merchant 用到的三个接口。"""

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
    return CardMerchantAnalyzer().analyze(ctx).leads


def test_single_keyword_is_review() -> None:
    # 命中单个高区分关键词 → 一条线索，MEDIUM·待核，绝不自动建议调证。
    leads = _leads(_Ctx(dex=["欢迎光临本站，专业卡商一手货源"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.CARD_MERCHANT
    assert lead.confidence is Confidence.MEDIUM
    assert lead.advice == infra.ADVICE_REVIEW
    assert "卡商" in lead.value


def test_multi_keyword_marks_focus_still_review() -> None:
    # 命中多个不同高区分关键词 → notes 标「重点」，但仍 MEDIUM·待核（不升 advice）。
    leads = _leads(
        _Ctx(dex=["银行卡料 四件套 身份证料 全套供应"])
    )
    assert len(leads) == 1
    lead = leads[0]
    assert lead.confidence is Confidence.MEDIUM
    assert lead.advice == infra.ADVICE_REVIEW
    assert "重点" in lead.notes


def test_short_generic_word_no_lead() -> None:
    # 单字泛词（"料""卡"）不应误报：规则不收，正文里出现也不产线索。
    leads = _leads(_Ctx(dex=["原料充足，库存有卡", "饮料 资料 材料"]))
    assert leads == []


def test_weak_word_alone_no_lead() -> None:
    # 弱区分词"跑分"单独出现（安兔兔跑分）→ 不产线索、不计 title。
    leads = _leads(_Ctx(dex=["安兔兔手机跑分排行"]))
    assert leads == []


def test_weak_word_with_card_merchant_word_is_review() -> None:
    # "跑分" + 另一卡商高区分词共现 → 出"待核·重点"线索（仍 MEDIUM·待核）。
    leads = _leads(_Ctx(dex=["卡商接单跑分代收付"]))
    assert len(leads) == 1
    lead = leads[0]
    assert lead.category is LeadCategory.CARD_MERCHANT
    assert lead.confidence is Confidence.MEDIUM
    assert lead.advice == infra.ADVICE_REVIEW
    assert "重点" in lead.notes
    assert "跑分" in lead.value
    assert "卡商" in lead.value


def test_boundary_word_in_english_string_no_lead() -> None:
    # "收U"嵌在英文长串里（callbackUrl 之类）→ 词边界不成立且无高区分词共现 → 不产线索。
    leads = _leads(_Ctx(dex=["var callback收Url = getReceiveUrl();"]))
    assert leads == []


def test_boundary_word_with_word_boundary_is_review() -> None:
    # "收U"在中文语境（前后非 ASCII 字母数字）→ 词边界成立 → 单独出现即可产待核线索。
    leads = _leads(_Ctx(dex=["长期收U，秒结"]))
    assert len(leads) == 1
    assert leads[0].advice == infra.ADVICE_REVIEW
    assert leads[0].confidence is Confidence.MEDIUM


def test_whitelist_far_context_does_not_swallow_real_hit() -> None:
    # 长文本里别处出现白名单"银行卡管理"，不应吞掉远处的"卡商一手"真命中。
    text = "银行卡管理" + ("帮助说明文档内容" * 60) + "卡商一手货源"
    leads = _leads(_Ctx(dex=[text]))
    assert len(leads) == 1
    assert "卡商" in leads[0].value


def test_whitelist_context_excluded() -> None:
    # 正规票据 / 卡包功能描述行命中白名单 → 跳过该命中（不产线索）。
    leads = _leads(_Ctx(dex=["承兑汇票贴现业务办理指南"]))
    assert leads == []


def test_known_infra_host_excluded() -> None:
    # 含已知正规基础设施 host 的 URL 行 → 视为正规语境，跳过该命中。
    leads = _leads(
        _Ctx(dex=["https://docs.aliyun.com/卡商 接入文档示例"])
    )
    assert leads == []


def test_no_keyword_no_lead() -> None:
    leads = _leads(_Ctx(dex=["https://evilbackend.com/home/index", "正常文案"]))
    assert leads == []


def test_dedup_single_lead_across_sources() -> None:
    # 同一关键词在 dex 与资源多处命中 → 仅一条线索（整样本级去重）。
    ctx = _Ctx(
        dex=["卡商一手", "卡商批发"],
        files=["assets/www/app.js"],
        contents={"assets/www/app.js": "卡商联系方式".encode("utf-8")},
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].value == "卡商"


def test_resource_scan_detects_keyword() -> None:
    ctx = _Ctx(
        files=["assets/www/app-service.js", "res/raw/foo.png"],
        contents={
            "assets/www/app-service.js": "var t='专业料商 银行卡料 全套';".encode("utf-8"),
            "res/raw/foo.png": b"\x89PNG not-text",
        },
    )
    leads = _leads(ctx)
    assert len(leads) == 1
    assert leads[0].source_refs[0].source == "resource"
    assert "app-service.js" in leads[0].source_refs[0].location


def test_not_letter_ready_skipped_by_letters() -> None:
    # 本类无直接调证对象 → where_to_request 为占位文案，letters 据此跳过（预期）。
    leads = _leads(_Ctx(dex=["卡商料商一手货源"]))
    lead = leads[0]
    assert "无直接调证对象" in (lead.where_to_request or "")
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
    assert drafts == []  # 待核 + 无受文机关 → 不套打
