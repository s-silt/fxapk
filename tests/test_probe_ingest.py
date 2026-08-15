"""apkscan.dynamic.probe_ingest 的单测。

probe_ingest 把独立 frida 探针(自备，`-l` 注入)吐到 console 的 `[tag][LEAD-...]` 散点输出，
解析→按 LeadCategory 分类→去重→聚成调证台账(md/json)，并可追加进 report.json。
本套测试覆盖：解析只取含 [LEAD 的行、tag→category 分类、去重、台账分组、report.json 追加。
"""

from __future__ import annotations

import json

import pytest

from apkscan.core import infra
from apkscan.core import runtime_inventory as _inv
from apkscan.core.closure import CLOSURE_PARTIAL, evaluate_capture_quality
from apkscan.core.models import LeadCategory
from apkscan.dynamic import probe_ingest
from tests.doc_addresses import (
    DOC_BACKEND_IP,
    DOC_IPV6,
    DOC_SECOND_IP,
    public_and_non_public_probe_cases,
    restore_real_address_calipers,
    treat_doc_addresses_as_public,
)


@pytest.fixture(autouse=True)
def _treat_documentation_ip_as_a_synthetic_public_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """夹具地址一律用 RFC 5737 / RFC 3849 文档段，「需要被判公网」改由定向放行表达。

    放行只覆盖列出的三个占位值（见 :mod:`tests.doc_addresses`），
    ``192.168.1.9`` / ``127.0.0.1`` / ``::1`` / ``fe80::1`` 这些本机侧地址仍走真实判据，
    故「私网不入端点」这类断言不会被补丁抽空。
    """
    treat_doc_addresses_as_public(monkeypatch, DOC_BACKEND_IP, DOC_SECOND_IP, DOC_IPV6)


# ---- 真实探针输出取样（格式与 probe-templates/*.js 实际 console.log 一致）----
_SAMPLE_LOG = "\n".join(
    [
        "[pay][alipay] PayTask.payV2 调起：",
        "[pay][alipay]   seller_id = 2088123456789012  [LEAD-定人:收款主体→向支付宝调实名结算账户]",
        "[pay][alipay]   notify_url = https://pay.evil-backend.com/notify  [LEAD-穿透:真后端]",
        "[pay][wechat]   partnerId = 1900000109  [LEAD-定人:商户号→向财付通/微信支付调实名结算账户]",
        "[sms][LEAD-定人] 转发 destinationAddress=+8613800138000 正文=验证码123456 [LEAD-OTP]",
        "[push-c2][LEAD-C2] payload 含 wss://c2.evil-backend.com:8443/cmd",
        "[sens][LEAD-固证] 读取通讯录 ← ContentResolver.query content://contacts",
        "[ks][LEAD-固证:可拷脱机解密] alias=\"chat_key\" 类型=对称密钥 安全级别=软件(可拷走→脱机解密)",
        "[a11y][LEAD-固证] dispatchGesture ← 模拟手势(自动确认转账)",
        "[nfc][LEAD-固证] IsoDep.transceive >>> 00A4040007A0000000031010  [LEAD-定人] SELECT AID=A0000000031010",
        "[netstat] [LEAD->接入节点] 198.51.100.12:30113  SYN_SENT",
        "[sdk] OpenInstall appKey = ehahb5  [LEAD]",
        "[tg] TL_auth_signIn username=qq888999  [LEAD->登录明文]",
        "[nav] onCreate com.x.SplashActivity   <== 疑似 splash/loading/视频层",  # 无 LEAD，应被忽略
        "[wipe] 已就绪 —— 普通日志行，无 LEAD",  # 无 LEAD，应被忽略
    ]
)


def test_parse_only_keeps_lead_lines() -> None:
    """只解析含 [LEAD 的行，普通日志行(onCreate/已就绪)被忽略。"""
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    assert len(leads) >= 11  # 11 条带 LEAD 的取样
    for pl in leads:
        assert "[LEAD" in pl.raw


def test_classify_pay_to_payment() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    pay = [pl for pl in leads if pl.probe == "pay"]
    assert pay, "应解析出 pay 探针的线索"
    assert all(pl.category == LeadCategory.PAYMENT for pl in pay)
    # 商户号/seller_id 的 where_to_request 指向支付机构
    assert any("支付" in (pl.where_to_request or "") for pl in pay)


def test_classify_sms_to_sms_forwarding() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    sms = [pl for pl in leads if pl.probe == "sms"]
    assert sms and all(pl.category == LeadCategory.SMS_FORWARDING for pl in sms)


def test_classify_push_c2_to_self_hosted_im() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    c2 = [pl for pl in leads if pl.probe == "push-c2"]
    assert c2 and all(pl.category == LeadCategory.SELF_HOSTED_IM for pl in c2)


def test_classify_sensitive_to_victim_data() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    sens = [pl for pl in leads if pl.probe == "sens"]
    assert sens and all(pl.category == LeadCategory.VICTIM_DATA for pl in sens)


def test_classify_keystore_to_crypto_recipe() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    ks = [pl for pl in leads if pl.probe == "ks"]
    assert ks and all(pl.category == LeadCategory.CRYPTO_RECIPE for pl in ks)


def test_classify_a11y_to_remote_control() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    a = [pl for pl in leads if pl.probe == "a11y"]
    assert a and all(pl.category == LeadCategory.REMOTE_CONTROL for pl in a)


def test_classify_nfc_to_card_merchant() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    n = [pl for pl in leads if pl.probe == "nfc"]
    assert n and all(pl.category == LeadCategory.CARD_MERCHANT for pl in n)


def test_classify_netstat_to_ip() -> None:
    leads = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    ns = [pl for pl in leads if pl.probe == "netstat"]
    assert ns and all(pl.category == LeadCategory.IP for pl in ns)
    assert any("30113" in pl.value for pl in ns)


def test_value_strips_bracket_markers() -> None:
    """value 去掉 [tag]/[LEAD..] 方括号标记，保留真锚点内容。"""
    leads = probe_ingest.parse_probe_log("[sdk] OpenInstall appKey = ehahb5  [LEAD]")
    assert leads
    assert "ehahb5" in leads[0].value
    assert "[LEAD" not in leads[0].value and "[sdk]" not in leads[0].value


def test_dedup_by_category_and_value() -> None:
    dup = "[sdk] appKey = ehahb5 [LEAD]\n[sdk] appKey = ehahb5 [LEAD]\n[sdk] appKey = other [LEAD]"
    leads = probe_ingest.dedup(probe_ingest.parse_probe_log(dup))
    vals = [pl.value for pl in leads]
    assert len(vals) == len(set((pl.category, pl.value) for pl in leads))
    assert len([v for v in vals if "ehahb5" in v]) == 1


def test_build_ledger_md_groups_by_category() -> None:
    md = probe_ingest.build_ledger_md(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert "# " in md or "## " in md  # 有标题
    # 分类中文名/where_to_request 出现
    assert "PAYMENT" in md or "支付" in md
    assert "向" in md  # where_to_request 含"向…调"
    assert "ehahb5" in md  # 锚点值进了台账


def test_to_report_leads_sets_runtime_source_and_advice() -> None:
    rls = probe_ingest.to_report_leads(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert rls
    for lead in rls:
        assert lead.source_refs and lead.source_refs[0].source.startswith("runtime")
        assert lead.advice in ("建议调证", "待核")
    # is_runtime_seen 应为 True（source=runtime）
    assert all(lead.is_runtime_seen for lead in rls)


def test_probe_infra_domain_from_the_real_tag_path_does_not_reach_the_top_tier() -> None:
    """★走**真入口**：``[push-c2] <厂商域>`` 日志行 → parse_probe_log → to_report_leads。

    这条必须从日志行起跑，不能手搓 ``ProbeLead(category=DOMAIN, ...)``：``push-c2`` 这个 tag
    经 ``_TAG_MAP`` 映射到的是 :attr:`LeadCategory.SELF_HOSTED_IM`，**不是** DOMAIN。手搓
    DOMAIN 的测试会全绿，而真实链路上厂商推送域照旧判最高档——那正是本刀第一版漏掉的东西，
    也正是「接线锁必须走真入口」这条纪律说的：只调被测函数测不到接线。
    """
    infra_host = sorted(infra.KNOWN_INFRA_EXACT)[0]

    leads = probe_ingest.to_report_leads(
        probe_ingest.parse_probe_log(f"[push-c2] {infra_host} [LEAD-穿透]")
    )

    assert len(leads) == 1
    assert leads[0].category == LeadCategory.SELF_HOSTED_IM, (
        "前置断言：真实链路上它就是 SELF_HOSTED_IM 而非 DOMAIN——这正是按 category 分流会漏掉它的原因"
    )
    assert leads[0].advice != infra.ADVICE_INVESTIGATE, (
        f"{infra_host} 命中已知第三方基础设施名单，探针见过它不构成「其持有方值得被追问」"
    )


def test_probe_infra_domain_bottoms_out_at_review_not_skip() -> None:
    """保底「待核」、不落 SKIP：SKIP 是判据链结论、不走抑制账本，``lead restore`` 够不着。

    探针是进程内的，捕到的是这个 App 自己的行为（不像整机 pcap 有归因问题）。真 C2 借宿在
    厂商域下时，待核是唯一还留得住这条观测的档位：关掉自动出口，但留在清单里供人核。
    """
    infra_host = sorted(infra.KNOWN_INFRA_EXACT)[0]
    # 前置断言：判据链本身对该值判的确实是 SKIP，否则本测试测不到保底那条分支。
    assert infra.classify_domain(infra_host)[0] == infra.ADVICE_SKIP

    leads = probe_ingest.to_report_leads(
        probe_ingest.parse_probe_log(f"[push-c2] {infra_host} [LEAD-穿透]")
    )

    assert leads[0].advice == infra.ADVICE_REVIEW, "判据链判 SKIP 时应保底抬到待核"
    assert leads[0].base_advice == infra.ADVICE_REVIEW, (
        "base_advice 必须一并封存——否则这条线索上任何降档都撤不回来"
    )


def test_probe_extracts_the_network_target_out_of_url_and_hostport_shapes() -> None:
    """标的按**形态**提取：URL 取 host、``host:port`` 剥端口——厂商域藏在这两种形态里同样要被抓到。"""
    infra_host = sorted(infra.KNOWN_INFRA_EXACT)[0]

    for line in (
        f"[push-c2] wss://{infra_host}:8443/ws [LEAD-穿透]",
        f"[push-c2] {infra_host}:443 [LEAD-穿透]",
        f"[push-c2] https://{infra_host}/api/v1/push [LEAD-穿透]",
    ):
        leads = probe_ingest.to_report_leads(probe_ingest.parse_probe_log(line))
        assert leads, line
        assert leads[0].advice == infra.ADVICE_REVIEW, (
            f"{line!r}：标的是厂商域，无论包在哪种形态里都不该判最高档"
        )


def test_probe_public_dns_ip_goes_through_the_ip_criteria_not_the_domain_ones() -> None:
    """IP 走 :func:`infra.classify_ip`——公共递归 DNS 这类判据只在 IP 侧，拿域名判据判会整套绕过。"""
    dns_ip = "8.8.8.8"  # leak-scan: allow 公共递归 DNS 的判据夹具，须是真实可路由地址才命中该判据
    # 前置断言：IP 判据链确实把它判成最低档，否则本测试测不到「走对了判据链」这件事。
    assert infra.classify_ip(dns_ip)[0] == infra.ADVICE_SKIP
    assert infra.classify_domain(dns_ip)[0] != infra.ADVICE_SKIP, (
        "前置断言：域名判据链对它给不出同样结论——这正是必须分流的原因"
    )

    leads = probe_ingest.to_report_leads(probe_ingest.parse_probe_log(f"[netstat] {dns_ip}:53 [LEAD-穿透]"))

    assert leads[0].advice == infra.ADVICE_REVIEW, "IP 判据判 SKIP → 保底待核，而不是最高档"


@pytest.mark.parametrize("not_a_target", [
    "key=abcdefghijklmnopqrstuvwxyz0123456789.ab",   # 点分密钥：标签含 '='，不是合法 DNS 标签
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ab_cd",    # JWT：base64url 的 '_' 不是合法 DNS 字符
    "2088000000000001",                              # 商户号：无点、无 scheme、无端口
    "aes-256-cbc key/iv derived from build id",      # 描述串：含空格与斜杠
    "13800138000",                                   # 手机号
    "-lead-.example.com",                            # 标签以连字符开头
])
def test_network_target_rejects_values_that_are_not_network_targets(not_a_target: str) -> None:
    """★负向：非网络标的**不得**被提取——否则它们会被交给判据链，按值的偶然形态压档。

    探针的值里本来就混着密钥、token、签名串、号码。严格 DNS 标签校验是它们与真标的之间
    唯一的分界；用宽松的 ``valid_url_host``（只查「含点 + 末段 2–24 位字母」）挡不住这些。
    """
    assert probe_ingest._network_target(not_a_target) is None


def test_network_target_requires_a_numeric_port_before_stripping() -> None:
    """端口必须是数字才剥——否则 ``<厂商域>:not-a-port`` 这种描述串会被剥出一个厂商域来。"""
    infra_host = sorted(infra.KNOWN_INFRA_EXACT)[0]

    assert probe_ingest._network_target(f"{infra_host}:443") == ("domain", infra_host)
    assert probe_ingest._network_target(f"{infra_host}:not-a-port") is None


def test_probe_shape_suspicion_does_not_press_a_crypto_lead_down() -> None:
    """★形态怀疑**不**参与压档：密钥线索不因值恰好长得像编码伪域名而被压出最高档。

    判据链里两类结论混在一起——「这个标的的持有方是谁」（身份判定）与「这个字面像不像真域名」
    （形态怀疑）。对探针捕获的值只有前者成立：探针看到的是 App 真的在用的字符串，它像不像
    域名不影响其持有方是不是无关第三方。让后者参与压档，CRYPTO_RECIPE 这类本该最高档的线索
    会因值的偶然形态被压下去。

    夹具是一个足够长、足够高熵的标签——它确实会被 ``looks_like_encoding`` 判成编码伪域名
    （下面第一条断言钉住这个前提），但档位不受影响。

    ★TLD **不能**用 ``.example`` / ``.test``：那些是 RFC 保留域，属身份判定（标准保证不存在
      注册人）、本来就该压档，夹具命中它就测不到「纯形态怀疑」那条路了。三条前置断言分别
      排除三类身份判定命中。
    """
    encoded_like = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.com"  # leak-scan: allow 合成高熵标签，TLD 必须非保留域否则命中保留域判据、测不到形态怀疑那条路
    # 前置断言：判据链对这个值给的确实是「形态怀疑」类的待核，否则本测试测不到那条分支。
    assert infra.classify_domain(encoded_like)[0] == infra.ADVICE_REVIEW
    assert infra._matched_infra(encoded_like) is None, "前置断言：它不是身份判定命中"
    assert infra._reserved_domain_match(encoded_like) is None, "前置断言：它不是 RFC 保留域"
    assert infra._public_ip_echo_service(encoded_like) is None, "前置断言：它不是回显服务"

    leads = probe_ingest.to_report_leads(
        [probe_ingest.ProbeLead(category=LeadCategory.CRYPTO_RECIPE, value=encoded_like,
                                probe="ks", raw="x")]
    )

    assert leads[0].advice == infra.ADVICE_INVESTIGATE, (
        "形态怀疑不该把密钥线索压出最高档——判据链只在身份判定命中时才有话语权"
    )


def test_probe_echo_service_is_still_pressed_down() -> None:
    """回显服务判 REVIEW 而不是 SKIP，但它属**身份判定**，仍须压档——不能跟形态怀疑一起被忽略。"""
    echo_host = sorted(infra._IP_ECHO_SERVICES)[0]
    assert infra.classify_domain(echo_host)[0] == infra.ADVICE_REVIEW, "前置断言：它不是 SKIP 档"

    leads = probe_ingest.to_report_leads(
        probe_ingest.parse_probe_log(f"[push-c2] {echo_host} [LEAD-穿透]")
    )

    assert leads[0].advice == infra.ADVICE_REVIEW, "回显服务的持有方与本次分析无关，须压档"


@pytest.mark.parametrize("reserved_line, reserved_host", [
    ("[push-c2] https://config.test/api [LEAD-穿透]", "config.test"),
    ("[push-c2] c2.localhost [LEAD-穿透]", "c2.localhost"),
    ("[push-c2] gateway.local:8443 [LEAD-穿透]", "gateway.local"),
])
def test_probe_rfc_reserved_domain_is_pressed_down(reserved_line: str, reserved_host: str) -> None:
    """★RFC 保留的文档 / 测试域须压档——标准保证了它**不存在可查的注册人**。

    这条容易被归错类：保留域走的是判据链里那些「出口为待核」的分支，看着像形态怀疑
    （「这串东西可能不是真域名」），实则是**可查性判定**——``.test`` / ``.localhost`` /
    ``.local`` 由 RFC 明令不可注册，不是「像不像域名」的问题，是「查无此人」的问题。
    当形态怀疑放行，就会让一个明知没有持有方的域进最高档、进而进文书出口。
    """
    # 前置断言：判据链对它给的是待核而**不是** SKIP，否则本条测的就不是「特判分支」那条路。
    assert infra.classify_domain(reserved_host)[0] == infra.ADVICE_REVIEW
    assert infra._matched_infra(reserved_host) is None, "前置断言：它不是走 SKIP 那条身份判定"

    leads = probe_ingest.to_report_leads(probe_ingest.parse_probe_log(reserved_line))

    assert leads[0].advice == infra.ADVICE_REVIEW, (
        f"{reserved_host} 是 RFC 保留域，不存在可查的注册人，不得回升到最高档"
    )


@pytest.mark.parametrize("bogus_port_value", ["token:0", "key:999999999", "seed:000000"])
def test_network_target_rejects_out_of_range_ports(bogus_port_value: str) -> None:
    """端口须在合法范围内——``token:0`` 这种「冒号后跟一串数字」不该凭此拿到单标签放行。"""
    assert probe_ingest._network_target(bogus_port_value) is None


def test_probe_domain_with_no_infra_match_still_reaches_the_top_tier() -> None:
    """反向：陌生域名照旧判最高档——本刀收紧的只是「命中已知基础设施」那部分，不是全面降档。

    ★夹具不能用 ``*.example`` / ``*.test``：那些是 RFC 2606 保留域，会命中
      ``_reserved_domain_match`` 判待核，于是这条反向锁测的就不是「无命中→最高档」那条路径。
      形态要求：有子域（避开单常见词 SLD 判据）、标签短（避开编码判据）、不命中任何名单。
    """
    unknown = "api.the.com"  # leak-scan: allow 判据链上零命中的夹具，用保留域会命中保留域判据、测不到「无命中→最高档」
    leads = probe_ingest.to_report_leads(
        [probe_ingest.ProbeLead(category=LeadCategory.DOMAIN, value=unknown,
                                probe="push-c2", raw="x")]
    )

    assert leads[0].advice == infra.ADVICE_INVESTIGATE
    assert leads[0].base_advice == infra.ADVICE_INVESTIGATE


def test_probe_non_network_categories_keep_the_top_tier() -> None:
    """非网络类别不受影响：商户号 / 密钥这些的标的不是域名持有方，域名判据链管不着它们。"""
    leads = probe_ingest.to_report_leads([
        probe_ingest.ProbeLead(category=LeadCategory.PAYMENT, value="2088000000000001",
                               probe="pay", raw="x"),
        probe_ingest.ProbeLead(category=LeadCategory.CRYPTO_RECIPE, value="key=0011deadbeef",
                               probe="ks", raw="x"),
        probe_ingest.ProbeLead(category=LeadCategory.CARD_MERCHANT, value="A0000000031010",
                               probe="nfc", raw="x"),
    ])

    by_cat = {ld.category: ld.advice for ld in leads}
    assert by_cat[LeadCategory.PAYMENT] == infra.ADVICE_INVESTIGATE
    assert by_cat[LeadCategory.CRYPTO_RECIPE] == infra.ADVICE_INVESTIGATE
    assert by_cat[LeadCategory.CARD_MERCHANT] == infra.ADVICE_REVIEW  # 情报研判，默认待核


def test_probe_infra_domain_produces_no_letter_even_with_evidence_filled(tmp_path) -> None:
    """★端到端负向锁：探针捕到的已知基础设施域，**即便填了取证路径**也不得套打出文书。

    这条锁的是「设计」而不是「运气」。修复前，探针 Lead 全都判最高档，之所以没在 letters 上
    酿成事故，仅仅因为 probe 路径没填 ``evidence_to_obtain``——而 ``_is_actionable`` 的条件 2
    正好要求它非空。也就是说，谁哪天顺手给探针 Lead 补上取证路径（这是完全合理的改进），
    闸门就会无声打开，指向厂商持有方的文书当场开始产出。

    所以这里刻意**把取证路径填满**，只让档位这一道闸拦着：档位判对了才有 0 份文书。
    把 :func:`probe_ingest._network_advice` 退回硬编码最高档，这条立刻变红。

    链路是完整的：**日志行** → ``parse_probe_log``（含 ``_TAG_MAP`` 分类）→
    ``merge_into_report_json``（真回灌 + 真 JSON 序列化）→ 从盘上读回 → ``build_letters``。
    一段都不许绕：``push-c2`` 经 ``_TAG_MAP`` 映射成 SELF_HOSTED_IM，手搓
    ``ProbeLead(category=DOMAIN, ...)`` 的测试会全绿而真实链路照旧出文书。
    """
    from apkscan.report import letters

    infra_host = sorted(infra.KNOWN_INFRA_EXACT)[0]
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")

    added = probe_ingest.merge_into_report_json(
        str(report_path),
        probe_ingest.parse_probe_log(f"[push-c2] {infra_host} [LEAD-穿透]"),
    )
    assert added == 1

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["leads"][0]["where_to_request"], (
        "前置断言：_TAG_MAP 给了受文方，出口闸不是靠它空着挡的"
    )
    # ★故意填满：不让本测试依赖「probe 恰好没填 evidence_to_obtain」这个巧合。
    payload["leads"][0]["evidence_to_obtain"] = ["RDAP/WHOIS 注册人/注册邮箱/注册时间"]

    out = letters.build_letters(payload)

    assert out == [], (
        f"已知第三方基础设施域 {infra_host} 不得产出文书——其持有方与本次分析无关，"
        "向它发函正是本项目定义中最重的那类误判"
    )


def test_coverage_axes_flags_missing_and_suggests() -> None:
    """只抓到 PAYMENT(定人轴)时，穿透/固证轴标未覆盖并给补跑建议。"""
    leads = probe_ingest.parse_probe_log("[pay] seller_id=2088123 [LEAD-定人]")
    cov = probe_ingest.coverage_axes(leads)
    assert len(cov) == 3  # 定人/穿透/固证
    ren = {k: v for k, v in cov.items()}
    dingren = next(v for k, v in ren.items() if "定人" in k)
    assert dingren["covered"] and "PAYMENT" in dingren["categories"]
    chuantou = next(v for k, v in ren.items() if "穿透" in k)
    assert not chuantou["covered"]
    assert "http-url" in chuantou["suggestion"] or "netstat" in chuantou["suggestion"]
    guzheng = next(v for k, v in ren.items() if "固证" in k)
    assert not guzheng["covered"] and guzheng["suggestion"]


def test_ledger_md_includes_coverage_section() -> None:
    md = probe_ingest.build_ledger_md(probe_ingest.parse_probe_log(_SAMPLE_LOG))
    assert "取证完备性" in md
    assert "定人" in md and "穿透" in md and "固证" in md


def test_build_ledger_md_escapes_injection_in_value() -> None:
    """★回归（codex 全库审计 P1）：探针 value/probe 样本可控，markdown 台账须转义反引号/HTML/链接，
    不裸包 inline-code 让载荷逃逸注入（主 HTML 报告另走 Jinja 自动转义、不受此路径影响）。"""
    from apkscan.core.models import LeadCategory

    payload = "x` <img src=x onerror=alert(document.domain)> `"
    lead = probe_ingest.ProbeLead(category=LeadCategory.PAYMENT, value=payload, probe="pay", raw=payload)
    md = probe_ingest.build_ledger_md([lead])
    assert "<img" not in md.replace("\\<img", "")  # 无裸 <img（只余被转义的 \<img）
    assert "\\`" in md  # 反引号被转义，载荷无法逃逸 inline-code


def test_merge_into_report_json_appends_and_dedups(tmp_path) -> None:
    report = {"leads": [{"category": "PAYMENT", "value": "已存在 2088", "advice": "建议调证"}]}
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    pls = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    added = probe_ingest.merge_into_report_json(str(p), pls)
    assert added > 0
    out = json.loads(p.read_text(encoding="utf-8"))
    assert len(out["leads"]) == 1 + added
    # 原有 lead 仍在
    assert any(l.get("value") == "已存在 2088" for l in out["leads"])
    # 新 lead 带 source=runtime
    new_lead = next(l for l in out["leads"] if "ehahb5" in str(l.get("value", "")))
    assert new_lead["source_refs"][0]["source"].startswith("runtime")
    assert new_lead["source_refs"][0]["scope"] == "case_evidence"


# ======================================================================
# 原子写：写中途失败不留半截坏 JSON
# ======================================================================


def test_merge_atomic_keeps_old_content_when_write_fails(tmp_path, monkeypatch) -> None:
    p = tmp_path / "report.json"
    original = {"leads": [{"category": "PAYMENT", "value": "已存在 2088", "advice": "建议调证"}]}
    p.write_text(json.dumps(original, ensure_ascii=False, indent=2), encoding="utf-8")

    def boom(*_a, **_k):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(probe_ingest.atomic_write_text.__module__ + ".Path.write_text", boom, raising=True)

    pls = probe_ingest.parse_probe_log(_SAMPLE_LOG)
    added = probe_ingest.merge_into_report_json(str(p), pls)
    assert added == 0
    reloaded = json.loads(p.read_text(encoding="utf-8"))
    assert reloaded == original


# ======================================================================
# runtime 确认合并（非 dedup 丢弃）
# ======================================================================


def test_merge_runtime_confirms_existing_static_lead(tmp_path) -> None:
    """静态已有同 (category,value)，回灌 runtime 探针观测 → 合并升为活体确认，不丢 runtime 证据。"""
    p = tmp_path / "report.json"
    # OpenInstall appKey = ehahb5 → CONFIG_KEY / value 含 "ehahb5"
    pls = probe_ingest.parse_probe_log("[sdk] OpenInstall appKey = ehahb5  [LEAD]")
    runtime_lead = probe_ingest.to_report_leads(pls)[0]
    static_lead = {
        "category": runtime_lead.category.value,
        "value": runtime_lead.value,
        "advice": "建议调证",
        "source_refs": [{"source": "dex", "location": "com/x/Cfg", "snippet": "静态硬编码"}],
        "is_runtime_seen": False,
    }
    p.write_text(json.dumps({"leads": [static_lead]}, ensure_ascii=False, indent=2), encoding="utf-8")

    probe_ingest.merge_into_report_json(str(p), pls)
    out = json.loads(p.read_text(encoding="utf-8"))
    same = [l for l in out["leads"] if l.get("value") == runtime_lead.value]
    assert len(same) == 1  # 未新增重复
    merged = same[0]
    sources = [str(ev.get("source", "")) for ev in merged.get("source_refs", [])]
    assert any(s.startswith("runtime") for s in sources)
    assert any(s == "dex" for s in sources)
    assert merged.get("is_runtime_seen") is True


# ======================================================================
# Evidence.observed_at 回灌落库
# ======================================================================


def test_parse_extracts_leading_timestamp() -> None:
    """行首 ISO 时间戳被解析进 ProbeLead.observed_at（epoch 秒）；无则 None。"""
    ts_line = "2026-07-02 10:30:00 [sdk] appKey = ehahb5 [LEAD]"
    pls = probe_ingest.parse_probe_log(ts_line)
    assert pls
    assert pls[0].observed_at is not None
    # 无时间戳的行 observed_at 为 None
    plain = probe_ingest.parse_probe_log("[sdk] appKey = xyz [LEAD]")
    assert plain and plain[0].observed_at is None


def test_observed_at_落库_into_report_json(tmp_path) -> None:
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": []}, ensure_ascii=False), encoding="utf-8")
    pls = probe_ingest.parse_probe_log("2026-07-02 10:30:00 [sdk] appKey = ehahb5 [LEAD]")
    probe_ingest.merge_into_report_json(str(p), pls)
    out = json.loads(p.read_text(encoding="utf-8"))
    lead = next(l for l in out["leads"] if "ehahb5" in str(l.get("value", "")))
    assert lead["source_refs"][0].get("observed_at") is not None


# ======================================================================
# meta 面（B-2b）：合并不只动 leads —— 采集质量/可见性读的是 meta
# ======================================================================
#
# 同一份 report.json 有三个消费面、各读各的：letters 出口读 leads、闭环排序读 endpoints、
# 采集质量与可见性读 meta。probe 路径此前**只**更新 leads，于是出现三处自相矛盾而每处单看
# 都自洽的状态：Lead 标着 runtime 实测、可见性说未做运行时观测、闭环判 failed。
#
# 合成值说明：只用 RFC 5737 文档保留段；上面的 fixture 定向放行该占位值以覆盖公网候选分支。

_ADDR_LOG = "\n".join(
    [
        f"[netstat] [LEAD->接入节点] {DOC_BACKEND_IP}:30113  SYN_SENT",
        "[http][LEAD->穿透] POST https://api.example.test/v1/login",
        "[netstat] [LEAD->接入节点] 192.168.1.9:8080  ESTABLISHED",
    ]
)

#: 并集测试要的是「pcap 侧已有一个公网端点」。地址仍是**字面量**文档保留段（扫描器看得见、
#: 也确认它无害），「被判公网」这件事由 autouse fixture 的定向放行表达，而不是靠挑一个
#: 碰巧可路由的真地址再拼接躲开泄漏扫描。
_PCAP_IP = DOC_SECOND_IP

#: 抽不出地址的线索：支付商户号与密钥别名。一条都不该计进端点/域名。
_NON_ADDR_LOG = "\n".join(
    [
        "[pay][alipay]   seller_id = 0000000000  [LEAD-定人:收款主体]",
        "[ks][LEAD-固证] alias=\"chat_key\" 类型=对称密钥 安全级别=软件",
    ]
)


def _merged_meta(tmp_path, log: str, *, meta: dict | None = None) -> dict:
    """把 log 解析后并进一份最小 report.json，返回合并后的 ``meta``。"""
    p = tmp_path / "report.json"
    payload: dict = {"leads": [], "endpoints": []}
    if meta is not None:
        payload["meta"] = meta
    p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    probe_ingest.merge_into_report_json(str(p), probe_ingest.parse_probe_log(log))
    out = json.loads(p.read_text(encoding="utf-8"))
    return out.get("meta") or {}


def test_probe_address_values_only_takes_real_addresses() -> None:
    """★只认真的地址：抽不出地址的线索一条都不计。

    探针 lead 的 value 是整行日志（``198.51.100.7:30113 SYN_SENT``），不是干净地址。
    把整行当端点值会污染外部富化对象，也会让闭环的业务候选计数虚高。
    """
    ips, domains = probe_ingest.probe_address_values(
        probe_ingest.parse_probe_log(_ADDR_LOG)
    )
    assert ips == {"198.51.100.7"}, "私网 IP 应被过滤，合成公网候选应被抽出"
    assert domains == {"api.example.test"}, "URL 的 host 应被抽出，且不含路径/协议"

    # 支付商户号 / 密钥别名：不是地址，计数必须为 0（否则闭环凭它们凑出业务候选）
    none_ips, none_domains = probe_ingest.probe_address_values(
        probe_ingest.parse_probe_log(_NON_ADDR_LOG)
    )
    assert not none_ips and not none_domains


def test_probe_address_values_matches_pcap_caliber_on_private_ips() -> None:
    """口径必须与 pcap 路径一致：两条路径的贡献集合取并集，口径不同 = 同一后端算两次。"""
    from apkscan.dynamic import pcap_ingest

    for private in ("192.168.1.9", "10.0.0.5", "127.0.0.1", "169.254.1.1"):
        line = f"[netstat] [LEAD->接入节点] {private}:8080  ESTABLISHED"
        ips, _ = probe_ingest.probe_address_values(probe_ingest.parse_probe_log(line))
        assert not ips, f"{private} 被 probe 侧收下了"
        assert not pcap_ingest._ip_public(private), f"{private} 在 pcap 侧口径不一致"


def test_probe_address_values_rejects_non_public_url_hosts() -> None:
    """★URL 通道也必须过公网闸：``http://127.0.0.1:8080/`` 这类自查行绝不入端点。

    裸 IP 早就走 ``is_noise_bare_ip`` 过滤了，但 URL 的 host 此前只过 ``valid_url_host``——
    它只判"长得像主机名"，明确放行 ``localhost`` 与任意 IPv4 字面量。于是探针在分析机上
    打出的本机地址会被当业务候选：①并进 endpoints 后被下游拿去向外部源查一个本机地址；
    ②撑大闭环 ``business_candidate_count``，凭空长出观测强度。
    删掉 ``url_host_is_reportable`` 调用 → 本测试必红。
    """
    non_public = (
        "http://127.0.0.1:8080/cfg",
        "http://localhost/api/v1",
        "http://localhost:3000/",
        "http://192.168.1.9/cfg",
        "http://10.0.0.5:8080/x",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0:9090/",
        "http://[::1]:8080/",
        "http://box.local/cfg",
        "http://gw.lan/admin",
        "http://svc.internal/v1",
    )
    for url in non_public:
        line = f"[http][LEAD->穿透] GET {url}"
        ips, domains = probe_ingest.probe_address_values(probe_ingest.parse_probe_log(line))
        assert not ips, f"{url} 的 host 被当成 IP 候选收下了"
        assert not domains, f"{url} 的 host 被当成域名候选收下了"


def test_probe_address_values_still_takes_public_url_hosts() -> None:
    """公网闸不得过度收紧：正常的公网 URL host 仍须照收（否则真线索被一起杀掉）。

    地址是文档保留段的**字面量**；「它算公网候选」由 autouse fixture 的定向放行表达。
    """
    line = (
        "[http][LEAD->穿透] POST https://api.example.test/v1/login  "
        f"via {DOC_BACKEND_IP}:7158"
    )
    ips, domains = probe_ingest.probe_address_values(probe_ingest.parse_probe_log(line))
    assert domains == {"api.example.test"}
    assert ips == {DOC_BACKEND_IP}


def test_url_host_is_reportable_agrees_with_pcap_caliber(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """URL 通道的判据与 pcap 侧 ``_ip_public`` 必须同口径（并集口径不漂移）。

    ★先撤掉本模块的 autouse 放行补丁：带着它比对两侧口径，比的是「补丁 vs 补丁」，
    真判据一旦漂移也测不出来。撤销用的是导入期捕获的真实引用。

    两个方向都要测：
      ①真判据下，私网/回环/保留一档两侧同判 False；
      ②定向放行后，同一个占位值两侧同判 True——否则「一侧收下、另一侧不收」的漂移
        会让同一个后端在并集里被算两次，而单看任一侧都自洽。
    """
    from apkscan.dynamic import pcap_ingest

    restore_real_address_calipers(monkeypatch)
    for ip, should_be_public in public_and_non_public_probe_cases():
        assert probe_ingest.url_host_is_reportable(ip) is pcap_ingest._ip_public(ip), ip
        assert probe_ingest.url_host_is_reportable(ip) is should_be_public, ip

    treat_doc_addresses_as_public(monkeypatch, DOC_BACKEND_IP)
    assert (
        probe_ingest.url_host_is_reportable(DOC_BACKEND_IP)
        is pcap_ingest._ip_public(DOC_BACKEND_IP)
        is True
    )


# ---------------------------------------------------------------------------
# 裸 IPv6 / ``[v6]:port`` 抽取
#
# 修复前的缺陷：URL 通道只处理带 scheme 的（``https://[2001:db8::1]/`` 能收），v4 通道只认
# 点分四段，于是 socket/ssl/netstat 标签里最常见的两种写法 ——``[2001:db8::1]:443
# ESTABLISHED`` 与裸 ``2001:db8::1``—— 在**两条通道上都不匹配**，被静默丢弃：既不入
# endpoints、也不计闭环候选，报告长得跟"没观测到 v6 后端"完全一样。
# ---------------------------------------------------------------------------


def _probe_ips(line: str) -> set[str]:
    ips, _ = probe_ingest.probe_address_values(probe_ingest.parse_probe_log(line))
    return ips


@pytest.mark.parametrize(
    "line",
    [
        # URL 形态（修复前唯一能work的一条，作为不回退的锚）。★现在它也走方括号通道：
        # URL 语法要求 v6 必须带方括号，故 URL 分支不再自己解析 v6（见共享预算）。
        f"[http][LEAD->穿透] GET https://[{DOC_IPV6}]:443/v1/cfg",
        f"[http][LEAD->穿透] POST https://[{DOC_IPV6}]/api/login",
        # ★方括号 + 端口：netstat / ss 输出的标准形态
        f"[netstat] [LEAD->接入节点] [{DOC_IPV6}]:443  ESTABLISHED",
        f"[netstat] [LEAD->接入节点] [{DOC_IPV6}]:8443  SYN_SENT",
        # ★裸 v6：socket / ssl hook 常直接打对端地址
        f"[socket] [LEAD->接入节点] connect {DOC_IPV6} port 8443",
        f"[ssl] [LEAD->穿透] peer={DOC_IPV6}",
        f"[socket] [LEAD] getpeername -> {DOC_IPV6}",
    ],
)
def test_probe_takes_public_ipv6_in_every_shape(line: str) -> None:
    """三种形态（URL / ``[v6]:port`` / 裸 v6）都必须抽出同一个规范化地址。

    删掉 ``_iter_ipv6_candidates`` 的接线 → 后五条必红（URL 那两条走另一条通道）。
    """
    assert _probe_ips(line) == {DOC_IPV6}, line


def test_probe_normalizes_ipv6_writing_variants() -> None:
    """大写 / 非压缩写法归一到 ``ipaddress`` 的压缩形，同一后端不会被计成两个端点。"""
    line = (
        "[netstat] [LEAD->接入节点] [2001:DB8:0000:0000:0000:0000:0000:0001]:443 ESTABLISHED"
        f" 另一条 [{DOC_IPV6}]:8443 ESTABLISHED"
    )
    assert _probe_ips(line) == {DOC_IPV6}


@pytest.mark.parametrize(
    "line",
    [
        # 回环 / 链路本地 / ULA 私网 / 未指定 / 多播：探针跑在分析机上，这些是常态不是线索
        "[netstat] [LEAD->接入节点] [::1]:8080  ESTABLISHED",
        "[netstat] [LEAD->接入节点] [fe80::1]:80  ESTABLISHED",
        "[netstat] [LEAD->接入节点] [fd00::1]:80  ESTABLISHED",
        "[socket] [LEAD] connect fe80::1%wlan0 port 80",
        "[netstat] [LEAD] [::]:0 LISTEN",
        # ★下一行是 RFC 4291 的 all-nodes 链路本地多播组地址：``ipaddress`` 的 ``is_global``
        #   对它为真，故必须由提取器自己按 multicast 拒掉，这条阴性夹具锁的就是那道拒绝，
        #   字面不可替换。豁免只加在夹具那一行（散文里刻意不复述该字面，否则说明行会成为
        #   又一处命中点，而给散文加豁免等于给判据开天窗）。
        "[socket] [LEAD] join ff02::1",  # leak-scan: allow ip 提取器阴性夹具，RFC4291 链路本地多播组地址非主机地址
        # ★内嵌 v4 的私网：换个写法的 192.168.1.9，放行它等于给私网开后门
        "[netstat] [LEAD->接入节点] [::ffff:192.168.1.9]:443  ESTABLISHED",
        "[socket] [LEAD] connect ::ffff:127.0.0.1 port 8080",
        # 非法 v6：多冒号 / 段过长 —— 严格性交给 IPv6Address，不许被正则"猜"成地址
        "[x] [LEAD->接入节点] bogus 2001:db8:::1",
        "[x] [LEAD->接入节点] bogus 2001:db8:12345::1",
        # 时间戳与 MAC：冒号分隔但不是地址，绝不能进候选
        "[x] [LEAD->接入节点] time 12:34:56 mac 00:1a:2b:3c:4d:5e",
        # ★未被显式放行的另一个 RFC 3849 地址：真判据下 2001:db8::/32 是保留段，不该上报
        "[netstat] [LEAD->接入节点] [2001:db8::dead:beef]:443  ESTABLISHED",
    ],
)
def test_probe_rejects_non_reportable_ipv6(line: str) -> None:
    """裸 v6 抽取必须保守：私网/回环/链路本地/保留/内嵌私网 v4/非地址一律不收。

    最后一条同时锁住 :func:`treat_doc_addresses_as_public` 的**放行范围**：它只放行
    显式列出的地址，未列出的文档地址仍走真实判据（否则 v6 那半边的阴性断言全成假绿）。
    """
    assert _probe_ips(line) == set(), line


@pytest.mark.parametrize(
    "ipv6_form",
    [
        f"::ffff:{DOC_BACKEND_IP}",  # IPv4-mapped
        "2002:c633:6407::1",  # 6to4，内嵌同一个 198.51.100.7
    ],
)
def test_probe_canonicalizes_embedded_v4_to_the_v4_value(ipv6_form: str) -> None:
    """内嵌 v4 的可上报 v6 归一成**内嵌那个 v4**，同一台主机不会被计成两个端点。

    ``::ffff:198.51.100.7`` 与 ``198.51.100.7`` 是同一台主机的两种写法，而 v4 通道本来就会
    从同一行文本里抽出后者。不归一，同一个后端会以两种形态各计一次，闭环的业务候选数虚高。

    把 :func:`_reportable_ipv6_value` 的内嵌分支改成 ``return addr.compressed`` → 本测试红。
    """
    line = f"[netstat] [LEAD->接入节点] [{ipv6_form}]:443  ESTABLISHED"
    assert _probe_ips(line) == {DOC_BACKEND_IP}, line


def test_probe_counts_embedded_v4_and_bare_v4_as_one_endpoint() -> None:
    """同一行里 v6 内嵌形与裸 v4 形并存时，端点集合里只有一个值（并集不重复计数）。"""
    line = (
        f"[netstat] [LEAD->接入节点] [::ffff:{DOC_BACKEND_IP}]:443  ESTABLISHED"
        f" / 同一后端裸形 {DOC_BACKEND_IP}:443"
    )
    assert _probe_ips(line) == {DOC_BACKEND_IP}


def test_probe_ipv6_candidate_extraction_is_bounded() -> None:
    """单条线索的 v6 候选数有硬上限：畸形长行不能让抽取无界增长。

    ★断言刻意写成 ``== 上限``（而不是 ``<= 上限``）：后者对任何上限都恒真，连"上限根本没
    生效、600 个候选全收下"也照样绿——那种写法测的是算术不是行为。这里喂进远超上限的候选数，
    要求恰好截在上限上，把 ``_iter_ipv6_candidates`` 里的 ``break``/``return`` 真正压住。
    """
    cap = probe_ingest.MAX_IPV6_CANDIDATES_PER_LEAD
    assert cap > 0
    excess = cap * 4
    blob = " ".join(f"[2001:db8::{index:x}]:443" for index in range(1, excess + 1))
    candidates = probe_ingest._iter_ipv6_candidates(blob)
    assert len(candidates) == cap, f"上限失效：喂 {excess} 个候选却收下 {len(candidates)} 个"


def _many_doc_v6(count: int, *, start: int = 1) -> list[str]:
    """造 ``count`` 个互不相同的 RFC 3849 文档 v6 地址（全部落在 2001:db8::/32）。"""
    return [f"2001:db8::{index:x}" for index in range(start, start + count)]


def test_url_ipv6_shares_the_single_ipv6_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """★URL 里的 v6 **不得**绕过每条 lead 的 v6 候选上限。

    修复前 URL 分支自己 ``parse_ip_literal`` + ``ips.add()``，于是 192 个
    ``https://[v6]/`` 能全部进集合 —— ``MAX_IPV6_CANDIDATES_PER_LEAD`` 在最容易被刷的
    那条通道上恰好不生效。现在 URL 里的 v6 一律交方括号通道，在同一个预算里扣。

    把 URL 分支改回"自己 add v6" → 本测试红（会收到远超上限的地址数）。
    """
    cap = probe_ingest.MAX_IPV6_CANDIDATES_PER_LEAD
    addresses = _many_doc_v6(cap * 3)
    # 放行全部地址，否则文档段被真判据拒掉、上限根本测不到（集合恒为空 = 假绿）。
    treat_doc_addresses_as_public(monkeypatch, *addresses)
    line = "[http][LEAD->穿透] GET " + " ".join(
        f"https://[{value}]:443/v1/cfg" for value in addresses
    )
    got = _probe_ips(line)
    assert len(got) <= cap, f"URL v6 绕过了上限：收下 {len(got)} 个（上限 {cap}）"


def test_ipv6_budget_is_shared_across_url_bracket_and_bare_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """URL / ``[v6]:port`` / 裸 v6 三种形态共用**同一个** 64 额度，不是各拥有一份。

    三通道各给 64 的话，一条 lead 最多能产出 192 个 v6 —— "每条 lead 的 v6 候选有界"
    这个不变量就名存实亡。
    """
    cap = probe_ingest.MAX_IPV6_CANDIDATES_PER_LEAD
    url_part = _many_doc_v6(cap, start=1)
    bracket_part = _many_doc_v6(cap, start=cap + 1)
    bare_part = _many_doc_v6(cap, start=cap * 2 + 1)
    treat_doc_addresses_as_public(monkeypatch, *url_part, *bracket_part, *bare_part)
    line = (
        "[http][LEAD->穿透] "
        + " ".join(f"https://[{v}]:443/x" for v in url_part)
        + " "
        + " ".join(f"[{v}]:8443 ESTABLISHED" for v in bracket_part)
        + " "
        + " ".join(bare_part)
    )
    got = _probe_ips(line)
    assert len(got) <= cap, f"三形态各自计数了：收下 {len(got)} 个（共享上限应为 {cap}）"


@pytest.mark.parametrize(
    "ipv6_form",
    [
        f"::ffff:{DOC_BACKEND_IP}",  # IPv4-mapped
        "2002:c633:6407::1",  # 6to4，内嵌同一个 198.51.100.7
    ],
)
def test_url_ipv6_embedded_v4_collapses_to_one_canonical_value(ipv6_form: str) -> None:
    """★URL 里的内嵌 v4 形 v6 必须与裸 v4 折叠成**同一个**值。

    修复前 URL 分支直接 ``ips.add(addr.compressed)``（跳过
    :func:`_reportable_ipv6_value` 的内嵌折叠），而 socket 通道又从同一行抽出内嵌的
    v4 —— 同一台主机以 ``::ffff:198.51.100.7`` 与 ``198.51.100.7`` 两种写法同时留在集合里，
    闭环候选数虚高、下游把一个后端富化两次。
    """
    line = (
        f"[http][LEAD->穿透] GET https://[{ipv6_form}]:443/v1/cfg"
        f" [socket] [LEAD->接入节点] connect {DOC_BACKEND_IP} port 443"
    )
    assert _probe_ips(line) == {DOC_BACKEND_IP}, line


def test_url_only_embedded_v4_ipv6_still_canonicalizes() -> None:
    """只有 URL 形（没有裸 v4 陪衬）时，内嵌 v4 也必须产出折叠后的 v4 而非 v6 写法。"""
    line = f"[http][LEAD->穿透] GET https://[::ffff:{DOC_BACKEND_IP}]:8443/api"
    assert _probe_ips(line) == {DOC_BACKEND_IP}, line


@pytest.mark.parametrize(
    ("channel", "cap_name"),
    [
        ("url", "MAX_URL_CANDIDATES_PER_LEAD"),
        ("ipv4", "MAX_IPV4_CANDIDATES_PER_LEAD"),
        ("host", "MAX_HOST_CANDIDATES_PER_LEAD"),
    ],
)
def test_every_extraction_channel_has_an_explicit_cap(channel: str, cap_name: str) -> None:
    """URL / 点分四段 / 主机名三条通道各自都有明确上限（海量输入不得无界处理）。

    这三条通道此前用 ``re.findall`` —— 会把全部匹配一次性物化。上限只截候选数、不改判据。
    """
    cap = getattr(probe_ingest, cap_name)
    assert isinstance(cap, int) and cap > 0, cap_name
    if channel == "url":
        pattern = probe_ingest._ADDR_URL_RE
        blob = " ".join(f"https://h{i}.example.test/p" for i in range(cap * 3))
    elif channel == "ipv4":
        pattern = probe_ingest._ADDR_IPV4_RE
        blob = " ".join(f"198.51.100.{i % 254 + 1}" for i in range(cap * 3))
    else:
        pattern = probe_ingest._ADDR_HOST_RE
        blob = " ".join(f"h{i}.example.test" for i in range(cap * 3))
    got = probe_ingest._bounded_findall(pattern, blob, cap)
    assert len(got) == cap, f"{cap_name} 未生效：收下 {len(got)} 个"


def test_bounded_findall_never_materializes_all_matches() -> None:
    """``_bounded_findall`` 必须惰性推进（``finditer``），峰值由 limit 而非输入长度决定。

    断言方式：喂一个匹配数远超 limit 的输入，要求只取到 limit 个。若实现退回
    ``findall()[:limit]``，结果虽相同但会先物化全部匹配 —— 故同时断言
    :func:`probe_ingest` 源码里这几条通道不再出现 ``findall``。
    """
    import inspect

    cap = 3
    blob = " ".join(f"198.51.100.{i}" for i in range(1, 200))
    assert len(probe_ingest._bounded_findall(probe_ingest._ADDR_IPV4_RE, blob, cap)) == cap
    source = inspect.getsource(probe_ingest.probe_address_values)
    assert ".findall(" not in source, "probe_address_values 不得再用 findall（会物化全部匹配）"
    assert ".findall(" not in inspect.getsource(probe_ingest._iter_ipv6_candidates)
    assert ".findall(" not in inspect.getsource(probe_ingest._bounded_findall)



def test_probe_ipv6_reaches_endpoints_and_inventory(tmp_path) -> None:
    """★三面一致：抽出的 v6 必须同时落进 endpoints 与 runtime 清单计数。

    只让 ``probe_address_values`` 认出 v6、但下游三面不一致，等于信号提取了没接线：
    清单说有 1 个远端，endpoints 里却没有可富化对象。
    """
    log = f"[netstat] [LEAD->接入节点] [{DOC_IPV6}]:443  ESTABLISHED"
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"leads": [], "endpoints": []}, ensure_ascii=False), encoding="utf-8"
    )
    probe_ingest.merge_into_report_json(str(path), probe_ingest.parse_probe_log(log))
    payload = json.loads(path.read_text(encoding="utf-8"))

    values = {ep.get("value") for ep in payload.get("endpoints", [])}
    assert DOC_IPV6 in values, "v6 端点没进 endpoints（下游拿不到可富化对象）"
    inventory = _inv.read_inventory(payload.get("meta") or {})
    assert inventory["remote_endpoints"] == 1
    assert inventory["domain_leads"] == 0
    # 上限仍是 partial：探针无设备侧 socket 快照，不得因为多认了 v6 就抬高闭环。
    assert inventory["uid_attributed"] is False


def test_probe_merge_refreshes_the_visibility_snapshot(tmp_path) -> None:
    """★探针回灌往 meta 写了 ``runtime_merged`` / 清单，就必须重算派生视图。

    与 pcap 回灌同一条纪律：快照是**算出来的**，写方只写信号不刷快照，落盘就会自相矛盾——
    报告一边有探针线索、一边说「未做运行时观测（纯静态分析）」。本模块曾只写 leads，
    后来加了 meta 却没跟上刷新（codex 复审 P1）。

    断言比对「落盘快照 == 对该 payload 现场重算」，所以它不针对某个写方：
    将来谁往 meta 写信号却忘了刷新，这条就会红。
    """
    from apkscan.core import visibility

    log = "[netstat] [LEAD->接入节点] 198.51.100.44:8443  ESTABLISHED"
    path = tmp_path / "report.json"
    # 预置一份 analyze 期的陈旧快照：那时确实还没有运行时数据
    path.write_text(json.dumps({
        "leads": [], "endpoints": [],
        "meta": {"visibility": {
            "sources": {"runtime": {"visibility": visibility.VIS_UNAVAILABLE,
                                    "why": ["未做运行时观测（纯静态分析）"]}},
            "blocked_claims": [],
        }},
    }, ensure_ascii=False), encoding="utf-8")

    probe_ingest.merge_into_report_json(str(path), probe_ingest.parse_probe_log(log))
    payload = json.loads(path.read_text(encoding="utf-8"))

    stored = payload["meta"]["visibility"]
    assert stored == visibility.assess(payload), \
        "落盘快照与现场重算不一致——探针回灌写了信号却没刷派生视图"
    rt = stored["sources"]["runtime"]
    assert rt["visibility"] != visibility.VIS_UNAVAILABLE, "陈旧的『未做运行时观测』没被替换"
    assert not any("未做运行时观测" in w for w in rt["why"]), rt["why"]


def test_probe_ipv6_caliber_agrees_with_pcap(monkeypatch: pytest.MonkeyPatch) -> None:
    """v6 口径必须与 pcap 侧 ``_ip_public`` 一致——两条路径的产出取并集，口径不同 = 算两次。

    ★先撤补丁再比，否则比的是「补丁 vs 补丁」。
    """
    import ipaddress

    from apkscan.dynamic import pcap_ingest

    restore_real_address_calipers(monkeypatch)
    for value, expected in (
        ("::1", False),
        ("fe80::1", False),
        ("fd00::1", False),
        ("::", False),
        ("::ffff:192.168.1.9", False),
        (DOC_IPV6, False),  # 真判据下 2001:db8::/32 是保留段
    ):
        addr = ipaddress.IPv6Address(value)
        assert probe_ingest._ipv6_is_reportable(addr) is expected, value
        assert pcap_ingest._ip_public(value) is expected, value

    treat_doc_addresses_as_public(monkeypatch, DOC_IPV6)
    assert (
        probe_ingest._ipv6_is_reportable(ipaddress.IPv6Address(DOC_IPV6))
        is pcap_ingest._ip_public(DOC_IPV6)
        is True
    )


def test_doc_address_helper_refuses_non_documentation_ipv6() -> None:
    """放行工具不给真实公网 v6 开后门：非文档段直接 fail（不是静默放行）。"""
    from tests import doc_addresses

    assert doc_addresses.is_documentation_address(DOC_IPV6) is True
    # 反面用例取一个 is_global 为真的 IETF 协议 anycast（非文档段、非任何主机），
    # 放行工具必须拒它；字面见下行，故那一行带具体理由的行内豁免。
    assert doc_addresses.is_documentation_address("2001:1::1") is False  # leak-scan: allow ip 放行工具阴性夹具，RFC7723 协议 anycast 非主机地址


def test_probe_merge_writes_the_meta_face(tmp_path) -> None:
    """★B-2b 的核心：合并后 ``meta[\"runtime_merged\"]`` 为 True 且清单落地。

    可见性的 runtime 维靠这个标记从 ``unavailable`` 翻成「已做运行时观测」；
    闭环的采集质量门靠清单从 failed 翻成 partial。
    """
    meta = _merged_meta(tmp_path, _ADDR_LOG)
    assert meta.get("runtime_merged") is True, "只更新了 leads，meta 面仍是空白"

    inventory = _inv.read_inventory(meta)
    assert inventory, "清单没落地"
    assert inventory["sources"] == ["probe"]
    assert inventory["remote_endpoints"] == 1, "合成公网候选 198.51.100.7 应计 1"
    assert inventory["domain_leads"] == 1
    assert inventory["parse_status"] == "ok"
    assert inventory["parse_degraded"] is False
    # ★探针日志是进程内 hook 产出，但没有设备侧 socket 快照做五元组归因 —— 如实记 False。
    assert inventory["uid_attributed"] is False


def test_probe_meta_face_caps_the_closure_at_partial(tmp_path) -> None:
    """★★上限 partial：探针回灌绝不能把闭环抬成 complete（据以结案）。"""
    meta = _merged_meta(tmp_path, _ADDR_LOG)
    quality = evaluate_capture_quality(_inv.derive_capture_quality(_inv.read_inventory(meta)))
    assert quality["dynamic_status"] == CLOSURE_PARTIAL
    assert quality["bidirectional_target_count"] == 0, "双向载荷证据探针路径拿不到"


def test_probe_merge_writes_only_clean_address_values_into_endpoints(tmp_path) -> None:
    """endpoints 要接通，但只能写保守抽出的干净地址，不能写整行探针日志。"""
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"leads": [], "endpoints": []}, ensure_ascii=False), encoding="utf-8")
    probe_ingest.merge_into_report_json(str(p), probe_ingest.parse_probe_log(_ADDR_LOG))
    out = json.loads(p.read_text(encoding="utf-8"))
    endpoint_values = {endpoint["value"] for endpoint in out["endpoints"]}
    assert endpoint_values == {"198.51.100.7", "api.example.test"}
    assert all("SYN_SENT" not in value and "https://" not in value for value in endpoint_values)
    assert all(
        endpoint["enrichment"]["runtime"]["observed_by"] == "probe"
        for endpoint in out["endpoints"]
    )
    assert all(
        evidence.get("scope") == "case_evidence"
        for endpoint in out["endpoints"]
        for evidence in endpoint["evidences"]
        if evidence.get("source") == "runtime-probe"
    )
    assert out["leads"], "leads 面该照旧更新"


def test_probe_merge_marks_runtime_even_without_extractable_addresses(tmp_path) -> None:
    """抽不出地址但确实观测到线索：runtime_merged 仍要为 True，计数如实为 0。

    「跑过但没抓到可富化地址」与「压根没跑」是两回事：前者该显示为已做运行时观测、
    动态结论 failed（提示重抓），后者是 not_applicable。
    """
    meta = _merged_meta(tmp_path, _NON_ADDR_LOG)
    assert meta.get("runtime_merged") is True
    inventory = _inv.read_inventory(meta)
    assert inventory["remote_endpoints"] == 0 and inventory["domain_leads"] == 0
    # 清单存在（回灌跑过）→ 派生非空，动态维如实判 failed 而不是被豁免成 not_applicable
    assert _inv.derive_capture_quality(inventory)


def test_probe_merge_unions_with_an_existing_pcap_ledger(tmp_path) -> None:
    """★两条路径先后并进同一份报告：来源累计、计数取并集。

    pcap 先并入一个公网 IP 与 api.example.test，probe 再并入同一个 IP + 一个新域名：
    重叠的那个不该算两遍，新的那个不该漏。
    """
    pcap_meta: dict = {
        "runtime_merged": True,
        "runtime_pcap_endpoint_values": [_PCAP_IP],
        "runtime_pcap_domain_values": ["api.example.test"],
        _inv.INVENTORY_META_KEY: {
            "remote_endpoints": 1,
            "domain_leads": 1,
            "parse_status": "ok",
            "parse_degraded": False,
            "uid_attributed": False,
            "sources": ["pcap"],
        },
    }
    log = "\n".join(
        [
            f"[netstat] [LEAD->接入节点] {_PCAP_IP}:30113  SYN_SENT",
            "[http][LEAD->穿透] POST https://cfg.example.test/v1/conf",
        ]
    )
    inventory = _inv.read_inventory(_merged_meta(tmp_path, log, meta=pcap_meta))
    assert inventory["sources"] == ["pcap", "probe"], "来源被后一条覆盖了"
    assert inventory["remote_endpoints"] == 1, "两条路径的同一个 IP 被算了两遍"
    assert inventory["domain_leads"] == 2, "probe 新观测到的域名漏了"


def test_probe_merge_keeps_a_real_capture_quality_untouched(tmp_path) -> None:
    """真采集写过 ``capture_quality`` 时，回灌不得覆盖它（那份口径更完整）。"""
    real = {"channel_ready": True, "pcap_valid": True, "packet_count": 12,
            "business_candidate_count": 7, "target_attributed_count": 1,
            "bidirectional_target_count": 1}
    meta = _merged_meta(tmp_path, _ADDR_LOG, meta={"capture_quality": dict(real)})
    assert meta["capture_quality"] == real, "回灌把真采集的统计口径改了"
