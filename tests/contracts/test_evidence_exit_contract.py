"""证据出口契约：声明形状、缺口基线与关键值级执行锁。"""

from __future__ import annotations

import json
import base64

from apkscan.analyzers.dns_bypass import DnsBypassAnalyzer
from apkscan.analyzers.firebase import FirebaseAnalyzer
from apkscan.analyzers.manifest import ManifestAnalyzer
from apkscan.analyzers.packing import PackingAnalyzer
from apkscan.analyzers.re_toolkit import ReToolkitAnalyzer
from apkscan.analyzers.web_evidence import WebRedirectChainAnalyzer, WebRequestRecipeAnalyzer
from apkscan.analyzers.webview_jsbridge import WebViewJsBridgeAnalyzer
from apkscan.config.chain import build_control_chains
from apkscan.core.evidence_exit_contract import (
    EVIDENCE_EXITS, EVIDENCE_UNIT_INVENTORY, EXPECTED_GAPS, GapKind,
    SCENARIO_TESTS, SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT,
    validate_evidence_exit_contract,
)
from apkscan.core.models import Evidence, Finding, Report, Severity
from apkscan.dynamic import merge
from tests.conftest import FakeContext


def test_contract_is_complete_and_gap_numbers_are_honest() -> None:
    """缺口的实际条目必须与 ``EXPECTED_GAPS`` 声明的 (单元数, 键数) 逐类对上。

    ★不再另写一份「总数 == 6」的魔数：那样同一个事实存在两处，
      接好一个出口就要记得改两个地方，忘一个就是契约自己漂移——
      正是这套机制要治的毛病，不该在它自己的测试里复现。
    """
    assert validate_evidence_exit_contract() == []
    # ★所有 GapKind 都要出现，清零的那类写 (0, 0)——与 validate 同口径。
    #   删掉键读起来像「没查这一类」，写 0 才是「查过了、这一类没有」。
    actual = {
        kind: (
            sum(1 for item in EVIDENCE_EXITS if item.gap is kind),
            sum(len(item.producer) for item in EVIDENCE_EXITS if item.gap is kind),
        )
        for kind in GapKind
    }
    assert actual == EXPECTED_GAPS, "缺口条目与 EXPECTED_GAPS 声明不符"


def test_every_positive_lock_names_a_real_sink_and_executable_scenario() -> None:
    """正向单元 = 清单里除去已知缺口的那些；每个都必须有 sink、场景与必达字段。"""
    positives = [item for item in EVIDENCE_EXITS if item.gap is None]
    gap_units = {item.unit for item in EVIDENCE_EXITS if item.gap is not None}
    assert {item.unit for item in positives} == EVIDENCE_UNIT_INVENTORY - gap_units
    assert all(item.sinks and item.scenario and item.projection.required for item in positives)


def test_every_scenario_names_a_test_that_actually_exists() -> None:
    """★``SCENARIO_TESTS`` 指向的函数必须真的在本模块里存在。

    没有这一条，那张表本身就是新的自由字符串：写个不存在的函数名照样过，
    「scenario 已被某条行为锁覆盖」这句话就又变成没人验的声明。
    验证器负责「每个 scenario 都登记了」，本条负责「登记的那个真的存在」——
    两头都钉住才闭环。
    """
    import inspect

    module_tests = {
        name for name, obj in globals().items()
        if name.startswith("test_") and inspect.isfunction(obj)
    }
    declared = set(SCENARIO_TESTS.values())
    missing = declared - module_tests
    assert not missing, f"SCENARIO_TESTS 指向不存在的测试：{sorted(missing)}"


def test_signal_key_scope_cannot_widen_silently() -> None:
    """★新增 signal 键必须交代出口，不能靠「加个 debug 读取」同时躲过两道门。

    复审给的绕过：分析器新增 ``meta["new_signal"]``，再在生产代码里加一个只用于
    debug 日志的 ``meta.get("new_signal")``——孤儿扫描因「有生产读取」判它非孤儿，
    证据契约因「不在人工清单里」看不见它，三类 gap 仍全零。两道门都过，
    而那个信号其实没到任何人眼前。
    """
    from apkscan.core.meta_contract import META_CATEGORY_SIGNAL, META_KEY_REGISTRY

    signal_keys = {
        key for key, contract in META_KEY_REGISTRY.items()
        if contract.category == META_CATEGORY_SIGNAL
    }
    covered = {producer for item in EVIDENCE_EXITS for producer in item.producer}
    assert signal_keys - covered == SIGNAL_KEYS_OUTSIDE_EVIDENCE_CONTRACT, (
        "signal 键的契约外范围变了：新增的要建证据单元或显式入表，"
        "消失的要同步移除——别让表和现实脱节"
    )


def test_firebase_every_field_reaches_an_exit() -> None:
    """★字段级：四个原本只在 meta 的字段各自必须到达出口。

    分工按「它是什么」定，不是一律塞进同一个出口：
    - ``project_number`` / ``sender_id`` / ``api_key`` 是**同一个 GCP 项目**的其它标识符
      → 并进那条 CONFIG_KEY Lead 的证据（同一目标不重复产线索）
    - ``storage_bucket`` 是独立主机（可能存放配置与业务数据）
      → 与 ``database_url`` 同口径产 domain Endpoint，由 pipeline 统一做 infra 分级
    """
    xml = ("<resources><string name='project_id'>demo-project</string>"
           "<string name='google_storage_bucket'>demo-project.storage.example.com</string>"
           "<string name='google_api_key'>FAKE-API-KEY</string>"
           "<string name='gcm_defaultSenderId'>123456789012</string></resources>")
    result = FirebaseAnalyzer().analyze(FakeContext(files={"res/values/strings.xml": xml.encode()}))
    assert result.meta["firebase"] == {
        "project_id": "demo-project", "api_key": "FAKE-API-KEY",
        "sender_id": "123456789012", "storage_bucket": "demo-project.storage.example.com",
    }

    lead = next(lead for lead in result.leads if lead.value.startswith("firebase_project_id="))
    lead_evidence = " ".join(ev.snippet for ev in lead.source_refs)
    assert "FAKE-API-KEY" in lead_evidence, "api_key 未到达 Lead 证据"
    assert "123456789012" in lead_evidence, "sender_id 未到达 Lead 证据"

    assert any(ep.value == "demo-project.storage.example.com" for ep in result.endpoints), (
        "storage_bucket 未产 Endpoint"
    )

    # ★project_number 只能来自 google-services.json（strings.xml 没有对应键，
    #   见 _FALLBACK_STRINGS_KEYS），必须单独构夹具，否则这个字段其实没被覆盖。
    import json

    gs = json.dumps({
        "project_info": {
            "project_id": "demo-project",
            "project_number": "987654321098",
        },
        "client": [],
    })
    with_number = FirebaseAnalyzer().analyze(
        FakeContext(files={"assets/google-services.json": gs.encode()})
    )
    assert with_number.meta["firebase"]["project_number"] == "987654321098"
    number_lead = next(
        lead for lead in with_number.leads if lead.value.startswith("firebase_project_id=")
    )
    assert "987654321098" in " ".join(ev.snippet for ev in number_lead.source_refs), (
        "project_number 未到达 Lead 证据——缺 project_id 时它是唯一抓手"
    )


def test_firebase_identifiers_reach_lead_without_project_id() -> None:
    """★缺 project_id 时其余标识符仍须有出口。

    原实现 ``if not project_id: return``——只有 api_key / sender_id / project_number
    的样本一条线索都不产，那几个值只躺在 meta 里。复审用这个构造推翻了「字段级缺口已清零」
    的结论：我上一版的夹具**总是带着 project_id**，注释却写着「缺 project_id 时它是唯一抓手」，
    自相矛盾。
    """
    xml = ("<resources><string name='google_api_key'>FAKE-API-KEY</string>"
           "<string name='gcm_defaultSenderId'>123456789012</string></resources>")
    result = FirebaseAnalyzer().analyze(FakeContext(files={"res/values/strings.xml": xml.encode()}))

    assert not result.meta["firebase"].get("project_id"), "夹具不该带 project_id"
    lead = next(lead for lead in result.leads if lead.category.value == "CONFIG_KEY")
    assert lead.value.startswith("firebase_sender_id="), "缺 project_id 时应回落到 sender_id 锚点"
    evidence = " ".join(ev.snippet for ev in lead.source_refs)
    assert "FAKE-API-KEY" in evidence and "123456789012" in evidence


def test_digest_names_the_findings_it_omits() -> None:
    """★「省略必须说出来」不能只说数量：LOW 条目的 ID 必须列出来，否则无从定位。

    本轮补的三条 LOW 出口在默认 digest 里只体现为 omitted 计数——
    按本仓「决策只读 digest」的契约，那等于没到决策面。
    """
    from apkscan.report.digest import build_digest

    report = {
        "meta": {},
        "leads": [],
        "findings": [
            {"id": "HIGH-ONE", "severity": "HIGH", "title": "高危"},
            {"id": "APK-ABSOLUTE-PATH-ENTRIES", "severity": "LOW", "title": "绝对路径条目"},
            {"id": "MANIFEST-SUSPICIOUS-VERSION-NAME", "severity": "LOW", "title": "版本标记词"},
        ],
    }
    section = build_digest(report)["findings"]

    assert [i["id"] for i in section["items"]] == ["HIGH-ONE"]
    assert section["counts"]["omitted"] == 2
    assert section["omitted_ids"] == [
        "APK-ABSOLUTE-PATH-ENTRIES", "MANIFEST-SUSPICIOUS-VERSION-NAME",
    ], "被省略的条目必须报出 ID，只给计数等于知道自己瞎但不知道瞎在哪"


def test_both_container_branches_reach_a_finding() -> None:
    """★两支都要有出口：冒充核心名 → MEDIUM；仅绝对路径 → LOW（操作提示）。

    原实现在「有绝对路径但不冒充核心名」这一支直接 return，只写 meta——
    可 recommendation 里那条「别用会落盘解压的工具展开」的操作风险，
    对**所有**绝对路径条目都成立。意图不明是不下定性结论的理由，不是不告诉人的理由。
    """
    gap = PackingAnalyzer().analyze(FakeContext(files={"/tmp/note.txt": b"x"}))
    assert gap.meta["container_decoy_entries"]["absolute_path_entries"] == 1
    assert not any(f.id == "APK-CORE-NAME-DECOY-ENTRIES" for f in gap.findings)
    weak = next(f for f in gap.findings if f.id == "APK-ABSOLUTE-PATH-ENTRIES")
    assert weak.severity is Severity.LOW, "意图不明的一支不得与冒充核心名同级"
    assert "落盘解压" in weak.recommendation, "操作风险提示必须到达分析员"
    # 具体路径由 evidences 承载并在 HTML 渲染（见下一条测试）；这里只锁「边界写没写」——
    # 报告收了多少条、还有多少没进来，是取证依据列本身讲不了的事。
    assert "/tmp/note.txt" in {e.snippet for e in weak.evidences}
    assert "全部 1 条已列入" in weak.description, "收录边界必须写明，否则会被读成「就这么几条」"


def test_absolute_path_entries_actually_reach_rendered_html() -> None:
    """★到达「人看得见的产物」，不是到达 Finding 对象。

    此前所有行为锁都止于 ``AnalyzerResult`` / ``Report.findings``，
    证明的是「值到达了对象」。实测发现 Finding 的 evidences 在 HTML 与 digest
    都不渲染——只放那里的值，任何出口都看不到。本条渲染真 HTML 后查值。
    """
    from apkscan.report.html import render_to_string

    result = PackingAnalyzer().analyze(FakeContext(files={"/tmp/note.txt": b"x"}))
    report = Report(
        package_name="com.test.app", meta=dict(result.meta), leads=[], endpoints=[],
        findings=list(result.findings), analyzer_status=[],
    )
    html = render_to_string(report)

    assert "/tmp/note.txt" in html, "路径没出现在渲染后的 HTML 里"
    assert "落盘解压" in html, "操作风险提示没出现在渲染后的 HTML 里"

    # ★MEDIUM 支同样要给出**完整路径**而非仅计数：它的 recommendation 明确要求
    #   「先剥掉以 / 开头的条目」，只报「classes2.dex×1」剥不动任何东西。
    positive = PackingAnalyzer().analyze(
        FakeContext(files={"/classes2.dex/picture.png": b"x"})
    )
    positive_html = render_to_string(Report(
        package_name="com.test.app", meta=dict(positive.meta), leads=[], endpoints=[],
        findings=list(positive.findings), analyzer_status=[],
    ))
    assert "/classes2.dex/picture.png" in positive_html, "冒充核心名那一支的完整路径没到 HTML"


def test_finding_evidences_are_rendered_in_html() -> None:
    """★治本锁：``Finding.evidences`` 必须在 HTML 里渲染出来。

    全仓 40+ 处把关键取证值只写进 evidences，而此前 HTML 的 findings 表只有
    id/title/severity/category/description/recommendation，digest 只投影
    id/severity/title，letters 只读 Lead——值到了对象、到不了人。
    逐个把值搬进 description 是打地鼠，正解是让这个字段有出口。
    """
    from apkscan.report.html import render_to_string

    finding = Finding(
        id="X-EVIDENCE-RENDER", title="t", severity=Severity.LOW, category="c",
        description="d", recommendation="r",
        evidences=[
            Evidence(source="native", location=f"lib/arm64-v8a/lib{i}.so", snippet=f"值-{i}")
            for i in range(8)
        ],
    )
    html = render_to_string(Report(
        package_name="com.test.app", meta={}, leads=[], endpoints=[],
        findings=[finding], analyzer_status=[],
    ))

    assert "lib/arm64-v8a/lib0.so" in html and "值-0" in html, "证据的位置与片段都要渲染"
    # 有上限，但**截断必须自报**：只列前几条又不说，会被读成「就这么几条」。
    assert "另有 2 条" in html, "超出展开上限的部分必须报出条数，不得静默截断"


def test_decoy_finding_does_not_promise_a_list_it_does_not_have() -> None:
    """★超过 evidences 上限时，不得再写「完整清单见 report.json」。

    承诺一份并不存在的清单比不给更坏：分析员会以为自己已经查全了。
    """
    from apkscan.analyzers.packing import _DECOY_EVIDENCE_CAP

    over = _DECOY_EVIDENCE_CAP + 7
    result = PackingAnalyzer().analyze(FakeContext(
        files={f"/tmp/decoy-{i}.bin": b"x" for i in range(over)}
    ))
    finding = next(f for f in result.findings if f.id == "APK-ABSOLUTE-PATH-ENTRIES")

    assert "完整清单见 report.json" not in finding.description
    assert "余下 7 条未落进报告" in finding.description, "超出报告承载的条数必须如实说明"
    assert len(finding.evidences) == _DECOY_EVIDENCE_CAP

    # 未超上限时才能说「全部已列入」——此时 evidences 里确实是全集。
    few = PackingAnalyzer().analyze(FakeContext(
        files={f"/tmp/decoy-{i}.bin": b"x" for i in range(12)}
    ))
    few_finding = next(f for f in few.findings if f.id == "APK-ABSOLUTE-PATH-ENTRIES")
    assert "全部 12 条已列入" in few_finding.description
    assert len(few_finding.evidences) == 12


def test_evidence_values_survive_real_pipeline_and_json_roundtrip() -> None:
    """★端到端：真 ``pipeline.run`` → JSON 序列化往返 → digest + HTML。

    其余行为锁都用 producer 结果手拼 Report，绕过了 pipeline 聚合、report.json
    序列化与读回。接线回归若发生在 producer 之后、渲染之前，那些锁一条都不会红。
    """
    import json as _json

    from apkscan.core import pipeline
    from apkscan.core.models import AnalysisConfig
    from apkscan.report import json as report_json
    from apkscan.core.report_io import report_from_dict
    from apkscan.report.digest import build_digest
    from apkscan.report.html import render_to_string

    report = pipeline.run(
        FakeContext(files={"/classes2.dex/picture.png": b"x"}), AnalysisConfig(online=False)
    )
    payload = _json.loads(_json.dumps(report_json.to_dict(report), ensure_ascii=False))
    restored = report_from_dict(payload)

    html = render_to_string(restored)
    digest = _json.dumps(build_digest(payload), ensure_ascii=False)

    assert "/classes2.dex/picture.png" in html, "值没能穿过真 pipeline + JSON 往返到达 HTML"
    assert "APK-CORE-NAME-DECOY-ENTRIES" in digest, "该 Finding 在 digest 里连 ID 都不见"


def test_brand_hints_value_reaches_finding(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """★行为锁：品牌词必须**带着值**进 Finding，而不只是写进 meta。

    这个出口原本不存在——写入点注释写着「供报告呈现」，但没有任何东西呈现它，
    读报告的人看不到。

    ★必须走真入口 ``decrypt_runtime_messages``，不能直接调 ``_add_brand_hint_finding``：
      本仓实证过「只调被测函数的单测永远测不到接线」——删掉调用点，那种测试照样全绿。
      我写这条时先犯了一次，突变（把调用行换成 pass）没变红才发现。
    """
    import base64
    import json

    plaintext = json.dumps({"webName": "某某证券", "note": "某某银行股份"}, ensure_ascii=False)
    runtime_report = tmp_path / "runtime_report.json"
    runtime_report.write_text(
        json.dumps({"crypto_events": [
            {"plaintext_b64": base64.b64encode(plaintext.encode()).decode()},
        ]}),
        encoding="utf-8",
    )
    report = Report(
        package_name="com.test.app", meta={}, leads=[], endpoints=[],
        findings=[], analyzer_status=[],
    )
    merge.decrypt_runtime_messages(report, str(runtime_report))

    assert "某某证券" in report.meta["runtime_brand_hints"], "夹具没触发 brand hints 抽取"
    finding = next(f for f in report.findings if f.id == "RUNTIME-BRAND-HINTS")
    assert "某某证券" in finding.description
    assert "某某证券" in " ".join(ev.snippet for ev in finding.evidences)
    # 措辞不得替人下「冒充了 X」的结论——同名可能来自第三方 SDK 文案或行业通用词。
    assert "冒充" not in finding.title
    assert "同名不等于冒充" in finding.recommendation
    # ★合规提示必须在：词条截自解密明文、判据是「命中行业词」，可能连带无关的个人数据片段。
    #   挂在「品牌/行业词」这个看着无害的标签下而不标敏感，比放原文更危险
    #   （凭据 Lead 走的是 RUNTIME_CREDENTIAL + 合规提示，本条须对齐）。
    assert "合规提示" in finding.description
    assert "个人数据" in finding.description
    # ★分类字段不得替人断言「冒充」：它进统计与筛选，比正文更容易被当成结论。
    assert "impersonation" not in finding.category

    # ★幂等：重复合并（重跑动态 / 重渲染）不得堆出同 ID 的多条 Finding。
    merge.decrypt_runtime_messages(report, str(runtime_report))
    assert len([f for f in report.findings if f.id == "RUNTIME-BRAND-HINTS"]) == 1


def test_suspicious_version_value_reaches_finding() -> None:
    """★行为锁：命中的关键词与 versionName 必须带值进 Finding。

    原实现只写 meta 并在 docstring 里自称「研判标注」——可它谁也没告诉。
    走真入口 ``ManifestAnalyzer().analyze``，不直接调 ``_annotate_suspicious``。
    """
    xml = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.demo.app" android:versionName="1.0-马甲-debug">'
        "<application/></manifest>"
    )
    result = ManifestAnalyzer().analyze(FakeContext(manifest_xml=xml))

    assert result.meta["suspicious_version_hits"], "夹具没命中关键词"
    finding = next(f for f in result.findings if f.id == "MANIFEST-SUSPICIOUS-VERSION-NAME")
    assert "1.0-马甲-debug" in finding.description
    assert "马甲" in finding.description
    # 弱信号：份量必须压住，且不得替人定性。
    assert finding.severity is Severity.LOW
    assert "需另有证据" in finding.recommendation


def test_unknown_remote_target_reaches_finding_without_gesture(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """★无手势/录屏时，未知包也必须有出口。

    原实现把 Finding 挡在 ``gesture or screencapture`` 之后——而并回日志自己写着
    「launch-only 抓不到，多数需引导式人工动态」：抓包本就常常很浅，
    拿手势当报告前提，正好卡在最容易漏的地方。走真入口驱动。
    """
    import json

    runtime_report = tmp_path / "runtime_report.json"
    runtime_report.write_text(
        json.dumps({"remote_control_events": [
            {"event": "window", "package": "com.unknown.wallet.demo"},
        ]}),
        encoding="utf-8",
    )
    report = Report(
        package_name="com.test.app", meta={}, leads=[], endpoints=[],
        findings=[], analyzer_status=[],
    )
    merge.merge_runtime_remote_control(report, str(runtime_report))

    assert report.meta.get("runtime_remote_control_unknown_packages"), "夹具没触发未知包"
    finding = next(
        f for f in report.findings if f.id == "RUNTIME-REMOTE-CONTROL-UNKNOWN-TARGET"
    )
    assert "com.unknown.wallet.demo" in finding.description
    assert finding.severity is Severity.LOW, "无手势证据时不得与实测远控同级"
    assert "不代表不具备该能力" in finding.description


def test_control_chain_relation_reaches_digest() -> None:
    """★关系必须整条到达，不能拆成平铺 IOC。

    `build_control_chains` 的存在理由就是「不再是孤立 IOC，而是可读的控制链」，
    原先它只写 meta、无出口——组成节点各自可见 ≠ 这条关系可见。
    两端都走真入口：先用真 `build_control_chains` 造链，再过真 `build_digest`。
    """
    from types import SimpleNamespace

    from apkscan.report.digest import build_digest

    endpoint = SimpleNamespace(
        value="backend.example.com",
        enrichment={"attribution": {"ips": [{
            "ip": "203.0.113.7",
            "country": "SG",
            "hosting_provider": {"name": "Example IDC"},
        }]}},
    )
    chains = build_control_chains(
        artifacts=[{
            "source_url": "https://cfg.example.com/a.json",
            "decoded": True,
            "decode_chain": ["base64", "aes-cbc"],
            "domains": ["backend.example.com"],
        }],
        recipe={"algo": "AES", "mode": "CBC", "key_encoding": "hex"},
        endpoints=[endpoint],
    )
    assert chains, "夹具没造出控制链"

    digest = build_digest({"meta": {"control_chains": chains}, "leads": []})
    section = digest["control_chains"]
    assert len(section) == 1, "控制链未进 digest"

    chain = section[0]
    # ★整条关系都要在同一个对象里：配置对象 → 配方 → 后端 → 落地。
    assert chain["source_url"] == "https://cfg.example.com/a.json"
    assert chain["crypto_recipe"]["algo"] == "AES"
    assert chain["decode_chain"] == ["base64", "aes-cbc"]
    backend = chain["backends"][0]
    assert backend["value"] == "backend.example.com"
    assert backend["landing"][0]["ip"] == "203.0.113.7"
    assert backend["landing"][0]["hosting"] == "Example IDC"


def test_denial_bomb_value_reaches_finding() -> None:
    path = "assets/oversized.bin"
    result = PackingAnalyzer().analyze(FakeContext(files={path: b"x"}, declared_sizes={path: 600_000_000}))
    finding = next(f for f in result.findings if f.id == "APK-DENIAL-OF-ANALYSIS-BOMB")
    assert path in " ".join(ev.location + ev.snippet for ev in finding.evidences)


def test_dns_protocol_value_reaches_finding_and_visibility_wording() -> None:
    marker = "application/dns-message"
    result = DnsBypassAnalyzer().analyze(FakeContext(dex_strings=[marker]))
    finding = next(f for f in result.findings if f.id == "APP-MANAGED-DNS-RESOLUTION")
    assert marker in " ".join(ev.snippet for ev in finding.evidences)
    assert "SNI" in finding.recommendation


def test_manifest_anomaly_value_reaches_finding() -> None:
    anomaly = "合成清单包名交叉校验不一致"
    xml = "<manifest package='com.example.synthetic'><application/></manifest>"
    result = ManifestAnalyzer().analyze(FakeContext(manifest_xml=xml, manifest_anomaly=anomaly))
    finding = next(f for f in result.findings if f.id == "MANIFEST-PARSE-ANOMALY")
    assert anomaly in finding.description


def test_control_chain_relationship_is_archived_without_dedicated_sink() -> None:
    chains = build_control_chains(
        [{"source_url": "https://config.example.test/a", "decoded": True,
          "decode_chain": ["aes", "json"], "domains": ["api.example.test"], "ips": []}],
        {"algo": "AES", "key_encoding": "resource"}, [],
    )
    assert chains
    assert "config.example.test" in json.dumps(chains, ensure_ascii=False)
    assert "api.example.test" in json.dumps(chains, ensure_ascii=False)


def _report() -> Report:
    return Report(package_name="com.example.synthetic", meta={}, leads=[], endpoints=[],
                  findings=[], analyzer_status=[])


def test_runtime_antidetect_jsbridge_and_sensitive_values_reach_sinks(monkeypatch) -> None:
    report = _report()
    static = Finding(id="SAPI-IMEI", title="读取设备标识", severity=Severity.HIGH,
                     category="sensitive_api", description="调用 getDeviceId")
    report.findings.append(static)
    events = {
        "antidetect_events": [{"kind": "root", "probe": "synthetic-root-probe"}],
        "jsbridge_events": [{"event": "register", "iface": "SyntheticBridge", "methods": "pay"}],
        "sensitive_api_events": [{"api": "TelephonyManager.getDeviceId"}],
    }
    monkeypatch.setattr(merge, "_load_events_field", lambda _path, field: events[field])
    merge.merge_runtime_traces(report, "synthetic-runtime-report.json")
    anti = next(f for f in report.findings if f.category == "anti_analysis")
    assert "root" in anti.description and "synthetic-root-probe" in " ".join(e.snippet for e in anti.evidences)
    assert any(lead.value == "JSBridge:SyntheticBridge" for lead in report.leads)
    assert any(e.source == "runtime" and "getDeviceId" in e.snippet for e in static.evidences)


def test_re_toolkit_name_and_capability_reach_finding() -> None:
    result = ReToolkitAnalyzer().analyze(
        FakeContext(native_libs=["lib/arm64-v8a/libshadowhook.so"])
    )
    tool = result.meta["re_toolkit"][0]
    finding = next(f for f in result.findings if f.id == "RE-TOOLKIT-DETECTED")
    assert tool["name"] in finding.description
    assert tool["capability"] in finding.description


def test_web_redirect_fields_reach_finding_and_endpoint() -> None:
    first = "https://first.example.test/landing"
    second = "https://second.example.test/app"
    html = (f'<meta http-equiv="refresh" content="0;url={first}">'
            f'<script>location.replace("{second}")</script>').encode()
    result = WebRedirectChainAnalyzer().analyze(FakeContext(files={"web/a.html": html}))
    hops = result.meta["web_redirect_chain"][0]["hops"]
    finding = next(f for f in result.findings if f.id == "WEB-REDIRECT-CHAIN")
    assert [(h["step"], h["target"], h["mechanism"]) for h in hops] == [
        (1, first, "meta-refresh"), (2, second, "location-call"),
    ]
    assert finding.description.index(first) < finding.description.index(second)
    assert {ep.value for ep in result.endpoints} >= {first, second}


def test_web_request_decoded_value_and_context_reach_finding() -> None:
    decoded = "X-Synthetic-Header: placeholder"
    token = base64.b64encode(decoded.encode()).decode()
    js = f'xhr.setRequestHeader(atob("{token}"));'.encode()
    result = WebRequestRecipeAnalyzer().analyze(FakeContext(files={"web/app.js": js}))
    recipe = result.meta["web_request_recipe"][0]
    finding = next(f for f in result.findings if f.id == "WEB-REQUEST-RECIPE")
    assert recipe["decoded"] == decoded
    assert recipe["context"] in finding.description.lower()
    assert decoded in finding.description


def test_webview_signal_id_reaches_matching_finding() -> None:
    result = WebViewJsBridgeAnalyzer().analyze(
        FakeContext(dex_strings=["addJavascriptInterface", "Landroid/webkit/WebView;"])
    )
    assert "WV-ADD-JS-INTERFACE" in result.meta["webview_signals"]
    finding = next(f for f in result.findings if f.id == "WV-ADD-JS-INTERFACE")
    assert any("addJavascriptInterface" in ev.snippet for ev in finding.evidences)
