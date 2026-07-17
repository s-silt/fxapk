"""B1 国内 providers 分目录专库：多文件加载器（load_rules_dir / _merge_provider_rules）+ 分目录内容分类 +
digest 递归。分目录 rules/providers/{carrier,cloud,cdn,waf,idc}.yaml 合并进主 providers.yaml。"""

from __future__ import annotations

import importlib.resources

import pytest

from apkscan.core import attribution, registry


@pytest.fixture(autouse=True)
def _clear_providers_cache():
    """每个用例前后清 _PROVIDERS_CACHE：这些用例走真实分目录加载，不能被其它测试的缓存污染。"""
    attribution._PROVIDERS_CACHE = None
    yield
    attribution._PROVIDERS_CACHE = None


def test_merge_provider_rules_unions_categories_and_dedups() -> None:
    base = {
        "network_categories": {"cloud": {"org_keywords": ["aliyun"]}},
        "edge_providers": [{"id": "cdn.a", "name": "A"}],
        "scoring": {"confirmed": 10},
    }
    parts = [
        {"network_categories": {
            "cloud": {"org_keywords": ["aliyun", "ctyun"]},  # aliyun 与 base 重复 → 去重
            "idc": {"org_keywords": ["21vianet"]},
        }},
        {"edge_providers": [{"id": "cdn.a", "name": "DUP"}, {"id": "cdn.b", "name": "B"}]},  # cdn.a 重复 id
    ]
    m = attribution._merge_provider_rules(base, parts)
    assert m["network_categories"]["cloud"]["org_keywords"] == ["aliyun", "ctyun"]  # 去重保序
    assert m["network_categories"]["idc"]["org_keywords"] == ["21vianet"]  # 分目录新类别并入
    assert [e["id"] for e in m["edge_providers"]] == ["cdn.a", "cdn.b"]  # id 去重
    dup = next(e for e in m["edge_providers"] if e["id"] == "cdn.a")
    assert dup["name"] == "A"  # 先出现者（主文件）优先，不被分目录同 id 覆盖
    assert m["scoring"] == {"confirmed": 10}  # scoring 以主文件为准


def test_merge_provider_rules_robust_to_garbage() -> None:
    m = attribution._merge_provider_rules(
        {}, [None, "junk", {"network_categories": "bad"}, {"edge_providers": {}}]  # type: ignore[list-item]
    )
    assert m["network_categories"] == {} and m["edge_providers"] == []  # 坏输入逐项跳过、不抛


def test_load_rules_dir_reads_providers_subdir() -> None:
    parts = registry.load_rules_dir("providers")
    assert len(parts) >= 5  # carrier/cloud/cdn/waf/idc
    assert all(isinstance(p, dict) for p in parts)
    assert registry.load_rules_dir("does-not-exist") == []  # 缺目录 → []，不抛


def test_cn_providers_from_subdir_classify() -> None:
    """分目录补的国内厂商 org 关键字合并后 classify_network 生效（拉高国内归属）。"""
    assert attribution.classify_network("Ctyun Beijing Branch") == "cloud"       # 天翼云
    assert attribution.classify_network("21Vianet Group Inc") == "idc"           # 世纪互联
    assert attribution.classify_network("CHINA BROADNET") == "telecom"           # 中国广电
    assert attribution.classify_network("Wangsu Science & Technology") == "cdn"  # 网宿


def test_cn_org_keywords_no_false_positives() -> None:
    """★Fable 复审 P1-P4：收紧后的 org 关键字不再误匹配无关 org（撞城市名/无关公司），且真厂商仍命中。"""
    # P1 白山市/长白山的运营商分公司 → telecom（不再因裸"白山"误判 cdn）；白山云仍命中 cdn
    assert attribution.classify_network("China Unicom Jilin Province Baishan MAN") == "telecom"
    assert attribution.classify_network("中国电信股份有限公司长白山分公司") == "telecom"
    assert attribution.classify_network("贵州白山云科技股份有限公司") == "cdn"
    # P2 青云谱区（南昌地名）→ telecom（不再误 cloud）；青云科技仍命中 cloud
    assert attribution.classify_network("中国电信江西南昌青云谱区分局") == "telecom"
    assert attribution.classify_network("QingCloud Technology Beijing") == "cloud"
    # P3/P4 无关境外/非云公司不再被误标
    assert attribution.classify_network("MACMILLAN PUBLISHERS LTD") == "unknown"       # 曾撞 cmi
    assert attribution.classify_network("Unicomer Group") == "unknown"                 # 曾撞裸 unicom
    assert attribution.classify_network("UNICOM Global Inc") == "unknown"
    assert attribution.classify_network("SafeLine Ltd") == "unknown"                   # 曾撞 safeline
    assert attribution.classify_network("Kingsoft Corporation WPS Office") == "unknown"  # 曾撞裸 kingsoft


def test_cn_cdn_org_keyword_classifies_without_local_cname_fingerprint() -> None:
    """★定位校准（补在线不足、不重造在线已能做的）：本地库不再维护通用 CDN CNAME 指纹（靠在线富化
    as_org/server 识别）；只保留 org→类别映射。edge_providers 只剩主 providers.yaml 既有 4 条。"""
    ids = {e["id"] for e in attribution._providers_rules()["edge_providers"]}
    assert "cdn.tencent_cdn" not in ids and "cdn.huawei_cdn" not in ids  # 不维护通用 CDN CNAME 指纹（靠在线富化）
    assert ids >= {"cdn.cloudflare", "cdn.tencent_edgeone", "cdn.aliyun", "waf.jiasule"}  # 主文件既有 4 条仍在
    assert attribution.classify_network("Qiniu Cloud Storage") == "cdn"  # org 关键字仍把国内 CDN 厂商归类


def test_ruleset_digest_covers_subdir_files() -> None:
    """★分目录规则文件须入 digest（否则分目录改了规则、digest 不变、破坏可复现锚点）。"""
    digest = registry.ruleset_digest()
    assert digest != "unknown" and len(digest) == 16
    walked = {rel for rel, _ in registry._walk_rule_files(importlib.resources.files("apkscan") / "rules", "")}
    assert any(rel.startswith("providers/") and rel.endswith(".yaml") for rel in walked)  # 子目录文件被递归收进
    assert any(rel.startswith("providers/investigative/") for rel in walked)  # investigative 深层子目录也入 digest


def test_load_rules_dir_multilevel_subdir() -> None:
    """load_rules_dir 支持多级 subdir（providers/investigative）——加载 fxapk 自有防红指纹目录。"""
    parts = registry.load_rules_dir("providers/investigative")
    assert len(parts) >= 1 and any("edge_providers" in p for p in parts)
    assert registry.load_rules_dir("providers/does-not-exist") == []  # 缺子目录 → []，不抛


def test_investigative_fronting_fingerprint_loaded_and_probable() -> None:
    """★B2：fxapk 自有防红指纹（providers/investigative/）加载 + a1.init 共享前置 CNAME 命名空间命中——
    这是公开在线库/API 认不出、只能自建的核心壁垒。★单条 CNAME=1 强信号 → 至多 probable（不据一条判死
    confirmed）；标签级后缀防伪造。"""
    ids = {e["id"] for e in attribution._providers_rules()["edge_providers"]}
    assert "fronting.cn.a1init" in ids  # investigative 子目录被加载合并进 edge_providers
    ep = attribution.score_edge_provider({"cname_chain": ["all.foo-site.a1.inituu.com"]})
    assert ep is not None and ep["id"] == "fronting.cn.a1init"
    assert ep["role"] == "anti_blocking_fronting" and ep["tier"] == "probable"
    assert attribution.score_edge_provider({"cname_chain": ["a1.inituu.com.attacker.example"]}) is None  # 防伪造
