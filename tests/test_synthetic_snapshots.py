"""案例级语义回归基准：合成样本 × 六维度快照（战略 #1 的第二层地基）。

test_synthetic_regression 锁的是「检出了哪些类」；本文件把同一批合成样本跑完**真 pipeline +
close_report** 后的语义面按六个维度投影入锁（可见性 / 报告核心 / 归因缺席 / closure / digest 数字
/ corpus 条目），外加 HTML 渲染冒烟与五层归因 contract。任何语义漂移（掉一条主张阻断、闭环
判定松动、corpus 索引字段变形……）都会以结构化 diff 显式变红，逼一次**有意的基线更新**。

基线更新走 ``tools/update_synthetic_baseline.py``（四重闸，见该文件）；投影与 runner 的单一真源
在 ``tests/synthetic/snapshot.py``——本文件只做断言，不自带任何投影逻辑。
"""
from __future__ import annotations

import copy
import os

import pytest

from apkscan.core import corpus
from apkscan.core.attribution import build_endpoint_attribution
from apkscan.report.html import render_to_string
from tests.synthetic import snapshot
from tests.synthetic.samples import SAMPLES, SyntheticSample

_SAMPLE_NAMES = [s.name for s in SAMPLES]


@pytest.fixture(scope="module")
def synthetic_runs() -> dict[str, snapshot.SampleRun]:
    """全样本跑一次真 pipeline + close_report，多维度共用（module 级，别按测试重跑 9 遍）。

    close_report 在 fixture 内、取快照之前跑且只跑一次（唯一原地改、幂等已实测）；各维度投影
    经 JSON 往返取材，互相之间与 run.raw 之间零容器共享（见 snapshot.project）。
    """
    return snapshot.run_all()


@pytest.mark.parametrize("dimension", snapshot.DIMENSIONS)
@pytest.mark.parametrize("sample_name", _SAMPLE_NAMES)
def test_snapshot_matches_baseline(
    sample_name: str, dimension: str, synthetic_runs: dict[str, snapshot.SampleRun]
) -> None:
    """★样本 × 维度快照全等。失败给结构化 diff（路径: expected/actual），不甩整文件对比。"""
    baseline = snapshot.load_baseline(dimension)
    assert sample_name in baseline, (
        f"样本 {sample_name!r} 在 {snapshot.baseline_path(dimension).name} 无基线；"
        f"用 tools/update_synthetic_baseline.py --sample {sample_name} --dimension {dimension}"
        " --accept 生成（需环境变量 APKSCAN_ALLOW_BASELINE_UPDATE=1）"
    )
    actual = snapshot.project(dimension, synthetic_runs[sample_name])
    diffs = snapshot.flat_diff(baseline[sample_name], actual, prefix=f"{sample_name}.{dimension}")
    assert not diffs, (
        "语义快照漂移（若为有意变更，用 tools/update_synthetic_baseline.py 更新基线并 review diff）：\n"
        + "\n".join(diffs)
    )


@pytest.mark.parametrize("dimension", snapshot.DIMENSIONS)
def test_baselines_cover_all_samples(dimension: str) -> None:
    """每个维度基线与样本集一一对应（防新增样本忘记基线、或基线残留已删样本）。"""
    assert set(snapshot.load_baseline(dimension)) == set(_SAMPLE_NAMES), (
        f"{snapshot.baseline_path(dimension).name} 的样本键集与 SAMPLES 不一致"
    )


def test_sample_names_unique() -> None:
    """样本名必须唯一：run_samples 返回 {name: run}，重名会静默覆盖——一个样本从此不被跑、
    基线键集校验（set 比较）也看不出来。"""
    names = [s.name for s in SAMPLES]
    dup = sorted({n for n in names if names.count(n) > 1})
    assert not dup, f"SAMPLES 出现重名样本 {dup}，后者会静默覆盖前者"


def test_visibility_projection_includes_java_source() -> None:
    """B2 新增的 Java 通道必须进入语义快照，删除或漂移时基线才能报警。"""
    run = snapshot.SampleRun(
        report=None,  # type: ignore[arg-type] - 此投影只读取 raw
        raw={
            "meta": {
                "visibility": {
                    "sources": {"java": {"visibility": "timeout"}},
                }
            }
        },
        digest={},
    )
    assert snapshot._project_visibility(run)["sources"]["java"] == "timeout"


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s.name)
def test_pad_flag_matches_dex_shape(
    sample: SyntheticSample, synthetic_runs: dict[str, snapshot.SampleRun]
) -> None:
    """★pad_dex_strings 的可执行护栏（不再只靠注释）：声明的形态必须与真 pipeline 判出的
    dex 可见性一致——pad=True 的样本不得落回 stub_only（阈值上调超过填充余量、填充失效等），
    pad=False 的样本必须真判成 stub_only（否则它锁的"stub 接线"整条链是空转，比如漏了自有
    native 库导致按极简 App 放行）。对**新增样本**尤其关键：基线尚未生成时这条就先红，
    不给"夹具缺陷先被固化成基线契约"留窗口。"""
    meta = synthetic_runs[sample.name].raw.get("meta") or {}
    grade = (((meta.get("visibility") or {}).get("sources") or {}).get("dex") or {}).get("visibility")
    if sample.pad_dex_strings:
        assert grade != "stub_only", (
            f"样本 {sample.name} 声明 pad_dex_strings=True 却仍被判 stub_only："
            "填充没把 DEX 串顶过 stub 阈值（阈值调大了？余量不够？），快照锁到的不是正常样本语义"
        )
    else:
        assert grade == "stub_only", (
            f"样本 {sample.name} 声明壳桩形态（pad_dex_strings=False）但实际 dex={grade!r}："
            "stub 结构判定没触发（串数超阈值？缺自有 native 库？），该样本锁的 stub 接线链是空转"
        )


@pytest.mark.parametrize("sample_name", _SAMPLE_NAMES)
def test_corpus_sample_identity_stays_synthetic(
    sample_name: str, synthetic_runs: dict[str, snapshot.SampleRun]
) -> None:
    """★不变量：合成样本必须走 synthetic（nosha-）命名空间。

    同时锁死"将来有人往夹具塞假 meta.sample_sha256"这条路——那会让合成报告冒充真实样本身份，
    在 corpus 里抢占/污染真报告的入库位（见 corpus.sample_identity 的保留前缀防线）。

    第一条断言直接查 raw：sha 字段必须在约定位置（meta.sample_sha256）**缺席**。只断言
    sample_identity 的输出是不够的——实现将来若回归成忽略该字段，夹具里塞了假 sha 它照样
    返回 (nosha-, True)，函数级断言恒绿；raw 级断言与实现解耦，假 sha 一进夹具就红。
    ★不锁 nosha 哈希值本身的跨 run 稳定性：它从报告全文派生、报告含 volatile 时间戳，
    跨 run 本就不稳（这正是 corpus 投影剔除 sample_sha256 的原因），锁了必 flaky。
    """
    raw = synthetic_runs[sample_name].raw
    assert "sample_sha256" not in (raw.get("meta") or {}), (
        f"合成样本 {sample_name} 的 raw 里出现 meta.sample_sha256——合成报告不得携带样本身份哈希"
    )
    sha, synthetic = corpus.sample_identity(copy.deepcopy(raw))
    assert synthetic is True
    assert sha.startswith("nosha-")


@pytest.mark.parametrize("sample_name", _SAMPLE_NAMES)
def test_html_renders(sample_name: str, synthetic_runs: dict[str, snapshot.SampleRun]) -> None:
    """HTML 出口冒烟：渲染成功 + 标题结构在。★不锁全文字节——模板措辞/样式常改，锁了基线就成噪音。"""
    html = render_to_string(synthetic_runs[sample_name].report)
    assert html.lstrip().startswith("<!DOCTYPE html>")
    title = html.split("<title>", 1)[1].split("</title>", 1)[0] if "<title>" in html else ""
    assert "com.test.app" in title, f"HTML <title> 缺样本包名：{title!r}"
    assert len(html) > 1000  # 空壳模板兜底：渲染"成功"但正文没了也要红


def test_five_layer_contract_minimal_asn_payload() -> None:
    """五层归因 contract 层锁：最小 ASN payload → 五层键齐全 + service_operator 恒 unknown。

    ★为什么不做端到端（有意为之，勿"补全"）：``*.test`` 保留域进不了富化目标、CGNAT/TEST-NET IP
    会被判「无需调证」，唯一通路是非保留 TLD 的合成域名——那会触 leak-scan strict 的域名判据，
    是政策决定、不在本基准范围。故 pipeline 内的端到端五层链**未被本文件覆盖**，此处只锁
    build_endpoint_attribution 的公开契约。
    """
    att = build_endpoint_attribution("ip", "100.64.0.1", {"asn": {"asn": "AS64500"}})
    assert att is not None
    assert att["kind"] == "ip" and att["endpoint"] == "100.64.0.1"
    ips = att["ips"]
    assert len(ips) == 1
    five = {"resource_holder", "origin_network", "hosting_provider", "edge_provider", "service_operator"}
    assert five <= set(ips[0]), f"五层键不齐：缺 {sorted(five - set(ips[0]))}"
    # ★第 5 层恒 unknown：实际站点运营者绝不从 ASN/RDAP 推断（那是基础设施持有方，不是运营者）。
    assert ips[0]["service_operator"] == {"name": None, "confidence": "unknown", "source": None}
    assert ips[0]["origin_network"]["asn"] == 64500


def test_baseline_update_env_var_not_set() -> None:
    """★四重闸第 3 关之一：测试运行期间不允许基线更新开关在环境里。

    谁要是把 APKSCAN_ALLOW_BASELINE_UPDATE=1 写进 CI/本地环境常开，这条直接红。
    ★这条只看得见 pytest 进程自己的环境——"CI 里先设变量跑更新器、unset 后再跑 pytest"
    它是盲的；那条路由 ci.yml 的 ``git diff --exit-code -- tests/synthetic`` 文件守卫拦
    （两者合起来才是第 3 关）。本地更新完基线后也应 unset 再跑测试——开关常开等于没有闸。
    """
    assert os.environ.get("APKSCAN_ALLOW_BASELINE_UPDATE") != "1", (
        "检测到 APKSCAN_ALLOW_BASELINE_UPDATE=1：基线更新开关不得在测试/CI 环境常开，"
        "更新完基线请 unset 后再跑测试"
    )
