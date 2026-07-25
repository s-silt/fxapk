"""端口归一化反推（A2 静态×动态交叉校验）：用实测端口反推声明端口→真实端口的变换。

零真实案件数据：全部用合成 IP（TEST-NET-3 203.0.113.0/24）与合成常量。
"""
from __future__ import annotations

import json

from apkscan.config.port_norm import (
    PortPair,
    build_pairs,
    infer_port_transform,
    last_octet,
    observed_ports_from_report,
    predict_port,
)

# 合成归一化常量（**不是**任何真实案件的值；只用来验证求解器能反推出常量）。
_K = 1234


def _octet_pairs(specs: list[tuple[str, int]]) -> list[PortPair]:
    """按 真实 = 声明 + IP末段 + _K 造配对（模拟家族形态的归一化）。"""
    out = []
    for ip, declared in specs:
        octet = last_octet(ip)
        assert octet is not None
        out.append(PortPair(ip=ip, declared=declared, observed=declared + octet + _K))
    return out


def test_infers_octet_offset_transform() -> None:
    """★核心：给足够多样的配对 → 反推出「声明端口 + IP末段 + 常量」并给出常量值。"""
    pairs = _octet_pairs([
        ("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
        ("203.0.113.150", 8300), ("203.0.113.201", 9400),
    ])
    res = infer_port_transform(pairs)
    best = res.best
    assert best is not None, res.notes
    assert best.form == "octet_offset"
    assert best.constant == _K
    assert best.support_count == 5 and not best.contradicted
    assert res.degenerate is False


def test_identity_wins_when_ports_match() -> None:
    """端口本就一致 → 最简的 identity 被确认（不硬套复杂形式）。"""
    pairs = [
        PortPair("203.0.113.7", 443, 443),
        PortPair("203.0.113.42", 8080, 8080),
        PortPair("203.0.113.99", 9000, 9000),
    ]
    best = infer_port_transform(pairs).best
    assert best is not None and best.form == "identity" and best.constant == 0


def test_constant_offset_transform() -> None:
    pairs = [
        PortPair("203.0.113.7", 5000, 5000 + 77),
        PortPair("203.0.113.42", 6100, 6100 + 77),
        PortPair("203.0.113.99", 7200, 7200 + 77),
    ]
    best = infer_port_transform(pairs).best
    assert best is not None and best.form == "offset" and best.constant == 77


# --- 过拟合闸（④ 二进制提取的教训）--------------------------------------


def test_too_few_pairs_is_degenerate_not_confirmed() -> None:
    """★无修复即失败：仅 2 组配对 → 任何形式都能拟合 → 判 degenerate、**不给**确认结论。

    没有这道闸，offset 形式对任意 2 组都"完美拟合"，会输出一个凭空的公式——正是 ④ 翻车的机理。
    """
    pairs = _octet_pairs([("203.0.113.7", 5000), ("203.0.113.42", 6100)])
    res = infer_port_transform(pairs)
    assert res.degenerate is True
    assert res.best is None
    assert all(not c.confirmed for c in res.candidates)


def test_same_last_octet_is_degenerate() -> None:
    """★无修复即失败：全部配对 IP 末段相同 → offset 与 octet_offset 无法区分（末段被吸进常量）→ degenerate。

    修前会直接确认最简的 offset 形式，把一个只在该末段成立的公式当成通用规律。
    """
    pairs = [
        PortPair("203.0.113.7", 5000, 5000 + 7 + _K),
        PortPair("203.0.113.7", 6100, 6100 + 7 + _K),
        PortPair("203.0.113.7", 7200, 7200 + 7 + _K),
    ]
    res = infer_port_transform(pairs)
    assert res.degenerate is True and res.best is None
    assert "末段" in res.degenerate_reason


def test_same_declared_port_is_degenerate() -> None:
    """★声明端口全相同 → 无法区分「与声明端口相关」与「无关」→ degenerate。"""
    pairs = [
        PortPair("203.0.113.7", 5000, 5000 + 7 + _K),
        PortPair("203.0.113.42", 5000, 5000 + 42 + _K),
        PortPair("203.0.113.99", 5000, 5000 + 99 + _K),
    ]
    res = infer_port_transform(pairs)
    assert res.degenerate is True and res.best is None


def test_contradicting_pair_blocks_confirmation() -> None:
    """★一条反例即不确认：混入一个不服从该变换的端点 → 无确认结论，反例被明列（可复核）。"""
    pairs = _octet_pairs([
        ("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
        ("203.0.113.150", 8300),
    ])
    pairs.append(PortPair("203.0.113.201", 9400, 12345))  # 不服从
    res = infer_port_transform(pairs)
    assert res.best is None
    octet = next(c for c in res.candidates if c.form == "octet_offset")
    assert octet.confirmed is False
    assert [p.ip for p in octet.contradicted] == ["203.0.113.201"]


def test_min_support_is_configurable() -> None:
    pairs = _octet_pairs([
        ("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
    ])
    assert infer_port_transform(pairs, min_support=3).best is not None
    assert infer_port_transform(pairs, min_support=10).best is None  # 要求更高证据即拒


# --- 预测方向（推导值，绝不当观测）----------------------------------------


def test_predict_only_from_confirmed_candidate() -> None:
    """★无修复即失败：未确认的候选**不得**用于预测（否则等于凭未经验证的假设造端口）。"""
    pairs = _octet_pairs([
        ("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
        ("203.0.113.150", 8300),
    ])
    res = infer_port_transform(pairs)
    best = res.best
    assert best is not None
    # 已确认 → 可预测未观测 IP 的真实端口
    assert predict_port(best, "203.0.113.88", 4000) == 4000 + 88 + _K

    # 未确认候选（同一批数据下 identity 必然有反例）→ 拒绝预测
    identity = next(c for c in res.candidates if c.form == "identity")
    assert identity.confirmed is False
    assert predict_port(identity, "203.0.113.88", 4000) is None


def test_predict_rejects_out_of_range() -> None:
    pairs = _octet_pairs([
        ("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
    ])
    best = infer_port_transform(pairs).best
    assert best is not None
    assert predict_port(best, "203.0.113.250", 65000) is None  # 算出越界 → 不给数


# --- 与报告实测端口对接 ----------------------------------------------------


def _report_with_runtime(ip_ports: dict[str, list[int]]) -> dict:
    return {
        "endpoints": [
            {
                "value": ip, "kind": "ip",
                "enrichment": {"runtime": {"remote_endpoints": [f"{ip}:{p}" for p in ports]}},
            }
            for ip, ports in ip_ports.items()
        ]
    }


def test_observed_ports_from_report() -> None:
    """从 report.json 的 enrichment.runtime.remote_endpoints 取实测端口（真观测侧）。"""
    rep = _report_with_runtime({"203.0.113.7": [6241], "203.0.113.42": [7376]})
    got = observed_ports_from_report(rep)
    assert got == {"203.0.113.7": {6241}, "203.0.113.42": {7376}}


def test_observed_ports_tolerates_garbage() -> None:
    assert observed_ports_from_report(None) == {}
    assert observed_ports_from_report({"endpoints": "nope"}) == {}
    bad = {"endpoints": [{"enrichment": {"runtime": {"remote_endpoints": ["no-colon", "x:abc", "1.2.3.4:99999"]}}}]}
    assert observed_ports_from_report(bad) == {}


def test_build_pairs_flags_ambiguous_and_unmatched() -> None:
    """★同一 IP 多个实测端口 → 判 ambiguous **不擅自挑一个**（挑=替办案人猜）。"""
    declared = {"203.0.113.7": 5000, "203.0.113.42": 6100, "203.0.113.99": 7200}
    observed = {"203.0.113.7": {6241}, "203.0.113.42": {7376, 8000}}
    pairs, ambiguous, unmatched = build_pairs(declared, observed)
    assert [p.ip for p in pairs] == ["203.0.113.7"]
    assert ambiguous == ["203.0.113.42"]   # 两个实测端口，不猜
    assert unmatched == ["203.0.113.99"]   # 声明了但没实测到


def test_end_to_end_report_to_transform() -> None:
    """★端到端：解密所得声明端口 + 报告里的实测端口 → 反推出变换（两条管线互相印证）。"""
    specs = [("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
             ("203.0.113.150", 8300)]
    declared = dict(specs)
    rep = _report_with_runtime({
        ip: [d + (last_octet(ip) or 0) + _K] for ip, d in specs
    })
    pairs, _amb, _unm = build_pairs(declared, observed_ports_from_report(rep))
    best = infer_port_transform(pairs).best
    assert best is not None and best.form == "octet_offset" and best.constant == _K


def test_cli_port_normalize(tmp_path) -> None:
    from typer.testing import CliRunner

    from apkscan import cli

    specs = [("203.0.113.7", 5000), ("203.0.113.42", 6100), ("203.0.113.99", 7200),
             ("203.0.113.150", 8300)]
    dpath = tmp_path / "declared.json"
    dpath.write_text(json.dumps(dict(specs)), encoding="utf-8")
    rpath = tmp_path / "report.json"
    rpath.write_text(json.dumps(_report_with_runtime({
        ip: [d + (last_octet(ip) or 0) + _K] for ip, d in specs
    })), encoding="utf-8")

    r = CliRunner().invoke(cli.app, [
        "port-normalize", "--declared", str(dpath), "--report", str(rpath)])
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["pair_count"] == 4
    assert payload["degenerate"] is False
    assert payload["confirmed"]["form"] == "octet_offset"
    assert payload["confirmed"]["constant"] == _K


def test_cli_rejects_missing_observed_source(tmp_path) -> None:
    from typer.testing import CliRunner

    from apkscan import cli

    dpath = tmp_path / "declared.json"
    dpath.write_text(json.dumps({"203.0.113.7": 5000}), encoding="utf-8")
    r = CliRunner().invoke(cli.app, ["port-normalize", "--declared", str(dpath)])
    assert r.exit_code == 2  # 无实测来源即拒跑，不静默产空结论
