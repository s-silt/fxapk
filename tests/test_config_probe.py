"""配置探测预案：把配置接口路径 × 后端域名拼成候选 URL。零真实数据、零网络。"""
from __future__ import annotations

from apkscan.core import config_probe as cp


def _meta(paths: list[str], hosts: list[tuple[str, float]], **extra) -> dict:
    return {
        "api_surface": {"config_endpoints": paths},
        "asset_scores": [
            {"value": h, "kind": "domain", "score": s} for h, s in hosts
        ],
        **extra,
    }


def test_builds_candidate_urls():
    plan = cp.build_plan(_meta(["/api/home/config"], [("api.example.test", 9.0)]))
    assert plan is not None
    assert plan["candidates"][0]["url"] == "https://api.example.test/api/home/config"
    assert plan["candidates"][0]["host_score"] == 9.0


def test_hosts_taken_in_asset_score_order():
    """★host 取 asset_score 靠前的——那个视图按「最像 App 自有后端」排序，正是要打的那批。

    顺序不对的话，截断时留下的会是三方 SDK 域名，预案就废了。
    """
    plan = cp.build_plan(_meta(
        ["/api/config"],
        [("own-backend.test", 9.5), ("sdk-vendor.test", 1.0)],
    ))
    assert [c["host"] for c in plan["candidates"]] == ["own-backend.test", "sdk-vendor.test"]


def test_combination_is_capped_and_truncation_reported(monkeypatch):
    """★组合数封顶，且截断量必须说出来。

    N 域名 × M 路径里绝大多数组合不存在；静默截断会被读成「已全覆盖」——那正是本项目
    反复要防的「缺失被当不存在」。
    """
    monkeypatch.setattr(cp, "_MAX_CANDIDATES", 3)
    plan = cp.build_plan(_meta(
        ["/a", "/b", "/c", "/d"],
        [("h1.test", 9.0), ("h2.test", 8.0)],
    ))
    assert len(plan["candidates"]) == 3
    assert plan["truncated"] == 8 - 3, "截断量没如实记录"
    # 截断时保住最高分 host 的完整路径集，而不是每个 host 各切一半
    assert {c["host"] for c in plan["candidates"]} == {"h1.test"}


def test_ip_assets_not_used_as_host():
    """只对域名拼 URL：IP 直连配置接口的形态存在但误报率高，交人工判断。"""
    meta = _meta(["/api/config"], [])
    meta["asset_scores"] = [{"value": "203.0.113.9", "kind": "ip", "score": 9.0}]
    assert cp.build_plan(meta) is None


def test_malformed_paths_rejected():
    plan = cp.build_plan(_meta(
        ["not-a-path", "https://evil.test/x", "/api/ok", "/api/ok?a=1"],
        [("h.test", 5.0)],
    ))
    paths = sorted({c["path"] for c in plan["candidates"]})
    assert paths == ["/api/ok"], f"畸形路径未被拒：{paths}"


def test_url_form_asset_value_reduced_to_host():
    plan = cp.build_plan(_meta(["/api/config"], []) | {
        "asset_scores": [{"value": "https://api.example.test/some/page", "kind": "domain", "score": 7.0}]
    })
    assert plan["candidates"][0]["url"] == "https://api.example.test/api/config"


def test_missing_inputs_return_none():
    assert cp.build_plan(None) is None
    assert cp.build_plan({}) is None
    assert cp.build_plan(_meta([], [("h.test", 1.0)])) is None          # 无配置路径
    assert cp.build_plan(_meta(["/api/config"], [])) is None            # 无可信 host


def test_never_raises_on_garbage():
    for bad in ({"api_surface": "x"}, {"api_surface": {"config_endpoints": "x"}},
                {"api_surface": {"config_endpoints": [1, None]}, "asset_scores": "x"}):
        assert cp.build_plan(bad) is None


def test_pipeline_stage_registered():
    """只写模块不接线 = 没做。"""
    import inspect

    from apkscan.core import pipeline

    assert '_run_stage(state, "config_probe_plan"' in inspect.getsource(pipeline)


def test_visibility_runs_after_plan_so_it_can_advise_on_it():
    """★阶段顺序：可见性求值必须排在预案**之后**，否则读不到它、给不出"授权后重跑"的补法。

    这个错真犯过：预案生成了 16 条候选，而补法建议是空的——因为求值时预案还没写进 meta。
    """
    import inspect

    from apkscan.core import pipeline

    src = inspect.getsource(pipeline)
    assert src.index('_run_stage(state, "config_probe_plan"') < src.index(
        '_run_stage(state, "visibility"'
    ), "可见性求值排到了预案之前，补法建议会看不到预案"


def test_plan_states_it_is_not_a_result():
    """预案里必须写明「多数组合并不真实存在、passive 下不发请求」——否则会被当成已探测结论。"""
    plan = cp.build_plan(_meta(["/api/config"], [("h.test", 5.0)]))
    assert "并不真实存在" in plan["note"]
    assert "passive" in plan["note"]
