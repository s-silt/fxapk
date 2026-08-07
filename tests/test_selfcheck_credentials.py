"""selfcheck 的凭据就绪度：让「没查成」有地方体现，且绝不回显凭据本身。

没配 key 的富化源会安静地不查。落到报告里，那条线索就成了"未发现"——而真相是
**压根没查**。两者的差别很实：前者能写进结论，后者只是一条没做完的活。
本组测试守两件事：这个区别在自检里看得见，以及看见它的过程不会把凭据本身带出来。
"""

from __future__ import annotations

import json

import pytest

from apkscan.core.registry import discover_enrichers
from apkscan.selfcheck import build_credential_components, run_selfcheck

#: 不该出现在任何输出里的哨兵值。
_SENTINEL = "sentinel-credential-value-must-never-be-echoed"


def _sources_needing_credentials() -> set[str]:
    return {
        e.name for e in discover_enrichers()
        if tuple(getattr(e, "required_env", ()) or ())
    }


def test_every_credentialed_source_is_reported() -> None:
    """★每个需要凭据的源都要有一项——漏一个，那个源的缺席就仍然是无声的。

    ★变异验证：给 build_credential_components 加个 ``[:3]`` 截断，本测试必红。
    """
    reported = {c["name"].split(":", 1)[1] for c in build_credential_components()}
    expected = _sources_needing_credentials()
    assert reported == expected, (
        f"凭据项与实际需要凭据的源不一致：只在自检={sorted(reported - expected)}；"
        f"只在源={sorted(expected - reported)}"
    )
    assert expected, "前提：仓库里确实存在需要凭据的富化源"


def test_missing_credential_says_it_was_never_queried(monkeypatch: pytest.MonkeyPatch) -> None:
    """★未配时的措辞必须点明「没查成」≠「查了没有」。

    这不是文案洁癖：读报告的人据此决定要不要补查。一句含糊的"无结果"会让人
    把一条没做的活当成已经排除的可能。
    """
    for e in discover_enrichers():
        for var in tuple(getattr(e, "required_env", ()) or ()):
            monkeypatch.delenv(var, raising=False)

    rows = build_credential_components()
    assert rows, "前提：至少有一个源需要凭据"
    for row in rows:
        assert row["status"] == "disabled"
        assert "没查成" in row["detail"], f"{row['name']} 的措辞没有点明证据边界：{row['detail']}"
        assert row["fix"], "未配就要给出怎么配"


def test_configured_credential_flips_to_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """配上任意一个候选变量即视为就绪（多个候选是同一凭据的不同惯用名）。"""
    target = next(
        e for e in discover_enrichers() if tuple(getattr(e, "required_env", ()) or ())
    )
    var = tuple(target.required_env)[0]
    monkeypatch.setenv(var, _SENTINEL)

    row = next(
        c for c in build_credential_components() if c["name"] == f"credential:{target.name}"
    )
    assert row["status"] == "ok"


def test_blank_credential_counts_as_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    """★空白值等于没配——必须与真正决定查不查的判据同口径。

    `enrichment._provider_configured` 与 `multisource._credential` 都是 strip 后判空，
    所以 `FXAPK_XX_KEY="   "` 那个源根本不会被查。自检若说「已配置」，方向恰好是最坏的：
    人以为查过了，而报告里那条线索的缺席其实是「没查成」。

    ★变异验证：去掉 build_credential_components 里的 .strip()，本测试必红。
    """
    target = next(
        e for e in discover_enrichers() if tuple(getattr(e, "required_env", ()) or ())
    )
    for var in tuple(target.required_env):
        monkeypatch.setenv(var, "   ")

    row = next(
        c for c in build_credential_components() if c["name"] == f"credential:{target.name}"
    )
    assert row["status"] == "disabled", "纯空白被当成了已配置"
    assert row["fix"], "既然实际没配，就要给出怎么配"


def test_credential_values_never_appear_in_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """★绝不回显：整份自检输出里不得出现凭据的任何片段。

    自检输出是给 agent 和人直接读的，还常被贴进工单。凭据只判在不在，
    连长度、前缀都不输出。

    ★变异验证：把 detail 改成带上 os.environ 里的值，本测试必红。
    """
    for e in discover_enrichers():
        for var in tuple(getattr(e, "required_env", ()) or ()):
            monkeypatch.setenv(var, _SENTINEL)

    blob = json.dumps(run_selfcheck(online=False, probe_network=False), ensure_ascii=False)
    assert _SENTINEL not in blob
    # 连片段也不行——截断回显同样是回显。
    assert _SENTINEL[:8] not in blob


def test_credentials_do_not_flip_overall_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """★未配凭据是「可选能力没开」，不是故障——不得把整体 ok 判成假。

    否则每台没配全 9 个源的机器都会看到自检失败，久而久之这个信号就没人看了。
    """
    for e in discover_enrichers():
        for var in tuple(getattr(e, "required_env", ()) or ()):
            monkeypatch.delenv(var, raising=False)

    result = run_selfcheck(online=False, probe_network=False)
    assert result["ok"] is True
    assert result["summary"].get("disabled", 0) >= len(_sources_needing_credentials())


def test_credential_components_survive_a_broken_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """自检自身绝不抛：发现富化源失败时返回空列表，其余项照常。"""
    def _boom():
        raise RuntimeError("registry 坏了")

    monkeypatch.setattr("apkscan.core.registry.discover_enrichers", _boom)
    assert build_credential_components() == []
    assert run_selfcheck(online=False, probe_network=False)["components"]
