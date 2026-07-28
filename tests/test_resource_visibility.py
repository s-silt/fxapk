"""资源层可见性：读失败必须被计数，"扫了 1 个"不得冒充"扫全了"。

守的是本项目最重的一类错误之一——让办案人把「未发现」读成「已穷尽」。

命中扫描目标却读不出来的资源（坏 CRC / 畸形局部头 / 超尺寸闸）此前被静默 `continue`，
于是「命中 100 个、99 个读不出、只读成 1 个」与「100 个全读成」在 meta 里完全一样，
可见性求值据此判 complete，报告便有资格签发「静态端点已穷尽」「未发现远程配置」——而
藏着真实后端的那个 assets 从未被打开过。畸形 zip 条目是本域在用的反分析手法，不是偶发噪声。

断言落在**最终产出**（主张资格 / blocked_claims / closure 状态），不是只断中间计数。
"""

from __future__ import annotations

import pytest

from apkscan.analyzers.endpoints import EndpointsAnalyzer
from apkscan.core import visibility
from apkscan.core.visibility import (
    VIS_COMPLETE,
    VIS_PARTIAL,
    VIS_UNAVAILABLE,
    VIS_UNKNOWN,
)

_EXHAUSTIVE_CLAIMS = ("static_endpoint_exhaustive", "no_remote_config")


class _Ctx:
    """最小 AnalysisContext 替身：只喂资源扫描要的三个接口。

    刻意不用 conftest.FakeContext——那个的 ``files`` 是 ``dict[str, bytes]``，表达不了
    「条目在，但读不出来」（read_file 返 None），而那正是本文件要覆盖的形态。
    """

    def __init__(self, files: dict[str, bytes | None], *, list_raises: bool = False) -> None:
        self._files = files
        self._list_raises = list_raises
        self.manifest_xml = ""

    def native_libs(self) -> list[str]:
        return []

    def dex_strings(self) -> list[str]:
        return []

    def list_files(self) -> list[str]:
        if self._list_raises:
            raise OSError("中央目录损坏")
        return list(self._files)

    def read_file(self, path: str) -> bytes | None:
        return self._files.get(path)


def _scan(files: dict[str, bytes | None], **kw) -> tuple[int, int, bool]:
    from apkscan.analyzers.endpoints import EndpointCollector

    a = EndpointsAnalyzer()
    return a._scan_resources(
        _Ctx(files, **kw),  # type: ignore[arg-type]  # 只用到 list_files/read_file
        EndpointCollector(),
        a._load_rules(),
    )


# --- 分析器层：三种结局必须可分 ------------------------------------------------


def test_read_failure_is_counted_not_silently_skipped() -> None:
    """★核心：命中目标却读不出来的资源必须计数。

    退回 `_scan_resources` 里的 failed 计数（改回无痕 continue），本测试即红——
    而那正是「扫了 1 个漏了 99 个」与「扫全了」不可分的根源。
    """
    scanned, failed, list_failed = _scan({
        "assets/site_config.json": None,          # 坏 CRC / 超尺寸闸 → read_file 返 None
        "res/xml/network_security_config.xml": b"<x>http://ok.test</x>",
    })
    assert (scanned, failed, list_failed) == (1, 1, False)


def test_clean_scan_reports_no_failures() -> None:
    """全读成时 failed=0——否则新判据会把干净样本一律降成 partial（误伤方向）。"""
    scanned, failed, list_failed = _scan({
        "assets/a.json": b"{}",
        "res/xml/b.xml": b"<b/>",
    })
    assert (scanned, failed, list_failed) == (2, 0, False)


def test_listing_failure_is_distinct_from_empty_package() -> None:
    """★列举失败 ≠ 包里没有资源目标：前者是本次实测故障，后者是事实。

    折叠成同一个 (0, 0) 会让「压根没能枚举」走进专供旧报告的 unknown 豁免通道。
    """
    assert _scan({}, list_raises=True) == (0, 0, True)
    assert _scan({"classes.dex": b"\x00"}) == (0, 0, False), "无资源目标是事实，不是故障"


# --- 可见性求值层：档位与主张资格 ----------------------------------------------


def _assess(meta: dict) -> dict:
    return visibility.assess({"meta": {"dex_available": True, "dex_scanned": True, **meta}})


def test_partial_read_failure_blocks_exhaustive_claims() -> None:
    """★出口锁：一个资源读失败 → 资源层 partial → 穷尽性主张全部无资格。

    退回 `_resource_visibility` 的 read_failed 分支，它会回落到"扫过 1 个 → complete"，
    主张重新变得 eligible，报告又有资格签发「已穷尽」。
    """
    a = _assess({"resource_files_scanned": 1, "resource_files_read_failed": 1})

    assert a["sources"]["resource"]["visibility"] == VIS_PARTIAL
    for claim in _EXHAUSTIVE_CLAIMS:
        assert a["claims"][claim]["eligible"] is False, claim
        assert "resource" in a["claims"][claim]["missing_sources"], claim
    assert a["degraded"] is True
    assert any("读取失败" in w for w in a["sources"]["resource"]["why"])


def test_listing_failure_is_unavailable_not_unknown() -> None:
    """★列举失败进 _INSUFFICIENT（确证盲区），不进 unknown（未评估）。

    两者对 closure 的含义不同：确证盲区是本次分析的实际缺口、该封顶；未评估走的是
    专给旧报告的豁免通道。把实测故障混进后者 = 故障被当成"这一维没做"而免于降级。
    """
    a = _assess({"resource_listing_failed": True})

    assert a["sources"]["resource"]["visibility"] == VIS_UNAVAILABLE
    claim = a["claims"]["static_endpoint_exhaustive"]
    assert "resource" in claim["missing_sources"]
    assert "resource" not in claim["unassessed_sources"], "确证盲区不得被记成未评估"


def test_clean_scan_still_reads_complete() -> None:
    """反向护栏：干净扫描不受影响，仍判 complete（否则全库样本一律降级）。"""
    a = _assess({"resource_files_scanned": 12, "resource_files_read_failed": 0})
    assert a["sources"]["resource"]["visibility"] == VIS_COMPLETE


def test_legacy_report_without_new_keys_unchanged() -> None:
    """旧报告没有新键 → 行为与加这条判据之前逐字一致（有扫描数即 complete）。"""
    assert _assess({"resource_files_scanned": 3})["sources"]["resource"]["visibility"] == VIS_COMPLETE
    assert _assess({})["sources"]["resource"]["visibility"] == VIS_UNKNOWN


@pytest.mark.parametrize(
    "meta, expected, why",
    [
        ({"uni_encrypted": True, "resource_files_read_failed": 5}, "opaque",
         "确证不可读优先于部分不可读"),
        ({"resource_listing_failed": True, "crypto_recipe": {"k": "v"}}, VIS_UNAVAILABLE,
         "列举都失败了，谈不上「识别出加密配置」的部分可读"),
    ],
)
def test_priority_order_is_conservative(meta: dict, expected: str, why: str) -> None:
    """判据优先级保守：越严的档位越先返回。"""
    assert _assess(meta)["sources"]["resource"]["visibility"] == expected, why


# --- 端到端：分析器写的键要真的被可见性读到 ------------------------------------


def test_analyzer_meta_keys_reach_visibility() -> None:
    """★接线锁：分析器写的键名必须与可见性读的键名对上。

    这两处此前不存在耦合关系，改名/漏写就是一条死信号——分析器辛苦数出来的读失败数
    没人消费，报告照旧签「已穷尽」。
    """
    ctx = _Ctx({
        "assets/broken.json": None,
        "res/xml/ok.xml": b"<x>https://api.test/</x>",
    })
    result = EndpointsAnalyzer().analyze(ctx)  # type: ignore[arg-type]

    assert result.error is None
    assert result.meta["resource_files_read_failed"] == 1
    assert result.meta["resource_listing_failed"] is False

    a = visibility.assess({"meta": {"dex_available": True, **result.meta}})
    assert a["sources"]["resource"]["visibility"] == VIS_PARTIAL, (
        "分析器数出了读失败，可见性却没读到——键名对不上，信号是死的"
    )
