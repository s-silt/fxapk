"""FaviconAnalyzer 单测 —— FakeContext 喂图标字节，验证测绘 pivot 线索产出。

覆盖：
- mipmap/drawable 下 ic_launcher.png → CONFIG_KEY Lead（value=favicon_mmh3=<hash>）。
- Lead notes 含 FOFA / Shodan / ZoomEye 一键查询串；where_to_request 指向测绘平台。
- result.meta["favicon_mmh3"] = <int>，供团伙聚类当并簇键。
- assets/www/static 下 favicon.* 也能定位。
- denylist 命中（全透明/空白占位）→ 跳过，不产线索。
- 无图标 / 坏字节 / read_file 抛异常 → 不抛、error 为 None。
"""

from __future__ import annotations

from apkscan.analyzers.favicon import FaviconAnalyzer
from apkscan.core.models import AnalyzerResult, Confidence, LeadCategory
from apkscan.dynamic.fingerprint import favicon_hash
from tests.conftest import FakeContext

# 一段非平凡的"图标"字节（够长触发 base64 换行，且不在 denylist 里）。
_ICON_BYTES = bytes(range(256)) * 8  # 2048 字节


def _analyze(files: dict[str, bytes]) -> AnalyzerResult:
    return FaviconAnalyzer().analyze(FakeContext(files=files))


# ---------------------------------------------------------------------------
# 基本属性
# ---------------------------------------------------------------------------


def test_analyzer_identity() -> None:
    a = FaviconAnalyzer()
    assert a.name == "favicon"
    assert a.requires == []


# ---------------------------------------------------------------------------
# 命中 → CONFIG_KEY Lead + meta
# ---------------------------------------------------------------------------


def test_mipmap_ic_launcher_yields_lead_and_meta() -> None:
    result = _analyze({"res/mipmap-xxhdpi/ic_launcher.png": _ICON_BYTES})

    assert result.error is None
    expected_hash = favicon_hash(_ICON_BYTES)

    # meta 并簇键。
    assert result.meta["favicon_mmh3"] == expected_hash
    assert isinstance(result.meta["favicon_mmh3"], int)

    # 恰一条 CONFIG_KEY Lead。
    leads = [lead for lead in result.leads if lead.category == LeadCategory.CONFIG_KEY]
    assert len(leads) == 1
    lead = leads[0]

    assert lead.value == f"favicon_mmh3={expected_hash}"
    assert lead.subject == "待核（测绘 pivot 锚点）"
    assert lead.confidence == Confidence.HIGH
    assert lead.advice == "建议调证"
    assert "测绘" in (lead.where_to_request or "")
    assert any("公网 IP" in e for e in lead.evidence_to_obtain)

    # notes 必含三家平台一键查询串。
    assert f'icon_hash="{expected_hash}"' in lead.notes  # FOFA
    assert f"http.favicon.hash:{expected_hash}" in lead.notes  # Shodan
    assert f'iconhash:"{expected_hash}"' in lead.notes  # ZoomEye

    # source_refs 指到具体图标文件。
    assert lead.source_refs
    assert lead.source_refs[0].location == "res/mipmap-xxhdpi/ic_launcher.png"


def test_webp_launcher_and_drawable_located() -> None:
    for path in (
        "res/mipmap-anydpi-v26/ic_launcher.webp",
        "res/drawable-xhdpi/ic_launcher_round.png",
    ):
        result = _analyze({path: _ICON_BYTES})
        assert result.meta.get("favicon_mmh3") == favicon_hash(_ICON_BYTES)
        assert any(lead.category == LeadCategory.CONFIG_KEY for lead in result.leads)


def test_assets_www_static_favicon_located() -> None:
    for path in (
        "assets/web/favicon.ico",
        "www/favicon.png",
        "static/favicon.ico",
    ):
        result = _analyze({path: _ICON_BYTES})
        assert result.meta.get("favicon_mmh3") == favicon_hash(_ICON_BYTES), path
        assert any(lead.category == LeadCategory.CONFIG_KEY for lead in result.leads), path


# ---------------------------------------------------------------------------
# denylist
# ---------------------------------------------------------------------------


def test_denylisted_blank_icon_skipped() -> None:
    # 空字节占位（全透明/空白模板）属 denylist，命中即跳过、不产线索。
    blank = b"\x00" * 1024
    result = _analyze({"res/mipmap-hdpi/ic_launcher.png": blank})

    assert result.error is None
    assert not [lead for lead in result.leads if lead.category == LeadCategory.CONFIG_KEY]
    # denylist 命中不应写 meta 并簇键（否则把通用图标当强连边）。
    assert "favicon_mmh3" not in result.meta


def test_empty_icon_bytes_denylisted() -> None:
    # 空文件（0 字节）也属显然排除项。
    result = _analyze({"static/favicon.ico": b""})
    assert result.error is None
    assert not result.leads


# ---------------------------------------------------------------------------
# 错误韧性
# ---------------------------------------------------------------------------


def test_no_icon_files_clean() -> None:
    result = _analyze(
        {
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": b"dex\n035\x00",
            "res/raw/config.json": b"{}",
        }
    )
    assert result.error is None
    assert not result.leads
    assert "favicon_mmh3" not in result.meta


def test_read_file_raises_does_not_crash() -> None:
    class _BoomCtx(FakeContext):
        def read_file(self, path: str) -> bytes | None:
            raise OSError("boom")

    ctx = _BoomCtx(files={"res/mipmap-xxhdpi/ic_launcher.png": _ICON_BYTES})
    result = FaviconAnalyzer().analyze(ctx)
    # 单个坏图标不炸 analyze。
    assert result.error is None
    assert not result.leads


def test_list_files_raises_sets_error_not_throw() -> None:
    class _BoomCtx(FakeContext):
        def list_files(self) -> list[str]:
            raise OSError("boom")

    result = FaviconAnalyzer().analyze(_BoomCtx())
    # 顶层数据源失败：记 error 而非抛出。
    assert result.error is not None


def test_one_bad_icon_does_not_block_others() -> None:
    # 第一个图标 read 返回 None（坏），第二个正常 → 仍产正常那条线索。
    class _PartialCtx(FakeContext):
        def read_file(self, path: str) -> bytes | None:
            if path.endswith("bad.png"):
                return None
            return super().read_file(path)

    ctx = _PartialCtx(
        files={
            "res/mipmap-hdpi/ic_launcher_bad.png": b"ignored",
            "res/mipmap-xxhdpi/ic_launcher.png": _ICON_BYTES,
        }
    )
    result = FaviconAnalyzer().analyze(ctx)
    assert result.error is None
    assert result.meta.get("favicon_mmh3") == favicon_hash(_ICON_BYTES)
