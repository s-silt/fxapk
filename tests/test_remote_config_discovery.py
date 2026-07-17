"""config-chain slice-1a：远程配置对象**被动发现**测试。

覆盖：各对象存储/CDN 家族命中 + store_kind、非对象存储 host 的"后缀+路径"双证降噪、常见噪音不误报、
分析器端到端从 dex 字符串产 REMOTE_CONFIG 线索。纯离线（发现层不联网）。
"""

from __future__ import annotations

from apkscan.analyzers.remote_config import RemoteConfigAnalyzer
from apkscan.config.discover import DiscoveryRules, classify_config_url
from apkscan.core.models import LeadCategory

_RULES = DiscoveryRules.load()


def _classify(url: str):
    return classify_config_url(url, "dex-string[0]", _RULES)


# --------------------------------------------------------------------------- #
# 对象存储 / CDN 家族识别（单证入选）
# --------------------------------------------------------------------------- #
def test_aliyun_oss_object_is_candidate() -> None:
    c = _classify("https://my-bucket.oss-cn-hangzhou.aliyuncs.com/app/config.dat")
    assert c is not None
    assert c.store_kind == "aliyun-oss"
    assert "object-storage-host" in c.reasons
    assert c.object_path == "/app/config.dat"


def test_tencent_cos_and_huawei_obs_and_aws_s3_and_qiniu() -> None:
    fam = {
        "https://bkt.cos.ap-guangzhou.myqcloud.com/c.bin": "tencent-cos",
        "https://bkt.obs.cn-north-4.myhuaweicloud.com/c.json": "huawei-obs",
        "https://bkt.s3.us-east-1.amazonaws.com/c.dat": "aws-s3",
        "https://bkt.s3.amazonaws.com/c.dat": "aws-s3",
        "https://cdn.clouddn.com/init/c.data": "qiniu",
    }
    for url, expected in fam.items():
        c = _classify(url)
        assert c is not None and c.store_kind == expected, url
        assert "object-storage-host" in c.reasons


def test_path_style_oss_endpoint_host_matches() -> None:
    # path-style（bucket 在路径而非子域）：host 本身就是 oss-*.aliyuncs.com
    c = _classify("https://oss-cn-beijing.aliyuncs.com/bucket/settings.json")
    assert c is not None and c.store_kind == "aliyun-oss"


# --------------------------------------------------------------------------- #
# 非对象存储 host：后缀 + 路径双证才入选（降噪）
# --------------------------------------------------------------------------- #
def test_generic_host_needs_both_ext_and_path_hint() -> None:
    # 双证齐 → 入选（store_kind=http）
    c = _classify("https://api.example.com/appconfig/data.dat")
    assert c is not None
    assert c.store_kind == "http"
    assert "config-like-ext" in c.reasons and "config-like-path" in c.reasons

    # 只有后缀、无配置路径 → 不入选（普通 .json 端点不当配置）
    assert _classify("https://api.example.com/user/list.json") is None
    # 只有配置路径、无配置后缀 → 不入选
    assert _classify("https://api.example.com/config/index.html") is None


def test_common_noise_not_flagged() -> None:
    for url in (
        "https://www.google.com/search?q=x",
        "https://schemas.android.com/apk/res/android",
        "https://github.com/foo/bar",
        "wss://im.example.com/socket",  # 非 http(s)，_URL_RE/classify 均不收
        "not a url",
    ):
        assert _classify(url) is None, url


# --------------------------------------------------------------------------- #
# 分析器端到端
# --------------------------------------------------------------------------- #
class _StubCtx:
    def __init__(self, strings: list[str]) -> None:
        self._strings = strings

    def dex_strings(self):
        return iter(self._strings)


def test_analyzer_emits_remote_config_leads_from_dex_strings() -> None:
    ctx = _StubCtx([
        "prefix https://cfg.oss-cn-shenzhen.aliyuncs.com/app/domain.dat suffix",
        "https://www.google.com/",  # 噪音
        "https://api.example.com/appconfig/settings.conf",  # 双证
    ])
    result = RemoteConfigAnalyzer().analyze(ctx)  # type: ignore[arg-type]
    assert result.error is None
    values = {lead.value for lead in result.leads}
    assert "https://cfg.oss-cn-shenzhen.aliyuncs.com/app/domain.dat" in values
    assert "https://api.example.com/appconfig/settings.conf" in values
    assert "https://www.google.com/" not in values
    assert all(lead.category is LeadCategory.REMOTE_CONFIG for lead in result.leads)
    assert all(lead.advice == "待核" for lead in result.leads)  # 未下载解码、不下调证结论
    assert result.meta["remote_config_candidate_count"] == 2
    assert result.meta["remote_config_source_scope"] == "dex-strings"


def test_analyzer_dedups_repeated_url() -> None:
    url = "https://b.oss-cn-hangzhou.aliyuncs.com/c.dat"
    result = RemoteConfigAnalyzer().analyze(_StubCtx([url, f"x {url} y", url]))  # type: ignore[arg-type]
    assert len([lead for lead in result.leads if lead.value == url]) == 1
