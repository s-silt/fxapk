"""对象存储的租户桶不是"云厂商基础设施"，是能落到人的查询目标。

来源是一处实打实的漏报：一个真实存在的桶域名在一份报告里被判「无需核查」，而**同一个桶**
在线索清单里早已被两个案子列为查询目标、受文单位写的就是百度智能云。全清单统计：8 个案子、
21 处把这类桶域名当目标用。

根因是判据把两类东西混在一个后缀底下：
  · 厂商自有门户与静态资源域——与租户无关，判无需核查是对的；
  · ``<桶名>.gz.bcebos.com``——**租户专属**子域，桶名（腾讯 COS 还带 appid）本身就是租户凭据。
一刀切成"云厂商 = 无需核查"，等于把最能落到实名的那类目标静默划掉——降噪走到了漏报那一侧。

★两个方向都要钉死：桶必须进出口，**裸服务端点必须照旧不进**。后者松了，每份报告都会多出
  一堆查不出租户的公共端点，那就把这条判据的收益又赔回去了。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra

_INV = infra.ADVICE_INVESTIGATE
_SKIP = infra.ADVICE_SKIP


# ---------------------------------------------------------------------------
# 正向：清单里被人工列为目标的那批，必须进出口
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("domain", "provider", "bucket"), [
    # 以下九个是线索清单里 8 个案子实际用过的桶（去重后），即本判据的现成验证集。
    ("bucket-a.example.invalid", "百度智能云 BOS", "REDACTED-A"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-b.example.invalid", "百度智能云 BOS", "REDACTED-B"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-c.example.invalid", "百度智能云 BOS", "REDACTED-C"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-d.example.invalid", "百度智能云 BOS", "REDACTED-D"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-e.example.invalid", "阿里云 OSS", "REDACTED-E"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-f.example.invalid", "阿里云 OSS", "REDACTED-F"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-g.example.invalid", "阿里云 OSS", "REDACTED-G"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-h.example.invalid", "AWS S3", "REDACTED-H"),  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    ("bucket-i.example.invalid", "腾讯云 COS",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
     "REDACTED-I"),
])
def test_tenant_buckets_are_investigation_targets(domain: str, provider: str, bucket: str) -> None:
    """桶域名进出口，且理由要写明云厂商与桶名——受文对象和凭据都得在理由里。"""
    advice, reason = infra.classify_domain(domain)
    assert advice == _INV, f"{domain} 仍判 {advice}（这是能落到实名的目标，不该被划掉）"
    assert provider in reason
    assert bucket in reason
    assert infra.tenant_bucket(domain) == (provider, bucket)


@pytest.mark.parametrize("domain", [
    "b.s3.amazonaws.com",                      # 无区域段的 S3 老形态  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "b.s3-us-west-2.amazonaws.com",            # 短横线区域形态  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "b.obs.cn-north-4.myhuaweicloud.com",      # 华为 OBS  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "b-1250000000.file.myqcloud.com",          # 腾讯云老 file 域  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "b-1250000000.pic.myqcloud.com",           # 腾讯云老 pic 域  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
])
def test_other_documented_bucket_shapes_also_match(domain: str) -> None:
    assert infra.classify_domain(domain)[0] == _INV, f"{domain} 没被认成租户桶"


# ---------------------------------------------------------------------------
# 反向：裸服务端点绝不能被拖进出口
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "bj.bcebos.com",                     # 百度 BOS 区域端点（无桶名）  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "gz.bcebos.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "oss-cn-hangzhou.aliyuncs.com",      # 阿里 OSS 区域端点  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "oss-accelerate.aliyuncs.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "cos.ap-beijing.myqcloud.com",       # 腾讯 COS 区域端点  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "s3.amazonaws.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "s3.us-east-1.amazonaws.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "obs.cn-north-4.myhuaweicloud.com",  # 华为 OBS 区域端点  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "www.baidu.com",                     # 厂商自有服务，与租户无关  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "bdstatic.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "www.taobao.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
])
def test_bare_service_endpoints_stay_out_of_the_list(domain: str) -> None:
    """★没有桶名就没有租户，查不出人；这些必须照旧判无需核查。"""
    assert infra.tenant_bucket(domain) is None, f"{domain} 被误认成租户桶"
    assert infra.classify_domain(domain)[0] == _SKIP, f"{domain} 被拖进了出口"


def test_huawei_bare_endpoint_now_behaves_like_the_other_four() -> None:
    """★补名单的理由：五家云里只有华为云的裸端点从来没进过 KNOWN_INFRA。

    不补的话，"桶→进出口、裸端点→不进"这条规则在华为云那一行自相矛盾（裸端点也进出口）。
    """
    assert infra.classify_domain("obs.cn-north-4.myhuaweicloud.com")[0] == _SKIP  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    assert infra.classify_domain("b.obs.cn-north-4.myhuaweicloud.com")[0] == _INV  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态


# ---------------------------------------------------------------------------
# 边界
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("domain", [
    "bucket.gz.bcebos.com.attacker.top",   # 后缀边界：不得因含 bcebos.com 就被认成桶  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "notbcebos.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "fake-amazonaws.com",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    "b.s3.amazonaws.com.evil.top",  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
])
def test_bucket_matching_respects_domain_boundaries(domain: str) -> None:
    """判据按整串锚定匹配，构造成"含云厂商域"的名字不得混成桶。"""
    assert infra.tenant_bucket(domain) is None


def test_bucket_check_runs_before_the_blanket_vendor_exemption() -> None:
    """★顺序即判据：桶域名的后缀正是云厂商域，先走整域豁免就被吃掉了。

    这条把"必须排在 KNOWN_INFRA 之前"钉成契约——调换顺序时它会红。
    """
    advice, reason = infra.classify_domain("bucket-a.example.invalid")  # leak-scan: allow 判据夹具：桶/端点形态本身就是被测对象，换占位域即失去被测形态
    assert advice == _INV
    assert "已知第三方基础设施" not in reason, "被整域豁免抢先命中了"


def test_bad_input_never_raises() -> None:
    for value in ("", "   ", "...", "a", "http://", None):
        assert infra.tenant_bucket(value) is None  # type: ignore[arg-type]
