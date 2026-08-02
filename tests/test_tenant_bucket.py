"""对象存储的租户桶：`<桶名>.<厂商端点>` 不得被「云厂商整域豁免」吃掉。

云厂商域下混着两类完全不同的东西——厂商自有门户/静态资源域（与租户无关，判无需核查是对的），
和 `<桶名>.<区域>.<厂商域>` 这种租户专属子域（桶名就是租户凭据，拿它能向云厂商核出实名、
付款与访问日志）。判据若不分这两类、一刀切成「云厂商 = 无需核查」，划掉的恰恰是最能落到人的
那一类目标。

本文件此前**不存在**，而 `infra._TENANT_BUCKET_PATTERNS` 的注释一直写着「反向用例逐条列在
tests/test_tenant_bucket.py」——判据零覆盖，承诺落空。

★两组断言的分工：
  · `tenant_bucket()` 只管识别形态；
  · **真正要锁的不变量在 `classify_domain()`**——租户桶判定必须排在已知基础设施名单之前。
    顺序一反，桶名后缀正是厂商域，整域豁免会先命中，桶就没了。只测前者测不出这件事。
"""

from __future__ import annotations

import pytest

from apkscan.core import infra

#: 合成桶名：形态与真实一致（十六进制串），不含任何取自样本材料的值。
_B = "0123456789abcdef"

#: `(域名, 期望的厂商标签)` —— 每家一条正向用例。
_TENANT_BUCKETS: tuple[tuple[str, str], ...] = (
    (f"{_B}.oss-cn-hangzhou.aliyuncs.com", "阿里云 OSS"),
    (f"{_B}.oss-accelerate.aliyuncs.com", "阿里云 OSS"),
    (f"{_B}.gz.bcebos.com", "百度智能云 BOS"),
    (f"{_B}-1250000000.cos.ap-nanjing.myqcloud.com", "腾讯云 COS"),
    (f"{_B}-1250000000.file.myqcloud.com", "腾讯云 COS"),
    (f"{_B}.s3.amazonaws.com", "AWS S3"),
    (f"{_B}.s3-us-west-2.amazonaws.com", "AWS S3"),
    (f"{_B}.obs.cn-north-4.myhuaweicloud.com", "华为云 OBS"),
    (f"{_B}.jiangsu-10.zos.ctyun.cn", "天翼云 ZOS"),
    (f"{_B}.ks3-cn-beijing.ksyuncs.com", "金山云 KS3"),
    (f"{_B}.ks3-cn-beijing.ksyun.com", "金山云 KS3"),
    (f"{_B}.cn-bj.ufileos.com", "UCloud US3"),
    (f"{_B}.pek3b.qingstor.com", "青云 QingStor"),
    (f"{_B}.s3.cn-north-1.jdcloud-oss.com", "京东云 OSS"),
    (f"{_B}.storage.googleapis.com", "Google Cloud Storage"),
    # ★这里曾有一条按 host-style 写的某家 FDS 用例，已随实现一并撤回：该厂商公开的接口是
    #   path-style（桶在 URL 路径里而非主机名里），按主机名构造的形态找不到公开依据。
    #   声称覆盖一个可能不存在的形态比不覆盖更糟——会让人以为那家已经护住了。
    (f"{_B}.obs.myhwclouds.com", "华为云 OBS"),
    (f"{_B}.obs-website.cn-north-4.myhuaweicloud.com", "华为云 OBS"),
    (f"{_B}.blob.core.windows.net", "Azure Blob"),
    # 中间段是 32 位十六进制的账号标识，不是区域码——用 _B 拼两遍凑足 32 位。
    (f"{_B}.{_B * 2}.r2.cloudflarestorage.com", "Cloudflare R2"),
    (f"{_B}.nyc3.digitaloceanspaces.com", "DigitalOcean Spaces"),
    (f"{_B}.storage.yandexcloud.net", "Yandex Object Storage"),
)

#: ★这条不是预防，是**修一个当时正在生效的漏洞**：厂商域在已知基础设施名单里、而桶形态
#: 不在本表，于是整域豁免先命中，桶被判无需核查——既不富化、不进闭环、也不出文书。
#: 单独列出来并单独断言，是为了让后人删改对应正则时看到的红是「活洞复发」而不是「少了一条」。
_LIVE_HOLES: tuple[tuple[str, str], ...] = (
    (f"{_B}.storage.googleapis.com", "该厂商整域豁免曾吃掉其对象存储租户桶"),  # leak-scan: allow 活洞回归用例，须用真实存储端点域才复现得了「被整域豁免吃掉」
)

#: 裸区域端点：**没有桶名标签**，就没有租户，查不出人 —— 不得被当成租户桶。
#:
#: ★这一组必须用**各厂商真实的端点域**：判据正是按这些端点域的形态写的，护栏要验证的恰恰是
#:   「同一个端点域，带桶名标签的认、不带的不认」。换成保留域就没有任何东西可验——正则压根
#:   不会去匹配 example.com。故逐条豁免，理由随用途分列，不共用一句糊满。
_BARE_ENDPOINTS: tuple[str, ...] = (
    "oss-cn-hangzhou.aliyuncs.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "bcebos.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    # ★区域段一旦被放开成可选，这条就会被当成「桶名=gz」——它是那个改动的看门人。
    "gz.bcebos.com",  # leak-scan: allow 裸区域端点，锁住「区域段不得放开成可选」
    "cos.ap-nanjing.myqcloud.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "s3.amazonaws.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "obs.cn-north-4.myhuaweicloud.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "zos.ctyun.cn",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "jiangsu-10.zos.ctyun.cn",  # leak-scan: allow 裸区域端点，锁住「区域段不得放开成可选」
    "ks3-cn-beijing.ksyuncs.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "cn-bj.ufileos.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "pek3b.qingstor.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "s3.cn-north-1.jdcloud-oss.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "storage.googleapis.com",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    # 同一厂商域下的非存储服务：比裸端点更不该被当成桶。
    "fonts.googleapis.com",  # leak-scan: allow 同厂商域下的非存储服务，验正则不越界到该域其它子域
    "blob.core.windows.net",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
    "storage.yandexcloud.net",  # leak-scan: allow 裸端点反向用例，须用真实端点域才验得到「无桶名不认」
)


# ---------------------------------------------------------------------------
# 形态识别
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("domain", "provider"), _TENANT_BUCKETS)
def test_tenant_bucket_recognised(domain: str, provider: str) -> None:
    """每家的 `<桶名>.<端点>` 都要能认出，并把桶名原样取出来。"""
    got = infra.tenant_bucket(domain)

    assert got is not None, f"未识别为租户桶：{domain}"
    assert got[0] == provider
    assert got[1].startswith(_B), f"桶名取错：{got[1]}"


@pytest.mark.parametrize("domain", _BARE_ENDPOINTS)
def test_bare_endpoint_is_not_a_tenant_bucket(domain: str) -> None:
    """★反向护栏：没有桶名标签就没有租户。误判成桶会凭空造出一个查不到的目标。"""
    assert infra.tenant_bucket(domain) is None, f"裸端点被误判为租户桶：{domain}"


#: 域边界攻击：后缀匹配必须钉在真域边界上，不能被「后接他域」「缺点分隔」「换 TLD」绕过。
#: 这类值一旦被误判成租户桶，会凭空产出一个查不到租户的目标——比漏更糟。
#: ★同样必须基于真实端点域构造：绕过手法针对的就是「后缀匹配是否钉在真域边界上」，
#:   拿保留域拼出来的攻击串测不到这件事。
_BOUNDARY_ATTACKS: tuple[str, ...] = (
    f"{_B}.storage.googleapis.com.evil.tld",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}xstorage.googleapis.com",  # leak-scan: allow 域边界用例：缺点分隔，验不被子串命中
    f"{_B}.storage.googleapis.com.cn",  # leak-scan: allow 域边界用例：换 TLD，验后缀不被截断匹配
    "evil-googleapis.com",  # leak-scan: allow 域边界用例：前缀粘连，验不被子串命中
    f"{_B}.zos.ctyun.cn.attacker.top",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}.jiangsu-10.zos.ctyun.cn.evil.tld",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}.blob.core.windows.net.phish.io",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}.r2.cloudflarestorage.com.evil.tld",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}.storage.yandexcloud.net.evil.tld",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
    f"{_B}.obs-website.cn-north-4.myhuaweicloud.com.evil.tld",  # leak-scan: allow 域边界用例：真端点域后接他域，验尾锚定
)

#: 与对象存储无关的域名：不得被任何一条正则捎带命中。
#: 这批只需验证「不被误匹配」，用合成域名即可——真实厂商域只留在确实需要它的
#: `_BARE_ENDPOINTS`（裸端点）与 `_BOUNDARY_ATTACKS`（域边界）两组里。
_NOT_BUCKETS: tuple[str, ...] = (
    "www.example.com",
    "api.example.com",
    "login.example.com",
    "cdn.example.net",
    "storage.example.org",      # 名字里带 storage，但不属任何厂商端点
    "bucket.example.com",       # 名字里带 bucket，同上
    "s3.example.com",           # 名字里带 s3，同上
    "host.invalid",
)


@pytest.mark.parametrize("domain", _BOUNDARY_ATTACKS)
def test_boundary_attack_is_not_a_tenant_bucket(domain: str) -> None:
    """★域边界：`$` 锚定与点分隔必须真的挡住这些构造。"""
    assert infra.tenant_bucket(domain) is None, f"域边界被绕过：{domain}"


@pytest.mark.parametrize("domain", _NOT_BUCKETS)
def test_unrelated_domain_is_not_a_tenant_bucket(domain: str) -> None:
    """正则不得捎带命中与对象存储无关的域名。"""
    assert infra.tenant_bucket(domain) is None, f"误匹配：{domain}"


def test_gcs_bucket_name_may_contain_dots() -> None:
    """GCS 的虚拟主机式写法允许桶名含点——桶名要整段取出，不能只切最后一节。"""
    got = infra.tenant_bucket("my.dotted.bucket.storage.googleapis.com")  # leak-scan: allow 含点桶名用例，须用真实存储端点域才验得到该切法

    assert got is not None
    assert got == ("Google Cloud Storage", "my.dotted.bucket")


#: 语法上不可能存在的租户标识：端点后缀虽对，但标识本身违反该厂商公开的命名约束。
#: ★这一组防的是「凭空造目标」——端点写对只说明是哪家厂商，标识非法就意味着这个租户根本
#:   不存在，认下来只会产出一条查不到人的线索。
_ILLEGAL_IDENTIFIERS: tuple[tuple[str, str], ...] = (
    ("中文桶.storage.googleapis.com", "非 ASCII：Python 的 \\w 会放行，DNS 标签不允许"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到字符类收紧
    ("a.storage.googleapis.com", "单字符：短于公开的桶名下限"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到长度下限
    # ★这条才是连续点约束的有效看门人：两侧都有合法字符，形态判据本身放得过去，
    #   只有语法校验能拦下。写成 `a..storage...` 会被「桶名须以字母数字结尾」顺带挡住，
    #   删掉连续点约束也照样红不了——那是个假看门人。
    ("ab..cd.storage.googleapis.com", "连续点：不是合法 DNS 名"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到连续点被拒
    ("ab.-cd.storage.googleapis.com", "点后紧跟连字符"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到相邻组合约束
    ("ab-.cd.storage.googleapis.com", "连字符后紧跟点"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到相邻组合约束
    ("192.0.2.1.storage.googleapis.com", "整体成 IPv4 字面，厂商禁止桶名长成 IP 的样子"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到 IPv4 形态被拒
    ("ab.-cd.storage.yandexcloud.net", "点后紧跟连字符（另一家同样禁止）"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到相邻组合约束
    ("ab-.cd.storage.yandexcloud.net", "连字符后紧跟点（另一家同样禁止）"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到相邻组合约束
    ("bucket.0123456789abcdef0123456789abcdef.zz.r2.cloudflarestorage.com", "辖区段不在公开枚举内"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到辖区枚举约束
    ("-lead.storage.googleapis.com", "以连字符开头"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到首字符约束
    ("trail-.storage.googleapis.com", "以连字符结尾"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到尾字符约束
    ("a_b.blob.core.windows.net", "该厂商账户名不允许下划线"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到该厂商字符集约束
    ("a-b.blob.core.windows.net", "该厂商账户名不允许连字符"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到该厂商字符集约束
    ("ab.blob.core.windows.net", "短于该厂商账户名下限（3）"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到该厂商长度下限
    ("a" * 25 + ".blob.core.windows.net", "长于该厂商账户名上限（24）"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到该厂商长度上限
    ("bucket.notanaccountid.r2.cloudflarestorage.com", "中间段不是 32 位十六进制账号标识"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到账号标识形态约束
    ("bucket.deadbeef.r2.cloudflarestorage.com", "账号标识位数不足"),  # leak-scan: allow 非法标识用例，须用真实端点域才验得到账号标识位数约束
)


@pytest.mark.parametrize(("domain", "why"), _ILLEGAL_IDENTIFIERS)
def test_illegal_identifier_is_not_a_tenant_bucket(domain: str, why: str) -> None:
    """★端点后缀对、但租户标识语法非法 → 不得认成桶。

    只收紧端点后缀而放任标识字符类，会匹配出一批语法上不可能存在的账户名——那是凭空造目标，
    比漏更糟。放宽 `_BUCKET` / `_BUCKET_DOTTED` 或 Azure、R2 两条的标识约束，本组即红。
    """
    assert infra.tenant_bucket(domain) is None, f"非法标识被认成桶（{why}）：{domain}"


def test_dotted_bucket_names_are_recognised_where_the_vendor_allows_them() -> None:
    """★允许带点桶名的几家，合法带点标识不得被拒。

    收紧字符类时曾把这几家一并换成不含点的片段，合法的带点桶名会因此被整域豁免吃掉——
    「宁漏勿宽」不等于可以漏掉厂商明确允许的形态。
    """
    for domain, provider in (
        ("my.valid.bucket.s3.amazonaws.com", "AWS S3"),  # leak-scan: allow 带点桶名正例，须用真实端点域才验得到该厂商允许点号
        ("my.valid.bucket.obs.cn-north-4.myhuaweicloud.com", "华为云 OBS"),  # leak-scan: allow 带点桶名正例，须用真实端点域才验得到该厂商允许点号
        ("my.valid.bucket.storage.yandexcloud.net", "Yandex Object Storage"),  # leak-scan: allow 带点桶名正例，须用真实端点域才验得到该厂商允许点号
    ):
        got = infra.tenant_bucket(domain)
        assert got is not None, f"合法带点桶名被拒：{domain}"
        assert got == (provider, "my.valid.bucket")


def test_r2_jurisdiction_endpoints_are_recognised() -> None:
    """公开枚举内的辖区端点要认；枚举外的在非法用例里已断言不认。"""
    account = "0123456789abcdef" * 2
    for jurisdiction in ("eu", "fedramp"):
        # leak-scan: allow 辖区端点正例，须用真实端点域才验得到枚举内取值被接受
        domain = f"my-bucket.{account}.{jurisdiction}.r2.cloudflarestorage.com"
        assert infra.tenant_bucket(domain) == ("Cloudflare R2", "my-bucket"), jurisdiction


def test_legal_identifier_edges_still_recognised() -> None:
    """反向：合法但处在边界上的标识不得被误伤（收紧不能收过头）。"""
    assert infra.tenant_bucket("abc.storage.googleapis.com") is not None, "3 字符是合法下限"  # leak-scan: allow 边界正例，须用真实端点域才验得到长度下限
    assert infra.tenant_bucket("abc.blob.core.windows.net") is not None, "3 字符账户名合法"  # leak-scan: allow 边界正例，须用真实端点域才验得到长度下限
    assert infra.tenant_bucket("a" * 24 + ".blob.core.windows.net") is not None, "24 字符是上限"  # leak-scan: allow 边界正例，须用真实端点域才验得到长度上限
    r2 = f"my-bucket.{'0123456789abcdef' * 2}.r2.cloudflarestorage.com"  # leak-scan: allow 边界正例，须用真实端点域才验得到账号标识形态
    assert infra.tenant_bucket(r2) is not None, "32 位十六进制账号标识是合法形态"


def test_non_bucket_inputs_do_not_raise() -> None:
    """坏输入不得抛：判据在 classify_domain 的第一步，抛了就整条链断。"""
    for bad in ("", "   ", "not a domain", "http://", "...", "a." * 200):
        assert infra.tenant_bucket(bad) is None


# ---------------------------------------------------------------------------
# ★不变量：租户桶必须排在已知基础设施名单之前
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("domain", "provider"), _TENANT_BUCKETS)
def test_tenant_bucket_reaches_investigate_at_the_real_entry(domain: str, provider: str) -> None:
    """走 `classify_domain` 这个真入口，每家的桶都要判 ADVICE_INVESTIGATE 并点明厂商。

    ★这条锁的是「结果」，不是「顺序」——名字别起成 survives_known_infra_exemption 那种，
      会把保证说得比实际强：对于厂商域**不在**已知基础设施名单里的那几家，即使把
      tenant_bucket 短路挪到 `_matched_infra` 之后，它们照样能从末尾兜底档拿到
      ADVICE_INVESTIGATE，这条对它们并不构成顺序保证。
      真正逐项锁顺序的是下面的 `test_live_hole_stays_closed`（它显式要求厂商域在名单内）
      与 `test_bucket_beats_infra_even_for_listed_provider_domain`（同域带/不带桶名的对照）。
    """
    advice, reason = infra.classify_domain(domain)

    assert advice == infra.ADVICE_INVESTIGATE, f"{domain} 被降档，整域豁免吃掉了租户桶"
    assert provider in reason, "理由里要点明是哪家云厂商，否则不知道该向谁核"


@pytest.mark.parametrize(("domain", "history"), _LIVE_HOLES)
def test_live_hole_stays_closed(domain: str, history: str) -> None:
    """★回归锁：这些形态曾被整域豁免真正吃掉过（不是理论风险）。

    三处都要钉，缺一处这条锁就会在语义漂移后仍然全绿：
      1. 该厂商域**确实还在**已知基础设施名单里——这是「会被整域豁免吃掉」的前提。
         若哪天该条目被移出名单，本用例就不再复现原缺陷，此时应重挑用例而不是继续绿着；
      2. 形态被认出来是租户桶；
      3. 真入口上没被降成无需核查。
    删掉对应正则条目，第 2、3 条即红——红的含义是「那个洞又开了」。
    """
    assert infra._matched_infra(domain) is not None, (
        f"前提已不成立：该厂商域已不在已知基础设施名单里，本用例不再复现原缺陷（{history}）"
    )

    assert infra.tenant_bucket(domain) is not None, f"形态未被识别：{history}"

    advice, _reason = infra.classify_domain(domain)
    assert advice == infra.ADVICE_INVESTIGATE, f"活洞复发：{history}"


def test_bare_endpoint_still_exempt_when_in_known_infra() -> None:
    """反向：厂商自有的裸端点该豁免就豁免——护栏不能宽到把厂商门户也当目标。

    只对**确实收录在已知基础设施名单里**的裸端点断言，避免把「名单里没有」误当成判据失效。
    """
    checked = 0
    for domain in _BARE_ENDPOINTS:
        if infra._matched_infra(domain) is None:
            continue  # 该厂商域不在名单里，落兜底档，本条不适用
        checked += 1
        advice, _reason = infra.classify_domain(domain)
        assert advice == infra.ADVICE_SKIP, f"名单内的裸端点不该被当成目标：{domain}"
    assert checked, "名单里一个裸端点都没有，这条反向断言没有实际效力，需重新挑用例"


def test_bucket_beats_infra_even_for_listed_provider_domain() -> None:
    """★把上面两条合起来钉死：同一个厂商域，裸端点豁免、带桶名的不豁免。

    这才是「整域豁免吃掉租户桶」这个缺陷的最小复现形态——两者只差一个桶名标签。
    """
    listed = [d for d in _BARE_ENDPOINTS if infra._matched_infra(d) is not None]
    assert listed, "需要至少一个在已知基础设施名单里的厂商域来构造该对照"

    checked = 0
    for bare in listed:
        with_bucket = f"{_B}.{bare}"
        if infra.tenant_bucket(with_bucket) is None:
            continue  # 该形态不是本判据覆盖的桶写法，跳过
        checked += 1
        assert infra.classify_domain(bare)[0] == infra.ADVICE_SKIP
        assert infra.classify_domain(with_bucket)[0] == infra.ADVICE_INVESTIGATE, (
            f"仅多一个桶名标签就该从豁免翻成目标：{bare} → {with_bucket}"
        )
    # ★没有这一句，上面的 continue 全部跳过时本测试会静静地通过、变成恒真。
    #   `assert listed` 只保证「有名单内厂商域」，保证不了「其中至少一个能构造出桶」。
    assert checked, "一个对照都没跑到，本测试已退化为恒真——需重挑用例"


# ---------------------------------------------------------------------------
# 桶名是**占位符**的模板形态
#
# 实测样本（Go 控制面）里，配置地址是 `https://%s.<厂商端点>/%s.dat` 这样的模板——桶名每天
# 由算法现算，静态里只有占位符。这类域名的尾缀恰恰是云厂商域，于是整域豁免先命中、判「无需
# 再核」：一条「样本会去某家对象存储取东西、桶名还是运行时算出来的」的事实，被判成与本案无关。
# 而 ADVICE_SKIP 是判据链结论、不走抑制账本，`fxapk lead restore` 够不着——落进去捞不回来。
# ---------------------------------------------------------------------------

#: `(域名, 期望厂商, 期望占位字面)`。占位符本身是合成的模板语法，非取自任何样本材料。
_TEMPLATE_BUCKETS: tuple[tuple[str, str, str], ...] = (
    ("%s.gz.bcebos.com", "百度智能云 BOS", "%s"),  # leak-scan: allow 桶模板正向用例，须用真实端点域才验得到「模板不被整域豁免吃掉」
    ("%s.oss-accelerate.aliyuncs.com", "阿里云 OSS", "%s"),  # leak-scan: allow 桶模板正向用例，覆盖另一家的加速端点形态
    ("%s.jiangsu-10.zos.ctyun.cn", "天翼云 ZOS", "%s"),  # leak-scan: allow 桶模板正向用例，覆盖区域段可变的端点形态
    ("%1$s.storage.googleapis.com", "Google Cloud Storage", "%1$s"),  # leak-scan: allow 桶模板正向用例，覆盖 printf 位置参数写法
    ("{bucket}.s3.amazonaws.com", "AWS S3", "{bucket}"),  # leak-scan: allow 桶模板正向用例，覆盖花括号模板写法
    ("{}.pek3b.qingstor.com", "青云 QingStor", "{}"),  # leak-scan: allow 桶模板正向用例，覆盖空花括号写法
    ("${bucket}.cn-bj.ufileos.com", "UCloud US3", "${bucket}"),  # leak-scan: allow 桶模板正向用例，覆盖 shell 风格变量写法
    ("<bucket>.blob.core.windows.net", "Azure Blob", "<bucket>"),  # leak-scan: allow 桶模板正向用例，覆盖尖括号写法与最严的账户名语法
)

#: 长得像但**不是**运行时填充记号的，逐条说明为什么。
_NOT_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("*.oss-cn-hangzhou.aliyuncs.com", "通配符语义是「任意/此处被隐去」，不是「运行时拼值进去」"),  # leak-scan: allow 通配符反向用例，须用真实端点域才验得到「通配符不算模板」
    ("s.gz.bcebos.com", "裸域名通道剥掉 % 之后的残片——已经没有占位符信息了"),  # leak-scan: allow 残片反向用例，须用真实端点域才验得到「剥掉 % 的残片不算模板」
    ("%s.fonts.googleapis.com", "同厂商但不是对象存储端点，尾缀判据不该命中"),  # leak-scan: allow 同厂商非存储子域反向用例，须用真实域才验得到「尾缀不是存储端点就不认」
    ("%s.example.com", "尾缀不属任何已知厂商"),
    ("%s.gz.bcebos.com.evil.example", "域边界：厂商端点后面还挂着别的注册域"),  # leak-scan: allow 域边界反向用例，须用真实端点域才验得到「后面还挂着别的注册域就不认」
    ("b%sé.gz.bcebos.com", "非 ASCII 夹杂元字符，多半是字符串表粘连噪音而非模板语言"),  # leak-scan: allow 非 ASCII 反向用例，须用真实端点域才验得到 isascii 门
)


@pytest.mark.parametrize("domain, provider, placeholder", _TEMPLATE_BUCKETS)
def test_template_bucket_recognised(domain: str, provider: str, placeholder: str) -> None:
    """占位字面**原样**取出，不伪装成桶名——它对应不到任何真实租户。"""
    assert infra.tenant_bucket_template(domain) == (provider, placeholder)


@pytest.mark.parametrize("domain, _provider, _placeholder", _TEMPLATE_BUCKETS)
def test_template_bucket_is_not_a_real_bucket(domain: str, _provider: str, _placeholder: str) -> None:
    """★误升档主锁：模板绝不能被真桶判据吃进去——那会让它判最高档、进文书出口。"""
    assert infra.tenant_bucket(domain) is None


@pytest.mark.parametrize("domain, provider, placeholder", _TEMPLATE_BUCKETS)
def test_template_reaches_review_at_the_real_entry(
    domain: str, provider: str, placeholder: str
) -> None:
    """走 ``classify_domain`` 真入口，**精确**断言待核：既不是无需再核，也不是最高档。

    两个方向都要锁：判 SKIP 是替人下「与本案无关」的结论且撤不回来；判最高档则是主张
    「该向这个标的的持有方发函」——可占位符没有能让云厂商检索到租户的键，那句话不成立。
    """
    advice, reason = infra.classify_domain(domain)

    assert advice == infra.ADVICE_REVIEW
    assert provider in reason and placeholder in reason, "厂商与占位字面都要写进理由供人看"


def test_template_beats_infra_for_listed_provider_domain() -> None:
    """★三钉法，锁的是**判据顺序**：模板分支必须排在整域豁免之前。

    先钉前提（厂商域确在已知基础设施名单里，否则这个洞压根复现不出来），再钉结论。
    """
    checked = 0
    for domain, provider, _placeholder in _TEMPLATE_BUCKETS:
        _label, _, tail = domain.partition(".")
        if infra._matched_infra(tail) is None:
            continue  # 该厂商域不在名单里，构不成「被整域豁免吃掉」的场景
        checked += 1
        assert infra.classify_domain(domain)[0] == infra.ADVICE_REVIEW, (
            f"{provider} 的域在已知基础设施名单里，模板分支排到它后面就会被整域豁免吃掉"
        )
    assert checked, "一条名单内厂商域都没跑到，本测试已退化为恒真——需重挑用例"


@pytest.mark.parametrize("domain, why", _NOT_TEMPLATES)
def test_non_template_is_not_recognised(domain: str, why: str) -> None:
    assert infra.tenant_bucket_template(domain) is None, why


def test_multi_label_template_is_a_known_gap_not_a_covered_case() -> None:
    """★如实钉住一个**已知缺口**：只有第一个标签会被当占位符处理。

    ``tenant_bucket_template`` 把第一个标签换成探针标识后交给真桶正则，所以
    ``%s.%s.<端点>`` 这种「用多个格式参数拼出带点桶名」的写法替换后仍含占位符、匹配不上，
    最终落回整域豁免。对允许点号桶名的厂商，这是实际存在的模型缺口。

    ★这条测试的意义是**不让后人误以为多段模板已经覆盖了**。修它的正确做法不是把所有标签
      一律替换——区域段、账号段同样可能含模板，盲目替换会放宽既有的严格判据（那些段的
      形态约束正是「不凭空造出不存在的端点」的保证）。要修得单独设计。
    """
    multi = "%s.%s.storage.googleapis.com"  # leak-scan: allow 已知缺口用例，须用真实端点域才复现得了「多段模板落回整域豁免」

    assert infra.tenant_bucket_template(multi) is None, "当前实现只处理第一个标签"
    assert infra.classify_domain(multi)[0] == infra.ADVICE_SKIP, (
        "如实记录现状：多段模板仍被整域豁免吃掉。这条变红说明缺口被修了——"
        "届时请把本测试改成正向用例，而不是删掉它"
    )


def test_wildcard_and_residue_stay_exempt() -> None:
    """模板判据不外溢：该被整域豁免吃掉的照旧吃掉，不因新增分支而松动。"""
    # leak-scan: allow 通配符的档位反向用例，须用真实端点域才验得到
    assert infra.classify_domain("*.oss-cn-hangzhou.aliyuncs.com")[0] == infra.ADVICE_SKIP
    assert infra.classify_domain("s.gz.bcebos.com")[0] == infra.ADVICE_SKIP  # leak-scan: allow 残片的档位反向用例，须用真实端点域才验得到


def test_template_reason_reaches_the_lead_through_the_real_entry() -> None:
    """★接线锁：降档的理由必须跟到线索上，走 ``build_endpoint_leads`` 真入口。

    只判对档位不够——出口读不到理由的话，人看到的是一条没有来由的「待核」，不知道
    「这是个桶名占位符、下一步该去取运行时真桶名」。本仓栽过两次同款
    （``shape_uncertain`` / ``sni_masquerade`` 都曾只写进 notes 而出口不渲染）。
    """
    from apkscan.core.leads import build_endpoint_leads
    from apkscan.core.models import Endpoint, Evidence

    value = "%s.gz.bcebos.com"  # leak-scan: allow 接线锁夹具，须用真实端点域才走得到模板判据
    ep = Endpoint(
        value=value,
        kind="domain",
        evidences=[Evidence(source="native", location="lib/arm64-v8a/libapp.so",
                            snippet=f"https://{value}/%s.dat")],
    )

    leads = build_endpoint_leads([ep], online=False)

    assert len(leads) == 1
    assert leads[0].advice == infra.ADVICE_REVIEW
    assert "桶名位置是占位符" in leads[0].notes, "降档理由没跟到线索上，出口就看不见它"


def test_template_survives_the_extraction_layer() -> None:
    """★提取层锁：占位符得先**活着**走完端点提取，判据才有机会看到它。

    这条锁的是一个隐式前提：``textutil.valid_url_host`` 的 docstring 明写它的用途正是
    「剔除 ``http://%s`` 这类来自格式串的伪 URL」。它目前只拦无点 host，所以带点的
    ``%s.<厂商端点>`` 能过——但后人顺手把「host 含 %」加进剔除条件是完全可能的动作，
    那一刻模板判据静默失能，而上面那些手造 ``Endpoint`` 的测试**照常全绿**。
    所以必须有一条从原始字节起跑的锁。
    """
    from apkscan.analyzers.endpoints import EndpointsAnalyzer
    from tests.conftest import FakeContext

    template_url = "https://%s.gz.bcebos.com/%s.dat"  # leak-scan: allow 提取层锁夹具，须用真实端点域才走得到模板判据
    result = EndpointsAnalyzer().analyze(
        FakeContext(files={"assets/cfg.json": template_url.encode()})
    )

    domains = {ep.value for ep in result.endpoints if ep.kind == "domain"}
    assert "%s.gz.bcebos.com" in domains, (  # leak-scan: allow 提取层锁断言，须用真实端点域才验得到
        "占位符在提取层就被吃掉了——模板判据永远收不到这个值，"
        f"而所有手造 Endpoint 的测试仍会全绿。实际提取到：{sorted(domains)}"
    )
