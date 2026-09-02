"""提交前泄漏扫描（``core/leakscan.py``）的判据测试。

阳性夹具为什么是**字面量 + 行内豁免**
------------------------------------

本文件此前把阳性夹具按片段拼出（``".".join((45, 76, 1, 1))``），注释还写明这样做是为了
躲开自家扫描器。那条路必须封掉：

1. **它把门禁变成摆设。** 拼接模板一旦存在于仓库，任何真实地址都能用同一手法写进来，
   而扫描器永远看不见。护栏的价值等于它最容易被绕过的那条缝。
2. **它把手法教给下一个人。** 复制这段代码的人会连同绕过手法一起复制。

改法：阳性夹具一律写成**字面量**（扫描器看得见），"这行是有意的合成夹具"由
:mod:`apkscan.core.leakscan` 既有的行内豁免机制 ``leak-scan: allow <理由>`` 声明——
例外因此**可见、可审计**，而不是隐写。判据本身**一点没弱化**：豁免只作用于常量定义
那一行，夹具值经 f-string 进入被扫描的 diff 行时照常命中（见
:func:`test_positive_fixtures_still_fire_without_any_exemption`）。

阳性 IP 夹具的选值刻意避开"某人的真实主机"
----------------------------------------

需要一个 ``is_global`` 为真的地址才能触发判据，而 RFC 5737 / RFC 3849 文档段被
:mod:`ipaddress` 判为 private。故选 **IETF 协议专用的全局 anycast 段**：

- IPv4 取 RFC 7526 **已废弃**的 6to4 中继 anycast 前缀（该前缀已停止分配给任何主机）；
- IPv6 取 RFC 7723 Port Control Protocol anycast 前缀。

两者 ``is_global`` 为真（判据会命中，测试有意义），但都不是任何组织的业务后端地址。

★具体字面量只出现在下方常量定义那一行、且各自带行内豁免；本段说明**刻意不复述**
  地址本身——否则文档行会成为又一处扫描器命中点，而给散文加豁免等于给判据开天窗
  （见 :func:`test_this_test_file_itself_passes_strict_scan`，它扫的是整份文件）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.core import leakscan

# --- 阳性夹具：字面量 + 带理由的行内豁免（绝不拼接绕过，见模块文档） ----------------
#: 触发 ``ip`` 判据用。RFC 7526 已废弃的 6to4 中继 anycast，不是任何主机的地址。
_PUBLIC_IPV4 = "192.88.99.1"  # leak-scan: allow ip 判据阳性夹具，RFC7526 已废弃的协议 anycast 非真实主机
#: 触发 ``ip`` 判据用。RFC 7723 PCP anycast。
_PUBLIC_IPV6 = "2001:1::1"  # leak-scan: allow ip 判据阳性夹具，RFC7723 协议 anycast 非真实主机
#: 触发 ``domain`` 判据用：不在允许清单里的合成域名（未注册、语义自证合成）。
_OUTSIDE_DOMAIN = "synthetic-backend.top"  # leak-scan: allow domain 判据阳性夹具，合成未注册域名
#: 触发 ``secret`` 判据用：随机键盘串，不是任何服务的凭据。刻意不含占位标记词，
#: 否则 ``_looks_placeholder`` 会把它放行、阳性测试变成空测。
_SECRET_VALUE = "Zk3Qw9Lm2Rt7Yb4Nc8Vp"  # leak-scan: allow secret 判据阳性夹具，合成随机串非真实凭据
_CONTEXT_A = "办案"  # leak-scan: allow 语境词判据自测夹具
_CONTEXT_B = "涉诈"  # leak-scan: allow 语境词判据自测夹具
#: 触发 ``person_name`` 判据用：占位姓名 + 「案」。**形态真、值假**——判据有意不识别占位名
#: （真人也可能就叫这个名字），所以它与真名一样命中，正是合格的阳性夹具。
_CASE_NAME = "张三案"  # leak-scan: allow person_name 判据阳性夹具，占位姓名非案件当事人
#: 触发 ``contact`` 判据用：QQ 与微信内部 id 两种形态，号码/账号均为合成值。
_QQ_TEXT = "客服QQ：123456"  # leak-scan: allow contact 判据阳性夹具，合成 QQ 号
_WXID_TEXT = "wxid_synth0fixture"  # leak-scan: allow contact 判据阳性夹具，合成微信内部 id
#: 触发 ``package`` 判据用：随机化的包名段（连续辅音 10）。**刻意不用任何真实样本的包名**——
#: 那是案件值；本判据要的只是"某段像随机串"这个形态，合成串同样成立。
_REPACK_PACKAGE = "im.zxcvbnmqwr.messenger"  # leak-scan: allow package 判据阳性夹具，合成随机段包名

#: 阴性夹具：文档保留段，扫描器必须放行（故这几行**不带**豁免注释）。
_DOC_IP = "198.51.100.7"
_DOC_IPV6 = "2001:db8::1"
#: 阴性夹具：跨词边界的巧合（于/成 是姓氏字），以及公开的第三方包名与 Python 模块路径。
_NOT_A_CASE_NAME = "用于串案索引"
_STOCK_PACKAGE = "org.telegram.messenger"
_MODULE_PATH = "apkscan.core.leakscan"


def _diff(path: str, *added: str) -> str:
    """构造一份最小 unified diff（全部为新增行）。"""
    body = "".join(f"+{line}\n" for line in added)
    return f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(added)} @@\n{body}"


def _rules(findings: list[leakscan.Finding]) -> set[str]:
    return {f.rule for f in findings}


# ---------------------------------------------------------------------------
# 判据 1：IP
# ---------------------------------------------------------------------------


def test_real_public_ipv4_is_rejected() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'HOST = "{_PUBLIC_IPV4}"'))
    ip_findings = [f for f in findings if f.rule == "ip"]
    assert ip_findings, "真公网 IPv4 必须被判为泄漏"
    assert ip_findings[0].value == _PUBLIC_IPV4
    assert leakscan.blocking(findings), "IP 判据必须阻断"


def test_real_public_ipv6_is_rejected() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'HOST = "{_PUBLIC_IPV6}"'))
    assert [f for f in findings if f.rule == "ip" and f.value == _PUBLIC_IPV6]


def test_documentation_reserved_ranges_pass() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "tests/test_x.py",
            f'ep = "{_DOC_IP}"',
            f'v6 = "{_DOC_IPV6}"',
            'private = "10.0.0.1"',
            'loopback = "127.0.0.1"',
            'linklocal = "169.254.1.1"',
        )
    )
    assert not [f for f in findings if f.rule == "ip"], f"保留段被误判：{findings}"


def test_public_resolver_and_intercept_lists_pass() -> None:
    """公共解析器 / 已知拦截节点写进代码是功能需要，不是泄漏。"""
    findings = leakscan.scan_diff(
        _diff("apkscan/network/fingerprints.py", 'R = {"8.8.8.8", "223.5.5.5", "183.192.65.101"}')
    )
    assert not [f for f in findings if f.rule == "ip"]


def test_oid_arcs_are_not_mistaken_for_ipv4() -> None:
    """X.509 OID 与 IPv4 同形；不跳过则证书解析代码永远误报。"""
    findings = leakscan.scan_diff(
        _diff("apkscan/core/infra.py", 'OIDS = ("2.5.4.3", "2.5.29.17", "1.3.6.1", "1.3.101.112")')
    )
    assert not [f for f in findings if f.rule == "ip"], f"OID 被误判成 IP：{findings}"


def test_long_dotted_sequences_are_not_ipv4() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'oid = "1.3.101.112.1"'))
    assert not [f for f in findings if f.rule == "ip"]


def test_out_of_range_octets_are_not_ipv4() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'v = "999.1.2.3"'))
    assert not [f for f in findings if f.rule == "ip"]


# ---------------------------------------------------------------------------
# 判据 2：疑似密钥
# ---------------------------------------------------------------------------


def test_hardcoded_secret_is_rejected() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'api_key = "{_SECRET_VALUE}"'))
    secrets = [f for f in findings if f.rule == "secret"]
    assert secrets, "硬编码凭据必须被判为泄漏"
    assert _SECRET_VALUE not in secrets[0].value, "finding 不得回显凭据明文"
    assert leakscan.blocking(findings), "密钥判据必须阻断"


def test_jwt_bearer_value_is_rejected() -> None:
    """JWT 头虽固定，但完整 token 仍是可直接使用的 bearer credential。"""
    # 合成 token：头/载荷是 ``{"alg":"HS256"}`` / ``{"sub":"1234567890"}`` 的 base64，
    # 签名段明文即 "synthetic-signature"。字面量写出、由行内豁免声明其合成性质。
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c3ludGhldGljLXNpZ25hdHVyZQ"  # leak-scan: allow secret 判据阳性夹具，签名段明文为 synthetic-signature
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'token = "{token}"'))

    assert any(f.rule == "secret" for f in findings)
    assert leakscan.blocking(findings)


def test_environment_variable_read_is_not_a_secret() -> None:
    """读环境变量是**正确**做法，不能被自家护栏拦下。"""
    findings = leakscan.scan_diff(
        _diff("apkscan/enrichers/x.py", 'key = os.environ.get("FXAPK_FOFA_KEY", "")')
    )
    assert not [f for f in findings if f.rule == "secret"]


def test_key_in_docstring_with_wrapper_call_is_rejected() -> None:
    """裸 ``key`` + 值被一层函数包住的形态必须被拦。

    凭据不一定写成 ``api_key = "…"``：名字可能是裸 ``key``，赋值右侧也可能
    先过一层编码函数。两者叠加时判据仍须命中。
    """
    findings = leakscan.scan_diff(
        _diff("apkscan/core/x.py", f'key=UTF-8("{_SECRET_VALUE}")（32B）')
    )
    secrets = [f for f in findings if f.rule == "secret"]
    assert secrets, "docstring 里被函数包住的 key 也必须判为泄漏"
    assert _SECRET_VALUE not in secrets[0].value, "finding 不得回显凭据明文"
    assert leakscan.blocking(findings)


def test_env_reader_wrapper_exempts_but_lookalike_value_does_not() -> None:
    """豁免只认**语法位置**（值裹在环境读取调用里），不认值的长相。

    ★这条锁的是一个真被绕过的形态：曾按"全大写下划线就当变量名"放行，于是
    任何长得像变量名的硬编码值都被整类放过——扫描器无法从字符串长相分辨
    它是环境变量索引还是真凭据。判断必须落在语法位置上。
    """
    # 值在 os.environ.get(...) 里 → 是变量名，放行
    exempt = leakscan.scan_diff(
        _diff("apkscan/x.py", 'key = os.environ.get("FXAPK_FOFA_KEY", "")')
    )
    assert not [f for f in exempt if f.rule == "secret"], "从环境取值是推荐写法，不能被拦"

    # 同样长相、但是直接赋值 → 必须拦
    lookalike = leakscan.scan_diff(
        _diff("apkscan/x.py", 'key = "REAL_SECRET_VALUE_7Q9K"')  # leak-scan: allow secret 判据阳性夹具，合成串非真实凭据
    )
    assert [f for f in lookalike if f.rule == "secret"], "长得像变量名的硬编码值仍须被拦"


def test_compound_credential_names_are_covered() -> None:
    """``client_secret`` / ``private_key`` 这类**复合名**必须命中。

    下划线是正则的单词字符，靠 ``\\b`` 锚定的裸 ``secret``/``key`` 分支
    匹配不到它们——这类名字恰恰是最常见的凭据写法。
    """
    for name in ("client_secret", "auth_token", "private_key", "encryption_key"):
        line = f'{name} = "{_SECRET_VALUE}"'
        findings = leakscan.scan_diff(_diff("apkscan/x.py", line))
        assert [f for f in findings if f.rule == "secret"], f"{name} 未被覆盖"


def test_env_mention_does_not_exempt_whole_line() -> None:
    """行里提到 ``os.environ`` **不能**让整行免检——同行的硬编码凭据仍须被拦。

    放行的理由必须落在「值长什么样」上，不能落在「这行提到了 os.environ」上：
    否则一句注释就能让任何凭据免检。
    """
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", f'api_key = "{_SECRET_VALUE}"  # 迁移自 os.environ.get("X")')
    )
    assert [f for f in findings if f.rule == "secret"], "带 env 字样的行里，硬编码凭据仍须被拦"


def test_placeholder_secrets_pass() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "tests/test_x.py",
            'token = "synthetic-token-value"',
            'password = "placeholder-not-real"',
            'secret = "your-api-key-here"',
            'api_key = "aaaaaaaaaaaaaaaa"',
        )
    )
    assert not [f for f in findings if f.rule == "secret"], f"占位值被误判：{findings}"


def test_short_values_are_not_secrets() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'token = "abc123"'))
    assert not [f for f in findings if f.rule == "secret"]


# ---------------------------------------------------------------------------
# 判据 3：域名
# ---------------------------------------------------------------------------


def test_outside_domain_is_reported() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'H = "{_OUTSIDE_DOMAIN}"'))
    domains = [f for f in findings if f.rule == "domain"]
    assert domains and domains[0].value == _OUTSIDE_DOMAIN


def test_outside_domain_is_advisory_by_default_and_blocks_in_strict() -> None:
    """域名判据噪音大：默认只提示，``strict`` 才阻断。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'H = "{_OUTSIDE_DOMAIN}"'))
    assert not leakscan.blocking(findings), "域名判据默认不该阻断"
    assert leakscan.blocking(findings, strict=True), "strict 下必须阻断"


def test_reserved_and_allowlisted_domains_pass() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "tests/test_x.py",
            'a = "api.example.com"',
            'b = "gw.example.test"',
            'c = "x.invalid"',
            'd = "svc.localhost"',
        )
    )
    assert not [f for f in findings if f.rule == "domain"], f"保留域名被误判：{findings}"


def test_provider_official_domains_pass() -> None:
    """任务 1 要把富化器搬进仓库，其中的官方域必须能过自家扫描。"""
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/enrichers/multisource.py",
            '_URL = "https://stat.ripe.net/data/prefix-overview/data.json"',
            '_BASE = "https://otx.alienvault.com/api/v1/indicators"',
            '_URL = "https://urlscan.io/api/v1/search/"',
            '_URL = "https://api.abuseipdb.com/api/v2/check"',
            '_URL = "https://fofa.info/api/v1/search/all"',
            '_URL = "https://quake.360.net/api/v3/search/quake_service"',
            '_URL = "https://hunter.qianxin.com/openApi/search"',
            '_URL = "https://api.8450.cn/api/icp"',
        )
    )
    assert not [f for f in findings if f.rule == "domain"], f"提供方官方域被误判：{findings}"


def test_reverse_dns_package_names_are_not_domains() -> None:
    findings = leakscan.scan_diff(
        _diff("tests/test_x.py", 'pkg = "com.test.app"', 'other = "cn.example.demo"')
    )
    assert not [f for f in findings if f.rule == "domain"]


def test_filenames_and_attribute_access_are_not_domains() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            "logger.info('hi')",
            'name = "libjiagu.so"',
            'p = "report.json"',
            "sev = severity.info",
        )
    )
    assert not [f for f in findings if f.rule == "domain"], f"文件名/属性访问被误判：{findings}"


def test_python_domain_scans_data_tokens_not_executable_tokens(monkeypatch) -> None:
    """Python 的分界是文字 token / 代码 token，不按碰撞 TLD 猜属性含义。"""
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            f'url = "https://{_OUTSIDE_DOMAIN}/x"',
            f'other = f"https://{{host}}.{_OUTSIDE_DOMAIN}"',
            f'before = f"https://{_OUTSIDE_DOMAIN}/{{p}}"',
            f'after = f"https://{_OUTSIDE_DOMAIN}{{path}}"',
            f"# 落地在 {_OUTSIDE_DOMAIN}",
            "a = node.func.id",  # leak-scan: allow domain 判据阴性夹具，验证代码属性链不误报
            "b = ast.store",  # leak-scan: allow domain 判据阴性夹具，验证代码属性链不误报
            "c = service.space",  # leak-scan: allow domain 判据阴性夹具，验证任意 TLD 属性链不误报
            "d = product.tech",  # leak-scan: allow domain 判据阴性夹具，验证任意 TLD 属性链不误报
        )
    )
    domains = [finding.value for finding in findings if finding.rule == "domain"]
    assert domains == [_OUTSIDE_DOMAIN] * 5

    # 当前测试环境即使是 3.11，也显式模拟 3.12 的 token 流来锁住片段边界分支；
    # 否则 3.11 的整串 STRING + ``}.`` 兼容路径会让删掉该分支的突变假绿。
    source = f'other = f"https://{{host}}.{_OUTSIDE_DOMAIN}"'
    middle_type = 10_001
    left = source.index(f".{_OUTSIDE_DOMAIN}")
    right = left + len(_OUTSIDE_DOMAIN) + 1
    middle = leakscan.tokenize.TokenInfo(
        middle_type, source[left:right], (1, left), (1, right), source
    )
    monkeypatch.setattr(leakscan.token, "FSTRING_MIDDLE", middle_type, raising=False)
    monkeypatch.setattr(leakscan.tokenize, "generate_tokens", lambda _readline: iter([middle]))

    domains = [
        finding.value
        for finding in leakscan.scan_text(source, "x.py")
        if finding.rule == "domain"
    ]
    assert domains == [_OUTSIDE_DOMAIN]


def test_non_python_files_keep_line_regex_domain_detection() -> None:
    for suffix in ("md", "json", "yaml", "j2"):
        findings = leakscan.scan_diff(_diff(f"fixture.{suffix}", f'value: "{_OUTSIDE_DOMAIN}"'))
        assert [finding for finding in findings if finding.rule == "domain"], suffix


def test_python_allowlists_reserved_tlds_and_reverse_dns_still_apply() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            'allowed = "api.example.com"',
            'reserved = "backend.invalid"',
            'package = "com.test.app"',
        )
    )
    assert not [finding for finding in findings if finding.rule == "domain"]


def test_python_tokenize_failure_falls_back_to_conservative_line_scan(monkeypatch) -> None:
    """残缺 diff 无法 tokenize 时必须多报，不能把安全控制变成静默放行。"""
    def fail(_readline):
        raise IndentationError("合成 tokenizer 失败")

    monkeypatch.setattr(leakscan.tokenize, "generate_tokens", fail)
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'value = "{_OUTSIDE_DOMAIN}"'))
    assert [finding for finding in findings if finding.rule == "domain"]


def test_full_python_file_uses_precise_token_spans_on_mixed_lines() -> None:
    text = f'value = "{_OUTSIDE_DOMAIN}"; ignored = node.func.id\n# {_OUTSIDE_DOMAIN}\n'  # leak-scan: allow domain 判据阴性夹具，同行属性链只用于验证 token 精确跨度
    domains = [finding.value for finding in leakscan.scan_text(text, "x.py") if finding.rule == "domain"]
    assert domains == [_OUTSIDE_DOMAIN, _OUTSIDE_DOMAIN]


def test_diff_worktree_mapping_handles_multiline_string_and_code(tmp_path: Path) -> None:
    """完整文件映射不能把多行字符串正文误当代码；普通属性链仍不判。"""
    package = tmp_path / "apkscan"
    package.mkdir()
    source = f'"""\n{_OUTSIDE_DOMAIN}\n"""\nvalue = node.func.id\n'  # leak-scan: allow domain 判据阴性夹具，验证完整文件 token 映射
    (package / "x.py").write_text(source, encoding="utf-8", newline="\n")
    diff = (
        "--- /dev/null\n+++ b/apkscan/x.py\n@@ -0,0 +1,4 @@\n"
        + "".join(f"+{line}\n" for line in source.splitlines())
    )
    domains = [
        finding.value
        for finding in leakscan.scan_diff(diff, source_root=tmp_path)
        if finding.rule == "domain"
    ]
    assert domains == [_OUTSIDE_DOMAIN]


def test_diff_worktree_mismatch_falls_back_conservatively(tmp_path: Path) -> None:
    """工作树不是 diff 对应版本时不得套用错位掩码并静默放行。"""
    (tmp_path / "x.py").write_text("value = node.func.id\n", encoding="utf-8")  # leak-scan: allow domain 判据阴性夹具，构造与 diff 错位的工作树
    findings = leakscan.scan_diff(
        _diff("x.py", f'value = "{_OUTSIDE_DOMAIN}"'), source_root=tmp_path
    )
    assert [finding for finding in findings if finding.rule == "domain"]


# ---------------------------------------------------------------------------
# 判据 4：语境框架词
# ---------------------------------------------------------------------------


def test_context_terms_are_reported() -> None:
    line = "本工具用于协助" + _CONTEXT_A + "人员分析" + _CONTEXT_B + "样本"
    findings = leakscan.scan_diff(_diff("README.md", line))
    context = [f for f in findings if f.rule == "context"]
    assert {f.value for f in context} >= {_CONTEXT_A, _CONTEXT_B}


def test_context_terms_are_advisory_by_default() -> None:
    findings = leakscan.scan_diff(_diff("README.md", _CONTEXT_B))
    assert not leakscan.blocking(findings)
    assert leakscan.blocking(findings, strict=True)


def test_neutral_technical_text_passes() -> None:
    findings = leakscan.scan_diff(
        _diff("README.md", "静态分析 APK 的端点与配置键值，产出结构化线索。")
    )
    assert not findings, f"纯技术描述被误判：{findings}"


# ---------------------------------------------------------------------------
# 判据 5：中文人名（「姓名 + 案」）
# ---------------------------------------------------------------------------


def test_person_name_with_case_marker_is_rejected() -> None:
    """★这是本判据的起因：探针注释里的「对应<真名>案：<QQ 号>」曾整条漏过。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.js", f"// 对应{_CASE_NAME}：登录明文触发"))
    names = [f for f in findings if f.rule == "person_name"]
    assert names, "「姓名 + 案」必须被判为泄漏"
    assert leakscan.blocking(findings), "person_name 判据必须默认阻断"


def test_person_name_finding_does_not_echo_the_name() -> None:
    """★脱敏：公开仓库的 CI 日志同样公开，把真名打进 Actions 输出＝换个地方泄漏。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.js", f"// 见{_CASE_NAME}"))
    names = [f for f in findings if f.rule == "person_name"]
    assert names
    assert _CASE_NAME[:-1] not in names[0].value, f"finding 值回显了姓名：{names[0].value}"
    assert names[0].value == "<中文姓名 2 字>案"


def test_cross_word_boundary_coincidences_are_not_person_names() -> None:
    """★汉语没有词边界，姓氏字大量兼任虚词——这是本判据唯一的误报来源。

    「用**于串案**索引」会被读成 于(姓)+串+案，「当**成并案**依据」读成 成(姓)+并+案。
    这几行都是本仓真实存在的技术文字，全树实测的误报**全部**是这一形态。
    """
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            f"# {_NOT_A_CASE_NAME}的域名规范化",
            "# 会被当成并案依据的写法",
            "# 报告阶段的逐案事实",
            "# 本案的解决方案与应急预案已归档",
            "# 该案由专案组按立案标准处理，涉案金额见结案报告",
            "# 关联案件与同类案件另行归档",
        )
    )
    assert not [f for f in findings if f.rule == "person_name"], (
        f"跨词边界的巧合被误判成人名：{findings}"
    )


def test_case_compound_words_are_not_person_names() -> None:
    """「案」后紧跟 例/卷/由… 时「案X」自身是普通词，不判（有意的漏报，见模块文档）。"""
    findings = leakscan.scan_diff(_diff("README.md", "石墨文档案例库与档案卷宗管理"))
    assert not [f for f in findings if f.rule == "person_name"]


def test_name_plus_case_file_is_not_a_bypass() -> None:
    """★「<真名>案件」必须照样命中——只挡「<真名>案」等于留了一条改措辞就能绕的缝。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.js", f"// 见{_CASE_NAME}件的样本"))
    assert [f for f in findings if f.rule == "person_name"], (
        f"「姓名 + 案件」是自然写法，必须与「姓名 + 案」同等对待：{findings}"
    )


def test_case_file_phrasing_does_not_reintroduce_false_positives() -> None:
    """★放开「案件」后走的是**全字**检查，技术文本里的高频巧合必须仍被挡住。

    这几行都是本仓真实存在的句子：「当**成当前案件**证据」会被读成 成+当前+案件，
    「不是任何**真实案件**的值」读成 何+真实+案件——姓名候选里带虚词字即弃。
    """
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            "# 不能静默当成当前案件直接证据",
            "# 钱包内容校验不能替代它属于当前案件",
            "# 只能把整机流量里的背景连接当案件线索",
            "# 样本包名是案件值，不进公开仓库",
            "# 合成常量，不是任何真实案件的值",
        )
    )
    assert not [f for f in findings if f.rule == "person_name"], (
        f"「案件」形态的全字检查没挡住技术文本巧合：{findings}"
    )


def test_names_ending_in_ambiguous_chars_are_still_caught() -> None:
    """★末字黑名单收窄的回归锁：这些字能作人名末字，收进黑名单就是确定性漏报。

    曾把 成 / 民 / 新 / 真 收进表里（为了挡"成案""新案"这类词），代价是名字以这几个字
    收尾的人整类查不出来，而实测表明多收它们换不来任何误报收益。

    下面的姓名全是**占位名**（判据有意不识别占位——真人也可能就叫这个），扫描器会照常
    命中，故该行按本仓纪律用带理由的行内豁免声明，而不是拼接绕过。
    """
    for name_with_case in ("李成案", "王民案", "刘新案", "李真案", "甄子丹案"):  # leak-scan: allow 末字歧义回归夹具，五个占位姓名非案件当事人
        findings = leakscan.scan_diff(_diff("apkscan/x.js", f"// 对应{name_with_case}"))
        assert [f for f in findings if f.rule == "person_name"], (
            f"{name_with_case} 未命中——末字黑名单收得太宽会造成确定性漏报"
        )


# ---------------------------------------------------------------------------
# 判据 6：联系方式（QQ / 微信 / Telegram）
# ---------------------------------------------------------------------------


def test_qq_and_wxid_are_rejected() -> None:
    findings = leakscan.scan_diff(
        _diff("apkscan/x.js", f"// {_QQ_TEXT}", f"// {_WXID_TEXT}")
    )
    contacts = [f for f in findings if f.rule == "contact"]
    assert len(contacts) == 2, f"QQ 与 wxid_ 两种形态都必须命中：{findings}"
    assert leakscan.blocking(findings), "contact 判据必须默认阻断"


def test_contact_finding_does_not_echo_the_account() -> None:
    """★同样脱敏：只报形态与长度，账号本身由人打开文件看。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.js", f"// {_QQ_TEXT}"))
    contacts = [f for f in findings if f.rule == "contact"]
    assert contacts
    assert "123456" not in contacts[0].value, f"finding 值回显了账号：{contacts[0].value}"
    assert contacts[0].value.startswith("qq=<")


def test_wechat_sdk_identifiers_are_not_contacts() -> None:
    """``weixinJSBridge`` 这类 SDK 标识符不是联系方式——规则表的 blacklist 必须生效。

    这条误报是 ``rules/contacts.yaml`` 早就踩过并写下结论的，护栏复用那份判断而不是
    另写一套，正是为了不把同一个坑再踩一遍。
    """
    findings = leakscan.scan_diff(
        _diff("apkscan/x.js", "if (window.weixinJSBridge) { wechat_sdk.init(); }")
    )
    assert not [f for f in findings if f.rule == "contact"], f"SDK 标识符被误判：{findings}"


def test_bare_digits_without_a_platform_cue_are_not_contacts() -> None:
    """没有平台触发词的裸数字不判——手机号那类误报正是这么来的（见规则表注释）。"""
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", 'TIMEOUT_MS = 123456', 'BUILD = "20260822"')
    )
    assert not [f for f in findings if f.rule == "contact"], f"裸数字被误判：{findings}"


def test_contact_patterns_really_come_from_the_rules_file() -> None:
    """★判据形态取自 ``rules/contacts.yaml``——复用而非另立一份，否则两份必然漂移。

    断言的是**正则源串逐条相等**，不是"四个 kind 都在"：后者硬编码一份同名清单也能过，
    那样接线断了测试照样绿。
    """
    from apkscan.core.registry import load_rules

    data = load_rules("contacts")
    assert isinstance(data, dict)
    expected: set[tuple[str, str]] = {
        (str(entry["kind"]), str(pattern))
        for entry in data.get("types", [])
        if isinstance(entry, dict)
        and entry.get("kind") in {"qq", "wechat", "telegram", "telegram_bot"}
        for pattern in entry.get("patterns") or []
    }
    assert expected, "规则表里读不到联系方式形态，本测试失去意义"
    actual = {(kind, pattern.pattern) for kind, pattern, _black in leakscan._CONTACT_PATTERNS}
    assert expected <= actual, (
        f"规则表里的形态没有全部接进护栏，缺：{expected - actual}"
    )


def test_contact_falls_back_when_the_rules_file_is_unreadable(monkeypatch) -> None:
    """★规则表读不到时**不许**退化成空判据。

    其余"读不到规则就退化"的地方（如占位 IP 名单）退化方向是多报，安全；contact 退化成
    空集却是**漏报**——正是本判据要防的事。故必须有内置兜底。
    """
    import apkscan.core.registry as registry

    monkeypatch.setattr(registry, "load_rules", lambda name: (_ for _ in ()).throw(OSError("boom")))
    patterns = leakscan._contact_patterns()
    assert patterns, "读不到规则表时护栏不得整个消失"
    kinds = {kind for kind, _p, _b in patterns}
    assert kinds == {"qq", "wechat"}, f"兜底集应刻意窄于规则表：{kinds}"


def test_contact_fallback_is_merged_per_kind(monkeypatch) -> None:
    """★规则表**仍可解析、但少了某一类**时也要补兜底。

    这是个静默失效的形态：YAML 照常解析、其余判据照常工作，只有被删掉的那一类判据
    悄悄消失。护栏不允许存在"看起来在跑、实际少了一条"的状态。
    """
    import apkscan.core.registry as registry

    def _only_telegram(name: str) -> dict:
        assert name == "contacts"
        return {"types": [{"kind": "telegram", "patterns": [r"t\.me/(\w+)"], "blacklist": []}]}

    monkeypatch.setattr(registry, "load_rules", _only_telegram)
    kinds = {kind for kind, _p, _b in leakscan._contact_patterns()}
    assert kinds == {"telegram", "qq", "wechat"}, (
        f"规则表缺 qq/wechat 时必须按 kind 补回兜底，实际：{kinds}"
    )


# ---------------------------------------------------------------------------
# 判据 7：二开 / 改包样本包名
# ---------------------------------------------------------------------------


def test_opaque_repack_package_is_rejected() -> None:
    findings = leakscan.scan_diff(_diff("apkscan/x.py", f'PKG = "{_REPACK_PACKAGE}"'))
    packages = [f for f in findings if f.rule == "package"]
    assert packages, f"含随机化段的包名必须被判为泄漏：{findings}"
    assert leakscan.blocking(findings), "package 判据必须默认阻断"
    assert "zxcvbnmqwr" not in packages[0].value, f"finding 值回显了包名：{packages[0].value}"
    assert packages[0].value == "im.<10 字符不透明段>.messenger"


def test_open_source_and_framework_packages_pass() -> None:
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            f'UPSTREAM = "{_STOCK_PACKAGE}"',
            'FRAMEWORK = "com.android.providers.settings"',
            'ANDROIDX = "androidx.core.app"',
            'XMPP = "org.jivesoftware.smack"',
            'CIPHER = "net.sqlcipher.database"',
        )
    )
    assert not [f for f in findings if f.rule == "package"], f"公开库包名被误判：{findings}"


def test_packages_registered_in_the_rules_files_pass() -> None:
    """★白名单复用 ``rules/bank_packages.yaml`` + ``rules/sdks.yaml``。

    这样往规则表新增一个银行包名时，扫的是工作树里的当前文件，白名单跟着那一行一起生效，
    不会因为新包名撞上辅音串启发而把 PR 门禁卡红。

    取的是**规则表里当前真正会触发启发的那些包名**，不是硬编码一个——硬编码的话，
    白名单接线断了（``_KNOWN_PACKAGES`` 变空）本条也能靠改判据蒙混过去。
    """
    assert leakscan._KNOWN_PACKAGES, "规则表里的已知第三方包名一个都没读到"
    would_fire = [
        package for package in sorted(leakscan._KNOWN_PACKAGES)
        if any(leakscan._is_opaque_segment(label) for label in package.split("."))
        and package.split(".")[0] in leakscan.PACKAGE_HEADS
    ]
    assert would_fire, "规则表里没有会触发辅音串启发的包名，本测试失去意义"
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", *[f'PKG = "{package}"' for package in would_fire])
    )
    assert not [f for f in findings if f.rule == "package"], (
        f"规则表登记的公开包名被误判（白名单接线断了？）：{findings}"
    )


def test_rules_whitelist_does_not_fold_case() -> None:
    """★白名单不得折叠大小写——那是一条真实的绕过路径。

    ``_PACKAGE_RE`` 只匹配小写包名。若白名单把 YAML 里的 ``IM.ZXCVBNMQWR.MESSENGER``
    折成小写收进来，那一行 YAML 自己因为是大写**不会**被判据命中，却给源码里的小写同名
    包名开了一张免检票——一次改动就能让任意包名免检。不折叠后，想加白名单就必须在规则表
    里写小写包名，而那一行会被判据自己命中，形成闭环。
    """
    import apkscan.core.registry as registry

    def _uppercased(name: str) -> dict:
        if name == "bank_packages":
            return {"packages": {"IM.ZXCVBNMQWR.MESSENGER": "伪造项"}}
        return {"sdks": []}

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(registry, "load_rules", _uppercased)
        known = leakscan._known_packages()
    assert known == frozenset(), f"非小写规则项不得进白名单：{known}"


def test_legitimate_mixed_case_package_names_are_harmless() -> None:
    """★不折叠大小写的副作用检查：规则表里确有合法的大写包名，被排除必须无害。

    ``com.bankcomm.Bankcomm`` 这类（Android 包名允许大写）不进白名单，但它们本来就不在
    ``_PACKAGE_RE`` 的匹配面内（该正则只认小写），故排除它们不会产生任何 finding。
    """
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            'BANK = "com.bankcomm.Bankcomm"',
            'PAY = "com.eg.android.AlipayGphone"',
        )
    )
    assert not [f for f in findings if f.rule == "package"], (
        f"合法的大写包名被排除后产生了误报：{findings}"
    )


def test_python_module_paths_are_not_packages() -> None:
    """Python 模块路径与属性链同形；不排除则整片误报（全树实测 15 处）。"""
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            f"# 见 {_MODULE_PATH} 的实现",
            "spec = importlib.util.find_spec(name)",
            'monkeypatch.setattr("apkscan.config.fetch.fetch_config_object", rec)',
        )
    )
    assert not [f for f in findings if f.rule == "package"], f"模块路径被误判成包名：{findings}"


def test_package_rule_ignores_domain_shaped_values() -> None:
    """末段是 TLD ⇒ 那是域名，归 ``domain`` 判据管，两条判据不重复报。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'HOST = "im.zxcvbnmqwr.com"'))  # leak-scan: allow 验证 domain 判据接手用的合成未注册域名
    assert not [f for f in findings if f.rule == "package"]
    assert [f for f in findings if f.rule == "domain"], "域名形态应由 domain 判据接手"


def test_opaque_segment_thresholds_are_the_measured_ones() -> None:
    """★两个阈值是全树实测定出来的，不是估的——改动前请重跑那一轮实测。

    门槛取 4 会命中 ``sqlcipher`` / ``tendcloud`` 这类真实库名（全树 107 处），
    取 6 则漏掉 ``rightkinghts`` 这类目标形态（其最长辅音串正好 5）。
    """
    assert leakscan.OPAQUE_SEGMENT_MIN_LEN == 8
    assert leakscan.OPAQUE_SEGMENT_MIN_CONSONANT_RUN == 5
    assert leakscan._max_consonant_run("zxcvbnmqwr") == 10
    assert leakscan._max_consonant_run("sqlcipher") == 4  # 真实库名，必须落在门槛外
    assert leakscan._is_opaque_segment("zxcvbnmqwr")
    assert not leakscan._is_opaque_segment("messenger")
    assert not leakscan._is_opaque_segment("telegram")


def test_opaque_segment_accepts_digits_but_not_pure_numbers() -> None:
    """★随机化的包名段常混数字；只认纯字母等于留了"加个数字就绕过"的缝。"""
    assert leakscan._is_opaque_segment("zxcvbnm123"), "带数字的随机段必须仍算不透明"
    assert not leakscan._is_opaque_segment("20260822"), "纯数字是版本号/序号，不是名字"
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'PKG = "im.zxcvbnm123.messenger"'))  # leak-scan: allow package 判据阳性夹具，合成随机段包名
    assert [f for f in findings if f.rule == "package"], f"数字段绕过没堵住：{findings}"


def test_two_segment_package_is_covered() -> None:
    """★``im.<随机段>`` 这种两段包名也要认——只扫 ≥3 段等于留一条去掉一段就绕过的缝。"""
    findings = leakscan.scan_diff(_diff("apkscan/x.py", 'PKG = "im.zxcvbnmqwr"'))  # leak-scan: allow package 判据阳性夹具，合成两段随机包名
    assert [f for f in findings if f.rule == "package"], f"两段包名漏扫：{findings}"


def test_y_counts_as_a_vowel_and_that_is_a_measured_tradeoff() -> None:
    """★``y`` 算元音是**实测过的取舍**，不是疏忽——本条把这个决定连同理由一起锁住。

    把 y 也算辅音能堵住"插 y 稀释辅音串"的绕过，代价实测是全树 38 处误报，其中 37 处是
    本仓标准合成包名 ``com.example.synthetic``（y 算辅音时 ``synth`` 连成 5 连辅音）、
    另一处是 AOSP 的 ``com.android.org.conscrypt``。护栏防的是**无意**写入，不防主动规避
    （主动规避有行内豁免这条正门），故不拿 38 处误报换那一条路径。
    """
    assert "y" in leakscan._PSEUDO_VOWELS
    # 这两个真实名字必须落在门槛外——它们正是 y 算辅音时会炸出来的那 38 处。
    assert not leakscan._is_opaque_segment("synthetic")
    assert not leakscan._is_opaque_segment("conscrypt")
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", 'PKG = "com.example.synthetic"', 'AOSP = "com.android.org.conscrypt"')
    )
    assert not [f for f in findings if f.rule == "package"], f"y 口径变了会炸出误报：{findings}"


def test_transliterated_library_names_are_not_packages() -> None:
    """非英语来源（拼音 / 音译）的库名不得误报——它们是新增 SDK 的常见形态。"""
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            'A = "com.zhangshangyinhang.mobile"',
            'B = "cn.gongxiangdanche.app"',
            'C = "com.kuaishouspeed.player"',
            'D = "org.freedesktop.gstreamer"',
        )
    )
    assert not [f for f in findings if f.rule == "package"], f"音译库名被误判：{findings}"


# ---------------------------------------------------------------------------
# 豁免机制
# ---------------------------------------------------------------------------


def test_exemption_with_reason_allows_the_line() -> None:
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", f'HOST = "{_PUBLIC_IPV4}"  # leak-scan: allow 公共解析器名单')
    )
    assert not findings, f"带理由的豁免必须放行：{findings}"


def test_exemption_without_reason_is_itself_a_blocking_finding() -> None:
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", f'HOST = "{_PUBLIC_IPV4}"  # leak-scan: allow')
    )
    assert _rules(findings) == {"exemption"}, "无理由豁免应产 exemption finding"
    assert leakscan.blocking(findings), "无理由豁免必须阻断（护栏自身的完整性检查）"


# ---------------------------------------------------------------------------
# diff 解析
# ---------------------------------------------------------------------------


def test_only_added_lines_are_scanned() -> None:
    """删除行与上下文行不扫——仓库既有内容不该被本护栏追溯审判。"""
    diff = (
        "--- a/apkscan/x.py\n"
        "+++ b/apkscan/x.py\n"
        "@@ -1,3 +1,3 @@\n"
        f'-OLD = "{_PUBLIC_IPV4}"\n'
        f' CTX = "{_PUBLIC_IPV4}"\n'
        f'+NEW = "{_DOC_IP}"\n'
    )
    assert not leakscan.scan_diff(diff)


def test_added_line_numbers_track_the_new_file_side() -> None:
    diff = (
        "--- a/apkscan/x.py\n"
        "+++ b/apkscan/x.py\n"
        "@@ -10,4 +20,5 @@\n"
        " ctx1\n"
        "-removed\n"
        " ctx2\n"
        f'+HOST = "{_PUBLIC_IPV4}"\n'
    )
    findings = [f for f in leakscan.scan_diff(diff) if f.rule == "ip"]
    assert findings and findings[0].line_no == 22, f"行号应为 22，实际 {findings}"
    assert findings[0].path == "apkscan/x.py"


def test_binary_and_asset_paths_are_skipped() -> None:
    diff = _diff("tests/synthetic/blob.pcap", f"garbage {_PUBLIC_IPV4} bytes")
    assert not leakscan.scan_diff(diff)


def test_multiple_files_in_one_diff_are_attributed_correctly() -> None:
    diff = (
        _diff("apkscan/a.py", f'A = "{_DOC_IP}"')
        + _diff("apkscan/b.py", f'B = "{_PUBLIC_IPV4}"')
    )
    findings = [f for f in leakscan.scan_diff(diff) if f.rule == "ip"]
    assert [f.path for f in findings] == ["apkscan/b.py"]


def test_empty_diff_yields_nothing() -> None:
    assert leakscan.scan_diff("") == []
    assert leakscan.iter_added_lines("") == []


# ---------------------------------------------------------------------------
# 报告与全树审计
# ---------------------------------------------------------------------------


def test_format_findings_is_stable_and_marks_blocking() -> None:
    findings = leakscan.scan_diff(
        _diff("apkscan/x.py", f'H = "{_PUBLIC_IPV4}"', f'D = "{_OUTSIDE_DOMAIN}"')
    )
    text = leakscan.format_findings(findings)
    assert text == leakscan.format_findings(findings), "输出必须确定"
    assert "[阻断]" in text and "[提示]" in text
    assert "leak-scan: allow" in text, "报告须告知豁免办法"


def test_format_findings_empty() -> None:
    assert "未发现" in leakscan.format_findings([])


def test_scan_paths_reads_files(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text(f'HOST = "{_PUBLIC_IPV4}"\n', encoding="utf-8")
    findings = leakscan.scan_paths([target])
    assert [f.rule for f in findings] == ["ip"]
    assert findings[0].line_no == 1


def test_scan_paths_tolerates_missing_files(tmp_path: Path) -> None:
    assert leakscan.scan_paths([tmp_path / "nope.py"]) == []


def test_scan_text_respects_first_line_offset() -> None:
    findings = leakscan.scan_text(f'H = "{_PUBLIC_IPV4}"', path="x.py", first_line=100)
    assert findings and findings[0].line_no == 100


# ---------------------------------------------------------------------------
# 判据契约（防漂移）
# ---------------------------------------------------------------------------


def test_blocking_rules_are_the_precise_ones() -> None:
    """精确判据阻断、噪音判据只提示——这个分档是有意的，改动须同时改文档。

    ``exemption`` 与 ``bulk_exemption`` 是护栏**自身**的完整性检查（前者查"豁免没写理由"，
    后者查"同一条理由被复制到大量新增行"），两条都恒阻断：允许静默削弱护栏的护栏等于没有。

    ``person_name`` / ``contact`` / ``package`` 三条案件值判据同样默认阻断。它们落到默认档
    的前提是"误报可控"，而这是**实测**过的（全树 528 个文件上前两者各 0 条、contact 只命中
    ``tests/`` 里的合成夹具）——改判据参数前请重跑那一轮实测，别只改这条断言。
    """
    assert leakscan.BLOCKING_RULES == frozenset({
        "ip", "secret", "person_name", "contact", "package", "exemption", "bulk_exemption",
    })
    assert set(leakscan.RULES) == {
        "ip", "secret", "domain", "context", "person_name", "contact", "package",
        "exemption", "bulk_exemption",
    }
    # domain / context 仍只提示：它们对全树噪音太大，靠 PR diff 关的 strict 档兜住。
    assert not (leakscan.BLOCKING_RULES & {"domain", "context"})


def test_reserved_doc_networks_are_documented() -> None:
    assert "192.0.2.0/24" in leakscan.RESERVED_DOC_NETWORKS
    assert "2001:db8::/32" in leakscan.RESERVED_DOC_NETWORKS


# ---------------------------------------------------------------------------
# 护栏的自审：本文件自己必须过得了 strict 扫描，且豁免不得弱化判据
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()


def test_this_test_file_itself_passes_strict_scan() -> None:
    """★本文件自身在 **strict** 档下必须零 finding。

    阳性夹具是完整字面量（IP / 域名 / 凭据形态都在源码里），故本文件天然是扫描器的
    "重灾区"。它必须靠**带理由的行内豁免**过关，而不是靠拼接隐写——一旦有人把夹具改回
    ``".".join(...)`` 那种绕过写法，或删掉豁免理由，本条立刻变红。

    用 strict 档而非默认档：默认档不阻断 ``domain`` / ``context``，会让域名与语境词夹具
    的豁免缺失蒙混过关。
    """
    findings = leakscan.scan_paths([_THIS_FILE])
    assert findings == [], (
        "本测试文件自身未通过 strict 泄漏扫描（阳性夹具须用带理由的行内豁免声明）：\n"
        + leakscan.format_findings(findings)
    )


def test_doc_addresses_helper_passes_strict_scan() -> None:
    """``tests/doc_addresses.py`` 同样必须零 finding：它是"夹具该怎么写"的样板。"""
    helper = _THIS_FILE.parent / "doc_addresses.py"
    findings = leakscan.scan_paths([helper])
    assert findings == [], leakscan.format_findings(findings)


def test_positive_fixtures_still_fire_without_any_exemption() -> None:
    """★豁免只声明"这个常量是合成的"，**没有**弱化判据本身。

    证明方式：把四个阳性夹具值放进**不带**任何豁免注释的 diff 行，四条判据必须全部命中。
    若有人为了让上面那条自审测试变绿而去削弱判据（放宽 anycast 段、把合成域名加进允许
    清单、给随机串加占位标记），本条会立刻变红——两条测试互为对角，不能同时靠"改判据"满足。
    """
    findings = leakscan.scan_diff(
        _diff(
            "apkscan/x.py",
            f'ipv4 = "{_PUBLIC_IPV4}"',
            f'ipv6 = "{_PUBLIC_IPV6}"',
            f'host = "{_OUTSIDE_DOMAIN}"',
            f'api_key = "{_SECRET_VALUE}"',
            f'case = "{_CASE_NAME}"',
            f'qq = "{_QQ_TEXT}"',
            f'wx = "{_WXID_TEXT}"',
            f'pkg = "{_REPACK_PACKAGE}"',
        )
    )
    assert _rules(findings) == {
        "ip", "secret", "domain", "person_name", "contact", "package",
    }, f"阳性夹具在无豁免行上必须照常命中，实际：{findings}"
    # 两个 IP 夹具都要各自命中，不能只中一个。
    assert {f.value for f in findings if f.rule == "ip"} == {_PUBLIC_IPV4, _PUBLIC_IPV6}
    # 两条 contact 夹具（QQ / wxid_）也各自命中。
    assert len([f for f in findings if f.rule == "contact"]) == 2
    assert leakscan.blocking(findings), "ip / secret / 案件值三条判据必须阻断"


def test_no_split_join_evasion_templates_in_this_file() -> None:
    """★源码里不得再出现"按片段拼装地址/凭据"的绕过模板。

    判据故意写得直白：夹具区（模块顶部到第一个 ``def``）内不允许出现 ``".".join`` /
    ``":".join`` / ``"".join`` 这类拼装调用。文档段里作为**反面例子**引用的那一处
    在三引号注释内，故按行判定时需排除文档字符串——这里取巧的办法是只看赋值语句行。
    """
    source = _THIS_FILE.read_text(encoding="utf-8")
    fixture_region = source.split("\ndef ", 1)[0]
    offending = [
        line.strip()
        for line in fixture_region.splitlines()
        # 只看常量赋值行（``_NAME = ...``），从而排开模块文档里的反面例子。
        if line.startswith("_") and "=" in line and ".join(" in line
    ]
    assert offending == [], f"夹具不得用拼接绕过扫描器：{offending}"


# ---------------------------------------------------------------------------
# 全树门禁：跟踪的 apkscan/ + tests/ 默认阻断恒为 0
# ---------------------------------------------------------------------------

_REPO_ROOT = _THIS_FILE.parent.parent


def test_tracked_apkscan_and_tests_have_zero_default_blocking() -> None:
    """★git 跟踪的 ``apkscan/`` + ``tests/`` 默认阻断项必须恒为 **0**。

    为什么这条测试非有不可：PR diff 判据只看**新增行**，故合并前已存在的阻断项会被永久
    grandfather —— 清理干净的树，只要有人改一条既有行把公网字面写回去，diff 关未必看得见
    （改的是既有行的相邻内容时）。这一关对全树施压，把"清理"变成"不可回退的状态"。

    只压**默认**阻断档（``ip`` / ``secret`` / ``exemption`` 三条精确判据）：
    ``domain`` / ``context`` 噪音大（合成域名、``logger.info``、中文说明文字都会撞），
    对全树按 strict 施压会产生数千条误报，误报多了人就习惯性加豁免、护栏随之失效。
    PR diff 关仍按 strict 跑，两关**互补**。

    枚举失败（无 git / ls-files 报错）时 ``errors`` 非空 → 本条红。这是有意的：
    "枚举不到"绝不允许与"全树干净"同形。
    """
    errors: list[str] = []
    targets = leakscan.tracked_files(["apkscan", "tests"], repo_root=_REPO_ROOT, errors=errors)
    assert errors == [], f"枚举已跟踪文件失败，拒绝给出「干净」结论：{errors}"
    assert len(targets) > 100, f"只枚举到 {len(targets)} 个跟踪文件，疑似枚举口径坏了"

    scan_errors: list[str] = []
    findings = leakscan.scan_paths(targets, scan_errors)
    assert scan_errors == [], f"读取待扫文件失败：{scan_errors}"
    blocking = leakscan.blocking(findings)
    assert blocking == [], (
        "跟踪的 apkscan/ + tests/ 默认阻断项必须为 0（夹具改用 RFC5737/RFC3849，"
        "确属功能需要的常量用带具体理由的行内豁免）：\n"
        + leakscan.format_findings(blocking)
    )


def test_tracked_files_reports_error_for_unknown_root() -> None:
    """枚举不到任何跟踪文件时必须**如实报错**，不得返回空列表冒充干净。"""
    errors: list[str] = []
    assert leakscan.tracked_files(["no_such_dir_xyz"], repo_root=_REPO_ROOT, errors=errors) == []
    assert errors, "枚举不到跟踪文件必须写入 errors"


def test_tracked_files_all_valid_roots_report_no_error() -> None:
    """全部 root 有效 → 无错误、两棵树的文件都在（确定性排序）。"""
    errors: list[str] = []
    targets = leakscan.tracked_files(["apkscan", "tests"], repo_root=_REPO_ROOT, errors=errors)
    assert errors == []
    assert targets == sorted(targets), "输出必须确定性排序"
    assert len(targets) == len(set(targets)), "不得有重复项"
    rels = {p.relative_to(_REPO_ROOT).as_posix() for p in targets}
    assert any(r.startswith("apkscan/") for r in rels)
    assert any(r.startswith("tests/") for r in rels)


def test_tracked_files_mixed_valid_and_missing_root_is_an_error() -> None:
    """★一个有效 root + 一个缺失 root：**必须**报错，不得被有效 root 的结果掩盖。

    这曾是个假绿：``git ls-files -- apkscan typo_xyz`` 一次查询返回 apkscan 的两百个
    文件、退出码 0、``errors`` 为空 —— 门禁于是在漏扫一整棵树的前提下报绿。现在每个
    root 独立验证，缺失的那个自己记一条错误。
    """
    errors: list[str] = []
    targets = leakscan.tracked_files(
        ["apkscan", "definitely_missing_tree_xyz"], repo_root=_REPO_ROOT, errors=errors
    )
    assert errors, "缺失 root 必须记入 errors，不能被有效 root 掩盖"
    assert any("definitely_missing_tree_xyz" in e for e in errors), errors
    # 有效 root 的结果照常返回（调用方负责按 errors 变红），但"扫到了东西"不等于"扫全了"。
    assert targets, "有效 root 的文件仍应返回"


def test_cli_tracked_mode_with_one_missing_root_exits_two() -> None:
    """CLI 侧：有效 root + 缺失 root 必须 exit 2，且不得输出"未发现"横幅。"""
    result = _run_cli(
        "--tracked", "--path", "apkscan", "--path", "definitely_missing_tree_xyz"
    )
    assert result.exit_code == 2, f"混合 root 必须 exit 2，实际 {result.exit_code}：{result.output}"
    assert "leak-scan: 未发现泄漏嫌疑" not in result.output
    assert "definitely_missing_tree_xyz" in result.output


# ---------------------------------------------------------------------------
# CLI 门禁行为：目录有违规必须红、路径不存在必须红、空匹配必须红
# ---------------------------------------------------------------------------


def _run_cli(*argv: str):
    from typer.testing import CliRunner

    from apkscan import cli

    return CliRunner().invoke(cli.app, ["leak-scan", *argv])


def test_cli_path_mode_recurses_into_directories_and_blocks(tmp_path: Path) -> None:
    """★``--path <目录>`` 必须**递归展开**并对目录内的违规值变红。

    这曾是个**假绿门禁**：目录被当成"读不动的文件"静默跳过，命令输出"未发现泄漏嫌疑"
    + exit 0 —— 看起来全树干净，实际一个文件都没扫。
    """
    nested = tmp_path / "pkg" / "sub"
    nested.mkdir(parents=True)
    (nested / "leaky.py").write_text(f'HOST = "{_PUBLIC_IPV4}"\n', encoding="utf-8")

    result = _run_cli("--path", str(tmp_path))
    assert result.exit_code == 1, f"目录内有阻断项必须 exit 1，实际 {result.exit_code}：{result.output}"
    assert "已扫描" in result.output, "必须如实报告扫了多少个文件"
    assert _PUBLIC_IPV4 in result.output


def test_cli_path_mode_is_green_only_when_really_clean(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(f'DOC = "{_DOC_IP}"\n', encoding="utf-8")
    result = _run_cli("--path", str(tmp_path))
    assert result.exit_code == 0, result.output


def test_cli_missing_path_exits_two_not_green(tmp_path: Path) -> None:
    """路径不存在 → exit 2。"少扫了"绝不与"扫全了"同形。"""
    result = _run_cli("--path", str(tmp_path / "nope"))
    assert result.exit_code == 2, f"路径不存在必须 exit 2，实际 {result.exit_code}：{result.output}"
    # 断言的是**结论横幅**不得出现（"拒绝给出「未发现」结论"这句拒答文案本身含该词，
    # 故不能只判子串），并要求错误里点明是哪条路径没扫到。
    assert "leak-scan: 未发现泄漏嫌疑" not in result.output
    assert "输入路径不存在" in result.output


def test_cli_empty_match_exits_two(tmp_path: Path) -> None:
    """一个待扫文件都枚举不到 → exit 2，不许输出"未发现"后返回 0。"""
    empty = tmp_path / "empty"
    empty.mkdir()
    result = _run_cli("--path", str(empty))
    assert result.exit_code == 2, f"空匹配必须 exit 2，实际 {result.exit_code}：{result.output}"


def test_cli_tracked_mode_requires_a_path() -> None:
    assert _run_cli("--tracked").exit_code == 2


def test_cli_tracked_mode_on_this_repo_is_green() -> None:
    """★与 CI 全树门禁同一条命令：跟踪的 apkscan/ + tests/ 必须 exit 0。"""
    result = _run_cli("--tracked", "--path", "apkscan", "--path", "tests")
    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# CI 接线：两关的**命令行本身**必须带对档位（断言解析出的 run 脚本，不是注释）
# ---------------------------------------------------------------------------


def _ci_leak_scan_run_scripts() -> "dict[str, str]":
    """从 ci.yml 解析出两个 leak-scan job 的 run 脚本正文。

    ★为什么解析 YAML 而不是 grep 整份文件：注释里写着"diff 关按 strict 跑"而命令行
    实际没有 ``--strict``，是这轮审查抓到的真实缺口。只 grep ``--strict`` 会被那句
    注释满足、测试照绿。故必须断言**被执行的 run 字符串**。
    """
    import yaml

    workflow = yaml.safe_load((_REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    scripts: dict[str, str] = {}
    for job_id, job in workflow["jobs"].items():
        if not job_id.startswith("leak-scan"):
            continue
        runs = [
            step["run"]
            for step in job["steps"]
            if "run" in step and "leak-scan" in step["run"]
        ]
        assert runs, f"job {job_id} 没有任何跑 leak-scan 的 run 步骤"
        scripts[job_id] = "\n".join(runs)
    return scripts


def test_ci_defines_both_leak_scan_gates() -> None:
    """两关必须都在：diff 关（PR，严）+ 全树关（恒为 0）。少一关都不许静默通过。"""
    scripts = _ci_leak_scan_run_scripts()
    assert set(scripts) == {"leak-scan", "leak-scan-full-tree"}, scripts.keys()


# ---------------------------------------------------------------------------
# 未提交改动提示：--base 走三点 diff，不含工作树
# ---------------------------------------------------------------------------


def test_uncommitted_paths_lists_dirty_files(tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """★脏工作树必须能被列出——这条提示的全部价值在于「说出没扫到什么」。"""
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.test"}
    import os
    env = {**os.environ, **env}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, env=env)

    assert leakscan.uncommitted_paths(repo_root=repo) == [], "干净工作树不该报改动"

    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")   # 已跟踪文件被改
    (repo / "b.py").write_text("y = 3\n", encoding="utf-8")   # 新增未跟踪
    dirty = leakscan.uncommitted_paths(repo_root=repo)
    assert "a.py" in dirty, dirty
    assert "b.py" in dirty, dirty


def test_uncommitted_paths_counts_a_rename_as_one_change(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """★porcelain -z 的重命名/复制占**两段**（``R  new\\0old``），旧路径段没有 XY 前缀。

    曾把旧路径段也按 ``XY<空格>path`` 切头：``longoldname.py`` 被削首 3 字符成
    ``goldname.py`` 混进结果，一次重命名被报成 2 条未提交改动。旧路径不该出现在
    结果里——改动内容如今活在新路径上。
    """
    import os
    import subprocess

    # 钉死 rename 检测：用户全局 gitconfig 可设 status.renames=false，那会把重命名拆成
    # 普通的 A+D 两条单段记录，本测试要走的「两段记录」解析路径就测不到了。
    # uncommitted_paths 内部起的 git 子进程继承 os.environ，故这里 setenv 对它同样生效。
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "status.renames")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.test",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.test"}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    (repo / "longoldname.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "mv", "longoldname.py", "newname.py"], cwd=repo, check=True, env=env)

    # 不喂伪造字节：让函数自己跑真 `git status --porcelain -z`，锁的是对真 git 输出的解析。
    assert leakscan.uncommitted_paths(repo_root=repo) == ["newname.py"]


def test_uncommitted_paths_is_quiet_outside_a_repo(tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """★取不到就返回空、不抛：这只是一句提示，不该让整个扫描失败。"""
    assert leakscan.uncommitted_paths(repo_root=tmp_path) == []


def test_ci_pr_diff_gate_runs_strict() -> None:
    """★PR diff 关必须带 ``--strict``（把 domain / context 也升为阻断）。

    断言的是解析出的 run 脚本里 ``leak-scan`` 那一行本身带 ``--strict``，
    而不是文件里任何位置出现过这个词。
    """
    script = _ci_leak_scan_run_scripts()["leak-scan"]
    invocation = next(
        line for line in script.splitlines() if "apkscan.cli leak-scan" in line
    )
    assert "--strict" in invocation, f"PR diff 关缺 --strict：{invocation}"
    assert "--base" in invocation, f"PR diff 关必须按 base 算 diff：{invocation}"


def test_ci_full_tree_gate_stays_tracked_and_default_tier() -> None:
    """全树关保持 ``--tracked`` 且**不加** ``--strict``（两关互补，不是替代）。

    全树按 strict 会产生数千条 domain/context 误报 → 人会习惯性加豁免、护栏失效。
    故这一关只压默认阻断档；同时必须有 ``--tracked``，否则门禁随未跟踪产物漂移。
    """
    script = _ci_leak_scan_run_scripts()["leak-scan-full-tree"]
    invocation = next(
        line for line in script.splitlines() if "apkscan.cli leak-scan" in line
    )
    assert "--tracked" in invocation, invocation
    assert "--strict" not in invocation, f"全树关不应升 strict：{invocation}"
    assert "--path apkscan" in invocation and "--path tests" in invocation, invocation

def test_global_fixture_segment_contract() -> None:
    """散在各测试里的 ``is_global`` 夹具依赖标准库分类，这条钉住那个前提。

    ★放在这里而不是各处重复断言：翻转时**只有这一条**红，且失败信息直接说明
      哪些文件要迁、按什么规则迁。否则十余条业务测试会以看不懂的方式同时失败。
    """
    from tests.doc_addresses import assert_global_fixture_contract

    assert_global_fixture_contract()
