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

#: 阴性夹具：文档保留段，扫描器必须放行（故这几行**不带**豁免注释）。
_DOC_IP = "198.51.100.7"
_DOC_IPV6 = "2001:db8::1"


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
    """精确判据阻断、噪音判据只提示——这个分档是有意的，改动须同时改文档。"""
    assert leakscan.BLOCKING_RULES == frozenset({"ip", "secret", "exemption"})
    assert set(leakscan.RULES) == {"ip", "secret", "domain", "context", "exemption"}


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
        )
    )
    assert _rules(findings) == {"ip", "secret", "domain"}, (
        f"阳性夹具在无豁免行上必须照常命中，实际：{findings}"
    )
    # 两个 IP 夹具都要各自命中，不能只中一个。
    assert {f.value for f in findings if f.rule == "ip"} == {_PUBLIC_IPV4, _PUBLIC_IPV6}
    assert leakscan.blocking(findings), "ip / secret 判据必须阻断"


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
