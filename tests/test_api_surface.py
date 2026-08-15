"""api_surface 分析器测试：后端接口提取 + 三层误报过滤 + 功能语义标注。

零真实案件数据：全部用合成 bytes/字符串构造，不引用 OneDrive 路径、不含真实域名/案件名。
每条断言力求「删掉实现里对应那段即变红」。
"""
from __future__ import annotations

from apkscan.analyzers.api_surface import (
    ApiSurfaceAnalyzer,
    rejection_reason,
    semantics_for,
)
from apkscan.core.models import Severity
from tests.conftest import FakeContext


def _analyze(dex_strings=None, files=None, native_libs=None):
    return ApiSurfaceAnalyzer().analyze(
        FakeContext(dex_strings=dex_strings, files=files, native_libs=native_libs)
    )


def _ids(result) -> list[str]:
    return [f.id for f in result.findings]


def _surface(result) -> dict:
    return result.meta["api_surface"]


def _paths(result) -> list[str]:
    return [e["path"] for e in _surface(result)["endpoints"]]


# ---------------------------------------------------------------------------
# 提取 + 概览
# ---------------------------------------------------------------------------


def test_extracts_self_owned_endpoints_and_overview():
    result = _analyze(
        dex_strings=[
            "/api/home/getContactList",
            "/api/home/config",
            "https://example.test/api/finance/withdraw?x=1",
        ]
    )
    paths = _paths(result)
    assert "/api/home/getContactList" in paths
    assert "/api/home/config" in paths
    # query 串应被切掉
    assert "/api/finance/withdraw" in paths
    assert "API-SURFACE-OVERVIEW" in _ids(result)
    assert _surface(result)["counts"]["own"] == 3


def test_various_api_prefixes_recognized():
    """api / v1~v9 / app / client / mobile / gateway / open 前缀都要认。"""
    result = _analyze(
        dex_strings=[
            "/v2/user/profile",
            "/gateway/order/list",
            "/mobile/home/index",
            "/client/init/setup",
            "/open/pay/query",
        ]
    )
    paths = _paths(result)
    for p in ("/v2/user/profile", "/gateway/order/list", "/mobile/home/index",
              "/client/init/setup", "/open/pay/query"):
        assert p in paths


def test_non_api_prefix_not_matched():
    """无接口命名空间首段的普通路径不算接口面（防过度提取）。"""
    result = _analyze(dex_strings=["/static/img/logo.png", "/res/layout/main", "/apixyz/foo"])
    assert _paths(result) == []


def test_no_leads_ever_produced():
    """★契约：URL path 不是可发函的调证对象，本分析器恒不产 Lead。"""
    result = _analyze(dex_strings=["/api/home/getContactList", "/api/home/config"])
    assert result.leads == []


# ---------------------------------------------------------------------------
# 三层误报过滤（每层「无修复即失败」）
# ---------------------------------------------------------------------------


def test_layer1_classname_filtered():
    """第 1 层：DEX 类描述符切出的 /api/CommonStatusCodes、/api/Auth（段大写开头）须滤掉。"""
    result = _analyze(
        dex_strings=[
            "Lcom/google/android/gms/common/api/CommonStatusCodes;",
            "/api/Auth",
            "Lcom/example/app/util/StringHelper;",  # /app/util/StringHelper 叶子大写
        ]
    )
    paths = _paths(result)
    assert "/api/CommonStatusCodes" not in paths
    assert "/api/Auth" not in paths
    assert "/app/util/StringHelper" not in paths
    assert _surface(result)["counts"]["filtered_class_name"] >= 2


def test_layer2_r8_obfuscated_filtered():
    """第 2 层：zz/za 形态的 R8 混淆占位类名须滤掉（用非 SDK 首段隔离出纯第 2 层判据）。"""
    result = _analyze(dex_strings=["/gateway/user/zzb", "/api/home/zzc"])
    paths = _paths(result)
    assert "/gateway/user/zzb" not in paths
    assert "/api/home/zzc" not in paths
    assert _surface(result)["counts"]["filtered_obfuscated"] >= 2


def test_layer3_sdk_segment_filtered_but_real_leaf_kept():
    """第 3 层：SDK 命名空间**首段**（credentials/internal）须滤；但把 SDK 词用作**叶子**的真接口保留。"""
    result = _analyze(
        dex_strings=[
            "/api/credentials/get",       # 首段=SDK → 滤
            "/api/internal/state",        # 首段=SDK → 滤
            "/api/home/signin",           # signin 在叶子 → 真接口，保留
        ]
    )
    paths = _paths(result)
    assert "/api/credentials/get" not in paths
    assert "/api/internal/state" not in paths
    assert "/api/home/signin" in paths
    assert _surface(result)["counts"]["filtered_sdk"] >= 2


def test_rejection_reason_pure_function():
    assert rejection_reason("/api/CommonStatusCodes") == "class_name"
    assert rejection_reason("/gateway/user/zzb") == "obfuscated"
    assert rejection_reason("/api/credentials/get") == "sdk"
    assert rejection_reason("/api/home/getContactList") is None
    assert rejection_reason("/api/home/config") is None


# ---------------------------------------------------------------------------
# 功能语义标注
# ---------------------------------------------------------------------------


def test_contact_theft_semantic_and_finding():
    result = _analyze(dex_strings=["/api/home/getContactList"])
    ep = next(e for e in _surface(result)["endpoints"] if e["path"] == "/api/home/getContactList")
    assert "通讯录窃取" in ep["semantics"]
    f = next(f for f in result.findings if f.id == "API-SEMANTIC-CONTACT-THEFT")
    assert f.severity == Severity.HIGH


def test_domain_rotation_semantic_and_finding():
    result = _analyze(dex_strings=["/api/home/domainCheckReport"])
    assert "域名存活上报" in semantics_for("/api/home/domainCheckReport")
    assert "API-SEMANTIC-DOMAIN-ROTATION" in _ids(result)


def test_remote_config_listed_in_dedicated_key():
    """★远程配置路径必须单列 config_endpoints（下游拼配置 URL 依赖此键）。"""
    result = _analyze(dex_strings=["/api/home/config", "/v1/app/getConfig"])
    cfg = _surface(result)["config_endpoints"]
    assert "/api/home/config" in cfg
    assert "/v1/app/getConfig" in cfg
    assert "API-SEMANTIC-REMOTE-CONFIG" in _ids(result)


def test_object_storage_semantic():
    result = _analyze(dex_strings=["/api/home/r2upload_info"])
    assert "对象存储上传" in semantics_for("/api/home/r2upload_info")
    assert "API-SEMANTIC-OBJECT-STORAGE" in _ids(result)


def test_finance_and_gambling_and_face_findings():
    result = _analyze(
        dex_strings=[
            "/api/finance/recharge",
            "/api/order/withdraw",
            "/api/points/exchange",
            "/api/home/lottery_link",
            "/api/ai/change_face",
            "/api/ai/my_face",
        ]
    )
    ids = _ids(result)
    assert "API-SEMANTIC-FINANCE" in ids
    assert "API-SEMANTIC-GAMBLING" in ids
    assert "API-SEMANTIC-FACE-SWAP" in ids


def test_semantics_for_pure_function_positive():
    assert "远程配置下发" in semantics_for("/api/home/config")
    assert "博彩彩票" in semantics_for("/api/home/lottery_link")
    assert "资金充提兑换" in semantics_for("/api/order/withdraw")
    assert "AI换脸" in semantics_for("/api/ai/change_face")


def test_semantics_avoid_overtagging():
    """★不误标：客服「联系我们」不是通讯录窃取；OTP「发短信」不是短信窃取。"""
    assert "通讯录窃取" not in semantics_for("/api/contact/us")
    assert "短信窃取" not in semantics_for("/api/sms/send")


def test_compiled_source_paths_are_not_backend_apis():
    """★真样本回归：WebRTC 的 __FILE__ 调试串被编进 .so，形如 /api/…/xxx.cc。

    多份真样本的报告里这类路径被整片当成后端接口面。段字符集含 `.`，
    正则天然吃得下扩展名，故必须显式排除编译型源码/头文件叶子。
    """
    for path in (
        "/api/audio/audio_frame.cc",
        "/api/video/video_frame.cc",
        "/api/rtc_event_log_output_file.cc",
        "/client/basic_port_allocator.cc",
        "/api/audio_codecs/audio_decoder.h",
        "/api/task_queue/task_queue_base.hpp",
    ):
        assert rejection_reason(path) == "source_file", path

    # 真实后端接口形态不受影响——.php/.jsp/.do 是接口，不是源码。
    assert rejection_reason("/api/user/login.php") is None
    assert rejection_reason("/api/order/submit.do") is None
    assert rejection_reason("/api/home/config") is None


def test_go_symbol_table_is_not_backend_api():
    """★真样本回归：gomobile 绑定层符号（golang.org/x/mobile/bind）命中 `mobile` 前缀，
    整片被收成 /mobile/bind/seq.Delete 这类"接口"。剔掉 .cc 后剩下的 10 条全是这个。
    """
    for path in (
        "/mobile/bind/seq.Delete",
        "/mobile/bind/seq.FromRefNum",
        "/mobile/bind/seq.UTF16Encode",
        "/mobile/bind/seq.countedObj",
        "/mobile/bind/java.setContext",
        "/mobile/bind/seq.init.0",
        "/mobile/bind/seq.Delete.deferwrap1",
        "/mobile/bind/seq.",
    ):
        assert rejection_reason(path) == "code_symbol", path

    # ★不得误伤真实接口：/mobile/bind/card 是绑卡接口，不能因前缀被一刀切。
    assert rejection_reason("/mobile/bind/card") is None
    assert rejection_reason("/mobile/bind/phone") is None
    assert rejection_reason("/api/user/login.php") is None
    assert rejection_reason("/api/v1/config.json") is None


def test_auth_marker_requires_word_boundary():
    """★真样本回归：/api/rtc_event_log_output_file.cc 去分隔符后 log+output 粘出 logout，
    被标成「账号认证」。marker 必须整词对齐，跨词粘连不算命中。
    """
    assert "账号认证" not in semantics_for("/api/rtc_event_log_output_file")
    assert "账号认证" not in semantics_for("/api/event/log_output/file")
    assert "账号认证" not in semantics_for("/api/logOutputFile")
    # 真的登出/登录接口仍须命中（词边界判据不得损召回）
    assert "账号认证" in semantics_for("/api/user/logout")
    assert "账号认证" in semantics_for("/api/user/login")
    assert "账号认证" in semantics_for("/api/auth/resetPassword")


def test_word_boundary_keeps_cross_separator_markers():
    """词边界判据不得损召回：marker 本就设计成跨分隔符匹配（get_contact_list / getContactList）。"""
    for path in (
        "/api/home/getContactList",
        "/api/home/get_contact_list",
        "/api/home/get-contact-list",
        "/api/upload/uploadContactList",
        "/api/home/domainCheckReport",
        "/api/home/r2upload_info",
    ):
        assert semantics_for(path), f"{path} 应至少命中一条语义"
    assert "通讯录窃取" in semantics_for("/api/upload/uploadContactList")
    assert "域名存活上报" in semantics_for("/api/home/domainCheckReport")


def test_weak_semantics_do_not_spawn_standalone_finding():
    """弱语义（账号认证等）只进 meta，不单独产 Finding（否则每个 App 都刷一堆噪声）。"""
    result = _analyze(dex_strings=["/api/user/login"])
    assert "账号认证" in semantics_for("/api/user/login")
    # 只有概览，没有针对「账号认证」的独立 Finding id
    assert _ids(result) == ["API-SURFACE-OVERVIEW"]


# ---------------------------------------------------------------------------
# native .so 提取（整库读、不采样）
# ---------------------------------------------------------------------------


def test_native_so_extraction_reads_whole_lib_not_sampled():
    """★接口串埋在库中段（超出头窗、错过中窗起点）：整库读能提到，头/中/尾采样会漏。

    构造 ~1.2MB 的 libapp.so，把接口放在 offset≈600K：采样(head/mid/tail 各 256K)的 mid 窗从
    ~612K 起，正好错过该串；若实现退化为采样即变红。
    """
    pad = b"\x00" * 600_000
    so = b"\x7fELF" + pad + b"\n/api/home/getContactList\n/api/home/config\n" + pad
    result = _analyze(
        files={"lib/arm64-v8a/libapp.so": so},
        native_libs=["lib/arm64-v8a/libapp.so"],
    )
    endpoints = {e["path"]: e for e in _surface(result)["endpoints"]}
    assert "/api/home/getContactList" in endpoints
    assert "native" in endpoints["/api/home/getContactList"]["source"]
    assert "/api/home/config" in _surface(result)["config_endpoints"]


def test_oversized_so_skipped_by_declared_size():
    """声明大小超单库上限的 .so 不读（防超大/zip-bomb 膨胀内存）。"""
    from apkscan.analyzers.api_surface import _MAX_SO_BYTES

    so = b"\x7fELF/api/home/getContactList"
    result = ApiSurfaceAnalyzer().analyze(
        FakeContext(
            files={"lib/arm64-v8a/libbig.so": so},
            native_libs=["lib/arm64-v8a/libbig.so"],
            declared_sizes={"lib/arm64-v8a/libbig.so": _MAX_SO_BYTES + 1},
        )
    )
    assert _paths(result) == []


# ---------------------------------------------------------------------------
# assets 提取
# ---------------------------------------------------------------------------


def test_asset_extraction_and_source_tag():
    result = _analyze(
        files={"assets/config.json": b'{"base":"https://h.test/v1/user/config"}'}
    )
    endpoints = {e["path"]: e for e in _surface(result)["endpoints"]}
    assert "/v1/user/config" in endpoints
    assert "asset" in endpoints["/v1/user/config"]["source"]
    assert "/v1/user/config" in _surface(result)["config_endpoints"]


def test_binary_resource_not_scanned_as_text():
    """二进制资源即便落 assets/ 也不当文本扫（.so 归 native 扫；字体/图片不扫）。"""
    result = _analyze(files={"assets/font/MyFont.ttf": b"/api/home/getContactList" * 10})
    # .ttf 属二进制、is_text_resource 排除；native 扫只认 .so，故此处不应提到
    assert _paths(result) == []


# ---------------------------------------------------------------------------
# 干净样本 / 空
# ---------------------------------------------------------------------------


def test_clean_app_no_endpoints_no_findings():
    result = _analyze(dex_strings=["com.example.MainActivity", "just some text", "value=1"])
    assert _paths(result) == []
    assert result.findings == []
    assert _surface(result)["counts"]["own"] == 0
