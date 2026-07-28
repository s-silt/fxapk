"""build_provenance 分析器测试——全部合成数据，零真实案件信息。

覆盖点与"无修复即失败"对应关系：
- 提取：lookbehind 排 URL 内嵌 / 最小深度 / 设备挂载点排除 / Windows 形态 / .so 二进制提取；
- 分层：只看构建根（私有根下挂已知第三方目录名的踩坑回归）/ 已知第三方前缀 /
  公共工具链 /opt 不误判 / 主目录保守降 unknown；
- 标识解析：三段拆 批次-代号-业务、多余段并入业务、不足三段原样保留；
- 边界：声明大小前置门、累计预算、用户名不进 Finding 正文只进 meta、不产 Lead。
"""
from __future__ import annotations

import pytest

import apkscan.analyzers.build_provenance as bp
from apkscan.analyzers.build_provenance import (
    TIER_SELF_HOSTED,
    TIER_THIRD_PARTY,
    TIER_UNKNOWN,
    BuildProvenanceAnalyzer,
    classify_path,
    extract_paths,
    parse_build_identifier,
)
from apkscan.core.models import AnalyzerResult, Severity
from tests.conftest import FakeContext

# 合成的私有构建平台路径（结构仿真实形态，标识/项目名均为编造）。
_SYN_SELF_HOSTED = "/opt/work/Env9901-Zdemo-Wallet/Android-Gray/DemoPrj/jni/voip/audio.cc"
_SYN_THIRD_PARTY = "/Users/drklo/Documents/telega/jni/audio/echo.c"


def _run(dex_strings: list[str] | None = None, files: dict[str, bytes] | None = None,
         native_libs: list[str] | None = None, **kw) -> AnalyzerResult:
    ctx = FakeContext(dex_strings=dex_strings or [], files=files or {},
                      native_libs=native_libs or [], **kw)
    return BuildProvenanceAnalyzer().analyze(ctx)


def _all_finding_text(result: AnalyzerResult) -> str:
    parts: list[str] = []
    for f in result.findings:
        parts.extend([f.title, f.description, f.recommendation])
        parts.extend(ev.snippet + ev.location for ev in f.evidences)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 提取（extract_paths 纯函数）
# ---------------------------------------------------------------------------


def test_extract_unix_path_from_binary_blob() -> None:
    blob = b"\x00garbage\x00" + _SYN_SELF_HOSTED.encode() + b"\x00more"
    assert extract_paths(blob) == [_SYN_SELF_HOSTED]


def test_extract_rejects_url_embedded_segment() -> None:
    # URL 路径段里的 /home、/opt 前一个字符是路径字符 → lookbehind 排除。
    blob = b"https://cdn.example/home/pano/index.html \x00 com/foo/opt/work/x/y/z"
    assert extract_paths(blob) == []


def test_extract_min_depth_filters_shallow_paths() -> None:
    assert extract_paths(b"\x00/opt/tmp\x00/root/x.c\x00") == []


def test_extract_windows_path_normalized() -> None:
    blob = b"\x00C:\\Users\\dev9x\\proj\\app\\main.c\x00"
    assert extract_paths(blob) == ["C:/Users/dev9x/proj/app/main.c"]


def test_extract_excludes_device_runtime_mounts() -> None:
    # /mnt/sdcard 是设备运行时路径，不是构建机路径。
    assert extract_paths(b"\x00/mnt/sdcard/Download/pkg.apk\x00") == []


def test_extract_dedups_case_insensitively() -> None:
    blob = _SYN_SELF_HOSTED.encode() + b"\x00" + _SYN_SELF_HOSTED.upper().encode()
    assert len(extract_paths(blob)) == 1


# ---------------------------------------------------------------------------
# 分层（classify_path 纯函数）
# ---------------------------------------------------------------------------


def test_classify_self_hosted_workspace() -> None:
    cp = classify_path(_SYN_SELF_HOSTED)
    assert cp.tier == TIER_SELF_HOSTED
    assert cp.root == "/opt/work"
    assert cp.identifier == "Env9901-Zdemo-Wallet"


def test_classify_judges_root_only_not_full_path() -> None:
    # ★踩坑回归：私有构建根下挂着已知第三方来源的目录名（home/pano、webrtc）。
    # 判据只看构建根 → 仍是 self_hosted；若实现改成整条路径子串匹配第三方清单即红。
    trap = "/opt/work/Env9901-Zdemo-Wallet/Prj/jni/libvoip/home/pano/webrtc_dsp/ns.cc"
    assert classify_path(trap).tier == TIER_SELF_HOSTED


def test_classify_known_third_party_prefix() -> None:
    cp = classify_path(_SYN_THIRD_PARTY)
    assert cp.tier == TIER_THIRD_PARTY
    assert cp.origin  # 附标定依据说明
    assert cp.username == "drklo"


def test_classify_public_toolchain_opt_is_not_self_hosted() -> None:
    # /opt 下的公共工具链安装位形似私有工作区但零身份信息（实测验真补录的 FP 类）。
    for p in (
        "/opt/hostedtoolcache/Python/3.11.9/x64/lib/abc.py",
        "/opt/android-sdk/ndk/25.2.9519653/sysroot/usr/include/errno.h",
    ):
        assert classify_path(p).tier == TIER_THIRD_PARTY, p


def test_classify_unlisted_home_dir_stays_unknown() -> None:
    # 未收录的个人主目录不冒进判 self_hosted（可能是未收录的 SDK 开发者）。
    cp = classify_path("/Users/zhangsan9/dev/proj/native/x.c")
    assert cp.tier == TIER_UNKNOWN
    assert cp.username == "zhangsan9"


def test_extract_windows_project_root_outside_users() -> None:
    """★真样本回归：Go 的 module replace 把开发机项目根编进二进制，形如 D:\\<工作区>\\<项目>。

    旧正则只认 <盘符>:\\Users\\，这类自定义盘符根整类漏掉；且 D:/x/y 只有两个斜杠，
    与 Unix 共用 _MIN_SLASHES 会再被深度门槛挡一次。
    """
    blob = b"\x00D:\\im_demo2\\sdk_app2\\sdk\\pool.go\x00"
    assert extract_paths(blob) == ["D:/im_demo2/sdk_app2/sdk/pool.go"]
    # 两段的项目根本身也要留下（它就是身份线索）
    assert extract_paths(b"\x00D:\\im_demo2\\sdk_app2\x00") == ["D:/im_demo2/sdk_app2"]

    cp = classify_path("D:/im_demo2/sdk_app2/sdk/pool.go")
    assert cp.tier == TIER_SELF_HOSTED
    assert cp.root == "d:/im_demo2"
    assert cp.identifier == "sdk_app2"


def test_classify_windows_toolchain_is_not_self_hosted() -> None:
    """放开非 Users 盘符根后必须同时立墙：编译器/SDK/包管理器默认位人人相同、零身份信息。"""
    for p in (
        "D:/go/src/runtime/proc.go",
        "C:/ProgramData/chocolatey/lib/x/y.c",
        "C:/msys64/mingw64/include/stdio.h",
        "E:/android-sdk/ndk/25.2.9519653/sysroot/usr/include/errno.h",
        "C:/Windows/System32/drivers/x.sys",
    ):
        assert classify_path(p).tier == TIER_THIRD_PARTY, p

    # `C:\Program Files\...` 走不到分层——正则不吃空格，截断成 `C:/Program`（深度 1）后
    # 被深度门槛挡掉。这里把该前提钉住，免得将来放开空格时悄悄多出一类误判。
    assert extract_paths(b"\x00C:\\Program Files\\Java\\jdk-17\\include\\jni.h\x00") == []


def test_per_root_quota_stops_one_library_starving_the_rest() -> None:
    """★真样本回归：一个第三方库的近重复路径吃光全局预算，团伙自建的库一条都轮不到。

    实测两个样本里，同 APK 打包的 Telegram 分支 .so 产出 397 条同根路径占满 400 名额，
    后面的 Go 控制面库整库没被扫——报告 self_hosted 是空的，读的人会当成"没有自建路径"。
    这个缺陷只在跑**完整分析器**时暴露：直接调 extract_paths 是绕过预算的，测不出来。
    """
    from apkscan.analyzers.build_provenance import BuildProvenanceAnalyzer

    noisy = b"\x00".join(
        f"/Users/thirdparty/Projects/vendor/src/module{i:03d}/file{i:03d}.cpp".encode()
        for i in range(400)
    )
    mine = b"\x00".join(
        f"D:\\my_workspace\\my_project\\sdk\\unit{i:02d}.go".encode() for i in range(20)
    )

    class _Ctx:
        platform = "android"

        def native_libs(self) -> list[str]:
            return ["lib/arm64-v8a/libvendor.so", "lib/arm64-v8a/libmine.so"]

        def list_files(self) -> list[str]:
            return ["lib/arm64-v8a/libvendor.so", "lib/arm64-v8a/libmine.so"]

        def declared_size(self, path: str) -> int:
            return len(noisy) if "vendor" in path else len(mine)

        def read_file(self, path: str) -> bytes:
            return noisy if "vendor" in path else mine

        def dex_strings(self) -> list[str]:
            return []

    result = BuildProvenanceAnalyzer().analyze(_Ctx())  # type: ignore[arg-type]
    meta = result.meta["build_provenance"]

    assert meta["self_hosted"], "自建根必须被扫到，不能被第三方根的重复路径挤掉"
    roots = {g["root"] for g in meta["self_hosted"]}
    assert "d:/my_workspace" in roots

    # 噪声根被配额压住，而不是占满整个预算
    noisy_group = next(
        (g for g in meta["third_party"] + meta["unknown"] if "thirdparty" in g["root"]), None
    )
    assert noisy_group is not None
    assert noisy_group["count"] <= 32, f"单根应受配额限制，实得 {noisy_group['count']}"


def test_per_root_quota_applies_within_a_single_source() -> None:
    """★配额必须在**提取时**生效，不能只在收集侧做。

    调用方对每个 .so 各调一次 extract_paths；若提取层先按 limit 取满 400 条，
    同一个库里排在前面的噪声根就能把名额吃光，后面的自建根根本到不了收集侧的配额逻辑。
    上一版只测了"两个独立 .so"，覆盖不到这条单源路径。
    """
    blob = b"\x00".join(
        [f"/opt/vendorci/build{i:04d}/src/file{i:04d}.cpp".encode() for i in range(500)]
        + [b"D:\\my_workspace\\my_project\\sdk\\core.go"]
    )
    paths = extract_paths(blob)
    roots = [p for p in paths if p.lower().startswith("d:/my_workspace")]
    assert roots, "同一个 blob 里排在噪声之后的自建根必须仍能被提取到"
    noisy = [p for p in paths if p.startswith("/opt/vendorci")]
    assert len(noisy) <= 32, f"单根在提取层就该受配额限制，实得 {len(noisy)}"


def test_classify_dependency_cache_is_third_party() -> None:
    """★这条防的是把开源作者当嫌疑人：依赖缓存在作者机器上，内容却全是下载来的第三方源码。

    实测样本里有 /Users/<u>/go/pkg/mod/github.com/<开源组织>/<库>，若停在 unknown 而被
    当成线索，指向的是一位真实的开源项目作者。
    """
    for p in (
        "/Users/1/go/pkg/mod/github.com/someorg/somelib",
        "C:/Users/1/go/pkg/mod/golang.org/x/crypto",
        "/home/dev/.cargo/registry/src/index.crates.io/foo-1.0/lib.rs",
        "/home/dev/proj/node_modules/left-pad/index.js",
    ):
        cp = classify_path(p)
        assert cp.tier == TIER_THIRD_PARTY, p
        assert cp.origin, p

    # ★不得反噬：作者自己的源码目录不含依赖缓存标志，仍是 self_hosted。
    assert classify_path("D:/im_demo2/sdk_app2/sdk/pool.go").tier == TIER_SELF_HOSTED


# ---------------------------------------------------------------------------
# 标识解析
# ---------------------------------------------------------------------------


def test_identifier_parse_three_parts() -> None:
    info = parse_build_identifier("Env9901-Zdemo-Wallet")
    assert info == {"raw": "Env9901-Zdemo-Wallet", "batch": "Env9901",
                    "code": "Zdemo", "business": "Wallet"}


def test_identifier_parse_extra_parts_join_business() -> None:
    assert parse_build_identifier("BB07-Xdemo-AV-EXTRA-MM")["business"] == "AV-EXTRA-MM"


def test_identifier_parse_unstructured_kept_raw() -> None:
    info = parse_build_identifier("myserver")
    assert info["raw"] == "myserver"
    assert info["batch"] is None


# ---------------------------------------------------------------------------
# 分析器端到端
# ---------------------------------------------------------------------------


def test_analyze_self_hosted_from_dex_produces_finding_and_meta() -> None:
    result = _run(dex_strings=["assert failed: " + _SYN_SELF_HOSTED + ":120"])
    ids = [f.id for f in result.findings]
    assert "BUILD-PROVENANCE-SELF-HOSTED" in ids
    assert "BUILD-PROVENANCE-PATHS" in ids
    meta = result.meta["build_provenance"]
    assert meta["self_hosted"][0]["identifier"] == "Env9901-Zdemo-Wallet"
    assert meta["identifiers"][0]["batch"] == "Env9901"


def test_analyze_extracts_from_native_so() -> None:
    so = b"\x7fELF\x00\x00" + _SYN_SELF_HOSTED.encode() + b"\x00"
    result = _run(files={"lib/arm64-v8a/libdemo.so": so},
                  native_libs=["lib/arm64-v8a/libdemo.so"])
    sh = [f for f in result.findings if f.id == "BUILD-PROVENANCE-SELF-HOSTED"]
    assert sh and sh[0].evidences[0].source == "native"
    assert sh[0].evidences[0].location == "lib/arm64-v8a/libdemo.so"


def test_analyze_third_party_only_no_self_hosted_finding() -> None:
    result = _run(dex_strings=[_SYN_THIRD_PARTY])
    ids = [f.id for f in result.findings]
    assert ids == ["BUILD-PROVENANCE-PATHS"]
    meta = result.meta["build_provenance"]
    assert meta["self_hosted"] == []
    assert meta["third_party"][0]["root"] == "/users/drklo"


def test_withdrawn_third_party_root_falls_back_to_unknown() -> None:
    """撤回名单：证据不足以判第三方的构建根停在 unknown，且**带上撤回理由**。

    退回任一环节本测试必红：
      · 把该根放回 _KNOWN_THIRD_PARTY_ROOTS → tier 变 third_party；
      · 只把它从名单删掉、不进撤回名单 → origin 为空，分析员无从分辨"查过"与"没查过"。
    """
    cp = classify_path("/Users/dhmac/StudioProjects/proj/jni/voip/x.cpp")
    assert cp.tier == TIER_UNKNOWN
    assert cp.origin and "撤回" in cp.origin
    assert cp.username == "dhmac"


def test_withdrawn_root_not_promoted_to_self_hosted() -> None:
    """撤回≠改判自建：共现证明不了作者身份，冒进判自建会把开源作者写成嫌疑人。"""
    for p in (
        "/Users/dhmac/StudioProjects/proj/jni/a.cpp",
        "/Users/dhmac/go/src/app/main.go",
    ):
        assert classify_path(p).tier != TIER_SELF_HOSTED, p


def test_withdrawal_does_not_leak_to_neighbouring_roots() -> None:
    """撤回只作用于被撤那一条：同批样本里分布相同的其它个人根不受影响。

    ``/users/dkaraush/`` 与被撤根出现在完全相同的样本集合里，却是真实的开源贡献者——
    若实现按"与自建符号共现"之类的模糊条件批量撤回，这条即红。
    """
    assert classify_path("/Users/dkaraush/projects/tmessages-ffmpeg/x.c").tier == TIER_THIRD_PARTY
    assert classify_path("/Users/jbrateman/proj/src/y.c").tier == TIER_THIRD_PARTY


def test_analyze_withdrawn_root_origin_reaches_meta() -> None:
    """★接线：撤回理由要真的出现在 report 的 meta 里，不能只活在 classify_path 的返回值上。

    只改 classify_path、不改 _summarize 的 unknown 投影，本测试即红（origin 被丢掉）。
    """
    result = _run(dex_strings=["/Users/dhmac/StudioProjects/proj/jni/voip/x.cpp"])
    unknown = result.meta["build_provenance"]["unknown"]
    entry = next(u for u in unknown if u["root"] == "/users/dhmac")
    assert "撤回" in entry["origin"]
    # 撤回理由属分层依据，不进用户可见 Finding 正文（同用户名的处理口径）。
    assert "dhmac" not in _all_finding_text(result)


def test_analyze_usernames_only_in_meta_not_in_findings() -> None:
    result = _run(dex_strings=["/Users/zhangsan9/dev/proj/native/x.c", _SYN_SELF_HOSTED])
    assert "zhangsan9" not in _all_finding_text(result)
    names = {u["name"]: u["classification"]
             for u in result.meta["build_provenance"]["usernames"]}
    assert names == {"zhangsan9": TIER_UNKNOWN}


def test_analyze_severities_are_informational() -> None:
    result = _run(dex_strings=[_SYN_SELF_HOSTED])
    by_id = {f.id: f for f in result.findings}
    assert by_id["BUILD-PROVENANCE-PATHS"].severity == Severity.INFO
    assert by_id["BUILD-PROVENANCE-SELF-HOSTED"].severity == Severity.LOW


def test_analyze_produces_no_leads() -> None:
    result = _run(dex_strings=[_SYN_SELF_HOSTED, _SYN_THIRD_PARTY])
    assert result.leads == []


def test_analyze_empty_sample_no_findings_meta_present() -> None:
    result = _run()
    assert result.findings == []
    assert result.meta["build_provenance"]["self_hosted"] == []


def test_declared_size_gate_skips_oversized_so() -> None:
    # 声明大小超单库上限 → 读前拦截：即使实际内容很小且含路径也不得被提取。
    so = _SYN_SELF_HOSTED.encode() + b"\x00"
    result = _run(
        files={"lib/arm64-v8a/libbig.so": so},
        native_libs=["lib/arm64-v8a/libbig.so"],
        declared_sizes={"lib/arm64-v8a/libbig.so": bp._MAX_LIB_BYTES + 1},
    )
    assert result.findings == []


@pytest.mark.parametrize(
    "path,origin",
    [
        ("/workspace/src/grpc/src/core/lib/surface/call.cc", "Google Cloud Build 默认工作目录"),
        ("/workspace/onertc/alirtc-ci-auto/src/rtc.cc", "商用 RTC SDK 的 CI"),
        ("/workspace/.gradle/caches/transforms/x/jni/y.c", "Gradle 缓存"),
        ("/build/src/openssl/crypto/mem.c", "Docker 构建镜像惯用目录"),
        ("/srv/jenkins/workspace/sdk-release/src/a.cpp", "厂商自建 Jenkins"),
        ("/opt/jenkins/workspace/vendor-sdk/jni/x.cpp", "厂商 Jenkins"),
        ("/opt/buildkite-agent/builds/host/proj/x.cc", "Buildkite"),
        ("/opt/gitlab-runner/builds/abc/0/grp/proj/x.c", "GitLab Runner"),
        ("/opt/teamcity/buildAgent/work/abc/src/x.cpp", "TeamCity"),
        ("/opt/atlassian/pipelines/agent/build/src/x.c", "Bitbucket Pipelines"),
    ],
)
def test_public_ci_paths_never_judged_self_hosted(path: str, origin: str) -> None:
    """★公共 CI / 容器构建目录不得判成「自建构建环境」。

    这些是通用、公开的构建环境默认路径——正常 App 里的合法 SDK 只要在这类环境上编译过就会
    带上它们。实测这 10 条曾**全部**被判 self_hosted：干净 App 会凭空多出一条取证结论。
    两条判据各管一半：``/workspace`` ``/build`` 是公共约定目录（不给私有工作区资格），
    其余靠构建根里的 CI 标志物识别（安装位各家不同，逐个列根是打地鼠）。
    """
    assert bp.classify_path(path).tier != bp.TIER_SELF_HOSTED, f"{origin} 被误判为自建"


def test_private_workspace_still_self_hosted() -> None:
    """对照：真·私有工作区不得被上面那条误伤（否则修误报的代价是丢掉全部检出）。"""
    c = bp.classify_path("/opt/work/Env0000-Aaaa-AV/Proj/jni/x.cc")
    assert c.tier == bp.TIER_SELF_HOSTED
    assert c.identifier == "Env0000-Aaaa-AV"


def test_ci_marker_matched_on_root_only_not_whole_path() -> None:
    """★CI 标志物只在**构建根**上匹配：私有工作区下面挂个叫 gradle 的目录不该让整条路径改判。

    与「只看构建根、不看整条路径」是同一条纪律——上一次栽在它上面是把私有平台误判成第三方。
    """
    c = bp.classify_path("/opt/work/Env0000-Aaaa-AV/Proj/gradle/caches/x.c")
    assert c.tier == bp.TIER_SELF_HOSTED


def test_media_asset_path_is_not_a_build_environment() -> None:
    """★测试码流/媒体资源路径不得判为自建构建环境。

    实测代价：一份编解码库内嵌的 HEVC 测试码流路径被判 self_hosted 后，
    两个**互不相干**的样本因共有它而在跨案构建环境反查里聚成同一簇——
    把无关案件串到一起，是串案分析最忌讳的假阳性。
    """
    c = classify_path("c:/content/test-UHD-HEVC_01_FMV_Med_track1.hvc")
    assert c.tier == TIER_UNKNOWN, "媒体测试资源被当成了构建环境"
    assert "测试码流" in (c.origin or "")


@pytest.mark.parametrize("path", [
    "c:/content/clip.h265",
    "d:/assets/sample_stream.ivf",
    "/opt/media/track1.yuv",
])
def test_media_asset_suffixes_are_rejected(path: str) -> None:
    assert classify_path(path).tier == TIER_UNKNOWN


def test_real_project_root_not_hit_by_asset_guard() -> None:
    """对照：真·私有项目根不得被媒体资源守卫误伤。"""
    c = classify_path("D:/im_sdk2/sdk_app2/sdk/bootstrap.go")
    assert c.tier == TIER_SELF_HOSTED
    assert c.identifier == "sdk_app2"


@pytest.mark.parametrize("path, why", [
    ("e:/tingyunandroid-oom/koom-common/src/main/cpp/x.cc", "听云 APM 源码树"),
    ("E:/TingyunAndroid-OOM/koom-fast-dump/src/a.cpp", "同上，大小写不敏感"),
    ("d:/bugly-android/src/main/jni/x.c", "腾讯 Bugly SDK 源码树"),
    ("f:/matrix/matrix-android/x.cc", "腾讯 Matrix SDK 源码树"),
])
def test_third_party_sdk_source_trees_on_any_drive(path: str, why: str) -> None:
    """★第三方 SDK 的源码树可以放在任意盘符下，前缀匹配对它们无效。

    实测代价：``e:/tingyunandroid-oom`` 下的 KOOM 被判自建，进而进了跨案串案维度——
    而它随 APM SDK 继承进任何接入方，拿它串案会把互不相干的案件聚成一簇。
    """
    c = classify_path(path)
    assert c.tier == TIER_THIRD_PARTY, f"{why} 被当成了自建构建环境"


def test_real_windows_project_root_still_self_hosted() -> None:
    """对照：真·私有 Windows 项目根不得被上面那条误伤。"""
    c = classify_path("D:/im_sdk2/sdk_app2/sdk/bootstrap.go")
    assert c.tier == TIER_SELF_HOSTED and c.identifier == "sdk_app2"


def test_corpus_build_env_lookup_is_reachable_from_cli() -> None:
    """★接线锁：构建环境反查必须有 CLI 出口。

    ``find_by_build_env`` / ``shared_build_environments`` 实现完备却**零调用方**——
    提取、解析、入库、反查全做了，就是没人调，于是同一开发环境跨案这件事
    始终要靠人工比对才能发现。只测库函数挡不住这种「写了但没接上」。
    """
    import inspect

    from apkscan.commands import corpus as cmd

    src = inspect.getsource(cmd)
    assert "find_by_build_env" in src, "corpus seen 没有接构建环境反查"
    assert "shared_build_environments" in src, "没有跨样本构建环境簇的 CLI 出口"


# ---------------------------------------------------------------------------
# 串案维度的路径数门槛（corpus 侧）
# ---------------------------------------------------------------------------


def _env_report(items: list[dict]) -> dict:
    return {"meta": {"build_provenance": {"self_hosted": items}}}


def test_sparse_build_env_is_kept_out_of_cross_case_dimension() -> None:
    """★只留一两条路径的「构建环境」不得进串案维度。

    实测的三个噪音（HEVC 测试码流 1 条、JavaCC 语法文件 1 条、第三方 APM 2 条）
    都靠这个挡；而真实构建环境实测 26–32 条，两侧中间是空的。
    串案对假阳性最敏感——一条噪音就能把两个互不相干的案件聚成一簇。
    """
    from apkscan.core import corpus as C

    got = C._build_environments(_env_report([
        {"root": "c:/content", "identifier": "test-UHD.hvc", "count": 1},
        {"root": "e:/x", "identifier": "koom-common", "count": 2},
        {"root": "/opt/work", "identifier": "Env0000-Aaaa-AV", "count": 32},
        {"root": "d:/im_sdk2", "identifier": "sdk_app2", "count": 26},
    ]))

    idents = [g["identifier"] for g in got]
    assert idents == ["Env0000-Aaaa-AV", "sdk_app2"], f"门槛没生效：{idents}"


def test_build_env_without_count_is_not_dropped() -> None:
    """★缺 count 字段（旧报告）时放行——不因少个字段就丢掉已有数据。"""
    from apkscan.core import corpus as C

    got = C._build_environments(_env_report([
        {"root": "/opt/work", "identifier": "Env1856-Gccc-Verify"},
    ]))
    assert [g["identifier"] for g in got] == ["Env1856-Gccc-Verify"]


def test_analyzer_still_reports_sparse_paths_in_full() -> None:
    """★门槛只作用于串案维度，分析器仍全量如实记录。

    人核报告要看得到全部（包括弱证据），能不能拿去跨案聚簇是另一回事。
    两者混为一谈，就会为了降噪而删掉人该看到的事实。
    """
    lib = (b"\x00" * 16 + b"z:/jc/units/javascript.jc\x00"
           + _SYN_SELF_HOSTED.encode() + b"\x00")
    result = _run(files={"lib/arm64-v8a/liba.so": lib},
                  native_libs=["lib/arm64-v8a/liba.so"])
    meta = result.meta["build_provenance"]
    roots = {str(g.get("root")) for g in meta["self_hosted"]}
    assert "z:/jc" in roots, "分析器把弱证据也滤掉了——那是串案维度该做的事，不是它"


def test_total_budget_stops_scanning_remaining_libs(monkeypatch: pytest.MonkeyPatch) -> None:
    # 第一库耗尽累计预算 → 第二库不读（其中的第三方路径不出现在 meta）。
    lib_a = b"\x00" * 64 + _SYN_SELF_HOSTED.encode() + b"\x00"
    lib_b = _SYN_THIRD_PARTY.encode() + b"\x00"
    monkeypatch.setattr(bp, "_MAX_TOTAL_LIB_BYTES", len(lib_a))
    result = _run(
        files={"lib/arm64-v8a/liba.so": lib_a, "lib/arm64-v8a/libb.so": lib_b},
        native_libs=["lib/arm64-v8a/liba.so", "lib/arm64-v8a/libb.so"],
    )
    meta = result.meta["build_provenance"]
    assert meta["self_hosted"] and meta["third_party"] == []
