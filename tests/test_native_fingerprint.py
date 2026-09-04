"""native_fingerprint 分析器 + corpus so_sha256 候选召回。零真实样本：合成 .so 字节。"""
from __future__ import annotations

import hashlib

from apkscan.analyzers.native_fingerprint import NativeFingerprintAnalyzer
from apkscan.core import corpus
from tests.conftest import FakeContext

_SO_A = b"\x7fELF" + b"family-core-bytes" * 100      # 合成"核心业务 .so"
_SO_B = b"\x7fELF" + b"other-lib" * 50


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_analyzer_hashes_app_so_into_meta() -> None:
    ctx = FakeContext(files={
        "lib/arm64-v8a/libclientcore.so": _SO_A,
        "lib/arm64-v8a/libother.so": _SO_B,
    }, native_libs=["lib/arm64-v8a/libclientcore.so", "lib/arm64-v8a/libother.so"])
    result = NativeFingerprintAnalyzer().analyze(ctx)
    hashes = result.meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert _sha(_SO_A) in shas and _sha(_SO_B) in shas
    core = next(h for h in hashes if h["sha256"] == _sha(_SO_A))
    assert core["name"] == "libclientcore.so" and core["size"] == len(_SO_A)


def test_analyzer_dedups_identical_so() -> None:
    """两个路径中的同字节 .so → 去重为一条指纹；不在分析器内推断来源。"""
    ctx = FakeContext(files={"lib/a/libx.so": _SO_A, "lib/b/liby.so": _SO_A},
                      native_libs=["lib/a/libx.so", "lib/b/liby.so"])
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    assert len([h for h in hashes if h["sha256"] == _sha(_SO_A)]) == 1


_SO_ARM64 = b"\x7fELF" + b"arm64-core" * 80
_SO_ARMV7 = b"\x7fELF" + b"armv7-core" * 80  # 同 basename、不同 ABI → 字节不同、sha256 不同


def test_hashes_all_abi_variants_same_basename() -> None:
    """★P1 无修复即失败：同名多 ABI 变体（libclientcore.so × arm64/armeabi）字节不同 → **各自**哈希。

    修前按 basename 塌缩（collect_so_basenames）会把两变体并成一条、漏掉另一个构建；本测试断言两个
    sha256 都在，修前必失败。
    """
    ctx = FakeContext(files={
        "lib/arm64-v8a/libclientcore.so": _SO_ARM64,
        "lib/armeabi-v7a/libclientcore.so": _SO_ARMV7,
    }, native_libs=["lib/arm64-v8a/libclientcore.so", "lib/armeabi-v7a/libclientcore.so"])
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert _sha(_SO_ARM64) in shas and _sha(_SO_ARMV7) in shas
    assert len(hashes) == 2  # 两 ABI 变体各一条，未塌缩


def test_declared_size_gate_skips_oversized_so() -> None:
    """★P0-5 无修复即失败：声明解压后 > 64MB 的 .so 在 read_file **前**被拦——绝不 read。

    模拟「小压缩、巨解压」炸弹 .so：实际字节很小但 zip 声明 200MB。修前无前置 size 门 → read_file
    会被调用（并在真 APK 上让 androguard 全量膨胀进内存）；本测试断言该路径从未进入 reads，修前必失败。
    """
    class _Recording(FakeContext):
        def __init__(self, **kw) -> None:
            super().__init__(**kw)
            self.reads: list[str] = []

        def read_file(self, path: str) -> bytes | None:  # type: ignore[override]
            self.reads.append(path)
            return super().read_file(path)

    big, ok = "lib/arm64-v8a/libbomb.so", "lib/arm64-v8a/libok.so"
    ctx = _Recording(
        files={big: b"\x7fELF" + b"x" * 100, ok: _SO_A},
        native_libs=[big, ok],
        declared_sizes={big: 200 * 1024 * 1024},  # 声明 200MB（> 64MB 上限），实际字节仅百余字节
    )
    hashes = NativeFingerprintAnalyzer().analyze(ctx).meta["native_lib_hashes"]
    shas = {h["sha256"] for h in hashes}
    assert big not in ctx.reads  # 前置门拦下：从未 read（不膨胀）
    assert _sha(_SO_A) in shas  # 正常 .so 照常哈希
    assert not any(h["name"] == "libbomb.so" for h in hashes)


def test_native_lib_hashes_rejects_malformed_sha256() -> None:
    """★P2 无修复即失败：meta 里 sha256 非 64 位十六进制（截断/非 hex/占位）→ 丢弃，不造假候选簇。

    修前只判 `if sha`（任意非空串即收录），坏/导入的旧报告能凭 "deadbeef" 这类串造出假簇。断言坏形状被丢、
    负 size 归 None，修前必失败。
    """
    report = {"meta": {"native_lib_hashes": [
        {"name": "good.so", "sha256": _sha(_SO_A), "size": len(_SO_A)},
        {"name": "trunc.so", "sha256": "deadbeef", "size": 10},   # 太短（8 位）
        {"name": "nonhex.so", "sha256": "z" * 64, "size": 10},     # 64 位但非十六进制
        {"name": "neg.so", "sha256": _sha(_SO_B), "size": -5},     # 合法 sha 但 size 负
    ]}}
    out = corpus._native_lib_hashes(report)
    shas = {h["sha256"] for h in out}
    assert _sha(_SO_A) in shas
    assert "deadbeef" not in shas and "z" * 64 not in shas  # 坏形状丢弃
    neg = next(h for h in out if h["sha256"] == _sha(_SO_B))
    assert neg["size"] is None  # 负 size 归 None


def _entry(sample_sha: str, *so_bytes: bytes) -> dict:
    """构造一条 manifest 记录（经 manifest_entry，模拟报告有 native_lib_hashes）。"""
    report = {
        "meta": {"sample_sha256": sample_sha, "native_lib_hashes": [
            {"name": f"lib{i}.so", "sha256": _sha(b), "size": len(b)} for i, b in enumerate(so_bytes)
        ]},
    }
    return corpus.manifest_entry(report)


def test_manifest_entry_records_native_lib_hashes() -> None:
    e = _entry("aaa", _SO_A, _SO_B)
    shas = {h["sha256"] for h in e["native_lib_hashes"]}
    assert shas == {_sha(_SO_A), _sha(_SO_B)}


def test_find_by_so_sha256_returns_matching_candidates() -> None:
    """同一 .so SHA-256 的两条记录 + 一条不匹配记录 → 只召回前两条候选。"""
    entries = [_entry("s1", _SO_A, _SO_B), _entry("s2", _SO_A), _entry("s3", _SO_B)]
    hits = corpus.find_by_native_lib(entries, _sha(_SO_A))
    samples = sorted(e["sample_sha256"] for e in hits)
    assert samples == ["s1", "s2"]  # s3 无 _SO_A，不命中


def test_find_by_so_sha256_case_insensitive_and_empty() -> None:
    entries = [_entry("s1", _SO_A)]
    assert corpus.find_by_native_lib(entries, _sha(_SO_A).upper())  # 大小写归一
    assert corpus.find_by_native_lib(entries, "") == []


def test_find_by_native_name_is_candidate_recall_not_hash_equivalence() -> None:
    """同名、不同字节的 .so 都会命中兼容查询，因此名称结果只能是候选召回。"""
    entries = [
        _named_entry("s1", ("libshared.so", _SO_A)),
        _named_entry("s2", ("libshared.so", _SO_B)),
    ]
    hits = corpus.find_by_native_lib(entries, "libshared.so")
    assert sorted(entry["sample_sha256"] for entry in hits) == ["s1", "s2"]
    assert len({entry["native_lib_hashes"][0]["sha256"] for entry in hits}) == 2


def test_shared_native_libs_groups_matching_candidates() -> None:
    """跨样本同一 .so SHA-256 被 ≥2 样本引用 → 形成待复核候选簇。"""
    entries = [_entry("s1", _SO_A), _entry("s2", _SO_A), _entry("s3", _SO_B)]
    clusters = corpus.shared_native_libs(entries)
    core = [c for c in clusters if c["sha256"] == _sha(_SO_A)]
    assert core and core[0]["samples"] == ["s1", "s2"]
    assert not any(c["sha256"] == _sha(_SO_B) for c in clusters)  # _SO_B 仅 1 样本，不成簇


def _named_entry(sample_sha: str, *libs: tuple[str, bytes]) -> dict:
    """同 ``_entry`` 但可指定 .so 库名（降噪判据看的是名字，不是字节）。"""
    report = {
        "meta": {
            "sample_sha256": sample_sha,
            "native_lib_hashes": [
                {"name": name, "sha256": _sha(blob), "size": len(blob)} for name, blob in libs
            ],
        },
    }
    return corpus.manifest_entry(report)


# 取自 rules/packers.yaml 的 so_names（真源，不另建名单）；改规则会让这些测试变红=正确的耦合。
_PACKER_SO = "libDexHelper.so"          # 梆梆加固
_PACKER_SO_PREFIX = "libnllvm1665488792.so"  # 百度加固：规则写前缀 libnllvm，随机数字后缀
_SDK_SO = "libhermes.so"                # React Native 引擎，随 SDK 继承


def test_native_anchor_weakness_names_packer_and_sdk() -> None:
    """★判据可命名：加固壳 → ``packer:<产品名>``；第三方 SDK → ``third-party-sdk``；业务库 → None。"""
    packer = corpus.native_anchor_weakness(_PACKER_SO)
    assert packer is not None and packer.startswith("packer:")
    assert packer != "packer:"  # 必须带得出产品名，不能是空壳标签
    assert corpus.native_anchor_weakness(_SDK_SO) == "third-party-sdk"
    assert corpus.native_anchor_weakness("libclientcore.so") is None
    assert corpus.native_anchor_weakness("") is None
    policy = corpus.native_anchor_policy_snapshot()
    assert policy["status"] == "complete"
    assert len(policy["packer_so_names"]) > 0
    assert "libapp.so" in policy["app_own_code_libs"]
    assert "libhermes" in policy["benign_substrings"]


def test_business_code_container_is_not_downgraded_as_third_party() -> None:
    """本应用自己的业务代码容器是较高特异性的候选，不能被第三方名单误降噪。

    Flutter 的 libapp.so、Unity 的 libil2cpp.so 装着这个 App 的全部业务逻辑。
    两份样本共享同一份逐字节相同的业务代码容器，比共享框架运行时更具体，但仍须排除
    公开构建产物与重打包继承，不能单独认定家族或主体。

    这里踩过的坑：第三方名单按**子串**匹配，而 "libil2cpp" 就在名单里（它在那儿服务的是
    另一个用途——给扫描器划定输入范围）。同一张表被两处消费、目的相反，串案这一侧必须
    按自己的口径先行豁免。

    ★变异验证：删掉 native_anchor_weakness 里的 is_app_own_code 豁免，本测试必红。
    """
    for own in ("libil2cpp.so", "libapp.so", "lib/arm64-v8a/libil2cpp.so"):
        assert corpus.native_anchor_weakness(own) is None, (
            f"{own} 被当第三方降噪了——Unity/Flutter 业务代码候选会被丢弃"
        )
    # 与之相对：框架**引擎**库仍是第三方，照旧降噪。
    assert corpus.native_anchor_weakness("libunity.so") == "third-party-sdk"
    assert corpus.native_anchor_weakness("libflutter.so") == "third-party-sdk"


def test_app_so_paths_keeps_business_code_containers() -> None:
    """★★分析器要读得到 Unity/Flutter 的业务代码容器。

    ``app_so_paths`` 的白名单按**子串**匹配，而 "libil2cpp" 在表里（它在那儿是为了排除
    引擎运行时）。照子串滤掉，api_surface / build_provenance / native_config_channel
    这几个分析器就**从来没读过** Unity 样本的业务代码——端点、构建路径、控制面全在
    那个文件里。

    ★变异验证：删掉 app_so_paths 里的 is_app_own_code 豁免，本测试必红。
    """
    from apkscan.analyzers._common import app_so_paths

    class _Ctx:
        def native_libs(self):
            return ["lib/arm64-v8a/libil2cpp.so", "lib/arm64-v8a/libunity.so",
                    "lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so",
                    "lib/arm64-v8a/libbiz.so"]

        def list_files(self):
            return []

    got = {p.rsplit("/", 1)[-1] for p in app_so_paths(_Ctx(), "test")}
    assert "libil2cpp.so" in got, "Unity 的业务代码容器被当第三方滤掉了"
    assert "libapp.so" in got, "Flutter 的业务代码容器被滤掉了"
    assert "libbiz.so" in got
    # 引擎运行时仍该排除——豁免只针对业务代码容器，不是把白名单整个放开。
    assert "libunity.so" not in got and "libflutter.so" not in got


def test_native_anchor_weakness_normalizes_path_and_case() -> None:
    """APK 里 .so 带 ABI 目录前缀；库名大小写不一 → 都要归一到 basename 小写再判。"""
    assert corpus.native_anchor_weakness(f"lib/arm64-v8a/{_PACKER_SO}") is not None
    assert corpus.native_anchor_weakness(_PACKER_SO.upper()) is not None
    assert corpus.native_anchor_weakness(f"lib\\armeabi-v7a\\{_PACKER_SO}") is not None
    # 规则里写成不带 .so 的前缀式（libnllvm*）也要认
    assert corpus.native_anchor_weakness(_PACKER_SO_PREFIX) is not None


def test_shared_native_libs_annotates_packer_and_keeps_specific_candidate_first() -> None:
    """加固壳簇标 weak_anchor，未命名为通用组件的业务候选排在其前。"""
    packer_blob = b"\x7fELF" + b"packer-runtime" * 30
    entries = [
        _named_entry("s1", ("libclientcore.so", _SO_A), (_PACKER_SO, packer_blob)),
        _named_entry("s2", ("libclientcore.so", _SO_A), (_PACKER_SO, packer_blob)),
        _named_entry("s3", (_PACKER_SO, packer_blob)),  # 第三个不相干样本也用同款加固
    ]
    clusters = corpus.shared_native_libs(entries)

    business = next(c for c in clusters if c["sha256"] == _sha(_SO_A))
    assert business["weak_anchor"] is False
    assert business["weak_anchor_reason"] is None

    packer = next(c for c in clusters if c["sha256"] == _sha(packer_blob))
    assert packer["weak_anchor"] is True
    assert packer["weak_anchor_reason"].startswith("packer:")
    # ★标注而非删除：共享事实仍在（多个样本都列出），但不升级成家族或主体结论
    assert packer["samples"] == ["s1", "s2", "s3"]

    # 弱锚沉底：加固壳簇样本更多（3>2），若只按样本数排会排在前面
    assert clusters[0]["sha256"] == _sha(_SO_A)
    assert clusters[-1]["sha256"] == _sha(packer_blob)


def test_shared_native_libs_annotates_third_party_sdk() -> None:
    sdk_blob = b"\x7fELF" + b"rn-engine" * 40
    entries = [_named_entry("s1", (_SDK_SO, sdk_blob)), _named_entry("s2", (_SDK_SO, sdk_blob))]
    cluster = corpus.shared_native_libs(entries)[0]
    assert cluster["weak_anchor"] is True and cluster["weak_anchor_reason"] == "third-party-sdk"


def test_shared_native_libs_degrades_when_rules_unavailable(monkeypatch) -> None:
    """规则加载失败 → 不标注（宁可少标注也不误标），且不抛。"""
    corpus._packer_so_names.cache_clear()

    def _boom(*_a, **_k):
        raise OSError("boom")

    monkeypatch.setattr("apkscan.core.registry.load_rules", _boom)
    try:
        assert corpus.native_anchor_weakness(_PACKER_SO) is None
        assert corpus.native_anchor_policy_snapshot()["status"] == "partial"
        packer_blob = b"\x7fELF" + b"packer-runtime" * 30
        entries = [_named_entry("s1", (_PACKER_SO, packer_blob)),
                   _named_entry("s2", (_PACKER_SO, packer_blob))]
        assert corpus.shared_native_libs(entries)[0]["weak_anchor"] is False
    finally:
        corpus._packer_so_names.cache_clear()  # 别把空 mapping 留给后续测试


def test_shared_native_libs_classification_is_input_order_independent() -> None:
    """★同一 sha 被多个样本用**不同库名**登记时，分类结果不得随输入顺序变化。

    真实场景：同一份 .so 在一个样本里叫业务名、在另一个样本里被改名成壳名（重打包/改名
    对抗），于是一个 sha 对应多个观测名。若分类取"第一个见到的名字"，那么 manifest 的
    入库顺序（= 谁先 corpus add）就会决定这簇是否命中弱锚标注 —— 同一份证据两次运行给出
    相反结论，这类不确定性在串案里是直接的误判源。

    判据：把 entries 正序与逆序各跑一遍，``name`` / ``weak_anchor`` / ``weak_anchor_reason``
    必须逐字段相同（把"取首个名字"改回去 → 本测试必红）。
    """
    shared_blob = b"\x7fELF" + b"renamed-shared" * 30
    forward = [
        _named_entry("s1", ("libclientcore.so", shared_blob)),
        _named_entry("s2", (_PACKER_SO, shared_blob)),
        _named_entry("s3", (_SDK_SO, shared_blob)),
    ]
    backward = list(reversed(forward))

    first = corpus.shared_native_libs(forward)
    second = corpus.shared_native_libs(backward)

    assert len(first) == 1 and len(second) == 1
    for field in ("sha256", "name", "weak_anchor", "weak_anchor_reason", "samples"):
        assert first[0][field] == second[0][field], field
    # 名字冲突时判据必须给出**可解释**的确定结果：加固壳优先（最强的降噪理由）。
    assert first[0]["weak_anchor"] is True
    assert first[0]["weak_anchor_reason"].startswith("packer:")


def test_shared_native_libs_order_independent_when_only_one_name_is_weak() -> None:
    """业务名 + 第三方 SDK 名混登同一 sha：无论顺序，都必须给同一个（降噪）结论。

    与上一条的区别是这里没有加固壳名参与排序，验证"弱锚理由的选取"本身也不看输入顺序。
    """
    shared_blob = b"\x7fELF" + b"sdk-or-business" * 25
    forward = [
        _named_entry("s1", (_SDK_SO, shared_blob)),
        _named_entry("s2", ("libclientcore.so", shared_blob)),
    ]
    first = corpus.shared_native_libs(forward)[0]
    second = corpus.shared_native_libs(list(reversed(forward)))[0]

    assert first == second
    assert first["weak_anchor"] is True and first["weak_anchor_reason"] == "third-party-sdk"


def test_shared_native_libs_missing_name_is_not_weak() -> None:
    """库名缺失 → 无从命名判据，不得凭空标弱（未知≠弱锚）。"""
    entries = [
        corpus.manifest_entry({"meta": {"sample_sha256": "s1", "native_lib_hashes": [
            {"name": "", "sha256": _sha(_SO_A), "size": 1}]}}),
        corpus.manifest_entry({"meta": {"sample_sha256": "s2", "native_lib_hashes": [
            {"name": "", "sha256": _sha(_SO_A), "size": 1}]}}),
    ]
    cluster = corpus.shared_native_libs(entries)[0]
    assert cluster["name"] is None
    assert cluster["weak_anchor"] is False and cluster["weak_anchor_reason"] is None


def test_corpus_cli_help_marks_shared_values_as_candidates() -> None:
    """用户可见 help 必须阻止把共享证书、配置或 native 命中直接升级为归属结论。"""
    from typer.testing import CliRunner

    from apkscan import cli

    runner = CliRunner()
    seen = runner.invoke(cli.app, ["corpus", "seen", "--help"])
    shared_native = runner.invoke(cli.app, ["corpus", "shared-native", "--help"])
    shared_config = runner.invoke(cli.app, ["corpus", "shared-config", "--help"])
    assert seen.exit_code == shared_native.exit_code == shared_config.exit_code == 0

    seen_help = " ".join(seen.stdout.split())
    native_help = " ".join(shared_native.stdout.split())
    config_help = " ".join(shared_config.stdout.split())
    assert "命中只做候选召回" in seen_help
    assert "不能单独认定同一家族或主体" in seen_help
    assert "供关联候选召回" in native_help
    assert "weak_anchor=false" in native_help
    assert "不代表已确认家族或主体" in native_help
    assert "不能单独认定同一家族或主体" in config_help
    assert "家族级硬指纹" not in seen_help + native_help


def test_cli_seen_by_so_sha256(tmp_path) -> None:
    """CLI 端到端：corpus seen --by so_sha256 只召回哈希匹配候选。"""
    import json

    from typer.testing import CliRunner

    from apkscan import cli

    def _report(sample: str, so_bytes: bytes) -> dict:
        return {
            "schema_version": "1.0", "analysis_status": "complete", "completeness": 1.0,
            "package_name": "com.x",
            "meta": {"sample_sha256": sample, "tool_version": "0.9.0", "ruleset_digest": "dd",
                     "native_lib_hashes": [{"name": "libclientcore.so", "sha256": _sha(so_bytes),
                                            "size": len(so_bytes)}]},
            "leads": [], "endpoints": [], "findings": [],
        }

    runner = CliRunner()
    corpus_dir = tmp_path / "corpus"
    for sha, blob in (("fam1", _SO_A), ("fam2", _SO_A), ("other", _SO_B)):
        rp = tmp_path / f"{sha}.json"
        rp.write_text(json.dumps(_report(sha, blob)), encoding="utf-8")
        add = runner.invoke(cli.app, ["corpus", "add", str(rp), "--case", "c1", "--corpus", str(corpus_dir)])
        assert add.exit_code == 0, add.stdout

    seen = runner.invoke(
        cli.app, ["corpus", "seen", _sha(_SO_A), "--by", "so_sha256", "--corpus", str(corpus_dir)])
    assert seen.exit_code == 0, seen.stdout
    payload = json.loads(seen.stdout)
    assert payload["seen"] is True and payload["count"] == 2  # fam1 + fam2，不含 other

    # ★shared-native：同一 .so 字节被 2 样本共享 → 待复核候选簇
    shared = runner.invoke(cli.app, ["corpus", "shared-native", "--corpus", str(corpus_dir)])
    assert shared.exit_code == 0, shared.stdout
    clusters = json.loads(shared.stdout)["clusters"]
    core = next(c for c in clusters if c["sha256"] == _sha(_SO_A))
    assert sorted(core["samples"]) == ["fam1", "fam2"]

    # ★拼错 --by 拒跑（exit 2），且错误信息里列出 so_sha256（help 完整、不静默假阴性）
    bad = runner.invoke(cli.app, ["corpus", "seen", "x", "--by", "so_sh256", "--corpus", str(corpus_dir)])
    assert bad.exit_code == 2
    assert "so_sha256" in bad.stdout + str(bad.stderr or "")


def test_cli_shared_native_surfaces_weak_anchor(tmp_path) -> None:
    """★降噪信号必须走到消费方：weak_anchor / weak_anchor_reason 要出现在 CLI 的 JSON 里。

    只在 core 函数里算出来不算做完——``corpus shared-native`` 是唯一生产消费方，
    字段没渲染出去，看报告的人可能把加固壳簇误作高特异性候选。
    """
    import json

    from typer.testing import CliRunner

    from apkscan import cli

    packer_blob = b"\x7fELF" + b"packer-runtime" * 30

    def _report(sample: str, libs: list[tuple[str, bytes]]) -> dict:
        return {
            "schema_version": "1.0", "analysis_status": "complete", "completeness": 1.0,
            "package_name": "com.x",
            "meta": {"sample_sha256": sample, "tool_version": "0.9.0", "ruleset_digest": "dd",
                     "native_lib_hashes": [
                         {"name": n, "sha256": _sha(b), "size": len(b)} for n, b in libs]},
            "leads": [], "endpoints": [], "findings": [],
        }

    runner = CliRunner()
    corpus_dir = tmp_path / "corpus"
    # ★w3 只带加固壳：让加固壳簇(3 样本)比真业务簇(2 样本)**更大**——这正是要降噪的现实形态
    # （同款加固的无关样本越多，假簇越显眼）。也使「弱锚沉底」只能靠 weak_anchor 排序键成立：
    # 若只按样本数降序，加固壳簇会排在最前，末位断言必红。
    fixtures = {
        "w1": [("libclientcore.so", _SO_A), (_PACKER_SO, packer_blob)],
        "w2": [("libclientcore.so", _SO_A), (_PACKER_SO, packer_blob)],
        "w3": [(_PACKER_SO, packer_blob)],
    }
    for sha, libs in fixtures.items():
        rp = tmp_path / f"{sha}.json"
        rp.write_text(json.dumps(_report(sha, libs)), encoding="utf-8")
        add = runner.invoke(cli.app, ["corpus", "add", str(rp), "--case", "c1", "--corpus", str(corpus_dir)])
        assert add.exit_code == 0, add.stdout

    res = runner.invoke(cli.app, ["corpus", "shared-native", "--corpus", str(corpus_dir)])
    assert res.exit_code == 0, res.stdout
    clusters = json.loads(res.stdout)["clusters"]

    packer = next(c for c in clusters if c["sha256"] == _sha(packer_blob))
    assert packer["weak_anchor"] is True
    assert packer["weak_anchor_reason"].startswith("packer:")
    business = next(c for c in clusters if c["sha256"] == _sha(_SO_A))
    assert business["weak_anchor"] is False and business["weak_anchor_reason"] is None
    # 加固壳簇样本更多却仍排末位 → 沉底靠的是 weak_anchor，不是样本数
    assert len(packer["samples"]) > len(business["samples"])
    assert clusters[-1]["sha256"] == _sha(packer_blob)
