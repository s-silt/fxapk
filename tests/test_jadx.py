"""JadxAnalyzer 测试：mock proctree.run_owned（不真跑 jadx），覆盖成功 / 超时 / 非零 / 无 apk_path，
以及 coverage receipt（B2：Java 面 complete 契约、确定性截断、cleanup 受检）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkscan.analyzers import jadx
from apkscan.analyzers.jadx import JadxAnalyzer
from apkscan.core import proctree
from tests.conftest import FakeContext


@pytest.fixture(autouse=True)
def _stub_resolve_jadx(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认把 tools.resolve_jadx 桩成「裸 jadx、无额外 env」，使既有用例只关注执行行为。
    需要测 resolve_jadx 解析/JAVA_HOME 注入的用例各自覆盖此桩。"""
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: (["jadx"], {}))


def _ctx(tmp_path: Path) -> FakeContext:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    return FakeContext(apk_path=str(apk))


def _owned(
    returncode: int | None = 0,
    *,
    timed_out: bool = False,
    ownership: bool = True,
    terminated: bool = True,
    forced: bool = False,
    stderr: str = "",
    reasons: tuple[str, ...] = (),
) -> proctree.OwnedRun:
    return proctree.OwnedRun(
        returncode=None if timed_out else returncode, stdout="", stderr=stderr,
        timed_out=timed_out, ownership_complete=ownership,
        termination_complete=terminated, forced_tree_kill=forced,
        reason_codes=tuple(sorted(set(reasons))),
    )


def _patch_run_owned(monkeypatch: pytest.MonkeyPatch, handler) -> list[dict]:  # noqa: ANN001
    """把 jadx 的 proctree.run_owned 换成受控替身，记录每次调用的 cmd/timeout/env。"""
    calls: list[dict] = []

    def _run(cmd, *, timeout, env=None):  # noqa: ANN001
        calls.append({"cmd": list(cmd), "timeout": timeout, "env": env})
        return handler(cmd)

    monkeypatch.setattr(jadx.proctree, "run_owned", _run)
    return calls


def _writes(java_body: str, returncode: int = 0, stderr: str = ""):
    """替身 handler：把 java_body 写进 jadx 的 -d 输出目录后返回对应结局。"""

    def _handler(cmd):  # noqa: ANN001
        out_dir = Path(cmd[cmd.index("-d") + 1])
        pkg = out_dir / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "C.java").write_text(java_body, encoding="utf-8")
        return _owned(returncode, stderr=stderr)

    return _handler


def _java_vis(meta: dict) -> str:
    """按 visibility 消费端口径求 java 面档位（消费端接线由 test_pipeline_stages 锁真入口）。"""
    from apkscan.core import visibility

    return visibility.assess({"meta": dict(meta)})["sources"]["java"]["visibility"]


def test_no_apk_path_still_writes_failclosed_receipt() -> None:
    """无 apk_path 早退也产 receipt（complete=False）：「每次 analyze 都有 jadx_receipt」
    无例外，visibility 的 receipt 通道识别 no_apk_path → unavailable。"""
    result = JadxAnalyzer().analyze(FakeContext(apk_path=""))
    receipt = result.meta["jadx_receipt"]
    assert receipt["status"] == "no_apk_path"
    assert receipt["complete"] is False
    assert receipt["runs"] == []
    assert _java_vis(result.meta) == "unavailable"


def test_no_apk_path_skips_cleanly() -> None:
    result = JadxAnalyzer().analyze(FakeContext())
    assert result.meta["jadx_status"] == "no_apk_path"
    assert result.endpoints == []
    assert result.findings == []
    # 优雅跳过：记 error 文案但不抛。
    assert result.error == "无 apk_path，跳过 jadx 反编译"


def test_extracts_endpoint_and_secret(monkeypatch, tmp_path) -> None:
    java = (
        'public class C {\n'
        '  String url = "https://c2.jadx-found.cn/api/report";\n'
        '  String app_secret = "Abc123Xyz789Def456";\n'  # leak-scan: allow 反编译输出夹具，模拟被检出的硬编码凭据，值为合成串
        '  int n = obj.length;  // 不应被当域名\n'
        '}\n'
    )
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_status"] == "ok"
    assert result.error is None
    vals = {e.value for e in result.endpoints}
    assert "https://c2.jadx-found.cn/api/report" in vals
    assert "c2.jadx-found.cn" in vals  # URL host 也抽成 domain 端点
    assert "obj.length" not in vals  # 代码片段不误判
    assert any(f.category == "secret" for f in result.findings)
    assert result.meta["jadx_endpoint_count"] >= 2


def test_clean_run_receipt_complete(monkeypatch, tmp_path) -> None:
    """★B2 契约正例：干净单次执行 + 枚举/读取/清理全成 → receipt.complete=True（Java 面完整覆盖
    的唯一凭据），visibility 才给 complete 档。"""
    java = 'class A { String u = "https://clean.example.com/x"; }'
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    receipt = result.meta["jadx_receipt"]
    assert receipt["complete"] is True
    assert receipt["reason_codes"] == []
    assert receipt["cleanup"] == {"complete": True, "reason_codes": []}
    assert len(receipt["runs"]) == 1
    scan = receipt["scan"]
    assert scan["files_total"] == scan["files_scanned"] == 1
    assert scan["read_failed"] == 0 and scan["truncated_files"] == 0
    assert scan["bytes_scanned"] == scan["bytes_total"] > 0
    assert not scan["scan_limit_hit"]
    assert scan["selected_paths_digest"].startswith("sha256:")
    assert _java_vis(result.meta) == "complete"


def test_timeout_records_status_not_crash(monkeypatch, tmp_path) -> None:
    def _handler(cmd):  # noqa: ANN001 — 超时被终止：无任何产物
        Path(cmd[cmd.index("-d") + 1]).mkdir(parents=True, exist_ok=True)
        return _owned(timed_out=True, reasons=("timeout",))

    _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "timeout"
    assert result.error is None  # 超时不抛，按无产物继续（端点为空）
    assert result.endpoints == []
    receipt = result.meta["jadx_receipt"]
    assert receipt["complete"] is False
    assert "producer_timeout" in receipt["reason_codes"]


def test_timeout_keeps_partial_positives(monkeypatch, tmp_path) -> None:
    """★B2 partial 阳性保留：超时前已产出的 .java 照扫，端点保留；只有穷尽性资格被挡
    （java=timeout），阳性发现不受影响。"""
    java = 'class A { String u = "https://half-done.example.com/x"; }'

    def _handler(cmd):  # noqa: ANN001
        _writes(java)(cmd)  # 先写出部分产物
        return _owned(timed_out=True, reasons=("timeout",))

    _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "timeout"
    assert any(e.value == "https://half-done.example.com/x" for e in result.endpoints)
    assert result.meta["jadx_receipt"]["complete"] is False
    assert _java_vis(result.meta) == "timeout"


def test_nonzero_exit_still_scans_partial_output(monkeypatch, tmp_path) -> None:
    java = 'class A { String u = "http://gw.evil-jadx.vip/x"; }'
    _patch_run_owned(monkeypatch, _writes(java, returncode=1, stderr="some classes failed"))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "partial"
    assert any(e.value == "http://gw.evil-jadx.vip/x" for e in result.endpoints)


def test_ownership_failure_fails_closed(monkeypatch, tmp_path) -> None:
    """★进程树所有权（Job assign / spawn）建立失败 → fail closed：按 failed 定性、不算覆盖。"""
    _patch_run_owned(
        monkeypatch,
        lambda cmd: _owned(
            None, ownership=False, reasons=("job_assignment_failed",)
        ),
    )
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "failed"
    receipt = result.meta["jadx_receipt"]
    assert receipt["complete"] is False
    assert "ownership_incomplete" in receipt["reason_codes"]
    assert _java_vis(result.meta) == "failed"


def test_forced_tree_kill_downgrades_ok_to_partial(monkeypatch, tmp_path) -> None:
    """退出码 0 但留了后代被强杀 → 产物可能被腰斩，按 partial 计，不许读成全部成功。"""
    java = 'class A { String u = "https://survivor.example.com/x"; }'

    def _handler(cmd):  # noqa: ANN001
        _writes(java)(cmd)
        return _owned(0, forced=True, reasons=("descendants_after_root_exit",))

    _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_status"] == "partial"
    assert "descendants_after_root_exit" in result.meta["jadx_receipt"]["reason_codes"]


def test_requires_jadx_capability() -> None:
    # requires 声明 jadx，pipeline 在无 jadx 能力时会 skipped（此处仅断言声明）。
    assert JadxAnalyzer().requires == ["jadx", "apk"]


# --- 脱壳 dump 的额外 DEX 一并喂给 jadx 反编译 -----------------------------


def _dump_dex(tmp_path: Path, names: list[str]) -> list[str]:
    """在 tmp 下造几个占位 .dex 文件（内容不必是合法 DEX，只测路径接线）。"""
    dump = tmp_path / "dump"
    dump.mkdir(exist_ok=True)
    out: list[str] = []
    for n in names:
        p = dump / n
        p.write_bytes(b"dex\n035\x00" + b"\x00" * 32)
        out.append(str(p))
    return out


def test_extra_dex_paths_fed_to_jadx(monkeypatch, tmp_path) -> None:
    """★核心接线：脱壳 dump 的额外 DEX 必须作为额外输入喂给 jadx。

    不喂进来，加固样本只反编译出壳桩（jadx_java_files 停在个位数），真实代码仅以字符串池可见。
    同时锁：dump DEX 存在时关 checksum 校验（内存 dump 的 DEX checksum 与磁盘态不一致会被拒载），
    且超时按 dex 数量伸缩、由 analyzer 自己交给 run_owned 执行（自有 deadline）。
    """
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    dex_paths = _dump_dex(tmp_path, ["classes.dex", "classes02.dex"])
    ctx = FakeContext(apk_path=str(apk), extra_dex_paths=dex_paths)

    calls = _patch_run_owned(monkeypatch, _writes("class A {}"))
    JadxAnalyzer().analyze(ctx)

    cmd = calls[0]["cmd"]
    for p in dex_paths:
        assert p in cmd, "dump DEX 未作为 jadx 输入——加固样本只会反编译出壳桩"
    assert "-Pdex-input.verify-checksum=no" in cmd, "未关 checksum 校验，内存 dump DEX 会被拒载"
    # 2 个额外 dex → 超时 300 + 2*30 = 360，且作为自有 deadline 传给 run_owned
    assert calls[0]["timeout"] == jadx._TIMEOUT + 2 * jadx._TIMEOUT_PER_EXTRA_DEX


def test_extra_dex_paths_fed_to_jadx_through_snapshot(monkeypatch, tmp_path) -> None:
    """★消费方 × 真实快照类型：android APK 的短批次走并行，jadx 在 long lane 拿到的仍是同一
    ctx 类型契约。曾漏带 extra_dex_paths：消费方 getattr 兜底静默退化成空列表，串行单测
    （FakeContext 自带字段）全绿、实际使用路径 jadx 拿到 0 个 dump DEX。本测把消费方直接钉在
    build_snapshot 的产物上，快照再漏字段立即变红。"""
    from apkscan.core.snapshot import build_snapshot

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    dex_paths = _dump_dex(tmp_path, ["classes.dex", "classes02.dex"])
    snap = build_snapshot(FakeContext(apk_path=str(apk), extra_dex_paths=dex_paths))

    calls = _patch_run_owned(monkeypatch, _writes("class A {}"))
    JadxAnalyzer().analyze(snap)

    cmd = calls[0]["cmd"]
    for p in dex_paths:
        assert p in cmd, "dump DEX 未穿过快照边界喂给 jadx——并行（默认）路径静默失效"
    assert "-Pdex-input.verify-checksum=no" in cmd


def test_no_extra_dex_keeps_base_invocation(monkeypatch, tmp_path) -> None:
    """无额外 DEX → 命令与超时回落原样（普通 APK 路径零改动、不误加 checksum 开关）。"""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    ctx = FakeContext(apk_path=str(apk))  # 无 extra_dex_paths

    calls = _patch_run_owned(monkeypatch, _writes("class A {}"))
    JadxAnalyzer().analyze(ctx)

    assert "-Pdex-input.verify-checksum=no" not in calls[0]["cmd"]
    assert calls[0]["timeout"] == jadx._TIMEOUT
    # 仅原 APK 一个输入（末位是 apk 路径）
    assert calls[0]["cmd"][-1].endswith("app.apk")


def test_nonexistent_extra_dex_paths_filtered(monkeypatch, tmp_path) -> None:
    """不存在的额外 DEX 路径被剔除，不让单个坏路径把 jadx 整体拖成非零退出。"""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    ctx = FakeContext(apk_path=str(apk), extra_dex_paths=[str(tmp_path / "nope.dex")])

    calls = _patch_run_owned(monkeypatch, _writes("class A {}"))
    JadxAnalyzer().analyze(ctx)

    assert "nope.dex" not in " ".join(calls[0]["cmd"])
    assert "-Pdex-input.verify-checksum=no" not in calls[0]["cmd"]  # 无有效额外 dex
    assert calls[0]["timeout"] == jadx._TIMEOUT


def _make_dex(path: Path, *, good: bool) -> str:
    """造最小合成 DEX：magic + checksum 头 + 零负载。good 控制 Adler32 头校验和是否与正文一致。"""
    import struct
    import zlib

    data = bytearray(b"dex\n035\x00" + b"\x00\x00\x00\x00" + b"\x00" * 64)
    if good:
        struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
    else:
        struct.pack_into("<I", data, 8, 0xDEADBEEF)  # 必与正文 Adler32 不符
    path.write_bytes(bytes(data))
    return str(path)


def test_wipeout_with_bad_dex_triggers_filtered_retry(monkeypatch, tmp_path) -> None:
    """★损坏 dump DEX 拖垮 jadx（载入期 OOM 崩、0 产出）→ 剔除坏 checksum DEX 降级重跑。

    实测（真实加固样本）：头体不一致的坏 DEX 在场时 jadx 整体 0 产出，比不喂 dump 还差；
    重跑只喂好 DEX 能把产出救回来。同时锁「如实体现部分丢失」：状态不许报 ok、被剔除的
    DEX 以 basename 落 meta.jadx_bad_dex_excluded；两次执行的 options_digest 必须可辨
    （重跑输入集已缩小，receipt 里不得被误当同一输入的重复执行）。
    """
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    good = _make_dex(tmp_path / "classes.dex", good=True)
    bad = _make_dex(tmp_path / "classes02.dex", good=False)
    ctx = FakeContext(apk_path=str(apk), extra_dex_paths=[good, bad])

    java = 'class A { String u = "https://rescued.example.com/x"; }'
    seen: list[list[str]] = []

    def _handler(cmd):  # noqa: ANN001
        seen.append(list(cmd))
        out_dir = Path(cmd[cmd.index("-d") + 1])
        if len(seen) == 1:
            # 首跑：坏 DEX 让 jadx 载入期崩溃——非零退出、一个 .java 都没写出来。
            out_dir.mkdir(parents=True, exist_ok=True)
            return _owned(1, stderr="OutOfMemoryError")
        return _writes(java)(cmd)

    _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(ctx)

    assert len(seen) == 2, "0 产出 + 坏 checksum DEX 在场必须降级重跑"
    assert bad not in seen[1], "重跑必须剔除坏 checksum DEX——它就是拖垮首跑的元凶"
    assert good in seen[1], "重跑必须保留好 DEX——降级是救好 DEX 的产出，不是全放弃"
    # ★重跑写进全新输出目录：不复用首跑目录，杜绝首跑残留混进重跑产物的污染窗口。
    assert seen[0][seen[0].index("-d") + 1] != seen[1][seen[1].index("-d") + 1]
    # 两个目录都被受检清理收口（合并 cleanup receipt 仍 complete）。
    assert result.meta["jadx_receipt"]["cleanup"] == {"complete": True, "reason_codes": []}
    assert any(e.value == "https://rescued.example.com/x" for e in result.endpoints)
    assert result.meta["jadx_java_files"] == 1
    # 剔除即部分丢失：即使重跑干净退出也不报 ok，且剔了什么在 meta 里可见。
    assert result.meta["jadx_status"] == "partial"
    assert result.meta["jadx_bad_dex_excluded"] == ["classes02.dex"]
    # ★options_digest 区分两次执行参数：重跑剔了坏 DEX → 输入身份不同 → 摘要必不同。
    runs = result.meta["jadx_receipt"]["runs"]
    assert len(runs) == 2 and runs[1]["degraded_rerun"] is True
    assert runs[0]["options_digest"] != runs[1]["options_digest"]
    assert "degraded_rerun" in result.meta["jadx_receipt"]["reason_codes"]


def test_partial_output_with_bad_dex_no_retry(monkeypatch, tmp_path) -> None:
    """首跑有产出（非零退出但部分成功）→ 不重跑：checksum 不符也可能只是 dump 后过期、
    jadx 已正常反编译（这正是 verify-checksum=no 的意义），重跑剔除反而丢信息。"""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    bad = _make_dex(tmp_path / "classes.dex", good=False)
    ctx = FakeContext(apk_path=str(apk), extra_dex_paths=[bad])

    java = 'class A { String u = "https://kept.example.com/x"; }'
    calls = _patch_run_owned(monkeypatch, _writes(java, returncode=1, stderr="some classes failed"))
    result = JadxAnalyzer().analyze(ctx)

    assert len(calls) == 1, "有产出就不重跑——过期 checksum 的有效 dump 不能被剔除"
    assert result.meta["jadx_status"] == "partial"
    assert "jadx_bad_dex_excluded" not in result.meta


def test_wipeout_without_bad_dex_no_retry(monkeypatch, tmp_path) -> None:
    """0 产出但额外 DEX checksum 全好 → 无可剔除，不空转重跑（输入不变重跑没有意义）。"""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04placeholder")
    good = _make_dex(tmp_path / "classes.dex", good=True)
    ctx = FakeContext(apk_path=str(apk), extra_dex_paths=[good])

    def _handler(cmd):  # noqa: ANN001
        Path(cmd[cmd.index("-d") + 1]).mkdir(parents=True, exist_ok=True)
        return _owned(1, stderr="boom")

    calls = _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(ctx)

    assert len(calls) == 1
    assert result.meta["jadx_status"] == "partial"
    assert "jadx_bad_dex_excluded" not in result.meta


def test_scan_truncation_flagged_in_meta(monkeypatch, tmp_path) -> None:
    """撞 _MAX_JAVA_FILES 上限 → meta.jadx_scan_truncated=True：与 jadx 进程的 partial/timeout
    正交，读报告的人才能分清「恰好 N 个文件」与「截断于 N 个」。未截断则不落此键。
    同时锁 B2：撞上限 → receipt.scan_limit_hit → complete=False → java 面非 complete。"""
    monkeypatch.setattr(jadx, "_MAX_JAVA_FILES", 1)
    java = 'class A { String u = "https://cap.example.com/x"; }'

    def _handler(cmd):  # noqa: ANN001
        pkg = Path(cmd[cmd.index("-d") + 1]) / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "A.java").write_text(java, encoding="utf-8")
        (pkg / "B.java").write_text(java, encoding="utf-8")
        return _owned(0)

    _patch_run_owned(monkeypatch, _handler)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert result.meta["jadx_scan_truncated"] is True
    assert result.meta["jadx_java_files"] == 1  # 计数停在上限
    receipt = result.meta["jadx_receipt"]
    assert receipt["complete"] is False
    assert "scan_limit_hit" in receipt["reason_codes"]
    assert receipt["scan"]["files_total"] == 2 and receipt["scan"]["files_selected"] == 1
    assert _java_vis(result.meta) == "partial"


def test_no_truncation_key_when_under_cap(monkeypatch, tmp_path) -> None:
    java = 'class A { String u = "https://cap.example.com/x"; }'
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert "jadx_scan_truncated" not in result.meta


def test_jadx_timeout_scales_with_extra_dex() -> None:
    """超时按额外 DEX 数量线性伸缩、封顶；无额外 DEX 回落基础值。"""
    assert JadxAnalyzer._jadx_timeout(0) == jadx._TIMEOUT
    assert JadxAnalyzer._jadx_timeout(2) == jadx._TIMEOUT + 2 * jadx._TIMEOUT_PER_EXTRA_DEX
    assert JadxAnalyzer._jadx_timeout(10_000) == jadx._TIMEOUT_MAX  # 封顶


# --- B2：确定性截断 + coverage 缺口逐项使 Java 面非 complete ----------------


def test_scan_selection_deterministic_across_creation_orders(monkeypatch, tmp_path) -> None:
    """★同一棵产物树（同一路径集合）两次扫描的截断选中集合必须一致：先全量收集、确定性排序，
    再取前 N——不吃文件系统枚举顺序。以 selected_paths_digest（顺序敏感 sha256）为证。
    枚举顺序**受控强制相反**（不指望真实文件系统顺序恰好不同），删掉生产侧排序本测必红。"""
    monkeypatch.setattr(jadx, "_MAX_JAVA_FILES", 3)
    names = ["b.java", "a.java", "D.java", "c.java", "E.java"]
    java = 'class A { String u = "https://det.example.com/x"; }'

    def _tree(root: Path) -> Path:
        pkg = root / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        for n in names:
            (pkg / n).write_text(java, encoding="utf-8")
        return root

    root_a, root_b = _tree(tmp_path / "A"), _tree(tmp_path / "B")
    real_rglob = Path.rglob

    def _forced_order(self: Path, pattern: str):  # A 正序、B 逆序：模拟枚举顺序漂移
        items = sorted(real_rglob(self, pattern))
        return iter(reversed(items) if self == root_b else items)

    monkeypatch.setattr(Path, "rglob", _forced_order)
    out_a = JadxAnalyzer()._scan_java(root_a)
    out_b = JadxAnalyzer()._scan_java(root_b)

    assert out_a.truncated and out_a.receipt["scan_limit_hit"]
    assert out_a.receipt["files_selected"] == out_b.receipt["files_selected"] == 3
    assert out_a.receipt["selected_paths_digest"] == out_b.receipt["selected_paths_digest"]


def test_read_failure_blocks_java_complete_but_keeps_positives(monkeypatch, tmp_path) -> None:
    """读单个 .java 失败 → 不炸、其余照扫（阳性保留），但 receipt.read_failed>0 →
    complete=False → java 面非 complete（穷尽性资格被挡）。"""
    java = 'class A { String u = "https://readable.example.com/x"; }'

    def _handler(cmd):  # noqa: ANN001
        pkg = Path(cmd[cmd.index("-d") + 1]) / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "Good.java").write_text(java, encoding="utf-8")
        (pkg / "Locked.java").write_text("class B {}", encoding="utf-8")
        return _owned(0)

    _patch_run_owned(monkeypatch, _handler)
    real_read = Path.read_bytes

    def _flaky(self: Path) -> bytes:
        if self.name == "Locked.java":
            raise OSError("sharing violation (模拟句柄被占)")
        return real_read(self)

    monkeypatch.setattr(jadx.Path, "read_bytes", _flaky)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_status"] == "ok"  # 进程本身干净退出
    assert any(e.value == "https://readable.example.com/x" for e in result.endpoints)
    receipt = result.meta["jadx_receipt"]
    assert receipt["scan"]["read_failed"] == 1
    assert receipt["complete"] is False
    assert "read_failed" in receipt["reason_codes"]
    assert _java_vis(result.meta) == "partial"


def test_per_file_truncation_blocks_java_complete(monkeypatch, tmp_path) -> None:
    """单文件超 _MAX_FILE_BYTES 被截断 → truncated_files>0 → complete=False（截掉的那段可能
    正藏着端点，不得宣称穷尽）。"""
    monkeypatch.setattr(jadx, "_MAX_FILE_BYTES", 16)
    _patch_run_owned(monkeypatch, _writes('class A { String u = "https://cut.example.com/x"; }'))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    receipt = result.meta["jadx_receipt"]
    assert receipt["scan"]["truncated_files"] == 1
    assert receipt["scan"]["bytes_scanned"] < receipt["scan"]["bytes_total"]
    assert receipt["complete"] is False
    assert "source_file_truncated" in receipt["reason_codes"]
    assert _java_vis(result.meta) == "partial"


def test_scan_exception_blocks_java_complete(monkeypatch, tmp_path) -> None:
    """单文件扫描内部异常被吞掉继续（不炸整跑、其余文件阳性保留），但必须留痕：
    receipt.scan.scan_exceptions>0 → complete=False（该文件的端点可能漏掉，穷尽性无资格）。"""
    java = 'class A { String u = "https://kept-alive.example.com/x"; }'

    def _handler(cmd):  # noqa: ANN001
        pkg = Path(cmd[cmd.index("-d") + 1]) / "sources" / "com" / "x"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "Good.java").write_text(java, encoding="utf-8")
        (pkg / "Poison.java").write_text("class P {}", encoding="utf-8")
        return _owned(0)

    _patch_run_owned(monkeypatch, _handler)
    real_scan_text = JadxAnalyzer._scan_text

    def _flaky(self, text, location, collector, secret_hits):  # noqa: ANN001
        if "poison" in location:
            raise RuntimeError("正则引擎内部故障（模拟）")
        return real_scan_text(self, text, location, collector, secret_hits)

    monkeypatch.setattr(JadxAnalyzer, "_scan_text", _flaky)
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_status"] == "ok"
    assert any(e.value == "https://kept-alive.example.com/x" for e in result.endpoints)
    receipt = result.meta["jadx_receipt"]
    assert receipt["scan"]["scan_exceptions"] == 1
    assert receipt["complete"] is False
    assert "scan_exception" in receipt["reason_codes"]
    assert _java_vis(result.meta) == "partial"


def test_cleanup_failure_blocks_java_complete(monkeypatch, tmp_path) -> None:
    """★清理受检：临时目录删不掉（Windows 残余句柄占用形态）→ 不再无痕，cleanup receipt
    complete=False → Java 面非 complete。"""
    workdir = tmp_path / "jadx_tmp"

    def _mkdtemp(prefix: str = "") -> str:
        workdir.mkdir(exist_ok=True)
        return str(workdir)

    monkeypatch.setattr(jadx.tempfile, "mkdtemp", _mkdtemp)
    monkeypatch.setattr(jadx.shutil, "rmtree", lambda *a, **k: None)  # 删除静默失败（句柄被占）
    monkeypatch.setattr(jadx, "_CLEANUP_ATTEMPTS", 1)
    monkeypatch.setattr(jadx, "_CLEANUP_BACKOFF", 0.0)
    _patch_run_owned(monkeypatch, _writes('class A { String u = "https://leak.example.com/x"; }'))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))

    assert result.meta["jadx_status"] == "ok"
    receipt = result.meta["jadx_receipt"]
    assert receipt["cleanup"] == {"complete": False, "reason_codes": ["temp_tree_still_exists"]}
    assert receipt["complete"] is False
    assert "cleanup_incomplete" in receipt["reason_codes"]
    assert _java_vis(result.meta) == "partial"


# --- C2：SDK 常量名误报被过滤 --------------------------------------------


def test_sdk_constant_secrets_not_flagged(monkeypatch, tmp_path) -> None:
    # MIPUSH_APPKEY=MIPUSH_APPKEY（value==key）、OPPOPUSH_APPKEY=OPPOPUSH_APPKEY、
    # KEY_DEVICE_TOKEN=deviceToken、METHOD_CHECK_APPKEY=dc_checkappkey 全是 SDK 常量名误报。
    java = (
        "class C {\n"
        '  String MIPUSH_APPKEY = "MIPUSH_APPKEY";\n'
        '  String OPPOPUSH_APPKEY = "OPPOPUSH_APPKEY";\n'
        '  String KEY_DEVICE_TOKEN = "deviceToken";\n'
        '  String METHOD_CHECK_APPKEY = "dc_checkappkey";\n'
        "}\n"
    )
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert [f for f in result.findings if f.category == "secret"] == []


def test_real_secret_still_flagged(monkeypatch, tmp_path) -> None:
    # ★ 回归锁：真凭据 app_secret=Abc123Xyz789Def456 仍产 HIGH secret Finding。
    java = 'class C { String app_secret = "Abc123Xyz789Def456"; }'  # leak-scan: allow 反编译输出夹具，模拟被检出的硬编码凭据，值为合成串
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    assert any(f.category == "secret" for f in result.findings)


def test_version_ip_filtered_real_ip_kept(monkeypatch, tmp_path) -> None:
    # C4：jadx 路径裸 IP 与 endpoints 共享判定——版本号 13.3.3.7 过滤，真 IP 保留。
    # 注：原用 8.8.8.8 作"真 IP"，但它是公共 DNS 解析器、已入 noise_ips（见 test_endpoints 的
    #     test_public_dns_resolver_ips_filtered），故换普通公网 IP，本意不变。
    java = (
        "class C {\n"
        '  String ver = "13.3.3.7";\n'
        '  String backend = "139.59.12.34";\n'  # leak-scan: allow jadx 抽取夹具，验真后端不被 noise 判据误杀
        '  String lan = "192.168.0.1";\n'
        "}\n"
    )
    _patch_run_owned(monkeypatch, _writes(java))
    result = JadxAnalyzer().analyze(_ctx(tmp_path))
    vals = {e.value for e in result.endpoints}
    assert "13.3.3.7" not in vals
    assert "192.168.0.1" not in vals
    assert "139.59.12.34" in vals  # leak-scan: allow jadx 抽取夹具，验真后端不被 noise 判据误杀


def test_run_jadx_uses_resolved_full_path(monkeypatch, tmp_path) -> None:
    """回归：argv[0] 必须是 tools.resolve_jadx() 解析出的完整路径（Windows 下 jadx.bat），
    而非裸 'jadx'（裸名经 subprocess 启动会 WinError2，CreateProcess 不走 PATHEXT）。"""
    fake_exe = r"C:\tools\jadx\bin\jadx.BAT"
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: ([fake_exe], {}))
    calls = _patch_run_owned(monkeypatch, lambda cmd: _owned(0))

    run = JadxAnalyzer()._run_jadx("app.apk", str(tmp_path))
    assert run.status == "ok"
    cmd = calls[0]["cmd"]
    assert isinstance(cmd, list) and cmd[0] == fake_exe
    assert calls[0]["env"] is None  # 无额外 env → 不显式传 env


def test_run_jadx_injects_java_home_from_addon(monkeypatch, tmp_path) -> None:
    """插件包路径：resolve_jadx 返回 JAVA_HOME → 必须注入子进程 env（无系统 Java 也能跑）。"""
    monkeypatch.setattr(
        jadx.tools,
        "resolve_jadx",
        lambda: ([r"C:\addon\jadx\bin\jadx.BAT"], {"JAVA_HOME": r"C:\addon\jre"}),
    )
    calls = _patch_run_owned(monkeypatch, lambda cmd: _owned(0))

    JadxAnalyzer()._run_jadx("app.apk", str(tmp_path))
    env = calls[0]["env"]
    assert isinstance(env, dict)
    assert env.get("JAVA_HOME") == r"C:\addon\jre"


def test_run_jadx_failed_when_no_jadx(monkeypatch, tmp_path) -> None:
    """resolve_jadx 落空（理论上 requires=['jadx'] 已门控）→ 返回 failed，不启动进程、不崩。"""
    monkeypatch.setattr(jadx.tools, "resolve_jadx", lambda: None)

    def _boom(cmd, *, timeout, env=None):  # noqa: ANN001
        raise AssertionError("resolve_jadx 为 None 时不应启动进程")

    monkeypatch.setattr(jadx.proctree, "run_owned", _boom)

    run = JadxAnalyzer()._run_jadx("app.apk", str(tmp_path))
    assert run.status == "failed"
    assert run.process is None


def test_scan_java_marks_ip_tier_by_package_path(tmp_path) -> None:
    """jadx 的 IP 端点同样按包路径标来源档：库包降档、app 包标 app 档（best_tier 救回入口）。

    此前只有域名分支传 tier，IP 两条通道（URL-host / 裸 IP）都不传——vendor bundle 侧
    的降档在 DEX 反编译源里出现同值时救不回来。
    """
    from tests.doc_addresses import GLOBAL_FIXTURE_IP

    # ★裸 IP 字面（非 URL）：只有裸 IP 分支收取——URL 形式会被两个分支都收（jadx 无
    #   consumed 追踪），互相掩护后单删裸分支的 tier 杀不死。URL-host 分支由下一条单锁。
    java = f'class C {{ String h = "{GLOBAL_FIXTURE_IP}"; }}'

    def _tree(pkg: str) -> Path:
        root = tmp_path / pkg.replace("/", "_") / "out"
        d = root / "sources" / Path(pkg)
        d.mkdir(parents=True, exist_ok=True)
        (d / "C.java").write_text(java, encoding="utf-8")
        return root

    lib_eps = JadxAnalyzer()._scan_java(_tree("com/squareup/okhttp")).endpoints
    app_eps = JadxAnalyzer()._scan_java(_tree("com/zmeiop/app")).endpoints
    lib_by = {e.value: e for e in lib_eps}
    app_by = {e.value: e for e in app_eps}
    assert lib_by[GLOBAL_FIXTURE_IP].enrichment.get("tier") == "library-file"
    assert app_by[GLOBAL_FIXTURE_IP].enrichment.get("tier") == "app"


def test_scan_java_url_host_ip_tier_not_masked_by_bare_branch(tmp_path) -> None:
    """URL-host IP 分支的 tier 单独锁死。

    ★jadx 没有 endpoints.py 那样的 consumed 区间追踪，URL 里的 IP 会被裸 IP 分支再收一遍，
      两个分支互相掩护——只删 URL 分支的 tier、突变照样绿。故用**末段为 0** 的地址：
      裸 IP 降噪（``_is_noise_bare_ip`` 判网络地址）会跳过它，只有 URL-host 分支收，
      该分支的 tier 一删本条即红。
    """
    url_only_ip = "192.88.99.0"  # leak-scan: allow 夹具段网络地址，仅经 URL-host 通道收取
    java = f'class D {{ String u = "https://{url_only_ip}:8443/api"; }}'
    root = tmp_path / "out"
    d = root / "sources" / "com" / "squareup" / "okhttp"
    d.mkdir(parents=True, exist_ok=True)
    (d / "D.java").write_text(java, encoding="utf-8")

    eps = JadxAnalyzer()._scan_java(root).endpoints
    by = {e.value: e for e in eps}
    assert url_only_ip in by, "URL-host 通道未收取该 IP——前提变了，本条锁失效"
    assert by[url_only_ip].enrichment.get("tier") == "library-file"


def _tree_with_pkg_case(tmp_path: Path, pkg_case: str, java: str) -> Path:
    """在 tmp 下造一棵 jadx 产物树，把同一类文件落进包目录 sources/<pkg_case>/（大小写可控）。"""
    root = tmp_path / pkg_case / "out"
    pkg = root / "sources" / pkg_case
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "AbstractC0336d.java").write_text(java, encoding="utf-8")
    return root


def _endpoint_locations(endpoints: list) -> list[tuple[str, str]]:  # noqa: ANN001
    return sorted((e.value, ev.location) for e in endpoints for ev in e.evidences)


def test_scan_java_location_case_deterministic(tmp_path) -> None:
    """★codex 复审 JADX flaky：jadx 多线程在 NTFS 大小写不敏感盘上把仅大小写不同的混淆包（v/V）落成
    随机大小写目录，两次运行 evidence.location 漂移（破坏 evidence_id 稳定 + 串行==并行逐字节一致）。
    修法把 location 规范化为小写正斜杠 → 两次（v 与 V）产逐字段一致的端点证据、location 确定。"""
    java = 'class C { String u = "https://c2.jadx-case.cn/report"; }'
    lower = JadxAnalyzer()._scan_java(
        _tree_with_pkg_case(tmp_path / "lower-run", "v", java)
    )
    upper = JadxAnalyzer()._scan_java(
        _tree_with_pkg_case(tmp_path / "upper-run", "V", java)
    )
    eps_lower = lower.endpoints
    eps_upper = upper.endpoints

    # 包目录大小写不同（v vs V），但规范化后 location 逐字节一致 → 两次运行端点证据完全相等。
    assert _endpoint_locations(eps_lower) == _endpoint_locations(eps_upper)
    assert eps_lower  # 确有端点被抽出（否则相等是空对空的假成立）
    for e in eps_lower:
        for ev in e.evidences:
            assert ev.location == ev.location.lower()  # 全小写
            assert "\\" not in ev.location             # 正斜杠（跨 OS 确定）
            assert ev.location.startswith("sources/v/")
    assert (
        lower.receipt["selected_paths_digest"]
        == upper.receipt["selected_paths_digest"]
    ), "同一 JADX 相对路径仅大小写漂移时，coverage receipt 也必须逐字节稳定"


def test_analyzer_creates_no_persistent_index_by_default(tmp_path, monkeypatch) -> None:
    """★P1-A opt-in 回归锁：常规 JadxAnalyzer 运行绝不创建/查询持久索引。

    持久索引必须由调用方显式提供 cache root（JadxIndexStore）才存在；
    默认分析路径与 P1-A 之前同行为——不读 cwd、不摸样本旁目录、
    不产生任何 manifest/shard 产物。
    """
    workdir = tmp_path / "wd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"PK\x03\x04fake")
    JadxAnalyzer().analyze(FakeContext(apk_path=str(sample)))  # 无 jadx 工具时走既有降级
    index_artifacts = [
        p
        for p in tmp_path.rglob("*")
        if p.name == "manifest.json" or (p.parent.name == "shards" and p.suffix == ".json")
    ]
    assert index_artifacts == [], "默认分析不得留下任何持久索引产物"
    assert list(workdir.iterdir()) == [], "默认分析不得向 cwd 写任何东西"
