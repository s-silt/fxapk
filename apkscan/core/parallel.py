"""分析器进程池并行 + 内存封顶决策：绕 GIL 多核跑分析器、按可用内存/cgroup 限额封顶 worker 数。

从 pipeline.py 物理拆出（纯搬移、逻辑不变）：这一簇负责决定串行还是并行、并行时按核数与可用内存
（含容器 cgroup v1/v2 限额）封顶 worker 数、构建可 pickle 快照发进程池、超时兜底回退串行。pipeline
在 _stage_run_analyzers 里经 _analyze_eligible 调用本簇；执行顺序契约见 _analyze_parallel docstring。
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import pickle
import sys

import psutil

from apkscan.core.registry import discover_analyzers

logger = logging.getLogger(__name__)


_ENV_NO_PARALLEL = "FXAPK_NO_PARALLEL"

#: worker 进程级状态（spawn 后由 initializer 填充）。
_WORKER_STATE: dict = {}

# ---- worker 数内存封顶常量 ----
_ENV_MAX_WORKERS = "FXAPK_MAX_WORKERS"  # 运维强制覆盖最终 worker 数
_ENV_WORKER_BASE_MB = "FXAPK_WORKER_BASE_MB"  # 覆盖 _WORKER_BASE_BYTES（单位 MB）
_ENV_MEM_SAFETY = "FXAPK_MEM_SAFETY"  # 覆盖 _MEM_SAFETY（0<v<=1）
#: 单 worker 常驻基线（**不含快照**）：实测常驻 ~128MB 含 ~11.5MB 快照拷贝，剔除快照得 ~116MB，
#: 加 ~50MB 分析瞬时余量 ≈ 170MB。快照由 _SNAPSHOT_FACTOR*snapshot_size 单独叠加，勿在此重复计入。
_WORKER_BASE_BYTES = 170 * 1024 * 1024
#: snapshot pickle 体积→实际占用的放大系数：每 worker unpickle 后 dex_strings(12 万 str) 在堆里物化
#: 为 pickle 字节的 2~3 倍，同一份快照又在父侧 queue-feeder 并发缓冲。2.0 同时近似覆盖两者，偏保守。
_SNAPSHOT_FACTOR = 2.0
#: 父进程预留：决策时 avail 已扣父进程当前常驻，但决策之后父侧仍增长（W 份 pickle 缓冲 + W 个
#: AnalyzerResult 物化 + dedup/富化/classify 聚合）。实测并行净增属父侧部分，保守留 256MB。
_PARENT_RESERVE_BYTES = 256 * 1024 * 1024
#: 只用预算的 60%，给 OS/其他进程/spawn import 风暴/unpickle 双持留余量。按 Windows ullAvailPhys 标定。
_MEM_SAFETY = 0.6
#: psutil 查询运行时异常时的保守上限（psutil 已为核心依赖，此路径罕见）。取 min(cpu_cap, 4)。
_FIXED_FALLBACK_CAP = 4
#: 快照 pickle 体积超此值，worker 数再砍半（_SNAPSHOT_FACTOR 已线性吸收，此为病态大快照硬降档）。
_SNAPSHOT_TIER_THRESHOLD = 40 * 1024 * 1024

#: _decide_workers 的 env_n 哨兵：区分"未提供（自行读 env）"与"读到 env=None（未设置）"。
_UNSET = object()


def _parse_int_env(name: str) -> int | None:
    """读正整数 env：未设/空串→None（静默，未设置是正常态）；非整数或<=0→None+warning。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        n = int(raw)
    except ValueError:
        logger.warning("%s=%r 非整数，忽略", name, raw)
        return None
    if n <= 0:
        logger.warning("%s=%r 非正整数，忽略", name, raw)
        return None
    return n


def _parse_float_env(name: str, *, lo: float, hi: float) -> float | None:
    """读 (lo, hi] 区间浮点 env：未设/空串→None；非浮点或越界→None+warning。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        v = float(raw)
    except ValueError:
        logger.warning("%s=%r 非浮点，忽略", name, raw)
        return None
    if not (lo < v <= hi):
        logger.warning("%s=%r 越界 (%s, %s]，忽略", name, raw, lo, hi)
        return None
    return v


def _worker_base_bytes() -> int:
    """单 worker 基线字节数（FXAPK_WORKER_BASE_MB 可覆盖，现场纠偏阀）。"""
    mb = _parse_int_env(_ENV_WORKER_BASE_MB)
    return mb * 1024 * 1024 if mb is not None else _WORKER_BASE_BYTES


def _mem_safety() -> float:
    """内存安全系数（FXAPK_MEM_SAFETY 可覆盖）。"""
    v = _parse_float_env(_ENV_MEM_SAFETY, lo=0.0, hi=1.0)
    return v if v is not None else _MEM_SAFETY


def _read_cgroup_file(path: str) -> str:
    """读 cgroup 文件首行（抽出便于测试 monkeypatch）。"""
    with open(path) as f:
        return f.read().strip()


def _cgroup_limit_bytes() -> int | None:
    """cgroup 内存硬上限；未设限 / 非 cgroup / 读失败 → None。"""
    try:
        v2_max = "/sys/fs/cgroup/memory.max"
        if os.path.exists(v2_max):  # cgroup v2
            raw = _read_cgroup_file(v2_max)
            if raw == "max":
                return None  # 未设限
            return int(raw)
        v1_limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        if os.path.exists(v1_limit):  # cgroup v1
            limit = int(_read_cgroup_file(v1_limit))
            # 未设限哨兵：接近 2^63 的大数（经典 0x7FFFFFFFFFFFF000）或 >= 物理内存。
            if limit >= 2**62 or limit >= psutil.virtual_memory().total:
                return None
            return limit
    except Exception:  # noqa: BLE001 — 上限读失败 → None（回退 psutil，绝不炸决策）
        logger.debug("读取 cgroup 内存上限失败", exc_info=True)
    return None


def _cgroup_usage_bytes() -> int | None:
    """cgroup 当前用量；读失败 → None。"""
    try:
        v2_cur = "/sys/fs/cgroup/memory.current"
        if os.path.exists(v2_cur):
            return int(_read_cgroup_file(v2_cur))
        v1_usage = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
        if os.path.exists(v1_usage):
            return int(_read_cgroup_file(v1_usage))
    except Exception:  # noqa: BLE001 — 用量读失败 → None（由调用方保守按整个 limit 处理）
        logger.debug("读取 cgroup 内存用量失败", exc_info=True)
    return None


def _cgroup_available_bytes() -> int | None:
    """Linux cgroup 内存剩余 (limit - usage)；非 Linux / 未设限 / 上限读失败 → None。

    ★安全回退：上限已知但用量读失败时返回**上限本身**（保守按整个 limit 估），绝不退回宿主机内存
    ——否则容器里会按宿主机几十 GB 算 worker 数、撞穿 cgroup limit 被 OOMKilled（SIGKILL 无回退机会），
    正是本特性要防的场景。仅当上限本身都读不到（无 cgroup / 解析失败）才返回 None 退回 psutil。
    """
    if not sys.platform.startswith("linux"):
        return None
    limit = _cgroup_limit_bytes()
    if limit is None:
        return None
    usage = _cgroup_usage_bytes()
    if usage is None:
        return limit  # 用量未知 → 保守按整个 limit（仍受容器上限约束，远安全于退回宿主机）
    return max(0, limit - usage)


def _available_bytes() -> int:
    """可用内存：Windows=psutil.available；Linux 取 min(psutil.available, cgroup 剩余)——容器里
    psutil.available 读宿主机内存、与 cgroup limit 无关，不取 min 会撞穿 limit 被 OOMKilled。"""
    avail = psutil.virtual_memory().available
    cg = _cgroup_available_bytes()
    return min(avail, cg) if cg is not None else avail


def _decide_workers(snapshot_size: int, name_count: int, env_n: object = _UNSET) -> int:
    """据 CPU / 可用内存 / env 决定进程池 worker 数。纯计算、绝不抛（异常→保守兜底）。返回 >=1，
    调用方对 <=1 回退串行。env_n 缺省自行读 FXAPK_MAX_WORKERS（便于单测）；_analyze_parallel 传入
    避免重复解析/重复 warning。详见 specs/2026-06-22-parallel-worker-memory-cap-design.md。"""
    cpu_cap = max(1, min(name_count, os.cpu_count() or 2))
    n = _parse_max_workers_env() if env_n is _UNSET else env_n

    # (1) env 强制覆盖。
    if n is not None:
        return max(1, min(cpu_cap, n))  # type: ignore[arg-type]

    # (2) 按可用内存封顶。
    try:
        avail = _available_bytes()
        per_worker = _worker_base_bytes() + int(_SNAPSHOT_FACTOR * snapshot_size)
        budget = max(0, avail - _PARENT_RESERVE_BYTES)
        mem_cap = int(budget * _mem_safety() / per_worker) if per_worker > 0 else cpu_cap
        workers = min(cpu_cap, max(1, mem_cap))
        if 1 < workers < cpu_cap:
            logger.info(
                "内存受限：worker %d→%d（可用 %dMB，单 worker 估 %dMB）",
                cpu_cap, workers, avail // (1024 * 1024), per_worker // (1024 * 1024),
            )
        # 快照超阈再砍一档（病态大快照硬降档；_SNAPSHOT_FACTOR 已线性吸收，此为额外保守）。
        if snapshot_size > _SNAPSHOT_TIER_THRESHOLD and workers > 1:
            halved = max(1, workers // 2)
            logger.info(
                "快照体积 %d 字节超阈 %d，worker 再压一档 %d→%d",
                snapshot_size, _SNAPSHOT_TIER_THRESHOLD, workers, halved,
            )
            workers = halved
        return max(1, workers)
    except Exception:  # noqa: BLE001 — 内存探测失败不得炸并行决策；保守兜底（不向上冒泡）
        cap = max(1, min(cpu_cap, _FIXED_FALLBACK_CAP))
        logger.warning("psutil 查询可用内存失败，worker 用固定兜底 %d", cap)
        return cap


def _parse_max_workers_env() -> int | None:
    """读 FXAPK_MAX_WORKERS（运维强制覆盖最终 worker 数）。"""
    return _parse_int_env(_ENV_MAX_WORKERS)


def _sizeof_pickle(snapshot: object) -> int:
    """快照 pickle 体积（字节）——与父侧真实 IPC 序列化口径一致，作内存封顶公式输入。"""
    try:
        return len(pickle.dumps(snapshot))
    except Exception:  # noqa: BLE001 — 体积估算失败按 0（退化为仅 base 估算，绝不炸）
        logger.debug("快照 pickle 体积估算失败，按 0 处理", exc_info=True)
        return 0


def _worker_init(snapshot: object) -> None:
    """进程池 worker 初始化：配置日志 + 缓存快照 + 发现分析器（每 worker 一次，不含 androguard 重导入）。"""
    # spawn 的 worker 是全新进程，不继承主进程 cli 的 logging 配置——不配则分析器内
    # logger.info/warning/exception 走 root 兜底 handler（无时间戳、格式不一致、INFO 被丢）。
    # 取证工具的审计日志是关键证据，同一 APK 不能因走并行/串行而产出详尽程度不同的日志。
    # 与 cli.basicConfig 同口径（level/format 一致），保证两路日志一致。
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _WORKER_STATE["snapshot"] = snapshot
    _WORKER_STATE["analyzers"] = {
        (getattr(a, "name", "") or a.__class__.__name__): a for a in discover_analyzers()
    }


def _worker_analyze(name: str) -> tuple:
    """worker 内跑一个分析器，返回 (name, result|None, error|None)。结果须可 pickle。"""
    snap = _WORKER_STATE.get("snapshot")
    analyzer = (_WORKER_STATE.get("analyzers") or {}).get(name)
    if analyzer is None:
        return (name, None, "worker 未发现该分析器")
    try:
        return (name, analyzer.analyze(snap), None)
    except Exception as exc:  # noqa: BLE001 — 单分析器失败不炸 worker，回传错误
        # 错误处理铁律：记完整堆栈（与串行 _analyze_serial 同口径）。worker 已在 _worker_init
        # 配好日志，logger.exception 把 traceback 落到 worker stderr（继承主控台）；否则并行路只
        # 回一行 "ValueError: ..." 无堆栈，崩溃分析器排障从"看堆栈"退化成"盲猜"。
        logger.exception("分析器执行异常：%s", name)
        return (name, None, f"{type(exc).__name__}: {exc}")


def _should_parallelize(ctx: object, eligible: list) -> bool:
    """是否走进程池并行：android + 多核 + 足够多分析器 + 有 apk_path（惰性兜底需要）+ 未禁用。"""
    if os.environ.get(_ENV_NO_PARALLEL):
        return False
    if getattr(ctx, "platform", "android") != "android":
        return False  # IPA 等 read_file 语义不同 → 串行
    if (os.cpu_count() or 1) < 2 or len(eligible) < 3:
        return False  # 单核 / 分析器太少不值进程开销
    if not getattr(ctx, "apk_path", ""):
        return False  # 无 apk_path 无法在 worker 惰性兜底非文本 read_file
    return True


def _analyze_serial(ctx: object, eligible: list) -> list[tuple]:
    """串行跑（无 androguard pickle 开销；并行不适用/失败时的回退）。"""
    out: list[tuple] = []
    for name, analyzer in eligible:
        try:
            out.append((name, analyzer.analyze(ctx), None))
        except Exception as exc:  # noqa: BLE001 — 单点故障不中断流水线
            logger.exception("分析器执行异常：%s", name)
            out.append((name, None, f"{type(exc).__name__}: {exc}"))
    return out


#: 整批并行分析的总超时预算（秒）。防病态输入（如构造触发正则灾难性回溯的字符串）让某个分析器
#: 的 worker 无限期卡住、拖住整批结果永久不返回。固定值而非按分析器数线性放大——各分析器都是
#: 纯内存扫描（dex 字符串/manifest 正则，无网络 IO），正常情况下全部跑完通常数秒内，120s 是几十倍
#: 安全余量。注意 map_async().get(timeout) 的语义是「从 get() 起整批累计等待」而非逐个 task 各自计时。
_BATCH_TIMEOUT_SECONDS = 120.0


def _run_pool(snapshot: object, names: list[str], workers: int) -> list[tuple]:
    """纯建池 + map（不含内存决策）。map_async(...).get() 保序。真 spawn 等价测试直接调本函数以
    绕过 _decide_workers，保证它永远真 spawn（否则低 RAM 机上等价测试会因回退串行而 serial==serial 假绿）。

    超时防护：单个分析器卡死不应让整批并行结果永久挂起。超过 _BATCH_TIMEOUT_SECONDS → 放弃等待
    并抛 TimeoutError，外层 `_analyze_eligible` 的 except Exception 捕获后回退串行逐个执行（至少能
    继续产出结果、定位是哪个分析器卡死）。

    ★ 用 ``multiprocessing.Pool`` 而非 ``concurrent.futures.ProcessPoolExecutor``：前者的 with
    __exit__ 调 ``terminate()`` **强杀 worker 进程**，故超时后墙钟被真正 bound 住；后者 __exit__ 是
    ``shutdown(wait=True)``，超时抛出后反而挂住等卡死 worker 跑完，令超时形同虚设（实测：worker 卡死
    5s、超时压到 1s 时，ProcessPoolExecutor 版总耗时仍 5s，multiprocessing.Pool 版 1s）。
    """
    with multiprocessing.Pool(
        processes=workers, initializer=_worker_init, initargs=(snapshot,)
    ) as pool:
        try:
            return pool.map_async(_worker_analyze, names).get(timeout=_BATCH_TIMEOUT_SECONDS)
        except multiprocessing.TimeoutError as exc:
            logger.warning(
                "并行分析批次超时（%d 个分析器，预算 %.0fs）：疑似病态输入导致某分析器卡死，"
                "强杀 worker、放弃本批结果，回退串行逐个执行（会更慢但能继续产出）",
                len(names),
                _BATCH_TIMEOUT_SECONDS,
            )
            # with 退出时 multiprocessing.Pool.__exit__ → terminate() 强杀仍在跑的 worker，墙钟被真正
            # bound 住。归一到内置 TimeoutError，保持外层 _analyze_eligible 的 except 契约不变。
            raise TimeoutError(str(exc)) from exc


def _analyze_parallel(ctx: object, eligible: list) -> list[tuple]:
    """进程池并行跑（snapshot 发各 worker，绕 GIL 在多核真并行）。worker 数按 CPU+可用内存封顶；<=1 回退串行。

    执行顺序契约（钉死，勿打乱）：env 前置短路 → build_snapshot → _decide_workers →
    workers<=1 回退串行（**不发**『并行执行』INFO，否则审计日志说进程池却走了串行）→ 否则发 INFO + 建池。
    """
    from apkscan.core.snapshot import build_snapshot

    names = [name for name, _ in eligible]
    cpu_cap = max(1, min(len(names), os.cpu_count() or 2))
    # env 强制串行的廉价前置：FXAPK_MAX_WORKERS 使最终 <=1 → 在 build_snapshot 之前就回退，省 ~689ms。
    env_n = _parse_max_workers_env()
    if env_n is not None and min(cpu_cap, env_n) <= 1:
        logger.debug("FXAPK_MAX_WORKERS=%d → 回退串行", env_n)
        return _analyze_serial(ctx, eligible)

    snapshot = build_snapshot(ctx)
    workers = _decide_workers(_sizeof_pickle(snapshot), len(names), env_n=env_n)
    if workers <= 1:
        logger.debug("内存封顶后 workers<=1 → 回退串行（avail 不足 / 容器受限）")
        return _analyze_serial(ctx, eligible)
    logger.info("分析器并行执行：%d 个（进程池，%d worker）", len(names), workers)
    return _run_pool(snapshot, names, workers)


def _analyze_eligible(ctx: object, eligible: list) -> list[tuple]:
    """跑一组（已过 requires）分析器，返回 [(name, result, error)]。并行不适用/失败 → 串行回退。"""
    if _should_parallelize(ctx, eligible):
        try:
            return _analyze_parallel(ctx, eligible)
        except Exception:  # noqa: BLE001 — 并行整体失败（spawn/pickle 等）→ 回退串行，绝不漏分析
            logger.exception("分析器并行执行失败，回退串行")
    return _analyze_serial(ctx, eligible)
