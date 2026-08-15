"""分析器调度：short/long 双 lane + 进程池并行 + 内存封顶决策 + 逐 analyzer 执行 receipt。

这一簇负责：把分析器按 lane 拆开（长任务外部工具类 analyzer 进独立 long lane，父进程内串行、
由 analyzer 自身持有 deadline；其余进短任务批次）、决定短批次串行还是并行、并行时按核数与
可用内存（含容器 cgroup v1/v2 限额）封顶 worker 数、构建可 pickle 快照发进程池。pipeline 在
_stage_run_analyzers 里经 _analyze_eligible 调用本簇。

调度不变量（钉死，勿回退）：
- 120 秒预算只作用于**短任务批次**；long lane analyzer（jadx）自己持有并执行 300-1200 秒的
  外部进程 deadline，**绝不**接回短批次——接回去就会被批次预算提前强杀，孤儿出 java 进程。
- 每个 analyzer 恰好执行一次：批次超时只标记**未完成者**为 scheduler_timeout，已完成结果
  原样保留，**绝不整批串行重跑**。串行回退只允许发生在**任何任务派发之前**（快照构建 /
  建池失败）；一旦有任务进过池，失败以逐 analyzer 的 scheduler_error 落账。
- 每次执行产出确定性 receipt（lane + execution 状态；不含耗时/PID/临时路径/worker 数），
  串行与并行同一输入必须产出逐字节一致的 receipt。
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import pickle
import sys
import time

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
        return False  # 非 android 平台（防御式）→ 串行
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


#: **短任务批次**的总超时预算（秒）。防病态输入（如构造触发正则灾难性回溯的字符串）让某个
#: 分析器的 worker 无限期卡住、拖住整批结果永久不返回。固定值而非按分析器数线性放大——短批次
#: 里的分析器都是纯内存扫描（dex 字符串/manifest 正则，无网络 IO），正常全部跑完通常数秒内，
#: 120s 是几十倍安全余量。★调度不变量：这个预算**只**约束短批次；long lane analyzer（jadx，
#: 自身 deadline 300-1200s）不受它管，也绝不许接回短批次。超时只把**未完成者**标
#: scheduler_timeout，已完成结果保留、不整批重跑。
_BATCH_TIMEOUT_SECONDS = 120.0

#: 归 long lane 的 analyzer 名（外部长任务工具类：自身持有并执行 300-1200s 级 deadline）。
_LONG_LANE_ANALYZERS = frozenset({"jadx"})

#: 执行 receipt 的稳定状态字（不含耗时/PID/传输形态，串行==并行逐字节一致）。
EXEC_COMPLETED = "completed"            # analyzer 正常返回（其自身结果可为 timeout/failed）
EXEC_ANALYZER_ERROR = "analyzer_error"  # analyzer 抛异常（worker/串行内已捕获）
EXEC_SCHEDULER_TIMEOUT = "scheduler_timeout"  # 短批次预算耗尽时仍未完成，被调度器放弃
EXEC_SCHEDULER_ERROR = "scheduler_error"      # 派发/收集层故障（非 analyzer 自身问题）

#: error 串前缀 → receipt 执行状态的判别锚（error 由本模块产生，前缀即协议）。
_SCHEDULER_TIMEOUT_PREFIX = "scheduler_timeout:"
_SCHEDULER_ERROR_PREFIX = "scheduler_error:"


def _execution_lane(name: str) -> str:
    return "long" if name in _LONG_LANE_ANALYZERS else "short"


def _execution_state(error: str | None) -> str:
    if error is None:
        return EXEC_COMPLETED
    if error.startswith(_SCHEDULER_TIMEOUT_PREFIX):
        return EXEC_SCHEDULER_TIMEOUT
    if error.startswith(_SCHEDULER_ERROR_PREFIX):
        return EXEC_SCHEDULER_ERROR
    return EXEC_ANALYZER_ERROR


def _run_pool(snapshot: object, names: list[str], workers: int) -> list[tuple]:
    """纯建池 + 逐任务派发（不含内存决策）。返回按 ``names`` 保序的 [(name, result, error)]。
    真 spawn 等价测试直接调本函数以绕过 _decide_workers，保证它永远真 spawn（否则低 RAM 机上
    等价测试会因回退串行而 serial==serial 假绿）。

    exactly-once 契约：每个 analyzer 恰好派发一次。所有任务共享一个从派发起算的
    ``_BATCH_TIMEOUT_SECONDS`` deadline；到点时**已完成的结果原样收下**，仍未完成的逐个标
    ``scheduler_timeout``，随后收尾 ``terminate()`` 强杀残余 worker——**绝不**因个别
    任务超时抛异常触发外层整批串行重跑（那会让已完成的 analyzer 执行两次并丢弃其结果）。
    派发中途失败同理：已派发的照常收，未派发的标 ``scheduler_error``，不向外抛；
    收尾（terminate/join）自身的故障也只记日志（finally 内吞掉），保证「首个任务派发之后
    本函数绝不抛」是结构性成立的，而非注释承诺。

    ★ 用 ``multiprocessing.Pool`` 而非 ``concurrent.futures.ProcessPoolExecutor``：前者的
    ``terminate()`` **强杀 worker 进程**，故超时后墙钟被真正 bound 住；后者对应收尾是
    ``shutdown(wait=True)``，会挂住等卡死 worker 跑完，令超时形同虚设。
    """
    rows: list[tuple] = []
    # 建池失败向外抛：此刻尚未派发任何任务，外层串行回退不会造成重复执行。
    pool = multiprocessing.Pool(
        processes=workers, initializer=_worker_init, initargs=(snapshot,)
    )
    try:
        # deadline 从**首次派发之前**起算：apply_async 虽为非阻塞，也不许派发耗时蚕食
        # 收集侧对 120s 上界的承诺。
        deadline = time.monotonic() + _BATCH_TIMEOUT_SECONDS
        pending: list[tuple[str, object | None]] = []
        dispatch_error: str | None = None
        for name in names:
            if dispatch_error is None:
                try:
                    pending.append((name, pool.apply_async(_worker_analyze, (name,))))
                    continue
                except Exception as exc:  # noqa: BLE001 — 派发失败不抛：抛=触发整批重跑
                    dispatch_error = f"{type(exc).__name__}: {exc}"
                    logger.exception("并行任务派发失败，剩余分析器按 scheduler_error 落账")
            pending.append((name, None))
        timed_out_names: list[str] = []
        for name, task in pending:
            if task is None:
                rows.append((name, None, f"{_SCHEDULER_ERROR_PREFIX} 派发失败（{dispatch_error}）"))
                continue
            remaining = max(0.0, deadline - time.monotonic())
            try:
                rows.append(task.get(timeout=remaining))  # type: ignore[attr-defined]
            except multiprocessing.TimeoutError:
                timed_out_names.append(name)
                rows.append((
                    name, None,
                    f"{_SCHEDULER_TIMEOUT_PREFIX} 短批次预算 {_BATCH_TIMEOUT_SECONDS:.0f}s 内未完成"
                    "（已完成结果保留，不重跑）",
                ))
            except Exception as exc:  # noqa: BLE001 — 单任务收集失败只标记自身
                logger.exception("并行任务收集失败：%s", name)
                rows.append((name, None, f"{_SCHEDULER_ERROR_PREFIX} {type(exc).__name__}: {exc}"))
        if timed_out_names:
            logger.warning(
                "短批次并行超时（预算 %.0fs）：未完成 %s——保留其余已完成结果、"
                "仅标记超时者，强杀残余 worker，不整批重跑",
                _BATCH_TIMEOUT_SECONDS, ", ".join(timed_out_names),
            )
    finally:
        # ★结构性保证「派发后不抛」：池收尾（terminate/join）自身的故障也不得逃逸——
        #   逃逸会命中外层 except 触发整批串行重跑，让已完成的 analyzer 执行两次。
        try:
            pool.terminate()
            pool.join()
        except Exception:  # noqa: BLE001
            logger.exception("进程池收尾失败（结果已逐 analyzer 落账，忽略收尾故障）")
    return rows


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


def _analyze_eligible(ctx: object, eligible: list) -> tuple[list[tuple], dict[str, dict]]:
    """跑一组（已过 requires）分析器。返回 ``(rows, receipts)``：

    - ``rows``：按 ``eligible`` 原顺序的 ``[(name, result, error)]``；
    - ``receipts``：逐 analyzer 的确定性执行 receipt ``{name: {"lane", "execution"}}``——
      lane 是语义 lane（short/long），不是实际传输形态（串行/进程池），故串行与并行同一
      输入产出逐字节一致的 receipt。

    lane 拆分：``_LONG_LANE_ANALYZERS`` 进 long lane（父进程内逐个直跑，长任务 analyzer 自己
    持有并执行外部进程 deadline，调度器不加 worker 级超时——在这里强杀会重演孤儿进程与清理
    缺口）；其余进短批次（并行不适用/**派发前**失败 → 串行回退；派发后失败逐个落账，见
    ``_run_pool``）。任一 analyzer 的超时/失败只标记自身，绝不触发整批重跑。
    """
    short = [(name, analyzer) for name, analyzer in eligible if _execution_lane(name) == "short"]
    long_ = [(name, analyzer) for name, analyzer in eligible if _execution_lane(name) == "long"]

    rows_by_name: dict[str, tuple] = {}
    if short:
        if _should_parallelize(ctx, short):
            try:
                short_rows = _analyze_parallel(ctx, short)
            except Exception:  # noqa: BLE001 — 派发前失败（spawn/pickle/建池）→ 回退串行。
                # ★_run_pool 派发后绝不抛（超时/收集失败逐个落账），故走到这里必然尚未
                #   执行任何任务，串行回退不会造成重复执行。
                logger.exception("分析器并行执行失败（派发前），回退串行")
                short_rows = _analyze_serial(ctx, short)
        else:
            short_rows = _analyze_serial(ctx, short)
        rows_by_name.update({row[0]: row for row in short_rows})
    for name, analyzer in long_:
        rows_by_name[name] = _analyze_serial(ctx, [(name, analyzer)])[0]

    rows: list[tuple] = []
    receipts: dict[str, dict] = {}
    for name, _analyzer in eligible:
        row = rows_by_name.get(name)
        if row is None:  # 防御：调度器丢结果属自身故障，不嫁祸 analyzer
            row = (name, None, f"{_SCHEDULER_ERROR_PREFIX} 调度器未收到该分析器结果")
        rows.append(row)
        receipts[name] = {
            "lane": _execution_lane(name),
            "execution": _execution_state(row[2]),
        }
    return rows, receipts
