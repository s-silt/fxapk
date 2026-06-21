# 并行 worker 内存封顶设计（实现就绪 spec）

> 状态：经对抗式评审硬化 + 用户逐项签字，实现就绪。
> 决策快照：部署含 Linux/容器 → 做 cgroup 感知；psutil 提升为核心运行期依赖；5 处参数偏离全部采纳；纳入两个扩展（快照总体积阈值 + 常量 env 覆盖）。

## 1. 目标与背景

并行分析器路径（`apkscan/core/pipeline.py::_analyze_parallel`，Windows spawn + `ProcessPoolExecutor`）当前 worker 数恒为 `min(分析器数, os.cpu_count())`，完全不看内存。在「多核 + 大 APK + 低 RAM/容器」组合下会 OOM。本设计给 worker 数按可用内存封顶。

**范围**：worker 数内存封顶 +（本轮纳入）快照总体积阈值 + 关键常量 env 覆盖。不动 IPA/串行路、不做父侧快照双持回收。

### 实测依据（真实 30MB APK，4 核 Windows，psutil 7.2.2）

| 项 | 值 | 说明 |
|---|---|---|
| 父进程 `load_apk` 后 RSS | ~486MB | androguard 全量 DEX，常驻、不可避免，仅父进程 |
| 单 worker 常驻 | ~128MB | 解释器 + 25 分析器 import + **~11.5MB 快照拷贝**（快照已含在 128MB 内） |
| 串行峰值 | 585MB | |
| 并行峰值（4 worker） | 1097MB | 净增 ~512MB = worker×4 + 父侧 IPC/聚合瞬时 |
| 快照 pickle 体积 | ~11.5MB | `build_snapshot` ~689ms（父进程串行） |

## 2. 放置（方案 A，含执行顺序硬化 + `_run_pool` 抽取）

单一 helper `_decide_workers(snapshot_size: int, name_count: int) -> int`，在 `_analyze_parallel` 内 `build_snapshot` 之后调用（拿准确快照体积）。内存逻辑集中一处。

为同时满足「真 spawn 等价测试不假绿」与「worker≤1 不建池」，把「建池+map」抽成独立函数：

```python
def _run_pool(snapshot: object, names: list[str], workers: int) -> list[tuple]:
    """纯建池 + map，不含内存决策。等价测试直接调本函数 → 永远真 spawn。"""
    with ProcessPoolExecutor(
        max_workers=workers, initializer=_worker_init, initargs=(snapshot,)
    ) as pool:
        return list(pool.map(_worker_analyze, names))


def _analyze_parallel(ctx: object, eligible: list) -> list[tuple]:
    from apkscan.core.snapshot import build_snapshot
    names = [name for name, _ in eligible]
    cpu_cap = max(1, min(len(names), os.cpu_count() or 2))
    # env 强制串行的廉价前置：FXAPK_MAX_WORKERS 解析为正整数且 min(cpu_cap, n) <= 1
    # → build_snapshot 之前就回退串行，省掉 ~689ms 白跑。
    env_n = _parse_max_workers_env()           # int | None
    if env_n is not None and min(cpu_cap, env_n) <= 1:
        logger.debug("FXAPK_MAX_WORKERS=%d → 回退串行", env_n)
        return _analyze_serial(ctx, eligible)
    snapshot = build_snapshot(ctx)
    workers = _decide_workers(_sizeof_pickle(snapshot), len(names))
    if workers <= 1:
        logger.debug("内存封顶后 workers<=1 → 回退串行（avail 不足/容器受限）")
        return _analyze_serial(ctx, eligible)
    logger.info("分析器并行执行：%d 个（进程池，%d worker）", len(names), workers)
    return _run_pool(snapshot, names, workers)
```

**执行顺序契约（钉死）：**
1. env-only 前置短路（强制串行不付 689ms）。
2. `build_snapshot`。
3. `_decide_workers`。
4. `workers<=1` → `return _analyze_serial(...)`，**不发**「分析器并行执行」INFO（否则审计日志撒谎：说进程池却走串行）。
5. `workers>1` → 用决策后**真实 workers** 发 INFO，再 `_run_pool`。

> `snapshot_size` 取实际 pickle 体积（`_sizeof_pickle(snapshot) = len(pickle.dumps(snapshot))`），与父侧真实 IPC 序列化口径一致。

## 3. 封顶公式（按优先级）

```
cpu_cap = max(1, min(name_count, os.cpu_count() or 2))

(1) env FXAPK_MAX_WORKERS 解析为正整数 n → workers = min(cpu_cap, n)        # 运维逃生开关
(2) 否则：
       avail       = _available_bytes()                  # psutil + Linux cgroup 感知（第 5 节）
       per_worker  = _worker_base_bytes() + _SNAPSHOT_FACTOR * snapshot_size
       budget      = max(0, avail - _PARENT_RESERVE_BYTES)
       mem_cap     = int(budget * _mem_safety() / per_worker)
       workers     = min(cpu_cap, max(1, mem_cap))
       # 快照总体积阈值（本轮纳入）：超阈再压一档，防恶意大快照反噬封顶输入
       if snapshot_size > _SNAPSHOT_TIER_THRESHOLD:
           workers = max(1, workers // 2)
           logger.info("快照体积 %d 字节超阈，worker 再压一档 → %d", snapshot_size, workers)
(3) psutil 查询异常 → workers = min(cpu_cap, _FIXED_FALLBACK_CAP)

最终 workers = max(1, workers)；调用方 <=1 时回退串行。
```

## 4. 参数及依据（全部采纳评审修正值）

| 常量 | 取值 | 依据 |
|---|---|---|
| `_WORKER_BASE_BYTES` | **170 MB** | 单 worker 常驻 128MB **−** 11.5MB 快照（剔除，避免与 `+snapshot_size` 双计）**+** ~50MB 分析瞬时余量 ≈ 166MB，取 170。**不含快照**；快照由 `_SNAPSHOT_FACTOR * snapshot_size` 单独叠加。 |
| `_SNAPSHOT_FACTOR` | **2.0** | `snapshot_size` 是 **pickle 体积**，非 worker 堆占用。spawn 下每 worker unpickle 后 dex_strings(12 万 str) 在堆里膨胀为 pickle 字节的 2~3 倍，同一份快照又在父侧 queue-feeder 并发缓冲。系数 2.0 同时近似覆盖「worker 堆物化放大」+「父侧 IPC 均摊一份」，对大快照偏保守。 |
| `_PARENT_RESERVE_BYTES` | **256 MB** | 决策时 `avail` 已扣父进程当前 486MB（已 resident），但**决策之后**父侧仍增长：W 份 pickle 并发缓冲 + W 个 `AnalyzerResult` 物化进 list + `_dedup_endpoints`/富化/`classify_app` 聚合。实测并行净增 ~512MB 里属父侧部分，保守留 256MB。`_MEM_SAFETY` 按 per_worker 算、覆盖不了父侧瞬时，故必须显式扣减。 |
| `_MEM_SAFETY` | **0.6** | 只用预算 60%，给 OS/其他进程/spawn import 风暴/unpickle 双持留 40%。注释须写明：父进程 486MB 基线已隐含在 `avail`（方案 A 在 build_snapshot 之后取 avail），**勿重复扣减**；本系数按 Windows `ullAvailPhys` 标定，Linux `MemAvailable` 偏乐观，由第 5 节 cgroup 感知配合抵消。 |
| `_FIXED_FALLBACK_CAP` | **min(cpu_cap, 4)** | psutil 已为核心依赖（见第 9 节），此分支仅在 `virtual_memory()` 运行时异常的罕见情形触发。无内存信息时取保守 cpu 上限 4（实测就是 4 核机 1097MB/4worker；8 无背书且 spawn import 风暴更重）。 |
| `_SNAPSHOT_TIER_THRESHOLD` | **40 MB** | 快照 pickle 体积超此值，worker 数再砍半（本轮纳入扩展）。`_SNAPSHOT_FACTOR` 已线性吸收，但对病态大快照（恶意样本）加一道硬降档。 |
| `FXAPK_MAX_WORKERS` | env | 运维强制覆盖最终 worker 数，与 `FXAPK_NO_PARALLEL` 同风格。 |
| `FXAPK_WORKER_BASE_MB` | env（本轮纳入） | 覆盖 `_WORKER_BASE_BYTES`（单位 MB）。现场已知单 worker 实占（如精简 90MB / 大样本 300MB）时无需改码纠偏。非法值忽略 + warning。 |
| `FXAPK_MEM_SAFETY` | env（本轮纳入） | 覆盖 `_MEM_SAFETY`（0~1 浮点）。非法值/越界忽略 + warning。 |

> `_worker_base_bytes()` / `_mem_safety()` 为读对应 env、非法回落默认值的小函数。

### 触发白跑 build_snapshot 的量化阈值

psutil 路径下，并行需 `mem_cap >= 2`（否则 workers 被压到 1 → 回退串行）。per_worker ≈ 170 + 2×11.5 ≈ 193MB，故需 `budget * 0.6 / per_worker >= 2` 即 `budget >= 2×193/0.6 ≈ 643MB`，即 `avail >= 256 + 643 ≈ 900MB`。**`avail < ~900MB` 时 `build_snapshot`（~689ms）白跑后回退串行**。注释里用此数字替代模糊的「罕见低 RAM」。env 强制串行路已由第 2 节前置短路规避白跑。（`mem_cap` 恰=0 的更低边界约 `avail < 578MB`，仅用于理解 `int()` 截断点。）

### FXAPK_MAX_WORKERS 解析契约（复用 `recon._concurrency` 骨架）

```
raw = (os.environ.get("FXAPK_MAX_WORKERS") or "").strip()
空串            → 静默走 (2) 路径（未设置是正常态，不 warning）
int(raw) 失败   → logger.warning 忽略，走 (2)
解析出 <= 0     → logger.warning 忽略，走 (2)
解析出 n > 0    → min(cpu_cap, n)（超大值天然被 cpu_cap 夹）
```
用 `int(raw)`：`'4 '` strip 后接受；`'3.5'`/`'abc'`/`'3x'` ValueError 忽略+warning；`'0'`/`'-1'` <=0 忽略+warning。`FXAPK_MAX_WORKERS=1` 合法 → workers=1 → 回退串行（隐藏的强制串行，与 `FXAPK_NO_PARALLEL` 重叠，debug 日志区分，见第 7 节）。`FXAPK_WORKER_BASE_MB` / `FXAPK_MEM_SAFETY` 同一解析骨架（后者用 `float`，范围 0<v<=1）。

## 5. avail 取值与 cgroup 感知（Linux 容器 OOM 硬前提 — 已确认部署含容器）

`_available_bytes()`：
- **Windows**（主平台）：`psutil.virtual_memory().available`（= `ullAvailPhys`）。无 cgroup，分支跳过。
- **Linux**：`psutil.virtual_memory().available` 在容器里读**宿主机**内存（几十 GB），与 cgroup `memory.limit` 无关 → 封顶失效、撞穿 limit 被 OOMKilled（SIGKILL，无回退机会）。故取 `min(psutil.available, cgroup 剩余)`：
  - cgroup v2：读 `/sys/fs/cgroup/memory.max`（值为 `max` → 未设限）与 `memory.current`，剩余 = max − current。
  - cgroup v1：读 `/sys/fs/cgroup/memory/memory.limit_in_bytes`（`>= 2^62` 经典哨兵 或 `>= 物理内存` → 视为未设限）与 `memory.usage_in_bytes`。
- **上限与用量分两段读**（`_cgroup_limit_bytes()` / `_cgroup_usage_bytes()`），各自 `try/except` → `logger.debug`：
  - 上限读不到（无 cgroup / 解析失败 / 未设限）→ `None` → 回退 `psutil.available`。
  - **上限已知但用量读失败 → 返回上限本身**（保守按整个 limit 估，仍受容器上限约束）。★绝不因用量读失败就退回宿主机内存——否则容器里按宿主机几十 GB 算 worker 会撞穿 limit 被 OOMKilled，正是本特性要防的场景。
- `_cgroup_available_bytes() -> int | None`（None=无 cgroup 上限）；`_available_bytes` 取 `min(psutil.available, cgroup)`。

## 6. 错误处理

- `_decide_workers` / `_parse_max_workers_env` **纯计算、绝不抛**（最外层 `max(1, ...)` 兜底）。任何异常都不得冒泡到 `_analyze_eligible` 外层 `try/except`——否则会被误记为「分析器并行执行失败，回退串行」`logger.exception`，把正常的内存封顶决策误报成并行崩溃。
- `_available_bytes` 自身**可能抛**（psutil 查询/cgroup 解析），由其唯一调用方 `_decide_workers` 的 `try/except` 兜到 `_FIXED_FALLBACK_CAP`。若将来在 `try` 外新增对 `_available_bytes` 的直接调用，调用方须自行兜底。
- psutil 已为核心依赖（第 9 节），`import psutil` 置于模块顶层。运行时查询防御：`try: avail = _available_bytes() except Exception:` → 走 `_FIXED_FALLBACK_CAP` + `logger.warning("psutil 查询可用内存失败，worker 用固定兜底 %d", cap)`（装了却查不出，值得排查；对齐全局「不在 try/except 里 swallow log」）。
- `per_worker` 理论恒 > 0（base 170MB），仍防御除零（兜底固定值）。

## 7. 日志（多条通往串行的路必须可辨）

| 事件 | 级别 | 内容 |
|---|---|---|
| 内存封顶真正压低（`mem_cap < cpu_cap` 且 workers>1） | INFO | 含可用 RAM、单 worker 估算、最终 workers |
| 快照超阈再降档 | INFO | 快照体积 + 降档后 workers |
| 最终并行执行 | INFO | 用决策后**真实 workers**（仅 workers>1 分支） |
| 内存封顶回退串行（workers<=1） | debug | 「内存封顶后 workers<=1 → 回退串行」 |
| FXAPK_MAX_WORKERS=1 强制串行 | debug | 「FXAPK_MAX_WORKERS=1 → 串行」 |
| psutil 查询失败 | warning | 见第 6 节 |
| env 非法（MAX_WORKERS/WORKER_BASE_MB/MEM_SAFETY） | warning | 「%s=%r 非法，忽略」 |

caplog 断言须 `caplog.set_level(logging.DEBUG, logger=<pipeline 模块 logger 名>)`（否则 debug 捕不到=假绿）；断言 `levelno` + 语义标记（数字/关键 token），不逐字匹配中文文案。

## 8. 测试（纯逻辑、monkeypatch、零真 spawn）

### (1) `_decide_workers` / env 解析 纯函数表驱动测
monkeypatch `os.cpu_count`、`psutil.virtual_memory`、env、（Linux）cgroup 读取。参数化清单（每行断言 workers 数值 + 期望日志级别）：
- 低 RAM → 1（回退）；高 RAM → cpu_cap
- `mem_cap` 恰=0（`int()` 截断）→ max(1,0)=1 → 回退
- `mem_cap < cpu_cap` → 压低值 + **INFO**；`mem_cap >= cpu_cap` → cpu_cap
- psutil `virtual_memory` 抛异常 → `min(cpu_cap, 4)` + **warning**，**且不向上抛**（显式断言）
- env MAX_WORKERS：< cpu_cap → 该值；> cpu_cap → 被夹；`'4 '` → 4；`'0'/'-1'/'abc'/'3.5'/'3x'` → 忽略+warning；`''` → 静默走 (2)；`=1` → 回退串行
- env WORKER_BASE_MB / MEM_SAFETY：合法生效；非法/越界忽略+warning
- `os.cpu_count()` 返回 None → `or 2`
- `snapshot_size` 显著改变 `mem_cap`（11.5MB vs 大快照）→ 验证 `_SNAPSHOT_FACTOR` 生效
- `snapshot_size > _SNAPSHOT_TIER_THRESHOLD` → workers 砍半 + INFO
- （Linux）cgroup 限额 < 宿主机 avail → 取 cgroup；cgroup 未设限/读失败 → 取 psutil

### (2) `_analyze_parallel` 回退测（不建池硬断言）
monkeypatch `pipeline.build_snapshot` 为 `lambda ctx: object()`（回退路用不到快照内容，毫秒级、跨平台恒定）、`pipeline._decide_workers` → 1、`pipeline.ProcessPoolExecutor` → `__init__` 即 `raise AssertionError('不应建池')` 的哨兵类。断言：池从未被构造 + 返回值 == `_analyze_serial(ctx, eligible)`。

### 等价测试不假绿（核心不变量）
现有 `test_serial_parallel_byte_identical_real_apk`（tests/test_parallel_analyzers.py）直接调 `_analyze_parallel`，加入回退后在低 RAM 机上会「serial==serial」假绿、悄悄不再 spawn。**修复：等价测试改调 `pipeline._run_pool(build_snapshot(ctx), names, workers=cpu_cap)`**，绕过 `_decide_workers`，保证永远真 spawn。spec 显式声明此改动。

### 解耦回归断言
`psutil.virtual_memory` 被 patch 抛异常时 `_should_parallelize` 仍返回 True（门控不读内存）。现有 gating / 真 spawn 等价测保持不变。

## 9. 依赖与打包变更

- `pyproject.toml` `dependencies` 增加 **`psutil`**（6 → 7）。理由：内存封顶是本特性核心，若 psutil 可选则默认安装直接命中固定兜底、内存计算被架空。
- fat 打包已含 psutil；核心打包需确认 psutil 进 exe（PyInstaller 一般自动收集）。
- `_FIXED_FALLBACK_CAP` 因此降级为「psutil 查询运行时异常」的罕见防御路径，而非默认主路径。

## 10. 不做范围

- 父侧快照双持回收等小头优化。
- IPA / 无 apk_path / 串行路。
- 不把内存判断塞进 `_should_parallelize`（须保其零副作用纯判定；内存封顶需 snapshot_size，只能在 build_snapshot 之后）。
- 快照层除「总体积阈值」外不改结构。总体积阈值实现：`snapshot.py::build_snapshot` 增累计预读预算 `_MAX_SNAPSHOT_TOTAL_BYTES`（建议 64MB，与单文件 32MB 上限并存）；累计超预算后停止预读、剩余文件落 worker 惰性兜底、记 debug。

## 11. 已知局限 / 后续回标

- `_PARENT_RESERVE_BYTES=256MB`、`_SNAPSHOT_FACTOR=2.0`、`_MEM_SAFETY=0.6` 均为单次实测 + 工程外推估值，缺多样本背书；先按此发版，后续按真实低 RAM / 大 APK 样本回标（env 覆盖已提供现场纠偏阀）。
- Linux `MemAvailable` 偏乐观（含可回收 cache），与 cgroup 感知配合抵消；极端紧内存仍可能需更保守 `_MEM_SAFETY`，经 `FXAPK_MEM_SAFETY` 现场下调。
