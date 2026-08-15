"""合成样本语义快照的基线更新脚本（★四重闸，防"顺手全量刷绿"）。

用法（从仓库根跑）：
    python tools/update_synthetic_baseline.py --sample fourth-party-payment-gateway \\
        --dimension digest                       # 干跑：只打印新旧结构化 diff，不写
    APKSCAN_ALLOW_BASELINE_UPDATE=1 python tools/update_synthetic_baseline.py \\
        --sample all --dimension all --accept    # 真写（初次生成/大版本有意变更）

四重闸：
1. ``--sample`` 与 ``--dimension`` 必填（可重复给、或显式写 ``all``，但 ``all`` 不得与具体名
   混用——混着写通常意味着有个名字打错了，静默吞掉会让人以为更新了那个样本）——**没有**默认全量更新；
2. ``--accept`` 与环境变量 ``APKSCAN_ALLOW_BASELINE_UPDATE=1`` **同时**在场才写入，
   缺任一即干跑/报错——防脚本被别的自动化顺手带跑；
3. CI 侧双保险：tests/test_synthetic_snapshots.py 断言该环境变量未设（防 CI 常开），
   ci.yml 另有 ``git diff --exit-code -- tests/synthetic`` 关卡（防"CI 里先跑更新器再 unset"
   ——env 自检只看得见 pytest 进程自己的环境，看不见此前哪个步骤改了基线文件）；
4. **全部维度先算完、先打印**（结构化 diff、新增样本的完整基线内容、全局剔除字段清单），
   之后才开始写——更新永远是**看过 diff 的有意行为**，不是黑盒刷新。推荐流程仍是先干跑
   （不带 --accept）review，再带闸真写。

★原子性以**单文件**为界（每维度一次 atomic_write_text）：多维度写到一半失败不会留下半个
文件，但会留下"部分维度已更新"的状态——基线全在 git 里，``git diff`` 一眼可见、可整体回滚，
故不做跨文件事务（临时目录+统一替换在崩溃窗口上并不更优，还要自己收拾残目录）。

runner / 投影与测试共用同一真源（tests/synthetic/snapshot.py），此处零投影逻辑。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
# 入口脚本：注入仓库根一处，令 tests 包与 apkscan 均可导入（tests/conftest 提供 FakeContext）。
sys.path.insert(0, str(_REPO_ROOT))

from apkscan.core.atomic import atomic_write_text  # noqa: E402
from tests.synthetic import snapshot  # noqa: E402
from tests.synthetic.samples import SAMPLES  # noqa: E402

_ENV_FLAG = "APKSCAN_ALLOW_BASELINE_UPDATE"


def _resolve(values: list[str], universe: list[str], kind: str) -> list[str]:
    """把 --sample/--dimension 的输入解析成有效清单；``all`` 必须显式写出。未知名报错退出。"""
    if "all" in values:
        if len(values) > 1:
            # ★all 不得与具体名混用：`--sample all --sample typo` 里的 typo 若被静默吞掉，
            #   操作者会以为那个（打错的）样本也被有意更新了。
            print(f"错误：all 不得与其他{kind}混用：{values}", file=sys.stderr)
            raise SystemExit(2)
        return list(universe)
    unknown = [v for v in values if v not in universe]
    if unknown:
        print(f"错误：未知{kind} {unknown}；可用：{universe + ['all']}", file=sys.stderr)
        raise SystemExit(2)
    # 去重保序
    seen: set[str] = set()
    return [v for v in values if not (v in seen or seen.add(v))]


def main() -> int:
    parser = argparse.ArgumentParser(description="更新合成样本语义快照基线（四重闸）")
    parser.add_argument("--sample", action="append", required=True,
                        help="样本名（可重复；显式写 all 才全样本）")
    parser.add_argument("--dimension", action="append", required=True,
                        help=f"维度名（可重复；显式写 all 才全维度）：{list(snapshot.DIMENSIONS)}")
    parser.add_argument("--accept", action="store_true",
                        help=f"真写入（还需环境变量 {_ENV_FLAG}=1，缺一不写）")
    args = parser.parse_args()

    sample_names = _resolve(args.sample, [s.name for s in SAMPLES], "样本")
    dimensions = _resolve(args.dimension, list(snapshot.DIMENSIONS), "维度")

    env_ok = os.environ.get(_ENV_FLAG) == "1"
    if args.accept and not env_ok:
        # --accept 却没有环境变量：显式拒绝而非静默降级成干跑——操作者以为写了、实际没写，
        # 回头跑测试还是红，会误判成"更新脚本坏了"。
        print(f"错误：--accept 需要环境变量 {_ENV_FLAG}=1 同时在场（四重闸第 2 关）", file=sys.stderr)
        return 2
    will_write = args.accept and env_ok

    by_sample = snapshot.run_samples(tuple(s for s in SAMPLES if s.name in set(sample_names)))

    # ---- 第一阶段：全部维度先算完、先打印（闸 4：写入前必须看得到全部将要发生的事）----
    plans: list[tuple[str, dict, list[str]]] = []  # (维度, 新基线全量 dict, diff 行)
    for dimension in dimensions:
        old = snapshot.load_baseline(dimension)
        new = dict(old)
        diffs: list[str] = []
        for name in sample_names:
            new[name] = snapshot.project(dimension, by_sample[name])
            if name not in old:
                # ★新增样本必须打印**完整基线内容**，不是一个"<新增>"标记——否则首次生成
                #   的基线从没被人看过一眼就落盘，闸 4 对新样本形同虚设。
                content = json.dumps(new[name], ensure_ascii=False, sort_keys=True, indent=2)
                diffs.append(
                    f"{name}.{dimension}: <新增样本基线> 完整内容：\n"
                    + textwrap.indent(content, "      ")
                )
                continue
            diffs.extend(snapshot.flat_diff(old[name], new[name], prefix=f"{name}.{dimension}"))
        plans.append((dimension, new, diffs))

    total_changes = 0
    for dimension, _new, diffs in plans:
        print(f"== {dimension} ({snapshot.baseline_path(dimension)}) ==")
        if diffs:
            print("\n".join(f"  {line}" for line in diffs))
        else:
            print("  （无变化）")
        total_changes += len(diffs)

    print("\n-- 全局剔除字段（有意不入锁）--")
    for line in snapshot.EXCLUDED_FIELDS:
        print(f"  · {line}")

    # ---- 第二阶段：真写（原子性以单文件为界，见模块 docstring）----
    if will_write and total_changes:
        snapshot.BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        for dimension, new, diffs in plans:
            if diffs:
                atomic_write_text(str(snapshot.baseline_path(dimension)), snapshot.dump_baseline(new))
                print(f"已原子写入：{snapshot.baseline_path(dimension)}")

    if not will_write:
        print(f"\n干跑结束（未写入）。要写入：--accept 且 {_ENV_FLAG}=1（两者缺一不可）。")
    elif total_changes == 0:
        print("\n基线与当前实现一致，无需写入。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
