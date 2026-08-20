"""召回基线的再生成与指纹工具（P2-a 出处可复现 + P1-d 自守护配套，非测试模块）。

背景：基线字面量（MASTER_EXTRACTION / MASTER_PATHS，现住纯数据模块
`tests/jadx_recall_master_baseline.py`——CI 依赖对齐缘由见其 docstring）声称
「master `bd58041` 实测生成」。此前生成脚本只存在于会话 scratchpad，仓库内
无法复现出处——第三轮复审（P2-a）点名。本模块把再生成入库，并提供基线指纹：
改基线必然成为显式两步（改字面量 + 换指纹），且任何人随时可从 git 历史重放
master 行为对账。

用法（子命令均从仓库根运行）：

0) ``replay`` —— ★端到端一步式（CI 的 ``jadx-recall-replay`` job 与人工复核
   都走它）：从本仓库 git 对象库导出 :data:`MASTER_COMMIT` 的 apkscan 树 →
   在该树上起子进程跑 ``dump`` → 与钉住基线对账（``verify`` 同一裁决函数）::

       python tests/gen_jadx_recall_baseline.py replay [--dump-out master.json]

   exit：0=逐项一致；1=有差异；2=环境/流程失败（含浅克隆缺历史对象——报错
   会给出 ``git fetch`` 补取命令；也含 dump 输出非法 JSON、或合法 JSON 但结构
   损坏——结构损坏是流程失败，绝不伪装成「对账差异」误导人去改基线）。

1) ``dump`` —— 在「当前 sys.path 可导入的那份 apkscan」下实测语料的提取面与
   默认限额路径面，JSON 落 stdout（``replay`` 的子进程走的就是它；单独手跑
   属分步排障）::

       python tests/gen_jadx_recall_baseline.py dump --workdir <空目录>

   要手工测 master：先把 master 树导出到仓库外再前插（不污染本工作树）::

       git archive bd58041 apkscan | tar -x -C <tmp>/master-tree
       PYTHONPATH=<tmp>/master-tree python tests/gen_jadx_recall_baseline.py dump \
           --workdir <tmp>/work > master.json

   master(schema 1.3，trace 返回 tuple) 与本分支(返回 CallPathTrace) 的形态差异
   由脚本自动兼容；路径面只取节点序（master 基线的可比面就到节点序为止）。

2) ``verify`` —— 在分支环境下把一份 master dump 与钉住的基线字面量精确对账::

       python tests/gen_jadx_recall_baseline.py verify master.json

   全等 → exit 0；任何差异 → 逐条打印并 exit 1；dump 结构损坏（合法 JSON 但
   顶层/字段形状不对）→ exit 2（流程失败，与对账差异分立）。（分支自身的行为
   对账不走这里，由 pytest 的召回基线契约负责——本子命令只回答「字面量 ==
   master 实测」。）对账前先验 dump 的 ``index_schema`` 必须是 master 的
   ``1.3``——拿分支自身的 dump（1.6）冒充 master 对账在这里直接被拒（exit 1）。

★出处保证边界（第四轮复审提出「dump 来自哪个 commit 不可机器自证」；CI 端到
端后口径更新）：dump JSON 自身仍不携带树身份（``git archive`` 导出的树没有
版本信息，schema 常量只能粗筛），但「导出的确实是 :data:`MASTER_COMMIT`」由
``replay`` 保证——树经 ``git archive <MASTER_COMMIT>`` 从对象库导出，commit
SHA 是内容寻址（覆盖整棵树）；ci.yml 的 ``jadx-recall-replay`` job 每次
push/PR 从 origin 重取对象跑完整 replay。自此「基线字面量 == 该 commit 树在
本语料上的实测」为机器可证、逐次重证。仍不担保的：「MASTER_COMMIT 该不该当
基线」是人的裁决（换它是守门文件显式 diff，且 CI 重放会逼出与旧字面量的不一
致）；重放跑在当下的 Python/依赖上（对照实验要求的正是与分支同环境，不是历
史环境考古）；连同本脚本/workflow/基线字面量一起改的蓄意合谋不设防（任何测
试体系皆然）。对账裁决逻辑本身有单测（test_jadx_recall_baseline.py 的
verify 裁判两测）。

3) ``digest`` —— 打印当前钉住基线的指纹（更新基线后粘回
   ``BASELINE_FINGERPRINT`` 用）::

       python tests/gen_jadx_recall_baseline.py digest

import 纪律：模块级只碰标准库（语料模块、apkscan、基线数据模块、测试模块全部
在子命令内延迟 import）——``dump`` 必须能在 master 树的 sys.path 下运行，而
pytest 侧只需要 :func:`baseline_fingerprint` 这个纯函数。★replay/verify 的
裁决链（:func:`diff_dump_against_pinned`）只许 import 纯数据模块
（jadx_recall_master_baseline / jadx_recall_corpus）：CI 的 replay job 只装
运行期依赖，从测试模块拿字面量会连带 ``import pytest`` 当场挂（PR #37 首跑
实证——本地 venv 有 pytest，这类断裂只有 CI 同构环境才测得出）。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

_FINGERPRINT_SCHEMA = "jadx-recall-baseline-fingerprint-v2"
#: master bd58041 的索引 schema——verify 用它粗筛「这份 dump 到底测的是不是
#: master」：分支自身 dump（1.6）冒充 master 对账在这里直接被拒。
MASTER_INDEX_SCHEMA = "1.3"
#: master 基线 commit 的完整 SHA（短形 bd58041，两测试模块的文档一律以短形引
#: 用）。``replay`` 用它从 git 对象库导树——commit SHA 内容寻址覆盖整棵树，
#: 这就是「dump 来自哪棵树」的机器身份。换基线 = 改这里 + 重放对齐全部基线
#: 字面量（CI 的 jadx-recall-replay 会逼出不一致）+ 过 SHA 常量锁单测。
MASTER_COMMIT = "bd5804197a89744e1382ad1e52ee487b91c72ef2"


def baseline_fingerprint(
    *,
    corpus: Mapping[str, str],
    fanout_candidates: int,
    master_extraction: Mapping[str, set[tuple[str, int]]],
    master_paths: Mapping[str, tuple[tuple[str, ...], ...]],
    parity_queries: Iterable[tuple[str, str]],
    removal_queries: Mapping[tuple[str, str], str],
    extraction_removals: Mapping[tuple[str, str, int], str],
    extraction_additions: Mapping[tuple[str, str, int], str],
    decl_proof_deny: Iterable[str],
    proof_markers: Iterable[str],
) -> str:
    """基线闸门全部内容的规范化指纹（sha256:<hex>）。

    覆盖面刻意包含**全部**决定闸门语义的数据：语料、master 两面基线、查询集、
    两份白名单，以及独立证明器的两组裁决数据（左证放行集 ``decl_proof_deny``
    与消毒标记 ``proof_markers``——第四轮复审：削放行集是「把真实调用证成
    声明」的单点，数据面纳入指纹，代码面由逐关键字负例锁看住）。任何一处变动
    都会换指纹——静默改基线/改清单/削放行集在 diff 里必然是两步显式编辑，
    且新值可用 ``digest`` 子命令复算核对。
    """
    payload: dict[str, Any] = {
        "schema": _FINGERPRINT_SCHEMA,
        "corpus": dict(sorted(corpus.items())),
        "fanout_candidates": fanout_candidates,
        "decl_proof_deny": sorted(decl_proof_deny),
        "proof_markers": sorted(proof_markers),
        "master_extraction": {
            ident: sorted([callee, line] for callee, line in pairs)
            for ident, pairs in sorted(master_extraction.items())
        },
        "master_paths": {
            key: [list(nodes) for nodes in paths]
            for key, paths in sorted(master_paths.items())
        },
        "parity_queries": [list(pair) for pair in parity_queries],
        "removal_queries": {
            f"{source} => {target}": reason
            for (source, target), reason in sorted(removal_queries.items())
        },
        "extraction_removals": {
            f"{ident}|{callee}|{line}": reason
            for (ident, callee, line), reason in sorted(extraction_removals.items())
        },
        "extraction_additions": {
            f"{ident}|{callee}|{line}": reason
            for (ident, callee, line), reason in sorted(extraction_additions.items())
        },
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _measure(workdir: Path) -> dict[str, Any]:
    """在 workdir 下建索引并实测：提取面 (callee,line) 集 + 默认限额路径节点序。"""
    from apkscan.core.jadx_callpath import trace_callpath
    from apkscan.core.jadx_index import (
        INDEX_SCHEMA_VERSION,
        DexInput,
        DexRole,
        JadxIndexManifest,
        JadxIndexStore,
        Limits,
        build_key_material,
        derive_index_key,
        scan_java_sources,
        verify_dex_inputs,
    )

    from tests.jadx_recall_corpus import CORPUS, PARITY_QUERIES, REMOVAL_QUERIES

    opts = "sha256:" + "a" * 64
    src = workdir / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "classes.dex").write_bytes(b"dex-0")
    inputs = [
        DexInput(
            role=DexRole.APK_DEX,
            ordinal=0,
            source_label="classes.dex",
            relative_path="classes.dex",
            declared_digest="sha256:" + hashlib.sha256(b"dex-0").hexdigest(),
        )
    ]
    lineage = verify_dex_inputs(src, inputs)
    manifest = JadxIndexManifest(
        index_key=derive_index_key(lineage, "1.5.2", opts),
        key_material=build_key_material(lineage, "1.5.2", opts),
        dex_lineage=lineage,
        jadx_version="1.5.2",
        options_digest=opts,
    )
    out = workdir / "out"
    for rel, content in CORPUS.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    scan = scan_java_sources(out, [], lineage=lineage[0], limits=Limits())
    if scan.coverage != "complete":
        raise SystemExit(f"语料必须整树可扫，实测 coverage={scan.coverage!r}")

    extraction: dict[str, list[list[object]]] = {}
    for cls in scan.structure:
        for method in cls["methods"]:  # type: ignore[index]
            ident = f"{cls['name']}#{method['name']}/{method['arity']}"  # type: ignore[index]
            if ident in extraction:
                raise SystemExit(f"语料内方法身份撞名：{ident}")
            extraction[ident] = sorted(
                [c["callee"], c["line"]]  # type: ignore[index]
                for c in method["calls"]  # type: ignore[index]
            )

    store = JadxIndexStore(workdir / "cache")
    result = store.build_index(src, manifest, scan=scan)
    if getattr(result, "state", None) is None or result.state.value != "built":  # type: ignore[union-attr]
        raise SystemExit(f"索引构建失败：{result!r}")
    loaded = store.load_index(manifest.index_key)

    paths: dict[str, list[list[str]]] = {}
    queries = list(PARITY_QUERIES) + sorted(REMOVAL_QUERIES)
    for source, target in queries:
        traced = trace_callpath(loaded, source, target)  # type: ignore[arg-type]
        # master 返回 tuple[CallPath, ...]；分支返回带 .paths 的 CallPathTrace。
        found: Any = getattr(traced, "paths", traced)
        paths[f"{source} => {target}"] = [list(p.nodes) for p in found]

    return {
        "index_schema": INDEX_SCHEMA_VERSION,
        "extraction": dict(sorted(extraction.items())),
        "paths": dict(sorted(paths.items())),
    }


def _cmd_dump(workdir: str) -> int:
    print(json.dumps(_measure(Path(workdir)), ensure_ascii=False, indent=1, sort_keys=True))
    return 0


class DumpShapeError(ValueError):
    """dump 是合法 JSON 但结构损坏（顶层/字段形状不对）——属流程失败（exit
    2），不是对账差异（exit 1）。守门代码若把它误报成差异，会误导人以为基线
    漂移了去改基线（第五轮复审点名）。消息只报「哪里坏了、期待什么形状」，
    不倒 dump 内容。"""


def _shape_error(where: str, want: str, got: object) -> DumpShapeError:
    """形状错误的统一措辞：只报定位与类型名，绝不打印值本身。"""
    return DumpShapeError(f"{where}：期待 {want}，实测类型 {type(got).__name__}")


def ensure_dump_shape(dump: object) -> Mapping[str, Any]:
    """裁决前的形状校验：顶层与三字段逐层验清，任何损坏抛 :class:`DumpShapeError`。

    校验必须深到叶子——``paths`` 的值若是字符串，迭代字符不抛异常，会静默
    产出假「对账差异」（最危险的误导形态）；浅校验拦不住它。line 显式排除
    bool（JSON true/false 在 Python 是 int 子类，冒充行号必须拒）。
    """
    if not isinstance(dump, Mapping):
        raise _shape_error("dump 顶层", "JSON 对象", dump)
    for field in ("index_schema", "extraction", "paths"):
        if field not in dump:
            raise DumpShapeError(f"dump 缺字段 {field!r}")
    if not isinstance(dump["index_schema"], str):
        raise _shape_error("index_schema", "字符串", dump["index_schema"])
    extraction = dump["extraction"]
    if not isinstance(extraction, Mapping):
        raise _shape_error("extraction", "对象", extraction)
    for ident, pairs in extraction.items():
        if not isinstance(ident, str):
            raise _shape_error("extraction 的键", "字符串", ident)
        if not isinstance(pairs, list):
            raise _shape_error(f"extraction[{ident}]", "列表", pairs)
        for i, pair in enumerate(pairs):
            if not isinstance(pair, list) or len(pair) != 2:
                raise DumpShapeError(
                    f"extraction[{ident}] 第 {i} 项：期待 [callee, line] 两元列表"
                )
            callee, line = pair
            if not isinstance(callee, str):
                raise _shape_error(f"extraction[{ident}] 第 {i} 项的 callee", "字符串", callee)
            if not isinstance(line, int) or isinstance(line, bool):
                raise _shape_error(f"extraction[{ident}] 第 {i} 项的 line", "整数", line)
    paths = dump["paths"]
    if not isinstance(paths, Mapping):
        raise _shape_error("paths", "对象", paths)
    for key, value in paths.items():
        if not isinstance(key, str):
            raise _shape_error("paths 的键", "字符串", key)
        if not isinstance(value, list):
            raise _shape_error(f"paths[{key}]", "列表", value)
        for i, nodes in enumerate(value):
            if not isinstance(nodes, list):
                raise _shape_error(f"paths[{key}] 第 {i} 条路径", "节点列表", nodes)
            for j, node in enumerate(nodes):
                if not isinstance(node, str):
                    raise _shape_error(f"paths[{key}] 第 {i} 条路径第 {j} 个节点", "字符串", node)
    return dump


def diff_dump_against_pinned(dump: object) -> list[str]:
    """verify 的裁决核心（纯函数，供单测直接喂合成 dump）：master dump 与钉住
    基线字面量精确对账，返回逐条差异（空列表 = 全等）。

    裁决前先过 :func:`ensure_dump_shape`——结构损坏抛 :class:`DumpShapeError`
    （调用方归为 exit 2），不混进差异列表。形状过关后验 ``index_schema``：
    不是 master 的 ``1.3`` 判对账失败（返回差异，exit 1）——分支自身的
    dump（1.6）冒充 master、或拿老 schema 树误测，都在这里现形。
    """
    # ★只 import 纯数据模块：replay 裁决进程跑在 CI 的运行期依赖环境（不装
    #   pytest），从测试模块拿字面量会连带 `import pytest` 挂掉（PR #37 首跑
    #   实证）。基线字面量因此单独住 jadx_recall_master_baseline。
    from tests.jadx_recall_master_baseline import MASTER_EXTRACTION, MASTER_PATHS

    dump = ensure_dump_shape(dump)
    schema = dump.get("index_schema")
    if schema != MASTER_INDEX_SCHEMA:
        return [
            f"index_schema: 实测={schema!r} 要求={MASTER_INDEX_SCHEMA!r}——"
            "这份 dump 不是 master 树的实测（分支冒充/树导错），对账中止"
        ]

    problems: list[str] = []
    measured_extraction = {
        ident: {(callee, line) for callee, line in pairs}
        for ident, pairs in dump["extraction"].items()
    }
    pinned_extraction = {ident: set(pairs) for ident, pairs in MASTER_EXTRACTION.items()}
    for ident in sorted(set(measured_extraction) | set(pinned_extraction)):
        got = measured_extraction.get(ident)
        want = pinned_extraction.get(ident)
        if got != want:
            problems.append(f"extraction[{ident}]: 实测={got!r} 钉住={want!r}")

    measured_paths = {
        key: tuple(tuple(nodes) for nodes in value)
        for key, value in dump["paths"].items()
    }
    for key in sorted(set(measured_paths) | set(MASTER_PATHS)):
        got_paths = measured_paths.get(key)
        want_paths = MASTER_PATHS.get(key)
        if got_paths != want_paths:
            problems.append(f"paths[{key}]: 实测={got_paths!r} 钉住={want_paths!r}")
    return problems


def _report_diff(problems: list[str]) -> int:
    """verify/replay 共用的裁决输出：差异逐条打印并 exit 1，全等 exit 0。"""
    if problems:
        for problem in problems:
            print(problem)
        print(f"共 {len(problems)} 处差异：dump 与钉住基线不一致。")
        return 1
    print("dump 与钉住基线逐项一致。")
    return 0


def _judge_dump(dump: object) -> int:
    """verify/replay 共用的裁决通道：形状校验 + 对账 + exit 归类。

    0=全等；1=对账差异；2=结构损坏（:class:`DumpShapeError` 在这里统一转成
    可读 stderr 消息，不让 traceback 伪装成 exit 1 的「对账差异」）。两个入口
    都必须走这里——单独调 :func:`diff_dump_against_pinned` 会把流程失败漏成
    未捕获异常。
    """
    try:
        problems = diff_dump_against_pinned(dump)
    except DumpShapeError as exc:
        print(f"master dump 结构损坏（流程失败，非对账差异）：{exc}", file=sys.stderr)
        return 2
    return _report_diff(problems)


def _cmd_verify(dump_path: str) -> int:
    with open(dump_path, encoding="utf-8") as handle:
        dump = json.load(handle)
    return _judge_dump(dump)


def _cmd_replay(dump_out: str | None) -> int:
    """端到端重放：git archive :data:`MASTER_COMMIT` 的 apkscan 树 → 该树上起
    子进程 dump → 进程内与钉住基线对账。

    dump 必须是子进程：master 树靠 PYTHONPATH 前插生效，本进程的 sys.path 与
    已加载模块（editable finder 的缓存）无法安全地就地切到另一棵 apkscan。
    exit 语义：0=一致，1=对账有差异，2=环境/流程失败（含 dump 输出非法 JSON
    或结构损坏——与对账差异区分开，CI 红叉时先看是哪一类，别把流程失败当
    基线漂移去改基线）。
    """
    repo_root = Path(__file__).resolve().parent.parent
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{MASTER_COMMIT}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        print(
            f"master 基线 commit {MASTER_COMMIT} 不在本地 git 对象库（浅克隆？）。\n"
            f"先补取对象：git fetch --no-tags --depth=1 origin {MASTER_COMMIT}",
            file=sys.stderr,
        )
        return 2
    archive = subprocess.run(
        ["git", "archive", "--format=tar", MASTER_COMMIT, "apkscan"],
        cwd=repo_root,
        capture_output=True,
    )
    if archive.returncode != 0:
        sys.stderr.write(archive.stderr.decode("utf-8", errors="replace"))
        print("git archive 失败，重放中止。", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(
        prefix="jadx-recall-replay-", ignore_cleanup_errors=True
    ) as tmp:
        master_tree = Path(tmp) / "master-tree"
        master_tree.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(master_tree, filter="data")
        if not (master_tree / "apkscan" / "__init__.py").is_file():
            print("导出的 master 树里没有 apkscan 包——archive 覆盖面变了？", file=sys.stderr)
            return 2
        env = dict(os.environ)
        prior = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            str(master_tree) if not prior else str(master_tree) + os.pathsep + prior
        )
        dump_proc = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "dump",
                "--workdir",
                str(Path(tmp) / "work"),
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
    if dump_proc.returncode != 0:
        sys.stderr.write(dump_proc.stderr)
        print(f"master 树上的 dump 子进程失败（exit {dump_proc.returncode}）。", file=sys.stderr)
        return 2
    try:
        dump = json.loads(dump_proc.stdout)
    except json.JSONDecodeError as exc:
        sys.stderr.write(dump_proc.stdout[:2000])
        print(f"dump 输出不是合法 JSON：{exc}", file=sys.stderr)
        return 2
    if dump_out:
        Path(dump_out).write_text(
            json.dumps(dump, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"master dump 已另存：{dump_out}", file=sys.stderr)
    print(f"重放对象：origin master {MASTER_COMMIT[:7]}（git archive 导树实测）")
    return _judge_dump(dump)


def _cmd_digest() -> int:
    # digest 在 dev 环境跑（白名单/放行集住测试模块，import 连带 pytest 无妨），
    # 但 master 两面基线与 diff 裁决同源——都从纯数据模块拿，杜绝「文档说 A、
    # 机器算 B」的来源分叉。
    from tests import test_jadx_recall_baseline as baseline
    from tests.jadx_recall_corpus import (
        CORPUS,
        FANOUT_CANDIDATES,
        PARITY_QUERIES,
        REMOVAL_QUERIES,
    )
    from tests.jadx_recall_master_baseline import MASTER_EXTRACTION, MASTER_PATHS

    print(
        baseline_fingerprint(
            corpus=CORPUS,
            fanout_candidates=FANOUT_CANDIDATES,
            master_extraction=MASTER_EXTRACTION,
            master_paths=MASTER_PATHS,
            parity_queries=PARITY_QUERIES,
            removal_queries=REMOVAL_QUERIES,
            extraction_removals=baseline.INTENDED_EXTRACTION_REMOVALS,
            extraction_additions=baseline.INTENDED_EXTRACTION_ADDITIONS,
            decl_proof_deny=baseline._DECL_PROOF_DENY,
            proof_markers=baseline._PROOF_MARKERS,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # 入口脚本约定：注入仓库根一处，随后全部绝对包限定导入（tests.*）。
    # ★追加而非前插：master 复测靠 PYTHONPATH 前插 master 树拿 apkscan——
    #   仓库根若插在它前面，分支 apkscan 会把 master 树静默压掉。
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.append(repo_root)

    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser(
        "replay", help="端到端：git archive master 基线树 → 子进程 dump → 对账"
    )
    replay.add_argument(
        "--dump-out", default=None, help="把 master dump JSON 另存一份（排障用）"
    )
    dump = sub.add_parser("dump", help="实测当前环境 apkscan 的提取面与路径面")
    dump.add_argument("--workdir", required=True, help="空工作目录（建索引用）")
    verify = sub.add_parser("verify", help="master dump 与钉住基线精确对账")
    verify.add_argument("dump_path", help="dump 子命令输出的 JSON 文件")
    sub.add_parser("digest", help="打印钉住基线的指纹")

    args = parser.parse_args(argv)
    if args.command == "replay":
        return _cmd_replay(args.dump_out)
    if args.command == "dump":
        return _cmd_dump(args.workdir)
    if args.command == "verify":
        return _cmd_verify(args.dump_path)
    return _cmd_digest()


if __name__ == "__main__":
    raise SystemExit(main())
