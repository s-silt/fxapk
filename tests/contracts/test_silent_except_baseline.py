"""静默 except 基线契约：存量逐条钉住，新增立刻变红，修好也要更新基线。"""

from __future__ import annotations

from pathlib import Path

from tests.contracts import silent_except


def test_silent_except_baseline_matches_reality_both_ways() -> None:
    root = Path(__file__).resolve().parents[2]
    problems = silent_except.diff_against_baseline(
        silent_except.compute_silent_excepts(root), silent_except.load_baseline()
    )
    assert not problems, (
        "静默 except 与基线不一致。新增项请改成留日志或返回明确失败状态；"
        "修复项请用 python -m tests.contracts.silent_except --write 更新基线：\n  "
        + "\n  ".join(problems)
    )


def test_baseline_is_nonvacuous() -> None:
    # 防扫描器整体失效后 --write 出空基线、主契约在两个空集上假绿。
    # 变更史（下调时写清修了哪处）：
    #   60：初始基线。
    #   60 → 52：处理 except Exception 后直接 pass/continue 的写法。
    #     decision._gate_proposal_hosts：normalize_host 不抛异常，删掉 try。
    #     re_toolkit：收窄到 binascii.Error/ValueError，计数并留 debug。
    #     assemble、socket_attr：跳过时留 warning。
    #     fetch 四处关闭失败：留 debug。
    #     logsetup.format 保留：在 formatter 里再打日志会递归。
    #   52 → 49：扫描扩到 ... / 裸字符串填充（存量未变）；以下三处改为留痕。
    #     corpus.verify_reports：路径解析失败会让孤儿结果偏多，留 warning。
    #     phase2.triage._read_parent_versions：已登记报告重读失败，留 warning。
    #     core.attribution._score_one_edge：规则正则非法，留 warning。
    #     （enrichment._terminate_new_children 仅 NoSuchProcess 仍静默，其余留 warning；次数不变）
    #   49 → 47：proctree._run_owned_impl 移除两处 subprocess.TimeoutExpired 静默 pass。
    #     改为 _reap_returncode 记 process_exit_unverified，退出码回收不再静默跳过。
    assert sum(silent_except.load_baseline().values()) == 47


def test_every_baseline_entry_has_a_reason() -> None:
    """基线是审过的白名单：--write 给新增键留空理由，不补就过不了。"""
    missing = [k for k, reason in silent_except.load_reasons().items() if not reason.strip()]
    assert not missing, "以下基线条目没写允许静默的理由：\n  " + "\n  ".join(missing)


def test_detects_pass_continue_break_and_scope() -> None:
    src = (
        "def f(xs):\n"
        "    for x in xs:\n"
        "        try:\n"
        "            int(x)\n"
        "        except ValueError:\n"
        "            continue\n"
        "class C:\n"
        "    def g(self):\n"
        "        try:\n"
        "            pass\n"
        "        except:\n"
        "            pass\n"
        "while True:\n"
        "    try:\n"
        "        next(iter([]))\n"
        "    except (StopIteration, OSError):\n"
        "        break\n"
    )
    found = silent_except.scan_source(src, "fxapk/x.py")
    assert found == {
        "fxapk/x.py::f::ValueError::continue": 1,
        "fxapk/x.py::C.g::<bare>::pass": 1,
        "fxapk/x.py::<module>::(StopIteration, OSError)::break": 1,
    }


def test_padding_does_not_bypass_detection() -> None:
    src = (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except OSError:\n"
        "        '''故意忽略'''\n"
        "        pass\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        ...\n"
    )
    assert silent_except.scan_source(src, "fxapk/x.py") == {
        "fxapk/x.py::f::OSError::pass": 1,
        "fxapk/x.py::f::ValueError::pass": 1,
    }


def test_handled_except_is_not_flagged() -> None:
    src = (
        "import logging\n"
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except OSError as exc:\n"
        "        logging.debug('x: %s', exc)\n"
        "        return None\n"
    )
    assert not silent_except.scan_source(src, "fxapk/x.py")


def test_new_and_fixed_are_both_reported() -> None:
    problems = silent_except.diff_against_baseline({"a": 2, "c": 1}, {"a": 1, "b": 1})
    assert len(problems) == 3
    assert sum("新增" in p for p in problems) == 2
    assert sum("已修复" in p for p in problems) == 1


def test_identical_state_yields_no_problems() -> None:
    assert silent_except.diff_against_baseline({"a": 1}, {"a": 1}) == []
