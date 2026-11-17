"""Fail-closed synthetic type contract, explicitly run by the existing type job."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


IMPORT = 'from fxapk.dynamic.auto import _step, _finish_run\n'
VALID = IMPORT + (
    "_step('synthetic', 'degraded', 'fixed reason')\n"
    "_finish_run(status='partial', closure={}, strict_case=False, "
    "steps=[_step('synthetic', 'done', '')], report_paths=[], "
    "package_name='', out_dir='', delivery_sink=[])\n"
)
INVALID = IMPORT + (
    "_step('synthetic', 'dnoe', '')\n"
    "_finish_run(status='partial', closure={}, strict_case=False, "
    "steps=[{'name': 'synthetic', 'status': 'done'}], report_paths=[], "
    "package_name='', out_dir='', delivery_sink=[])\n"
)


class ContractFailure(Exception):
    """Fixed local failure categories; checker output is not echoed."""


def check_result(result: subprocess.CompletedProcess, probe: Path, *, invalid: bool) -> None:
    """Require the intended argument diagnostics, not merely a nonzero exit."""
    try:
        data = json.loads(result.stdout)
        summary = data['summary']
        diagnostics = data['generalDiagnostics']
        count = 2 if invalid else 0
        if result.returncode != (1 if invalid else 0):
            raise ContractFailure('UNEXPECTED_CHECKER_EXIT')
        expected_summary = dict(filesAnalyzed=1, errorCount=count, warningCount=0, informationCount=0)
        if any(type(summary.get(k)) is not int or summary[k] != v for k, v in expected_summary.items()):
            raise ContractFailure('UNEXPECTED_CHECKER_SUMMARY')
        if not isinstance(diagnostics, list) or len(diagnostics) != count:
            raise ContractFailure('UNEXPECTED_DIAGNOSTICS')
        if not invalid:
            return
        lines = INVALID.splitlines()
        spans = [(1, lines[1].index("'dnoe'"), len("'dnoe'")),
                 (2, lines[2].index('[{'), len("[{'name': 'synthetic', 'status': 'done'}]"))]
        fragments = [('dnoe', 'StepStatus', 'parameter "status"'),
                     ('"detail" is required in "StepResult"',)]
        for diagnostic, (line, start, length), required in zip(diagnostics, spans, fragments, strict=True):
            if (Path(diagnostic['file']).resolve() != probe.resolve()
                    or diagnostic['severity'] != 'error'
                    or diagnostic['rule'] != 'reportArgumentType'
                    or diagnostic['range'] != {
                        'start': {'line': line, 'character': start},
                        'end': {'line': line, 'character': start + length},
                    }
                    or not isinstance(diagnostic['message'], str)
                    or not all(fragment in diagnostic['message'] for fragment in required)):
                raise ContractFailure('WRONG_ARGUMENT_DIAGNOSTIC')
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
        raise ContractFailure('INVALID_CHECKER_OUTPUT') from exc


def run_contract(root: Path) -> None:
    if importlib.util.find_spec('pyright') is None or shutil.which('node') is None:
        raise ContractFailure('TYPE_TOOL_UNAVAILABLE')
    with tempfile.TemporaryDirectory(prefix='auto-result-types-') as directory:
        for name, source, invalid in [('valid.py', VALID, False), ('invalid.py', INVALID, True)]:
            probe = Path(directory) / name
            probe.write_text(source, encoding='utf-8')
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pyright', '--project', str(root / 'pyproject.toml'),
                     '--outputjson', str(probe)], cwd=root, capture_output=True, text=True,
                    timeout=60, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ContractFailure('TYPE_TOOL_FAILED') from exc
            check_result(result, probe, invalid=invalid)


def main() -> int:
    try:
        run_contract(Path(__file__).resolve().parents[1])
    except ContractFailure as exc:
        print(f'auto result type contract: {exc}', file=sys.stderr)
        return 1
    print('auto result type contract: valid control and exact two negative diagnostics verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
