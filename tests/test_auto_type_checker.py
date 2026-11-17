"""The required CI type probe must fail closed without needing Pyright in pytest."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from tests import check_auto_result_types as checker


def result(probe, invalid):
    lines = checker.INVALID.splitlines()
    diagnostics = []
    if invalid:
        for line, token, message in [
            (1, "'dnoe'", 'dnoe incompatible with StepStatus parameter "status"'),
            (2, "[{'name': 'synthetic', 'status': 'done'}]", '"detail" is required in "StepResult"'),
        ]:
            start = lines[line].index(token)
            diagnostics.append(dict(file=str(probe), severity='error', rule='reportArgumentType',
                                    message=message, range=dict(start=dict(line=line, character=start),
                                                               end=dict(line=line, character=start + len(token)))))
    return dict(summary=dict(filesAnalyzed=1, errorCount=len(diagnostics), warningCount=0, informationCount=0),
                generalDiagnostics=diagnostics)


@pytest.mark.parametrize('mutation', ['none', 'empty', 'wrong_rule', 'wrong_message', 'wrong_line', 'wrong_file', 'extra'])
def test_exact_diagnostic_acceptance(tmp_path, mutation):
    probe = tmp_path / 'invalid.py'
    data = deepcopy(result(probe, True))
    if mutation == 'empty':
        data = result(probe, False)
    elif mutation == 'wrong_rule':
        data['generalDiagnostics'][0]['rule'] = 'reportMissingImports'
    elif mutation == 'wrong_message':
        data['generalDiagnostics'][1]['message'] = 'unrelated argument error'
    elif mutation == 'wrong_line':
        data['generalDiagnostics'][1]['range']['start']['line'] = 0
    elif mutation == 'wrong_file':
        data['generalDiagnostics'][0]['file'] = str(tmp_path / 'other.py')
    elif mutation == 'extra':
        data['generalDiagnostics'].append(data['generalDiagnostics'][0])
    completed = subprocess.CompletedProcess([], 1, json.dumps(data))
    if mutation == 'none':
        checker.check_result(completed, probe, invalid=True)
    else:
        with pytest.raises(checker.ContractFailure):
            checker.check_result(completed, probe, invalid=True)


@pytest.mark.parametrize('fault', ['none', 'valid_control', 'old_accepts_bad', 'empty_output', 'tool_crash'])
def test_cli_gate_requires_both_real_probe_outcomes(monkeypatch, capsys, fault):
    monkeypatch.setattr(checker.importlib.util, 'find_spec', lambda _: object())
    monkeypatch.setattr(checker.shutil, 'which', lambda _: 'synthetic-node')
    calls = []

    def run(command, **kwargs):
        probe = Path(command[-1])
        invalid = probe.name == 'invalid.py'
        assert probe.read_text() == (checker.INVALID if invalid else checker.VALID)
        assert '--project' in command and '--outputjson' in command
        calls.append(probe.name)
        if fault == 'tool_crash':
            raise OSError('synthetic')
        data = result(probe, invalid)
        code = 1 if invalid else 0
        if fault == 'valid_control' and not invalid:
            code = 1
        if fault == 'old_accepts_bad' and invalid:
            data, code = result(probe, False), 0
        return subprocess.CompletedProcess(command, code, '' if fault == 'empty_output' else json.dumps(data))

    monkeypatch.setattr(checker.subprocess, 'run', run)
    assert checker.main() == (0 if fault == 'none' else 1)
    assert calls == (['valid.py', 'invalid.py'] if fault in ('none', 'old_accepts_bad') else ['valid.py'])
    if fault != 'none':
        assert 'verified' not in capsys.readouterr().out


@pytest.mark.parametrize('missing', ['pyright', 'node'])
def test_missing_tool_is_failure_not_skip(monkeypatch, missing):
    monkeypatch.setattr(checker.importlib.util, 'find_spec', lambda _: None if missing == 'pyright' else object())
    monkeypatch.setattr(checker.shutil, 'which', lambda _: None if missing == 'node' else 'synthetic-node')
    monkeypatch.setattr(checker.subprocess, 'run', lambda *a, **kw: pytest.fail('must not launch'))
    assert checker.main() == 1
