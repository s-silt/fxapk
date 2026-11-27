"""Guard the non-publishing rehearsal's direct input coverage."""
from pathlib import Path

import yaml

from tools.release_preflight import PROJECTS


def test_rehearsal_triggers_for_every_release_preflight_input() -> None:
    workflow_path = ".github/workflows/release-evidence-check.yml"
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load((root / workflow_path).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    triggers = workflow["on"]
    assert set(triggers) == {"pull_request", "workflow_dispatch"}
    assert {
        workflow_path,
        ".github/workflows/release.yml",
        ".github/release-notes-template.md",
        "tools/release_preflight.py",
        "CHANGELOG.md",
        *PROJECTS,
    } <= set(triggers["pull_request"]["paths"])
