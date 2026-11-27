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
        "tools/verify_release_license.py",
        "LICENSE",
        "plugins/*/LICENSE",
        "CHANGELOG.md",
        *PROJECTS,
    } <= set(triggers["pull_request"]["paths"])


def test_rehearsal_checks_built_archives_before_preflight() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / ".github/workflows/release-evidence-check.yml"
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["manifest-roundtrip"]["steps"]
    setup = next(step for step in steps if step.get("uses", "").startswith("actions/setup-python@"))
    assert setup["with"]["python-version"] == "3.11"
    build = next(step["run"] for step in steps if step.get("id") == "preflight")
    # Keep the exact lower bound and test the packages that preflight will inventory.
    assert "'setuptools==77.0.3'" in build
    assert build.index("cp dist/") < build.index("python -m tools.verify_release_license")
    assert build.index("python -m tools.verify_release_license") < build.index("python tools/release_preflight.py")
