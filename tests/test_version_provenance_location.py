"""Optional diagnostic location failures must not erase known version evidence."""
from __future__ import annotations

import importlib.metadata as metadata

import pytest

from fxapk._version import resolve_version


@pytest.mark.parametrize("failure", ["path_property", "locate_file"])
def test_location_failure_preserves_version_provenance(
    monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    calls: list[str] = []

    class Distribution:
        version = "2.0.0"

        @property
        def _path(self) -> None:
            calls.append("path")
            if failure == "path_property":
                raise OSError("synthetic location unavailable")
            return None

        def locate_file(self, _path: str) -> str:
            calls.append("locate")
            raise OSError("synthetic location unavailable")

    def distribution(name: str) -> Distribution:
        assert name == "fxapk"
        return Distribution()

    monkeypatch.setattr(metadata, "distribution", distribution)

    result = resolve_version("2.0.0")

    assert calls == (["path"] if failure == "path_property" else ["path", "locate"])
    assert result.distribution_location == ""
    assert result.report_record() == {
        "effective_version": "2.0.0",
        "source_version": "2.0.0",
        "distribution_version": "2.0.0",
        "distribution_status": "available",
        "selected_source": "distribution",
        "consistency": "consistent",
    }
