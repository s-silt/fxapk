"""Offline synthetic contract against the validated release-preflight inventory."""
import hashlib
import json
from pathlib import Path
import pytest
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

from tools.artifact_handoff import inspect_handoff
from tools.release_preflight import PROJECTS, archive_names, projects, verified_inventory


class TestHandoffContract:
    @pytest.fixture(autouse=True)
    def fixture(self, tmp_path: Path):
        self.root = tmp_path
        for i, relative in enumerate(PROJECTS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f'[project]\nname = "synthetic-{i}"\nversion = "1.{i}.0"\n',
                encoding="utf-8",
            )
        for name in ("dist", "plugin-dist", "release-assets", "received"):
            (self.root / name).mkdir()
        for i, declaration in enumerate(projects(self.root)):
            for name in archive_names(declaration):
                payload = f"synthetic byte fixture {name}".encode()
                (self.root / ("dist" if i == 0 else "plugin-dist") / name).write_bytes(payload)
                (self.root / "release-assets" / name).write_bytes(payload)
        assets = self.root / "release-assets"
        manifest = "".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
            for p in sorted(assets.iterdir())
        )
        (assets / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")
        self.inventory = verified_inventory(
            self.root, self.root / "dist", self.root / "plugin-dist", assets
        )
        assert len(self.inventory) == 11
        self.context = {
            "GITHUB_REPOSITORY_ID": "123", "GITHUB_RUN_ID": "456",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40, "VERSION": "1.0.0",
        }

    def run_case(self, change=None, receiver=None, downloader_error=False, inventory=None):
        assets = self.root / "release-assets"
        archive = self.root / "synthetic.zip"
        first = sorted(n for n in self.inventory if n.endswith(".whl"))[0]
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
            for name in sorted(self.inventory):
                if change == "missing" and name == first:
                    continue
                data = (assets / name).read_bytes()
                if change == "changed" and name == first:
                    data = b"other synthetic payload"
                bundle.writestr(name, data)
            if change == "duplicate":
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(first, (assets / first).read_bytes())
        # Recompute outer hash, so content negatives must be caught by the accepted map.
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        events = []
        received = self.root / "received"

        def download():
            events.append("download")
            if downloader_error:
                raise OSError("synthetic transport failure")
            (received / "artifact").write_bytes(archive.read_bytes())
            return received

        result = inspect_handoff(
            self.context if receiver is None else receiver, json.dumps(self.context),
            "789", digest, json.dumps(self.inventory) if inventory is None else inventory,
            download,
        )
        # Only a harmless local sentinel, not a real publication capability.
        if result.accepted:
            events.append("synthetic-consumer")
        return result, events

    def test_same_accepted_content_reaches_synthetic_consumer(self):
        result, events = self.run_case()
        assert result.reason is None
        assert events == ["download", "synthetic-consumer"]

    def test_stale_producer_never_downloads_or_consumes(self):
        result, events = self.run_case(receiver={**self.context, "GITHUB_RUN_ATTEMPT": "2"})
        assert result.reason == "STALE_PRODUCER_ATTEMPT"
        assert events == []

    def test_different_commit_never_downloads_or_consumes(self):
        result, events = self.run_case(receiver={**self.context, "GITHUB_SHA": "b" * 40})
        assert result.reason == "COMMIT_MISMATCH"
        assert events == []

    def test_changed_bytes_never_consume_even_when_outer_hash_matches(self):
        result, events = self.run_case(change="changed")
        assert result.reason == "ARCHIVE_MEMBER_DIGEST_MISMATCH"
        assert events == ["download"]

    def test_missing_member_never_consumes_even_when_outer_hash_matches(self):
        result, events = self.run_case(change="missing")
        assert result.reason == "ARCHIVE_INVENTORY_MISMATCH"
        assert events == ["download"]

    def test_duplicate_name_never_consumes_even_when_all_digests_match(self):
        result, events = self.run_case(change="duplicate")
        assert result.reason == "ARCHIVE_INVENTORY_MISMATCH"
        assert events == ["download"]

    def test_invalid_inventory_never_consumes(self):
        result, events = self.run_case(inventory="[]")
        assert result.reason == "INVENTORY_INVALID"
        assert events == ["download"]

    def test_transport_failure_does_not_become_accepted(self):
        with pytest.raises(OSError, match="synthetic transport failure"):
            self.run_case(downloader_error=True)


def test_verifier_import_has_no_io_or_environment_dependency(monkeypatch, capsys):
    import builtins
    import importlib.util
    import os
    import socket
    import subprocess
    import sys
    import tools.artifact_handoff as verifier

    source = Path(verifier.__file__).read_text(encoding="utf-8")
    code = compile(source, verifier.__file__, "exec")
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader("_handoff_import_probe", loader=None)
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("import attempted an external side effect")

    # Preload the standard-library imports, then execute the module body afresh.
    # No configuration, file access, subprocess, network, or output is required.
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, module.__name__, module)
        patch.setattr(os, "environ", {})
        patch.setattr(builtins, "open", forbidden)
        patch.setattr(Path, "open", forbidden)
        patch.setattr(os, "scandir", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(socket, "getaddrinfo", forbidden)
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(os, "system", forbidden)
        exec(code, module.__dict__)
    assert callable(module.receipt_check)
    assert callable(module.archive_check)
    assert callable(module.inspect_handoff)
    assert capsys.readouterr() == ("", "")


def test_verifier_uses_only_offline_standard_library_imports():
    import ast
    import tools.artifact_handoff as verifier

    tree = ast.parse(Path(verifier.__file__).read_text(encoding="utf-8"))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module)
    assert imports == {
        "hashlib", "json", "os", "collections.abc", "dataclasses", "pathlib",
        "re", "stat", "zipfile", "zlib", "typing",
    }
