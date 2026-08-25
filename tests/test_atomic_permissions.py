from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path

import pytest

from apkscan.core import atomic


_POSIX_PERMISSION_REASON = (
    "Windows mode bits do not represent an owner-only ACL; "
    "the implementation intentionally makes no such guarantee"
)


@pytest.fixture
def zero_umask() -> Iterator[None]:
    """Make exact creation modes deterministic for POSIX permission tests."""

    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.skipif(os.name == "nt", reason=_POSIX_PERMISSION_REASON)
@pytest.mark.parametrize("operation", ["text", "bytes", "create"])
def test_posix_final_file_and_created_directories_are_private(
    tmp_path: Path,
    zero_umask: None,
    operation: str,
) -> None:
    first_directory = tmp_path / "case"
    second_directory = first_directory / "evidence"
    target = second_directory / "report.bin"

    if operation == "text":
        atomic.atomic_write_text(target, "first\nsecond\r\n")
        expected = b"first\nsecond\r\n"
    elif operation == "bytes":
        atomic.atomic_write_bytes(target, b"\x00private\nbytes")
        expected = b"\x00private\nbytes"
    else:
        assert atomic.atomic_create_bytes(target, b"create-only")
        expected = b"create-only"

    assert target.read_bytes() == expected

    # Exact checks intentionally fail if creation modes are weakened, e.g.
    # 0o600 -> 0o666 or 0o700 -> 0o777.
    assert first_directory.stat().st_mode & 0o777 == 0o700
    assert second_directory.stat().st_mode & 0o777 == 0o700
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason=_POSIX_PERMISSION_REASON)
@pytest.mark.parametrize(
    ("operation", "value"),
    [
        ("text", "temporary text"),
        ("bytes", b"temporary bytes"),
    ],
)
def test_replace_temporary_is_private_before_publication(
    tmp_path: Path,
    zero_umask: None,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    value: str | bytes,
) -> None:
    target = tmp_path / "private" / "report.bin"
    original_replace = atomic._replace_temp
    observed_modes: list[int] = []

    def inspect_then_replace(source: Path, destination: Path) -> None:
        assert source.exists()
        assert not destination.exists()
        observed_modes.append(source.stat().st_mode & 0o777)
        original_replace(source, destination)

    monkeypatch.setattr(atomic, "_replace_temp", inspect_then_replace)

    if operation == "text":
        assert isinstance(value, str)
        atomic.atomic_write_text(target, value)
    else:
        assert isinstance(value, bytes)
        atomic.atomic_write_bytes(target, value)

    assert observed_modes == [0o600]
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason=_POSIX_PERMISSION_REASON)
def test_create_only_temporary_is_private_before_link_publication(
    tmp_path: Path,
    zero_umask: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private" / "capture.bin"
    original_link = atomic.os.link
    observed_modes: list[int] = []

    def inspect_then_link(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
    ) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        assert source_path.exists()
        assert not destination_path.exists()
        observed_modes.append(source_path.stat().st_mode & 0o777)
        original_link(source_path, destination_path)

    monkeypatch.setattr(atomic.os, "link", inspect_then_link)

    assert atomic.atomic_create_bytes(target, b"complete")
    assert observed_modes == [0o600]
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("operation", "new_value"),
    [
        ("text", "new text"),
        ("bytes", b"new bytes"),
    ],
)
def test_publication_failure_preserves_complete_old_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    new_value: str | bytes,
) -> None:
    target = tmp_path / "report.bin"
    old_value = b'{"state":"old-and-complete"}'
    target.write_bytes(old_value)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(atomic, "_replace_temp", fail_replace)

    with pytest.raises(OSError, match="simulated publication failure"):
        if operation == "text":
            assert isinstance(new_value, str)
            atomic.atomic_write_text(target, new_value)
        else:
            assert isinstance(new_value, bytes)
            atomic.atomic_write_bytes(target, new_value)

    assert target.read_bytes() == old_value
    assert set(tmp_path.iterdir()) == {target}


def test_text_write_preserves_newline_bytes(tmp_path: Path) -> None:
    target = tmp_path / "report.txt"

    atomic.atomic_write_text(target, "lf\ncrlf\r\n")

    assert target.read_bytes() == b"lf\ncrlf\r\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific degradation test")
def test_windows_preserves_atomic_behavior_without_claiming_acl_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private" / "report.txt"
    target.parent.mkdir()
    target.write_bytes(b"old")
    original_replace = atomic._replace_temp
    publication_checked = False

    def inspect_then_replace(source: Path, destination: Path) -> None:
        nonlocal publication_checked
        # Windows st_mode is not used as an ACL assertion. We still verify
        # that complete bytes exist under a distinct temporary name while the
        # canonical target retains its complete old content.
        assert source != destination
        assert source.read_bytes() == b"new\ncontent"
        assert destination.read_bytes() == b"old"
        publication_checked = True
        original_replace(source, destination)

    monkeypatch.setattr(atomic, "_replace_temp", inspect_then_replace)

    atomic.atomic_write_text(target, "new\ncontent")

    assert publication_checked
    assert target.read_bytes() == b"new\ncontent"
