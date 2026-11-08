"""Standard ZIP interoperability and strict bounded frame acceptance."""
from __future__ import annotations

import hashlib
import json
import struct
import zipfile
import zlib

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core import evidence_archive as ea
from apkscan.core.evidence_output import EvidenceOutput


def frame_archive(path, frame, plaintext, method=93):
    """Construct a ZIP member independently of pack's writer."""
    row = {"path": "payload", "size": len(plaintext), "sha256": hashlib.sha256(plaintext).hexdigest()}
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("payload", frame)
        bundle.writestr(ea.INDEX, json.dumps({"schema_version": ea.SCHEMA, "files": [row]}))
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as bundle:
        local = bundle.getinfo("payload").header_offset
        central = bundle.start_dir
    for offset in (local + 8, central + 10):
        struct.pack_into("<H", raw, offset, method)
    for offset in (local + 14, central + 16):
        struct.pack_into("<L", raw, offset, ea.zlib.crc32(plaintext))
    for offset in (local + 22, central + 24):
        struct.pack_into("<L", raw, offset, len(plaintext))
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize("damage", ["truncated", "extra_data", "extra_stream", "size_lie"])
def test_deflate_stream_must_finish_exactly_before_verification(tmp_path, damage):
    plaintext = b"synthetic evidence\n" * 10000
    compressor = zlib.compressobj(wbits=-15)
    frame = compressor.compress(plaintext) + compressor.flush()
    if damage == "truncated":
        frame = frame[:-1]
    elif damage == "extra_data":
        frame += b"extra"
    elif damage == "extra_stream":
        frame += frame
    else:
        plaintext = plaintext[:100]
    archive = frame_archive(tmp_path / "bad-deflate.zip", frame, plaintext, method=8)
    result = CliRunner().invoke(app, ["evidence", "verify", str(archive)])
    assert result.exit_code == 6
    assert '"state": "failed"' in result.output


def test_deflate_output_bound_and_valid_empty_stream(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    data = b"\0" * (4 * 1024 * 1024 + 17)
    (source / "large").write_bytes(data)
    (source / "empty").write_bytes(b"")
    archive = tmp_path / "bounded.zip"
    ea.pack(source, archive, compression="deflate")
    original = zlib.decompressobj
    sizes = []

    class Bounded:
        def __init__(self, *args):
            self.decoder = original(*args)

        def __getattr__(self, name):
            return getattr(self.decoder, name)

        def decompress(self, block, *, max_length):
            assert 0 < max_length <= 1024 * 1024
            output = self.decoder.decompress(block, max_length=max_length)
            sizes.append(len(output))
            return output

    monkeypatch.setattr(zlib, "decompressobj", Bounded)
    assert ea.read_reference(f"{archive}::large", len(data)) == data
    assert len(sizes) >= 5 and max(sizes) <= 1024 * 1024
    assert ea.read_reference(f"{archive}::empty", 1) == b""


@pytest.mark.parametrize("damage", ["trailer_missing", "trailer_bad", "extra_data", "extra_frame", "size_lie", "window"])
def test_bounded_decoder_rejects_incomplete_and_overstated_frames(tmp_path, damage):
    codec = ea._zstd_backend()
    plaintext = b"synthetic evidence\n" * 10000
    frame = codec.compress(plaintext, options={codec.CompressionParameter.compression_level: 6,
                                              codec.CompressionParameter.checksum_flag: 1})
    if damage == "trailer_missing":
        frame = frame[:-4]  # All original bytes can be emitted; EOF must still fail.
    elif damage == "trailer_bad":
        frame = frame[:-1] + bytes([frame[-1] ^ 127])
    elif damage == "extra_data":
        frame += b"extra"
    elif damage == "extra_frame":
        frame += codec.compress(b"another frame")
    elif damage == "size_lie":
        plaintext = plaintext[:100]
    else:
        compressor = codec.ZstdCompressor(options={codec.CompressionParameter.window_log: 27})
        frame = compressor.compress(plaintext) + compressor.flush()
    archive = frame_archive(tmp_path / "bad.zip", frame, plaintext)
    result = CliRunner().invoke(app, ["evidence", "verify", str(archive)])
    assert result.exit_code == 6
    assert '"state": "failed"' in result.output
    assert "archive_decode_failed" in result.output or "archive_member_budget" in result.output


def test_decoder_output_is_bounded_and_full_trailer_is_required(tmp_path, monkeypatch):
    codec = ea._zstd_backend()
    data = b"\0" * (ea.CHUNK * 4 + 17)
    archive = frame_archive(tmp_path / "bounded.zip", codec.compress(data), data)
    seen = []
    original = codec.ZstdDecompressor
    class Bounded:
        def __init__(self, **kwargs):
            assert kwargs["options"][codec.DecompressionParameter.window_log_max] == 26
            self.decoder = original(**kwargs)
        def __getattr__(self, name):
            return getattr(self.decoder, name)
        def decompress(self, block, *, max_length):
            assert 0 < max_length <= ea.CHUNK
            result = self.decoder.decompress(block, max_length=max_length)
            seen.append(len(result))
            return result
    monkeypatch.setattr(codec, "ZstdDecompressor", Bounded)
    assert ea.read_reference(f"{archive}::payload", len(data)) == data
    assert len(seen) >= 5 and max(seen) <= ea.CHUNK


@pytest.mark.parametrize("damage", ["method", "name", "crc", "size", "flags", "overlap"])
@pytest.mark.parametrize("method", [0, 8, 93])
def test_local_header_and_data_span_must_match_directory(tmp_path, damage, method):
    data = b"synthetic"
    if method == 93:
        frame = ea._zstd_backend().compress(data)
    elif method == 8:
        compressor = zlib.compressobj(wbits=-15)
        frame = compressor.compress(data) + compressor.flush()
    else:
        frame = data
    archive = frame_archive(tmp_path / "header.zip", frame, data, method=method)
    raw = bytearray(archive.read_bytes())
    if damage == "method":
        struct.pack_into("<H", raw, 8, 8 if method != 8 else 0)
    elif damage == "name":
        raw[30] ^= 1
    elif damage == "crc":
        raw[14] ^= 1
    elif damage == "size":
        raw[22] ^= 1
    elif damage == "flags":
        raw[6] ^= 8
    else:
        with zipfile.ZipFile(archive) as bundle:
            central = bundle.start_dir
        for offset in (18, central + 20):
            struct.pack_into("<L", raw, offset, len(raw))
    archive.write_bytes(raw)
    with pytest.raises(ea.ArchiveError, match="archive_(local_header_invalid|member_overlap)"):
        ea.read_reference(f"{archive}::payload", 100)


def test_missing_dependency_is_explicit_retains_staging_and_keeps_old_zip_readable(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").write_bytes(b"synthetic")
    modern, old = tmp_path / "modern.zip", tmp_path / "old.zip"
    ea.pack(source, modern)
    ea.pack(source, old, compression="deflate")
    def missing():
        raise ea.ArchiveError("archive_zstd_dependency_missing")
    monkeypatch.setattr(ea, "_zstd_backend", missing)
    assert ea.read_reference(f"{old}::data", 100) == b"synthetic"
    result = CliRunner().invoke(app, ["evidence", "verify", str(modern)])
    assert result.exit_code == 6 and "archive_zstd_dependency_missing" in result.output
    output = tmp_path / "capture.zip"
    with pytest.raises(ea.ArchiveError, match="archive_zstd_dependency_missing"):
        with EvidenceOutput(None, output) as destination:
            destination.path.mkdir()
            (destination.path / "data").write_bytes(b"retained")
    assert not output.exists()
    assert (destination.path / "data").read_bytes() == b"retained"
    receipt = json.loads(output.with_suffix(".zip.receipt.json").read_text())
    assert receipt["state"] == "failed" and receipt["retained_staging"]
    assert receipt["reason_codes"] == ["archive_zstd_dependency_missing"]


@pytest.mark.parametrize("compression,method", [("zstd", 93), ("deflate", 8)])
def test_public_pack_profile_and_automatic_output_profile(tmp_path, compression, method):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").write_bytes(b"synthetic")
    output = tmp_path / "packed.zip"
    result = CliRunner().invoke(app, ["evidence", "pack", str(source), "--out", str(output),
                                    "--compression", compression])
    assert result.exit_code == 0, result.output
    automatic = tmp_path / "automatic.zip"
    with EvidenceOutput(None, automatic, compression=compression) as destination:
        destination.path.mkdir()
        (destination.path / "data").write_bytes(b"synthetic")
    with zipfile.ZipFile(output) as a, zipfile.ZipFile(automatic) as b:
        assert a.getinfo("data").compress_type == b.getinfo("data").compress_type == method
    assert destination.storage["compression"] == compression


def test_original_zipfile_is_not_globally_patched(tmp_path):
    original = zipfile._get_decompressor
    source = tmp_path / "source"
    source.mkdir()
    ea.pack(source, tmp_path / "empty.zip")
    assert zipfile._get_decompressor is original


@pytest.mark.parametrize("compression", ["zstd", "deflate"])
@pytest.mark.parametrize("state,exit_code", [("ok", 0), ("partial", 5), ("failed", 6)])
def test_recovery_archive_keeps_upstream_failures_and_actual_codec(tmp_path, monkeypatch, compression, state, exit_code):
    from apkscan.dynamic import recovery
    def run(plan, output, progress, *, retain_review_inputs):
        assert retain_review_inputs
        output.mkdir()
        receipt = {"state": state, "reason_codes": ["synthetic_stage_gap"] if state != "ok" else []}
        (output / "recovery.json").write_text(json.dumps(receipt))
        return receipt
    monkeypatch.setattr(recovery, "run", run)
    archive = tmp_path / "recovery.zip"
    result = CliRunner().invoke(app, ["recover-runtime", str(tmp_path / "plan.json"),
                                    "--archive-out", str(archive), "--archive-compression", compression])
    assert result.exit_code == exit_code, result.output
    with ea.EvidenceArchive(archive) as reader:
        recovered = json.loads(reader.read("recovery.json", 10000))
        assert recovered["state"] == state
        assert recovered["reason_codes"] == (["synthetic_stage_gap"] if state != "ok" else [])
        assert reader.verify()["compression_methods"] == ([93] if compression == "zstd" else [8])
