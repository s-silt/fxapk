"""Offline native boundary capture tests; no device or target traffic."""

import hashlib
import struct

import pytest


def fixture():
    # Minimal AArch64 ELF with one executable, file-backed segment.
    blob = bytearray(512)
    blob[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", blob, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 256, 4096, 4096, 256, 256, 4096)
    blob[256:260] = bytes.fromhex("1f2003d5")
    profile = {
        "schema": "fxapk-go-config-profile-1",
        "module_sha256": hashlib.sha256(blob).hexdigest(),
        "architecture": "arm64",
        "sites": [
            {
                "name": "body",
                "role": "body_return",
                "file_offset": 256,
                "instruction_hex": "1f2003d5",
                "pointer": "%x0",
                "length": "%x1",
                "max_bytes": 32,
            }
        ],
    }
    return bytes(blob), profile


def test_profile_compiles_only_regular_uprobes_and_bounded_words():
    from apkscan.dynamic.go_config_observer import compile_profile

    blob, profile = fixture()
    lines = compile_profile(
        profile, blob, remote_path="/data/local/tmp/fixture.so", group="fxapk_go_test"
    )
    assert len(lines) == 1 and lines[0].startswith("p:fxapk_go_test/body ")
    assert "g=%x28:u64" in lines[0] and "lr=%x30:u64" in lines[0]
    assert "w000=+0(%x0):x64" in lines[0] and "w003=+24(%x0):x64" in lines[0]
    assert "[" not in lines[0] and "$retval" not in lines[0]


def test_android_install_paths_with_literal_tilde_are_supported():
    from apkscan.dynamic.go_config_observer import compile_profile

    blob, profile = fixture()
    assert compile_profile(
        profile,
        blob,
        remote_path="/data/app/~~opaque==/test.example.app-opaque==/lib/arm64/fixture.so",
        group="fxapk_go_test",
    )


def test_register_only_stage_does_not_claim_truncated_material():
    from apkscan.dynamic.go_config_observer import project_trace

    _, profile = fixture()
    profile["sites"][0].update(role="stage_enter", max_bytes=0)
    result = project_trace(profile, event(len="4294967296"), lost_events=0)
    assert "native_snapshot_truncated" not in result["gaps"]
    assert result["events"][0]["snapshot_complete"] is False
    assert result["events"][0]["body_hex"] == ""


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "opcode",
        "unaligned",
        "outside",
        "nonexec",
        "duplicate",
        "oversize",
        "expression",
        "path",
        "group",
    ],
)
def test_profiles_fail_closed_before_device_writes(change):
    from apkscan.dynamic.go_config_observer import compile_profile

    blob, profile = fixture()
    path, group = "/data/local/tmp/fixture.so", "fxapk_go_test"
    site = profile["sites"][0]
    if change == "hash":
        profile["module_sha256"] = "f" * 64
    if change == "opcode":
        site["instruction_hex"] = "00000000"
    if change == "unaligned":
        site["file_offset"] = 257
    if change == "outside":
        site["file_offset"] = 800
    if change == "nonexec":
        data = bytearray(blob)
        struct.pack_into("<I", data, 68, 4)
        blob = bytes(data)
        profile["module_sha256"] = hashlib.sha256(blob).hexdigest()
    if change == "duplicate":
        profile["sites"].append(dict(site))
    if change == "oversize":
        site["max_bytes"] = 65536
    if change == "expression":
        site["pointer"] = "%x0; reboot"
    if change == "path":
        path += "'$(id)"
    if change == "group":
        group = "other"
    with pytest.raises(ValueError):
        compile_profile(profile, blob, remote_path=path, group=group)


def event(body=b'{"h":"api.example.test"}', **extra):
    data = body.ljust(32, b"\0")
    values = {
        "g": "1000",
        "lr": "2000",
        "ptr": "3000",
        "len": str(len(body)),
        **{f"w{i:03}": hex(int.from_bytes(data[i * 8 : i * 8 + 8], "little")) for i in range(4)},
        **extra,
    }
    return "worker-12 ( 11) [001] .... 10.123456: body: (0x1000) " + " ".join(
        f"{k}={v}" for k, v in values.items()
    )


def test_snapshot_keeps_exact_length_and_does_not_claim_consumption():
    from apkscan.dynamic.go_config_observer import project_trace

    _, profile = fixture()
    result = project_trace(profile, event(), lost_events=0)
    row = result["events"][0]
    assert row["body_hex"] == b'{"h":"api.example.test"}'.hex()
    assert row["snapshot_complete"] is True
    assert row["tid"] == 12 and row["tgid"] == 11
    assert row["consumption"] == "candidate"
    assert "field_to_network_origin_unbound" in result["gaps"]


@pytest.mark.parametrize(
    "change,gap",
    [
        ("fault", "native_memory_read_failed"),
        ("long", "native_snapshot_truncated"),
        ("lost", "native_events_lost"),
        ("unknown_loss", "native_loss_status_unknown"),
        ("malformed", "native_trace_malformed"),
    ],
)
def test_bad_snapshots_cannot_be_used_as_complete_material(change, gap):
    from apkscan.dynamic.go_config_observer import project_trace

    _, profile = fixture()
    trace, lost = event(), 0
    if change == "fault":
        trace = event(w001="(fault)")
    if change == "long":
        trace = event(len="33")
    if change == "lost":
        lost = 1
    if change == "unknown_loss":
        lost = None
    if change == "malformed":
        trace = event(len="invalid")
    result = project_trace(profile, trace, lost_events=lost)
    assert gap in result["gaps"]
    assert not any(r["snapshot_complete"] for r in result["events"])


def test_zero_words_have_unknown_read_status_and_unknown_process_is_not_attributed():
    from apkscan.dynamic.go_config_observer import project_trace

    _, profile = fixture()
    result = project_trace(profile, event(b"\0" * 24).replace("( 11)", "(-----)"), lost_events=0)
    assert result["events"][0]["body_hex"] == "00" * 24
    assert result["events"][0]["snapshot_complete"] is False
    assert "native_memory_read_status_unknown" in result["gaps"]
    assert result["events"][0]["tgid"] is None
    assert "native_process_binding_missing" in result["gaps"]
