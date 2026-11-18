from __future__ import annotations

import os
import time
from dataclasses import replace
from pathlib import Path

import pytest

from capture.dumpcap import (
    CaptureError,
    DumpcapCapture,
    _strip_usage_dump,
    build_dumpcap_command,
    completed_pcap_files,
    find_dumpcap,
    pcap_output_format_flags,
    retire_processed_pcap,
)


def test_build_command_includes_ring_buffer_and_filter(tmp_path: Path) -> None:
    command = build_dumpcap_command(
        Path("/usr/bin/dumpcap"),
        interface="eth0",
        output_pattern=tmp_path / "nids.pcap",
        rotation_seconds=30,
        ring_files=5,
        capture_filter="tcp port 80",
        format_flags=["-F", "pcap"],
    )
    assert command[0] == str(Path("/usr/bin/dumpcap"))
    assert command[command.index("-i") + 1] == "eth0"
    assert command[command.index("-w") + 1] == str(tmp_path / "nids.pcap")
    assert "duration:30" in command
    assert "files:5" in command
    assert command[command.index("-F") + 1] == "pcap"
    assert command[command.index("-f") + 1] == "tcp port 80"


def _fake_dumpcap(tmp_path: Path, help_text: str) -> Path:
    """Create an executable stub that only answers ``-h``."""

    script = tmp_path / "fake_dumpcap"
    script.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-h\" ]; then\n"
        f"  printf '%s' \"{help_text}\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_pcap_format_flags_use_libpcap_switch_on_dumpcap_3x(tmp_path: Path) -> None:
    help_text = (
        "Usage: dumpcap [options] ...\n"
        "  -n                       use pcapng format instead of pcap (default)\n"
        "  -P                       use libpcap format instead of pcapng\n"
    )
    dumpcap = _fake_dumpcap(tmp_path, help_text)
    assert pcap_output_format_flags(dumpcap) == ["-P"]


def test_pcap_format_flags_use_F_on_dumpcap_4x(tmp_path: Path) -> None:
    help_text = (
        "Usage: dumpcap [options] ...\n"
        "  -F <capture file format>, --file-format <capture file format>\n"
        "                           set the capture file format\n"
    )
    dumpcap = _fake_dumpcap(tmp_path, help_text)
    assert pcap_output_format_flags(dumpcap) == ["-F", "pcap"]


def test_strip_usage_dump_keeps_the_real_error() -> None:
    text = (
        "dumpcap: unrecognized option: F\n"
        "Usage: dumpcap [options] ...\n"
        "Capture interface:\n"
        "  -i <interface>\n"
    )
    summary = _strip_usage_dump(text)
    assert "unrecognized option: F" in summary
    assert "Capture interface" not in summary
    assert "usage text" in summary


def test_find_dumpcap_rejects_missing_configured_path() -> None:
    with pytest.raises(CaptureError, match="does not exist"):
        find_dumpcap("/definitely/missing/dumpcap")


def _touch(path: Path, age: float) -> None:
    path.write_bytes(b"x")
    timestamp = time.time() - age
    os.utime(path, (timestamp, timestamp))


def test_completed_files_excludes_active_newest(tmp_path: Path) -> None:
    old = tmp_path / "capture_00001.pcap"
    newest = tmp_path / "capture_00002.pcap"
    _touch(old, age=10)
    _touch(newest, age=0)
    files = completed_pcap_files(tmp_path, stable_seconds=1.0)
    assert files == [old]


def test_completed_files_respects_stability(tmp_path: Path) -> None:
    warm = tmp_path / "capture_00001.pcap"
    newest = tmp_path / "capture_00002.pcap"
    _touch(warm, age=0.1)
    _touch(newest, age=0.0)
    assert completed_pcap_files(tmp_path, stable_seconds=5.0) == []


def test_completed_files_include_last_after_stop(tmp_path: Path) -> None:
    only = tmp_path / "capture_00001.pcap"
    _touch(only, age=10)
    assert completed_pcap_files(tmp_path, stable_seconds=0.0, include_last=True) == [only]


def test_completed_files_ignores_non_capture_files(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("x")
    assert completed_pcap_files(tmp_path) == []


def test_capture_requires_interface(tmp_settings) -> None:
    capture = DumpcapCapture(tmp_settings)
    with pytest.raises(CaptureError, match="interface"):
        capture.start()


def test_capture_start_reports_exit_code_and_short_log(
    tmp_settings, tmp_path: Path
) -> None:
    script = tmp_path / "fake_dumpcap"
    script.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-h\" ]; then\n"
        "  echo '  -P   use libpcap format instead of pcapng'\n"
        "  exit 0\n"
        "fi\n"
        "echo 'dumpcap: unrecognized option: F' >&2\n"
        "echo '' >&2\n"
        "echo 'Usage: dumpcap [options] ...' >&2\n"
        "echo 'Capture interface:' >&2\n"
        "echo '  -i <interface>' >&2\n"
        "exit 2\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    settings = replace(tmp_settings, interface="wlo1", dumpcap_path=str(script))

    with pytest.raises(CaptureError) as excinfo:
        DumpcapCapture(settings).start()

    message = str(excinfo.value)
    assert "exited immediately with code 2" in message
    assert "unrecognized option: F" in message
    assert "usage text" in message
    assert "Capture interface:" not in message


def test_retire_processed_pcap_deletes_by_default(tmp_path: Path) -> None:
    pcap = tmp_path / "capture_00001.pcap"
    pcap.write_bytes(b"x")
    retire_processed_pcap(
        pcap, action="delete", archive_dir=tmp_path / "archive"
    )
    assert not pcap.exists()


def test_retire_processed_pcap_can_archive(tmp_path: Path) -> None:
    pcap = tmp_path / "capture_00001.pcap"
    pcap.write_bytes(b"x")
    archive = tmp_path / "archive"
    retire_processed_pcap(pcap, action="archive", archive_dir=archive)
    assert not pcap.exists()
    assert (archive / pcap.name).exists()


def test_retire_processed_pcap_keep_leaves_file(tmp_path: Path) -> None:
    pcap = tmp_path / "capture_00001.pcap"
    pcap.write_bytes(b"x")
    retire_processed_pcap(pcap, action="keep", archive_dir=tmp_path / "archive")
    assert pcap.exists()


def test_retire_processed_pcap_rejects_unknown_action(tmp_path: Path) -> None:
    pcap = tmp_path / "capture_00001.pcap"
    pcap.write_bytes(b"x")
    with pytest.raises(CaptureError, match="NIDS_PCAP_AFTER_PROCESS"):
        retire_processed_pcap(
            pcap, action="explode", archive_dir=tmp_path / "archive"
        )
