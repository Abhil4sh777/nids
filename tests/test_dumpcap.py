from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from capture.dumpcap import (
    CaptureError,
    DumpcapCapture,
    build_dumpcap_command,
    completed_pcap_files,
    find_dumpcap,
)


def test_build_command_includes_ring_buffer_and_filter(tmp_path: Path) -> None:
    command = build_dumpcap_command(
        Path(r"C:\Wireshark\dumpcap.exe"),
        interface=r"\Device\NPF_{test}",
        output_pattern=tmp_path / "nids.pcap",
        rotation_seconds=30,
        ring_files=5,
        capture_filter="tcp port 80",
    )
    assert command[0].endswith("dumpcap.exe")
    assert command[command.index("-i") + 1] == r"\Device\NPF_{test}"
    assert command[command.index("-w") + 1] == str(tmp_path / "nids.pcap")
    assert "duration:30" in command
    assert "files:5" in command
    assert command[command.index("-f") + 1] == "tcp port 80"


def test_find_dumpcap_rejects_missing_configured_path() -> None:
    with pytest.raises(CaptureError, match="does not exist"):
        find_dumpcap(r"C:\definitely\missing\dumpcap.exe")


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
