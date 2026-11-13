from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from config import Settings
from features.ntlflowlyzer import (
    CaptureFormatError,
    NTLFlowLyzerError,
    NTLFlowLyzerRunner,
    _convert_to_pcap,
    _resolve_command,
    detect_capture_format,
)


def test_config_requests_small_flushes(tmp_settings: Settings) -> None:
    runner = NTLFlowLyzerRunner(tmp_settings)
    config = runner.build_config(Path("in.pcap"), Path("out.csv"))
    assert config["pcap_file_address"] == "in.pcap"
    assert config["output_file_address"] == "out.csv"
    assert config["feature_extractor_min_flows"] == 1
    assert config["writer_min_rows"] == 1
    assert config["features_ignore_list"] == []
    assert config["floating_point_unit"] == ".4f"


def test_missing_executable_has_clear_error(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(NTLFlowLyzerError, match="not found"):
        _resolve_command(("definitely-not-installed",))


def test_missing_pcap_has_clear_error(tmp_settings: Settings) -> None:
    runner = NTLFlowLyzerRunner(tmp_settings)
    with pytest.raises(NTLFlowLyzerError, match="not found"):
        runner.run(Path("missing.pcap"))


@pytest.mark.parametrize(
    ("magic", "expected"),
    [
        (b"\xd4\xc3\xb2\xa1", "pcap"),
        (b"\xa1\xb2\xc3\xd4", "pcap"),
        (b"\x4d\x3c\xb2\xa1", "pcap"),
        (b"\xa1\xb2\x3c\x4d", "pcap"),
        (b"\x0a\x0d\x0d\x0a", "pcapng"),
    ],
)
def test_detect_capture_format_uses_magic_bytes(
    tmp_path: Path, magic: bytes, expected: str
) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(magic + b"\x00" * 32)
    assert detect_capture_format(path) == expected


def test_detect_capture_format_rejects_unknown(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"not a capture")
    with pytest.raises(CaptureFormatError, match="Unsupported"):
        detect_capture_format(path)


def test_existing_converted_pcap_is_reused(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    converted = tmp_path / "capture_converted.pcap"
    converted.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)

    def fail(*args, **kwargs):
        raise AssertionError("converter must not run when a fresh conversion exists")

    monkeypatch.setattr("features.ntlflowlyzer.subprocess.run", fail)
    assert _convert_to_pcap(source, tmp_path) == converted


def test_pcapng_with_pcap_suffix_is_converted(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "mislabelled.pcap"
    source.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    output_dir = tmp_path / "flows"
    editcap = tmp_path / "editcap.exe"
    editcap.write_bytes(b"")
    monkeypatch.setattr(
        "features.ntlflowlyzer._find_wireshark_tool",
        lambda name: editcap if name == "editcap" else None,
    )

    def fake_run(command, **kwargs):
        Path(command[-1]).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("features.ntlflowlyzer.subprocess.run", fake_run)
    converted = _convert_to_pcap(source, output_dir)
    assert converted == output_dir / "mislabelled_converted.pcap"
    assert detect_capture_format(converted) == "pcap"


def test_runner_reads_and_validates_csv(
    tmp_settings: Settings,
    tmp_path: Path,
    attack_row: dict[str, object],
    monkeypatch,
) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"fake")
    extra_row = dict(attack_row)
    extra_row["extra_ntl_column"] = 1.0

    def fake_run(command, **kwargs):
        config_path = Path(command[command.index("-c") + 1])
        config = json.loads(config_path.read_text(encoding="utf-8"))
        pd.DataFrame([extra_row]).to_csv(config["output_file_address"], index=False)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "features.ntlflowlyzer._resolve_command", lambda command: ["fake"]
    )
    monkeypatch.setattr("features.ntlflowlyzer.subprocess.run", fake_run)

    frame = NTLFlowLyzerRunner(tmp_settings).run(pcap)
    assert len(frame) == 1
    assert "extra_ntl_column" not in frame.columns
    assert frame.loc[0, "flow_id"] == "attack-0"


def test_runner_reports_nonzero_exit(
    tmp_settings: Settings,
    tmp_path: Path,
    monkeypatch,
) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"fake")
    monkeypatch.setattr(
        "features.ntlflowlyzer._resolve_command", lambda command: ["fake"]
    )
    monkeypatch.setattr(
        "features.ntlflowlyzer.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="boom"
        ),
    )
    with pytest.raises(NTLFlowLyzerError, match="boom"):
        NTLFlowLyzerRunner(tmp_settings).run(pcap)
