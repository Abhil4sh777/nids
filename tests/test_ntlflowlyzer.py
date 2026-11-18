from __future__ import annotations

import json
import os
import sys
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
    _resolve,
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


def test_resolve_command_uses_script_next_to_interpreter(
    tmp_path: Path, monkeypatch
) -> None:
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    script = bin_dir / "ntlflowlyzer"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)

    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(
        "features.ntlflowlyzer._interpreter_script_dirs", lambda: [bin_dir]
    )

    assert _resolve_command(("ntlflowlyzer",)) == [str(script)]


def test_resolve_command_prefers_path_over_interpreter_bin(
    tmp_path: Path, monkeypatch
) -> None:
    on_path = tmp_path / "path_bin" / "ntlflowlyzer"
    on_path.parent.mkdir()
    on_path.write_text("#!/bin/sh\n", encoding="utf-8")
    on_path.chmod(0o755)

    monkeypatch.setattr("shutil.which", lambda name: str(on_path))
    monkeypatch.setattr("features.ntlflowlyzer._interpreter_script_dirs", lambda: [])

    assert _resolve_command(("ntlflowlyzer",)) == [str(on_path)]


def test_resolve_command_falls_back_to_python_module(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr("features.ntlflowlyzer._interpreter_script_dirs", lambda: [])
    monkeypatch.setattr(
        "features.ntlflowlyzer.importlib.util.find_spec", lambda name: object()
    )

    command = _resolve_command(("ntlflowlyzer", "-c", "cfg.json"))
    assert command == [sys.executable, "-m", "NTLFlowLyzer", "-c", "cfg.json"]


def _make_checkout(tmp_path: Path) -> Path:
    """Create the minimal repository layout of an NTLFlowLyzer checkout."""

    repo = tmp_path / "download" / "NTLFlowLyzer"
    package = repo / "NTLFlowLyzer"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "__main__.py").write_text("", encoding="utf-8")
    return repo


def test_resolve_command_accepts_source_checkout(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _make_checkout(tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    command, env = _resolve((str(repo), "-c", "cfg.json"))

    assert command == [
        sys.executable,
        "-m",
        "NTLFlowLyzer",
        "-c",
        "cfg.json",
    ]
    assert env == {"PYTHONPATH": str(repo)}
    # The argv-only helper stays available for callers that only log it.
    assert _resolve_command((str(repo), "-c", "cfg.json")) == command


def test_source_checkout_env_keeps_existing_pythonpath(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _make_checkout(tmp_path)
    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")

    _, env = _resolve((str(repo),))

    assert env["PYTHONPATH"] == f"{repo}{os.pathsep}/somewhere/else"


def test_resolve_command_accepts_package_directory(
    tmp_path: Path, monkeypatch
) -> None:
    repo = _make_checkout(tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)

    command, env = _resolve((str(repo / "NTLFlowLyzer"),))

    assert command == [sys.executable, "-m", "NTLFlowLyzer"]
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(repo)


def test_plain_directory_has_clear_error(tmp_path: Path) -> None:
    empty = tmp_path / "not-a-checkout"
    empty.mkdir()

    with pytest.raises(NTLFlowLyzerError, match="is a directory"):
        _resolve_command((str(empty),))


def test_non_executable_file_has_clear_error(tmp_path: Path) -> None:
    script = tmp_path / "ntlflowlyzer"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o644)

    with pytest.raises(NTLFlowLyzerError, match="not executable"):
        _resolve_command((str(script),))


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
    editcap = tmp_path / "editcap"
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
