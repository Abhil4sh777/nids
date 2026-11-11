from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from config import Settings
from features.ntlflowlyzer import (
    NTLFlowLyzerError,
    NTLFlowLyzerRunner,
    _resolve_command,
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


def test_runner_reads_and_validates_csv(
    tmp_settings: Settings,
    tmp_path: Path,
    attack_row: dict[str, object],
    monkeypatch,
) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"fake")
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
    pcap.write_bytes(b"fake")
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
