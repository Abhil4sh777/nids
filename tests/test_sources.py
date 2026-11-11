from __future__ import annotations

from pathlib import Path

import pandas as pd

from config import Settings
from features.sources import (
    CsvFeatureSource,
    PcapFeatureSource,
    StaticFeatureSource,
)


def test_static_source_validates_frame(prepared_attack: pd.DataFrame) -> None:
    batches = list(StaticFeatureSource(prepared_attack, "batch-1").stream())
    assert len(batches) == 1
    assert batches[0].batch_id == "batch-1"
    assert batches[0].frame.equals(prepared_attack)


def test_csv_source_maps_columns_and_drops_extras(
    attack_row: dict[str, object], tmp_path: Path
) -> None:
    csv_path = tmp_path / "flows.csv"
    frame = pd.DataFrame([attack_row])
    frame["Label"] = "Benign"
    frame.to_csv(csv_path, index=False)

    batches = list(CsvFeatureSource(csv_path).stream())
    assert len(batches) == 1
    assert batches[0].batch_id == "flows"
    assert "Label" not in batches[0].frame.columns
    assert len(batches[0].frame) == 1


def test_pcap_source_delegates_to_extractor(
    prepared_attack: pd.DataFrame,
    tmp_path: Path,
    tmp_settings: Settings,
    monkeypatch,
) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"not-a-real-pcap")
    monkeypatch.setattr(
        "features.sources.NTLFlowLyzerRunner.run",
        lambda self, path: prepared_attack,
    )
    batches = list(PcapFeatureSource(pcap, tmp_settings).stream())
    assert len(batches) == 1
    assert batches[0].batch_id == "sample"
    assert batches[0].frame.equals(prepared_attack)


def test_csv_source_missing_file_raises(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        CsvFeatureSource(tmp_path / "missing.csv")
