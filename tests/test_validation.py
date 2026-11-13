from __future__ import annotations

import logging

import pandas as pd
import pytest

from features.contract import ALL_FEATURES, DETECTOR_FEATURES, IDENTIFIER_FEATURES
from features.validation import (
    FeatureContractError,
    prepare_flow_frame,
    prepare_inference_frame,
)


def test_missing_columns_are_named(attack_row: dict[str, object]) -> None:
    frame = pd.DataFrame([attack_row]).drop(columns=["duration", "packets_count"])
    with pytest.raises(FeatureContractError) as excinfo:
        prepare_flow_frame(frame)
    message = str(excinfo.value)
    assert "duration" in message
    assert "packets_count" in message
    assert "missing" in message.lower()


def test_case_space_and_camel_case_mapping(attack_row: dict[str, object]) -> None:
    frame = pd.DataFrame([attack_row]).rename(
        columns={
            "flow_id": "Flow ID",
            "duration": "Duration",
            "packets_count": "Packets Count",
            "fwd_psh_flag_counts": "FwdPSHFlagCounts",
            "packets_IAT_mean": "PacketsIATMean",
        }
    )
    prepared = prepare_flow_frame(frame)
    assert list(prepared.columns) == ALL_FEATURES
    assert prepared.loc[0, "flow_id"] == attack_row["flow_id"]
    assert prepared.loc[0, "protocol"] == "TCP"


def test_ntlflowlyzer_segment_size_names_are_mapped(
    attack_row: dict[str, object],
) -> None:
    values = dict(attack_row)
    for name in ("fwd_avg_segment_size", "bwd_avg_segment_size", "avg_segment_size"):
        del values[name]
    values.update(
        fwd_segment_size_mean=101.0,
        bwd_segment_size_mean=202.0,
        segment_size_mean=303.0,
    )
    prepared = prepare_flow_frame(pd.DataFrame([values]))
    assert prepared.loc[0, "fwd_avg_segment_size"] == 101.0
    assert prepared.loc[0, "bwd_avg_segment_size"] == 202.0
    assert prepared.loc[0, "avg_segment_size"] == 303.0


def test_extra_columns_are_dropped_with_warning(
    attack_row: dict[str, object], caplog: pytest.LogCaptureFixture
) -> None:
    frame = pd.DataFrame([attack_row])
    frame["Label"] = "Benign"
    frame["unnamed: 0"] = 7
    with caplog.at_level(logging.WARNING):
        prepared = prepare_flow_frame(frame)
    assert "Label" not in prepared.columns
    assert "Dropping" in caplog.text
    assert list(prepared.columns) == ALL_FEATURES


def test_duplicate_columns_are_ambiguous(attack_row: dict[str, object]) -> None:
    frame = pd.DataFrame([attack_row])
    frame["Protocol"] = frame["protocol"]
    with pytest.raises(FeatureContractError, match="Ambiguous"):
        prepare_flow_frame(frame)


def test_numeric_protocol_mapping(attack_row: dict[str, object]) -> None:
    second = dict(attack_row)
    second["flow_id"] = "second"
    second["protocol"] = 17
    frame = pd.DataFrame([{**attack_row, "protocol": 6}, second])
    prepared = prepare_flow_frame(frame)
    assert prepared["protocol"].tolist() == ["TCP", "UDP"]


def test_unsupported_protocol_rejected(attack_row: dict[str, object]) -> None:
    frame = pd.DataFrame([{**attack_row, "protocol": 1}])
    with pytest.raises(FeatureContractError, match="Unsupported protocol"):
        prepare_flow_frame(frame)


def test_non_numeric_feature_rejected(attack_row: dict[str, object]) -> None:
    frame = pd.DataFrame([{**attack_row, "duration": "not-a-number"}])
    with pytest.raises(FeatureContractError, match="duration"):
        prepare_flow_frame(frame)


def test_empty_frame_with_contract_columns_is_valid() -> None:
    frame = pd.DataFrame(columns=ALL_FEATURES)
    prepared = prepare_flow_frame(frame)
    assert prepared.empty
    assert list(prepared.columns) == ALL_FEATURES


def test_inference_frame_keeps_identifiers_and_detector_features(
    attack_row: dict[str, object],
) -> None:
    prepared = prepare_inference_frame(pd.DataFrame([attack_row]))
    expected = [name for name in ALL_FEATURES if name in set(IDENTIFIER_FEATURES + DETECTOR_FEATURES)]
    assert list(prepared.columns) == expected
    assert len(prepared.columns) == 118
