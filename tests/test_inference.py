from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from features.contract import ALL_FEATURES, DETECTOR_THRESHOLD
from features.validation import FeatureContractError, prepare_flow_frame
from models.inference import InferenceEngine


def test_real_models_predict_attack_and_benign(
    engine: InferenceEngine, mixed_frame: pd.DataFrame
) -> None:
    predictions = engine.predict(mixed_frame)
    assert len(predictions) == 2
    attack, benign = predictions
    assert attack.flow_id == "attack-0"
    assert attack.is_attack is True
    assert attack.attack_probability >= DETECTOR_THRESHOLD
    assert attack.predicted_class == "SSH-Patator"
    assert attack.class_index == 6
    assert 0.0 <= attack.class_probability <= 1.0
    assert benign.flow_id == "benign-0"
    assert benign.is_attack is False
    assert benign.predicted_class is None
    assert benign.class_probability is None


def test_threshold_boundary_is_inclusive_at_3545(
    engine: InferenceEngine, mixed_frame: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        engine,
        "detector_probabilities",
        lambda df: np.array([0.3544, 0.3545]),
    )
    monkeypatch.setattr(
        engine,
        "classifier_probabilities",
        lambda df: np.array([[0.9] + [0.01] * 12]),
    )
    predictions = engine.predict(mixed_frame)
    assert predictions[0].is_attack is False
    assert predictions[1].is_attack is True
    assert predictions[1].predicted_class == "DoS_Hulk"


def test_empty_frame_returns_no_predictions(engine: InferenceEngine) -> None:
    frame = prepare_flow_frame(pd.DataFrame(columns=ALL_FEATURES))
    assert engine.predict(frame) == []


def test_missing_flow_id_is_rejected(
    engine: InferenceEngine, mixed_frame: pd.DataFrame
) -> None:
    with pytest.raises(FeatureContractError, match="flow_id"):
        engine.predict(mixed_frame.drop(columns=["flow_id"]))


def test_missing_flow_id_value_is_rejected(
    engine: InferenceEngine, mixed_frame: pd.DataFrame
) -> None:
    frame = mixed_frame.copy()
    frame.loc[0, "flow_id"] = None
    with pytest.raises(FeatureContractError, match="flow_id"):
        engine.predict(frame)
