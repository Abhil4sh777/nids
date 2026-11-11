from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from config import Settings
from features.contract import CLASSIFIER_FEATURES, DETECTOR_FEATURES
from models.loader import ModelContractError, load_model, load_models


def test_models_match_contract(settings: Settings) -> None:
    models = load_models(settings)
    assert list(models.detector.feature_names) == DETECTOR_FEATURES
    assert list(models.classifier.feature_names) == CLASSIFIER_FEATURES
    assert list(models.detector.pipeline.feature_names_in_) == DETECTOR_FEATURES
    assert list(models.classifier.pipeline.feature_names_in_) == CLASSIFIER_FEATURES


def test_encoders_and_boosters_agree(settings: Settings) -> None:
    models = load_models(settings)
    for model in (models.detector, models.classifier):
        encoder = model.preprocessing.named_steps["encoder"]
        assert list(encoder.get_feature_names_out()) == list(
            model.classifier.get_booster().feature_names
        )
        assert tuple(encoder.get_feature_names_out()) == model.encoded_feature_names
        assert len(model.encoded_feature_names) == len(model.feature_names)


def test_inference_device_is_cpu(settings: Settings) -> None:
    models = load_models(settings)
    assert models.detector.booster_device() == "cpu"
    assert models.classifier.booster_device() == "cpu"
    assert models.detector.classifier.get_params()["device"] == "cpu"
    assert models.classifier.classifier.get_params()["device"] == "cpu"


def test_classes_are_contract_classes(settings: Settings) -> None:
    models = load_models(settings)
    assert models.detector.classes == (0, 1)
    assert models.classifier.classes == tuple(range(13))


def test_device_other_than_cpu_is_rejected(settings: Settings) -> None:
    with pytest.raises(ModelContractError, match="CPU-only"):
        load_model(
            settings.detector_path,
            name="detector",
            expected_features=DETECTOR_FEATURES,
            expected_classes=(0, 1),
            device="cuda",
        )


def test_missing_artifact_has_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ModelContractError, match="not found"):
        load_model(
            tmp_path / "missing.joblib",
            name="detector",
            expected_features=DETECTOR_FEATURES,
            expected_classes=(0, 1),
        )


def test_wrong_expected_feature_count_is_rejected(settings: Settings) -> None:
    with pytest.raises(ModelContractError, match="different feature names"):
        load_model(
            settings.detector_path,
            name="detector",
            expected_features=DETECTOR_FEATURES[:-1],
            expected_classes=(0, 1),
        )
