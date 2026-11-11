"""Load the fitted artifacts, enforce the contract, and force CPU inference."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import shap

from config import Settings
from features.contract import CLASSIFIER_FEATURES, DETECTOR_FEATURES

logger = logging.getLogger(__name__)


class ModelContractError(RuntimeError):
    """Raised when a fitted artifact does not match the feature contract."""


@dataclass(frozen=True)
class LoadedModel:
    name: str
    pipeline: Any
    feature_names: tuple[str, ...]
    encoded_feature_names: tuple[str, ...]
    classes: tuple[int, ...]
    explainer: shap.TreeExplainer

    @property
    def classifier(self) -> Any:
        return self.pipeline.named_steps["classifier"]

    @property
    def preprocessing(self) -> Any:
        return self.pipeline.named_steps["preprocessing"]

    def booster_device(self) -> str:
        config = json.loads(self.classifier.get_booster().save_config())
        return config["learner"]["generic_param"].get("device", "unknown")


@dataclass(frozen=True)
class LoadedModels:
    detector: LoadedModel
    classifier: LoadedModel


def _verify_feature_contract(
    model: LoadedModel, expected_features: list[str]
) -> None:
    actual = list(getattr(model.pipeline, "feature_names_in_", []))
    if actual != expected_features:
        raise ModelContractError(
            f"{model.name} was trained on different feature names/order. "
            f"Expected {len(expected_features)} columns starting with "
            f"{expected_features[:3]}, got {len(actual)} starting with "
            f"{actual[:3]}."
        )

    encoder = model.preprocessing.named_steps["encoder"]
    encoded_names = list(encoder.get_feature_names_out())
    booster_names = list(model.classifier.get_booster().feature_names or [])
    if encoded_names != booster_names:
        raise ModelContractError(
            f"{model.name} encoded feature names do not match the booster order"
        )
    if len(encoded_names) != len(expected_features):
        raise ModelContractError(
            f"{model.name} encoded {len(encoded_names)} columns, expected "
            f"{len(expected_features)}"
        )


def load_model(
    path: Path,
    *,
    name: str,
    expected_features: list[str],
    expected_classes: tuple[int, ...],
    device: str = "cpu",
) -> LoadedModel:
    """Load one artifact and apply the CPU inference policy."""

    if device != "cpu":
        raise ModelContractError(
            "XGBoost inference is defined as CPU-only for this project; "
            f"refusing device={device!r}."
        )
    if not path.exists():
        raise ModelContractError(
            f"Model artifact not found: {path}. Run from the project root or set "
            "NIDS_MODEL_DIR."
        )

    pipeline = joblib.load(path)
    if "preprocessing" not in pipeline.named_steps:
        raise ModelContractError(f"{name} artifact has no 'preprocessing' step")
    if "classifier" not in pipeline.named_steps:
        raise ModelContractError(f"{name} artifact has no 'classifier' step")

    classifier = pipeline.named_steps["classifier"]
    try:
        classifier.set_params(device="cpu")
        classifier.get_booster().set_param({"device": "cpu"})
    except Exception as exc:  # pragma: no cover - defensive around xgboost APIs
        raise ModelContractError(
            f"Could not force {name} XGBoost inference onto CPU: {exc}"
        ) from exc

    classes = tuple(int(value) for value in classifier.classes_)
    if classes != expected_classes:
        raise ModelContractError(
            f"{name} classes are {classes}, expected {expected_classes}"
        )

    encoder = pipeline.named_steps["preprocessing"].named_steps["encoder"]
    model = LoadedModel(
        name=name,
        pipeline=pipeline,
        feature_names=tuple(expected_features),
        encoded_feature_names=tuple(encoder.get_feature_names_out()),
        classes=classes,
        explainer=shap.TreeExplainer(classifier),
    )
    _verify_feature_contract(model, expected_features)

    if model.booster_device() != "cpu":
        raise ModelContractError(
            f"{name} booster is still on device {model.booster_device()!r}"
        )

    logger.info(
        "Loaded %s from %s (%d features, %d classes, device=cpu)",
        name,
        path,
        len(expected_features),
        len(classes),
    )
    return model


def load_models(settings: Settings) -> LoadedModels:
    detector = load_model(
        settings.detector_path,
        name="detector",
        expected_features=DETECTOR_FEATURES,
        expected_classes=(0, 1),
        device=settings.xgboost_device,
    )
    classifier = load_model(
        settings.classifier_path,
        name="classifier",
        expected_features=CLASSIFIER_FEATURES,
        expected_classes=tuple(range(13)),
        device=settings.xgboost_device,
    )
    return LoadedModels(detector=detector, classifier=classifier)
