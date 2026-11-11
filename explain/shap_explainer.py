"""SHAP attributions for the detector and classifier.

Both explainers are TreeExplainers built once at startup against the inner
XGBoost classifier (not the whole Pipeline).  The single-row encoded DataFrame
is the same data that is fed to the model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
import pandas as pd

from features.contract import DETECTOR_FEATURES
from features.model_input import (
    classifier_input,
    detector_input,
    encode_with_pipeline,
    encoded_to_raw_feature,
)
from features.validation import FeatureContractError
from models.loader import LoadedModel, LoadedModels

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TopFeature:
    feature: str
    value: object
    shap_value: float


def _unwrap(values: object) -> object:
    if hasattr(values, "values"):
        return values.values
    return values


def select_shap_values(
    values: object, class_index: int, n_features: int
) -> np.ndarray:
    """Normalise SHAP output across versions and model types.

    Supported shapes for a single row:
    - ``(1, n_features)``
    - a list of per-class ``(1, n_features)`` arrays
    - ``(1, n_features, n_classes)``
    - ``(1, n_classes, n_features)``
    """

    values = _unwrap(values)

    if isinstance(values, list):
        if class_index >= len(values):
            raise ValueError(
                f"SHAP returned {len(values)} class arrays, need index {class_index}"
            )
        selected = np.asarray(values[class_index])
        if selected.shape[0] != 1:
            raise ValueError(f"Expected one row of SHAP values, got {selected.shape}")
        return selected[0]

    array = np.asarray(values)
    if array.ndim == 2:
        if array.shape[0] != 1 or array.shape[1] != n_features:
            raise ValueError(
                f"Expected SHAP shape (1, {n_features}), got {array.shape}"
            )
        return array[0]
    if array.ndim == 3:
        if array.shape[0] != 1:
            raise ValueError(f"Expected one row of SHAP values, got {array.shape}")
        if array.shape[1] == n_features:
            return array[0, :, class_index]
        if array.shape[-1] == n_features:
            return array[0, class_index, :]
        raise ValueError(
            f"Cannot locate the feature axis in SHAP shape {array.shape}"
        )
    raise ValueError(f"Unsupported SHAP output shape {array.shape}")


def top_features(
    encoded_row: pd.DataFrame,
    shap_values: np.ndarray,
    raw_row: pd.Series,
    *,
    k: int = 5,
) -> list[TopFeature]:
    """Return the k largest absolute SHAP values, preserving their sign."""

    if len(shap_values) != encoded_row.shape[1]:
        raise FeatureContractError(
            "SHAP values and encoded features have different lengths"
        )
    order = np.argsort(-np.abs(shap_values))[:k]
    result: list[TopFeature] = []
    for position in order:
        encoded_name = str(encoded_row.columns[int(position)])
        raw_name = encoded_to_raw_feature(encoded_name, list(raw_row.index))
        raw_value = raw_row[raw_name]
        if isinstance(raw_value, np.generic):
            raw_value = raw_value.item()
        result.append(
            TopFeature(
                feature=raw_name,
                value=raw_value,
                shap_value=float(shap_values[int(position)]),
            )
        )
    return result


def _single_frame(row: pd.Series | pd.DataFrame) -> pd.DataFrame:
    """Return a one-row frame that preserves the prepared column dtypes."""

    if isinstance(row, pd.Series):
        frame = row.to_frame().T.infer_objects()
    elif isinstance(row, pd.DataFrame):
        frame = row.copy()
    else:
        raise TypeError(f"Expected a Series or DataFrame row, got {type(row).__name__}")
    if len(frame) != 1:
        raise ValueError(f"Expected exactly one flow row, got {len(frame)}")
    return frame.reset_index(drop=True)


class ShapService:
    """Per-flow explanations for the detector and the predicted class."""

    def __init__(self, models: LoadedModels) -> None:
        self.models = models

    def detector_contributions(
        self, row: pd.Series | pd.DataFrame
    ) -> list[TopFeature]:
        single = _single_frame(row)
        X = detector_input(single)
        return self._contributions(
            model=self.models.detector,
            X=X,
            raw_row=single.iloc[0],
            class_index=1,  # Attack class
        )

    def classifier_contributions(
        self, row: pd.Series | pd.DataFrame, class_index: int
    ) -> list[TopFeature]:
        single = _single_frame(row)
        X = classifier_input(single)
        return self._contributions(
            model=self.models.classifier,
            X=X,
            raw_row=single.iloc[0],
            class_index=class_index,
        )

    def _contributions(
        self,
        *,
        model: LoadedModel,
        X: pd.DataFrame,
        raw_row: pd.Series,
        class_index: int,
    ) -> list[TopFeature]:
        encoded = encode_with_pipeline(model.pipeline, X)
        values = model.explainer.shap_values(encoded)
        selected = select_shap_values(
            values, class_index=class_index, n_features=encoded.shape[1]
        )
        return top_features(encoded, selected, raw_row, k=5)
