"""Detector and classifier inference.  The LLM never decides anything here."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from features.contract import CLASSIFIER_LABELS, DETECTOR_THRESHOLD
from features.model_input import classifier_input, detector_input
from features.validation import FeatureContractError
from models.loader import LoadedModels


@dataclass(frozen=True)
class FlowPrediction:
    """Model-only verdict for one flow row."""

    row_position: int
    flow_id: str
    is_attack: bool
    attack_probability: float
    predicted_class: str | None
    class_index: int | None
    class_probability: float | None


class InferenceEngine:
    """Thin wrapper around the two fitted pipelines."""

    def __init__(self, models: LoadedModels) -> None:
        self.models = models

    def detector_probabilities(self, df: pd.DataFrame) -> np.ndarray:
        X = detector_input(df)
        probabilities = self.models.detector.pipeline.predict_proba(X)
        return np.asarray(probabilities)[:, 1]

    def classifier_probabilities(self, df: pd.DataFrame) -> np.ndarray:
        X = classifier_input(df)
        return np.asarray(self.models.classifier.pipeline.predict_proba(X))

    def predict(self, df: pd.DataFrame) -> list[FlowPrediction]:
        """Run the detector on every row and the classifier only on attacks."""

        if df.empty:
            return []

        if "flow_id" not in df.columns:
            raise FeatureContractError("flow_id column is required for inference")
        if bool(df["flow_id"].isna().any()):
            raise FeatureContractError("flow_id contains missing values")

        attack_probabilities = self.detector_probabilities(df)
        attack_mask = attack_probabilities >= DETECTOR_THRESHOLD
        attack_positions = np.flatnonzero(attack_mask)

        predicted_classes: dict[int, tuple[str, int, float]] = {}
        if attack_positions.size:
            attack_rows = df.iloc[attack_positions]
            class_probabilities = self.classifier_probabilities(attack_rows)
            class_positions = np.argmax(class_probabilities, axis=1)
            for class_row, position in enumerate(attack_positions):
                class_position = int(class_positions[class_row])
                class_index = int(self.models.classifier.classes[class_position])
                label = CLASSIFIER_LABELS.get(class_index)
                if label is None:
                    raise FeatureContractError(
                        f"Classifier returned unknown class index {class_index}"
                    )
                probability = float(
                    class_probabilities[class_row, class_position]
                )
                predicted_classes[int(position)] = (label, class_index, probability)

        results: list[FlowPrediction] = []
        for position, row in enumerate(df.itertuples(index=False)):
            is_attack = bool(attack_mask[position])
            flow_id = str(getattr(row, "flow_id"))
            if is_attack:
                label, class_index, class_probability = predicted_classes[position]
            else:
                label, class_index, class_probability = None, None, None
            results.append(
                FlowPrediction(
                    row_position=position,
                    flow_id=flow_id,
                    is_attack=is_attack,
                    attack_probability=float(attack_probabilities[position]),
                    predicted_class=label,
                    class_index=class_index,
                    class_probability=class_probability,
                )
            )
        return results
