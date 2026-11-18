"""Build the evidence packet that is the only source of facts for the LLM."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np
import pandas as pd

from explain.knowledge_base import KnowledgeBase
from explain.shap_explainer import TopFeature
from models.inference import FlowPrediction


def _jsonable(value: Any) -> Any:
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, float) and np.isnan(value):
        return None
    if value is pd.NA or value is pd.NaT:
        return None
    return value


def _feature_dict(contribution: TopFeature, kb: KnowledgeBase) -> dict[str, Any]:
    return {
        "feature": contribution.feature,
        "meaning": kb.feature_meaning(contribution.feature),
        "value": _jsonable(contribution.value),
        "shap_value": float(contribution.shap_value),
    }


@dataclass(frozen=True)
class EvidencePacket:
    flow_id: str
    attack_probability: float
    predicted_class: str
    class_probability: float
    description: str
    mitigation: tuple[str, ...]
    detector_top5: tuple[dict[str, Any], ...]
    classifier_top5: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "attack_probability": self.attack_probability,
            "predicted_class": self.predicted_class,
            "class_probability": self.class_probability,
            "description": self.description,
            "mitigation": list(self.mitigation),
            "detector_top5": [dict(item) for item in self.detector_top5],
            "classifier_top5": [dict(item) for item in self.classifier_top5],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidencePacket":
        """Rebuild a packet from its plain-dict form.

        Backends accept either shape; this keeps the ``LLMBackend`` contract
        (``evidence: dict``) usable without leaking construction logic.
        """

        try:
            return cls(
                flow_id=str(data["flow_id"]),
                attack_probability=float(data["attack_probability"]),
                predicted_class=str(data["predicted_class"]),
                class_probability=float(data["class_probability"]),
                description=str(data["description"]),
                mitigation=tuple(str(item) for item in data["mitigation"]),
                detector_top5=tuple(
                    dict(item) for item in data["detector_top5"]
                ),
                classifier_top5=tuple(
                    dict(item) for item in data["classifier_top5"]
                ),
            )
        except KeyError as exc:
            raise ValueError(
                f"Evidence packet is missing required field {exc}"
            ) from exc


def build_evidence_packet(
    prediction: FlowPrediction,
    row: pd.Series,
    detector_top5: list[TopFeature],
    classifier_top5: list[TopFeature],
    kb: KnowledgeBase,
) -> EvidencePacket:
    """Assemble one alert.  Benign rows must never reach this function."""

    if not prediction.is_attack:
        raise ValueError("Evidence packets are only built for flagged attacks")
    if prediction.predicted_class is None or prediction.class_probability is None:
        raise ValueError("Attack prediction is missing its classifier result")

    attack = kb.attack(prediction.predicted_class)
    if len(detector_top5) != 5 or len(classifier_top5) != 5:
        raise ValueError("Evidence packets require exactly five SHAP features each")

    return EvidencePacket(
        flow_id=prediction.flow_id,
        attack_probability=float(prediction.attack_probability),
        predicted_class=prediction.predicted_class,
        class_probability=float(prediction.class_probability),
        description=attack.description,
        mitigation=attack.mitigation,
        detector_top5=tuple(_feature_dict(item, kb) for item in detector_top5),
        classifier_top5=tuple(_feature_dict(item, kb) for item in classifier_top5),
    )


def predictions_from_row(row: pd.Series) -> dict[str, Any]:
    """Small helper for tests and UI detail views: expose raw identifier fields."""

    keys = ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port"]
    return {key: _jsonable(row.get(key)) for key in keys}
