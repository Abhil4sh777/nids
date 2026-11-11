"""Inference -> classification -> SHAP -> evidence -> LLM orchestration."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

import pandas as pd

from config import Settings
from explain.evidence import EvidencePacket, build_evidence_packet
from explain.knowledge_base import KnowledgeBase, load_knowledge_base
from explain.llm import Explanation, OllamaClient
from explain.shap_explainer import ShapService
from features.validation import prepare_flow_frame
from models.inference import FlowPrediction, InferenceEngine
from models.loader import LoadedModels, load_models

logger = logging.getLogger(__name__)


class ExplanationClient(Protocol):
    def generate(self, packet: EvidencePacket) -> Explanation: ...


@dataclass
class FlowResult:
    """One analyzed flow, ready for the UI store."""

    row_key: str
    flow_id: str
    timestamp: str
    src_ip: str
    src_port: Any
    dst_ip: str
    dst_port: Any
    is_attack: bool
    attack_probability: float
    predicted_class: str | None
    class_probability: float | None
    evidence: EvidencePacket | None = None
    explanation: Explanation | None = None

    @property
    def verdict(self) -> str:
        return "Attack" if self.is_attack else "Benign"


def _text(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value)


def _port(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class Pipeline:
    def __init__(
        self,
        models: LoadedModels,
        knowledge: KnowledgeBase,
        llm: ExplanationClient,
    ) -> None:
        self.models = models
        self.knowledge = knowledge
        self.llm = llm
        self.engine = InferenceEngine(models)
        self.shap = ShapService(models)

    def analyze_frame(
        self, df: pd.DataFrame, *, batch_id: str = ""
    ) -> list[FlowResult]:
        """Run models and SHAP.  The LLM is deliberately not called here."""

        prepared = prepare_flow_frame(df)
        predictions = self.engine.predict(prepared)
        results: list[FlowResult] = []

        for prediction in predictions:
            row = prepared.iloc[prediction.row_position]
            row_key = (
                f"{batch_id}:{prediction.row_position}:{prediction.flow_id}"
                if batch_id
                else f"{prediction.row_position}:{prediction.flow_id}"
            )
            evidence = None
            if prediction.is_attack:
                evidence = self._build_evidence(prepared, prediction)

            results.append(
                FlowResult(
                    row_key=row_key,
                    flow_id=prediction.flow_id,
                    timestamp=_text(row.get("timestamp")),
                    src_ip=_text(row.get("src_ip")),
                    src_port=_port(row.get("src_port")),
                    dst_ip=_text(row.get("dst_ip")),
                    dst_port=_port(row.get("dst_port")),
                    is_attack=prediction.is_attack,
                    attack_probability=prediction.attack_probability,
                    predicted_class=prediction.predicted_class,
                    class_probability=prediction.class_probability,
                    evidence=evidence,
                )
            )
        return results

    def _build_evidence(
        self, prepared: pd.DataFrame, prediction: FlowPrediction
    ) -> EvidencePacket:
        row = prepared.iloc[prediction.row_position]
        detector_top5 = self.shap.detector_contributions(row)
        if prediction.class_index is None:
            raise ValueError("Attack prediction has no classifier class index")
        classifier_top5 = self.shap.classifier_contributions(
            row, prediction.class_index
        )
        return build_evidence_packet(
            prediction, row, detector_top5, classifier_top5, self.knowledge
        )

    def explain_result(self, result: FlowResult) -> Explanation | None:
        """Call the LLM for one attack.  Benign rows never reach the LLM."""

        if not result.is_attack:
            return None
        if result.evidence is None:
            raise ValueError("Attack result is missing its evidence packet")
        return self.llm.generate(result.evidence)

    def run_frame(
        self, df: pd.DataFrame, *, batch_id: str = ""
    ) -> list[FlowResult]:
        """Synchronous convenience path used by tests and batch replays."""

        results = self.analyze_frame(df, batch_id=batch_id)
        for result in results:
            explanation = self.explain_result(result)
            if explanation is not None:
                result.explanation = explanation
        return results


def build_pipeline(settings: Settings) -> Pipeline:
    models = load_models(settings)
    knowledge = load_knowledge_base(settings.knowledge_dir)
    return Pipeline(models, knowledge, OllamaClient(settings))
