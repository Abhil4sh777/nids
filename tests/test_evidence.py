from __future__ import annotations

import pandas as pd
import pytest

from explain.evidence import EvidencePacket, build_evidence_packet, predictions_from_row
from explain.knowledge_base import KnowledgeBase
from explain.shap_explainer import ShapService
from models.inference import FlowPrediction


def _packet(
    models, knowledge: KnowledgeBase, prepared_attack: pd.DataFrame, engine
) -> EvidencePacket:
    prediction = engine.predict(prepared_attack)[0]
    service = ShapService(models)
    detector_top = service.detector_contributions(prepared_attack.iloc[0])
    classifier_top = service.classifier_contributions(
        prepared_attack.iloc[0], prediction.class_index
    )
    return build_evidence_packet(
        prediction,
        prepared_attack.iloc[0],
        detector_top,
        classifier_top,
        knowledge,
    )


def test_evidence_packet_fields(
    models,
    knowledge: KnowledgeBase,
    prepared_attack: pd.DataFrame,
    engine,
) -> None:
    packet = _packet(models, knowledge, prepared_attack, engine)
    data = packet.to_dict()
    assert set(data) == {
        "flow_id",
        "attack_probability",
        "predicted_class",
        "class_probability",
        "description",
        "mitigation",
        "detector_top5",
        "classifier_top5",
    }
    assert data["flow_id"] == "attack-0"
    assert data["predicted_class"] == "SSH-Patator"
    assert 0.0 <= data["attack_probability"] <= 1.0
    assert 0.0 <= data["class_probability"] <= 1.0
    assert data["mitigation"] == list(knowledge.attack("SSH-Patator").mitigation)
    assert data["description"] == knowledge.attack("SSH-Patator").description
    for key in ("detector_top5", "classifier_top5"):
        assert len(data[key]) == 5
        for item in data[key]:
            assert set(item) == {"feature", "meaning", "value", "shap_value"}
            assert item["meaning"] == knowledge.feature_meaning(item["feature"])


def test_evidence_values_are_the_flow_raw_values(
    models,
    knowledge: KnowledgeBase,
    prepared_attack: pd.DataFrame,
    engine,
) -> None:
    packet = _packet(models, knowledge, prepared_attack, engine)
    row = prepared_attack.iloc[0]
    for item in packet.detector_top5 + packet.classifier_top5:
        assert item["value"] == pytest.approx(float(row[item["feature"]]))


def test_benign_prediction_cannot_build_evidence(
    knowledge: KnowledgeBase, mixed_frame: pd.DataFrame, engine
) -> None:
    benign = engine.predict(mixed_frame)[1]
    with pytest.raises(ValueError, match="only built for flagged attacks"):
        build_evidence_packet(benign, mixed_frame.iloc[1], [], [], knowledge)


def test_attack_without_classifier_result_is_rejected(
    knowledge: KnowledgeBase, prepared_attack: pd.DataFrame
) -> None:
    prediction = FlowPrediction(
        row_position=0,
        flow_id="attack-0",
        is_attack=True,
        attack_probability=0.9,
        predicted_class=None,
        class_index=None,
        class_probability=None,
    )
    with pytest.raises(ValueError, match="classifier result"):
        build_evidence_packet(
            prediction, prepared_attack.iloc[0], [], [], knowledge
        )


def test_predictions_from_row_returns_identifiers(
    prepared_attack: pd.DataFrame,
) -> None:
    identifiers = predictions_from_row(prepared_attack.iloc[0])
    assert identifiers["flow_id"] == "attack-0"
    assert identifiers["src_ip"] == "10.0.0.1"
    assert identifiers["dst_port"] == prepared_attack.iloc[0]["dst_port"]
