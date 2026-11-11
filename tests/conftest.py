from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from config import Settings, get_settings
from explain.evidence import EvidencePacket, build_evidence_packet
from explain.knowledge_base import KnowledgeBase, load_knowledge_base
from explain.llm import Explanation
from explain.shap_explainer import ShapService
from features.contract import ALL_FEATURES
from features.validation import prepare_flow_frame
from models.inference import InferenceEngine
from models.loader import LoadedModels, load_models


@pytest.fixture(scope="session")
def settings() -> Settings:
    return get_settings()


@pytest.fixture(scope="session")
def models(settings: Settings) -> LoadedModels:
    return load_models(settings)


@pytest.fixture(scope="session")
def knowledge(settings: Settings) -> KnowledgeBase:
    return load_knowledge_base(settings.knowledge_dir)


@pytest.fixture(scope="session")
def engine(models: LoadedModels) -> InferenceEngine:
    return InferenceEngine(models)


@pytest.fixture()
def tmp_settings(settings: Settings, tmp_path: Path) -> Settings:
    return replace(
        settings,
        capture_dir=tmp_path / "pcaps",
        output_dir=tmp_path / "flows",
    )


def zero_row(flow_id: str = "benign-0") -> dict[str, object]:
    row: dict[str, object] = {feature: 0.0 for feature in ALL_FEATURES}
    row.update(
        flow_id=flow_id,
        timestamp="2026-01-01 00:00:00",
        src_ip="10.0.0.1",
        src_port=12345,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
    )
    return row


def random_row(seed: int, flow_id: str) -> dict[str, object]:
    """Deterministic synthetic flow.  Seed 0 is an attack with the real model."""

    rng = np.random.default_rng(seed)
    row: dict[str, object] = {feature: 0.0 for feature in ALL_FEATURES}
    for feature in ALL_FEATURES:
        if feature in {"flow_id", "timestamp", "src_ip", "dst_ip"}:
            continue
        if feature == "protocol":
            row[feature] = "TCP"
        elif feature in {"src_port", "dst_port"}:
            row[feature] = int(rng.integers(1, 65535))
        elif feature == "duration":
            row[feature] = float(rng.uniform(0.001, 100))
        else:
            row[feature] = float(rng.uniform(0, 1000))
    row.update(
        flow_id=flow_id,
        timestamp="2026-01-01 00:00:00",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
    return row


@pytest.fixture()
def attack_row() -> dict[str, object]:
    return random_row(0, "attack-0")


@pytest.fixture()
def benign_row() -> dict[str, object]:
    return zero_row()


@pytest.fixture()
def prepared_attack(attack_row: dict[str, object]) -> pd.DataFrame:
    return prepare_flow_frame(pd.DataFrame([attack_row]))


@pytest.fixture()
def mixed_frame(prepared_attack: pd.DataFrame) -> pd.DataFrame:
    benign = prepare_flow_frame(pd.DataFrame([zero_row()]))
    return pd.concat([prepared_attack, benign], ignore_index=True)


class StubLLM:
    def __init__(self, text: str = "Stub explanation") -> None:
        self.text = text
        self.packets: list[object] = []

    def generate(self, packet: object) -> Explanation:
        self.packets.append(packet)
        return Explanation(text=self.text, source="llm")


@pytest.fixture()
def stub_llm() -> StubLLM:
    return StubLLM()


@pytest.fixture()
def evidence_packet(
    models: LoadedModels,
    knowledge: KnowledgeBase,
    prepared_attack: pd.DataFrame,
    engine: InferenceEngine,
) -> EvidencePacket:
    prediction = engine.predict(prepared_attack)[0]
    service = ShapService(models)
    return build_evidence_packet(
        prediction,
        prepared_attack.iloc[0],
        service.detector_contributions(prepared_attack.iloc[0]),
        service.classifier_contributions(
            prepared_attack.iloc[0], prediction.class_index
        ),
        knowledge,
    )
