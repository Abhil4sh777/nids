from __future__ import annotations

import pandas as pd

from explain.evidence import build_evidence_packet
from explain.prompt import SYSTEM_PROMPT, build_prompt
from explain.shap_explainer import ShapService


def test_prompt_contains_only_grounded_sections(
    models, knowledge, prepared_attack: pd.DataFrame, engine
) -> None:
    prediction = engine.predict(prepared_attack)[0]
    service = ShapService(models)
    packet = build_evidence_packet(
        prediction,
        prepared_attack.iloc[0],
        service.detector_contributions(prepared_attack.iloc[0]),
        service.classifier_contributions(
            prepared_attack.iloc[0], prediction.class_index
        ),
        knowledge,
    )
    prompt = build_prompt(packet)
    assert "EVIDENCE" in prompt
    assert f"attack_probability: {prediction.attack_probability:.6g}" in prompt
    assert "predicted_class: SSH-Patator" in prompt
    assert packet.description in prompt
    for action in packet.mitigation:
        assert action in prompt
    assert "detector_top5:" in prompt
    assert "classifier_top5:" in prompt
    detector_lines = [
        line
        for line in prompt.splitlines()
        if line.startswith("- feature=") and "shap=" in line
    ]
    assert len(detector_lines) == 10
    assert "src_ip" not in prompt
    assert "10.0.0.1" not in prompt


def test_system_prompt_forbids_invention_and_fixes_format() -> None:
    assert "ONLY the evidence" in SYSTEM_PROMPT
    assert "Do not invent" in SYSTEM_PROMPT
    for section in ("Summary:", "Why it was flagged:", "Recommended actions:"):
        assert section in SYSTEM_PROMPT
    assert "verbatim" in SYSTEM_PROMPT
