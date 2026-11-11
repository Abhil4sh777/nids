"""Prompt template for the small local LLM.

Keep this file free of I/O and model logic so the wording can be tuned without
touching the pipeline.
"""

from __future__ import annotations

from typing import Any

from explain.evidence import EvidencePacket

SYSTEM_PROMPT = """You are a network security analyst explaining an intrusion-detection alert.
Use ONLY the evidence in the user message. Do not invent IP addresses, hostnames, CVEs, tools, or facts. Do not describe mitigations as if they were already in place. If the evidence is insufficient, say what is missing.
Answer in exactly this format:
Summary: one short sentence naming the predicted class and attack probability.
Why it was flagged: two or three short sentences that refer only to attack_probability, class_probability, and the listed feature names with their SHAP signs. Do not explain what a feature means. Do not mention mitigations and do not claim any defense is already in place.
Recommended actions: copy the three mitigation bullets verbatim, one per line, numbered 1 to 3. Do not add any other action."""


def _format_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def _format_top5(items: tuple[dict[str, Any], ...]) -> list[str]:
    lines: list[str] = []
    for item in items:
        lines.append(
            "- feature={feature} | meaning={meaning} | value={value} | shap={shap}".format(
                feature=item["feature"],
                meaning=item["meaning"],
                value=_format_value(item["value"]),
                shap=_format_value(item["shap_value"]),
            )
        )
    return lines


def build_prompt(packet: EvidencePacket) -> str:
    """Render the evidence packet as short labeled text for a 1B model."""

    lines = [
        "EVIDENCE",
        f"flow_id: {packet.flow_id}",
        f"attack_probability: {_format_value(packet.attack_probability)}",
        f"predicted_class: {packet.predicted_class}",
        f"class_probability: {_format_value(packet.class_probability)}",
        f"description: {packet.description}",
        "mitigation:",
    ]
    lines.extend(f"- {item}" for item in packet.mitigation)
    lines.append("detector_top5:")
    lines.extend(_format_top5(packet.detector_top5))
    lines.append("classifier_top5:")
    lines.extend(_format_top5(packet.classifier_top5))
    lines.append("END EVIDENCE")
    return "\n".join(lines)
