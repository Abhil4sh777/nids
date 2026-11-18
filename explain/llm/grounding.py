"""Evidence-grounded explanation text.

A 1B model can add plausible-sounding mitigations, feature meanings, or claim
that a defense is already deployed.  The knowledge packet is the contract, so
the "Why" and "Recommended actions" sections are always rebuilt from grounded
evidence by every backend.  Only the Summary is taken from the model.
"""

from __future__ import annotations

import re

from explain.evidence import EvidencePacket

DEFAULT_SUMMARY_LIMIT = 400


def ground_explanation(
    text: str, packet: EvidencePacket, *, summary_limit: int = DEFAULT_SUMMARY_LIMIT
) -> str:
    """Rebuild an LLM answer so every fact comes from the evidence packet.

    Raises ``ValueError`` when the response has no usable Summary section; the
    caller then falls back to :func:`fallback_text`.
    """

    summary_match = re.search(
        r"(?im)^\s*summary\s*:\s*(.+?)(?=\n\s*(?:why it was flagged|recommended actions)\s*:|$)",
        text,
        flags=re.DOTALL,
    )
    if summary_match is None:
        raise ValueError("LLM response did not include a Summary section")

    candidate = " ".join(summary_match.group(1).split())
    if (
        not candidate
        or len(candidate) > summary_limit
        or "recommended actions" in candidate.lower()
        or any(action.lower() in candidate.lower() for action in packet.mitigation)
        or (
            packet.predicted_class.lower() not in candidate.lower()
            and "attack" not in candidate.lower()
        )
    ):
        candidate = (
            f"The detector flagged this flow as {packet.predicted_class} "
            f"(P(Attack)={packet.attack_probability:.3f})."
        )

    detector = ", ".join(
        f"{item['feature']} (SHAP {item['shap_value']:+.3f})"
        for item in packet.detector_top5[:3]
    )
    classifier = ", ".join(
        f"{item['feature']} (SHAP {item['shap_value']:+.3f})"
        for item in packet.classifier_top5[:3]
    )
    why = (
        f"The detector assigned P(Attack)={packet.attack_probability:.3f}. "
        f"The classifier selected {packet.predicted_class} with probability "
        f"{packet.class_probability:.3f}. "
        f"The largest detector contributions were {detector}. "
        f"The largest classifier contributions were {classifier}. "
        f"{packet.description}"
    )
    actions = "\n".join(
        f"{position}. {action}"
        for position, action in enumerate(packet.mitigation, start=1)
    )
    return (
        f"Summary: {candidate}\n"
        f"Why it was flagged: {why}\n"
        f"Recommended actions:\n{actions}"
    )


def fallback_text(packet: EvidencePacket) -> str:
    """Deterministic explanation built only from the evidence packet."""

    detector_features = ", ".join(
        item["feature"] for item in packet.detector_top5[:3]
    )
    classifier_features = ", ".join(
        item["feature"] for item in packet.classifier_top5[:3]
    )
    actions = "\n".join(
        f"{position}. {action}"
        for position, action in enumerate(packet.mitigation, start=1)
    )
    return (
        f"Summary: The detector flagged this flow as {packet.predicted_class} "
        f"with P(Attack)={packet.attack_probability:.3f}.\n"
        "Why it was flagged: "
        f"The classifier selected {packet.predicted_class} with probability "
        f"{packet.class_probability:.3f}. "
        f"The strongest detector contributions were {detector_features}; "
        f"the strongest classifier contributions were {classifier_features}. "
        f"{packet.description}\n"
        f"Recommended actions:\n{actions}"
    )
