from __future__ import annotations

from dataclasses import dataclass

import pytest

from explain.evidence import EvidencePacket
from explain.llm import ExplanationService
from explain.llm.base import BackendError
from explain.llm.grounding import ground_explanation
from explain.llm.service import DEFAULT_TIMEOUT_SECONDS


@dataclass
class RaisingBackend:
    """Backend that always fails, standing in for a runner or model error."""

    name: str = "raising"
    error: Exception = BackendError("runner failed")

    def explain(self, evidence):
        raise self.error

    def count_prompt_tokens(self, evidence):
        return 1


def test_grounding_keeps_the_summary_and_rebuilds_the_rest(
    evidence_packet: EvidencePacket,
) -> None:
    text = ground_explanation(
        "Summary: SSH-Patator was detected.\n"
        "Why it was flagged: invented reason.\n"
        "Recommended actions:\n"
        "1. Invented action that is not in the packet.",
        evidence_packet,
    )

    assert text.startswith("Summary: SSH-Patator was detected.")
    assert "Invented action" not in text
    assert "Why it was flagged: The detector assigned P(Attack)=" in text
    for action in evidence_packet.mitigation:
        assert action in text


def test_grounding_rejects_a_summary_that_is_a_mitigation(
    evidence_packet: EvidencePacket,
) -> None:
    text = ground_explanation(
        f"Summary: {evidence_packet.mitigation[0]}\n"
        "Why it was flagged: x\n"
        "Recommended actions:\n1. y",
        evidence_packet,
    )

    assert text.startswith(
        f"Summary: The detector flagged this flow as {evidence_packet.predicted_class}"
    )
    assert evidence_packet.description in text
    assert text.count(evidence_packet.mitigation[0]) == 1
    assert "invented" not in text.lower()


def test_grounding_requires_a_summary_section(
    evidence_packet: EvidencePacket,
) -> None:
    with pytest.raises(ValueError, match="Summary"):
        ground_explanation("It is probably bad.", evidence_packet)


def test_service_falls_back_on_backend_failure(
    evidence_packet: EvidencePacket,
) -> None:
    explanation = ExplanationService(
        RaisingBackend(error=TimeoutError("timed out"))
    ).explain(evidence_packet)

    assert explanation.source == "fallback"
    assert "timed out" in (explanation.error or "")
    assert "Summary:" in explanation.text
    assert "Recommended actions:" in explanation.text


def test_service_falls_back_when_backend_returns_nothing(
    evidence_packet: EvidencePacket,
) -> None:
    class EmptyBackend:
        name = "empty"

        def explain(self, evidence):
            return "   "

        def count_prompt_tokens(self, evidence):
            return 1

    explanation = ExplanationService(EmptyBackend()).explain(evidence_packet)
    assert explanation.source == "fallback"
    assert "empty" in (explanation.error or "").lower()


def test_service_returns_llm_text(
    evidence_packet: EvidencePacket,
) -> None:
    class GoodBackend:
        name = "good"

        def explain(self, evidence):
            return "Summary: grounded text"

        def count_prompt_tokens(self, evidence):
            return 42

    explanation = ExplanationService(GoodBackend()).explain(evidence_packet)
    assert explanation.source == "llm"
    assert explanation.text == "Summary: grounded text"


def test_fallback_uses_only_evidence(evidence_packet: EvidencePacket) -> None:
    explanation = ExplanationService.fallback(evidence_packet, error="test")
    assert explanation.source == "fallback"
    assert evidence_packet.predicted_class in explanation.text
    assert evidence_packet.description in explanation.text
    for action in evidence_packet.mitigation:
        assert action in explanation.text
    assert explanation.error == "test"


def test_service_reports_the_backend_timeout(evidence_packet: EvidencePacket) -> None:
    """The UI must ask the backend for its timeout, never read engine settings."""

    class TimeoutBackend:
        name = "timeout"
        timeout_seconds = 7.5

        def explain(self, evidence):
            return "Summary: text"

        def count_prompt_tokens(self, evidence):
            return 1

    assert ExplanationService(TimeoutBackend()).timeout_seconds == 7.5


def test_service_has_a_default_timeout(evidence_packet: EvidencePacket) -> None:
    class BareBackend:
        name = "bare"

        def explain(self, evidence):
            return "Summary: text"

        def count_prompt_tokens(self, evidence):
            return 1

    assert (
        ExplanationService(BareBackend()).timeout_seconds
        == DEFAULT_TIMEOUT_SECONDS
    )
