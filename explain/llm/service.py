"""Backend-agnostic explanation service used by the pipeline and UI.

This is the only place that catches backend failures and substitutes the
evidence-based fallback, so no row can ever end up with an empty explanation.
"""

from __future__ import annotations

import logging

from explain.evidence import EvidencePacket
from explain.llm.base import Evidence, Explanation, LLMBackend, as_packet
from explain.llm.grounding import fallback_text

logger = logging.getLogger(__name__)

# Used only when a backend does not declare its own timeout.
DEFAULT_TIMEOUT_SECONDS = 120.0


class ExplanationService:
    """Turns an :class:`LLMBackend` into pipeline-safe explanations."""

    def __init__(self, backend: LLMBackend) -> None:
        self.backend = backend

    @property
    def timeout_seconds(self) -> float:
        """Worst-case duration of one explanation, as declared by the backend."""

        return float(
            getattr(self.backend, "timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        )

    def _log_prompt_size(self, packet: EvidencePacket) -> None:
        try:
            tokens = self.backend.count_prompt_tokens(packet)
        except Exception as exc:  # counting must never block an alert
            logger.debug("Could not count prompt tokens: %s", exc)
            return
        logger.info(
            "LLM alert flow_id=%s backend=%s prompt_tokens=%d",
            packet.flow_id,
            self.backend.name,
            tokens,
        )

    def explain(self, evidence: Evidence) -> Explanation:
        packet = as_packet(evidence)
        self._log_prompt_size(packet)
        try:
            text = self.backend.explain(packet)
            if not text.strip():
                raise ValueError("Backend returned an empty explanation")
            return Explanation(text=text, source="llm")
        except Exception as exc:
            logger.warning(
                "LLM backend %s failed for flow %s: %s",
                self.backend.name,
                packet.flow_id,
                exc,
            )
            return self.fallback(packet, error=str(exc))

    @staticmethod
    def fallback(
        evidence: Evidence, *, error: str | None = None
    ) -> Explanation:
        packet = as_packet(evidence)
        return Explanation(
            text=fallback_text(packet), source="fallback", error=error
        )
