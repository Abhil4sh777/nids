"""Swappable LLM backends behind one interface.

Only this package may import or know about a specific engine (ExecuTorch).  The
pipeline, alert queue, UI, and tests use ``LLMBackend`` and
``ExplanationService`` exclusively.
"""

from explain.llm.base import (
    BackendError,
    BackendStatus,
    Evidence,
    Explanation,
    LLMBackend,
    PromptWindowError,
    StatusProvider,
    as_packet,
)
from explain.llm.factory import build_backend
from explain.llm.grounding import fallback_text, ground_explanation
from explain.llm.service import ExplanationService

__all__ = [
    "BackendError",
    "BackendStatus",
    "Evidence",
    "Explanation",
    "ExplanationService",
    "LLMBackend",
    "PromptWindowError",
    "StatusProvider",
    "as_packet",
    "build_backend",
    "fallback_text",
    "ground_explanation",
]
