"""The single LLM interface.  No engine-specific code may live here.

Everything outside :mod:`explain.llm` talks to :class:`LLMBackend` only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from explain.evidence import EvidencePacket

# Backends accept either the dataclass or its plain-dict form.
Evidence = EvidencePacket | Mapping[str, Any]


class BackendError(RuntimeError):
    """Raised when a backend cannot produce an explanation."""


class PromptWindowError(BackendError):
    """Raised when a prompt would not fit inside the model's fixed window."""


@dataclass(frozen=True)
class Explanation:
    """User-facing explanation plus where it came from."""

    text: str
    source: str  # "llm" or "fallback"
    error: str | None = None


@dataclass(frozen=True)
class BackendStatus:
    """Lightweight readiness report for the UI sidebar."""

    backend: str
    ready: bool
    detail: str


def as_packet(evidence: Evidence) -> EvidencePacket:
    """Normalise dict-shaped evidence to the packet dataclass."""

    if isinstance(evidence, EvidencePacket):
        return evidence
    return EvidencePacket.from_dict(evidence)


class LLMBackend(Protocol):
    """Swappable explanation engine.

    ``explain`` returns the generated explanation text and raises on failure or
    timeout.  ``count_prompt_tokens`` reports the real (or best available)
    prompt token count so the pipeline can log and size-check every alert.
    """

    name: str

    def explain(self, evidence: Evidence) -> str: ...

    def count_prompt_tokens(self, evidence: Evidence) -> int: ...


@runtime_checkable
class StatusProvider(Protocol):
    """Optional capability used by the UI; not required of a backend."""

    def status(self) -> BackendStatus: ...
