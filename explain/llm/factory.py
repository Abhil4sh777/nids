"""Backend selection from config."""

from __future__ import annotations

from config import Settings
from explain.llm.base import LLMBackend


def build_backend(settings: Settings) -> LLMBackend:
    """Return the configured backend.

    ``LLM_BACKEND=ollama`` (default, dev laptop) or ``executorch`` (Pi).  The
    rest of the pipeline never learns which engine was chosen.
    """

    key = settings.llm_backend.strip().lower()
    if key == "ollama":
        from explain.llm.ollama_backend import OllamaBackend

        return OllamaBackend(settings)
    if key == "executorch":
        from explain.llm.executorch_backend import ExecutorchBackend

        return ExecutorchBackend(settings)
    raise ValueError(
        f"Unknown LLM backend {settings.llm_backend!r}; expected 'ollama' or "
        "'executorch' (set LLM_BACKEND)"
    )
