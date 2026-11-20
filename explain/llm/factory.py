"""Backend selection from config.

ExecuTorch is the only backend shipped with the Raspberry Pi appliance.  The
factory stays so that ``LLM_BACKEND`` remains checked in one place and a
misconfiguration fails at startup instead of producing silent fallback text.
"""

from __future__ import annotations

from config import Settings
from explain.llm.base import LLMBackend


def build_backend(settings: Settings) -> LLMBackend:
    """Return the configured backend.

    The rest of the pipeline never learns which engine was chosen.
    """

    key = settings.llm_backend.strip().lower()
    if key == "executorch":
        from explain.llm.executorch_backend import ExecutorchBackend

        return ExecutorchBackend(settings)
    raise ValueError(
        f"Unknown LLM backend {settings.llm_backend!r}; expected 'executorch' "
        "(set LLM_BACKEND in /etc/nids/nids.env)"
    )
