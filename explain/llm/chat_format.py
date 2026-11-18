"""Llama 3 chat formatting for the ExecuTorch runner.

The ExecuTorch ``.pte`` is a raw causal language model: it needs the Llama 3
chat markers applied by the caller and generation must stop on the end-of-turn
tokens.

Token IDs below come from the model repo's ``xnnpack/config.json``
(``methods.get_bos_id`` / ``methods.get_eos_ids``).  Arm's published list also
names 128006 and 128007 (header markers), which this export does not report.
TODO(open-question): confirm on the Pi which IDs the runner actually stops on;
the repo's config.json values win until then.
"""

from __future__ import annotations

LLAMA3_STOP_TOKEN_IDS: tuple[int, ...] = (128009, 128001, 128008)
LLAMA3_BOS_TOKEN_ID: int = 128000

_EOT = "<|eot_id|>"
_STOP_MARKERS: tuple[str, ...] = (
    "<|eot_id|>",
    "<|end_of_text|>",
    "<|start_header_id|>",
    "<|end_header_id|>",
    "<|begin_of_text|>",
)


def llama3_chat_prompt(system: str, user: str) -> str:
    """Render the Llama 3 instruct chat template."""

    return (
        "<|begin_of_text|>"
        "<|start_header_id|>system<|end_header_id|>\n\n"
        f"{system.strip()}{_EOT}"
        "<|start_header_id|>user<|end_header_id|>\n\n"
        f"{user.strip()}{_EOT}"
        "<|start_header_id|>assistant<|end_header_id|>\n\n"
    )


def clean_generation(text: str, prompt: str = "") -> str:
    """Strip an echoed prompt and every special/end-of-turn marker."""

    output = text.strip()
    if prompt:
        stripped_prompt = prompt.strip()
        if output.startswith(stripped_prompt):
            output = output[len(stripped_prompt) :]
    for marker in _STOP_MARKERS:
        index = output.find(marker)
        if index != -1:
            output = output[:index]
    return output.strip()
