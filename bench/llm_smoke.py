"""Standalone ExecuTorch smoke test for the Pi.

Must generate one correct sentence on the Pi before the backend is wired into
the live pipeline.  Uses the model card's own question.

Usage::

    EXECUTORCH_PTE_PATH=/data/models_llm/xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte \
    EXECUTORCH_TOKENIZER_PATH=/data/models_llm/tokenizer.json \
    EXECUTORCH_RUNNER_PATH=/opt/executorch/build/executorch_llama_runner \
    python -m bench.llm_smoke
"""

from __future__ import annotations

import sys

from config import get_settings
from explain.llm import build_backend

QUESTION = "What is the capital of France?"


def main() -> int:
    backend = build_backend(get_settings())
    if backend.name != "executorch":
        print(
            "Set LLM_BACKEND=executorch to smoke-test the .pte on the Pi.",
            file=sys.stderr,
        )
        return 2
    status_method = getattr(backend, "status", None)
    if status_method is not None:
        status = status_method()
        if not status.ready:
            print(f"{backend.name} not ready: {status.detail}", file=sys.stderr)
            return 2

    generate = getattr(backend, "generate_text", None)
    build_prompt = getattr(backend, "raw_chat_prompt", None)
    if generate is None or build_prompt is None:
        print(
            "This backend does not expose raw generation; use the ExecuTorch "
            "backend for the smoke test.",
            file=sys.stderr,
        )
        return 2

    prompt = build_prompt(QUESTION)
    print(f"Question: {QUESTION}")
    answer = generate(prompt)
    print(f"Answer: {answer}")

    if "paris" not in answer.lower():
        print(
            "Smoke test failed: the expected answer mentions Paris.",
            file=sys.stderr,
        )
        return 1
    print("Smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
