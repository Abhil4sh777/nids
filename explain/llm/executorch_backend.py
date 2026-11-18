"""ExecuTorch backend (Raspberry Pi 5).

Runs the ExecuTorch Llama 3.2 1B runner as a separate process.  This first
version performs one-shot runs, so the runner reloads the model for every alert;
keeping the runner warm over stdin is the follow-up once its CLI is confirmed on
the Pi (TODO(open-question)).  ``bench/bench_llm.py`` reports the first call
separately because it includes the model load.

The window and token IDs are read from ``xnnpack/config.json`` next to the
``.pte`` and cross-checked against ``EXECUTORCH_WINDOW``.  A mismatch is a hard
error: the KV cache is allocated from the window baked into the ``.pte``.

Memory: the 4k ``.pte`` allocates a 256 MiB KV cache on top of about 0.96 GB of
weights (65,536 bytes/token).  4k is the default window; do not grow it without
a measurement.

TODO(open-question): confirm the runner's command line.  By default the
configured command gets ``--model <pte> --tokenizer <tokenizer> --seq_len
<window>`` appended and receives the prompt on stdin; override
``EXECUTORCH_RUNNER_PATH`` with a ``{pte}``/``{tokenizer}``/``{window}`` template
if the real runner differs.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from config import Settings
from explain.evidence import EvidencePacket
from explain.llm.base import (
    BackendError,
    BackendStatus,
    Evidence,
    PromptWindowError,
    as_packet,
)
from explain.llm.chat_format import clean_generation, llama3_chat_prompt
from explain.llm.grounding import ground_explanation
from explain.llm.tokens import count_tokens
from explain.prompt import SYSTEM_PROMPT, build_prompt

logger = logging.getLogger(__name__)

_DEFAULT_FLAGS: tuple[str, ...] = (
    "--model",
    "{pte}",
    "--tokenizer",
    "{tokenizer}",
    "--seq_len",
    "{window}",
)

# Fallback when xnnpack/config.json is not downloaded next to the .pte.
_WINDOW_BY_FILENAME: dict[str, int] = {
    "-2k.pte": 2048,
    "-4k.pte": 4096,
    "-8k.pte": 8192,
    "-16k.pte": 16384,
    "-32k.pte": 32768,
}


class ExecutorchBackend:
    """``LLMBackend`` implementation backed by a subprocess runner."""

    name = "executorch"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- readiness ------------------------------------------------------
    @property
    def pte_path(self) -> Path:
        return self.settings.executorch_pte_path

    @property
    def tokenizer_path(self) -> Path:
        return self.settings.executorch_tokenizer_path

    @property
    def timeout_seconds(self) -> float:
        return self.settings.executorch_timeout_seconds

    def _resolve_runner(self) -> Path | None:
        command = self.settings.executorch_runner_command
        if not command:
            return None
        executable = Path(command[0]).expanduser()
        if executable.exists():
            return executable
        found = shutil.which(command[0])
        return Path(found) if found else None

    def _model_config(self) -> dict[str, Any] | None:
        """Return the matching variant from ``xnnpack/config.json``, if present."""

        path = self.pte_path.parent / "config.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read ExecuTorch config %s: %s", path, exc)
            return None
        for variant in data.get("variants", []):
            if isinstance(variant, dict) and variant.get("file") == self.pte_path.name:
                return variant
        logger.warning(
            "No variant for %s in %s; falling back to the file name",
            self.pte_path.name,
            path,
        )
        return None

    def _expected_window(self) -> tuple[int | None, str]:
        """Window baked into the .pte, from config.json or the file name."""

        variant = self._model_config()
        if variant is not None:
            context = variant.get("context")
            methods = variant.get("methods") or {}
            logger.debug(
                "ExecuTorch metadata: context=%s max_seq_len=%s bos=%s eos=%s",
                context,
                methods.get("get_max_seq_len"),
                methods.get("get_bos_id"),
                methods.get("get_eos_ids"),
            )
            if isinstance(context, int):
                return context, "xnnpack/config.json"
            max_context = methods.get("get_max_context_len")
            if isinstance(max_context, int):
                return max_context, "xnnpack/config.json methods"
        for suffix, size in _WINDOW_BY_FILENAME.items():
            if self.pte_path.name.endswith(suffix):
                return size, "the .pte file name"
        return None, "unknown"

    def _problems(self) -> list[str]:
        problems: list[str] = []
        if not self.pte_path.exists():
            problems.append(f"EXECUTORCH_PTE_PATH missing ({self.pte_path})")
        if not self.tokenizer_path.exists():
            problems.append(
                f"EXECUTORCH_TOKENIZER_PATH missing ({self.tokenizer_path})"
            )
        if self._resolve_runner() is None:
            problems.append(
                "EXECUTORCH_RUNNER_PATH not found "
                f"({self.settings.executorch_runner_command[0] if self.settings.executorch_runner_command else 'empty'})"
            )
        expected, source = self._expected_window()
        if expected is not None and expected != self.settings.executorch_window:
            problems.append(
                f"{self.pte_path.name} has a {expected}-token window (from "
                f"{source}) but EXECUTORCH_WINDOW={self.settings.executorch_window}"
            )
        return problems

    def _ensure_ready(self) -> Path:
        problems = self._problems()
        if problems:
            raise BackendError(
                "ExecuTorch backend is not ready: " + "; ".join(problems)
            )
        runner = self._resolve_runner()
        assert runner is not None
        return runner

    def status(self) -> BackendStatus:
        problems = self._problems()
        if problems:
            return BackendStatus(
                backend=self.name, ready=False, detail="; ".join(problems)
            )
        return BackendStatus(
            backend=self.name,
            ready=True,
            detail=(
                f"ExecuTorch ready: {self.pte_path.name} "
                f"({self.settings.executorch_window} token window)"
            ),
        )

    # -- prompt helpers -------------------------------------------------
    def _prompt_text(self, packet: EvidencePacket) -> str:
        return llama3_chat_prompt(SYSTEM_PROMPT, build_prompt(packet))

    def count_prompt_tokens(self, evidence: Evidence) -> int:
        packet = as_packet(evidence)
        count, method = count_tokens(
            self._prompt_text(packet), self.tokenizer_path
        )
        logger.debug("executorch prompt token %s count: %d", method, count)
        return count

    def _build_command(self, runner: Path) -> list[str]:
        template = list(self.settings.executorch_runner_command)
        template[0] = str(runner)
        if not any("{" in part for part in template):
            template.extend(_DEFAULT_FLAGS)
        values = {
            "pte": str(self.pte_path),
            "tokenizer": str(self.tokenizer_path),
            "window": str(self.settings.executorch_window),
        }
        try:
            return [part.format(**values) for part in template]
        except KeyError as exc:
            raise BackendError(
                f"Unknown placeholder {exc} in EXECUTORCH_RUNNER_PATH template"
            ) from exc

    # -- generation -----------------------------------------------------
    def raw_chat_prompt(self, question: str) -> str:
        """One-turn chat prompt for the model-card smoke test.

        Kept here (rather than in ``bench/``) so the Llama 3 chat format stays
        entirely inside ``explain/llm``.
        """

        return llama3_chat_prompt(
            "You are a helpful assistant. Answer in one short sentence.",
            question,
        )

    def generate_text(self, prompt: str) -> str:
        """Run one raw prompt through the runner (used by bench/llm_smoke.py)."""

        runner = self._ensure_ready()
        command = self._build_command(runner)
        logger.info("Running ExecuTorch runner: %s", " ".join(command))
        try:
            result = subprocess.run(
                command,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.settings.executorch_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BackendError(
                "ExecuTorch runner timed out after "
                f"{self.settings.executorch_timeout_seconds}s"
            ) from exc
        if result.returncode != 0:
            raise BackendError(
                f"ExecuTorch runner failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        text = clean_generation(result.stdout, prompt)
        if not text:
            raise BackendError("ExecuTorch runner returned an empty response")
        return text

    def explain(self, evidence: Evidence) -> str:
        packet = as_packet(evidence)
        prompt = self._prompt_text(packet)
        tokens, method = count_tokens(prompt, self.tokenizer_path)
        window = self.settings.executorch_window
        budget = window - self.settings.executorch_reserved_output_tokens
        logger.info(
            "ExecuTorch prompt: %d tokens (%s), window %d, %d reserved for output",
            tokens,
            method,
            window,
            self.settings.executorch_reserved_output_tokens,
        )
        if tokens > budget:
            raise PromptWindowError(
                f"Prompt needs {tokens} tokens but only {budget} fit in the "
                f"{window}-token window after reserving "
                f"{self.settings.executorch_reserved_output_tokens} for output"
            )
        text = self.generate_text(prompt)
        return ground_explanation(text, packet)
