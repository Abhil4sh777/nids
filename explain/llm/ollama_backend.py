"""Ollama backend (development laptop).

CPU only: this project ignores GPUs on every target.  Ollama is reached over
its local HTTP API, non-streaming, with a keep-alive so the 1B model stays warm.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from config import Settings
from explain.evidence import EvidencePacket
from explain.llm.base import (
    BackendError,
    BackendStatus,
    Evidence,
    as_packet,
)
from explain.llm.grounding import ground_explanation
from explain.llm.tokens import count_tokens
from explain.prompt import SYSTEM_PROMPT, build_prompt

logger = logging.getLogger(__name__)


def _normalise_model(name: str) -> str:
    value = name.strip().lower()
    if ":" not in value.rsplit("/", 1)[-1]:
        value += ":latest"
    return value


def _model_matches(requested: str, candidate: str) -> bool:
    return _normalise_model(requested) == _normalise_model(candidate)


def _model_repo(name: str) -> str:
    """Model name without its tag, e.g. ``hf.co/user/repo``."""

    value = name.strip().lower()
    repo, separator, _tag = value.rpartition(":")
    return repo if separator and repo else value


def _is_model_not_found(exc: requests.HTTPError) -> bool:
    """True when Ollama answered 404 with its "model not found" body.

    A 404 from a wrong base URL must not be reported as a missing model.
    """

    response = getattr(exc, "response", None)
    if response is None or response.status_code != 404:
        return False
    try:
        detail = str(response.json().get("error", "")).lower()
    except Exception:
        detail = ""
    return "model" in detail and "not found" in detail


class OllamaBackend:
    """``LLMBackend`` implementation backed by Ollama."""

    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def model(self) -> str:
        return self.settings.ollama_model

    @property
    def timeout_seconds(self) -> float:
        return self.settings.ollama_timeout_seconds

    def _url(self, path: str) -> str:
        return f"{self.settings.ollama_url}{path}"

    def _prompt_text(self, packet: EvidencePacket) -> str:
        # Ollama applies the model's own chat template, so system and prompt are
        # sent separately; the count includes both for window budgeting.
        return f"{SYSTEM_PROMPT}\n\n{build_prompt(packet)}"

    def count_prompt_tokens(self, evidence: Evidence) -> int:
        text = self._prompt_text(as_packet(evidence))
        count, method = count_tokens(text)
        logger.debug("ollama prompt token %s count: %d", method, count)
        return count

    def status(self) -> BackendStatus:
        """Report reachability and whether the configured model is installed."""

        try:
            models = self._fetch_installed_models()
        except Exception as exc:
            return BackendStatus(
                backend=self.name,
                ready=False,
                detail=(
                    f"Ollama unreachable at {self.settings.ollama_url}: {exc}"
                ),
            )

        if any(_model_matches(self.model, name) for name in models):
            return BackendStatus(
                backend=self.name,
                ready=True,
                detail=f"Ollama ready with model {self.model}",
            )

        variant = self._installed_variant(models)
        if variant is None:
            return BackendStatus(
                backend=self.name,
                ready=False,
                detail=(
                    f"Model {self.model!r} is not installed in Ollama "
                    f"(try: ollama pull {self.model})"
                ),
            )
        return BackendStatus(
            backend=self.name,
            ready=True,
            detail=(
                f"Ollama ready with model {variant} "
                f"(configured {self.model} is not installed)"
            ),
        )

    def _fetch_installed_models(self) -> list[str]:
        """Model tags installed in Ollama.  Raises if Ollama is unreachable."""

        response = requests.get(
            self._url("/api/tags"),
            timeout=min(5.0, self.settings.ollama_timeout_seconds),
        )
        response.raise_for_status()
        names: list[str] = []
        for item in response.json().get("models", []):
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("model") or "")
                if name:
                    names.append(name)
        return names

    def _installed_variant(self, models: list[str] | None = None) -> str | None:
        """A different tag of the same model repo, if one is installed.

        Pulling ``repo:Q4_K_M`` does not create ``repo:latest``, so a tag
        mismatch otherwise fails every alert with an opaque 404.
        """

        wanted = _model_repo(self.model)
        names = models
        if names is None:
            try:
                names = self._fetch_installed_models()
            except Exception as exc:
                logger.debug("could not list Ollama models: %s", exc)
                return None
        candidates = sorted(
            {
                name
                for name in names
                if _model_repo(name) == wanted
                and not _model_matches(self.model, name)
            }
        )
        return candidates[0] if candidates else None

    def _generate(self, model: str, payload: dict[str, Any]) -> str:
        response = requests.post(
            self._url("/api/generate"),
            json={**payload, "model": model},
            timeout=self.settings.ollama_timeout_seconds,
        )
        response.raise_for_status()
        return str(response.json().get("response", "")).strip()

    def explain(self, evidence: Evidence) -> str:
        """Generate and ground one explanation.  Raises on failure/timeout."""

        packet = as_packet(evidence)
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": build_prompt(packet),
            "system": SYSTEM_PROMPT,
            "stream": False,
            "keep_alive": self.settings.ollama_keep_alive,
            "options": {
                "temperature": self.settings.ollama_temperature,
                "num_ctx": self.settings.ollama_num_ctx,
                "num_predict": self.settings.ollama_num_predict,
            },
        }
        try:
            text = self._generate(self.model, payload)
        except requests.HTTPError as exc:
            if not _is_model_not_found(exc):
                raise BackendError(f"Ollama request failed: {exc}") from exc
            variant = self._installed_variant()
            if variant is None:
                raise BackendError(
                    f"Ollama has no model {self.model!r} (HTTP 404). "
                    f"Install it with: ollama pull {self.model}"
                ) from exc
            logger.warning(
                "Ollama model %s is not installed; using installed tag %s",
                self.model,
                variant,
            )
            try:
                text = self._generate(variant, payload)
            except requests.HTTPError as retry_exc:
                raise BackendError(
                    f"Ollama request with installed tag {variant!r} failed: "
                    f"{retry_exc}"
                ) from retry_exc
        if not text:
            raise BackendError("Ollama returned an empty response")
        return ground_explanation(text, packet)
