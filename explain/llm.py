"""Local Ollama client for explanations, with an evidence-based fallback.

The LLM is requested to use GPU offload explicitly (``num_gpu``).  If Ollama
is unavailable, times out, or fails, the caller still gets a deterministic
explanation built directly from the evidence packet.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import requests

from config import Settings
from explain.evidence import EvidencePacket
from explain.prompt import SYSTEM_PROMPT, build_prompt

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Explanation:
    text: str
    source: str  # "llm" or "fallback"
    error: str | None = None


@dataclass(frozen=True)
class LlmStatus:
    reachable: bool
    model_available: bool
    model_loaded: bool
    gpu: bool | None
    vram_bytes: int | None
    detail: str


def _normalise_model(name: str) -> str:
    value = name.strip().lower()
    if ":" not in value.rsplit("/", 1)[-1]:
        value += ":latest"
    return value


def _model_matches(requested: str, candidate: str) -> bool:
    return _normalise_model(requested) == _normalise_model(candidate)


class OllamaClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def model(self) -> str:
        return self.settings.ollama_model

    def _url(self, path: str) -> str:
        return f"{self.settings.ollama_url}{path}"

    def status(self) -> LlmStatus:
        """Report reachability, model presence, and whether it is on the GPU."""

        try:
            response = requests.get(
                self._url("/api/tags"),
                timeout=min(5.0, self.settings.ollama_timeout_seconds),
            )
            response.raise_for_status()
            models = response.json().get("models", [])
        except Exception as exc:
            return LlmStatus(
                reachable=False,
                model_available=False,
                model_loaded=False,
                gpu=None,
                vram_bytes=None,
                detail=f"Ollama unreachable at {self.settings.ollama_url}: {exc}",
            )

        available = any(
            _model_matches(
                self.model, str(item.get("name") or item.get("model") or "")
            )
            for item in models
            if isinstance(item, dict)
        )
        if not available:
            return LlmStatus(
                reachable=True,
                model_available=False,
                model_loaded=False,
                gpu=None,
                vram_bytes=None,
                detail=f"Model {self.model!r} is not installed in Ollama",
            )

        try:
            running_response = requests.get(
                self._url("/api/ps"),
                timeout=min(5.0, self.settings.ollama_timeout_seconds),
            )
            running_response.raise_for_status()
            running = running_response.json().get("models", [])
        except Exception as exc:
            return LlmStatus(
                reachable=True,
                model_available=True,
                model_loaded=False,
                gpu=None,
                vram_bytes=None,
                detail=f"Model installed; could not read /api/ps: {exc}",
            )

        for item in running:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("model") or "")
            if not _model_matches(self.model, name):
                continue
            vram = item.get("size_vram")
            vram_bytes = int(vram) if isinstance(vram, (int, float)) else None
            gpu = None if vram_bytes is None else vram_bytes > 0
            if gpu is True:
                detail = f"Model loaded on GPU ({vram_bytes} bytes in VRAM)"
            elif gpu is False:
                detail = "Model loaded but reports no VRAM; it is running on CPU"
            else:
                detail = "Model loaded; Ollama did not report VRAM usage"
            return LlmStatus(
                reachable=True,
                model_available=True,
                model_loaded=True,
                gpu=gpu,
                vram_bytes=vram_bytes,
                detail=detail,
            )

        return LlmStatus(
            reachable=True,
            model_available=True,
            model_loaded=False,
            gpu=None,
            vram_bytes=None,
            detail="Model installed but not currently loaded",
        )

    def generate(self, packet: EvidencePacket) -> Explanation:
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
                "num_gpu": self.settings.ollama_num_gpu,
            },
        }
        try:
            response = requests.post(
                self._url("/api/generate"),
                json=payload,
                timeout=self.settings.ollama_timeout_seconds,
            )
            response.raise_for_status()
            text = str(response.json().get("response", "")).strip()
            if not text:
                raise ValueError("Ollama returned an empty response")
            text = self._ground_explanation(text, packet)
            # Enforce the GPU-only policy.  If Ollama reports that the model
            # actually ran without VRAM, do not present CPU-generated text as a
            # valid explanation.
            status = self.status()
            if status.model_loaded and status.gpu is False:
                raise RuntimeError(
                    "GPU-only policy: Ollama is running the model on CPU "
                    "(size_vram=0)"
                )
            return Explanation(text=text, source="llm")
        except Exception as exc:
            logger.warning("LLM explanation failed: %s", exc)
            return self.fallback(packet, error=str(exc))

    @staticmethod
    def _ground_explanation(text: str, packet: EvidencePacket) -> str:
        """Use the LLM for a short summary and rebuild all facts from evidence.

        A 1B model can add plausible-sounding mitigations, feature meanings, or
        claim that a defense is already deployed.  The knowledge packet is the
        contract, so the Why and Recommended actions sections are always
        regenerated from grounded evidence.  Only the Summary is taken from the
        LLM, and it is rejected if it leaks mitigation text.
        """

        summary_match = re.search(
            r"(?im)^\s*summary\s*:\s*(.+?)(?=\n\s*(?:why it was flagged|recommended actions)\s*:|$)",
            text,
            flags=re.DOTALL,
        )
        if summary_match is None:
            raise ValueError("LLM response did not include a Summary section")

        candidate = " ".join(summary_match.group(1).split())
        if (
            not candidate
            or len(candidate) > 400
            or "recommended actions" in candidate.lower()
            or any(
                action.lower() in candidate.lower()
                for action in packet.mitigation
            )
            or (
                packet.predicted_class.lower() not in candidate.lower()
                and "attack" not in candidate.lower()
            )
        ):
            candidate = (
                f"The detector flagged this flow as {packet.predicted_class} "
                f"(P(Attack)={packet.attack_probability:.3f})."
            )

        detector = ", ".join(
            f"{item['feature']} (SHAP {item['shap_value']:+.3f})"
            for item in packet.detector_top5[:3]
        )
        classifier = ", ".join(
            f"{item['feature']} (SHAP {item['shap_value']:+.3f})"
            for item in packet.classifier_top5[:3]
        )
        why = (
            f"The detector assigned P(Attack)={packet.attack_probability:.3f}. "
            f"The classifier selected {packet.predicted_class} with probability "
            f"{packet.class_probability:.3f}. "
            f"The largest detector contributions were {detector}. "
            f"The largest classifier contributions were {classifier}. "
            f"{packet.description}"
        )
        actions = "\n".join(
            f"{position}. {action}"
            for position, action in enumerate(packet.mitigation, start=1)
        )
        return (
            f"Summary: {candidate}\n"
            f"Why it was flagged: {why}\n"
            f"Recommended actions:\n{actions}"
        )

    def fallback(self, packet: EvidencePacket, *, error: str | None = None) -> Explanation:
        detector_features = ", ".join(
            item["feature"] for item in packet.detector_top5[:3]
        )
        classifier_features = ", ".join(
            item["feature"] for item in packet.classifier_top5[:3]
        )
        actions = "\n".join(
            f"{position}. {action}"
            for position, action in enumerate(packet.mitigation, start=1)
        )
        text = (
            f"Summary: The detector flagged this flow as {packet.predicted_class} "
            f"with P(Attack)={packet.attack_probability:.3f}.\n"
            "Why it was flagged: "
            f"The classifier selected {packet.predicted_class} with probability "
            f"{packet.class_probability:.3f}. "
            f"The strongest detector contributions were {detector_features}; "
            f"the strongest classifier contributions were {classifier_features}. "
            f"{packet.description}\n"
            f"Recommended actions:\n{actions}"
        )
        return Explanation(text=text, source="fallback", error=error)
