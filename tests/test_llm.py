from __future__ import annotations

from dataclasses import replace

import requests

from config import Settings
from explain.evidence import EvidencePacket
from explain.llm import ExplanationService
from explain.llm.base import BackendError
from explain.llm.ollama_backend import OllamaBackend, _model_matches
from explain.llm.service import DEFAULT_TIMEOUT_SECONDS


class FakeResponse:
    def __init__(self, data: dict, status_code: int = 200) -> None:
        self._data = data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error = requests.HTTPError(f"status {self.status_code}")
            error.response = self
            raise error

    def json(self) -> dict:
        return self._data


def _valid_answer(*, summary: str = "SSH-Patator was detected.") -> dict:
    return {
        "response": (
            f"Summary: {summary}\n"
            "Why it was flagged: invented reason.\n"
            "Recommended actions:\n"
            "1. Invented action that is not in the packet."
        )
    }


def test_explain_is_cpu_only_and_grounds_invented_actions(
    settings: Settings,
    evidence_packet: EvidencePacket,
    monkeypatch,
) -> None:
    captured: dict = {}

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        captured["url"] = url
        captured["payload"] = json
        captured["timeout"] = timeout
        return FakeResponse(_valid_answer())

    monkeypatch.setattr(requests, "post", fake_post)
    backend = OllamaBackend(settings)
    text = backend.explain(evidence_packet)

    # The model's invented action is replaced by the knowledge packet's one.
    assert "Invented action" not in text
    for action in evidence_packet.mitigation:
        assert action in text

    assert captured["url"].endswith("/api/generate")
    payload = captured["payload"]
    assert payload["model"] == settings.ollama_model
    assert payload["stream"] is False
    assert payload["keep_alive"] == settings.ollama_keep_alive
    assert payload["options"]["temperature"] == settings.ollama_temperature
    assert payload["options"]["num_ctx"] == settings.ollama_num_ctx
    assert payload["options"]["num_predict"] == settings.ollama_num_predict
    # CPU-only deployment: never request GPU offload.
    assert "num_gpu" not in payload["options"]
    assert "EVIDENCE" in payload["prompt"]
    assert "ONLY the evidence" in payload["system"]
    assert captured["timeout"] == settings.ollama_timeout_seconds


def test_mitigation_summary_is_rejected_and_why_is_grounded(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            _valid_answer(summary=evidence_packet.mitigation[0])
        ),
    )
    text = OllamaBackend(settings).explain(evidence_packet)
    assert text.startswith(
        "Summary: The detector flagged this flow as SSH-Patator"
    )
    assert "Why it was flagged: The detector assigned P(Attack)=" in text
    assert evidence_packet.description in text
    assert text.count(evidence_packet.mitigation[0]) == 1
    assert "invented" not in text.lower()


def test_malformed_llm_sections_raise_for_the_service(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse({"response": "It is probably bad."}),
    )
    backend = OllamaBackend(settings)
    try:
        backend.explain(evidence_packet)
    except ValueError as exc:
        assert "Summary" in str(exc)
    else:  # pragma: no cover - the backend must raise here
        raise AssertionError("expected a ValueError")


def test_empty_response_raises(settings: Settings, evidence_packet, monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *args, **kwargs: FakeResponse({"response": ""})
    )
    backend = OllamaBackend(settings)
    try:
        backend.explain(evidence_packet)
    except BackendError as exc:
        assert "empty" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected BackendError")


def test_service_falls_back_on_timeout(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    def fake_post(*args, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "post", fake_post)
    explanation = ExplanationService(OllamaBackend(settings)).explain(
        evidence_packet
    )
    assert explanation.source == "fallback"
    assert "timed out" in (explanation.error or "")
    assert "Summary:" in explanation.text
    assert "Recommended actions:" in explanation.text


def test_service_falls_back_when_backend_returns_nothing(
    evidence_packet: EvidencePacket,
) -> None:
    class EmptyBackend:
        name = "empty"

        def explain(self, evidence):
            return "   "

        def count_prompt_tokens(self, evidence):
            return 1

    explanation = ExplanationService(EmptyBackend()).explain(evidence_packet)
    assert explanation.source == "fallback"
    assert "empty" in (explanation.error or "").lower()


def test_service_returns_llm_text(
    evidence_packet: EvidencePacket,
) -> None:
    class GoodBackend:
        name = "good"

        def explain(self, evidence):
            return "Summary: grounded text"

        def count_prompt_tokens(self, evidence):
            return 42

    explanation = ExplanationService(GoodBackend()).explain(evidence_packet)
    assert explanation.source == "llm"
    assert explanation.text == "Summary: grounded text"


def test_fallback_uses_only_evidence(evidence_packet: EvidencePacket) -> None:
    explanation = ExplanationService.fallback(evidence_packet, error="test")
    assert explanation.source == "fallback"
    assert evidence_packet.predicted_class in explanation.text
    assert evidence_packet.description in explanation.text
    for action in evidence_packet.mitigation:
        assert action in explanation.text
    assert explanation.error == "test"


def test_count_prompt_tokens_is_positive(
    settings: Settings, evidence_packet: EvidencePacket
) -> None:
    assert OllamaBackend(settings).count_prompt_tokens(evidence_packet) > 0


def test_service_reports_the_backend_timeout(settings: Settings) -> None:
    """The UI must ask the backend for its timeout, never read engine settings."""

    service = ExplanationService(OllamaBackend(settings))
    assert service.timeout_seconds == settings.ollama_timeout_seconds


def test_service_has_a_default_timeout(evidence_packet: EvidencePacket) -> None:
    class BareBackend:
        name = "bare"

        def explain(self, evidence):
            return "Summary: text"

        def count_prompt_tokens(self, evidence):
            return 1

    assert (
        ExplanationService(BareBackend()).timeout_seconds
        == DEFAULT_TIMEOUT_SECONDS
    )


def test_status_ready_when_model_is_installed(
    settings: Settings, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {"models": [{"name": settings.ollama_model}]}
        ),
    )
    status = OllamaBackend(settings).status()
    assert status.backend == "ollama"
    assert status.ready is True


def test_status_unreachable(settings: Settings, monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        raise requests.ConnectionError("no Ollama")

    monkeypatch.setattr(requests, "get", fake_get)
    status = OllamaBackend(settings).status()
    assert status.ready is False
    assert "unreachable" in status.detail.lower()


def test_status_missing_model(settings: Settings, monkeypatch) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse({"models": [{"name": "other:latest"}]}),
    )
    status = OllamaBackend(settings).status()
    assert status.ready is False
    assert "not installed" in status.detail


def test_model_name_matching_handles_latest_tag() -> None:
    assert _model_matches(
        "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF",
        "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest",
    )
    assert not _model_matches("foo:1", "foo:2")


def test_explain_uses_installed_tag_of_the_same_repo(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    """A missing configured tag must not turn every alert into a 404.

    ``ollama pull repo:Q4_K_M`` does not create ``repo:latest``; the backend
    should fall back to the tag that is actually installed.
    """

    configured = replace(
        settings, ollama_model="hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest"
    )
    installed = [
        {
            "name": "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M",
            "model": "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M",
        }
    ]
    posted: list[str] = []

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        posted.append(json["model"])
        if len(posted) == 1:
            return FakeResponse(
                {"error": f"model '{json['model']}' not found"}, status_code=404
            )
        return FakeResponse(_valid_answer())

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(
        requests, "get", lambda *args, **kwargs: FakeResponse({"models": installed})
    )

    text = OllamaBackend(configured).explain(evidence_packet)
    assert "Summary:" in text
    assert posted[0] == configured.ollama_model
    assert posted[1] == installed[0]["name"]


def test_explain_missing_model_raises_a_pull_hint(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"error": "model 'x' not found"}, status_code=404
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {"models": [{"name": "some-other-model:latest"}]}
        ),
    )
    backend = OllamaBackend(settings)
    try:
        backend.explain(evidence_packet)
    except BackendError as exc:
        assert "ollama pull" in str(exc)
    else:  # pragma: no cover - the backend must raise here
        raise AssertionError("expected BackendError")


def test_status_ready_with_installed_variant_of_the_repo(
    settings: Settings, monkeypatch
) -> None:
    configured = replace(
        settings, ollama_model="hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest"
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "models": [
                    {
                        "name": (
                            "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M"
                        )
                    }
                ]
            }
        ),
    )
    status = OllamaBackend(configured).status()
    assert status.ready is True
    assert "Q4_K_M" in status.detail


