from __future__ import annotations

import requests

from config import Settings
from explain.evidence import EvidencePacket
from explain.llm import LlmStatus, OllamaClient, _model_matches


class FakeResponse:
    def __init__(self, data: dict, status_code: int = 200) -> None:
        self._data = data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self) -> dict:
        return self._data


def test_generate_requests_gpu_and_replaces_invented_actions(
    settings: Settings,
    evidence_packet: EvidencePacket,
    monkeypatch,
) -> None:
    captured: dict = {}

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        captured["url"] = url
        captured["payload"] = json
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "response": (
                    "Summary: SSH-Patator was detected.\n"
                    "Why it was flagged: the flow shows high packet rates.\n"
                    "Recommended actions:\n"
                    "1. Invented action that is not in the packet."
                )
            }
        )

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(
        OllamaClient,
        "status",
        lambda self: LlmStatus(
            reachable=True,
            model_available=True,
            model_loaded=True,
            gpu=True,
            vram_bytes=1,
            detail="GPU",
        ),
    )
    client = OllamaClient(settings)
    explanation = client.generate(evidence_packet)

    assert explanation.source == "llm"
    assert explanation.error is None
    assert "Invented action" not in explanation.text
    for action in evidence_packet.mitigation:
        assert action in explanation.text

    assert captured["url"].endswith("/api/generate")
    payload = captured["payload"]
    assert payload["model"] == settings.ollama_model
    assert payload["stream"] is False
    assert payload["keep_alive"] == settings.ollama_keep_alive
    assert payload["options"]["num_gpu"] == settings.ollama_num_gpu
    assert payload["options"]["num_gpu"] > 0
    assert payload["options"]["temperature"] == settings.ollama_temperature
    assert payload["options"]["num_predict"] == settings.ollama_num_predict
    assert "EVIDENCE" in payload["prompt"]
    assert "ONLY the evidence" in payload["system"]


def test_mitigation_summary_is_rejected_and_why_is_grounded(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "response": (
                    f"Summary: {evidence_packet.mitigation[0]}\n"
                    "Why it was flagged: invented reason.\n"
                    "Recommended actions:\n"
                    "1. invented action"
                )
            }
        ),
    )
    monkeypatch.setattr(
        OllamaClient,
        "status",
        lambda self: LlmStatus(
            reachable=True,
            model_available=True,
            model_loaded=True,
            gpu=True,
            vram_bytes=1,
            detail="GPU",
        ),
    )
    explanation = OllamaClient(settings).generate(evidence_packet)
    assert explanation.source == "llm"
    assert explanation.text.startswith(
        "Summary: The detector flagged this flow as SSH-Patator"
    )
    assert "Why it was flagged: The detector assigned P(Attack)=" in explanation.text
    assert evidence_packet.description in explanation.text
    assert explanation.text.count(evidence_packet.mitigation[0]) == 1
    assert "invented" not in explanation.text.lower()


def test_cpu_loaded_llm_is_rejected_in_favour_of_fallback(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "response": (
                    "Summary: SSH-Patator attack.\\n"
                    "Why it was flagged: grounded?\\n"
                    "Recommended actions:\\n1. x"
                )
            }
        ),
    )
    monkeypatch.setattr(
        OllamaClient,
        "status",
        lambda self: LlmStatus(
            reachable=True,
            model_available=True,
            model_loaded=True,
            gpu=False,
            vram_bytes=0,
            detail="CPU",
        ),
    )
    explanation = OllamaClient(settings).generate(evidence_packet)
    assert explanation.source == "fallback"
    assert "GPU-only" in (explanation.error or "")


def test_malformed_llm_sections_use_fallback(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: FakeResponse({"response": "It is probably bad."}),
    )
    explanation = OllamaClient(settings).generate(evidence_packet)
    assert explanation.source == "fallback"
    assert explanation.error is not None
    assert "Summary:" in explanation.text
    assert "Recommended actions:" in explanation.text


def test_llm_timeout_uses_fallback(
    settings: Settings, evidence_packet: EvidencePacket, monkeypatch
) -> None:
    def fake_post(*args, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "post", fake_post)
    explanation = OllamaClient(settings).generate(evidence_packet)
    assert explanation.source == "fallback"
    assert "timed out" in (explanation.error or "")


def test_fallback_uses_only_evidence(
    settings: Settings, evidence_packet: EvidencePacket
) -> None:
    explanation = OllamaClient(settings).fallback(evidence_packet, error="test")
    assert explanation.source == "fallback"
    assert evidence_packet.predicted_class in explanation.text
    assert evidence_packet.description in explanation.text
    for action in evidence_packet.mitigation:
        assert action in explanation.text
    assert "test" == explanation.error


def test_status_reports_gpu_from_size_vram(
    settings: Settings, monkeypatch
) -> None:
    def fake_get(url: str, timeout: float) -> FakeResponse:
        if url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": settings.ollama_model}]})
        if url.endswith("/api/ps"):
            return FakeResponse(
                {
                    "models": [
                        {
                            "name": settings.ollama_model,
                            "size": 1000,
                            "size_vram": 800,
                        }
                    ]
                }
            )
        raise AssertionError(url)

    monkeypatch.setattr(requests, "get", fake_get)
    status = OllamaClient(settings).status()
    assert status.reachable is True
    assert status.model_available is True
    assert status.model_loaded is True
    assert status.gpu is True
    assert status.vram_bytes == 800


def test_status_reports_cpu_when_no_vram(
    settings: Settings, monkeypatch
) -> None:
    def fake_get(url: str, timeout: float) -> FakeResponse:
        if url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": settings.ollama_model}]})
        return FakeResponse(
            {
                "models": [
                    {"name": settings.ollama_model, "size": 1000, "size_vram": 0}
                ]
            }
        )

    monkeypatch.setattr(requests, "get", fake_get)
    status = OllamaClient(settings).status()
    assert status.model_loaded is True
    assert status.gpu is False


def test_status_unreachable(
    settings: Settings, monkeypatch
) -> None:
    def fake_get(*args, **kwargs):
        raise requests.ConnectionError("no Ollama")

    monkeypatch.setattr(requests, "get", fake_get)
    status = OllamaClient(settings).status()
    assert status.reachable is False
    assert status.model_available is False
    assert "unreachable" in status.detail.lower()


def test_status_missing_model(settings: Settings, monkeypatch) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse({"models": [{"name": "other:latest"}]}),
    )
    status = OllamaClient(settings).status()
    assert status.reachable is True
    assert status.model_available is False


def test_status_installed_but_not_loaded(
    settings: Settings, monkeypatch
) -> None:
    def fake_get(url: str, timeout: float) -> FakeResponse:
        if url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": settings.ollama_model}]})
        return FakeResponse({"models": []})

    monkeypatch.setattr(requests, "get", fake_get)
    status = OllamaClient(settings).status()
    assert status.model_available is True
    assert status.model_loaded is False


def test_model_name_matching_handles_latest_tag() -> None:
    assert _model_matches("hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF", "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest")
    assert not _model_matches("foo:1", "foo:2")
