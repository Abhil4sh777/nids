from __future__ import annotations

from dataclasses import replace

import pytest

from config import Settings
from explain.llm import build_backend
from explain.llm.executorch_backend import ExecutorchBackend
from explain.llm.ollama_backend import OllamaBackend


def test_ollama_is_the_default_backend(settings: Settings) -> None:
    assert isinstance(build_backend(settings), OllamaBackend)


def test_executorch_backend_is_selected_by_config(settings: Settings) -> None:
    backend = build_backend(replace(settings, llm_backend="EXECUTORCH"))
    assert isinstance(backend, ExecutorchBackend)
    assert backend.name == "executorch"


def test_unknown_backend_is_rejected(settings: Settings) -> None:
    with pytest.raises(ValueError, match="expected 'ollama' or 'executorch'"):
        build_backend(replace(settings, llm_backend="gpt4all"))


def test_env_llm_backend_is_read(monkeypatch) -> None:
    monkeypatch.setenv("LLM_BACKEND", "executorch")
    assert Settings.from_env().llm_backend == "executorch"


def test_env_executorch_values_are_read(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("EXECUTORCH_WINDOW", "2048")
    monkeypatch.setenv("EXECUTORCH_TIMEOUT_S", "12.5")
    monkeypatch.setenv("EXECUTORCH_PTE_PATH", str(tmp_path / "model.pte"))
    settings = Settings.from_env()
    assert settings.executorch_window == 2048
    assert settings.executorch_timeout_seconds == 12.5
    assert settings.executorch_pte_path == (tmp_path / "model.pte").resolve()


def test_alert_grouping_defaults_are_configurable(monkeypatch) -> None:
    monkeypatch.setenv("NIDS_ALERT_GROUP_WINDOW", "15")
    monkeypatch.setenv("NIDS_ALERT_QUEUE_SIZE", "3")
    settings = Settings.from_env()
    assert settings.alert_group_window_seconds == 15.0
    assert settings.alert_queue_size == 3
