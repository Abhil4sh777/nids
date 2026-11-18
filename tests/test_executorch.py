from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from config import Settings
from explain.evidence import EvidencePacket
from explain.llm.chat_format import (
    LLAMA3_STOP_TOKEN_IDS,
    clean_generation,
    llama3_chat_prompt,
)
from explain.llm.executorch_backend import ExecutorchBackend
from explain.llm.base import BackendError, PromptWindowError


def _settings(settings: Settings, tmp_path: Path, **overrides) -> Settings:
    pte = tmp_path / "model.pte"
    tokenizer = tmp_path / "tokenizer.json"
    pte.write_bytes(b"fake-pte")
    tokenizer.write_text("{}", encoding="utf-8")
    base = replace(
        settings,
        llm_backend="executorch",
        executorch_pte_path=pte,
        executorch_tokenizer_path=tokenizer,
        executorch_runner_command=(sys.executable,),
    )
    return replace(base, **overrides) if overrides else base


def _runner_script(tmp_path: Path, output: str) -> Path:
    script = tmp_path / "fake_runner.py"
    script.write_text(
        "import sys\n"
        "prompt = sys.stdin.read()\n"
        f"sys.stdout.write(prompt + {output!r})\n",
        encoding="utf-8",
    )
    return script


def test_chat_prompt_uses_llama3_markers() -> None:
    prompt = llama3_chat_prompt("system text", "user text")
    assert prompt.startswith("<|begin_of_text|><|start_header_id|>system")
    assert "<|start_header_id|>user<|end_header_id|>" in prompt
    assert prompt.endswith("<|start_header_id|>assistant<|end_header_id|>\n\n")
    assert 128009 in LLAMA3_STOP_TOKEN_IDS


def test_backend_exposes_smoke_prompt_and_timeout(
    settings: Settings, tmp_path: Path
) -> None:
    backend = ExecutorchBackend(_settings(settings, tmp_path))
    prompt = backend.raw_chat_prompt("What is the capital of France?")
    assert prompt == llama3_chat_prompt(
        "You are a helpful assistant. Answer in one short sentence.",
        "What is the capital of France?",
    )
    assert backend.timeout_seconds == backend.settings.executorch_timeout_seconds


def test_clean_generation_strips_prompt_and_markers() -> None:
    prompt = "<|begin_of_text|>prompt"
    text = prompt + " Summary: ok\nWhy it was flagged: x\n<|eot_id|>junk"
    assert clean_generation(text, prompt) == "Summary: ok\nWhy it was flagged: x"


def test_status_reports_missing_files(settings: Settings, tmp_path: Path) -> None:
    backend = ExecutorchBackend(
        replace(
            settings,
            llm_backend="executorch",
            executorch_pte_path=tmp_path / "missing.pte",
            executorch_tokenizer_path=tmp_path / "missing.json",
        )
    )
    status = backend.status()
    assert status.ready is False
    assert "EXECUTORCH_PTE_PATH" in status.detail


def test_window_mismatch_is_rejected(settings: Settings, tmp_path: Path) -> None:
    # The file name says 2k but the configured window is 4k.
    pte = tmp_path / "Llama-3.2-1B-Instruct-8da4w-gptq-2k.pte"
    pte.write_bytes(b"fake")
    tokenizer = tmp_path / "tokenizer.json"
    tokenizer.write_text("{}", encoding="utf-8")
    backend = ExecutorchBackend(
        replace(
            settings,
            llm_backend="executorch",
            executorch_pte_path=pte,
            executorch_tokenizer_path=tokenizer,
            executorch_runner_command=(sys.executable,),
        )
    )
    status = backend.status()
    assert status.ready is False
    assert "2048-token window" in status.detail


def test_config_json_metadata_is_preferred_over_file_name(
    settings: Settings, tmp_path: Path
) -> None:
    pte = tmp_path / "custom-name.pte"
    pte.write_bytes(b"fake")
    (tmp_path / "config.json").write_text(
        '{"variants": [{"file": "custom-name.pte", "context": 2048,'
        ' "methods": {"get_bos_id": 128000, "get_eos_ids": [128001, 128008, 128009]}}]}',
        encoding="utf-8",
    )
    tokenizer = tmp_path / "tokenizer.json"
    tokenizer.write_text("{}", encoding="utf-8")
    backend = ExecutorchBackend(
        replace(
            settings,
            llm_backend="executorch",
            executorch_pte_path=pte,
            executorch_tokenizer_path=tokenizer,
            executorch_runner_command=(sys.executable,),
        )
    )
    expected, source = backend._expected_window()
    assert expected == 2048
    assert source == "xnnpack/config.json"
    assert backend.status().ready is False


def test_status_ready_with_files(settings: Settings, tmp_path: Path) -> None:
    backend = ExecutorchBackend(_settings(settings, tmp_path))
    assert backend.status().ready is True


def test_explain_runs_the_runner_and_grounds_output(
    settings: Settings, tmp_path: Path, evidence_packet: EvidencePacket
) -> None:
    script = _runner_script(
        tmp_path,
        "Summary: The flow is SSH-Patator.\n"
        "Why it was flagged: invented.\n"
        "Recommended actions:\n1. invented action\n"
        "<|eot_id|>",
    )
    backend = ExecutorchBackend(
        _settings(settings, tmp_path, executorch_runner_command=(sys.executable, str(script)))
    )
    text = backend.explain(evidence_packet)
    assert text.startswith("Summary: The flow is SSH-Patator.")
    assert "invented action" not in text
    for action in evidence_packet.mitigation:
        assert action in text


def test_explain_refuses_prompts_that_overflow_the_window(
    settings: Settings, tmp_path: Path, evidence_packet: EvidencePacket
) -> None:
    backend = ExecutorchBackend(
        _settings(
            settings,
            tmp_path,
            executorch_window=64,
            executorch_reserved_output_tokens=32,
        )
    )
    with pytest.raises(PromptWindowError, match="only 32 fit"):
        backend.explain(evidence_packet)


def test_runner_failure_is_a_backend_error(
    settings: Settings, tmp_path: Path, evidence_packet: EvidencePacket
) -> None:
    script = tmp_path / "failing_runner.py"
    script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    backend = ExecutorchBackend(
        _settings(settings, tmp_path, executorch_runner_command=(sys.executable, str(script)))
    )
    with pytest.raises(BackendError, match="exit 3"):
        backend.explain(evidence_packet)


def test_generate_text_for_smoke_test(settings: Settings, tmp_path: Path) -> None:
    script = _runner_script(tmp_path, "Paris.<|end_of_text|>")
    backend = ExecutorchBackend(
        _settings(settings, tmp_path, executorch_runner_command=(sys.executable, str(script)))
    )
    assert backend.generate_text("What is the capital of France?") == "Paris."


def test_count_prompt_tokens_uses_estimate_without_tokenizers(
    settings: Settings, tmp_path: Path, evidence_packet: EvidencePacket
) -> None:
    backend = ExecutorchBackend(_settings(settings, tmp_path))
    assert backend.count_prompt_tokens(evidence_packet) > 0
