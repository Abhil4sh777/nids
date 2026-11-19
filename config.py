"""Runtime configuration for capture, inference, explanations, and the UI.

The model feature contract, labels, and detector threshold intentionally do not
live here; they are fixed constants in :mod:`features.contract`.

Environment variables are the supported override mechanism.  The ExecuTorch and
backend names follow the deployment contract in AGENTS.md (``LLM_BACKEND``,
``EXECUTORCH_*``); the ``NIDS_``-prefixed aliases are accepted as well so an
existing shell profile keeps working.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_first(names: tuple[str, ...], default: str) -> str:
    """Return the first non-empty value among ``names``."""

    for name in names:
        value = os.environ.get(name)
        if value is not None and value != "":
            return value
    return default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value is None or value == "" else int(value)


def _env_int_any(names: tuple[str, ...], default: int) -> int:
    return int(_env_first(names, str(default)))


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return default if value is None or value == "" else float(value)


def _env_float_any(names: tuple[str, ...], default: float) -> float:
    return float(_env_first(names, str(default)))


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_command(value: str) -> tuple[str, ...]:
    """Split a command template without invoking a shell."""

    return tuple(part for part in value.split() if part)


def _path_or_none(
    names: tuple[str, ...], default: Path, *, base: Path = PROJECT_ROOT
) -> Path:
    value = _env_first(names, str(default))
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base / path).resolve()


# Bare names from the deployment contract, then the NIDS_-prefixed aliases.
_LLM_BACKEND_ENV = ("LLM_BACKEND", "NIDS_LLM_BACKEND")
_EXECUTORCH_PTE_ENV = ("EXECUTORCH_PTE_PATH", "NIDS_EXECUTORCH_PTE_PATH")
_EXECUTORCH_TOKENIZER_ENV = (
    "EXECUTORCH_TOKENIZER_PATH",
    "NIDS_EXECUTORCH_TOKENIZER_PATH",
)
_EXECUTORCH_RUNNER_ENV = ("EXECUTORCH_RUNNER_PATH", "NIDS_EXECUTORCH_RUNNER_PATH")
_EXECUTORCH_WINDOW_ENV = ("EXECUTORCH_WINDOW", "NIDS_EXECUTORCH_WINDOW")
_EXECUTORCH_TIMEOUT_ENV = ("EXECUTORCH_TIMEOUT_S", "NIDS_EXECUTORCH_TIMEOUT_S")
_EXECUTORCH_OUTPUT_ENV = (
    "EXECUTORCH_RESERVED_OUTPUT_TOKENS",
    "NIDS_EXECUTORCH_RESERVED_OUTPUT_TOKENS",
)
_EXECUTORCH_TEMPERATURE_ENV = (
    "EXECUTORCH_TEMPERATURE",
    "NIDS_EXECUTORCH_TEMPERATURE",
)


@dataclass(frozen=True)
class Settings:
    """All tunable runtime settings.

    Paths in this object are absolute.  ``from_env`` is the only supported
    construction path in application code so environment variables are
    applied consistently.
    """

    project_root: Path = PROJECT_ROOT
    model_dir: Path = PROJECT_ROOT / "models"
    knowledge_dir: Path = PROJECT_ROOT / "explain" / "knowledge"
    capture_dir: Path = PROJECT_ROOT / "capture" / "pcaps"
    output_dir: Path = PROJECT_ROOT / "capture" / "flows"
    models_llm_dir: Path = PROJECT_ROOT / "models_llm"

    # Capture
    interface: str | None = None
    capture_filter: str = ""
    dumpcap_path: str | None = None
    pcap_rotation_seconds: int = 60
    pcap_ring_files: int = 10
    pcap_stable_seconds: float = 3.0
    capture_poll_seconds: float = 2.0
    # What to do with a capture file once its flows were extracted:
    # "delete" (default, SD-card friendly), "archive", or "keep".
    pcap_after_process: str = "delete"
    pcap_archive_dir: Path = PROJECT_ROOT / "capture" / "archive"

    # NTLFlowLyzer
    ntlflowlyzer_command: tuple[str, ...] = ("ntlflowlyzer",)
    ntlflowlyzer_timeout_seconds: float = 300.0
    ntlflowlyzer_threads: int = 4
    ntlflowlyzer_activity_timeout: int = 60
    ntlflowlyzer_max_flow_duration: int = 600

    # XGBoost inference is deliberately CPU-only.
    xgboost_device: str = "cpu"

    # LLM backend selection: "ollama" (dev laptop) or "executorch" (Pi).
    llm_backend: str = "ollama"

    # Ollama backend (CPU only; no GPU offload is requested).
    ollama_url: str = "http://localhost:11434"
    # Must match the tag that was pulled: Ollama treats a missing tag as
    # ``:latest``, and ``hf.co/...:Q4_K_M`` is a different model to Ollama.
    ollama_model: str = (
        "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M"
    )
    ollama_timeout_seconds: float = 120.0
    ollama_keep_alive: str = "30m"
    ollama_num_ctx: int = 4096
    ollama_num_predict: int = 220
    ollama_temperature: float = 0.2

    # ExecuTorch backend (Raspberry Pi).  The window is fixed inside the .pte;
    # 4k is the default because the evidence packet is about 1,000-1,500 tokens.
    executorch_pte_path: Path = (
        PROJECT_ROOT
        / "models_llm"
        / "xnnpack"
        / "Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte"
    )
    executorch_tokenizer_path: Path = PROJECT_ROOT / "models_llm" / "tokenizer.json"
    executorch_runner_command: tuple[str, ...] = ("executorch_llama_runner",)
    executorch_window: int = 4096
    executorch_timeout_seconds: float = 180.0
    executorch_reserved_output_tokens: int = 256
    # Sampler temperature for the runner's own sampling; 0.2 keeps the 1B
    # model close to the evidence instead of improvising.
    executorch_temperature: float = 0.2

    # Alert grouping and throttling (section 9.1).  One LLM call per
    # (predicted_class, src_ip, window).  A full queue falls back to the
    # evidence packet instead of blocking inference.
    alert_group_window_seconds: float = 60.0
    alert_queue_size: int = 64

    # UI
    history_limit: int = 500
    ui_refresh_seconds: float = 2.0
    # Appliance mode (Raspberry Pi): start live capture on load instead of
    # waiting for someone to press Start.  Off by default so the laptop
    # dashboard keeps its explicit start/stop control.
    autostart: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(_env_str("NIDS_ROOT", str(PROJECT_ROOT))).resolve()
        model_dir = Path(_env_str("NIDS_MODEL_DIR", str(root / "models")))
        knowledge_dir = Path(
            _env_str("NIDS_KNOWLEDGE_DIR", str(root / "explain" / "knowledge"))
        )
        capture_dir = Path(
            _env_str("NIDS_CAPTURE_DIR", str(root / "capture" / "pcaps"))
        )
        output_dir = Path(_env_str("NIDS_OUTPUT_DIR", str(root / "capture" / "flows")))
        models_llm_dir = Path(
            _env_str("NIDS_MODELS_LLM_DIR", str(root / "models_llm"))
        )

        interface = os.environ.get("NIDS_INTERFACE") or None
        dumpcap = os.environ.get("NIDS_DUMPCAP") or None
        ntl_command = _split_command(
            _env_str("NIDS_NTLFLOWLYZER", "ntlflowlyzer")
        )

        return cls(
            project_root=root,
            model_dir=model_dir,
            knowledge_dir=knowledge_dir,
            capture_dir=capture_dir,
            output_dir=output_dir,
            models_llm_dir=models_llm_dir,
            interface=interface,
            capture_filter=_env_str("NIDS_CAPTURE_FILTER", ""),
            dumpcap_path=dumpcap,
            pcap_rotation_seconds=_env_int("NIDS_PCAP_ROTATION", 60),
            pcap_ring_files=_env_int("NIDS_PCAP_RING", 10),
            pcap_stable_seconds=_env_float("NIDS_PCAP_STABLE", 3.0),
            capture_poll_seconds=_env_float("NIDS_CAPTURE_POLL", 2.0),
            pcap_after_process=_env_str("NIDS_PCAP_AFTER_PROCESS", "delete"),
            pcap_archive_dir=Path(
                _env_str("NIDS_PCAP_ARCHIVE_DIR", str(root / "capture" / "archive"))
            ),
            ntlflowlyzer_command=ntl_command,
            ntlflowlyzer_timeout_seconds=_env_float(
                "NIDS_NTLFLOWLYZER_TIMEOUT", 300.0
            ),
            ntlflowlyzer_threads=_env_int("NIDS_NTLFLOWLYZER_THREADS", 4),
            ntlflowlyzer_activity_timeout=_env_int(
                "NIDS_NTLFLOWLYZER_ACTIVITY_TIMEOUT", 60
            ),
            ntlflowlyzer_max_flow_duration=_env_int(
                "NIDS_NTLFLOWLYZER_MAX_FLOW_DURATION", 600
            ),
            xgboost_device=_env_str("NIDS_XGB_DEVICE", "cpu"),
            llm_backend=_env_first(_LLM_BACKEND_ENV, "ollama"),
            ollama_url=_env_str("NIDS_OLLAMA_URL", "http://localhost:11434").rstrip(
                "/"
            ),
            ollama_model=_env_str(
                "NIDS_OLLAMA_MODEL",
                "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M",
            ),
            ollama_timeout_seconds=_env_float("NIDS_OLLAMA_TIMEOUT", 120.0),
            ollama_keep_alive=_env_str("NIDS_OLLAMA_KEEP_ALIVE", "30m"),
            ollama_num_ctx=_env_int("NIDS_OLLAMA_NUM_CTX", 4096),
            ollama_num_predict=_env_int("NIDS_OLLAMA_NUM_PREDICT", 220),
            ollama_temperature=_env_float("NIDS_OLLAMA_TEMPERATURE", 0.2),
            executorch_pte_path=_path_or_none(
                _EXECUTORCH_PTE_ENV,
                models_llm_dir
                / "xnnpack"
                / "Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte",
                base=root,
            ),
            executorch_tokenizer_path=_path_or_none(
                _EXECUTORCH_TOKENIZER_ENV,
                models_llm_dir / "tokenizer.json",
                base=root,
            ),
            executorch_runner_command=_split_command(
                _env_first(_EXECUTORCH_RUNNER_ENV, "executorch_llama_runner")
            ),
            executorch_window=_env_int_any(_EXECUTORCH_WINDOW_ENV, 4096),
            executorch_timeout_seconds=_env_float_any(
                _EXECUTORCH_TIMEOUT_ENV, 180.0
            ),
            executorch_reserved_output_tokens=_env_int_any(
                _EXECUTORCH_OUTPUT_ENV, 256
            ),
            executorch_temperature=_env_float_any(
                _EXECUTORCH_TEMPERATURE_ENV, 0.2
            ),
            alert_group_window_seconds=_env_float(
                "NIDS_ALERT_GROUP_WINDOW", 60.0
            ),
            alert_queue_size=_env_int("NIDS_ALERT_QUEUE_SIZE", 64),
            history_limit=_env_int("NIDS_HISTORY_LIMIT", 500),
            ui_refresh_seconds=_env_float("NIDS_UI_REFRESH", 2.0),
            autostart=_env_bool("NIDS_AUTOSTART", False),
        )

    # Convenience paths -------------------------------------------------
    @property
    def detector_path(self) -> Path:
        return self.model_dir / "detector.joblib"

    @property
    def classifier_path(self) -> Path:
        return self.model_dir / "classifier.joblib"

    def ensure_directories(self) -> None:
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings.from_env()
