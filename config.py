"""Runtime configuration for capture, inference, explanations, and the UI.

The model feature contract, labels, and detector threshold intentionally do not
live here; they are fixed constants in :mod:`features.contract`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return default if value is None or value == "" else int(value)


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return default if value is None or value == "" else float(value)


def _split_command(value: str) -> tuple[str, ...]:
    """Split a command template without invoking a shell."""

    return tuple(part for part in value.split() if part)


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

    # Capture
    interface: str | None = None
    capture_filter: str = ""
    dumpcap_path: str | None = None
    pcap_rotation_seconds: int = 60
    pcap_ring_files: int = 10
    pcap_stable_seconds: float = 3.0
    capture_poll_seconds: float = 2.0

    # NTLFlowLyzer
    ntlflowlyzer_command: tuple[str, ...] = ("ntlflowlyzer",)
    ntlflowlyzer_timeout_seconds: float = 300.0
    ntlflowlyzer_threads: int = 4
    ntlflowlyzer_activity_timeout: int = 60
    ntlflowlyzer_max_flow_duration: int = 600

    # XGBoost inference is deliberately CPU-only.
    xgboost_device: str = "cpu"

    # Ollama / local LLM.  GPU offload is requested explicitly; nothing here
    # silently falls back to CPU inference.
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest"
    ollama_timeout_seconds: float = 120.0
    ollama_keep_alive: str = "30m"
    ollama_num_gpu: int = 999
    ollama_num_ctx: int = 2048
    ollama_num_predict: int = 220
    ollama_temperature: float = 0.2

    # UI
    history_limit: int = 500
    ui_refresh_seconds: float = 2.0

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
            interface=interface,
            capture_filter=_env_str("NIDS_CAPTURE_FILTER", ""),
            dumpcap_path=dumpcap,
            pcap_rotation_seconds=_env_int("NIDS_PCAP_ROTATION", 60),
            pcap_ring_files=_env_int("NIDS_PCAP_RING", 10),
            pcap_stable_seconds=_env_float("NIDS_PCAP_STABLE", 3.0),
            capture_poll_seconds=_env_float("NIDS_CAPTURE_POLL", 2.0),
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
            ollama_url=_env_str("NIDS_OLLAMA_URL", "http://localhost:11434").rstrip(
                "/"
            ),
            ollama_model=_env_str(
                "NIDS_OLLAMA_MODEL",
                "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest",
            ),
            ollama_timeout_seconds=_env_float("NIDS_OLLAMA_TIMEOUT", 120.0),
            ollama_keep_alive=_env_str("NIDS_OLLAMA_KEEP_ALIVE", "30m"),
            ollama_num_gpu=_env_int("NIDS_OLLAMA_NUM_GPU", 999),
            ollama_num_ctx=_env_int("NIDS_OLLAMA_NUM_CTX", 2048),
            ollama_num_predict=_env_int("NIDS_OLLAMA_NUM_PREDICT", 220),
            ollama_temperature=_env_float("NIDS_OLLAMA_TEMPERATURE", 0.2),
            history_limit=_env_int("NIDS_HISTORY_LIMIT", 500),
            ui_refresh_seconds=_env_float("NIDS_UI_REFRESH", 2.0),
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
