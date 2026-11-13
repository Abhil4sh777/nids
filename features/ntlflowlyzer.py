"""Run NTLFlowLyzer on completed pcap files and read its CSV output."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from config import Settings
from features.validation import FeatureContractError, prepare_flow_frame

logger = logging.getLogger(__name__)


class NTLFlowLyzerError(RuntimeError):
    """Raised when the flow extractor is missing or fails."""


def _resolve_command(command: tuple[str, ...]) -> list[str]:
    if not command:
        raise NTLFlowLyzerError("NTLFlowLyzer command is empty")
    executable = command[0]
    if Path(executable).exists():
        return list(command)
    found = shutil.which(executable)
    if found is None:
        raise NTLFlowLyzerError(
            f"NTLFlowLyzer executable {executable!r} was not found. Install it "
            "(pip install . in the NTLFlowLyzer repository) and add it to PATH, "
            "or set NIDS_NTLFLOWLYZER."
        )
    return [found, *command[1:]]


_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_COMMON_WIRESHARK_DIRS = (
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
)


class CaptureFormatError(NTLFlowLyzerError):
    """Raised when a capture file is not one of the formats we understand."""


def detect_capture_format(path: Path) -> str:
    """Return ``"pcap"`` or ``"pcapng"`` from the file magic.

    The extension is not trustworthy: CIC-IDS2017 files are commonly named
    ``.pcap`` while actually containing pcapng data.
    """

    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        raise NTLFlowLyzerError(f"Could not read capture file {path}: {exc}") from exc
    if magic in _PCAP_MAGIC:
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFormatError(
        f"Unsupported or corrupt capture file {path}: magic bytes "
        f"{magic.hex() or '(empty)'}. Expected classic pcap or pcapng."
    )


def _find_wireshark_tool(name: str) -> Path | None:
    """Find ``editcap``/``tshark`` via env, PATH, or the usual install dirs."""

    configured = os.environ.get(f"NIDS_{name.upper()}")
    if configured:
        path = Path(configured)
        if path.exists():
            return path
        raise NTLFlowLyzerError(
            f"Configured NIDS_{name.upper()} path does not exist: {path}"
        )

    on_path = shutil.which(name)
    if on_path:
        return Path(on_path)

    for directory in _COMMON_WIRESHARK_DIRS:
        candidate = directory / f"{name}.exe"
        if candidate.exists():
            return candidate
    return None


def _convert_to_pcap(pcap_path: Path, output_dir: Path) -> Path:
    if detect_capture_format(pcap_path) == "pcap":
        return pcap_path

    output_dir.mkdir(parents=True, exist_ok=True)
    converted = output_dir / f"{pcap_path.stem}_converted.pcap"
    # Reuse a classic-pcap conversion from an earlier run if it is at least as
    # new as the source capture.
    if converted.exists() and converted.stat().st_mtime >= pcap_path.stat().st_mtime:
        try:
            if detect_capture_format(converted) == "pcap":
                return converted
        except NTLFlowLyzerError:
            pass

    editcap = _find_wireshark_tool("editcap")
    tshark = _find_wireshark_tool("tshark")
    if editcap:
        command = [str(editcap), "-F", "pcap", str(pcap_path), str(converted)]
    elif tshark:
        command = [
            str(tshark),
            "-F",
            "pcap",
            "-r",
            str(pcap_path),
            "-w",
            str(converted),
        ]
    else:
        raise NTLFlowLyzerError(
            "NTLFlowLyzer only accepts classic pcap input, and this file is "
            "pcapng. Install Wireshark/tshark, set NIDS_EDITCAP or NIDS_TSHARK, "
            "or convert it manually with: editcap -F pcap input.pcapng output.pcap"
        )

    converted.unlink(missing_ok=True)
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=1800, check=False
    )
    if result.returncode != 0 or not converted.exists():
        raise NTLFlowLyzerError(
            f"Could not convert {pcap_path} to pcap: {result.stderr.strip()}"
        )
    return converted


class NTLFlowLyzerRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build_config(self, pcap_path: Path, output_csv: Path) -> dict[str, object]:
        return {
            "pcap_file_address": str(pcap_path),
            "output_file_address": str(output_csv),
            "number_of_threads": max(3, self.settings.ntlflowlyzer_threads),
            "feature_extractor_min_flows": 1,
            "writer_min_rows": 1,
            "read_packets_count_value_log_info": 1_000_000,
            "check_flows_ending_min_flows": 1,
            "capturer_updating_flows_min_value": 1,
            "max_flow_duration": self.settings.ntlflowlyzer_max_flow_duration,
            "activity_timeout": self.settings.ntlflowlyzer_activity_timeout,
            "floating_point_unit": ".4f",
            "max_rows_number": 900_000,
            "features_ignore_list": [],
        }

    def run(self, pcap_path: Path) -> pd.DataFrame:
        if not pcap_path.exists():
            raise NTLFlowLyzerError(f"Capture file not found: {pcap_path}")

        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = _convert_to_pcap(pcap_path, self.settings.output_dir)
        output_csv = self.settings.output_dir / f"{pcap_path.stem}_flows.csv"
        config_path = self.settings.output_dir / f"{pcap_path.stem}_flow_config.json"
        # Avoid mixing this run with CSVs left by an earlier replay of the same
        # capture (NTLFlowLyzer splits output when max_rows_number is reached).
        for stale in self.settings.output_dir.glob(f"{pcap_path.stem}_flows*.csv"):
            stale.unlink(missing_ok=True)
        config_path.write_text(
            json.dumps(self.build_config(pcap_path, output_csv), indent=2),
            encoding="utf-8",
        )

        command = [*_resolve_command(self.settings.ntlflowlyzer_command), "-c", str(config_path)]
        logger.info("Running NTLFlowLyzer: %s", " ".join(command))
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.settings.ntlflowlyzer_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NTLFlowLyzerError(
                f"NTLFlowLyzer timed out after "
                f"{self.settings.ntlflowlyzer_timeout_seconds}s on {pcap_path}"
            ) from exc

        if result.returncode != 0:
            raise NTLFlowLyzerError(
                f"NTLFlowLyzer failed on {pcap_path} (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        candidates = sorted(
            self.settings.output_dir.glob(f"{pcap_path.stem}_flows*.csv"),
            key=lambda path: path.stat().st_mtime,
        )
        if not candidates:
            raise NTLFlowLyzerError(
                f"NTLFlowLyzer produced no CSV for {pcap_path}. "
                f"stdout: {result.stdout.strip()[:500]}"
            )

        frames: list[pd.DataFrame] = []
        for csv_path in candidates:
            try:
                frames.append(
                    pd.read_csv(csv_path, encoding="utf-8-sig", low_memory=False)
                )
            except Exception as exc:
                raise NTLFlowLyzerError(f"Could not read {csv_path}: {exc}") from exc
        rows = pd.concat(frames, ignore_index=True) if len(frames) > 1 else frames[0]

        try:
            prepared = prepare_flow_frame(rows)
        except FeatureContractError as exc:
            raise NTLFlowLyzerError(
                f"NTLFlowLyzer output does not satisfy the contract: {exc}"
            ) from exc

        logger.info("Extracted %d flow(s) from %s", len(prepared), pcap_path.name)
        return prepared


def extract_flows(settings: Settings, pcap_path: Path) -> pd.DataFrame:
    return NTLFlowLyzerRunner(settings).run(pcap_path)
