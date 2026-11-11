"""Swappable sources of feature rows.

All three end-to-end modes share the same downstream inference/explain/UI code
and differ only in which source produces validated flow-row frames.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from capture.dumpcap import CaptureError, DumpcapCapture
from config import Settings
from features.ntlflowlyzer import NTLFlowLyzerRunner
from features.validation import prepare_flow_frame

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceBatch:
    batch_id: str
    frame: pd.DataFrame


class FeatureSource:
    """Common interface: yield validated batches until exhausted or stopped."""

    def stream(self) -> Iterator[SourceBatch]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class StaticFeatureSource(FeatureSource):
    """Mode 1: pre-extracted rows, e.g. a BCCC-format CSV."""

    def __init__(self, frame: pd.DataFrame, batch_id: str = "batch") -> None:
        self._frame = frame
        self._batch_id = batch_id

    def stream(self) -> Iterator[SourceBatch]:
        yield SourceBatch(self._batch_id, prepare_flow_frame(self._frame))


class CsvFeatureSource(StaticFeatureSource):
    def __init__(self, path: Path, batch_id: str | None = None) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Feature CSV not found: {path}")
        frame = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)
        super().__init__(frame, batch_id or path.stem)


class PcapFeatureSource(FeatureSource):
    """Mode 2: replay one pcap through NTLFlowLyzer, then the normal pipeline."""

    def __init__(self, pcap_path: Path, settings: Settings) -> None:
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")
        self.pcap_path = pcap_path
        self.settings = settings

    def stream(self) -> Iterator[SourceBatch]:
        runner = NTLFlowLyzerRunner(self.settings)
        yield SourceBatch(self.pcap_path.stem, runner.run(self.pcap_path))


class LiveFeatureSource(FeatureSource):
    """Mode 3: dumpcap rolling files + NTLFlowLyzer, one batch per file."""

    def __init__(
        self,
        settings: Settings,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.settings = settings
        self.stop_event = stop_event or threading.Event()
        self._capture = DumpcapCapture(settings)
        self._runner = NTLFlowLyzerRunner(settings)

    def close(self) -> None:
        self.stop_event.set()
        self._capture.stop()

    def stream(self) -> Iterator[SourceBatch]:
        processed: set[Path] = set()
        self._capture.start()
        try:
            while not self.stop_event.is_set():
                files = self._capture.completed_files()
                for path in files:
                    if path in processed:
                        continue
                    processed.add(path)
                    try:
                        frame = self._runner.run(path)
                    except Exception as exc:
                        logger.exception("Could not extract flows from %s", path)
                        raise
                    if not frame.empty:
                        yield SourceBatch(path.stem, frame)
                if not self._capture.is_running:
                    raise CaptureError(
                        "dumpcap stopped unexpectedly. Log: "
                        + self._capture.log_tail()
                    )
                time.sleep(self.settings.capture_poll_seconds)
        finally:
            self._capture.stop()

        # After stopping, flush the final rotated file as well.
        for path in self._capture.completed_files(include_last=True):
            if path in processed:
                continue
            processed.add(path)
            frame = self._runner.run(path)
            if not frame.empty:
                yield SourceBatch(path.stem, frame)
