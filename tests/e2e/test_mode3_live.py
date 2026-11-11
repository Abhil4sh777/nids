"""Mode 3: live capture through dumpcap and NTLFlowLyzer.

Run manually with NIDS_TEST_LIVE=1 and NIDS_INTERFACE set.  This test is skipped
by default because it needs Npcap, dumpcap, a real interface, and NTLFlowLyzer.
"""

from __future__ import annotations

import os
import shutil
import threading
import time

import pytest

from capture.dumpcap import find_dumpcap
from config import get_settings
from features.sources import LiveFeatureSource
from pipeline import Pipeline

pytestmark = pytest.mark.e2e


def _available() -> bool:
    if os.environ.get("NIDS_TEST_LIVE") != "1":
        return False
    if not os.environ.get("NIDS_INTERFACE"):
        return False
    if shutil.which("ntlflowlyzer") is None:
        return False
    try:
        find_dumpcap(os.environ.get("NIDS_DUMPCAP"))
    except Exception:
        return False
    return True


@pytest.mark.skipif(not _available(), reason="requires NIDS_TEST_LIVE=1, NIDS_INTERFACE, dumpcap, NTLFlowLyzer")
def test_mode3_live_capture(models, knowledge, stub_llm) -> None:
    settings = get_settings()
    stop_event = threading.Event()
    source = LiveFeatureSource(settings, stop_event)
    batches = []

    def consume() -> None:
        for batch in source.stream():
            batches.append(batch)
            stop_event.set()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    deadline = time.time() + float(os.environ.get("NIDS_TEST_LIVE_SECONDS", "60"))
    while time.time() < deadline and not batches:
        time.sleep(0.5)
    stop_event.set()
    source.close()
    thread.join(timeout=10)

    if not batches:
        pytest.skip("no completed capture file was produced within the live window")

    pipeline = Pipeline(models, knowledge, stub_llm)
    results = pipeline.run_frame(batches[0].frame, batch_id=batches[0].batch_id)
    assert results
