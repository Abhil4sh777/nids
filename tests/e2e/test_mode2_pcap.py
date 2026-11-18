"""Mode 2: replay a real pcap through NTLFlowLyzer, then the shared pipeline.

Set NIDS_TEST_PCAP to a capture file to run this test.  It skips cleanly when
the asset or the NTLFlowLyzer executable is unavailable.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from config import get_settings
from features.ntlflowlyzer import NTLFlowLyzerError, _resolve_command
from features.sources import PcapFeatureSource
from pipeline import Pipeline

pytestmark = pytest.mark.e2e

PCAP = os.environ.get("NIDS_TEST_PCAP")
SKIP_REASON = "set NIDS_TEST_PCAP and install NTLFlowLyzer to run mode 2"


def _ntlflowlyzer_available() -> bool:
    try:
        _resolve_command(get_settings().ntlflowlyzer_command)
    except NTLFlowLyzerError:
        return False
    return True


@pytest.mark.skipif(
    not PCAP or not Path(PCAP).exists() or not _ntlflowlyzer_available(),
    reason=SKIP_REASON,
)
def test_mode2_pcap_replay(models, knowledge, stub_llm) -> None:
    settings = get_settings()
    source = PcapFeatureSource(Path(PCAP), settings)
    batches = list(source.stream())
    assert len(batches) == 1
    frame = batches[0].frame
    if frame.empty:
        pytest.skip("NTLFlowLyzer produced no flows for this capture")

    pipeline = Pipeline(models, knowledge, stub_llm)
    results = pipeline.run_frame(frame, batch_id=batches[0].batch_id)
    assert len(results) == len(frame)
    for result in results:
        if result.is_attack:
            assert result.evidence is not None
            assert result.explanation is not None
        else:
            assert result.predicted_class is None
