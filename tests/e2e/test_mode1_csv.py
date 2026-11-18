"""Mode 1: pre-extracted feature rows -> inference -> SHAP -> LLM -> live table."""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import pytest

from features.contract import ALL_FEATURES
from features.sources import CsvFeatureSource, StaticFeatureSource
from pipeline import Pipeline
from ui.store import UiStore
from ui.table import TABLE_COLUMNS, rows_to_dataframe
from ui.worker import PipelineWorker


def test_mode1_csv_reaches_table(
    models,
    knowledge,
    attack_row: dict[str, object],
    benign_row: dict[str, object],
    tmp_path: Path,
    stub_llm,
) -> None:
    csv_path = tmp_path / "bccc_like.csv"
    pd.DataFrame([attack_row, benign_row]).to_csv(csv_path, index=False)

    source = CsvFeatureSource(csv_path)
    pipeline = Pipeline(models, knowledge, stub_llm)
    store = UiStore(history_limit=10)
    worker = PipelineWorker(source, pipeline, store)
    worker.start()
    worker.join(timeout=120)

    assert not worker.is_alive()
    status = store.status()
    assert status.state == "done"
    assert status.error is None
    assert status.processed == 2
    assert status.attacks == 1

    rows = store.snapshot()
    assert [row.flow_id for row in rows] == ["benign-0", "attack-0"]
    attack = next(row for row in rows if row.verdict == "Attack")
    benign_row = next(row for row in rows if row.verdict == "Benign")
    assert attack.pending is False
    assert attack.explanation == "Stub explanation"
    assert attack.evidence is not None
    assert len(attack.evidence.detector_top5) == 5
    assert benign_row.result_text == "Benign"

    frame = rows_to_dataframe(rows)
    assert list(frame.columns) == TABLE_COLUMNS
    assert set(frame["result"]) == {"Benign", "Stub explanation"}
    assert len(stub_llm.packets) == 1


REAL_CSV = os.environ.get("NIDS_TEST_CSV")
REAL_CSV_ROWS = int(os.environ.get("NIDS_TEST_CSV_ROWS", "20000"))


@pytest.mark.skipif(
    not REAL_CSV or not Path(REAL_CSV).exists(),
    reason="set NIDS_TEST_CSV to a real pre-extracted feature CSV for mode 1",
)
def test_mode1_real_csv_reaches_table(
    models,
    knowledge,
    stub_llm,
) -> None:
    """Exercise a real BCCC-format export, not synthetic rows."""

    source_path = Path(REAL_CSV)
    # Bound the run by default; a full export can be large.  Set
    # NIDS_TEST_CSV_ROWS=0 to analyze the whole file.
    nrows = None if REAL_CSV_ROWS <= 0 else REAL_CSV_ROWS
    frame = pd.read_csv(source_path, nrows=nrows, low_memory=False)
    assert list(frame.columns) == ALL_FEATURES, (
        "real BCCC CSV must already match the 121-column contract"
    )

    source = (
        StaticFeatureSource(frame, batch_id="real-bccc")
        if nrows is not None
        else CsvFeatureSource(source_path, batch_id="real-bccc")
    )

    pipeline = Pipeline(models, knowledge, stub_llm)
    store = UiStore(history_limit=max(10, len(frame)))
    worker = PipelineWorker(source, pipeline, store)
    worker.start()
    worker.join(timeout=3600)

    assert not worker.is_alive()
    status = store.status()
    assert status.state == "done"
    assert status.error is None
    assert status.processed == len(frame)
    assert status.attacks == sum(
        1 for row in store.snapshot() if row.verdict == "Attack"
    )

    rows = store.snapshot()
    assert len(rows) == len(frame)
    attacks = [row for row in rows if row.verdict == "Attack"]
    benign = [row for row in rows if row.verdict == "Benign"]
    assert attacks, "sample should contain at least one attack"
    assert benign, "sample should contain at least one benign flow"
    for row in attacks:
        assert row.pending is False
        assert row.explanation == "Stub explanation"
        assert row.evidence is not None
        assert len(row.evidence.detector_top5) == 5
        assert len(row.evidence.classifier_top5) == 5
        assert row.predicted_class is not None
    for row in benign:
        assert row.result_text == "Benign"
        assert row.evidence is None

    table = rows_to_dataframe(rows)
    assert list(table.columns) == TABLE_COLUMNS
    # Alerts are grouped by (class, src_ip, window), so one LLM call can cover
    # several attack rows; every call must still be reflected in the table.
    assert 0 < len(stub_llm.packets) <= len(attacks)
