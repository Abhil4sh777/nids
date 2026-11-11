"""Mode 1: pre-extracted feature rows -> inference -> SHAP -> LLM -> live table."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from features.sources import CsvFeatureSource
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
