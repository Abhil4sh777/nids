from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from features.contract import ALL_FEATURES, DETECTOR_THRESHOLD
from features.validation import prepare_flow_frame
from models.inference import InferenceEngine

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
ROWS_PATH = FIXTURE_DIR / "parity_rows.csv"
EXPECTED_PATH = FIXTURE_DIR / "parity_expected.json"


def _expected() -> dict:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


def test_fixture_files_exist() -> None:
    assert ROWS_PATH.exists()
    assert EXPECTED_PATH.exists()


def test_parity_with_reference_probabilities(models) -> None:
    """Re-run the committed fixture and require identical decisions here.

    The fixture records what the reference machine produced for these rows.
    deploy/verify.sh runs this on the Pi after every install.
    """

    payload = _expected()
    assert payload["detector_threshold"] == DETECTOR_THRESHOLD
    rows = pd.read_csv(ROWS_PATH, low_memory=False)
    assert list(rows.columns) == ALL_FEATURES
    assert len(rows) == payload["count"] == len(payload["rows"])

    frame = prepare_flow_frame(rows)
    engine = InferenceEngine(models)
    probabilities = engine.detector_probabilities(frame)
    predictions = engine.predict(frame)

    for expected, probability, prediction in zip(
        payload["rows"], probabilities, predictions
    ):
        assert prediction.flow_id == expected["flow_id"]
        assert probability == pytest.approx(
            expected["attack_probability"], abs=1e-6
        )
        assert (probability >= DETECTOR_THRESHOLD) == expected["is_attack"]
        assert prediction.is_attack == expected["is_attack"]
        assert prediction.predicted_class == expected["predicted_class"]
        if expected["class_probability"] is None:
            assert prediction.class_probability is None
        else:
            assert prediction.class_probability == pytest.approx(
                expected["class_probability"], abs=1e-6
            )
