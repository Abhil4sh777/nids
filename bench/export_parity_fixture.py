"""Export the laptop-vs-Pi parity fixture.

Writes 100 deterministic feature rows plus the detector/classifier results
produced by the laptop.  ``tests/test_parity.py`` re-runs the same rows and
asserts the probabilities, threshold decisions, and classes are unchanged.

Usage::

    python -m bench.export_parity_fixture
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from bench.common import library_versions, parity_frame
from config import get_settings
from features.contract import ALL_FEATURES, DETECTOR_THRESHOLD
from features.validation import prepare_flow_frame
from models.inference import InferenceEngine
from models.loader import load_models

DEFAULT_COUNT = 100
DEFAULT_OUTPUT_DIR = Path("tests") / "fixtures"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    settings = get_settings()
    frame = prepare_flow_frame(parity_frame(args.count))
    assert list(frame.columns) == ALL_FEATURES

    models = load_models(settings)
    predictions = InferenceEngine(models).predict(frame)

    expected = []
    for prediction in predictions:
        expected.append(
            {
                "flow_id": prediction.flow_id,
                "attack_probability": prediction.attack_probability,
                "is_attack": prediction.is_attack,
                "predicted_class": prediction.predicted_class,
                "class_probability": prediction.class_probability,
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows_path = args.output_dir / "parity_rows.csv"
    expected_path = args.output_dir / "parity_expected.json"
    frame.to_csv(rows_path, index=False)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "detector_threshold": DETECTOR_THRESHOLD,
        "count": len(frame),
        "versions": library_versions(),
        "rows": expected,
    }
    expected_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Wrote {len(frame)} rows to {rows_path}")
    print(f"Wrote expected results to {expected_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
