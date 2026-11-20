"""Measure capture->features, detector, and classifier+SHAP cost separately.

Usage (on the Pi)::

    python -m bench.bench_stages --pcap /data/Friday.pcap --max-alerts 50
    python -m bench.bench_stages --csv /data/bccc_sample.csv

The numbers are printed as a markdown table ready for ``bench/RESULTS.md``.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import pandas as pd

from bench.common import (
    child_peak_rss_bytes,
    cpu_temperature_celsius,
    library_versions,
    rss_bytes,
    synthetic_frame,
)
from config import get_settings
from explain.knowledge_base import load_knowledge_base
from explain.shap_explainer import ShapService
from features.contract import DETECTOR_THRESHOLD
from features.ntlflowlyzer import NTLFlowLyzerRunner
from features.validation import prepare_flow_frame
from models.inference import InferenceEngine
from models.loader import load_models


def _timed(callable_):
    start = time.perf_counter()
    value = callable_()
    return value, time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", type=Path, help="capture to extract flows from")
    source.add_argument("--csv", type=Path, help="pre-extracted feature rows")
    parser.add_argument("--rows", type=int, default=200, help="synthetic rows if no source")
    parser.add_argument("--max-alerts", type=int, default=50)
    args = parser.parse_args()

    settings = get_settings()
    rows: list[tuple[str, str, str]] = []

    if args.pcap:
        runner = NTLFlowLyzerRunner(settings)
        frame, seconds = _timed(lambda: runner.run(args.pcap))
        rows.append(("capture -> features", f"{len(frame)} flows", f"{seconds:.2f} s"))
    elif args.csv:
        frame, seconds = _timed(
            lambda: prepare_flow_frame(pd.read_csv(args.csv, low_memory=False))
        )
        rows.append(("csv -> features", f"{len(frame)} flows", f"{seconds:.2f} s"))
    else:
        frame = prepare_flow_frame(synthetic_frame(args.rows))
        rows.append(("synthetic rows", f"{len(frame)} flows", "n/a"))

    models = load_models(settings)
    knowledge = load_knowledge_base(settings.knowledge_dir)
    engine = InferenceEngine(models)
    shap = ShapService(models)

    probabilities, detect_seconds = _timed(
        lambda: engine.detector_probabilities(frame)
    )
    attack_positions = [
        index
        for index, value in enumerate(probabilities)
        if value >= DETECTOR_THRESHOLD
    ]
    per_flow_ms = detect_seconds * 1000.0 / max(1, len(frame))
    rows.append(
        (
            "detector",
            f"{len(frame)} flows, {len(attack_positions)} attacks",
            f"{detect_seconds:.2f} s ({per_flow_ms:.2f} ms/flow)",
        )
    )

    predictions = engine.predict(frame)
    alert_budget = max(0, args.max_alerts)
    attack_predictions = [item for item in predictions if item.is_attack][
        :alert_budget
    ]
    if attack_predictions:
        start = time.perf_counter()
        for prediction in attack_predictions:
            row = frame.iloc[prediction.row_position]
            shap.detector_contributions(row)
            if prediction.class_index is not None:
                shap.classifier_contributions(row, prediction.class_index)
        shap_seconds = time.perf_counter() - start
        rows.append(
            (
                "classifier + SHAP",
                f"{len(attack_predictions)} alerts",
                f"{shap_seconds:.2f} s "
                f"({shap_seconds * 1000.0 / len(attack_predictions):.2f} ms/alert)",
            )
        )
    else:
        rows.append(("classifier + SHAP", "0 alerts", "not measured"))

    for name, value in library_versions().items():
        rows.append(("environment", name, value))
    rss = rss_bytes()
    if rss is not None:
        rows.append(("memory", "process RSS", f"{rss / 1024 / 1024:.0f} MiB"))
    child = child_peak_rss_bytes()
    if child is not None:
        rows.append(("memory", "peak child RSS", f"{child / 1024 / 1024:.0f} MiB"))
    temperature = cpu_temperature_celsius()
    if temperature is not None:
        rows.append(("thermal", "CPU temperature", f"{temperature:.1f} C"))

    print("| Stage | Input | Measurement |")
    print("| --- | --- | --- |")
    for stage, detail, value in rows:
        print(f"| {stage} | {detail} | {value} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
