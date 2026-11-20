"""Measure the ExecuTorch explanation backend end to end.

Uses only the ``LLMBackend`` interface, so the script measures whatever backend
config selects.  The ExecuTorch runner is non-streaming and does not expose a
time-to-first-token, so the first call is reported separately: it includes the
runner's model load.

Usage::

    python -m bench.bench_llm --csv /data/bccc_sample.csv --repeats 5
    python -m bench.bench_llm --rows 200
"""

from __future__ import annotations

import argparse
import time

from bench.common import (
    child_peak_rss_bytes,
    cpu_temperature_celsius,
    library_versions,
    rss_bytes,
    synthetic_frame,
)
from config import get_settings
from explain.llm.tokens import estimate_tokens
from pipeline import build_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", help="pre-extracted feature rows")
    parser.add_argument("--rows", type=int, default=200)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    settings = get_settings()
    pipeline = build_pipeline(settings)
    backend = pipeline.backend
    if backend is None:
        print("The pipeline has no LLM backend to benchmark.")
        return 1

    if args.csv:
        import pandas as pd

        frame = pd.read_csv(args.csv, low_memory=False)
    else:
        frame = synthetic_frame(args.rows)
    results = pipeline.analyze_frame(frame)
    attacks = [result for result in results if result.is_attack]
    attack = next((item for item in attacks if item.evidence is not None), None)
    if attack is None:
        print("No attack row in this sample; pass a sample with at least one alert.")
        return 1

    assert attack.evidence is not None
    tokens = backend.count_prompt_tokens(attack.evidence)
    rss_before = rss_bytes()

    timings: list[float] = []
    for _ in range(max(1, args.repeats)):
        start = time.perf_counter()
        explanation = pipeline.explain_result(attack)
        timings.append(time.perf_counter() - start)
        assert explanation is not None
        if explanation.source != "llm":
            print(
                "Backend produced no text (fallback was used), so there is "
                f"nothing to measure: {explanation.error}"
            )
            return 1

    rss_after = rss_bytes()
    first, rest = timings[0], timings[1:] or [timings[0]]
    average = sum(rest) / len(rest)
    # Token/sec is estimated from the answer text; the interface returns text.
    answer_tokens = estimate_tokens(explanation.text)
    rows = [
        ("backend", backend.name),
        ("prompt tokens", str(tokens)),
        ("first call (includes load)", f"{first:.2f} s"),
        ("steady-state call", f"{average:.2f} s"),
        ("answer tokens (estimated)", str(answer_tokens)),
        ("answer tokens/s (estimated)", f"{answer_tokens / average:.2f}"),
    ]
    rss = rss_after or rss_before
    if rss is not None:
        rows.append(("process RSS", f"{rss / 1024 / 1024:.0f} MiB"))
    child = child_peak_rss_bytes()
    if child is not None:
        rows.append(("peak child RSS", f"{child / 1024 / 1024:.0f} MiB"))
    temperature = cpu_temperature_celsius()
    if temperature is not None:
        rows.append(("CPU temperature", f"{temperature:.1f} C"))
    for name, value in library_versions().items():
        rows.append((name, value))

    print("| Measure | Value |")
    print("| --- | --- |")
    for name, value in rows:
        print(f"| {name} | {value} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
