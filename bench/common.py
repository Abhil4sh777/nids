"""Shared helpers for benchmark scripts.

Everything here is read-only measurement: no behaviour changes, so a benchmark
never masks the cost it is trying to measure.
"""

from __future__ import annotations

import platform
from pathlib import Path

import numpy as np
import pandas as pd

from features.contract import ALL_FEATURES


def rss_bytes() -> int | None:
    """Resident set size of this process, or None outside Linux."""

    status = Path("/proc/self/status")
    if not status.exists():
        return None
    for line in status.read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None


def cpu_temperature_celsius() -> float | None:
    """Pi CPU temperature from the thermal zone, if available."""

    path = Path("/sys/class/thermal/thermal_zone0/temp")
    if not path.exists():
        return None
    try:
        return int(path.read_text().strip()) / 1000.0
    except (OSError, ValueError):
        return None


def child_peak_rss_bytes() -> int | None:
    """Peak RSS of reaped child processes (KiB on Linux) in bytes."""

    try:
        import resource
    except ImportError:  # pragma: no cover - Windows dev machine
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    # Linux reports KiB; macOS reports bytes.  Target is Linux.
    return int(usage.ru_maxrss) * 1024


def library_versions() -> dict[str, str]:
    import joblib
    import sklearn
    import shap
    import xgboost

    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "xgboost": xgboost.__version__,
        "scikit-learn": sklearn.__version__,
        "joblib": joblib.__version__,
        "shap": shap.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
    }


def synthetic_row(seed: int, flow_id: str) -> dict[str, object]:
    """Deterministic synthetic flow row (same generator as the parity fixture)."""

    rng = np.random.default_rng(seed)
    row: dict[str, object] = {feature: 0.0 for feature in ALL_FEATURES}
    for feature in ALL_FEATURES:
        if feature in {"flow_id", "timestamp", "src_ip", "dst_ip"}:
            continue
        if feature == "protocol":
            row[feature] = "TCP"
        elif feature in {"src_port", "dst_port"}:
            row[feature] = int(rng.integers(1, 65535))
        elif feature == "duration":
            row[feature] = float(rng.uniform(0.001, 100))
        else:
            row[feature] = float(rng.uniform(0, 1000))
    row.update(
        flow_id=flow_id,
        timestamp="2026-01-01 00:00:00",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
    return row


def zero_row(flow_id: str = "benign-0") -> dict[str, object]:
    """All-zero flow; the real detector classifies it as Benign."""

    row: dict[str, object] = {feature: 0.0 for feature in ALL_FEATURES}
    row.update(
        flow_id=flow_id,
        timestamp="2026-01-01 00:00:00",
        src_ip="10.0.0.1",
        src_port=12345,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
    )
    return row


def synthetic_frame(count: int, prefix: str = "bench") -> pd.DataFrame:
    return pd.DataFrame(
        [synthetic_row(seed, f"{prefix}-{seed:03d}") for seed in range(count)]
    )


def parity_frame(count: int, prefix: str = "parity") -> pd.DataFrame:
    """Deterministic mix of synthetic and all-zero flows for the parity fixture.

    Synthetic rows are almost all attacks with the real models, so every third
    row is replaced by an all-zero flow.  That keeps both branches of the
    0.3545 threshold represented and still gives the classifier something to
    disagree about.
    """

    rows = []
    for seed in range(count):
        flow_id = f"{prefix}-{seed:03d}"
        rows.append(
            zero_row(flow_id) if seed % 3 == 2 else synthetic_row(seed, flow_id)
        )
    return pd.DataFrame(rows)
