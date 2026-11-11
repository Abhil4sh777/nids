"""Column mapping, validation, and data hygiene for flow feature rows.

NTLFlowLyzer normally emits the contract names directly, but captured CSVs may
differ in case, spacing, or snake/camel style.  This module owns the single
mapping step used by every feature-row source.  Missing or ambiguous columns
are hard errors; extra columns are logged and dropped.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from typing import Any

import numpy as np
import pandas as pd

from features.contract import (
    ALL_FEATURES,
    DETECTOR_FEATURES,
    IDENTIFIER_FEATURES,
    SUPPORTED_PROTOCOLS,
)

logger = logging.getLogger(__name__)


class FeatureContractError(ValueError):
    """Raised when a feature-row source does not satisfy the model contract."""


def _compact(name: str) -> str:
    """Case/separator-insensitive key used for matching column names."""

    return re.sub(r"[^a-z0-9]", "", str(name).lower())


# Compact lookup handles snake_case, spaces, dashes, and CamelCase equally.
_CANONICAL_BY_COMPACT: dict[str, str] = {}
for _feature in ALL_FEATURES:
    _key = _compact(_feature)
    if _key in _CANONICAL_BY_COMPACT:
        raise RuntimeError(
            f"Feature contract has ambiguous compact name {_key!r}: "
            f"{_CANONICAL_BY_COMPACT[_key]!r} and {_feature!r}"
        )
    _CANONICAL_BY_COMPACT[_key] = _feature

# Safe synonyms seen in exported datasets.  Keys are compact names.
_ALIASES: dict[str, str] = {
    "flowid": "flow_id",
    "time": "timestamp",
    "flowtimestamp": "timestamp",
    "sourceip": "src_ip",
    "sourceaddress": "src_ip",
    "destinationip": "dst_ip",
    "destip": "dst_ip",
    "destinationaddress": "dst_ip",
    "sourceport": "src_port",
    "sport": "src_port",
    "destinationport": "dst_port",
    "destport": "dst_port",
    "dport": "dst_port",
    "proto": "protocol",
}
for _alias, _feature in _ALIASES.items():
    if _alias in _CANONICAL_BY_COMPACT and _CANONICAL_BY_COMPACT[_alias] != _feature:
        raise RuntimeError(f"Alias {_alias!r} conflicts with a contract feature")
    _CANONICAL_BY_COMPACT[_alias] = _feature

_NUMERIC_PROTOCOLS: dict[str, str] = {
    "6": "TCP",
    "17": "UDP",
}

_NON_NUMERIC_FEATURES: frozenset[str] = frozenset(IDENTIFIER_FEATURES + ["protocol"])


def _canonical_for(column: Any) -> str | None:
    return _CANONICAL_BY_COMPACT.get(_compact(str(column)))


def map_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Return ``df`` with contract column names, preserving row order.

    Extra source columns are dropped with a warning.  Two source columns that
    resolve to the same contract column are ambiguous and raise.
    """

    if not isinstance(df, pd.DataFrame):
        raise FeatureContractError(
            f"Expected a pandas DataFrame of flow rows, got {type(df).__name__}"
        )

    mapping: dict[Any, str] = {}
    seen: dict[str, Any] = {}
    unknown: list[Any] = []
    for column in df.columns:
        canonical = _canonical_for(column)
        if canonical is None:
            unknown.append(column)
            continue
        if canonical in seen:
            raise FeatureContractError(
                f"Ambiguous columns {seen[canonical]!r} and {column!r} both map "
                f"to contract feature {canonical!r}"
            )
        seen[canonical] = column
        mapping[column] = canonical

    if unknown:
        logger.warning(
            "Dropping %d column(s) that are not part of the feature contract: %s",
            len(unknown),
            ", ".join(map(str, unknown[:10])) + (" ..." if len(unknown) > 10 else ""),
        )

    return df.rename(columns=mapping)


def missing_columns(df: pd.DataFrame, required: Sequence[str]) -> list[str]:
    return [name for name in required if name not in df.columns]


def require_columns(df: pd.DataFrame, required: Sequence[str]) -> None:
    missing = missing_columns(df, required)
    if missing:
        shown = ", ".join(missing[:15])
        if len(missing) > 15:
            shown += f", ... ({len(missing) - 15} more)"
        raise FeatureContractError(
            f"Flow rows are missing {len(missing)} required column(s): {shown}. "
            "Refusing to pad or reorder silently."
        )


def coerce_protocol(series: pd.Series) -> pd.Series:
    """Normalise protocol values to the two categories seen in training."""

    def convert(value: Any) -> str:
        if value is None or (isinstance(value, float) and np.isnan(value)):
            raise FeatureContractError("protocol contains a missing value")
        text = str(value).strip()
        if not text:
            raise FeatureContractError("protocol contains an empty value")
        upper = text.upper()
        if upper in SUPPORTED_PROTOCOLS:
            return upper
        numeric = _NUMERIC_PROTOCOLS.get(text)
        if numeric is not None:
            return numeric
        # Handle numeric floats such as 6.0 without accepting arbitrary text.
        try:
            as_float = float(text)
        except ValueError:
            as_float = None
        if as_float is not None and as_float.is_integer():
            numeric = _NUMERIC_PROTOCOLS.get(str(int(as_float)))
            if numeric is not None:
                return numeric
        raise FeatureContractError(
            f"Unsupported protocol value {value!r}. The fitted encoder only "
            f"supports {SUPPORTED_PROTOCOLS} (or numeric 6/17)."
        )

    return series.map(convert).astype(object)


def coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Convert all non-identifier, non-protocol feature columns to numbers."""

    result = df.copy()
    for column in result.columns:
        if column in _NON_NUMERIC_FEATURES:
            continue
        try:
            result[column] = pd.to_numeric(result[column], errors="raise")
        except (TypeError, ValueError) as exc:
            sample = result[column].head(5).tolist()
            raise FeatureContractError(
                f"Column {column!r} contains non-numeric values "
                f"(first rows: {sample!r})"
            ) from exc
    return result


def prepare_flow_frame(
    df: pd.DataFrame,
    required: Sequence[str] = ALL_FEATURES,
    *,
    reset_index: bool = True,
) -> pd.DataFrame:
    """Map, validate, and normalise a frame of flow rows.

    The returned frame has exactly ``required`` as columns, in contract order.
    """

    required = list(required)
    mapped = map_columns(df)
    require_columns(mapped, required)

    result = mapped.loc[:, required].copy()
    if reset_index:
        result = result.reset_index(drop=True)

    if "protocol" in result.columns:
        result["protocol"] = coerce_protocol(result["protocol"])

    # Only touch columns that will actually be fed to a model.
    model_columns = [
        name for name in result.columns if name not in _NON_NUMERIC_FEATURES
    ]
    if model_columns:
        numeric = coerce_numeric(result.loc[:, model_columns])
        result.loc[:, model_columns] = numeric

    return result


def prepare_inference_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare rows for the full pipeline (identifiers + detector features).

    Classifier features are a subset of detector features, so these columns are
    sufficient for both models while retaining identifiers for the UI.
    """

    keep = set(IDENTIFIER_FEATURES) | set(DETECTOR_FEATURES)
    required = [name for name in ALL_FEATURES if name in keep]
    return prepare_flow_frame(df, required=required)


def split_feature_lists(required: Iterable[str]) -> tuple[list[str], list[str]]:
    """Utility for tests: return (known, unknown) contract membership."""

    known = set(ALL_FEATURES)
    return (
        [name for name in required if name in known],
        [name for name in required if name not in known],
    )
