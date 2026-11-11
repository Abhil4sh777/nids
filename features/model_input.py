"""Build model inputs as DataFrames selected by explicit contract lists."""

from __future__ import annotations

import numpy as np
import pandas as pd

from features.contract import CLASSIFIER_FEATURES, DETECTOR_FEATURES
from features.validation import FeatureContractError, require_columns


def select_features(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    """Select ``features`` by name and order, never by position."""

    require_columns(df, features)
    return df.loc[:, features].copy()


def detector_input(df: pd.DataFrame) -> pd.DataFrame:
    return select_features(df, DETECTOR_FEATURES)


def classifier_input(df: pd.DataFrame) -> pd.DataFrame:
    return select_features(df, CLASSIFIER_FEATURES)


def encode_with_pipeline(pipeline: object, X: pd.DataFrame) -> pd.DataFrame:
    """Run a fitted preprocessing step and return a named, encoded frame.

    XGBoost's booster was trained on the encoded column names.  Keeping those
    names on the DataFrame is required for SHAP's feature attribution order.
    """

    preprocessing = pipeline.named_steps["preprocessing"]  # type: ignore[attr-defined]
    encoded = preprocessing.transform(X)
    if hasattr(encoded, "toarray"):
        encoded = encoded.toarray()

    names = list(preprocessing.get_feature_names_out())
    booster = pipeline.named_steps["classifier"].get_booster()  # type: ignore[attr-defined]
    booster_names = list(booster.feature_names or [])
    if booster_names and names != booster_names:
        raise FeatureContractError(
            "Encoded feature names do not match the booster's feature order"
        )

    frame = pd.DataFrame(np.asarray(encoded), columns=names, index=X.index)
    return frame


def encoded_to_raw_feature(encoded_name: str, raw_columns: list[str]) -> str:
    """Map an encoded feature name back to the flow row's raw column."""

    if encoded_name in raw_columns:
        return encoded_name
    if encoded_name.startswith("protocol_"):
        return "protocol"
    raise FeatureContractError(
        f"Cannot map encoded feature {encoded_name!r} back to a raw flow column"
    )
