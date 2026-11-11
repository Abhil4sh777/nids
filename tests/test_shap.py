from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from explain.shap_explainer import (
    ShapService,
    select_shap_values,
    top_features,
)
from features.contract import ALL_FEATURES
from features.model_input import encoded_to_raw_feature


def test_two_dimensional_values() -> None:
    values = np.arange(10, dtype=float).reshape(1, 10)
    selected = select_shap_values(values, class_index=0, n_features=10)
    assert selected.shape == (10,)
    np.testing.assert_array_equal(selected, values[0])


def test_list_per_class_values() -> None:
    values = [np.ones((1, 5)), np.arange(5, dtype=float).reshape(1, 5)]
    selected = select_shap_values(values, class_index=1, n_features=5)
    np.testing.assert_array_equal(selected, np.arange(5))


def test_three_dimensional_feature_class_axis() -> None:
    values = np.zeros((1, 4, 3))
    values[0, :, 2] = [1, 2, 3, 4]
    selected = select_shap_values(values, class_index=2, n_features=4)
    np.testing.assert_array_equal(selected, [1, 2, 3, 4])


def test_three_dimensional_class_feature_axis() -> None:
    values = np.zeros((1, 3, 4))
    values[0, 1, :] = [4, 3, 2, 1]
    selected = select_shap_values(values, class_index=1, n_features=4)
    np.testing.assert_array_equal(selected, [4, 3, 2, 1])


def test_invalid_shape_is_rejected() -> None:
    with pytest.raises(ValueError):
        select_shap_values(np.zeros((2, 3, 4)), class_index=0, n_features=3)
    with pytest.raises(ValueError):
        select_shap_values(np.zeros(4), class_index=0, n_features=4)


def test_protocol_encoding_maps_back_to_raw_feature() -> None:
    assert encoded_to_raw_feature("protocol_UDP", list(ALL_FEATURES)) == "protocol"
    assert encoded_to_raw_feature("duration", list(ALL_FEATURES)) == "duration"


def test_top_features_keeps_signs_and_raw_values() -> None:
    encoded = pd.DataFrame(
        [[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]],
        columns=[
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
        ],
    )
    shap_values = np.array([-0.1, 5.0, -4.0, 0.2, 3.0, -2.0])
    raw = pd.Series({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6})
    result = top_features(encoded, shap_values, raw, k=5)
    assert [item.feature for item in result] == ["b", "c", "e", "f", "d"]
    assert [item.shap_value for item in result] == [5.0, -4.0, 3.0, -2.0, 0.2]
    assert result[0].value == 2


def test_real_detector_and_classifier_contributions(
    models, prepared_attack: pd.DataFrame, engine
) -> None:
    prediction = engine.predict(prepared_attack)[0]
    assert prediction.is_attack
    service = ShapService(models)
    detector_top = service.detector_contributions(prepared_attack.iloc[0])
    classifier_top = service.classifier_contributions(
        prepared_attack.iloc[0], prediction.class_index
    )
    for contributions in (detector_top, classifier_top):
        assert len(contributions) == 5
        assert all(item.feature in ALL_FEATURES for item in contributions)
        assert all(np.isfinite(item.shap_value) for item in contributions)
        assert [abs(item.shap_value) for item in contributions] == sorted(
            (abs(item.shap_value) for item in contributions), reverse=True
        )


def test_shap_accepts_one_row_dataframe(
    models, prepared_attack: pd.DataFrame, engine
) -> None:
    prediction = engine.predict(prepared_attack)[0]
    service = ShapService(models)
    top = service.detector_contributions(prepared_attack.iloc[[0]])
    assert len(top) == 5
    assert prediction.is_attack
