from __future__ import annotations

from features.contract import (
    ALL_FEATURES,
    CLASSIFIER_FEATURES,
    CLASSIFIER_LABELS,
    DETECTOR_FEATURES,
    DETECTOR_LABELS,
    DETECTOR_THRESHOLD,
    IDENTIFIER_FEATURES,
    SUPPORTED_PROTOCOLS,
)


def test_feature_counts() -> None:
    assert len(ALL_FEATURES) == 121
    assert len(DETECTOR_FEATURES) == 112
    assert len(CLASSIFIER_FEATURES) == 106
    assert len(set(ALL_FEATURES)) == 121


def test_detector_exclusions_and_order() -> None:
    excluded = set(IDENTIFIER_FEATURES) | {
        "urg_flag_counts",
        "fwd_urg_flag_counts",
        "bwd_urg_flag_counts",
    }
    assert DETECTOR_FEATURES == [name for name in ALL_FEATURES if name not in excluded]
    assert DETECTOR_FEATURES[0] == "protocol"
    assert DETECTOR_FEATURES[-1] == "subflow_bwd_bytes"


def test_classifier_is_subsequence() -> None:
    assert CLASSIFIER_FEATURES == [
        name
        for name in DETECTOR_FEATURES
        if name
        not in {
            "ece_flag_counts",
            "cwr_flag_counts",
            "fwd_ece_flag_counts",
            "fwd_cwr_flag_counts",
            "bwd_ece_flag_counts",
            "bwd_cwr_flag_counts",
        }
    ]
    positions = [DETECTOR_FEATURES.index(name) for name in CLASSIFIER_FEATURES]
    assert positions == sorted(positions)


def test_labels_and_threshold() -> None:
    assert DETECTOR_THRESHOLD == 0.3545
    assert DETECTOR_LABELS == {0: "Benign", 1: "Attack"}
    assert list(CLASSIFIER_LABELS) == list(range(13))
    assert len(set(CLASSIFIER_LABELS.values())) == 13
    assert CLASSIFIER_LABELS[0] == "DoS_Hulk"
    assert CLASSIFIER_LABELS[12] == "Heartbleed"


def test_protocol_categories_match_fitted_encoder() -> None:
    assert SUPPORTED_PROTOCOLS == ("TCP", "UDP")
