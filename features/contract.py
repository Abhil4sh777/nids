"""Single source of truth for the feature contract, labels, and threshold.

The order of ``ALL_FEATURES`` is part of the model contract.  Never sort,
rename, drop, or reorder these names.  ``DETECTOR_FEATURES`` and
``CLASSIFIER_FEATURES`` are derived below so the exclusions are defined only
once.
"""

from __future__ import annotations

# 121 flow features, in the exact order produced by NTLFlowLyzer and consumed
# by the training notebooks.
ALL_FEATURES: list[str] = [
    "flow_id",
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "duration",
    "packets_count",
    "fwd_packets_count",
    "bwd_packets_count",
    "total_payload_bytes",
    "fwd_total_payload_bytes",
    "bwd_total_payload_bytes",
    "payload_bytes_max",
    "payload_bytes_min",
    "payload_bytes_mean",
    "payload_bytes_std",
    "payload_bytes_variance",
    "fwd_payload_bytes_max",
    "fwd_payload_bytes_min",
    "fwd_payload_bytes_mean",
    "fwd_payload_bytes_std",
    "fwd_payload_bytes_variance",
    "bwd_payload_bytes_max",
    "bwd_payload_bytes_min",
    "bwd_payload_bytes_mean",
    "bwd_payload_bytes_std",
    "bwd_payload_bytes_variance",
    "total_header_bytes",
    "max_header_bytes",
    "min_header_bytes",
    "mean_header_bytes",
    "std_header_bytes",
    "fwd_total_header_bytes",
    "fwd_max_header_bytes",
    "fwd_min_header_bytes",
    "fwd_mean_header_bytes",
    "fwd_std_header_bytes",
    "bwd_total_header_bytes",
    "bwd_max_header_bytes",
    "bwd_min_header_bytes",
    "bwd_mean_header_bytes",
    "bwd_std_header_bytes",
    "fwd_avg_segment_size",
    "bwd_avg_segment_size",
    "avg_segment_size",
    "fwd_init_win_bytes",
    "bwd_init_win_bytes",
    "active_min",
    "active_max",
    "active_mean",
    "active_std",
    "idle_min",
    "idle_max",
    "idle_mean",
    "idle_std",
    "bytes_rate",
    "fwd_bytes_rate",
    "bwd_bytes_rate",
    "packets_rate",
    "bwd_packets_rate",
    "fwd_packets_rate",
    "down_up_rate",
    "avg_fwd_bytes_per_bulk",
    "avg_fwd_packets_per_bulk",
    "avg_fwd_bulk_rate",
    "avg_bwd_bytes_per_bulk",
    "avg_bwd_packets_bulk_rate",
    "avg_bwd_bulk_rate",
    "fwd_bulk_state_count",
    "fwd_bulk_total_size",
    "fwd_bulk_per_packet",
    "fwd_bulk_duration",
    "bwd_bulk_state_count",
    "bwd_bulk_total_size",
    "bwd_bulk_per_packet",
    "bwd_bulk_duration",
    "fin_flag_counts",
    "psh_flag_counts",
    "urg_flag_counts",
    "ece_flag_counts",
    "syn_flag_counts",
    "ack_flag_counts",
    "cwr_flag_counts",
    "rst_flag_counts",
    "fwd_fin_flag_counts",
    "fwd_psh_flag_counts",
    "fwd_urg_flag_counts",
    "fwd_ece_flag_counts",
    "fwd_syn_flag_counts",
    "fwd_ack_flag_counts",
    "fwd_cwr_flag_counts",
    "fwd_rst_flag_counts",
    "bwd_fin_flag_counts",
    "bwd_psh_flag_counts",
    "bwd_urg_flag_counts",
    "bwd_ece_flag_counts",
    "bwd_syn_flag_counts",
    "bwd_ack_flag_counts",
    "bwd_cwr_flag_counts",
    "bwd_rst_flag_counts",
    "packets_IAT_mean",
    "packet_IAT_std",
    "packet_IAT_max",
    "packet_IAT_min",
    "packet_IAT_total",
    "fwd_packets_IAT_mean",
    "fwd_packets_IAT_std",
    "fwd_packets_IAT_max",
    "fwd_packets_IAT_min",
    "fwd_packets_IAT_total",
    "bwd_packets_IAT_mean",
    "bwd_packets_IAT_std",
    "bwd_packets_IAT_max",
    "bwd_packets_IAT_min",
    "bwd_packets_IAT_total",
    "subflow_fwd_packets",
    "subflow_bwd_packets",
    "subflow_fwd_bytes",
    "subflow_bwd_bytes",
]

# Identifier columns are shown in the UI and used for row identity.  They are
# never fed to either model.
IDENTIFIER_FEATURES: list[str] = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "timestamp",
    "src_port",
    "dst_port",
]

# Columns removed from ALL_FEATURES to obtain the detector input.
_DETECTOR_EXCLUDED: frozenset[str] = frozenset(
    IDENTIFIER_FEATURES
    + ["urg_flag_counts", "fwd_urg_flag_counts", "bwd_urg_flag_counts"]
)

# Columns removed from DETECTOR_FEATURES to obtain the classifier input.
_CLASSIFIER_EXCLUDED: frozenset[str] = frozenset(
    [
        "ece_flag_counts",
        "cwr_flag_counts",
        "fwd_ece_flag_counts",
        "fwd_cwr_flag_counts",
        "bwd_ece_flag_counts",
        "bwd_cwr_flag_counts",
    ]
)

DETECTOR_FEATURES: list[str] = [
    name for name in ALL_FEATURES if name not in _DETECTOR_EXCLUDED
]

CLASSIFIER_FEATURES: list[str] = [
    name for name in DETECTOR_FEATURES if name not in _CLASSIFIER_EXCLUDED
]

# Fixed inference contract.  The detector threshold is applied to P(Attack).
DETECTOR_THRESHOLD: float = 0.3545

DETECTOR_LABELS: dict[int, str] = {0: "Benign", 1: "Attack"}

CLASSIFIER_LABELS: dict[int, str] = {
    0: "DoS_Hulk",
    1: "Port_Scan",
    2: "DDoS_LOIT",
    3: "FTP-Patator",
    4: "DoS_GoldenEye",
    5: "DoS_Slowhttptest",
    6: "SSH-Patator",
    7: "Botnet_ARES",
    8: "DoS_Slowloris",
    9: "Web_Brute_Force",
    10: "Web_XSS",
    11: "Web_SQL_Injection",
    12: "Heartbleed",
}

# The only protocol values the fitted one-hot encoder knows about.  Numeric
# protocol values are mapped to these strings by features.validation.
SUPPORTED_PROTOCOLS: tuple[str, ...] = ("TCP", "UDP")

assert len(ALL_FEATURES) == 121, len(ALL_FEATURES)
assert len(DETECTOR_FEATURES) == 112, len(DETECTOR_FEATURES)
assert len(CLASSIFIER_FEATURES) == 106, len(CLASSIFIER_FEATURES)
assert DETECTOR_FEATURES[0] == "protocol"
assert DETECTOR_FEATURES[-1] == "subflow_bwd_bytes"
assert len(set(ALL_FEATURES)) == len(ALL_FEATURES)
assert set(CLASSIFIER_FEATURES).issubset(DETECTOR_FEATURES)
