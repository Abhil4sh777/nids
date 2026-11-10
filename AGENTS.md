# AGENTS.md

Guidance for coding agents working in this repo. Read fully before editing. Follow it literally; when something is unspecified, ask or leave a `TODO(open-question)` instead of guessing.

## 1. Project summary

Windows-based, near-real-time network intrusion detection with explanations.

Pipeline: live packet capture -> flow features -> **detector** (Benign vs Attack) -> if Attack, **classifier** (13 attack classes) -> SHAP + knowledge packet -> small local LLM writes an explanation -> Streamlit live table.

Stack: Python, dumpcap + Npcap (Windows), NTLFlowLyzer, XGBoost, SHAP, Ollama, Streamlit.

## 2. Repository layout

```
capture/    dumpcap wrapper, rolling pcap files
features/   NTLFlowLyzer runner, feature contract, row -> model-input builders
models/     detector.joblib, classifier.joblib, loaders, inference
explain/    SHAP, knowledge packet, evidence packet, prompt builder, LLM client
ui/         Streamlit app (live table)
tests/      unit tests + the three end-to-end test modes (section 11)
```

Put the knowledge packet data in `explain/knowledge/` (`feature_info.json`, `attacks.json`). Shared constants (feature lists, thresholds, label maps) live in ONE module: `features/contract.py`. Never duplicate them elsewhere.

## 3. Hard rules

1. **Feature order and names are a contract.** Models were trained on exact column names in exact order. Never sort, rename, drop, or reorder. Some names look inconsistent on purpose (`packets_IAT_mean` vs `packet_IAT_std`, `avg_bwd_packets_bulk_rate`). Do not "fix" them.
2. Build model input as a DataFrame with columns selected by the explicit lists in `features/contract.py`, never by position.
3. Do not retrain, re-export, or modify the `.joblib` files unless explicitly asked.
4. The detector threshold is **0.3545** applied to P(Attack). Never use `predict()` default 0.5. Define it once as `DETECTOR_THRESHOLD`.
5. The LLM only explains; it never decides. Benign/Attack and the class come from the models. Benign flows never go to the LLM.
6. Never invent attack descriptions, mitigations, or feature meanings. They come only from the knowledge packet.
7. Do not block the Streamlit UI on LLM calls (see section 9).
8. Target OS is Windows. Use `pathlib`, no bash-only commands in code or docs.

## 4. Feature contract

### 4.1 Full flow features (121), in this exact order

NTLFlowLyzer output must provide these. Store as `ALL_FEATURES` in `features/contract.py`.

```python
ALL_FEATURES = ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "duration", "packets_count", "fwd_packets_count", "bwd_packets_count", "total_payload_bytes", "fwd_total_payload_bytes", "bwd_total_payload_bytes", "payload_bytes_max", "payload_bytes_min", "payload_bytes_mean", "payload_bytes_std", "payload_bytes_variance", "fwd_payload_bytes_max", "fwd_payload_bytes_min", "fwd_payload_bytes_mean", "fwd_payload_bytes_std", "fwd_payload_bytes_variance", "bwd_payload_bytes_max", "bwd_payload_bytes_min", "bwd_payload_bytes_mean", "bwd_payload_bytes_std", "bwd_payload_bytes_variance", "total_header_bytes", "max_header_bytes", "min_header_bytes", "mean_header_bytes", "std_header_bytes", "fwd_total_header_bytes", "fwd_max_header_bytes", "fwd_min_header_bytes", "fwd_mean_header_bytes", "fwd_std_header_bytes", "bwd_total_header_bytes", "bwd_max_header_bytes", "bwd_min_header_bytes", "bwd_mean_header_bytes", "bwd_std_header_bytes", "fwd_avg_segment_size", "bwd_avg_segment_size", "avg_segment_size", "fwd_init_win_bytes", "bwd_init_win_bytes", "active_min", "active_max", "active_mean", "active_std", "idle_min", "idle_max", "idle_mean", "idle_std", "bytes_rate", "fwd_bytes_rate", "bwd_bytes_rate", "packets_rate", "bwd_packets_rate", "fwd_packets_rate", "down_up_rate", "avg_fwd_bytes_per_bulk", "avg_fwd_packets_per_bulk", "avg_fwd_bulk_rate", "avg_bwd_bytes_per_bulk", "avg_bwd_packets_bulk_rate", "avg_bwd_bulk_rate", "fwd_bulk_state_count", "fwd_bulk_total_size", "fwd_bulk_per_packet", "fwd_bulk_duration", "bwd_bulk_state_count", "bwd_bulk_total_size", "bwd_bulk_per_packet", "bwd_bulk_duration", "fin_flag_counts", "psh_flag_counts", "urg_flag_counts", "ece_flag_counts", "syn_flag_counts", "ack_flag_counts", "cwr_flag_counts", "rst_flag_counts", "fwd_fin_flag_counts", "fwd_psh_flag_counts", "fwd_urg_flag_counts", "fwd_ece_flag_counts", "fwd_syn_flag_counts", "fwd_ack_flag_counts", "fwd_cwr_flag_counts", "fwd_rst_flag_counts", "bwd_fin_flag_counts", "bwd_psh_flag_counts", "bwd_urg_flag_counts", "bwd_ece_flag_counts", "bwd_syn_flag_counts", "bwd_ack_flag_counts", "bwd_cwr_flag_counts", "bwd_rst_flag_counts", "packets_IAT_mean", "packet_IAT_std", "packet_IAT_max", "packet_IAT_min", "packet_IAT_total", "fwd_packets_IAT_mean", "fwd_packets_IAT_std", "fwd_packets_IAT_max", "fwd_packets_IAT_min", "fwd_packets_IAT_total", "bwd_packets_IAT_mean", "bwd_packets_IAT_std", "bwd_packets_IAT_max", "bwd_packets_IAT_min", "bwd_packets_IAT_total", "subflow_fwd_packets", "subflow_bwd_packets", "subflow_fwd_bytes", "subflow_bwd_bytes"]
```

### 4.2 Identifier columns (never model inputs)

```python
IDENTIFIER_FEATURES = ["flow_id", "src_ip", "dst_ip", "timestamp", "src_port", "dst_port"]
```

### 4.3 Detector input (112 features)

`DETECTOR_FEATURES` = `ALL_FEATURES` in original order, minus:
- the 6 identifier columns above
- `urg_flag_counts`, `fwd_urg_flag_counts`, `bwd_urg_flag_counts`

Starts with `protocol`, ends with `subflow_bwd_bytes`. Assert `len == 112`.

### 4.4 Classifier input (106 features)

`CLASSIFIER_FEATURES` = `DETECTOR_FEATURES` in original order, minus the six features:
`ece_flag_counts`, `cwr_flag_counts`, `fwd_ece_flag_counts`, `fwd_cwr_flag_counts`, `bwd_ece_flag_counts`, `bwd_cwr_flag_counts`.

Assert `len == 106`.

Derive both lists programmatically from `ALL_FEATURES` with the exclusion sets above, and add a test that asserts counts, order, and that `CLASSIFIER_FEATURES` is a subsequence of `DETECTOR_FEATURES`. If a loaded model exposes `feature_names_in_` or `get_booster().feature_names`, assert it equals the list at load time.

### 4.5 Label maps and threshold

```python
DETECTOR_THRESHOLD = 0.3545
DETECTOR_LABELS = {0: "Benign", 1: "Attack"}
CLASSIFIER_LABELS = {0: "DoS_Hulk", 1: "Port_Scan", 2: "DDoS_LOIT", 3: "FTP-Patator",
    4: "DoS_GoldenEye", 5: "DoS_Slowhttptest", 6: "SSH-Patator", 7: "Botnet_ARES",
    8: "DoS_Slowloris", 9: "Web_Brute_Force", 10: "Web_XSS", 11: "Web_SQL_Injection",
    12: "Heartbleed"}
```

Class strings are also the keys of `attacks.json`. They must match exactly.

### 4.6 Data hygiene

- Missing columns from NTLFlowLyzer: raise a clear error naming them. Never silently pad.
- NTLFlowLyzer column names may differ from the contract in case or spelling. Add a single mapping/validation step in `features/` and fail loudly on any mismatch.

## 5. Knowledge packet

Stored as data in `explain/knowledge/`, loaded once at startup.

- `feature_info.json`: feature name -> one-line meaning, for all 121 features.
- `attacks.json`: attack class -> `{"description": str, "mitigation": [str, str, str]}`, for all 13 classes.

Source text is the project spec; keep wording verbatim. Test that every key in `ALL_FEATURES` has a feature_info entry and every `CLASSIFIER_LABELS` value has an attack entry.

## 6. Pipeline

1. **Capture** (`capture/`): run `dumpcap` (Npcap) from Python via `subprocess`, writing a rolling set of pcap files (ring buffer by duration/size). Interface and rotation are config, not hardcoded. Handle missing Npcap/dumpcap with a clear error.
2. **Feature extraction** (`features/`): run NTLFlowLyzer on each completed pcap file; read its CSV output. Only process files dumpcap has finished writing (not the active one). Caveat: flows spanning file boundaries get split; document, do not try to fix silently.
3. **Detect**: select `DETECTOR_FEATURES`, compute `p_attack = predict_proba(X)[:, 1]`, flag Attack when `p_attack >= 0.3545`.
4. **Classify** (only flagged flows): select `CLASSIFIER_FEATURES`, take the argmax class and its probability.
5. **Explain** (only flagged flows): SHAP for both models, build the evidence packet, call the LLM.
6. **UI**: update the live table as results arrive.

Benign flows: skip steps 4-5; table shows `Benign`.

## 7. Evidence packet (per alert)

Built in `explain/`, one dict per flagged flow:

- `attack_probability`: detector P(Attack)
- `predicted_class`: classifier label
- `class_probability`: classifier probability for that label
- `description`: from `attacks.json`
- `mitigation`: list from `attacks.json`
- `detector_top5` and `classifier_top5`: each is 5 items of `{feature, meaning (from feature_info), value (the flow's raw value), shap_value}`

SHAP rules:
- Use `shap.TreeExplainer`. Build each explainer once at startup, not per flow.
- Detector: SHAP values toward the Attack class.
- Classifier: SHAP values for the **predicted class** only (handle both list-per-class and 3-D array output shapes across SHAP versions; test it).
- Top 5 = largest by absolute SHAP value; keep the sign.
- Use the same single-row DataFrame that was fed to the model.

## 8. LLM

- Model: `bartowski/Llama-3.2-1B-Instruct-GGUF`, pulled from Hugging Face into Ollama (`ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M`).
- Call through the Ollama local API (`localhost:11434`), non-streaming is fine. Low temperature (about 0.2), capped output length.
- It is a 1B model: keep the prompt short and rigidly structured, with the evidence packet as plain labeled text/JSON. Instruct it to use ONLY the evidence given, not invent facts, IPs, or CVEs, and to answer in a fixed format (e.g. Summary / Why it was flagged / Recommended actions).
- Wrap the call with a timeout and error handling. On failure, show a fallback built from the evidence packet directly (class, description, mitigation steps) so the UI never shows an empty explanation.
- Keep the prompt template in one file (`explain/prompt.py`) so it can be tuned without touching logic.

## 9. UI (Streamlit)

Live table columns: `flow_id`, `src_ip`, `dst_ip`, `timestamp`, `src_port`, `dst_port`, then a result column:
- detector says Benign -> `Benign`
- detector says Attack -> the LLM output (plus class and probabilities where useful, e.g. in an expander)

Implementation notes:
- Run capture/extraction/inference in a background thread or process; the UI reads from a thread-safe queue or store and refreshes periodically. Do not run blocking work in the Streamlit script body.
- Show rows immediately with a "pending explanation" state; fill in the LLM text when ready.
- Newest rows first, bounded history length.
- Store models/explainers via `st.cache_resource`.

## 10. Conventions

- Python 3.10+, type hints, small functions, no global mutable state outside the UI store.
- Config (interface, paths, Ollama tag, thresholds other than the fixed contract) in one config file or env vars.
- No new heavy dependencies without need; list all in `requirements.txt` with the Windows setup notes in README.
- Log with `logging`, not print.
- Do not commit pcaps, CSV outputs, or model binaries unless asked.

## 11. Testing

Unit tests (pytest, in `tests/`): feature list derivation and counts, column validation, threshold logic, label maps, knowledge packet coverage, SHAP top-5 shape for both models, evidence packet builder, prompt builder, LLM fallback path.

Three end-to-end modes; each must end with the live table updating:

1. **BCCC-CIC-IDS-2017 data**: feed pre-extracted feature rows (no capture or NTLFlowLyzer). Rows must already match the contract; validate and map columns.
2. **CIC-IDS2017 pcap**: run a pcap through NTLFlowLyzer, then the same inference path (replay the file instead of live capture).
3. **Live network**: dumpcap on a real interface, rolling files, full pipeline.

All three share the same inference/explain/UI code and differ only in the source of feature rows. Design the feature-row source as a swappable interface.

## 12. Before finishing any task

- Run the tests.
- Confirm no feature list, threshold, or label map was duplicated or altered.
- State clearly anything unverified.
