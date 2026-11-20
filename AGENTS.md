# AGENTS.md

Guidance for coding agents working in this repo. Read fully before editing. Follow it literally; when something is unspecified, ask or leave a `TODO(open-question)` instead of guessing.

## 1. Project summary

Near-real-time network intrusion detection with explanations, deployed on a **Raspberry Pi 5 (CPU only)**.

Pipeline: live packet capture -> flow features -> **detector** (Benign vs Attack) -> if Attack, **classifier** (13 attack classes) -> SHAP + knowledge packet -> small local LLM writes an explanation -> Streamlit live table.

Stack: Python, dumpcap + libpcap (Raspberry Pi OS), NTLFlowLyzer, XGBoost, SHAP, Streamlit, and an LLM behind a swappable backend interface:
- **execution backend**: ExecuTorch + Llama 3.2 1B Instruct `.pte` export (XNNPACK CPU, 8da4w quantized, arm64, **4k window**) from `experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch`

Target:

| | Deploy |
|---|---|
| OS | Raspberry Pi OS 64-bit (Trixie, Python 3.13) |
| Compute | CPU only, shared by every stage |
| LLM backend | ExecuTorch |

The repository ships exactly one runtime: the packaged Raspberry Pi appliance built and installed from `deploy/`. There is no laptop/Ollama development pipeline; `LLM_BACKEND` accepts only `executorch`, and any other value must fail at startup.

## 2. Repository layout

```
capture/    dumpcap wrapper, rolling pcap files
features/   NTLFlowLyzer runner, feature contract, row -> model-input builders
models/     detector.joblib, classifier.joblib, loaders, inference
explain/    SHAP, knowledge packet, evidence packet, prompt builder, alert grouping
explain/llm/  LLMBackend interface, executorch_backend.py
ui/         Streamlit app (live table)
deploy/     Pi installer (repository checkout), systemd unit, verify script, runner build, Pi lock
tests/      unit tests + the three end-to-end test modes + parity tests (section 11)
bench/      per-stage benchmark scripts for the Pi (section 12)
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
8. Target OS is Raspberry Pi OS 64-bit. Use `pathlib`, no Windows-specific code, and no hard-coded paths or network interface names.
9. **The rest of the pipeline never imports a specific LLM engine.** It only calls the `LLMBackend` interface (section 8). No ExecuTorch code outside `explain/llm/`.
10. **The Pi is CPU-bound and shared.** Do not add work to the hot path (per-flow) without considering cost. Models and explainers are built once at startup.
11. **Pin versions.** The complete aarch64 install set is `deploy/requirements-pi.txt`; `requirements.txt` declares the application's direct pins and a test keeps the two in step (section 10).

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

1. **Capture** (`capture/`): run `dumpcap` (libpcap) from Python via `subprocess`, writing a rolling set of pcap files (ring buffer by duration/size). Interface name, rotation, and output directory are config, not hardcoded (names differ per machine: `eth0`, `wlan0`, `enp*`, ...). Capture must work **without running Python as root**: document and use the non-root setup (dumpcap capabilities / `wireshark` group) in README. Handle missing dumpcap or missing permission with a clear error.
2. **Feature extraction** (`features/`): run NTLFlowLyzer on each completed pcap file; read its CSV output. Only process files dumpcap has finished writing (not the active one). Caveat: flows spanning file boundaries get split; document, do not try to fix silently. Delete or archive processed pcaps per config (SD cards fill up and wear out).
3. **Detect**: select `DETECTOR_FEATURES`, compute `p_attack = predict_proba(X)[:, 1]`, flag Attack when `p_attack >= 0.3545`.
4. **Classify** (only flagged flows): select `CLASSIFIER_FEATURES`, take the argmax class and its probability.
5. **Explain** (only flagged flows): SHAP for both models, build the evidence packet, group/queue alerts (section 9.1), call the LLM backend.
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

## 8. LLM backends

### 8.1 Interface

In `explain/llm/`:

```python
class LLMBackend(Protocol):
    def explain(self, evidence: dict) -> str: ...   # returns explanation text; raises on failure/timeout
    def count_prompt_tokens(self, evidence: dict) -> int: ...
```

Backend is chosen by config (`LLM_BACKEND=executorch`, the only accepted value). Pipeline, UI, and tests only use the interface. The prompt text comes from one file, `explain/prompt.py`.

### 8.2 Prompt and generation rules

- It is a 1B model: keep the prompt short and rigidly structured, with the evidence packet as plain labeled text/JSON. Instruct it to use ONLY the evidence given, not invent facts, IPs, or CVEs, and to answer in a fixed format (e.g. Summary / Why it was flagged / Recommended actions).
- Low temperature (about 0.2), capped output length.
- Wrap every call with a timeout and error handling. On failure, show a fallback built from the evidence packet directly (class, description, mitigation steps) so the UI never shows an empty explanation. This is also what happens before an ExecuTorch runner is installed.

### 8.3 ExecuTorch backend (Raspberry Pi)

Model repo: https://huggingface.co/experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch (base: `meta-llama/Llama-3.2-1B-Instruct`; license `llama3.2`, keep `LICENSE.txt`, `USE_POLICY.md`, `NOTICE` with any redistribution).

Facts from the model card (re-check the card if anything fails):
- Use the **XNNPACK (CPU)** files only, in the repo's `xnnpack/` folder. Ignore the `vulkan/`, `qnn/` and `mtk/` folders (phone GPU/NPU targets, not for the Pi).
- File names: `xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-{2k,4k,8k,16k,32k}.pte` (about 0.96-0.98 GB each). Quantization: 8-bit dynamic activations, 4-bit weights (group size 32), int8 per-channel embeddings, fp32 KV cache, prefill chunk 2048.
- Built with **ExecuTorch 1.5.1** (`export_llm`) and meant for any ExecuTorch 1.5.1 runtime. **The runtime built on the Pi must be 1.5.1.** (1.4.0 applies only to the MediaTek files; do not use it.)
- Tokenizer: `tokenizer.json` at the repo root (copied unchanged from the source Llama repo).
- Each backend folder has a `config.json` listing every window variant with the metadata the `.pte` reports, plus an `export-report-<window>.json` per file. Read the `xnnpack/config.json` for the real metadata instead of hardcoding.
- **The window is fixed inside the `.pte`.** The runtime allocates the whole KV cache at load. KV cache cost is 65,536 bytes per token: 2k = 128 MiB, **4k = 256 MiB**, 8k = 512 MiB, 16k = 1 GiB, 32k = 2 GiB (on top of about 1 GB of weights).

Requirements:
- Config values (no hardcoded paths): `EXECUTORCH_PTE_PATH`, `EXECUTORCH_TOKENIZER_PATH`, `EXECUTORCH_RUNNER_PATH`, `EXECUTORCH_WINDOW` (default 4096), `EXECUTORCH_TIMEOUT_S`. Default file: `...-8da4w-gptq-4k.pte`.
- Download with `huggingface_hub` / `hf download experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte tokenizer.json xnnpack/config.json` into a models directory outside git. Do not download the whole repo (many GB of phone-only files).
- **Default window: 4k.** The evidence packet is roughly 1,000-1,500 tokens (instructions + class info + 10 SHAP items + room for the answer); 2k is too tight, and 8k+ costs memory for space never used. Alerts are independent, so no chat history is needed. Log the real prompt token count of every alert (`count_prompt_tokens`) and refuse or shorten prompts that would overflow the window; change the window only if logs show a problem.
- **Llama 3 chat format** is required (system/user header tokens, `<|eot_id|>`). Generation must stop on the model's end-of-sequence tokens. Take the stop-token and BOS IDs from the `.pte` metadata / `xnnpack/config.json` and cross-check with Arm's list (stop: 128009, 128001, 128006, 128007; start: 128000); store them in one constants/config place. Mark `TODO(open-question)` if they disagree.
- The tokenizer is a Hugging Face `tokenizer.json`: confirm the chosen runner (ExecuTorch Llama runner) accepts it at the 1.5.1 version; do not convert or edit it.
- Integration, first version: run the ExecuTorch Llama runner as a **separate process** called from `executorch_backend.py` (subprocess with timeout, prompt via file or stdin, parse generated text only, strip echoed prompt). Switch to Python bindings only after confirming they are practical on the Pi 5.
- The XNNPACK `.pte` files are for arm64: test on the Pi itself. There is no x86 fallback runtime in this repository.
- Load the model **once** (keep the runner warm if the runner supports a server/stdin loop); a fresh process per alert would reload about 1 GB each time. If only one-shot runs are possible at first, say so in a comment and measure load time in `bench/`.
- Before wiring into the pipeline, a standalone script (`bench/llm_smoke.py`) must make the `.pte` generate one correct sentence on the Pi (the card's own smoke test is a "capital of France" question).
- Memory budget: with an 8 GB Pi, 4k fits comfortably next to XGBoost/SHAP/Streamlit; on a 4 GB Pi stay at 2k-4k and watch RAM in `bench/`.

## 9. UI (Streamlit)

Live table columns: `flow_id`, `src_ip`, `dst_ip`, `timestamp`, `src_port`, `dst_port`, then a result column:
- detector says Benign -> `Benign`
- detector says Attack -> the LLM output (plus class and probabilities where useful, e.g. in an expander)

Implementation notes:
- Run capture/extraction/inference in a background thread or process; the UI reads from a thread-safe queue or store and refreshes periodically. Do not run blocking work in the Streamlit script body.
- **Show an attack row immediately** with state "explaining...", then fill in the text when the LLM finishes (asynchronously).
- Newest rows first, bounded history length.
- Store models/explainers via `st.cache_resource`.
- UI refresh must stay light (modest interval); it competes for the same CPU.

### 9.1 Alert grouping and throttling

A DoS attack can produce hundreds of alerts; a 1B model on a Pi cannot explain them all.
- All flagged flows appear in the table (with class and probabilities).
- The LLM is called **once per group**, where group = (`predicted_class`, `src_ip`, short time window). Window length is config.
- Use a bounded queue with a single LLM worker. If the queue is full, drop to the evidence-packet fallback text and log it.
- Rows in the same group share the group's explanation.
- Benign flows never reach the queue.

## 10. Conventions

- Python 3.12+, type hints, small functions, no global mutable state outside the UI store.
- Config (interface, paths, LLM backend, model paths/tags, token window, group window, queue size, thresholds other than the fixed contract) in one config file or env vars. On the Pi that file is `/etc/nids/nids.env`, rendered from `deploy/nids.env.example`.
- **Version pinning:** `xgboost`, `scikit-learn`, `joblib`, `shap`, `numpy`, `pandas` are pinned in `requirements.txt`, and the complete aarch64 install set (with the Pi-only flow-extraction, tokenizer and Hugging Face download packages) is `deploy/requirements-pi.txt`. The Pi clones this repository and `deploy/install.sh` installs that exact file into `/opt/nids/venv`; there is no bundle or manifest step. A test fails if the shared pins drift. A model saved with one version can break or behave differently on another. Use 64-bit Raspberry Pi OS to get prebuilt arm64 wheels.
- No new heavy dependencies without need; Pi setup notes (non-root capture, NTLFlowLyzer, ExecuTorch runtime build, cooling) go in README.
- Log with `logging`, not print.
- Do not commit pcaps, CSV outputs, `.pte`/model binaries, or `tokenizer.json` unless asked. Add `models_llm/` (or the configured model dir) to `.gitignore`.

## 11. Testing

Unit tests (pytest, in `tests/`): feature list derivation and counts, column validation, threshold logic, label maps, knowledge packet coverage, SHAP top-5 shape for both models, evidence packet builder, prompt builder, alert grouping/queue behavior, backend selection from config, LLM fallback path (use a fake backend).

Three end-to-end modes; each must end with the live table updating:

1. **BCCC-CIC-IDS-2017 data**: feed pre-extracted feature rows (no capture or NTLFlowLyzer). Rows must already match the contract; validate and map columns.
2. **CIC-IDS2017 pcap**: run a pcap through NTLFlowLyzer, then the same inference path (replay the file instead of live capture).
3. **Live network**: dumpcap on a real interface, rolling files, full pipeline.

All three share the same inference/explain/UI code and differ only in the source of feature rows. Design the feature-row source as a swappable interface. Re-run all three after any platform change.

**Parity test:** the committed fixture in `tests/fixtures/` holds 100 feature rows (65 attack, 35 benign) with the detector/classifier probabilities produced by the reference machine. On the Pi, `tests/test_parity.py` asserts the detector probabilities match within a small tolerance, and that the 0.3545 threshold yields the same Benign/Attack decisions and the same classifier classes on those rows. `deploy/verify.sh` runs it after every install. Regenerate the fixture only when the `.joblib` models are intentionally replaced, from a machine whose outputs you have checked by hand.

## 12. Benchmarking on the Pi (`bench/`)

The Pi runs capture, NTLFlowLyzer, XGBoost, SHAP, the LLM, and Streamlit at once. Measure each stage separately, then together during an attack replay:

- capture -> features time
- detector time per flow
- classifier + SHAP time per alert
- LLM time to first token and tokens per second
- LLM model load time and process RSS (4k window: expect about 0.96 GB weights + 256 MiB KV cache)
- RAM use and CPU temperature during an attack replay (active cooling recommended)

Record results in `bench/RESULTS.md` with the date, window size, and git commit. Do not "optimize" without a measurement.

## 13. Before finishing any task

- Run the tests.
- Confirm no feature list, threshold, or label map was duplicated or altered.
- Confirm no LLM-engine-specific code leaked outside `explain/llm/`.
- State clearly anything unverified (especially: ExecuTorch runner and `tokenizer.json` compatibility, stop-token IDs vs `xnnpack/config.json`, ExecuTorch 1.5.1 build on the Pi, NTLFlowLyzer column names, and any behaviour that has not been exercised on real Pi hardware).