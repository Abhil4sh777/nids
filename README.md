# NIDS: near-real-time network intrusion detection with explanations

Windows-first pipeline:

```
dumpcap / CSV rows -> NTLFlowLyzer -> detector (Benign vs Attack)
    -> classifier (13 attack classes) -> SHAP evidence -> local Ollama LLM
    -> Streamlit live table
```

The LLM only explains. Benign/Attack and the attack class always come from the
fitted models. Benign flows never call the LLM.

## Repository layout

```
capture/    dumpcap wrapper and rolling pcap files
features/   contract, column mapping, model inputs, NTLFlowLyzer runner, sources
models/     detector.joblib, classifier.joblib, loading and inference
explain/    knowledge packet, SHAP, evidence, prompt, Ollama client
ui/         thread-safe store, table, Streamlit app
tests/      unit tests and the three end-to-end modes
```

## Setup (Windows)

1. Install Python 3.12 or newer (tested with 3.14). The pinned
   scikit-learn/xgboost/shap stack requires 3.12+, and the artifacts were
   pickled with scikit-learn 1.9.1.
2. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Install Npcap and Wireshark. Confirm `dumpcap.exe` exists, then either add
   it to `PATH` or set `NIDS_DUMPCAP` to its full path.

4. Install NTLFlowLyzer from its repository (it is not on PyPI as a normal
   dependency). In the NTLFlowLyzer repository:

   ```powershell
   pip install .
   ntlflowlyzer --version
   ```

5. Pull the local explanation model:

   ```powershell
   ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
   ```

   The UI defaults to the locally installed
   `hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest` tag, which is the same
   Q4_K_M build. Override with `NIDS_OLLAMA_MODEL` if needed.

6. Start the UI:

   ```powershell
   streamlit run app.py
   ```

## Inference placement

- **XGBoost: CPU only.** Both artifacts were trained with CUDA, but the loader
  forces `device="cpu"` on the inner classifier and booster before building
  SHAP explainers. Predictions are unchanged; this avoids depending on a CUDA
  runtime for detection.
- **LLM: GPU.** Ollama requests use `options.num_gpu` (default `999`) to offload
  all layers, plus `keep_alive` so the 1B model stays resident. The sidebar
  reads `/api/ps` and reports whether the model is actually using VRAM. After
  each generation the client checks `/api/ps` again: if the model reports
  `size_vram=0`, the CPU-generated text is discarded and the evidence-based
  fallback is used. If GPU loading or the Ollama call fails, the row receives
  that fallback; the failure is surfaced in the UI rather than silently using a
  CPU LLM.

## Three end-to-end modes

All modes share the same inference, SHAP, explanation, and table code. They
differ only in the feature-row source (`features/sources.py`).

1. **CSV (pre-extracted rows)** — upload a BCCC-format CSV in the sidebar.
   Rows are validated/mapped to the 121-column contract. No capture or
   NTLFlowLyzer is used.
2. **PCAP replay** — give a `.pcap` path in the sidebar. The file is run through
   NTLFlowLyzer, then the normal pipeline. `.pcapng` is converted with
   `editcap`/`tshark` when available.
3. **Live capture** — give an interface name (for example
   `\Device\NPF_{GUID}`). dumpcap writes a ring of `.pcap` files; only completed
   files are processed. NTLFlowLyzer runs per file.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Unit tests use the real artifacts and a deterministic synthetic attack row.
Mode 1 is exercised end-to-end with a temporary CSV. Modes 2 and 3 skip cleanly
unless their external assets are present:

```powershell
$env:NIDS_TEST_PCAP = "C:\captures\test.pcap"   # mode 2
$env:NIDS_TEST_LIVE = "1"                       # mode 3
$env:NIDS_INTERFACE = "\Device\NPF_{GUID}"
```

## Configuration

All non-contract settings are in `config.py` and can be overridden by
environment variables:

| Variable | Meaning |
| --- | --- |
| `NIDS_INTERFACE` | Live capture interface |
| `NIDS_DUMPCAP` | Full path to `dumpcap.exe` |
| `NIDS_CAPTURE_DIR` | Rolling pcap directory |
| `NIDS_OUTPUT_DIR` | NTLFlowLyzer CSV/config output directory |
| `NIDS_PCAP_ROTATION` | Seconds per rolling file (default 60) |
| `NIDS_PCAP_RING` | Number of rolling files (default 10) |
| `NIDS_NTLFLOWLYZER` | NTLFlowLyzer command (default `ntlflowlyzer`) |
| `NIDS_OLLAMA_URL` | Ollama base URL (default `http://localhost:11434`) |
| `NIDS_OLLAMA_MODEL` | Ollama model tag |
| `NIDS_OLLAMA_NUM_GPU` | Layers to offload; default `999` |
| `NIDS_OLLAMA_KEEP_ALIVE` | Ollama keep-alive, default `30m` |
| `NIDS_XGB_DEVICE` | Must remain `cpu`; other values are rejected |

The detector threshold (`0.3545`), feature lists, and label maps are fixed in
`features/contract.py` and are never read from configuration.

## Design notes and caveats

- Feature names and order are a contract. `features/validation.py` maps case,
  spacing, and snake/camel variants, then fails loudly on missing or ambiguous
  columns. Extra source columns (for example a dataset label) are dropped with
  a warning.
- The fitted one-hot encoder knows only `TCP` and `UDP`. Numeric `6`/`17` are
  mapped to those strings; other protocols are rejected.
- Flows that span a rolling-file boundary are split. The pipeline processes
  each file independently; this is documented rather than silently stitched.
- NTLFlowLyzer outputs 348 columns; only the 121 contract columns are selected.
- SHAP uses `TreeExplainer` against the inner XGBoost classifier, not the whole
  pipeline. Detector attributions are toward the Attack class; classifier
  attributions are for the predicted class only.
- The LLM supplies a short Summary.  The "Why it was flagged" and
  "Recommended actions" sections are rebuilt from the evidence packet and
  `attacks.json`, so a 1B model cannot invent mitigations, feature meanings, or
  claim that a defense is already deployed.  The full SHAP evidence remains
  visible in the attack detail panel.
- The live table updates on a fixed interval and shows an attack row as
  `pending explanation` until the worker fills in the LLM text. Blocking work
  never runs in the Streamlit script body.

## Unverified in this checkout

- No BCCC CSV was supplied, so mode 1 was verified with synthetic rows that
  satisfy the contract rather than a real BCCC export.
- `dumpcap`/Npcap and NTLFlowLyzer are not installed in this environment, so
  modes 2 and 3 are implemented and unit-tested around their boundaries but
  were not executed against real captures.
- Ollama GPU offload was verified locally (`/api/ps` reported VRAM usage) with
  the installed Q4_K_M model.
