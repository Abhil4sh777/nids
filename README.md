# NIDS: near-real-time network intrusion detection, with explanations

This project watches network traffic, decides whether it looks benign or like an
attack, names the attack class, and then writes a short, plain-English
explanation of *why* it was flagged. It is built for Windows and runs entirely on
your own machine.

Here is the whole idea in one line:

```
dumpcap / CSV rows -> NTLFlowLyzer -> detector (Benign vs Attack)
    -> classifier (13 attack classes) -> SHAP evidence -> local Ollama LLM
    -> Streamlit live table
```

One important promise: **the LLM only explains.** The Benign/Attack decision and
the attack class always come from the fitted models. Benign flows never call the
LLM, so you are never paying for an explanation you do not need.

## The short version (quick start)

If you just want to see it working:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install .                 # inside the NTLFlowLyzer checkout, see step 4
ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
streamlit run app.py
```

Then pick a mode in the sidebar (CSV, pcap replay, or live capture) and press
**Start**. The sections below explain each piece in a bit more detail, plus the
Windows-specific bits that are easy to miss.

## What is in the box

```
capture/    dumpcap wrapper and rolling pcap files
features/   contract, column mapping, model inputs, NTLFlowLyzer runner, sources
models/     detector.joblib, classifier.joblib, loading and inference
explain/    knowledge packet, SHAP, evidence, prompt, Ollama client
ui/         thread-safe store, table, Streamlit app
tests/      unit tests and the three end-to-end modes
```

All three input modes share the same inference, SHAP, explanation, and table
code. Only the place the feature rows come from changes
(`features/sources.py`), so what you see in the table is identical no matter how
the data arrived.

## Setup on Windows, step by step

1. **Python 3.12 or newer** (developed and verified on 3.14). The pinned
   scikit-learn/xgboost/shap stack needs 3.12+, and the saved model artifacts were
   pickled with scikit-learn 1.9.1.
2. **Create a virtual environment and install the Python packages:**

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Install Npcap and Wireshark.** Live capture needs `dumpcap.exe`. Either add
   its folder to `PATH` or point `NIDS_DUMPCAP` at the full path, for example
   `C:\Program Files\Wireshark\dumpcap.exe`.

4. **Install NTLFlowLyzer.** It is not on PyPI as a normal dependency, so install
   it from its repository (the folder that contains its `setup.py`):

   ```powershell
   pip install -r requirements.txt   # scipy, multipledispatch, dpkt
   pip install .
   ntlflowlyzer --help
   ```

   The environment that runs the app must then have `ntlflowlyzer` on `PATH`, or
   you can set `NIDS_NTLFLOWLYZER` to the full command.

5. **Pull the local explanation model into Ollama:**

   ```powershell
   ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
   ```

   The app defaults to the local
   `hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:latest` tag, which is the same
   Q4_K_M build. Use `NIDS_OLLAMA_MODEL` if you want a different tag.

6. **Start the UI:**

   ```powershell
   streamlit run app.py
   ```

That is it. The sidebar tells you what it is doing at each step, including
whether the LLM is actually sitting on your GPU.

## Three ways to feed it data

1. **A CSV of pre-extracted features.** Upload a BCCC-format CSV in the sidebar,
   or paste a file path if the file is too large for the browser upload limit.
   Rows are validated and mapped to the 121-column contract. No capture and no
   NTLFlowLyzer needed, which makes this the fastest way to try things out.
2. **A pcap replay.** Point the sidebar at a `.pcap` file. It is run through
   NTLFlowLyzer and then follows the normal pipeline. `.pcapng` files are
   converted automatically with `editcap` (or `tshark`) when available.
3. **Live capture.** Give an interface name such as `\Device\NPF_{GUID}`.
   dumpcap writes a ring of `.pcap` files, and only completed files are
   processed, so the current file is never read while it is still being written.

## Where the work happens: CPU for detection, GPU for explanations

- **XGBoost runs on CPU only.** Both artifacts were originally trained with CUDA,
  but the loader forces `device="cpu"` on the inner classifier and booster before
  the SHAP explainers are built. Predictions are unchanged, and you do not need a
  CUDA runtime just to detect.
- **The LLM runs on GPU.** Ollama requests set `options.num_gpu` (default `999`)
  so all layers are offloaded, plus `keep_alive` so the small 1B model stays
  warm. The sidebar reads `/api/ps` and tells you whether the model really has
  VRAM allocated. After each generation the client checks again: if the model
  reports `size_vram=0`, the CPU-generated text is thrown away and the
  evidence-based fallback is shown instead. This is deliberate, so you are never
  quietly getting a slow CPU explanation that looks like a GPU one.

## Running the tests

The everyday suite is safe to run anywhere. The real-data tests skip themselves
when their assets or environment variables are missing, so a plain `pytest` will
not fail on a machine that has no captures.

```powershell
# Unit and boundary tests (95 passed, 3 skipped on a clean machine)
.\.venv\Scripts\python.exe -m pytest -q
```

Unit tests use the real model artifacts plus deterministic synthetic rows. The
end-to-end tests against real data are opt-in:

```powershell
# Mode 1: a pre-extracted BCCC-format CSV.
# NIDS_TEST_CSV_ROWS=0 runs the whole file; the default cap is 20,000 rows.
# A full file takes a while because SHAP runs for every flagged flow.
$env:NIDS_TEST_CSV = "D:\projects\bharat_ai_soc_challenge\experiment\test\BCCC.csv"
$env:NIDS_TEST_CSV_ROWS = "20000"
.\.venv\Scripts\python.exe -m pytest tests/e2e/test_mode1_csv.py -q

# Mode 2: a real capture. Give NTLFlowLyzer a generous timeout for large pcaps,
# and more threads if your machine can take it.
$env:PATH = "$PWD\.venv\Scripts;$env:PATH"   # if NTLFlowLyzer is in this venv
$env:NIDS_TEST_PCAP = "C:\Users\abhil\Downloads\Friday-WorkingHours.pcap"
$env:NIDS_NTLFLOWLYZER_TIMEOUT = "21600"
$env:NIDS_NTLFLOWLYZER_THREADS = "12"
.\.venv\Scripts\python.exe -m pytest tests/e2e/test_mode2_pcap.py -q

# Mode 3: live capture. Keep rotation short so a file completes quickly, and
# generate some traffic (browse a site, run a ping) while the test runs.
$env:PATH = "$PWD\.venv\Scripts;$env:PATH"
$env:NIDS_TEST_LIVE = "1"
$env:NIDS_TEST_LIVE_SECONDS = "120"
$env:NIDS_INTERFACE = "\Device\NPF_{GUID}"
$env:NIDS_DUMPCAP = "C:\Program Files\Wireshark\dumpcap.exe"
$env:NIDS_PCAP_ROTATION = "5"
$env:NIDS_PCAP_STABLE = "1"
.\.venv\Scripts\python.exe -m pytest tests/e2e/test_mode3_live.py -q
```

For very large or attack-dense captures, it helps to cut out a bounded window
with Wireshark's `editcap` and point `NIDS_TEST_PCAP` at that. The test computes
SHAP for every flagged flow, so a whole multi-hour flood capture is not a good
single batch:

```powershell
editcap -F pcap -A "2017-07-08 00:36:00" -B "2017-07-08 00:37:00" `
  capture.pcap capture_1min.pcap
```

Test captures can live under `capture/testdata/`. `.gitignore` excludes
`*.pcap`/`*.pcapng`, so they never end up in a commit.

## Configuration

Everything tunable lives in `config.py` and can be overridden with environment
variables. The model contract does not: the detector threshold (`0.3545`), the
feature lists, and the label maps are fixed in `features/contract.py` and are
never read from configuration.

| Variable | Meaning |
| --- | --- |
| `NIDS_ROOT` | Project root for the default paths below |
| `NIDS_INTERFACE` | Live capture interface |
| `NIDS_CAPTURE_FILTER` | Optional dumpcap capture filter (default: none) |
| `NIDS_DUMPCAP` | Full path to `dumpcap.exe` |
| `NIDS_EDITCAP` | Full path to `editcap.exe` (pcapng conversion) |
| `NIDS_TSHARK` | Full path to `tshark.exe` (fallback pcapng converter) |
| `NIDS_CAPTURE_DIR` | Rolling pcap directory (default `capture/pcaps`) |
| `NIDS_OUTPUT_DIR` | NTLFlowLyzer CSV/config output (default `capture/flows`) |
| `NIDS_PCAP_ROTATION` | Seconds per rolling file (default 60) |
| `NIDS_PCAP_RING` | Number of rolling files (default 10) |
| `NIDS_PCAP_STABLE` | Seconds a file must be untouched before capture |
| `NIDS_CAPTURE_POLL` | Seconds between checks for completed files (default 2) |
| `NIDS_NTLFLOWLYZER` | NTLFlowLyzer command (default `ntlflowlyzer`) |
| `NIDS_NTLFLOWLYZER_TIMEOUT` | Extraction timeout in seconds (default 300) |
| `NIDS_NTLFLOWLYZER_THREADS` | Extractor processes (default 4; more helps big pcaps) |
| `NIDS_NTLFLOWLYZER_ACTIVITY_TIMEOUT` | Flow activity timeout (default 60) |
| `NIDS_NTLFLOWLYZER_MAX_FLOW_DURATION` | Max flow duration (default 600) |
| `NIDS_MODEL_DIR` | Directory containing the two `.joblib` models |
| `NIDS_KNOWLEDGE_DIR` | Directory containing `feature_info.json` and `attacks.json` |
| `NIDS_OLLAMA_URL` | Ollama base URL (default `http://localhost:11434`) |
| `NIDS_OLLAMA_MODEL` | Ollama model tag |
| `NIDS_OLLAMA_TIMEOUT` | Request timeout in seconds (default 120) |
| `NIDS_OLLAMA_NUM_GPU` | Layers to offload; default `999` means all |
| `NIDS_OLLAMA_KEEP_ALIVE` | Ollama keep-alive (default `30m`) |
| `NIDS_OLLAMA_NUM_CTX` | Context window (default 2048) |
| `NIDS_OLLAMA_NUM_PREDICT` | Max generated tokens (default 220) |
| `NIDS_OLLAMA_TEMPERATURE` | Sampling temperature (default 0.2) |
| `NIDS_HISTORY_LIMIT` | Rows kept in the live table (default 500) |
| `NIDS_UI_REFRESH` | Table refresh interval in seconds (default 2) |
| `NIDS_XGB_DEVICE` | Must remain `cpu`; other values are rejected |

## Things worth knowing

- **The feature contract is the law.** Feature names and order are fixed. The
  validator (`features/validation.py`) smooths over case, spacing, and
  snake/camel differences, then fails loudly on missing or ambiguous columns.
  Extra columns from a source file (a dataset label, for example) are dropped
  with a warning rather than silently fed to the model.
- **Protocols are limited on purpose.** The fitted one-hot encoder only knows
  `TCP` and `UDP`. Numeric `6`/`17` are mapped to those names; anything else is
  rejected instead of guessed.
- **Flows that cross a rolling-file boundary get split.** Each file is processed
  independently. This is documented behavior rather than something the pipeline
  quietly tries to stitch back together.
- **File format is detected from the content, not the extension.** Some
  CIC-IDS2017 files are named `.pcap` but actually contain pcapng. Those are
  converted with `editcap` (or `tshark`) before NTLFlowLyzer sees them. Live
  capture writes classic pcap directly, so live files need no conversion.
- **NTLFlowLyzer output is much wider than the contract.** It emits roughly 347
  columns; only the 121 contract columns are kept. Its
  `<dir>_segment_size_mean` names are mapped to the contract's
  `fwd_avg_segment_size` / `bwd_avg_segment_size` / `avg_segment_size`.
- **SHAP explains the model, not the pipeline wrapper.** `TreeExplainer` runs
  against the inner XGBoost classifier. Detector attributions point toward the
  Attack class; classifier attributions are for the predicted class only.
- **Explanations are grounded.** The LLM writes the short Summary. The "Why it
  was flagged" and "Recommended actions" sections are rebuilt from the evidence
  packet and `attacks.json`, so a 1B model cannot invent a mitigation, a feature
  meaning, an IP, or a CVE, and cannot claim a defense is already deployed. The
  full SHAP evidence stays visible in the attack detail panel.
- **The UI never blocks on the LLM.** Capture, extraction, and inference run in a
  background worker. An attack row appears immediately as
  `pending explanation` and fills in when the text is ready. Newest rows come
  first, and history is bounded.

## If something does not work

- **`dumpcap` is not found.** Set `NIDS_DUMPCAP` to the full path and make sure
  Npcap is installed. The app reports the missing tool rather than failing
  silently.
- **`ntlflowlyzer` is not found.** Activate the environment where you installed
  it, or set `NIDS_NTLFLOWLYZER` to the full command.
- **Extraction times out on a big capture.** Raise
  `NIDS_NTLFLOWLYZER_TIMEOUT` and `NIDS_NTLFLOWLYZER_THREADS`.
- **Ollama is not running.** The row still gets a usable explanation built
  directly from the evidence packet, and the sidebar shows the error. You are
  never left with an empty explanation.
- **The LLM says it is on CPU.** The sidebar reads `/api/ps`; a `size_vram` of
  something like 936 MB means the 1B model is on the GPU as intended.

## What has actually been verified

Verified on Windows with Python 3.14.4, real Npcap/dumpcap, NTLFlowLyzer, and the
installed Q4_K_M Ollama model:

- **Unit/boundary suite:** 95 passed, 3 skipped when no real-data environment
  variables are set.
- **Mode 1 (real BCCC CSV):** the 20,000-row sample and the full 365,708-row
  export both passed through detector, classifier, SHAP, stub LLM, and the table.
  The full run took about 15 minutes and produced 12,109 detector attacks.
- **Mode 2 (real Friday capture):**
  - First 1,000,000 packets: 5,551 flows, 23 attacks (`DoS_Hulk`,
    `DoS_Slowhttptest`, `DDoS_LOIT`, `DoS_Slowloris`, `SSH-Patator`); passed in
    about 4 minutes with 12 extractor threads.
  - One-minute attack window (`2017-07-08 00:36`): 5,631 flows, 5,443 attacks
    (`DDoS_LOIT`, `Port_Scan`, `Botnet_ARES`, `DoS_GoldenEye`); passed in about
    11 minutes.
  - The complete 8.8 GB file was also extracted: 452,518 flows in about 40
    minutes with 12 threads, and the detector flags 274,751 of them. Running
    per-flow SHAP for every attack in one synchronous batch would take several
    hours, so the end-to-end test stays bounded to the slices above instead of
    holding the whole file in a single batch.
- **Mode 3 (live capture):** dumpcap/Npcap wrote rolling Wi-Fi files,
  NTLFlowLyzer extracted flows, and the pipeline reached the table; attack rows
  received explanations.
- **LLM:** real BCCC attack rows were explained by Ollama with `source="llm"`,
  and `/api/ps` reported `size_vram=936,189,623`, confirming GPU inference.
- **UI:** Streamlit `AppTest` loaded the app with no exceptions.

The external test assets are path-driven on purpose: the BCCC CSV and the real
captures stay outside the repository and are selected with `NIDS_TEST_CSV` /
`NIDS_TEST_PCAP`. Large intermediates land in `capture/flows/`, which git
ignores, so it is always safe to delete that folder when you want the disk space
back.
