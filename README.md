# NIDS: a network intrusion detector that explains itself

This program watches network traffic, decides whether it looks normal or like an
attack, names the type of attack, and writes a short, plain-English explanation
of *why* it was flagged.

You don't need to be a network engineer or a machine-learning expert to run it.
This page starts with the simplest possible path (try it on a CSV file, no
network access needed) and adds the harder setups (real packet capture, the
Raspberry Pi) only after that works.

## Contents

- [What it actually does](#what-it-actually-does)
- [What you need](#what-you-need)
- [Quick start on a laptop (about 10 minutes)](#quick-start-on-a-laptop-about-10-minutes)
- [Using the app](#using-the-app)
- [Running it on a Raspberry Pi 5](#running-it-on-a-raspberry-pi-5)
- [When something goes wrong](#when-something-goes-wrong)
- [How it works, in plain terms](#how-it-works-in-plain-terms)
- [All settings (reference)](#all-settings-reference)
- [Tests and benchmarks (reference)](#tests-and-benchmarks-reference)
- [What is verified, and what is not](#what-is-verified-and-what-is-not)

## What it actually does

Every few seconds the app looks at the recent traffic, groups packets into
"flows" (one conversation between two computers), and asks two trained models
two questions:

1. **Is this normal or an attack?** (the *detector*)
2. **If it is an attack, which of the 13 known types is it?** (the *classifier*)

For anything flagged as an attack it then works out which flow measurements
pushed the decision over the line (using a technique called SHAP), and asks a
small local AI model to turn those numbers into a few sentences you can read.

One important promise: **the AI only explains, it never decides.** The
normal/attack call and the attack type always come from the trained models. The
AI cannot invent a new verdict, and normal traffic never reaches it.

The whole journey looks like this:

```
packets (live or a saved file)  ->  flow measurements
    ->  detector: normal or attack?
    ->  classifier: which attack type?
    ->  evidence: the measurements that mattered
    ->  local AI model: a short explanation
    ->  a live table in your browser
```

## What you need

| Piece | Needed for | Notes |
| --- | --- | --- |
| Linux (laptop) or 64-bit Raspberry Pi OS | everything | Windows/macOS are not supported |
| Python 3.12 or newer | everything | the pinned libraries require it |
| The project's Python packages | everything | one `pip install` step below |
| Ollama + a small Llama model | explanations on the laptop | free, runs on the CPU |
| NTLFlowLyzer | reading `.pcap` files, live capture | a separate tool you install once |
| `dumpcap` (from Wireshark) | live capture only | Python never runs as root |
| ExecuTorch runtime | explanations on the Pi | only for deployment |

If you only want to see the thing work, you can skip Ollama, NTLFlowLyzer, and
`dumpcap` entirely and use a CSV - the app still explains attacks, it just uses
a built-in fallback text instead of the AI model.

## Quick start on a laptop (about 10 minutes)

Open a terminal in this project folder and run the steps in order. Each step
says what you should see, so you know whether it worked before moving on.

**1. Create a Python environment and install the packages**

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

You should see `Successfully installed ...` at the end. You need to run
`. .venv/bin/activate` in every new terminal window; that is what makes
`python` and `streamlit` refer to this project's environment.

**2. (Optional) Install the packet-to-flow tool**

Skip this if you are only going to try CSV files.

```bash
pip install dpkt multipledispatch    # NTLFlowLyzer's only dependencies
pip install .                        # run this inside the NTLFlowLyzer folder
ntlflowlyzer --help
```

`pip install .` must be run from the folder of the NTLFlowLyzer project, not
from this one. If you would rather not install it, point the app at the folder
you downloaded instead:

```bash
export NIDS_NTLFLOWLYZER=/path/to/NTLFlowLyzer
```

**3. (Optional) Install the local AI model**

Skip this and attacks will still get a sensible fallback explanation, but not
the AI-written one.

```bash
ollama pull hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
```

Ollama must be running (usually it is, after installing it; `ollama serve`
starts it by hand). The model is small - about 1 GB - and runs on the CPU.

**4. Start the app**

```bash
streamlit run app.py
```

Your browser opens a page with a sidebar. That is the app. Leave this terminal
open; closing it stops everything.

## Using the app

Pick one of three ways to feed it data in the sidebar, then press **Start**.

| Mode in the sidebar | What it does | What you need | Best for |
| --- | --- | --- | --- |
| **CSV (pre-extracted)** | Reads rows that were already turned into flow measurements | a BCCC-format `.csv` | trying it out, demos |
| **PCAP replay** | Reads a saved packet capture and processes it like live traffic | NTLFlowLyzer | checking a known attack file |
| **Live capture** | Watches a real network interface right now | `dumpcap` + permissions | the real thing |

Notes on each:

- **CSV (pre-extracted).** Upload it in the sidebar, or paste a path if it is
  too big for the browser upload. The columns are checked against what the
  models expect; a wrong or missing column produces a clear error instead of a
  wrong prediction.
- **PCAP replay.** Point the sidebar at a `.pcap` file. Files that are really
  pcapng (some CIC-IDS2017 downloads are) are converted automatically. A large
  file takes a while - the extractor is the slow part.
- **Live capture.** Type the interface name, e.g. `eth0`, `wlan0`, `enp3s0`, or
  `end0` on a Pi (find it with `ip link`). The app writes short rotating capture
  files and only processes ones that are finished, so it never reads a file
  that is still being written. Finished captures are deleted by default to
  spare the SD card; `NIDS_PCAP_AFTER_PROCESS` can archive or keep them instead.

### Reading the table

Above the table, four counters tell you what is happening at a glance: the
source you picked, how many flows have been processed, how many were attacks,
and whether it is running. If something fails, an error appears there in red
instead of silently stopping.

Newest rows appear at the top. You get the flow's addresses and ports, then:

- **result** - `Benign` for normal traffic (the AI is never called), or the
  explanation text for an attack. An attack row appears immediately and says
  `explaining...` until the AI finishes, so a slow model never freezes the
  table.
- **P(Attack)** - the detector's confidence that this flow is an attack, from 0
  to 1. Anything at or above 0.3545 is treated as an attack.
- **predicted_class / P(Class)** - the attack type and how confident the
  classifier is. Empty for normal traffic.

Below the table, the **Attack detail** selector shows one flagged flow at a
time: the explanation, both confidences, and the five flow measurements that
pushed each model, with their values and how much each one mattered.

### Why a flood of alerts is fine

A single denial-of-service attack can produce hundreds of flagged flows. A
small AI model cannot write hundreds of explanations in real time, so the app
explains **once per group** - same attack type, same source address, same short
time window - and every row in that group shares the explanation. If too many
groups arrive at once, extra ones get the fallback text and a log line; nothing
blocks. Normal traffic never enters that queue.

## Running it on a Raspberry Pi 5

The laptop version uses Ollama for explanations. The Pi uses ExecuTorch, a
lighter runtime that runs a pre-packaged Llama 3.2 1B model on the CPU. The
detection, attack classification, and explanation logic are identical - only
the piece that writes sentences changes.

Start with **64-bit Raspberry Pi OS**, and an 8 GB Pi is comfortable. Active
cooling is strongly recommended: capture, extraction, both models, the AI, and
the dashboard all share the CPU.

**1. System packages and Python environment**

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip wireshark-common tshark libpcap0.8
python3 -m venv ~/nids-venv
. ~/nids-venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**2. Let your user capture packets without root**

Live capture runs `dumpcap` as you, never as root. During
`apt install wireshark-common` you are asked whether non-superusers may capture
packets - answer **Yes**. Then either join the `wireshark` group (log out and
back in afterwards):

```bash
sudo usermod -aG wireshark "$USER"
```

or give `dumpcap` the two permissions it needs:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
```

If this is missing, `dumpcap` exits instantly and the app shows you its log
instead of failing silently.

**3. Install NTLFlowLyzer**

```bash
pip install dpkt multipledispatch
cd /path/to/NTLFlowLyzer && pip install .
```

Or skip the install and point the app at the checkout folder:

```bash
export NIDS_NTLFLOWLYZER=$HOME/NTLFlowLyzer
```

The app finds the command on `PATH`, next to the running Python (so activating
the environment is optional), or as `python -m NTLFlowLyzer`.

**4. Build the ExecuTorch 1.5.1 runtime**

The model file was exported with ExecuTorch **1.5.1** and needs a 1.5.1 runtime
with the XNNPACK (CPU) backend. Do not use 1.4.0 - that version is only for the
phone-target files. Then tell the app where the runner is:

```bash
export EXECUTORCH_RUNNER_PATH=/opt/executorch/build/executorch_llama_runner
```

The app calls the runner as a separate program, sending the prompt on its
standard input and reading the answer from its output. If your runner takes
different arguments, set `EXECUTORCH_RUNNER_PATH` to a template containing
`{pte}`, `{tokenizer}`, and `{window}`. This exact command line is **not yet
verified on a Pi** (see the last section).

**5. Download the model files**

These live outside git. Pick a folder, e.g. `~/models_llm`:

```bash
pip install huggingface_hub
export NIDS_MODELS_LLM_DIR="$HOME/models_llm"
hf download experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch \
  xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte \
  tokenizer.json \
  xnnpack/config.json \
  --local-dir "$NIDS_MODELS_LLM_DIR"
```

Download only those files - the repository also holds `vulkan/`, `qnn/`, and
`mtk/` versions for phones, which are several gigabytes and useless here. If
you redistribute the model, keep `LICENSE.txt`, `USE_POLICY.md`, and `NOTICE`
with it (the licence is `llama3.2`).

**6. Switch the app to ExecuTorch and check it**

```bash
export LLM_BACKEND=executorch
export EXECUTORCH_WINDOW=4096
export EXECUTORCH_TIMEOUT_S=180
python -m bench.llm_smoke
```

That last command should print a correct answer to a simple test question
("what is the capital of France?"). Do not trust the AI in the dashboard until
it does.

**7. Start the app** exactly as on the laptop: `streamlit run app.py`.

### Why 4k and not 8k or 2k

The conversation window is fixed inside the model file, and the runtime
reserves memory for the whole window when it loads:

| Window | Memory for the conversation | Model weights |
| --- | --- | --- |
| 2k | 128 MiB | about 1 GB |
| **4k (default)** | **256 MiB** | **about 1 GB** |
| 8k | 512 MiB | about 1 GB |
| 16k | 1 GiB | about 1 GB |
| 32k | 2 GiB | about 1 GB |

One alert uses roughly 1,000-1,500 tokens, so 2k is tight and 8k+ wastes memory
the Pi does not have. 4k fits next to everything else on an 8 GB Pi; on a 4 GB
Pi stay at 2k-4k and watch memory during a test run.

## When something goes wrong

Most problems are one of the rows below. The app tries to tell you which.

| What you see | What it means | Fix |
| --- | --- | --- |
| `dumpcap` is not found | Wireshark's capture tool is missing | `sudo apt install wireshark-common tshark`, or set `NIDS_DUMPCAP` |
| `dumpcap` exits immediately | wrong interface name, or you lack capture permission | check `ip link`; use the `wireshark` group or `setcap` step |
| `unrecognized option: F` in the log | your `dumpcap` is older than Wireshark 4.0 | usually nothing - the app already picks the right flag; upgrade only if it persists |
| `ntlflowlyzer` is not found | the extractor is not installed in this environment | `pip install dpkt multipledispatch`, then `pip install .` inside NTLFlowLyzer, or set `NIDS_NTLFLOWLYZER` |
| `NIDS_NTLFLOWLYZER` ... `Permission denied` | you pointed it at the wrong kind of folder | point it at the cloned NTLFlowLyzer folder (the one containing `setup.py`) or at the installed executable |
| extraction times out on a big capture | the extractor is slow by nature | raise `NIDS_NTLFLOWLYZER_TIMEOUT`; raise threads only if the machine has headroom |
| the sidebar's LLM panel shows a warning | Ollama is not running, or the model is missing | start Ollama (`ollama serve`); attacks still get fallback explanations |
| explanation says `404 ... /api/generate` | the model tag is not installed | `ollama pull` the tag from step 3, or set `NIDS_OLLAMA_MODEL` to a tag from `ollama list` (Ollama treats `model` and `model:latest` as different models) |
| ExecuTorch "not ready" | the `.pte`, `tokenizer.json`, or runner path is wrong | the status line names the missing piece; run `python -m bench.llm_smoke` |
| rows show fallback text and the log says the queue is full | a flood of alerts, by design | normal; increase `NIDS_ALERT_QUEUE_SIZE` or the grouping window if the machine has headroom |

## How it works, in plain terms

You can skip this if you only want to run it, but it explains the design
choices you will notice.

- **Traffic becomes "flows".** A flow is one conversation between two machines
  (same addresses, ports, and protocol). Instead of reasoning about individual
  packets, the models look at about a hundred measurements per flow: sizes,
  timing, flags, and so on.
- **The detector decides normal vs attack.** It outputs a probability, and the
  app uses a fixed cut-off of **0.3545** rather than the usual 0.5. That number
  came from training and is not a dial to play with.
- **The classifier names the attack.** Only flows the detector flags are
  classified, into one of 13 types such as `DoS_Hulk` or `Port_Scan`.
- **The measurements are a contract.** The models were trained with exact
  column names in an exact order. The app checks incoming data against that
  list and refuses to guess: missing or ambiguous columns produce an error, and
  unrelated extra columns are dropped with a warning.
- **SHAP shows the reasoning.** For each flagged flow, the app computes which
  five measurements mattered most and in which direction. That evidence is the
  only material the AI is allowed to use.
- **The AI writes words, not verdicts.** It produces a short summary; the "why
  it was flagged" and "recommended actions" text is assembled from the
  evidence and a fixed attack reference file, so a small model cannot invent a
  mitigation, an IP address, or a vulnerability number.
- **Everything runs on the CPU.** There is no GPU use anywhere, because the
  target is a Raspberry Pi. This is deliberate, not a limitation to fix.
- **Only TCP and UDP are understood.** The models were trained with those two
  protocols; numeric `6` and `17` are translated, and anything else is
  rejected. This is a training-data limit, not a missing switch.
- **A conversation split across two capture files stays split.** Each finished
  file is processed independently, so a flow that was mid-conversation when the
  file rotated is seen as two flows. That is known and documented; the pipeline
  does not quietly try to stitch them back together.

## All settings (reference)

Defaults live in `config.py` and every one can be overridden with an
environment variable. The detection contract does not move with them: the
0.3545 cut-off, the feature lists, and the attack names are fixed in
`features/contract.py`.

<details>
<summary>Show the project layout</summary>

```
capture/     dumpcap wrapper, rolling capture files, cleanup after processing
features/    feature contract, column mapping, model inputs, NTLFlowLyzer runner
models/      detector.joblib, classifier.joblib, loading and CPU inference
explain/     attack reference, SHAP, evidence, alert grouping, prompt
explain/llm/ the AI backends: ollama_backend.py, executorch_backend.py
ui/          thread-safe store, table, Streamlit app
tests/       unit tests, the three end-to-end modes, laptop-vs-Pi parity
bench/       per-stage benchmarks, ExecuTorch smoke test, parity exporter
```

All three input modes share the same detection, explanation, and table code.
Only the source of the feature rows changes (`features/sources.py`).

</details>

<details>
<summary>Show the full list of environment variables</summary>

| Variable | Meaning |
| --- | --- |
| `LLM_BACKEND` | `ollama` (default, laptop) or `executorch` (Pi) |
| `NIDS_ROOT` | Project root for the default paths below |
| `NIDS_INTERFACE` | Live capture interface (`eth0`, `wlan0`, ...) |
| `NIDS_CAPTURE_FILTER` | Optional dumpcap capture filter (default: none) |
| `NIDS_DUMPCAP` | Full path to `dumpcap` |
| `NIDS_EDITCAP` | Full path to `editcap` (pcapng conversion) |
| `NIDS_TSHARK` | Full path to `tshark` (fallback pcapng converter) |
| `NIDS_CAPTURE_DIR` | Rolling pcap directory (default `capture/pcaps`) |
| `NIDS_OUTPUT_DIR` | NTLFlowLyzer CSV/config output (default `capture/flows`) |
| `NIDS_PCAP_ROTATION` | Seconds per rolling file (default 60) |
| `NIDS_PCAP_RING` | Number of rolling files (default 10) |
| `NIDS_PCAP_STABLE` | Seconds a file must be untouched before processing |
| `NIDS_CAPTURE_POLL` | Seconds between checks for completed files (default 2) |
| `NIDS_PCAP_AFTER_PROCESS` | `delete` (default), `archive`, or `keep` |
| `NIDS_PCAP_ARCHIVE_DIR` | Destination for `archive` (default `capture/archive`) |
| `NIDS_NTLFLOWLYZER` | NTLFlowLyzer command, executable path, or repository folder (default `ntlflowlyzer`) |
| `NIDS_NTLFLOWLYZER_TIMEOUT` | Extraction timeout in seconds (default 300) |
| `NIDS_NTLFLOWLYZER_THREADS` | Extractor processes (default 4) |
| `NIDS_NTLFLOWLYZER_ACTIVITY_TIMEOUT` | Flow activity timeout (default 60) |
| `NIDS_NTLFLOWLYZER_MAX_FLOW_DURATION` | Max flow duration (default 600) |
| `NIDS_MODEL_DIR` | Directory containing the two `.joblib` models |
| `NIDS_KNOWLEDGE_DIR` | Directory containing `feature_info.json` and `attacks.json` |
| `NIDS_MODELS_LLM_DIR` | Base directory for `.pte` and `tokenizer.json` |
| `NIDS_OLLAMA_URL` | Ollama base URL (default `http://localhost:11434`) |
| `NIDS_OLLAMA_MODEL` | Ollama model tag (default `hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M`) |
| `NIDS_OLLAMA_TIMEOUT` | Request timeout in seconds (default 120) |
| `NIDS_OLLAMA_KEEP_ALIVE` | Ollama keep-alive (default `30m`) |
| `NIDS_OLLAMA_NUM_CTX` | Context window (default 4096) |
| `NIDS_OLLAMA_NUM_PREDICT` | Max generated tokens (default 220) |
| `NIDS_OLLAMA_TEMPERATURE` | Sampling temperature (default 0.2) |
| `EXECUTORCH_PTE_PATH` | Path to the 4k `.pte` (default under `models_llm/`) |
| `EXECUTORCH_TOKENIZER_PATH` | Path to `tokenizer.json` |
| `EXECUTORCH_RUNNER_PATH` | Runner command or `{pte}`/`{tokenizer}`/`{window}` template |
| `EXECUTORCH_WINDOW` | Fixed window of the `.pte` (default 4096) |
| `EXECUTORCH_TIMEOUT_S` | Runner timeout in seconds (default 180) |
| `EXECUTORCH_RESERVED_OUTPUT_TOKENS` | Window space kept for the answer (default 256) |
| `NIDS_ALERT_GROUP_WINDOW` | Alert group window in seconds (default 60) |
| `NIDS_ALERT_QUEUE_SIZE` | Bounded LLM queue length (default 64) |
| `NIDS_HISTORY_LIMIT` | Rows kept in the live table (default 500) |
| `NIDS_UI_REFRESH` | Table refresh interval in seconds (default 2) |
| `NIDS_XGB_DEVICE` | Must remain `cpu`; other values are rejected |

`NIDS_`-prefixed aliases for the bare `LLM_BACKEND`/`EXECUTORCH_*` names are also
accepted.

</details>

## Tests and benchmarks (reference)

The everyday suite needs no captures, no network, and no AI model. Real-data
tests skip themselves when their files are missing.

```bash
python -m pytest -q
```

If the environment is not activated, use `.venv/bin/python -m pytest -q`.

The suite covers the feature contract, column validation, the 0.3545 cut-off,
attack names, the attack reference file, SHAP output shapes, the explanation
text, alert grouping and the bounded queue, backend selection, and the
fallback path. It also contains a **laptop-versus-Pi check**:
`tests/fixtures/parity_rows.csv` holds 100 real feature rows (65 attack, 35
benign so both sides of the cut-off are exercised) and
`tests/fixtures/parity_expected.json` the probabilities the laptop produced.
Run `tests/test_parity.py` on the Pi after deployment to confirm the models
behave the same there. Regenerate those files only when the models are
intentionally replaced:

```bash
python -m bench.export_parity_fixture
```

The three end-to-end modes are opt-in:

```bash
# Mode 1: pre-extracted BCCC-format CSV
export NIDS_TEST_CSV=/data/BCCC.csv
export NIDS_TEST_CSV_ROWS=20000        # 0 runs the whole file
python -m pytest tests/e2e/test_mode1_csv.py -q

# Mode 2: real capture through NTLFlowLyzer
export PATH="$PWD/.venv/bin:$PATH"
export NIDS_TEST_PCAP=/data/Friday-WorkingHours.pcap
export NIDS_NTLFLOWLYZER_TIMEOUT=21600
export NIDS_NTLFLOWLYZER_THREADS=4     # lower this on a Pi
python -m pytest tests/e2e/test_mode2_pcap.py -q

# Mode 3: live capture (generate some traffic while it runs)
export NIDS_TEST_LIVE=1
export NIDS_TEST_LIVE_SECONDS=120
export NIDS_INTERFACE=eth0
export NIDS_PCAP_ROTATION=5
export NIDS_PCAP_STABLE=1
python -m pytest tests/e2e/test_mode3_live.py -q
```

Re-run all three after any platform change, especially the Pi port.

### Benchmarking on the Pi

The Pi runs every stage at once, so measure them separately and then together
during an attack replay:

```bash
python -m bench.bench_stages --pcap /data/Friday.pcap --max-alerts 50
LLM_BACKEND=executorch python -m bench.bench_llm --rows 200 --repeats 5
```

Record the date, window size, and git commit in `bench/RESULTS.md`. Do not
"optimise" anything without a measurement first.

## What is verified, and what is not

Verified on the original development machine (Windows, Python 3.14) before the
project was retargeted to Linux and the Raspberry Pi:

- The unit and integration suite: feature contract, models on CPU, SHAP,
  evidence, explanation text, Ollama grounding and fallback, alert
  grouping/queue, backend selection, parity fixture, and all three end-to-end
  modes on that platform.
- Real BCCC CSV and CIC-IDS2017 pcap replays through the shared pipeline.
- Ollama producing grounded explanations for real attack rows.

**Not yet verified** (state this plainly in any report):

- Linux live capture with the non-root `wireshark` group/capabilities setup.
- The ExecuTorch 1.5.1 runtime build on the Pi 5 and the exact
  `executorch_llama_runner` command-line flags.
- `tokenizer.json` compatibility with the chosen runner at 1.5.1.
- Llama 3 stop-token/BOS IDs against `xnnpack/config.json` (the constants carry
  a `TODO(open-question)`).
- The laptop-versus-Pi parity test on actual Pi hardware.
- NTLFlowLyzer column names on the Pi image versus the laptop.
- Runtime, memory, and temperature numbers in `bench/RESULTS.md` (template
  only).
