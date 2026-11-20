# NIDS on a Raspberry Pi 5: a network intrusion detector that explains itself

This program watches network traffic, decides whether it looks normal or like an
attack, names the type of attack, and writes a short, plain-English explanation
of *why* it was flagged.

It is packaged for exactly one runtime: a **Raspberry Pi 5** running 64-bit
Raspberry Pi OS. The repository carries the application, both trained models, a
one-command offline installer, and a systemd service that starts the dashboard
at boot. There is no laptop development runtime: the explanation backend is
ExecuTorch, and the model it runs is arm64 only.

## Contents

- [What it actually does](#what-it-actually-does)
- [What you need](#what-you-need)
- [Install it: offline USB bundle (recommended)](#install-it-offline-usb-bundle-recommended)
- [Install it: manual steps on the Pi](#install-it-manual-steps-on-the-pi)
- [Using the app](#using-the-app)
- [Everyday commands on the Pi](#everyday-commands-on-the-pi)
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
| Raspberry Pi 5, 8 GB recommended | everything | 4 GB works at the 2k-4k window; watch memory |
| 64-bit Raspberry Pi OS **Trixie** | everything | Python 3.13. Bookworm (3.11) is too old for the pinned libraries |
| Active cooling | everything | capture, extraction, both models, the AI and the dashboard share the CPU |
| A USB stick, 4 GB or more | the offline install | exFAT or FAT32; the LLM files are about 1 GB |
| `dumpcap` (from Wireshark) | live capture | installed by the installer; Python never runs as root |
| NTLFlowLyzer | pcap/live capture | vendored onto the stick by the bundler |
| ExecuTorch 1.5.1 runner | AI-written explanations | built by `deploy/build_executorch_runner.sh`; without it you get the evidence-based fallback text |

## Install it: offline USB bundle (recommended)

This is two commands on the Pi and one on a Linux build machine. The stick
carries the application, both models, the ExecuTorch files, and every Python
wheel, so the Pi needs no network.

```
build machine                                Raspberry Pi 5
─────────────                                ──────────────
python -m deploy.make_bundle --output <USB>   plug the stick in
        │                                          │
        └──────── files on the USB stick ──────────┘
                                                   │
                                    sudo bash install.sh
                                                   │
                                 systemd service + dashboard
```

**1. Check the Pi's Python once.** The wheels must match it:

```bash
python3 -V        # Trixie: Python 3.13.x
```

**2. Build the bundle on the Linux machine.** Plug the stick in and run from
the repository root:

```bash
python -m deploy.make_bundle --output /media/$USER/NIDS \
    --with-llm --download-llm \
    --ntlflowlyzer ../NTLFlowLyzer \
    --executorch-runner ./llama_main
```

| Flag | Why |
| --- | --- |
| `--output` | the mounted stick; the bundle is written directly into it |
| `--with-llm` | include the 4k `.pte`, `tokenizer.json`, `xnnpack/config.json` |
| `--download-llm` | fetch those three files from Hugging Face if `models_llm/` is empty |
| `--ntlflowlyzer` | vendor the flow extractor so the Pi needs no pip or git |
| `--executorch-runner` | prebuilt aarch64 runner; bundles it and `libllama_runner.so` into `bin/` |
| `--python-version`, `--abi` | match the Pi's Python (defaults `3.13` / `cp313`) |

Leave out `--with-llm` only if you deliberately want fallback-only
explanations. Leave out `--ntlflowlyzer` only if the extractor is already
installed on the Pi; without it, live capture cannot work. Full flags, the
offline `apt` option and a troubleshooting table are in
[`deploy/README.md`](deploy/README.md).

The bundler resolves `deploy/requirements-pi.txt` for `linux_aarch64` and
Python 3.13, so the pins are decided on the build machine and the Pi installs
exactly those wheels with `--no-index`.

**3. Install on the Pi.** Plug the stick in and run:

```bash
ls /media/$USER/                                  # find the stick, e.g. NIDS
sudo bash /media/$USER/NIDS/install.sh
```

The installer verifies every file against `MANIFEST.sha256`, checks the
architecture and Python version, creates a `nids` system user and
`/opt/nids/venv`, installs the wheels offline, copies the application and the
1 GB of model files, gives `dumpcap` its file capabilities, writes
`/etc/nids/nids.env`, and enables `nids.service`. Re-running it upgrades the
application and keeps your configuration.

**4. Check it.**

```bash
sudo bash /media/$USER/NIDS/verify.sh --smoke
```

That prints PASS/FAIL for the install tree, the service, the dashboard health
endpoint, loading both models and the knowledge packet, the parity fixture,
`dumpcap` as the `nids` user, NTLFlowLyzer resolution, the ExecuTorch backend,
and one generated sentence from the `.pte`.

**5. Open the dashboard** at `http://<pi-address>:8501`. The installer sets
`NIDS_AUTOSTART=1` when it finds a wired interface, so live capture starts as
soon as the page loads.

## Install it: manual steps on the Pi

Use this when you cannot build a bundle, or when you want to know what the
installer does. Every step runs on the Pi.

**1. System packages and Python environment**

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip wireshark-common tshark libpcap0.8
python3 -m venv ~/nids-venv
. ~/nids-venv/bin/activate
pip install --upgrade pip
pip install -r deploy/requirements-pi.txt
```

`deploy/requirements-pi.txt` is the complete pinned set for
`linux_aarch64`/Python 3.13. If your Pi runs a different Python, use the
matching interpreter for the venv; the bundle path is safer because it fails
early on a mismatch.

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

The app finds the command on `PATH`, next to the running Python, or as
`python -m NTLFlowLyzer`.

**4. Build the ExecuTorch 1.5.1 runtime**

The model file was exported with ExecuTorch **1.5.1** and needs a 1.5.1 runtime
with the XNNPACK (CPU) backend. Do not use 1.4.0 - that version is only for the
phone-target files.

`deploy/build_executorch_runner.sh` runs the upstream recipe for tag `v1.5.1`
(core libraries first, then the `examples/models/llama` example, target
`llama_main`). Build it on the Pi with:

```bash
sudo bash deploy/build_executorch_runner.sh
```

Cross-compiling on an x86_64 Ubuntu box is much faster:
`bash deploy/build_executorch_runner.sh --cross --out ./llama_main`. Build
against a glibc no newer than the Pi's (Trixie is 2.41); Ubuntu 22.04 (2.35)
and 24.04 (2.39) are both safe. Any relocatable aarch64 toolchain works - point
`CROSS_COMPILE` at its prefix and `CROSS_SYSROOT` at its sysroot if the
compiler does not know it. The host needs a Python 3 with `torch` installed
(the CMake build reads torch's headers) and CMake >= 3.26.

Then tell the app where the runner is:

```bash
export EXECUTORCH_RUNNER_PATH=/path/to/llama_main
```

The stock `llama_main` is called with `--model_path`, `--tokenizer_path`,
`--prompt_file` (the evidence prompt is written to a temporary file),
`--max_new_tokens`, and `--temperature`; the answer is read from its output. If
your runner takes different arguments, set `EXECUTORCH_RUNNER_PATH` to a
template containing `{pte}`, `{tokenizer}`, `{prompt_file}`, `{window}`,
`{max_new_tokens}`, and `{temperature}` - a template without `{prompt_file}`
gets the prompt on standard input instead.

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

**6. Check the model, then start the app**

```bash
export LLM_BACKEND=executorch
export EXECUTORCH_WINDOW=4096
export EXECUTORCH_TIMEOUT_S=180
python -m bench.llm_smoke          # must print a correct answer
streamlit run app.py
```

Do not trust the AI text in the dashboard until the smoke test passes. Without
a working runner, attack rows still appear immediately and still get an
explanation - the one assembled directly from the evidence packet.

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

## Using the app

Pick one of three ways to feed it data in the sidebar, then press **Start**.

| Mode in the sidebar | What it does | What you need | Best for |
| --- | --- | --- | --- |
| **CSV (pre-extracted)** | Reads rows that were already turned into flow measurements | a BCCC-format `.csv` | checking a known sample without capture |
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
- **Live capture.** Type the interface name, e.g. `end0` on a Pi (find it with
  `ip link`); the installer fills this in for you. The app writes short rotating
  capture files and only processes ones that are finished, so it never reads a
  file that is still being written. Finished captures are deleted by default to
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

## Everyday commands on the Pi

```bash
sudo systemctl status nids          # is it running
sudo journalctl -u nids -f          # live logs (capture, extraction, LLM)
sudo systemctl restart nids         # after editing /etc/nids/nids.env
sudo nano /etc/nids/nids.env        # all settings; see the table below
sudo bash /media/$USER/NIDS/verify.sh
```

## When something goes wrong

Most problems are one of the rows below. The app tries to tell you which.

| What you see | What it means | Fix |
| --- | --- | --- |
| `Python 3.11 is too old` | Bookworm's interpreter cannot run the pinned stack | use Raspberry Pi OS Trixie (64-bit) |
| `bundle holds wheels for Python 3.13 but the Pi runs 3.12` | the target Python was guessed | rebuild with `--python-version 3.12 --abi cp312` |
| `sha256sum: ... FAILED` during install | the stick was removed early or the copy is corrupt | copy the bundle again, eject safely |
| `offline wheel install failed` | a wheel is missing for this Python/arch | rebuild the bundle; or `--online` on the Pi |
| `dumpcap` is not found | Wireshark's capture tool is missing | `sudo apt install wireshark-common tshark` |
| `dumpcap` exits immediately | wrong interface name, or you lack capture permission | check `ip link`; rerun the installer's `setcap` step or join the `wireshark` group |
| `dumpcap cannot run as 'nids'` | file capabilities missing, or `/opt` is `nosuid` | `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap` |
| `ntlflowlyzer` is not found | the extractor was not bundled or installed | re-bundle with `--ntlflowlyzer`, or `pip install` it in `/opt/nids/venv` |
| extraction times out on a big capture | the extractor is slow by nature | raise `NIDS_NTLFLOWLYZER_TIMEOUT`; raise threads only if the machine has headroom |
| the LLM panel says `not ready` | the `.pte`, `tokenizer.json`, or runner path is wrong | the status line names the missing piece; run `python -m bench.llm_smoke` |
| every attack uses fallback text | no runner yet, or the runner failed | build the runner (above); detection and class are still real |
| rows show fallback text and the log says the queue is full | a flood of alerts, by design | normal; increase `NIDS_ALERT_QUEUE_SIZE` or the grouping window if the machine has headroom |
| `Address already in use` | something else holds the port | `--port 8502` and re-run the installer |

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
environment variable. On an installed appliance they come from
`/etc/nids/nids.env`, rendered from `deploy/nids.env.example`. The detection
contract does not move with them: the 0.3545 cut-off, the feature lists, and
the attack names are fixed in `features/contract.py`.

<details>
<summary>Show the project layout</summary>

```
capture/     dumpcap wrapper, rolling capture files, cleanup after processing
features/    feature contract, column mapping, model inputs, NTLFlowLyzer runner
models/      detector.joblib, classifier.joblib, loading and CPU inference
explain/     attack reference, SHAP, evidence, alert grouping, prompt
explain/llm/ the ExecuTorch backend behind the LLMBackend interface
ui/          thread-safe store, table, Streamlit app
tests/       unit tests, the three end-to-end modes, model parity fixture
bench/       per-stage benchmarks, ExecuTorch smoke test
deploy/      offline USB bundle builder, installer, systemd unit, Pi lock, health checks
```

All three input modes share the same detection, explanation, and table code.
Only the source of the feature rows changes (`features/sources.py`).

</details>

<details>
<summary>Show the full list of environment variables</summary>

| Variable | Meaning |
| --- | --- |
| `LLM_BACKEND` | must be `executorch`; anything else is rejected at startup |
| `NIDS_ROOT` | Project root for the default paths below |
| `NIDS_INTERFACE` | Live capture interface (`end0`, `eth0`, ...) |
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
| `EXECUTORCH_PTE_PATH` | Path to the 4k `.pte` (default under `models_llm/`) |
| `EXECUTORCH_TOKENIZER_PATH` | Path to `tokenizer.json` |
| `EXECUTORCH_RUNNER_PATH` | Runner command or `{pte}`/`{tokenizer}`/`{window}` template |
| `EXECUTORCH_WINDOW` | Fixed window of the `.pte` (default 4096) |
| `EXECUTORCH_TIMEOUT_S` | Runner timeout in seconds (default 180) |
| `EXECUTORCH_RESERVED_OUTPUT_TOKENS` | Window space kept for the answer (default 256) |
| `EXECUTORCH_TEMPERATURE` | Runner sampling temperature (default 0.2) |
| `NIDS_ALERT_GROUP_WINDOW` | Alert group window in seconds (default 60) |
| `NIDS_ALERT_QUEUE_SIZE` | Bounded LLM queue length (default 64) |
| `NIDS_HISTORY_LIMIT` | Rows kept in the live table (default 500) |
| `NIDS_UI_REFRESH` | Table refresh interval in seconds (default 2) |
| `NIDS_AUTOSTART` | `1` starts live capture on load (appliance mode; default off) |
| `NIDS_XGB_DEVICE` | Must remain `cpu`; other values are rejected |
| `STREAMLIT_SERVER_HEADLESS` | Set by the installer; keeps Streamlit non-interactive |
| `STREAMLIT_SERVER_PORT` | Dashboard port (default 8501) |

`NIDS_`-prefixed aliases for the bare `LLM_BACKEND`/`EXECUTORCH_*` names are also
accepted.

</details>

## Tests and benchmarks (reference)

The everyday suite needs no captures, no network, and no AI model. Real-data
tests skip themselves when their files are missing. On the Pi:

```bash
cd /opt/nids/app
/opt/nids/venv/bin/python -m pytest -q
```

The suite covers the feature contract, column validation, the 0.3545 cut-off,
attack names, the attack reference file, SHAP output shapes, the explanation
text, alert grouping and the bounded queue, backend selection, the ExecuTorch
command line, the deployment bundle, and the fallback path. It also contains
the **model parity check**: `tests/fixtures/parity_rows.csv` holds 100 real
feature rows (65 attack, 35 benign, so both sides of the cut-off are exercised)
and `tests/fixtures/parity_expected.json` the probabilities produced by the
reference machine. `deploy/verify.sh` runs this check after every install, so a
Pi whose XGBoost or SHAP build behaves differently is caught immediately.

The fixture is committed and is the reference. Regenerate it only when the
`.joblib` models are intentionally replaced: the rows come from
`bench.common.parity_frame(count)` and the expected probabilities from
`models.inference.InferenceEngine`, reviewed by hand before committing.

The three end-to-end modes are opt-in:

```bash
# Mode 1: pre-extracted BCCC-format CSV
export NIDS_TEST_CSV=/data/BCCC.csv
export NIDS_TEST_CSV_ROWS=20000        # 0 runs the whole file
python -m pytest tests/e2e/test_mode1_csv.py -q

# Mode 2: real capture through NTLFlowLyzer
export NIDS_TEST_PCAP=/data/Friday-WorkingHours.pcap
export NIDS_NTLFLOWLYZER_TIMEOUT=21600
export NIDS_NTLFLOWLYZER_THREADS=2     # the Pi shares its CPU
python -m pytest tests/e2e/test_mode2_pcap.py -q

# Mode 3: live capture (generate some traffic while it runs)
export NIDS_TEST_LIVE=1
export NIDS_TEST_LIVE_SECONDS=120
export NIDS_INTERFACE=end0
export NIDS_PCAP_ROTATION=5
export NIDS_PCAP_STABLE=1
python -m pytest tests/e2e/test_mode3_live.py -q
```

Re-run all three after any platform change.

### Benchmarking on the Pi

The Pi runs every stage at once, so measure them separately and then together
during an attack replay:

```bash
cd /opt/nids/app
python -m bench.bench_stages --pcap /data/Friday.pcap --max-alerts 50
python -m bench.bench_llm --rows 200 --repeats 5
python -m bench.llm_smoke
```

Record the date, window size, and git commit in `bench/RESULTS.md`. Do not
"optimise" anything without a measurement first.

## What is verified, and what is not

Verified in this repository:

- the unit and integration suite on the reference machine: feature contract,
  models on CPU, SHAP, evidence, explanation text, grounding and fallback,
  alert grouping/queue, backend selection, the ExecuTorch command line, the
  deployment bundle, the parity fixture, and the three end-to-end modes;
- real BCCC CSV and CIC-IDS2017 pcap replays through the shared pipeline;
- the bundler produces a complete, hashed tree for a Python 3.13 /
  `linux_aarch64` target, including every pinned wheel, the vendored
  NTLFlowLyzer, and the ExecuTorch files;
- the cross-compiled aarch64 `llama_main` (`readelf` confirms the ELF target).

**Not yet verified** (state this plainly in any report):

- an `install.sh` run on physical Raspberry Pi 5 hardware;
- Linux live capture with the non-root `wireshark` group/capabilities setup;
- the ExecuTorch 1.5.1 runtime build on the Pi 5 and the exact
  `executorch_llama_runner` command-line flags;
- `tokenizer.json` compatibility with the chosen runner at 1.5.1;
- Llama 3 stop-token/BOS IDs against `xnnpack/config.json` (the constants carry
  a `TODO(open-question)`);
- the parity test and the LLM smoke test on actual Pi hardware;
- NTLFlowLyzer column names on the Pi image;
- runtime, memory, and temperature numbers in `bench/RESULTS.md` (template
  only).
