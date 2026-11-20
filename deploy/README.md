# Deploying the NIDS to a Raspberry Pi 5 from this repository

The Pi installs straight from a git checkout. Clone the repository on the Pi,
run the installer, and systemd keeps the dashboard running:

```
Raspberry Pi 5 (64-bit Raspberry Pi OS)
──────────────────────────────────────
git clone <repository-url> nids
cd nids
sudo bash deploy/install.sh --download-llm ...
        │
        └──> /opt/nids/{app,venv,bin,models_llm} + nids.service
                    │
             http://<pi-address>:8501
```

There is no separate build machine, no wheel bundle, and no copy step. The
installer uses the checkout it lives in, so an update is `git pull` followed by
the same command.

## 1. What you need

| Piece | Notes |
| --- | --- |
| Raspberry Pi 5, 8 GB recommended | 4 GB works at the 2k-4k window; watch memory |
| 64-bit Raspberry Pi OS **Trixie** | Python 3.13. Bookworm (3.11) is too old for the pinned stack |
| Internet on the Pi | `apt` and `pip` run during the install; `--wheelhouse` covers the Python side offline |
| About 3 GB free under `/opt` | the app, the virtual environment, and about 1 GB of model files |
| Active cooling | capture, extraction, both models, the LLM and the dashboard share the CPU |

The Pi does not need a monitor or a keyboard. It does need to be on the same
network as the browser you will use.

## 2. Clone and install

On the Pi:

```bash
git clone <repository-url> nids
cd nids
sudo bash deploy/install.sh \
    --download-llm \
    --ntlflowlyzer /path/to/NTLFlowLyzer \
    --runner /path/to/executorch_llama_runner
```

Only the first line is required. The other flags add the pieces that live
outside git:

| Flag | Why |
| --- | --- |
| `--download-llm` | fetch the 4k `.pte`, `tokenizer.json` and `xnnpack/config.json` from Hugging Face |
| `--ntlflowlyzer DIR` | install a local NTLFlowLyzer checkout; needed for pcap and live capture |
| `--runner PATH` | install a prebuilt arm64 ExecuTorch runner for AI-written explanations |
| `--interface end0` | set the capture interface instead of autodetecting a wired port |
| `--port 8080` | dashboard port instead of 8501 |
| `--data-dir /mnt/ssd/nids` | put captures and flow CSVs on an external SSD, not the SD card |
| `--llm-dir /mnt/ssd/models_llm` | keep the 1 GB of model files off the SD card |
| `--wheelhouse DIR` | install Python wheels from a local folder instead of PyPI |
| `--repo DIR` | install a checkout other than the parent of `deploy/` |
| `--no-start` | install without enabling the service |
| `--no-verify` | skip the post-install checks |
| `--skip-apt` | never touch apt (packages must already be installed) |
| `--dry-run` | print every action, change nothing |
| `--uninstall` | stop and remove everything (`--purge` also drops `/etc/nids`) |

The installer, in order:

1. checks the architecture, the Python version and that the checkout has both
   `.joblib` models and the knowledge packet;
2. installs the few Debian packages (`python3-venv`, `python3-pip`, `libgomp1`,
   `libpcap0.8`, `wireshark-common`, `ca-certificates`);
3. creates a `nids` system user, `/opt/nids/venv`, and `/opt/nids/data`;
4. installs `deploy/requirements-pi.txt` with pip (pinned, so the versions are
   decided here, not at import time);
5. copies the checkout into `/opt/nids/app`, leaving out captures, caches and
   the model binaries;
6. vendors NTLFlowLyzer and installs the ExecuTorch runner when asked;
7. downloads or copies the three model files;
8. gives `dumpcap` the two file capabilities it needs, so no root capture;
9. writes `/etc/nids/nids.env` with the detected wired interface;
10. installs `nids.service`, enables it, and waits for the dashboard to answer.

It finishes with the dashboard URL. Re-running it upgrades the application and
keeps `/etc/nids/nids.env`.

## 3. Model files

The three ExecuTorch files are about 1 GB and are never committed. Pick one:

```bash
# a) let the installer fetch them (huggingface_hub is pinned in requirements-pi.txt)
sudo bash deploy/install.sh --download-llm

# b) download them yourself into the checkout, then install
pip install huggingface_hub
hf download experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch \
    xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte \
    tokenizer.json \
    xnnpack/config.json \
    --local-dir ./models_llm
sudo bash deploy/install.sh

# c) point at a folder that already has them
sudo bash deploy/install.sh --llm-dir /mnt/ssd/models_llm
```

Download only those files: the model repository also holds `vulkan/`, `qnn/`,
and `mtk/` variants for phones, which are several gigabytes and useless here.
If you redistribute the model, keep `LICENSE.txt`, `USE_POLICY.md`, and
`NOTICE` with it (the licence is `llama3.2`).

Without the files the dashboard still detects and classifies, but every
explanation comes from the evidence-packet fallback.

## 4. Optional: get the ExecuTorch runner

The `.pte` needs the **matching ExecuTorch 1.5.1 runtime**. There are two ways
to get it:

**Cross build on Ubuntu (fast, recommended).** The runner only has to be built
against a glibc/libstdc++ that is the same age or older than the Pi's. Raspberry
Pi OS Trixie ships glibc 2.41 / GCC 14, so Ubuntu 22.04 (2.35 / GCC 11) or
24.04 (2.39 / GCC 13) both produce a binary that runs there, and a fast x86 box
builds it in minutes instead of hours. On the Ubuntu machine:

```bash
git clone <this repository> && cd nids
bash deploy/build_executorch_runner.sh --cross --out ./llama_main
```

`--no-deps` skips the apt/pip installation if you already have the toolchain
(`g++-aarch64-linux-gnu`, CMake ≥ 3.26, a Python 3 with `torch`, which the CMake
build imports to find torch's headers). A relocatable aarch64 toolchain such as
Arm's works without apt packages:

```bash
CROSS_COMPILE=aarch64-none-linux-gnu- \
PATH=$HOME/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin:$PATH \
bash deploy/build_executorch_runner.sh --cross --no-deps --out ./llama_main
```

The build produces both the executable `llama_main` and the shared library
`libllama_runner.so` (which `llama_main` needs via `$ORIGIN`). Copy both to the
Pi, then install:

```bash
sudo bash deploy/install.sh --runner /path/to/llama_main
```

**Or build it on the Pi** (needs internet there, 8 GB free, 1–3 hours):

```bash
sudo bash deploy/build_executorch_runner.sh
sudo systemctl restart nids
sudo bash /opt/nids/app/deploy/verify.sh --smoke
```

Until a runner exists, attack rows still appear immediately and still get an
explanation — the one assembled directly from the evidence packet (predicted
class, description, mitigation, top features) instead of model-written prose.
The sidebar's LLM panel says exactly which piece is missing.

## 5. Optional: NTLFlowLyzer

`deploy/install.sh --ntlflowlyzer /path/to/NTLFlowLyzer` copies the checkout to
`/opt/nids/vendor/NTLFlowLyzer` and points `NIDS_NTLFLOWLYZER` at it. Without
it, CSV mode works but pcap replay and live capture do not.

If you prefer the package form, install it into the appliance's virtual
environment and remove the vendored setting:

```bash
sudo /opt/nids/venv/bin/pip install /path/to/NTLFlowLyzer
sudo sed -i 's|^NIDS_NTLFLOWLYZER=.*|NIDS_NTLFLOWLYZER=ntlflowlyzer|' /etc/nids/nids.env
sudo systemctl restart nids
```

## 6. Check it

```bash
sudo bash /opt/nids/app/deploy/verify.sh
```

It prints PASS/FAIL for: the install tree, the service, the dashboard health
endpoint, loading both models and the knowledge packet, the **model parity test**
(100 fixture rows, identical probabilities and decisions), `dumpcap` as the
`nids` user, NTLFlowLyzer resolution, and the LLM backend status. `--smoke` adds
the one-sentence ExecuTorch test.

The parity test is the important one: it proves the models behave on the Pi
exactly as they did on the reference machine that produced the fixture.

## 7. Open the dashboard

```
http://<pi-address>:8501
```

The installer detects a wired interface and sets `NIDS_AUTOSTART=1`, so live
capture starts as soon as the page loads (source column shows `Live: end0`).
Otherwise pick **Live capture**, type the interface (`ip link`), and press
**Start**.

There is **no login on the dashboard**. It listens on all interfaces so you can
reach it from another machine; keep the Pi on a trusted network or front it with
a reverse proxy if that is not acceptable.

## Everyday commands on the Pi

```bash
sudo systemctl status nids          # is it running
sudo journalctl -u nids -f          # live logs (capture, extraction, LLM)
sudo systemctl restart nids         # after editing /etc/nids/nids.env
sudo nano /etc/nids/nids.env        # all settings; see README in the app
```

Updating the appliance:

```bash
cd ~/nids
git pull
sudo bash deploy/install.sh
```

The application is replaced, the virtual environment is reused, and
`/etc/nids/nids.env` is kept. Model files already in place are not downloaded
again.

## Optional: install the Python side offline

If the Pi cannot reach PyPI, build a wheelhouse on a machine with the same
Python and architecture, copy it over with the checkout, and pass it to the
installer:

```bash
python -m pip download --only-binary=:all: --dest wheelhouse \
    --platform manylinux_2_39_aarch64 \
    --platform manylinux_2_28_aarch64 \
    --platform manylinux2014_aarch64 \
    --platform linux_aarch64 \
    --python-version 3.13 --implementation cp --abi cp313 \
    -r deploy/requirements-pi.txt
```

```bash
sudo bash deploy/install.sh --wheelhouse ./wheelhouse --skip-apt
```

`--skip-apt` is only safe when the Debian packages are already installed; apt
has no wheelhouse equivalent here.

## Troubleshooting

| What you see | What it means | Fix |
| --- | --- | --- |
| `Python 3.11 is too old` | Bookworm's interpreter cannot run the pinned stack | use Raspberry Pi OS Trixie |
| `pip install failed` / `No matching distribution found` | no network, or a pin has no wheel for this Python | check the Pi's network; or build a `--wheelhouse` for its Python |
| `apt-get update failed` | the Pi is offline | connect it once, or install the packages yourself and use `--skip-apt` |
| `dumpcap cannot run as 'nids'` | file capabilities missing, or `/opt` is `nosuid` | `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap`, keep `/opt` not `nosuid` |
| `NTLFlowLyzer is not installed` | no `--ntlflowlyzer` and no package in the venv | re-run with `--ntlflowlyzer /path/to/checkout` |
| the LLM panel says `not ready` | `.pte`, tokenizer, or runner missing | `verify.sh` names the missing piece |
| every attack uses fallback text | no runner yet, or `--download-llm` was not used | see sections 3 and 4; detection and class are still real |
| `Address already in use` | something else holds the port | `--port 8502` and re-run |
| dashboard loads but no rows | no traffic on that interface, or the wrong one | check `ip link`, then `journalctl -u nids -f` |

## What is verified, and what is not

Verified on the development machine:

- every script parses (`bash -n`), and every key the installer writes is read
  by `config.py`;
- the installed application tree passes its own tests, including the model
  parity fixture;
- `deploy/requirements-pi.txt` stays in step with `requirements.txt`
  (`tests/test_deploy.py`), and the installer has no reference to the removed
  bundle/manifest pathway;
- the cross-compiled aarch64 `llama_main` (`readelf` confirms the ELF target).

**Not verified** (same list as the main README, plus deployment specifics):

- an actual `install.sh` run on a Raspberry Pi 5 — every path, package name and
  systemd behaviour below is written for Raspberry Pi OS but has not been
  executed on physical Pi hardware;
- `pip install` of the pinned set on aarch64 Python 3.13;
- the parity test and the LLM smoke test on live Pi hardware.

If a step fails, the error message names the file, package, or setting; the
installer is safe to re-run after fixing it.
