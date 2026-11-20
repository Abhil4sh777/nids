# Deploying the NIDS to a Raspberry Pi 5 with a USB stick

This folder turns the project into a **self-contained USB installation** for a
Raspberry Pi 5 that already runs 64-bit Raspberry Pi OS. The stick carries the
application, both models, the pinned ExecuTorch LLM files, and every Python
wheel the Pi needs, so the Pi itself can stay offline.

```
build machine (Linux)                          Raspberry Pi 5
──────────────────────                         ──────────────
python -m deploy.make_bundle --output <USB>    plug the stick in
        │                                            │
        └────────── files on the USB stick ──────────┘
                                                     │
                                        sudo bash install.sh
                                                     │
                                     systemd service + dashboard
```

Two commands on each side. Everything else here is optional.

## 1. What you need

| Piece | Notes |
| --- | --- |
| Raspberry Pi 5 with 64-bit Raspberry Pi OS **Trixie** | already installed; Python 3.13. Bookworm (Python 3.11) is too old for the pinned models |
| USB stick, 4 GB or more | exFAT or FAT32 both work; the LLM files are about 1 GB |
| This repository on a Linux build machine | with `models/detector.joblib` and `models/classifier.joblib` present |
| The ExecuTorch model files | `--download-llm` fetches them, or copy them in yourself |
| Internet on the build machine | only while building the bundle |
| Active cooling on the Pi | capture, extraction, both models, the LLM and the UI share the CPU |

The Pi does **not** need internet, a monitor, or a keyboard. It needs to be on
the same network as the browser you will look at the dashboard from.

## 2. Find the Pi's Python version first

The wheels on the stick must match it, and it must be **3.12 or newer** — the
pinned `numpy`, `xgboost` and `shap` have no wheels for anything older. On the
Pi:

```bash
python3 -V            # expect Python 3.13.x
```

- **Python 3.13** (Raspberry Pi OS Trixie) → the defaults are correct:
  `--python-version 3.13 --abi cp313`.
- **Python 3.11** (Bookworm) → not supported by this stack. Install Trixie, or
  rebuild the bundle against a Python 3.12+ you provide yourself.

If the version does not match, the installer stops with the exact command to
rebuild. That is the most common failure and it is a one-line fix.

## 3. Build the bundle onto the stick

Plug the stick into the Linux build machine, mounted at `/media/$USER/NIDS`.
Run from the repository root:

```bash
python -m deploy.make_bundle --output /media/$USER/NIDS --with-llm --download-llm \
    --ntlflowlyzer ../NTLFlowLyzer \
    --executorch-runner /path/to/llama_main
```

The wheel set comes from `requirements-pi.txt` in this folder: the complete
pinned install list for `linux_aarch64` and the Pi's Python. The bundler
resolves it to wheels, so nothing is compiled or resolved on the Pi.

What those flags do:

| Flag | Why |
| --- | --- |
| `--output` | the mounted stick; the bundle is written directly into it |
| `--with-llm` | include the 4k `.pte`, `tokenizer.json`, `xnnpack/config.json` |
| `--download-llm` | fetch those three files from Hugging Face if `models_llm/` is empty |
| `--ntlflowlyzer` | vendor the flow extractor so the Pi does not need pip/git |
| `--executorch-runner` | prebuilt aarch64 runner; bundles binary & `libllama_runner.so` into `bin/` |
| `--python-version`, `--abi` | match the Pi's Python (see step 2) |

Leave out `--with-llm` only if you deliberately want the Pi to run on the
fallback explanations. Leave out `--ntlflowlyzer` only if the extractor is
already installed on the Pi — without it, live capture cannot work.

While it runs you will see the wheel download, then the LLM files being copied,
then a manifest of every file being hashed. It ends with:

```
[bundle] done: E:\ (1.7 GB)
[bundle] next: plug the stick into the Pi and run  sudo bash install.sh
```

The output folder is safe to eject when that appears. Rebuild it whenever the
code changes; the installer is idempotent.

## 4. Install on the Pi

Plug the stick into the Pi and log in over SSH. Find the mount point and run the
installer:

```bash
ls /media/$USER/                       # the stick's name, e.g. NIDS
sudo bash /media/$USER/NIDS/install.sh
```

The installer, in order:

1. verifies every file against `MANIFEST.sha256` (catches a half-copied stick);
2. checks the architecture and that the Python matches the wheels;
3. installs the few Debian packages (`python3-venv`, `libgomp1`, `libpcap0.8`,
   `wireshark-common`) — from `debs/` if you put them there, otherwise it
   assumes they are present;
4. creates a `nids` system user, `/opt/nids/venv`, and `/opt/nids/data`;
5. installs all wheels with `--no-index` (no network);
6. copies the app, the vendored NTLFlowLyzer, and the 1 GB of model files;
7. gives `dumpcap` the two file capabilities it needs, so no root capture;
8. writes `/etc/nids/nids.env` with the detected wired interface;
9. installs `nids.service`, enables it, and waits for the dashboard to answer.

It finishes with the dashboard URL. Re-running it later upgrades the
application, keeps `/etc/nids/nids.env`, and skips files that are already in
place — so an update is: copy the new bundle to the stick, run the same command.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--interface end0` | set the capture interface instead of autodetecting |
| `--port 8080` | dashboard port instead of 8501 |
| `--data-dir /mnt/ssd/nids` | put captures and flow CSVs on a USB SSD, not the SD card |
| `--llm-dir /mnt/ssd/models_llm` | keep the 1 GB of model files off the SD card |
| `--runner PATH` | install an already-built `executorch_llama_runner` |
| `--online` | allow apt/pip to reach the network if the stick is incomplete |
| `--no-start` | install without enabling the service |
| `--dry-run` | print every action, change nothing |
| `--uninstall` | stop and remove everything (`--purge` also drops `/etc/nids`) |

## 5. Check it

```bash
sudo bash /media/$USER/NIDS/verify.sh
```

It prints PASS/FAIL for: the install tree, the service, the dashboard health
endpoint, loading both models and the knowledge packet, the
**model parity test** (100 fixture rows, identical probabilities and decisions),
`dumpcap` as the `nids` user, NTLFlowLyzer resolution, and the LLM backend
status. `--smoke` adds the one-sentence ExecuTorch test.

The parity test is the important one: it proves the models behave on the Pi
exactly as they did on the reference machine that produced the fixture.

## 6. Open the dashboard

```
http://<pi-address>:8501
```

The installer detects a wired interface and sets `NIDS_AUTOSTART=1`, so live
capture starts as soon as the page loads (source column shows
`Live: end0`). Otherwise pick **Live capture**, type the interface (`ip link`),
and press **Start**.

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

## Optional: get the ExecuTorch runner

The `.pte` needs the **matching ExecuTorch 1.5.1 runtime**. There are two ways to
get it:

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
`libllama_runner.so` (which `llama_main` needs via `$ORIGIN`).

You can bundle them directly onto the stick:
```bash
python -m deploy.make_bundle --output /media/$USER/NIDS --with-llm \
    --ntlflowlyzer ../NTLFlowLyzer \
    --executorch-runner ./llama_main
```
When bundled with `--executorch-runner`, `make_bundle` places both `executorch_llama_runner`
and `libllama_runner.so` under `bin/` on the stick, and `install.sh` automatically
installs them into `/opt/nids/bin/`.

**Or copy the binary to the stick manually:**

```bash
cp llama_main libllama_runner.so /media/$USER/NIDS/
sudo bash /media/$USER/NIDS/install.sh --runner /media/$USER/NIDS/llama_main
```

**Or build it on the Pi** (needs internet there, 8 GB free, 1–3 hours):

```bash
sudo bash /media/$USER/NIDS/build_executorch_runner.sh
sudo systemctl restart nids
sudo bash /media/$USER/NIDS/verify.sh --smoke
```

Until a runner exists, attack rows still appear immediately and still get an
explanation — the one assembled directly from the evidence packet (predicted
class, description, mitigation, top features) instead of model-written prose.
The sidebar's LLM panel says exactly which piece is missing.

## Optional: fully offline Debian packages

`apt` is the only part of the install that may still need the network. To
remove that dependency, download the `.deb` files on a machine with the **same
OS release and architecture** and put them in `debs/` on the stick:

```bash
sudo apt-get install --download-only -y python3-venv python3-pip libgomp1 \
    libpcap0.8 wireshark-common ca-certificates
sudo cp /var/cache/apt/archives/*.deb /media/$USER/NIDS/debs/
```

The installer uses them automatically when the folder is present.

## Troubleshooting

| What you see | What it means | Fix |
| --- | --- | --- |
| `bundle holds wheels for Python 3.13 but the Pi runs 3.12` | the target Python was guessed | rebuild with `--python-version 3.12 --abi cp312` |
| `Python 3.11 is too old` | Bookworm's interpreter cannot run the pinned stack | use Raspberry Pi OS Trixie |
| `sha256sum: ... FAILED` during install | the stick was removed early or the copy is corrupt | copy the bundle again, eject safely |
| `offline wheel install failed` | a wheel is missing for this Python/arch | rebuild; or `--online` on the Pi |
| `No matching distribution found for numpy==...` | same cause, seen through pip | same fix |
| `dumpcap cannot run as 'nids'` | file capabilities missing, or `/opt` is `nosuid` | `sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap`, keep `/opt` not `nosuid` |
| dashboard shows `NTLFlowLyzer is not found` | extractor was not bundled | re-bundle with `--ntlflowlyzer`, or `pip install` it in `/opt/nids/venv` |
| the LLM panel says `not ready` | `.pte`, tokenizer, or runner missing | `verify.sh` names the missing piece |
| every attack uses fallback text | no runner yet | build it (above); detection and class are still real |
| `Address already in use` | something else holds the port | `--port 8502` and re-run |
| dashboard loads but no rows | no traffic on that interface, or the wrong one | check `ip link`, then `journalctl -u nids -f` |

## What is verified, and what is not

Verified here, on the development machine:

- the bundler produces a complete, hashed tree and refuses a half-empty repo;
- a real build for a Python 3.13 / `linux_aarch64` target resolved and saved all
  56 wheels (numpy, pandas, scikit-learn, xgboost, shap, streamlit, tokenizers
  and transitive dependencies), vendored NTLFlowLyzer, and wrote a 217-file
  manifest, every entry of which verifies with `sha256sum -c`;
- the `--with-llm` path: the 4k `.pte`, `tokenizer.json` and `xnnpack/config.json`
  are copied into the bundle under `models_llm/`;
- the `--executorch-runner` path: cross-compiled `llama_main` and `libllama_runner.so`
  for aarch64 (glibc 2.38) with the Arm GNU toolchain; verified ELF format with `readelf`,
  and bundled into `bin/` without line-ending corruption;
- every script parses (`bash -n`), and every key the installer writes is read
  by `config.py`;
- the copied `app/` tree passes its own tests from inside the bundle;
- `tests/test_deploy_bundle.py` (24 tests) pins the payload list, the placeholder
  rendering, the LF line endings, the service contract, binary preservation, runner
  bundling, and the dry-run / no-clobber behaviour.

**Not verified** (same list as the main README, plus deployment specifics):

- an actual `install.sh` run on a Raspberry Pi 5 — every path, package name and
  systemd behaviour below is written for Raspberry Pi OS but has not been
  executed on physical Pi hardware;
- the parity test and the LLM smoke test on live Pi hardware.

If a step fails, the error message names the file, package, or setting; the
installer is safe to re-run after fixing it.
