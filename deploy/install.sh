#!/usr/bin/env bash
# ===========================================================================
# NIDS installer for Ubuntu desktop 24.04 LTS on a Raspberry Pi 5.
#
# The Pi installs straight from a git checkout of this repository:
#
#       git clone <repository-url> nids
#       cd nids
#       sudo bash deploy/install.sh
#
# What it does, in order:
#   1. checks the board, the OS architecture, the Python version and the
#      repository contents (both .joblib models, the knowledge packet)
#   2. installs the few Debian packages needed
#   3. creates a dedicated 'nids' system user and a virtual environment
#   4. installs the pinned requirements with pip (deploy/requirements-pi.txt)
#   5. copies this checkout into /opt/nids/app
#   6. optionally vendors NTLFlowLyzer and installs the ExecuTorch runner
#   7. downloads the ExecuTorch model files when asked to, or copies them
#      from models_llm/ in this checkout
#   8. lets the service user run dumpcap without root
#   9. writes /etc/nids/nids.env (never overwritten on re-runs)
#  10. installs and starts the systemd service, then waits for the dashboard
#
# Re-running it upgrades the application and keeps the existing configuration,
# so an update is:  git pull  &&  sudo bash deploy/install.sh
# ===========================================================================
set -Eeuo pipefail

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SELF="$SELF_DIR/$(basename -- "${BASH_SOURCE[0]}")"

PREFIX=/opt/nids
SERVICE_NAME=nids
SERVICE_USER=nids
PORT=8501
ENV_DIR=/etc/nids
ENV_FILE=""
DATA_DIR=""
LLM_DIR=""
INTERFACE=""
RUNNER_SRC=""
NTLFLOWLYZER_SRC=""
WHEELHOUSE=""
REPO_ROOT=$(cd -- "$SELF_DIR/.." && pwd)
DOWNLOAD_LLM=0
APT_MODE=auto
DO_START=1
DO_VERIFY=1
DO_UNINSTALL=0
PURGE=0
KEEP_DATA=0
DRY_RUN=0

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warning]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if (( DRY_RUN )); then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }

trap 'printf "\033[1;31m[error]\033[0m failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

usage() {
    cat <<EOF
NIDS installer (repository checkout on the Raspberry Pi)

Usage: sudo bash deploy/install.sh [options]

  --repo DIR         repository checkout to install (default: parent of deploy/)
  --prefix DIR       install root (default: /opt/nids)
  --port N           dashboard port (default: 8501)
  --interface NAME   capture interface (default: autodetect a wired port)
  --data-dir DIR     captures and flow CSVs (default: <prefix>/data)
  --llm-dir DIR      where the .pte and tokenizer live (default: <prefix>/models_llm)
  --download-llm     fetch the ExecuTorch model files from Hugging Face
  --runner PATH      prebuilt arm64 executorch_llama_runner to install
  --ntlflowlyzer DIR NTLFlowLyzer checkout to vendor (needed for pcap/live capture)
  --wheelhouse DIR   install Python wheels from DIR instead of PyPI
  --no-start         install everything but do not enable/start the service
  --no-verify        skip the post-install verification pass
  --skip-apt         never touch apt (packages must already be installed)
  --dry-run          print what would happen, change nothing
  --uninstall        stop and remove the service and <prefix>
  --purge            with --uninstall: also remove /etc/nids
  --keep-data        with --uninstall: keep <data-dir>
  -h, --help         this text

The installer needs network access for apt and pip. Pass --wheelhouse with a
folder of pre-downloaded wheels (built for this Python and aarch64) to install
the Python side offline.

The ExecuTorch model files are about 1 GB and are never in git. Either pass
--download-llm, or put them in models_llm/ in this checkout, or point
--llm-dir at a folder that already has them. Without them the dashboard still
detects and classifies, but explanations use the evidence-packet fallback.
EOF
}

# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------
ORIGINAL_ARGS=("$@")
while (( $# )); do
    case "$1" in
        --repo)          REPO_ROOT=${2:?--repo needs a value}; shift 2 ;;
        --prefix)        PREFIX=${2:?--prefix needs a value}; shift 2 ;;
        --port)          PORT=${2:?--port needs a value}; shift 2 ;;
        --interface)     INTERFACE=${2:?--interface needs a value}; shift 2 ;;
        --data-dir)      DATA_DIR=${2:?--data-dir needs a value}; shift 2 ;;
        --llm-dir)       LLM_DIR=${2:?--llm-dir needs a value}; shift 2 ;;
        --download-llm)  DOWNLOAD_LLM=1; shift ;;
        --runner)        RUNNER_SRC=${2:?--runner needs a value}; shift 2 ;;
        --ntlflowlyzer)  NTLFLOWLYZER_SRC=${2:?--ntlflowlyzer needs a value}; shift 2 ;;
        --wheelhouse)    WHEELHOUSE=${2:?--wheelhouse needs a value}; shift 2 ;;
        --no-start)      DO_START=0; shift ;;
        --no-verify)     DO_VERIFY=0; shift ;;
        --skip-apt)      APT_MODE=skip; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        --uninstall)     DO_UNINSTALL=1; shift ;;
        --purge)         PURGE=1; shift ;;
        --keep-data)     KEEP_DATA=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "unknown option: $1 (see --help)" ;;
    esac
done

REPO_ROOT=$(cd -- "$REPO_ROOT" 2>/dev/null && pwd) || \
    die "--repo does not exist: $REPO_ROOT"
DEPLOY_DIR=$REPO_ROOT/deploy

DATA_DIR=${DATA_DIR:-$PREFIX/data}
LLM_DIR=${LLM_DIR:-$PREFIX/models_llm}
ENV_FILE=$ENV_DIR/nids.env
REPO_LLM_DIR=$REPO_ROOT/models_llm

#: The three files the ExecuTorch backend needs, relative to the model repo.
LLM_REPO=experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch
LLM_FILES=(
    xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte
    tokenizer.json
    xnnpack/config.json
)

[[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || \
    die "--port must be a number between 1 and 65535 (got '$PORT')"

if [[ ${EUID} -ne 0 ]]; then
    if (( DRY_RUN )); then
        warn "running --dry-run without root: nothing will be changed"
    else
        log "Root is required; re-running with sudo"
        exec sudo bash "$SELF" "${ORIGINAL_ARGS[@]}"
    fi
fi

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
detect_interface() {
    local iface
    # Wired interfaces first (eth0, end0, enp*, eno*).
    for pattern in '^end[0-9]' '^eth[0-9]' '^enp' '^eno'; do
        iface=$(ip -o link show up 2>/dev/null |
            awk -F': ' '{print $2}' |
            grep -E "$pattern" | head -n1 || true)
        [[ -n $iface ]] && { printf '%s\n' "$iface"; return 0; }
    done
    return 0
}

repo_commit() {
    git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || printf 'unknown\n'
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
uninstall() {
    log "Removing the NIDS service"
    if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
        run systemctl disable --now "$SERVICE_NAME" || warn "service was not running"
    fi
    run rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    run systemctl daemon-reload || true
    if (( DRY_RUN == 0 )); then
        rm -rf "$PREFIX/app" "$PREFIX/venv" "$PREFIX/bin" "$PREFIX/vendor"
        if [[ $LLM_DIR == "$PREFIX/models_llm" ]]; then
            rm -rf "$PREFIX/models_llm"
        fi
        (( KEEP_DATA )) || rm -rf "$DATA_DIR"
        rmdir "$PREFIX" 2>/dev/null || true
    fi
    if (( PURGE )); then
        run rm -rf "$ENV_DIR"
    else
        log "Kept $ENV_DIR (use --purge to remove it)"
    fi
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        warn "system user '$SERVICE_USER' was left in place (harmless)"
    fi
    log "Uninstalled"
}

if (( DO_UNINSTALL )); then
    uninstall
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. preflight
# ---------------------------------------------------------------------------
preflight() {
    log "Checking the repository checkout"

    local required=(
        app.py
        config.py
        pipeline.py
        models/detector.joblib
        models/classifier.joblib
        explain/knowledge/attacks.json
        explain/knowledge/feature_info.json
        deploy/requirements-pi.txt
        deploy/nids.service
        deploy/nids.env.example
        deploy/verify.sh
    )
    local missing=() item
    for item in "${required[@]}"; do
        [[ -e $REPO_ROOT/$item ]] || missing+=("$item")
    done
    if (( ${#missing[@]} )); then
        die "$REPO_ROOT is not a complete NIDS checkout; missing: ${missing[*]}"
    fi
    log "Source: $REPO_ROOT (commit $(repo_commit))"

    local arch
    arch=$(uname -m)
    [[ $arch == "aarch64" ]] || \
        warn "this is $arch, not aarch64: the ExecuTorch .pte only runs on 64-bit ARM"

    local os_id=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        os_id=${ID:-}${VERSION_ID:+-$VERSION_ID}
    fi
    log "OS: ${os_id:-unknown}, kernel $(uname -r), machine $arch"
    case "$os_id" in
        raspbian-*|debian-*|ubuntu-*) : ;;
        *) warn "expected Ubuntu / Debian; continuing anyway" ;;
    esac

    command -v python3 >/dev/null || die "python3 is missing (sudo apt install python3)"
    local pyver
    pyver=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
    local py_major=${pyver%%.*}
    local py_minor=${pyver#*.}
    if (( py_major < 3 || (py_major == 3 && py_minor < 12) )); then
        die "Python $pyver is too old: the pinned numpy, xgboost and shap need
3.12 or newer. Ubuntu desktop 24.04 LTS (Python 3.12) is the supported image."
    fi
    log "Python: $pyver"

    if [[ -n $WHEELHOUSE ]]; then
        [[ -d $WHEELHOUSE ]] || die "--wheelhouse is not a directory: $WHEELHOUSE"
        compgen -G "$WHEELHOUSE/*.whl" >/dev/null || \
            die "no .whl files in --wheelhouse $WHEELHOUSE"
    fi
    if [[ -n $RUNNER_SRC && ! -f $RUNNER_SRC ]]; then
        die "--runner does not exist: $RUNNER_SRC"
    fi
    if [[ -n $NTLFLOWLYZER_SRC && ! -f $NTLFLOWLYZER_SRC/NTLFlowLyzer/__main__.py ]]; then
        die "--ntlflowlyzer $NTLFLOWLYZER_SRC does not look like an NTLFlowLyzer checkout"
    fi

    local avail_mb
    avail_mb=$(df -Pk "$(dirname "$PREFIX")" 2>/dev/null | awk 'NR==2 {print int($4/1024)}')
    local want_mb=800
    if (( DOWNLOAD_LLM )) || compgen -G "$REPO_LLM_DIR/*" >/dev/null; then
        want_mb=2800
    fi
    if [[ -n ${avail_mb:-} ]] && (( avail_mb < want_mb )); then
        warn "only ${avail_mb} MiB free on $(dirname "$PREFIX"); ${want_mb} MiB recommended"
    fi
}

# ---------------------------------------------------------------------------
# 2. Debian packages
# ---------------------------------------------------------------------------
install_packages() {
    local packages=(python3-venv python3-pip libgomp1 libpcap0.8 wireshark-common ca-certificates)

    if [[ $APT_MODE == skip ]]; then
        warn "--skip-apt: assuming ${packages[*]} are already installed"
    else
        log "Installing Debian packages"
        # The wireshark-common question about non-superuser capture is answered
        # by setcap below; keep apt from waiting for an answer.
        run env DEBIAN_FRONTEND=noninteractive apt-get update -qq || \
            die "apt-get update failed; check the Pi's network or pass --skip-apt"
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y \
            --no-install-recommends "${packages[@]}" || \
            die "apt-get install failed; fix the error above or pass --skip-apt"
    fi

    local package
    for package in python3-venv wireshark-common libgomp1; do
        if ! dpkg -s "$package" >/dev/null 2>&1; then
            warn "Debian package '$package' is not installed"
        fi
    done
}

# ---------------------------------------------------------------------------
# 3. user, directories, virtual environment
# ---------------------------------------------------------------------------
create_user() {
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "Creating system user '$SERVICE_USER'"
        run useradd --system --create-home --home-dir "/var/lib/$SERVICE_USER" \
            --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    getent group wireshark >/dev/null 2>&1 && \
        run usermod -aG wireshark "$SERVICE_USER" || true
    run install -d -m 0755 "$PREFIX"
    run install -d -m 0755 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
    run install -d -m 0755 "$PREFIX/bin"
}

create_venv() {
    if [[ -x $PREFIX/venv/bin/python ]]; then
        local existing
        existing=$("$PREFIX/venv/bin/python" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
        local current
        current=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
        if [[ $existing != "$current" ]]; then
            die "$PREFIX/venv was built with Python $existing but this OS has $current.
Remove it and run the installer again:  sudo rm -rf $PREFIX/venv"
        fi
        log "Reusing the virtual environment in $PREFIX/venv"
    else
        log "Creating the virtual environment in $PREFIX/venv"
        run python3 -m venv "$PREFIX/venv"
    fi
}

install_python_deps() {
    local pip="$PREFIX/venv/bin/python"
    local -a common=(--no-cache-dir --disable-pip-version-check)

    if [[ -n $WHEELHOUSE ]]; then
        log "Installing pinned Python packages from $WHEELHOUSE"
        run "$pip" -m pip install "${common[@]}" --no-index \
            --find-links "$WHEELHOUSE" -r "$DEPLOY_DIR/requirements-pi.txt" || \
            die "the offline wheel install failed. Check that $WHEELHOUSE holds
aarch64 wheels for Python $(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')."
    else
        log "Installing pinned Python packages from PyPI"
        run "$pip" -m pip install "${common[@]}" \
            -r "$DEPLOY_DIR/requirements-pi.txt" || \
            die "pip install failed (network, or a version missing for this Python)"
    fi
}

install_application() {
    if [[ -d $PREFIX/app ]] && \
        [[ $(readlink -f "$REPO_ROOT") == "$(readlink -f "$PREFIX/app")" ]]; then
        log "The checkout is already installed in $PREFIX/app; leaving it in place"
        return
    fi
    log "Installing the application into $PREFIX/app"
    if (( DRY_RUN )); then
        printf '[dry-run] copy %s -> %s/app\n' "$REPO_ROOT" "$PREFIX"
        return
    fi
    rm -rf "$PREFIX/app.new"
    install -d -m 0755 "$PREFIX/app.new"
    # Copy the checkout without generated data, caches, or the LLM binaries.
    tar -C "$REPO_ROOT" \
        --exclude='./.git' \
        --exclude='./.venv' \
        --exclude='./.pytest_cache' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        --exclude='./capture/pcaps' \
        --exclude='./capture/flows' \
        --exclude='./capture/archive' \
        --exclude='./capture/testdata' \
        --exclude='./models_llm' \
        --exclude='./deploy/out' \
        --exclude='./bench/output' \
        --exclude='*.pcap' \
        --exclude='*.pcapng' \
        --exclude='*.log' \
        -cf - . | tar -C "$PREFIX/app.new" -xf -
    rm -rf "$PREFIX/app"
    mv "$PREFIX/app.new" "$PREFIX/app"
    chown -R root:root "$PREFIX/app"
    chmod -R u=rwX,go=rX "$PREFIX/app"
    chmod +x "$PREFIX/app/deploy/"*.sh 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 4. NTLFlowLyzer, ExecuTorch, LLM files
# ---------------------------------------------------------------------------
NTLFLOWLYZER_VALUE=ntlflowlyzer

install_ntlflowlyzer() {
    if [[ -n $NTLFLOWLYZER_SRC ]]; then
        log "Installing the NTLFlowLyzer checkout from $NTLFLOWLYZER_SRC"
        if (( DRY_RUN )); then
            printf '[dry-run] copy %s -> %s/vendor/NTLFlowLyzer\n' \
                "$NTLFLOWLYZER_SRC" "$PREFIX"
        else
            rm -rf "$PREFIX/vendor/NTLFlowLyzer"
            install -d -m 0755 "$PREFIX/vendor"
            cp -a "$NTLFLOWLYZER_SRC" "$PREFIX/vendor/NTLFlowLyzer"
            chown -R root:root "$PREFIX/vendor"
        fi
        NTLFLOWLYZER_VALUE=$PREFIX/vendor/NTLFlowLyzer
    elif [[ -x $PREFIX/venv/bin/ntlflowlyzer ]]; then
        log "Using the NTLFlowLyzer already installed in the venv"
        NTLFLOWLYZER_VALUE=$PREFIX/venv/bin/ntlflowlyzer
    else
        warn "NTLFlowLyzer is not installed."
        warn "Live capture and pcap replay will fail; CSV mode still works."
        warn "Re-run with --ntlflowlyzer /path/to/NTLFlowLyzer, or install it in"
        warn "$PREFIX/venv and set NIDS_NTLFLOWLYZER in $ENV_FILE"
    fi
}

install_runner() {
    local source=$RUNNER_SRC
    [[ -n $source ]] || source=$REPO_ROOT/bin/executorch_llama_runner
    if [[ -f $source ]]; then
        log "Installing the ExecuTorch runner"
        run install -m 0755 "$source" "$PREFIX/bin/executorch_llama_runner"
        local runner_dir
        runner_dir=$(dirname "$source")
        if [[ -f $runner_dir/libllama_runner.so ]]; then
            run install -m 0755 "$runner_dir/libllama_runner.so" "$PREFIX/bin/libllama_runner.so"
        elif [[ -f $PREFIX/bin/libllama_runner.so ]]; then
            log "Keeping the existing $PREFIX/bin/libllama_runner.so"
        else
            warn "libllama_runner.so was not found next to $source or in $PREFIX/bin"
            warn "The runner may fail to start; check with deploy/verify.sh --smoke"
        fi
    elif [[ -x $PREFIX/bin/executorch_llama_runner ]]; then
        log "Using the ExecuTorch runner already installed in $PREFIX/bin"
    else
        warn "No ExecuTorch runner was given."
        warn "Explanations still appear, but they come from the evidence-packet"
        warn "fallback until you build one (deploy/build_executorch_runner.sh)"
        warn "or pass --runner /path/to/executorch_llama_runner."
    fi
}

download_llm_files() {
    if (( DRY_RUN )); then
        printf '[dry-run] hf download %s %s --local-dir %s\n' \
            "$LLM_REPO" "${LLM_FILES[*]}" "$LLM_DIR"
        return 0
    fi
    local hf="$PREFIX/venv/bin/hf"
    if [[ ! -x $hf ]]; then
        die "huggingface_hub is not installed in $PREFIX/venv, so --download-llm
cannot run. Install the pinned requirements first (the installer does that),
or copy the files into $LLM_DIR by hand."
    fi
    log "Downloading the ExecuTorch model files into $LLM_DIR (about 1 GB)"
    install -d -m 0755 "$LLM_DIR"
    "$hf" download "$LLM_REPO" "${LLM_FILES[@]}" --local-dir "$LLM_DIR" || \
        die "the Hugging Face download failed (see the output above)"
}

copy_llm_files_from_repo() {
    if [[ ! -d $REPO_LLM_DIR ]] || (( DOWNLOAD_LLM )); then
        return 0
    fi
    if [[ -d $LLM_DIR ]] && \
        [[ $(readlink -f "$REPO_LLM_DIR") == "$(readlink -f "$LLM_DIR")" ]]; then
        return 0
    fi
    local name
    for name in "${LLM_FILES[@]}"; do
        [[ -f $REPO_LLM_DIR/$name ]] || return 0
    done
    log "Copying the ExecuTorch model files from $REPO_LLM_DIR into $LLM_DIR"
    if (( DRY_RUN )); then
        printf '[dry-run] copy %s/* -> %s\n' "$REPO_LLM_DIR" "$LLM_DIR"
        return 0
    fi
    install -d -m 0755 "$LLM_DIR"
    for name in "${LLM_FILES[@]}"; do
        if [[ -f $LLM_DIR/$name && $(stat -c %s "$REPO_LLM_DIR/$name") -eq $(stat -c %s "$LLM_DIR/$name") ]]; then
            continue
        fi
        install -D -m 0644 "$REPO_LLM_DIR/$name" "$LLM_DIR/$name"
    done
    chown -R root:root "$LLM_DIR"
    chmod -R u=rwX,go=rX "$LLM_DIR"
}

install_llm_files() {
    if (( DOWNLOAD_LLM )); then
        download_llm_files
    fi
    copy_llm_files_from_repo

    if (( DRY_RUN )); then
        printf '[dry-run] check the three model files in %s\n' "$LLM_DIR"
        return 0
    fi

    local missing=() name
    for name in "${LLM_FILES[@]}"; do
        [[ -f $LLM_DIR/$name ]] || missing+=("$name")
    done
    if (( ${#missing[@]} )); then
        warn "The ExecuTorch model files are incomplete in $LLM_DIR:"
        warn "  missing: ${missing[*]}"
        warn "The dashboard will detect and classify, but explanations will use"
        warn "the evidence-packet fallback. Re-run with --download-llm, or copy"
        warn "these files from $LLM_REPO into $LLM_DIR:"
        warn "  ${LLM_FILES[*]}"
    else
        log "ExecuTorch model files are in place: $LLM_DIR"
    fi
}

# ---------------------------------------------------------------------------
# 5. capture permissions
# ---------------------------------------------------------------------------
allow_capture_without_root() {
    local dumpcap
    dumpcap=$(command -v dumpcap || true)
    if [[ -z $dumpcap ]]; then
        warn "dumpcap not found: live capture will fail until wireshark-common is installed"
        return
    fi
    log "Letting '$SERVICE_USER' capture packets without root"
    run setcap cap_net_raw,cap_net_admin+eip "$dumpcap" || \
        warn "setcap failed; check that the filesystem is not mounted nosuid"
    if (( DRY_RUN == 0 )); then
        printf '    dumpcap: %s (%s)\n' "$dumpcap" "$(getcap "$dumpcap" 2>/dev/null || echo 'no file capabilities')"
    fi
}

# ---------------------------------------------------------------------------
# 6. configuration and service
# ---------------------------------------------------------------------------
render_env() {
    local autostart=0
    [[ -n $INTERFACE ]] && autostart=1
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@PORT@|$PORT|g" \
        -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
        -e "s|@INTERFACE@|$INTERFACE|g" \
        -e "s|@LLM_DIR@|$LLM_DIR|g" \
        -e "s|@DATA_DIR@|$DATA_DIR|g" \
        -e "s|@NTLFLOWLYZER@|$NTLFLOWLYZER_VALUE|g" \
        -e "s|@AUTOSTART@|$autostart|g" \
        "$DEPLOY_DIR/nids.env.example"
}

write_config() {
    if [[ -z $INTERFACE ]]; then
        INTERFACE=$(detect_interface)
        [[ -n $INTERFACE ]] && log "Detected capture interface: $INTERFACE" || \
            warn "could not detect a wired interface; set NIDS_INTERFACE in $ENV_FILE"
    fi

    run install -d -m 0755 "$ENV_DIR"
    if [[ -f $ENV_FILE ]]; then
        log "Keeping the existing $ENV_FILE"
        # Report what is actually configured, not what we just detected.
        local configured
        configured=$(grep -E '^NIDS_INTERFACE=' "$ENV_FILE" | tail -n1 | cut -d= -f2-)
        INTERFACE=${configured:-$INTERFACE}
        if (( DRY_RUN == 0 )); then
            render_env > "$ENV_DIR/nids.env.dist"
            chmod 0644 "$ENV_DIR/nids.env.dist"
            if ! diff -q "$ENV_FILE" "$ENV_DIR/nids.env.dist" >/dev/null 2>&1; then
                warn "this checkout ships a newer template: $ENV_DIR/nids.env.dist"
                warn "diff it against $ENV_FILE if a setting looks missing"
            fi
        fi
    else
        log "Writing $ENV_FILE"
        if (( DRY_RUN )); then
            printf '[dry-run] render %s -> %s\n' "$DEPLOY_DIR/nids.env.example" "$ENV_FILE"
        else
            render_env > "$ENV_FILE"
            chmod 0640 "$ENV_FILE"
            chown root:"$SERVICE_USER" "$ENV_FILE"
        fi
    fi
}

write_service() {
    local target="/etc/systemd/system/$SERVICE_NAME.service"
    log "Installing $target"
    if (( DRY_RUN )); then
        printf '[dry-run] render %s -> %s\n' "$DEPLOY_DIR/nids.service" "$target"
        return
    fi
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@PORT@|$PORT|g" \
        -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
        "$DEPLOY_DIR/nids.service" > "$target"
    chmod 0644 "$target"
    systemctl daemon-reload
}

wait_for_health() {
    if (( DRY_RUN )); then
        printf '[dry-run] wait for http://127.0.0.1:%s/_stcore/health\n' "$PORT"
        return 0
    fi
    log "Waiting for the dashboard on port $PORT (first start loads both models)"
    local attempt
    for attempt in $(seq 1 90); do
        if "$PREFIX/venv/bin/python" - "$PORT" <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{sys.argv[1]}/_stcore/health", timeout=2
    ) as response:
        sys.exit(0 if response.read().strip() == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
        then
            log "Dashboard is up"
            return 0
        fi
        sleep 2
    done
    warn "the dashboard did not answer within 3 minutes"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
    return 1
}

start_service() {
    if (( DO_START )); then
        log "Enabling and starting $SERVICE_NAME.service"
        run systemctl enable --now "$SERVICE_NAME"
        wait_for_health || die "the service did not become healthy (logs above)"
    else
        log "--no-start: not starting the service"
    fi
}

verify_install() {
    (( DO_VERIFY )) || return 0
    (( DRY_RUN )) && return 0
    local script=$PREFIX/app/deploy/verify.sh
    if [[ -f $script ]]; then
        log "Running the post-install checks"
        run env NIDS_ENV_FILE="$ENV_FILE" NIDS_PREFIX="$PREFIX" \
            bash "$script" || warn "verification reported problems (see above)"
    else
        warn "verify.sh is missing from the installed application; skipped the health checks"
    fi
}

summary() {
    local address
    address=$(hostname -I 2>/dev/null | awk '{print $1}')
    local headline="NIDS is installed."
    (( DRY_RUN )) && headline="Dry run complete; nothing was changed."
    cat <<EOF

────────────────────────────────────────────────────────────────
 $headline

   Dashboard   http://${address:-<pi-address>}:$PORT
   Interface   ${INTERFACE:-not set -- edit $ENV_FILE}
   Config      $ENV_FILE
   Data        $DATA_DIR
   Models      $LLM_DIR
   Source      $REPO_ROOT (commit $(repo_commit))
   Logs        sudo journalctl -u $SERVICE_NAME -f
   Verify      sudo bash $PREFIX/app/deploy/verify.sh

 Next: open the dashboard, pick "Live capture" and press Start
 (skipped when NIDS_AUTOSTART=1, which the installer sets when an
 interface was detected).

 Update later:  cd $REPO_ROOT && git pull && sudo bash deploy/install.sh

 This install was NOT validated on real hardware before delivery: see
 "What is verified, and what is not" in $PREFIX/app/README.md.
────────────────────────────────────────────────────────────────
EOF
}

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
preflight
install_packages
create_user
create_venv
install_python_deps
install_application
install_ntlflowlyzer
install_runner
install_llm_files
allow_capture_without_root
write_config
write_service
start_service
verify_install
summary
