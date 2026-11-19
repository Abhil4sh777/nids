#!/usr/bin/env bash
# ===========================================================================
# NIDS offline installer for Raspberry Pi OS (64-bit) on a Raspberry Pi 5.
#
#   Plug the USB stick in, find where it is mounted, then:
#
#       sudo bash /media/$USER/NIDS/install.sh
#
# What it does, in order:
#   1. verifies every file on the stick against MANIFEST.sha256
#   2. checks the board, the OS architecture and the Python version
#   3. installs the few Debian packages needed (from debs/ when present)
#   4. creates a dedicated 'nids' system user and a virtual environment
#   5. installs the pinned wheels offline (no network needed)
#   6. copies the application, the models and the ExecuTorch files
#   7. lets the service user run dumpcap without root
#   8. writes /etc/nids/nids.env (never overwritten on re-runs)
#   9. installs and starts the systemd service, then waits for the dashboard
#
# Re-running it upgrades the application and keeps the existing configuration.
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
APT_MODE=auto
ONLINE=0
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
NIDS offline installer

Usage: sudo bash install.sh [options]

  --prefix DIR       install root (default: /opt/nids)
  --port N           dashboard port (default: 8501)
  --interface NAME   capture interface (default: autodetect a wired port)
  --data-dir DIR     captures and flow CSVs (default: <prefix>/data)
  --llm-dir DIR      where the .pte and tokenizer live (default: <prefix>/models_llm)
  --runner PATH      prebuilt arm64 executorch_llama_runner to install
  --no-start         install everything but do not enable/start the service
  --no-verify        skip the post-install verification pass
  --online           allow apt/pip to use the network if the stick is incomplete
  --skip-apt         never touch apt (packages must already be installed)
  --dry-run          print what would happen, change nothing
  --uninstall        stop and remove the service and <prefix>
  --purge            with --uninstall: also remove /etc/nids
  --keep-data        with --uninstall: keep <data-dir>
  -h, --help         this text

Offline by default: wheels come from wheels/, Debian packages from debs/ when
present, and the ExecuTorch files from models_llm/. Nothing is downloaded
unless you pass --online (or the bundle was built with --no-wheels).
EOF
}

# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------
while (( $# )); do
    case "$1" in
        --prefix)      PREFIX=${2:?--prefix needs a value}; shift 2 ;;
        --port)        PORT=${2:?--port needs a value}; shift 2 ;;
        --interface)   INTERFACE=${2:?--interface needs a value}; shift 2 ;;
        --data-dir)    DATA_DIR=${2:?--data-dir needs a value}; shift 2 ;;
        --llm-dir)     LLM_DIR=${2:?--llm-dir needs a value}; shift 2 ;;
        --runner)      RUNNER_SRC=${2:?--runner needs a value}; shift 2 ;;
        --no-start)    DO_START=0; shift ;;
        --no-verify)   DO_VERIFY=0; shift ;;
        --online)      ONLINE=1; APT_MODE=online; shift ;;
        --skip-apt)    APT_MODE=skip; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --uninstall)   DO_UNINSTALL=1; shift ;;
        --purge)       PURGE=1; shift ;;
        --keep-data)   KEEP_DATA=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             die "unknown option: $1 (see --help)" ;;
    esac
done

DATA_DIR=${DATA_DIR:-$PREFIX/data}
LLM_DIR=${LLM_DIR:-$PREFIX/models_llm}
ENV_FILE=$ENV_DIR/nids.env

[[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || \
    die "--port must be a number between 1 and 65535 (got '$PORT')"

if [[ ${EUID} -ne 0 ]]; then
    (( DRY_RUN )) || log "Root is required; re-running with sudo"
    exec sudo bash "$SELF" "$@"
fi

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
json_get() {
    # Read one top-level key from the bundle marker without needing jq.
    python3 - "$1" "$2" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, ValueError):
    sys.exit(0)
value = data.get(sys.argv[2])
if value is not None:
    print(value)
PY
}

detect_interface() {
    local iface
    # Wired interfaces first (eth0 on Bookworm, end0/enp*/eno* on Trixie).
    for pattern in '^end[0-9]' '^eth[0-9]' '^enp' '^eno'; do
        iface=$(ip -o link show up 2>/dev/null |
            awk -F': ' '{print $2}' |
            grep -E "$pattern" | head -n1 || true)
        [[ -n $iface ]] && { printf '%s\n' "$iface"; return 0; }
    done
    return 0
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
        [[ -d $PREFIX/app ]] && rm -rf "$PREFIX/app"
        [[ -d $PREFIX/venv ]] && rm -rf "$PREFIX/venv"
        [[ -d $PREFIX/bin ]] && rm -rf "$PREFIX/bin"
        [[ -d $PREFIX/models_llm && $LLM_DIR == "$PREFIX/models_llm" ]] && rm -rf "$PREFIX/models_llm"
        [[ -d $PREFIX/vendor ]] && rm -rf "$PREFIX/vendor"
        (( KEEP_DATA )) || rm -rf "$DATA_DIR"
        rmdir "$PREFIX" 2>/dev/null || true
    fi
    if (( PURGE )); then
        run rm -rf "$ENV_DIR"
    else
        log "Kept $ENV_DIR (use --purge to remove it)"
    fi
    id -u "$SERVICE_USER" >/dev/null 2>&1 && \
        warn "system user '$SERVICE_USER' was left in place (harmless)"
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
    log "Checking the bundle"

    [[ -f $SELF_DIR/BUNDLE.json ]] || \
        die "$SELF_DIR/BUNDLE.json is missing: this does not look like a NIDS bundle"
    [[ -f $SELF_DIR/app/requirements.txt ]] || \
        die "$SELF_DIR/app is missing: rebuild the bundle with deploy/make_bundle.py"
    [[ -f $SELF_DIR/install.sh ]] || die "$SELF_DIR/install.sh is missing"

    local arch
    arch=$(uname -m)
    [[ $arch == "aarch64" ]] || \
        warn "this is $arch, not aarch64: the bundled wheels are built for 64-bit ARM"

    local os_id=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        os_id=${ID:-}${VERSION_ID:+-$VERSION_ID}
    fi
    log "OS: ${os_id:-unknown}, kernel $(uname -r), machine $arch"
    case "$os_id" in
        raspbian-*|debian-*|ubuntu-*) : ;;
        *) warn "expected Raspberry Pi OS / Debian; continuing anyway" ;;
    esac

    command -v python3 >/dev/null || die "python3 is missing (sudo apt install python3)"
    local pyver
    pyver=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
    local py_major=${pyver%%.*}
    local py_minor=${pyver#*.}
    if (( py_major < 3 || (py_major == 3 && py_minor < 12) )); then
        die "Python $pyver is too old: the pinned numpy, xgboost and shap need
3.12 or newer. Raspberry Pi OS Trixie (Python 3.13) is the supported image."
    fi
    local want_py
    want_py=$(json_get "$SELF_DIR/BUNDLE.json" python_version)
    log "Python: $pyver (bundle built for ${want_py:-unknown})"
    if [[ -n $want_py && $pyver != "$want_py" ]]; then
        die "this bundle holds wheels for Python $want_py but the Pi runs $pyver.
Rebuild it on the development machine with:
    python -m deploy.make_bundle --output <usb> --python-version $pyver --abi cp${pyver/./} --with-llm ..."
    fi

    if [[ -f $SELF_DIR/MANIFEST.sha256 ]]; then
        log "Verifying file integrity (this can take a minute)"
        ( cd "$SELF_DIR" && sha256sum -c --quiet MANIFEST.sha256 ) || \
            die "the bundle is corrupt (see the FAILED lines above). Copy it again."
    else
        warn "no MANIFEST.sha256 in the bundle; skipping the integrity check"
    fi

    local avail_mb
    avail_mb=$(df -Pk "$(dirname "$PREFIX")" 2>/dev/null | awk 'NR==2 {print int($4/1024)}')
    local want_mb=800
    [[ -d $SELF_DIR/models_llm ]] && want_mb=2800
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
        return
    fi

    if compgen -G "$SELF_DIR/debs/*.deb" >/dev/null; then
        log "Installing bundled Debian packages"
        if ! run apt-get install -y --no-install-recommends "$SELF_DIR"/debs/*.deb; then
            warn "apt could not install the bundled debs; trying dpkg directly"
            run dpkg -i "$SELF_DIR"/debs/*.deb || \
                warn "dpkg failed; run 'sudo apt-get -f install' once you are online"
        fi
    elif (( ONLINE )); then
        log "Installing Debian packages from the network"
        run apt-get update -qq
        run apt-get install -y --no-install-recommends "${packages[@]}"
    else
        warn "no debs/ in the bundle and --online was not given: assuming packages exist."
        warn "Missing pieces will show up in the verification step."
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

    if compgen -G "$SELF_DIR/wheels/*.whl" >/dev/null; then
        log "Installing Python wheels offline ($(find "$SELF_DIR/wheels" -name '*.whl' | wc -l) files)"
        run "$pip" -m pip install "${common[@]}" --no-index \
            --find-links "$SELF_DIR/wheels" -r "$SELF_DIR/app/requirements.txt" || \
            die "offline wheel install failed. The usual cause is a Python
version mismatch (see the error above); rebuilding the bundle for this
Python fixes it. Pass --online to install from PyPI instead."
        run "$pip" -m pip install "${common[@]}" --no-index \
            --find-links "$SELF_DIR/wheels" -r "$SELF_DIR/requirements-extras.txt" || \
            warn "could not install dpkt/multipledispatch; pcap extraction will not work"
    else
        (( ONLINE )) || die "no wheels/ in the bundle. Rebuild with wheels, or pass --online."
        log "Installing Python packages from the network"
        run "$pip" -m pip install "${common[@]}" -r "$SELF_DIR/app/requirements.txt" || \
            die "pip install failed (network, or a version missing for this Python)"
        run "$pip" -m pip install "${common[@]}" -r "$SELF_DIR/requirements-extras.txt" || \
            warn "could not install dpkt/multipledispatch"
    fi
}

install_application() {
    log "Installing the application into $PREFIX/app"
    if (( DRY_RUN )); then
        printf '[dry-run] copy %s/app -> %s/app\n' "$SELF_DIR" "$PREFIX"
        return
    fi
    rm -rf "$PREFIX/app.new"
    cp -a "$SELF_DIR/app" "$PREFIX/app.new"
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
    if [[ -d $SELF_DIR/vendor/NTLFlowLyzer/NTLFlowLyzer ]]; then
        log "Installing the bundled NTLFlowLyzer checkout"
        if (( DRY_RUN )); then
            printf '[dry-run] copy vendor/NTLFlowLyzer -> %s/vendor/NTLFlowLyzer\n' "$PREFIX"
        else
            rm -rf "$PREFIX/vendor/NTLFlowLyzer"
            install -d -m 0755 "$PREFIX/vendor"
            cp -a "$SELF_DIR/vendor/NTLFlowLyzer" "$PREFIX/vendor/NTLFlowLyzer"
            chown -R root:root "$PREFIX/vendor"
        fi
        NTLFLOWLYZER_VALUE=$PREFIX/vendor/NTLFlowLyzer
    elif [[ -x $PREFIX/venv/bin/ntlflowlyzer ]]; then
        log "Using the NTLFlowLyzer already installed in the venv"
        NTLFLOWLYZER_VALUE=$PREFIX/venv/bin/ntlflowlyzer
    else
        warn "NTLFlowLyzer is not in the bundle and not installed."
        warn "Live capture and pcap replay will fail; CSV mode still works."
        warn "Install it later, then edit NIDS_NTLFLOWLYZER in $ENV_FILE"
    fi
}

install_runner() {
    local source=$RUNNER_SRC
    [[ -n $source ]] || source=$SELF_DIR/bin/executorch_llama_runner
    if [[ -f $source ]]; then
        log "Installing the ExecuTorch runner"
        run install -m 0755 "$source" "$PREFIX/bin/executorch_llama_runner"
        local runner_dir
        runner_dir=$(dirname "$source")
        if [[ -f $runner_dir/libllama_runner.so ]]; then
            run install -m 0755 "$runner_dir/libllama_runner.so" "$PREFIX/bin/libllama_runner.so"
        elif [[ -f $SELF_DIR/bin/libllama_runner.so ]]; then
            run install -m 0755 "$SELF_DIR/bin/libllama_runner.so" "$PREFIX/bin/libllama_runner.so"
        fi
    else
        warn "No ExecuTorch runner in the bundle."
        warn "Expansions still appear, but they come from the evidence-packet"
        warn "fallback until you build one (deploy/build_executorch_runner.sh)."
    fi
}

install_llm_files() {
    if [[ ! -d $SELF_DIR/models_llm ]]; then
        warn "No models_llm/ in the bundle: the dashboard will use the fallback text."
        return
    fi
    log "Installing ExecuTorch model files into $LLM_DIR (about 1 GB)"
    if (( DRY_RUN )); then
        printf '[dry-run] copy models_llm/* -> %s\n' "$LLM_DIR"
        return
    fi
    install -d -m 0755 "$LLM_DIR"
    local src rel
    while IFS= read -r -d '' src; do
        rel=${src#"$SELF_DIR/models_llm/"}
        if [[ -f $LLM_DIR/$rel && $(stat -c %s "$src") -eq $(stat -c %s "$LLM_DIR/$rel") ]]; then
            continue
        fi
        install -D -m 0644 "$src" "$LLM_DIR/$rel"
    done < <(find "$SELF_DIR/models_llm" -type f -print0)
    chown -R root:root "$LLM_DIR"
    chmod -R u=rwX,go=rX "$LLM_DIR"
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
        "$SELF_DIR/nids.env.example"
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
                warn "the bundle ships a newer template: $ENV_DIR/nids.env.dist"
                warn "diff it against $ENV_FILE if a setting looks missing"
            fi
        fi
    else
        log "Writing $ENV_FILE"
        if (( DRY_RUN )); then
            printf '[dry-run] render %s -> %s\n' "$SELF_DIR/nids.env.example" "$ENV_FILE"
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
        printf '[dry-run] render %s -> %s\n' "$SELF_DIR/nids.service" "$target"
        return
    fi
    sed -e "s|@PREFIX@|$PREFIX|g" \
        -e "s|@PORT@|$PORT|g" \
        -e "s|@SERVICE_USER@|$SERVICE_USER|g" \
        "$SELF_DIR/nids.service" > "$target"
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
    # Run it through bash: USB sticks are FAT/exFAT, so the execute bit is not
    # guaranteed to exist here.
    if [[ -f $SELF_DIR/verify.sh ]]; then
        log "Running the post-install checks"
        run env NIDS_ENV_FILE="$ENV_FILE" NIDS_PREFIX="$PREFIX" \
            bash "$SELF_DIR/verify.sh" || warn "verification reported problems (see above)"
    else
        warn "verify.sh is missing from the bundle; skipped the health checks"
    fi
}

summary() {
    local address
    address=$(hostname -I 2>/dev/null | awk '{print $1}')
    cat <<EOF

────────────────────────────────────────────────────────────────
 NIDS is installed.

   Dashboard   http://${address:-<pi-address>}:$PORT
   Interface   ${INTERFACE:-not set -- edit $ENV_FILE}
   Config      $ENV_FILE
   Data        $DATA_DIR
   Models      $LLM_DIR
   Logs        sudo journalctl -u $SERVICE_NAME -f
   Verify      sudo bash $SELF_DIR/verify.sh

 Next: open the dashboard, pick "Live capture" and press Start
 (skipped when NIDS_AUTOSTART=1, which the installer sets when an
 interface was detected).

 This bundle was NOT validated on real hardware before delivery: see
 "What is verified, and what is not" in app/README.md.
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
