#!/usr/bin/env bash
# ===========================================================================
# Build the ExecuTorch 1.5.1 Llama runner (llama_main) for the Raspberry Pi 5.
#
# Three modes:
#
#   1. native build, ON the Pi (aarch64):
#        sudo bash build_executorch_runner.sh
#
#   2. cross build, on a Linux x86_64 machine (e.g. Ubuntu 22.04):
#        bash build_executorch_runner.sh --cross --out ./executorch_llama_runner
#      then copy the binary to the Pi and install it, or drop it in the
#      bundle's bin/ before installing.
#
#   3. install an already-built binary:
#        sudo bash build_executorch_runner.sh --runner /path/to/llama_main
#
# Why build on Ubuntu 22.04 instead of the Pi: the binary links against the
# build machine's glibc and libstdc++, so it must be built against an OLDER or
# equal C library than the Pi's.  Raspberry Pi OS Trixie ships glibc 2.41 /
# GCC 14; Ubuntu 22.04 (glibc 2.35 / GCC 11) and 24.04 (glibc 2.39 / GCC 13)
# are both safe, while anything newer than the Pi is not.  A cross build on a
# fast x86 box also takes minutes instead of the 1-3 hours a Pi 5 needs.
#
# The .pte was exported with ExecuTorch 1.5.1, so the runtime must be 1.5.1.
# Verify the version matches the model card before changing it.
#
# Verified against the upstream tree of tag v1.5.1: the runner example lives
# at examples/models/llama and produces the target `llama_main`; the core
# libraries must be configured and `install`ed first, because the example does
# `find_package(executorch CONFIG REQUIRED)`.
# TODO(open-question): the build has not been run end to end here (no aarch64
# or cross toolchain on the development machine).  If a flag has been renamed
# in the release you build, follow docs/source/llm/run-with-c-plus-plus.md for
# that tag; nothing else in this deployment depends on how the binary was made.
# ===========================================================================
set -Eeuo pipefail

EXECUTORCH_VERSION=${EXECUTORCH_VERSION:-v1.5.1}
EXECUTORCH_SRC=${EXECUTORCH_SRC:-/opt/executorch}
PREFIX=${NIDS_PREFIX:-/opt/nids}
JOBS=${JOBS:-$(nproc)}
CMAKE_MIN=3.26
AARCH64_MARCH=${AARCH64_MARCH:-armv8-a}

# Cross compiler prefix and optional sysroot.  The default is Ubuntu's
# aarch64-linux-gnu-g++; a relocatable toolchain such as Arm's
# arm-gnu-toolchain-*-aarch64-none-linux-gnu works too:
#   CROSS_COMPILE=aarch64-none-linux-gnu- bash build_executorch_runner.sh --cross
# CROSS_SYSROOT is only needed when the toolchain's sysroot is not where the
# compiler expects it (Arm's tarball does not need it).
CROSS_COMPILE=${CROSS_COMPILE:-aarch64-linux-gnu-}
CROSS_SYSROOT=${CROSS_SYSROOT:-}

PREBUILT=""
CROSS=0
OUT=""
ASSUME_DEPS=0
INSTALL_DEPS=1

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: bash build_executorch_runner.sh [options]

  --runner PATH   install an already-built runner binary instead of compiling
  --cross         build for aarch64 on a non-aarch64 host (does not install)
  --out PATH      where to put the cross-built binary (default: ./llama_main)
  --src DIR       ExecuTorch checkout (default: $EXECUTORCH_SRC)
  --version TAG   ExecuTorch git tag (default: $EXECUTORCH_VERSION, must be 1.5.1)
  --no-deps       do not install apt/pip dependencies
  -h, --help      this text

Environment for --cross: CROSS_COMPILE (compiler prefix, default
${CROSS_COMPILE}) and CROSS_SYSROOT (optional --sysroot for the target).

Native mode installs to $PREFIX/bin/executorch_llama_runner.
Cross mode writes the binary to --out and does not touch $PREFIX.
EOF
}

install_binary() {
    local binary=$1
    [[ -f $binary ]] || die "not a file: $binary"
    install -d -m 0755 "$PREFIX/bin"
    install -m 0755 "$binary" "$PREFIX/bin/executorch_llama_runner"
    log "Installed $PREFIX/bin/executorch_llama_runner"
    if [[ -n ${RUNNER_LIB:-} ]]; then
        install -m 0755 "$RUNNER_LIB" "$PREFIX/bin/libllama_runner.so"
        log "Installed $PREFIX/bin/libllama_runner.so"
    fi
    log "Now: sudo systemctl restart nids"
}

while (( $# )); do
    case "$1" in
        --runner)  PREBUILT=${2:?--runner needs a path}; shift 2 ;;
        --cross)   CROSS=1; shift ;;
        --out)     OUT=${2:?--out needs a path}; shift 2 ;;
        --src)     EXECUTORCH_SRC=${2:?--src needs a path}; shift 2 ;;
        --version) EXECUTORCH_VERSION=${2:?--version needs a tag}; shift 2 ;;
        --no-deps) INSTALL_DEPS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

if [[ -n $PREBUILT ]]; then
    install_binary "$PREBUILT"
    exit 0
fi

HOST_ARCH=$(uname -m)
if (( CROSS )); then
    [[ $HOST_ARCH != aarch64 ]] || die "--cross is for x86_64 hosts; build natively instead"
    [[ ${EUID} -ne 0 ]] || warn "cross mode does not need root; writing to $OUT as root is probably not what you want"
else
    [[ ${EUID} -eq 0 ]] || die "run this with sudo (native mode installs into $PREFIX)"
    [[ $HOST_ARCH == aarch64 ]] || die "this host is $HOST_ARCH, not aarch64; use --cross to build a Pi binary from x86_64"
fi

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
if (( INSTALL_DEPS )); then
    if (( CROSS )); then
        log "Installing cross-compilation dependencies"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            build-essential cmake git python3 python3-dev python3-pip \
            python3-venv g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
            unzip curl ca-certificates
    else
        log "Checking build dependencies"
        missing=()
        for tool in git cmake make g++ python3; do
            command -v "$tool" >/dev/null || missing+=("$tool")
        done
        if (( ${#missing[@]} )); then
            log "Installing ${missing[*]}"
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y --no-install-recommends git cmake make g++ \
                python3-dev python3-pip python3-venv libopenblas-dev libgomp1
        fi
    fi
fi

# Ubuntu 22.04 ships CMake 3.22, but the runner's CMakeLists requires >= 3.24.
check_cmake() {
    local want=$1
    if ! command -v cmake >/dev/null; then
        die "cmake is not installed"
    fi
    local have
    have=$(cmake -E capabilities 2>/dev/null | sed -n 's/.*"version":{"major":\([0-9]*\),"minor":\([0-9]*\).*/\1.\2/p' | head -n1)
    [[ -n $have ]] || have=$(cmake --version | head -n1 | awk '{print $3}' | cut -d. -f1,2)
    if printf '%s\n%s\n' "$want" "$have" | sort -V -C; then
        return 0
    fi
    die "cmake $have is too old (need >= $want). On Ubuntu 22.04:
       python3 -m pip install --user 'cmake>=3.26'   # or the Kitware apt repo
       then re-run with that cmake first on PATH"
}

# --------------------------------------------------------------------------
# ExecuTorch source
# --------------------------------------------------------------------------
if [[ ! -d $EXECUTORCH_SRC/.git ]]; then
    log "Cloning ExecuTorch $EXECUTORCH_VERSION into $EXECUTORCH_SRC"
    git clone --depth 1 --branch "$EXECUTORCH_VERSION" \
        https://github.com/pytorch/executorch.git "$EXECUTORCH_SRC"
else
    log "Reusing the ExecuTorch checkout at $EXECUTORCH_SRC"
fi

# The tokenizer support needs abseil-cpp and re2 as submodules; without them
# runner/CMakeLists.txt fails with "does not contain a CMakeLists.txt file".
log "Updating submodules (abseil-cpp, re2, XNNPACK, ... ; this takes a while)"
git -C "$EXECUTORCH_SRC" submodule sync --recursive
git -C "$EXECUTORCH_SRC" submodule update --init --recursive --depth 1

# --------------------------------------------------------------------------
# Host Python environment
#
# The C++ build runs code generation with the HOST python; it must be a native
# x86_64 / aarch64 interpreter even when cross-compiling, never the target's.
# --------------------------------------------------------------------------
VENV_DIR=$EXECUTORCH_SRC/.venv
if [[ ! -x $VENV_DIR/bin/python ]]; then
    log "Creating the build virtualenv"
    python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"
PYTHON=$VENV_DIR/bin/python

if (( INSTALL_DEPS )); then
    log "Installing the ExecuTorch Python package (host side, this takes a while)"
    pip install --upgrade pip
    ( cd "$EXECUTORCH_SRC" && ./install_executorch.sh --clean )
fi

check_cmake "$CMAKE_MIN"

# --------------------------------------------------------------------------
# Toolchain
# --------------------------------------------------------------------------
BUILD_DIR=$EXECUTORCH_SRC/cmake-out
CMAKE_EXTRA=()
if (( CROSS )); then
    command -v "${CROSS_COMPILE}g++" >/dev/null \
        || die "${CROSS_COMPILE}g++ is missing (apt install g++-aarch64-linux-gnu, or put a cross toolchain on PATH and set CROSS_COMPILE)"
    TOOLCHAIN=$BUILD_DIR/toolchain-aarch64.cmake
    install -d "$BUILD_DIR"
    {
        cat <<EOF
# Generated by deploy/build_executorch_runner.sh for ExecuTorch $EXECUTORCH_VERSION.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER ${CROSS_COMPILE}gcc)
set(CMAKE_CXX_COMPILER ${CROSS_COMPILE}g++)
set(CMAKE_C_FLAGS_INIT "-march=$AARCH64_MARCH")
set(CMAKE_CXX_FLAGS_INIT "-march=$AARCH64_MARCH")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
EOF
        if [[ -n $CROSS_SYSROOT ]]; then
            cat <<EOF
set(CMAKE_SYSROOT "$CROSS_SYSROOT")
EOF
        fi
    } > "$TOOLCHAIN"
    CMAKE_EXTRA=(-DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN")
    TARGET_DESC="aarch64 (cross, ${CROSS_COMPILE}g++, -march=$AARCH64_MARCH)"
else
    BUILD_DIR=$EXECUTORCH_SRC/cmake-out
    TARGET_DESC="aarch64 (native)"
fi

# --------------------------------------------------------------------------
# Build: core runtime first, then the Llama runner example
#
# Mirrors docs/source/llm/run-with-c-plus-plus.md + examples/models/llama/
# README.md "Step 3" for this tag.  The example links with
# find_package(executorch CONFIG REQUIRED), so `--target install` of the core
# libraries has to happen first.
# --------------------------------------------------------------------------
log "Configuring the ExecuTorch runtime libraries: $TARGET_DESC"
cmake -S "$EXECUTORCH_SRC" -B "$BUILD_DIR" \
    "${CMAKE_EXTRA[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$BUILD_DIR" \
    -DPYTHON_EXECUTABLE="$PYTHON" \
    -DEXECUTORCH_ENABLE_LOGGING=1 \
    -DEXECUTORCH_BUILD_EXTENSION_DATA_LOADER=ON \
    -DEXECUTORCH_BUILD_EXTENSION_FLAT_TENSOR=ON \
    -DEXECUTORCH_BUILD_EXTENSION_MODULE=ON \
    -DEXECUTORCH_BUILD_EXTENSION_TENSOR=ON \
    -DEXECUTORCH_BUILD_EXTENSION_NAMED_DATA_MAP=ON \
    -DEXECUTORCH_BUILD_EXTENSION_LLM=ON \
    -DEXECUTORCH_BUILD_EXTENSION_LLM_RUNNER=ON \
    -DEXECUTORCH_BUILD_XNNPACK=ON \
    -DEXECUTORCH_BUILD_KERNELS_OPTIMIZED=ON \
    -DEXECUTORCH_BUILD_KERNELS_QUANTIZED=ON \
    -DEXECUTORCH_BUILD_KERNELS_LLM=ON

log "Building and installing the core libraries (longest step)"
cmake --build "$BUILD_DIR" -j "$JOBS" --config Release --target install

LLAMA_DIR=$BUILD_DIR/examples/models/llama
log "Configuring the Llama runner: $TARGET_DESC"
cmake -S "$EXECUTORCH_SRC/examples/models/llama" -B "$LLAMA_DIR" \
    "${CMAKE_EXTRA[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$BUILD_DIR" \
    -DPYTHON_EXECUTABLE="$PYTHON" \
    -DEXECUTORCH_BUILD_XNNPACK=ON \
    -DEXECUTORCH_BUILD_KERNELS_OPTIMIZED=ON \
    -DEXECUTORCH_BUILD_KERNELS_QUANTIZED=ON \
    -DEXECUTORCH_BUILD_KERNELS_LLM=ON \
    -DSUPPORT_REGEX_LOOKAHEAD=ON

log "Building llama_main"
cmake --build "$LLAMA_DIR" -j "$JOBS" --config Release --target llama_main

BINARY=$(find "$LLAMA_DIR" -maxdepth 1 -type f -perm -u+x -name 'llama_main' | head -n1)
[[ -n $BINARY ]] || die "the build finished but llama_main was not found in $LLAMA_DIR"

# On Linux the example links llama_runner as a shared library, so the binary
# alone is not enough: libllama_runner.so must sit next to it (the link uses
# -rpath '$ORIGIN').  Both files are installed side by side.
RUNNER_LIB=$(find "$LLAMA_DIR" -type f -name 'libllama_runner.so*' | head -n1)
[[ -n $RUNNER_LIB ]] && log "Runner library: $RUNNER_LIB"

# --------------------------------------------------------------------------
# Verify the artefact really is an aarch64 Linux executable
# --------------------------------------------------------------------------
file "$BINARY"
if command -v readelf >/dev/null; then
    machine=$(readelf -h "$BINARY" | sed -n 's/^ *Machine: *//p')
    [[ $machine == *AArch64* ]] \
        || die "the binary is '$machine', not AArch64; the toolchain file was not applied"
    log "readelf confirms: $machine"
fi
if command -v "${CROSS_COMPILE}readelf" >/dev/null; then
    needs=$("${CROSS_COMPILE}readelf" -V "$BINARY" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n1)
    [[ -n $needs ]] && log "highest glibc symbol required: $needs (the Pi must ship at least this)"
fi

if (( CROSS )); then
    OUT=${OUT:-$PWD/llama_main}
    install -m 0755 "$BINARY" "$OUT"
    if [[ -n $RUNNER_LIB ]]; then
        install -m 0755 "$RUNNER_LIB" "$(dirname "$OUT")/libllama_runner.so"
        log "Also copy libllama_runner.so: the binary loads it from its own directory"
    fi
    log "Cross build done: $OUT"
    log "Next, on the Pi:  sudo bash install.sh --runner /media/\$USER/NIDS/llama_main"
    log "or copy it to the stick as bin/executorch_llama_runner before installing"
    exit 0
fi

install_binary "$BINARY"
