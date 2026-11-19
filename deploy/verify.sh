#!/usr/bin/env bash
# ===========================================================================
# Post-install health check for the NIDS Raspberry Pi appliance.
#
#   sudo bash verify.sh            # everything
#   sudo bash verify.sh --smoke    # also generate one sentence with the .pte
#
# Every check prints PASS/FAIL/SKIP and the script exits non-zero if anything
# failed.  Safe to run at any time; it only reads, except for the smoke test
# (which loads the model once).
# ===========================================================================
set -Euo pipefail

PREFIX=${NIDS_PREFIX:-/opt/nids}
ENV_FILE=${NIDS_ENV_FILE:-/etc/nids/nids.env}
SERVICE_NAME=nids
SERVICE_USER=nids
RUN_SMOKE=0

for arg in "$@"; do
    case "$arg" in
        --smoke) RUN_SMOKE=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

failures=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; failures=$((failures + 1)); }
skip() { printf '  \033[1;33mSKIP\033[0m  %s\n' "$*"; }
head() { printf '\n\033[1;34m%s\033[0m\n' "$*"; }

head "Installation"
[[ -d $PREFIX/app ]] && pass "application tree: $PREFIX/app" || fail "missing $PREFIX/app"
[[ -x $PREFIX/venv/bin/python ]] && pass "virtual environment: $PREFIX/venv" || fail "missing $PREFIX/venv"
[[ -f $ENV_FILE ]] && pass "configuration: $ENV_FILE" || fail "missing $ENV_FILE"

if [[ -f $ENV_FILE ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

head "Service"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    pass "$SERVICE_NAME.service is active"
else
    fail "$SERVICE_NAME.service is not active (journalctl -u $SERVICE_NAME -n 50)"
fi

port=${STREAMLIT_SERVER_PORT:-8501}
if "$PREFIX/venv/bin/python" - "$port" <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{sys.argv[1]}/_stcore/health", timeout=3
    ) as response:
        sys.exit(0 if response.read().strip() == b"ok" else 1)
except Exception:
    sys.exit(1)
PY
then
    pass "dashboard answers on port $port"
else
    fail "no healthy dashboard on port $port"
fi

head "Models and knowledge packet"
if ( cd "$PREFIX/app" && "$PREFIX/venv/bin/python" - <<'PY'
import sys

from config import get_settings
from explain.knowledge_base import load_knowledge_base
from models.loader import load_models

settings = get_settings()
models = load_models(settings)
knowledge = load_knowledge_base(settings.knowledge_dir)
print(
    f"      {models.detector.name}: {len(models.detector.feature_names)} features, "
    f"{len(models.classifier.classes)} attack classes, "
    f"{len(knowledge.attacks)} knowledge entries"
)
PY
); then
    pass "both models and the knowledge packet load"
else
    fail "models or knowledge packet failed to load"
fi

# This is the laptop-versus-Pi parity check: same 100 rows, same decisions.
head "Detector parity with the laptop fixture"
if ( cd "$PREFIX/app" && "$PREFIX/venv/bin/python" -m pytest -q \
        tests/test_parity.py tests/test_contract.py tests/test_knowledge.py ) >/tmp/nids-verify-pytest.log 2>&1; then
    pass "parity, feature contract and knowledge tests"
else
    fail "pytest failed; see /tmp/nids-verify-pytest.log"
    tail -n 20 /tmp/nids-verify-pytest.log | sed 's/^/      /'
fi

head "Packet capture without root"
if command -v dumpcap >/dev/null; then
    if sudo -u "$SERVICE_USER" dumpcap -D >/dev/null 2>&1; then
        pass "dumpcap works as '$SERVICE_USER'"
    else
        fail "dumpcap cannot run as '$SERVICE_USER' (setcap or wireshark group missing)"
    fi
else
    fail "dumpcap not installed (sudo apt install wireshark-common)"
fi

head "Flow extraction"
if ( cd "$PREFIX/app" && "$PREFIX/venv/bin/python" - <<'PY'
import sys

from config import get_settings
from features.ntlflowlyzer import _resolve

command, env = _resolve(get_settings().ntlflowlyzer_command)
print("      " + " ".join(command))
PY
); then
    pass "NTLFlowLyzer resolves"
else
    fail "NTLFlowLyzer not found; live capture will not work"
fi

head "Explanation backend"
if ( cd "$PREFIX/app" && "$PREFIX/venv/bin/python" - <<'PY'
import sys

from config import get_settings
from explain.llm import build_backend

backend = build_backend(get_settings())
status = getattr(backend, "status", lambda: None)()
print(f"      backend={backend.name} ready={getattr(status, 'ready', '?')}")
if status is not None and not status.ready:
    print(f"      {status.detail}")
sys.exit(0 if status is None or status.ready else 1)
PY
); then
    pass "configured backend is ready"
else
    skip "the backend is not ready; alerts use the evidence-packet fallback text"
fi

if (( RUN_SMOKE )); then
    head "ExecuTorch smoke test (one sentence from the .pte)"
    if ( cd "$PREFIX/app" && "$PREFIX/venv/bin/python" -m bench.llm_smoke ); then
        pass "the model generated a correct sentence"
    else
        fail "the .pte did not answer correctly; do not trust LLM text yet"
    fi
fi

printf '\n'
if (( failures )); then
    printf '\033[1;31m%d check(s) failed\033[0m\n' "$failures"
    exit 1
fi
printf '\033[1;32mAll checks passed\033[0m\n'
