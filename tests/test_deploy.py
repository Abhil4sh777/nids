"""Tests for the repository-based Raspberry Pi deployment (deploy/).

These pin the things that silently break an installation on a machine we are
not sitting in front of: a CRLF shell script, an environment key that no longer
exists in ``config.py``, a placeholder that the installer never renders, a
systemd unit that no longer starts the app, or documentation that still points
at the removed USB bundle.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from config import Settings

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"

_PLACEHOLDER = re.compile(r"@[A-Z][A-Z_]*@")
_SED_RULE = re.compile(r"s\|(@[A-Z][A-Z_]*@)\|")
_ENV_LINE = re.compile(r"^(?P<key>[A-Z0-9_]+)=(?P<value>.*)$")

DEPLOY_FILES = (
    "install.sh",
    "verify.sh",
    "build_executorch_runner.sh",
    "nids.service",
    "nids.env.example",
    "requirements-pi.txt",
    "README.md",
)


def _env_template_keys() -> list[str]:
    text = (DEPLOY_DIR / "nids.env.example").read_text(encoding="utf-8")
    keys = []
    for line in text.splitlines():
        match = _ENV_LINE.match(line.strip())
        if match:
            keys.append(match.group("key"))
    return keys


def _pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name, separator, version = line.partition("==")
        assert separator and version, f"{path.name}: unpinned requirement {line!r}"
        pins[name] = version
    return pins


def test_deploy_payload_exists() -> None:
    missing = [name for name in DEPLOY_FILES if not (DEPLOY_DIR / name).is_file()]
    assert missing == [], f"deployment payload is incomplete: {missing}"


@pytest.mark.parametrize("name", ["install.sh", "verify.sh", "build_executorch_runner.sh"])
def test_shell_scripts_are_lf_and_have_a_shebang(name: str) -> None:
    data = (DEPLOY_DIR / name).read_bytes()
    assert b"\r\n" not in data, f"{name} has CRLF line endings; bash fails on those"
    assert data.startswith(b"#!/usr/bin/env bash"), f"{name} needs a bash shebang"


@pytest.mark.parametrize("name", ["nids.service", "nids.env.example"])
def test_templates_are_lf(name: str) -> None:
    data = (DEPLOY_DIR / name).read_bytes()
    assert b"\r\n" not in data, f"{name} has CRLF line endings"


def test_env_template_keys_exist_in_config() -> None:
    """Every key the installer writes must be read by Settings.from_env."""

    config_source = (REPO_ROOT / "config.py").read_text(encoding="utf-8")
    keys = _env_template_keys()
    assert "NIDS_ROOT" in keys
    assert "NIDS_AUTOSTART" in keys
    assert "LLM_BACKEND" in keys

    unknown = [
        key for key in keys
        # Streamlit reads its own STREAMLIT_* variables; they never reach config.
        if not key.startswith("STREAMLIT_") and f'"{key}"' not in config_source
    ]
    assert unknown == [], f"settings not read by config.py: {unknown}"


def test_env_template_placeholders_are_rendered_by_the_installer() -> None:
    install = (DEPLOY_DIR / "install.sh").read_text(encoding="utf-8")
    rendered = set(_SED_RULE.findall(install))

    placeholders: set[str] = set()
    for name in ("nids.env.example", "nids.service"):
        placeholders |= set(_PLACEHOLDER.findall(
            (DEPLOY_DIR / name).read_text(encoding="utf-8")
        ))

    assert placeholders, "expected @PLACEHOLDER@ tokens in the templates"
    assert placeholders <= rendered, (
        "install.sh does not render: " + ", ".join(sorted(placeholders - rendered))
    )


def test_service_unit_starts_the_streamlit_app() -> None:
    unit = (DEPLOY_DIR / "nids.service").read_text(encoding="utf-8")
    assert "ExecStart=@PREFIX@/venv/bin/streamlit run @PREFIX@/app/app.py" in unit
    assert "--server.address 0.0.0.0" in unit
    assert "EnvironmentFile=/etc/nids/nids.env" in unit
    assert "User=@SERVICE_USER@" in unit
    assert "Restart=on-failure" in unit
    assert "WantedBy=multi-user.target" in unit
    # The port lives in exactly one place: the environment file.
    assert "--server.port" not in unit
    env = (DEPLOY_DIR / "nids.env.example").read_text(encoding="utf-8")
    assert "STREAMLIT_SERVER_PORT=@PORT@" in env
    # dumpcap needs its file capabilities: this directive would silently disable
    # them and break live capture as a service.
    assert not re.search(r"^NoNewPrivileges\s*=", unit, re.MULTILINE)


def test_installer_uses_the_repository_checkout() -> None:
    """The Pi installs from a git clone; there is no bundle or manifest step."""

    install = (DEPLOY_DIR / "install.sh").read_text(encoding="utf-8")

    for removed in ("BUNDLE.json", "MANIFEST.sha256", "make_bundle", "/media/$USER"):
        assert removed not in install, f"install.sh still references {removed}"

    assert "REPO_ROOT" in install
    assert "requirements-pi.txt" in install
    assert "models/detector.joblib" in install
    assert "models/classifier.joblib" in install
    assert "tar -C" in install
    assert "--download-llm" in install
    assert "--ntlflowlyzer" in install
    assert "setcap cap_net_raw,cap_net_admin+eip" in install


def test_installer_can_use_a_local_wheelhouse() -> None:
    install = (DEPLOY_DIR / "install.sh").read_text(encoding="utf-8")
    assert "--wheelhouse" in install
    assert "--no-index" in install
    assert "--find-links" in install


def test_pi_requirements_lock_matches_the_app_requirements() -> None:
    """The aarch64 lock must not drift from the application's own pins."""

    app = _pins(REPO_ROOT / "requirements.txt")
    pi = _pins(DEPLOY_DIR / "requirements-pi.txt")

    # Every application dependency is installed on the Pi at the same version.
    assert {name: pi.get(name) for name in app} == app
    # The Pi-only additions are present and pinned.
    assert {"dpkt", "multipledispatch", "tokenizers", "huggingface_hub"} <= set(pi)


def test_docs_do_not_reference_the_removed_usb_bundle() -> None:
    for name in ("README.md", "deploy/README.md", "AGENTS.md"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        for removed in ("make_bundle", "BUNDLE.json", "MANIFEST.sha256", "USB stick"):
            assert removed not in text, f"{name} still references {removed}"


def test_autostart_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NIDS_AUTOSTART", raising=False)
    assert Settings.from_env().autostart is False

    monkeypatch.setenv("NIDS_AUTOSTART", "1")
    assert Settings.from_env().autostart is True

    monkeypatch.setenv("NIDS_AUTOSTART", "0")
    assert Settings.from_env().autostart is False
