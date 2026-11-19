"""Tests for the offline USB deployment bundle (deploy/).

These pin the things that silently break an installation on a machine we are
not sitting in front of: a file missing from the payload, a CRLF shell script,
an environment key that no longer exists in ``config.py``, a placeholder that
the installer never renders, or a systemd unit that no longer starts the app.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from config import Settings
from deploy import make_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"

_PLACEHOLDER = re.compile(r"@[A-Z][A-Z_]*@")
_SED_RULE = re.compile(r"s\|(@[A-Z][A-Z_]*@)\|")
_ENV_LINE = re.compile(r"^(?P<key>[A-Z0-9_]+)=(?P<value>.*)$")


def _env_template_keys() -> list[str]:
    text = (DEPLOY_DIR / "nids.env.example").read_text(encoding="utf-8")
    keys = []
    for line in text.splitlines():
        match = _ENV_LINE.match(line.strip())
        if match:
            keys.append(match.group("key"))
    return keys


def test_payload_files_exist() -> None:
    missing = [
        name for name in make_bundle.DEPLOY_PAYLOAD
        if not (DEPLOY_DIR / name).is_file()
    ]
    assert missing == [], f"bundle payload is incomplete: {missing}"

    for name in ("requirements-extras.txt", "nids.service", "nids.env.example"):
        assert (DEPLOY_DIR / name).is_file()


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


def test_installer_is_offline_by_default() -> None:
    install = (DEPLOY_DIR / "install.sh").read_text(encoding="utf-8")
    assert "MANIFEST.sha256" in install
    assert "sha256sum -c" in install
    assert "--no-index" in install
    assert "requirements-extras.txt" in install
    assert "python_version" in install
    assert "setcap cap_net_raw,cap_net_admin+eip" in install


def test_extras_are_pinned_and_shared() -> None:
    extras = make_bundle.read_requirements(DEPLOY_DIR / "requirements-extras.txt")
    assert extras == ["dpkt==1.9.8", "multipledispatch==1.0.0", "tokenizers==0.21.1"]
    # The bundler downloads exactly this file; the installer installs it.
    assert "requirements-extras.txt" in make_bundle.DEPLOY_PAYLOAD


def test_copy_tree_skips_generated_files_and_normalises_line_endings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    (source / "capture" / "pcaps").mkdir(parents=True)
    (source / "capture" / "__pycache__").mkdir(parents=True)
    (source / "capture" / "dumpcap.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    (source / "capture" / "dumpcap.pcap").write_bytes(b"\x00\x01")
    (source / "capture" / "pcaps" / "live.pcap").write_bytes(b"\x00\x02")
    (source / "capture" / "__pycache__" / "mod.pyc").write_bytes(b"\x00\x03")

    copied = make_bundle.copy_tree(source, tmp_path / "out", skip=set())

    assert copied == 1
    written = sorted(p.name for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert written == ["dumpcap.py"]
    assert (tmp_path / "out" / "capture" / "dumpcap.py").read_bytes() == b"a = 1\nb = 2\n"


def test_manifest_matches_the_files_on_the_stick(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "app").mkdir(parents=True)
    (bundle / "app" / "config.py").write_text("x = 1\n", encoding="utf-8")
    (bundle / "wheels").mkdir()
    (bundle / "wheels" / "numpy.whl").write_bytes(b"binary")
    (bundle / "BUNDLE.json").write_text("{}", encoding="utf-8")

    entries = make_bundle.write_manifest(bundle)
    assert entries == 2

    lines = (bundle / make_bundle.MANIFEST_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        digest, relative = line.split("  ", 1)
        assert relative not in {make_bundle.MANIFEST_NAME, make_bundle.BUNDLE_MARKER}
        assert digest == make_bundle.sha256_file(bundle / relative)


def test_marker_and_instructions_describe_the_bundle(tmp_path: Path) -> None:
    plan = make_bundle.BundlePlan(
        bundle=tmp_path,
        python_version="3.13",
        abi="cp313",
        platforms=("manylinux_2_28_aarch64",),
        with_llm=True,
        llm_dir=tmp_path / "llm",
        ntlflowlyzer=None,
        runner=None,
    )
    make_bundle.write_marker(tmp_path, plan)
    make_bundle.write_start_here(tmp_path, plan)

    marker = json.loads((tmp_path / make_bundle.BUNDLE_MARKER).read_text(encoding="utf-8"))
    assert marker["format"] == make_bundle.BUNDLE_FORMAT
    assert marker["python_version"] == "3.13"
    assert marker["includes_llm"] is True
    assert marker["platforms"] == ["manylinux_2_28_aarch64"]

    instructions = (tmp_path / "START-HERE.txt").read_text(encoding="utf-8")
    assert "install.sh" in instructions
    assert "Python 3.13" in instructions


def test_runner_build_targets_the_v1_5_1_example() -> None:
    """The runner example moved between releases; v1.5.1 has only this path.

    ``examples/models/llama3_2`` never existed, and the core libraries must be
    installed before the example can ``find_package(executorch CONFIG)``.
    """

    text = (DEPLOY_DIR / "build_executorch_runner.sh").read_text(encoding="utf-8")

    assert "examples/models/llama" in text
    assert "examples/models/llama3_2" not in text
    assert "--target llama_main" in text
    assert "llama_main" in text
    # core libraries first, or find_package(executorch CONFIG REQUIRED) fails
    example_invocation = '-S "$EXECUTORCH_SRC/examples/models/llama"'
    assert example_invocation in text
    assert text.index("--target install") < text.index(example_invocation)


def test_runner_build_supports_cross_compiling() -> None:
    text = (DEPLOY_DIR / "build_executorch_runner.sh").read_text(encoding="utf-8")

    assert "--cross" in text
    assert "aarch64-linux-gnu-g++" in text
    assert "CMAKE_TOOLCHAIN_FILE" in text


def test_prepare_output_never_deletes_unrelated_files(tmp_path: Path) -> None:
    stick = tmp_path / "usb"
    stick.mkdir()
    (stick / "holiday.jpg").write_bytes(b"not ours")
    (stick / "app").mkdir()
    (stick / "app" / "stale.py").write_text("old\n", encoding="utf-8")
    (stick / "debs").mkdir()
    (stick / "debs" / "libgomp1.deb").write_bytes(b"cached by the operator")

    with pytest.raises(make_bundle.BundleError):
        make_bundle.prepare_output(stick, force=False)

    make_bundle.prepare_output(stick, force=True)
    assert (stick / "holiday.jpg").is_file(), "unrelated files must survive --force"
    assert (stick / "debs" / "libgomp1.deb").is_file(), "operator debs must survive"
    assert not (stick / "app").exists(), "bundle-owned entries must be replaced"


def test_prepare_output_tolerates_os_drive_metadata(tmp_path: Path) -> None:
    """A freshly formatted Windows stick is not "non-empty" in a meaningful sense."""

    stick = tmp_path / "usb"
    (stick / "System Volume Information").mkdir(parents=True)
    (stick / "System Volume Information" / "tracking.log").write_bytes(b"os")
    (stick / "$RECYCLE.BIN").mkdir()

    make_bundle.prepare_output(stick, force=False)  # must not raise

    assert (stick / "System Volume Information" / "tracking.log").is_file()
    assert (stick / "$RECYCLE.BIN").is_dir()


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "stick"
    plan = make_bundle.BundlePlan(
        bundle=target,
        python_version="3.13",
        abi="cp313",
        platforms=("manylinux_2_28_aarch64",),
        with_llm=False,
        llm_dir=tmp_path / "llm",
        ntlflowlyzer=None,
        runner=None,
        dry_run=True,
    )
    make_bundle.build(plan, force=True)
    assert not target.exists()


def test_python_version_floor() -> None:
    make_bundle._check_python_version("3.13")
    make_bundle._check_python_version("3.12")
    with pytest.raises(make_bundle.BundleError, match="too old"):
        make_bundle._check_python_version("3.11")
    with pytest.raises(make_bundle.BundleError, match="must look like"):
        make_bundle._check_python_version("python3")


def test_with_llm_requires_the_model_files(tmp_path: Path) -> None:
    with pytest.raises(make_bundle.BundleError):
        make_bundle.ensure_llm_files(tmp_path, download=False)


def test_autostart_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NIDS_AUTOSTART", raising=False)
    assert Settings.from_env().autostart is False

    monkeypatch.setenv("NIDS_AUTOSTART", "1")
    assert Settings.from_env().autostart is True

    monkeypatch.setenv("NIDS_AUTOSTART", "0")
    assert Settings.from_env().autostart is False


def test_is_binary_recognises_elf_and_so(tmp_path: Path) -> None:
    so_file = tmp_path / "libdummy.so"
    so_file.write_bytes(b"\x00dummy")
    elf_file = tmp_path / "dummy_elf"
    elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    txt_file = tmp_path / "script.sh"
    txt_file.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")

    assert make_bundle._is_binary(so_file) is True
    assert make_bundle._is_binary(elf_file) is True
    assert make_bundle._is_binary(txt_file) is False


def test_copy_runner_copies_runner_and_shared_library(tmp_path: Path) -> None:
    runner_src = tmp_path / "src" / "llama_main"
    runner_src.parent.mkdir(parents=True)
    runner_src.write_bytes(b"\x7fELF-runner-bytes\r\n")
    so_src = tmp_path / "src" / "libllama_runner.so"
    so_src.write_bytes(b"\x7fELF-so-bytes\r\n")

    bundle = tmp_path / "bundle"
    copied = make_bundle.copy_runner(runner_src, bundle)
    assert copied is True

    runner_dest = bundle / "bin" / "executorch_llama_runner"
    so_dest = bundle / "bin" / "libllama_runner.so"
    assert runner_dest.is_file()
    assert so_dest.is_file()
    # Confirm line endings were NOT mangled on binaries
    assert runner_dest.read_bytes() == b"\x7fELF-runner-bytes\r\n"
    assert so_dest.read_bytes() == b"\x7fELF-so-bytes\r\n"
