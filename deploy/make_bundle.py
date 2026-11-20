"""Build the offline USB installation bundle for the Raspberry Pi 5.

Run this on the Linux build machine, point it at the mounted USB stick, then
carry the stick to the Pi and run ``sudo bash install.sh`` there.  Nothing is
downloaded on the Pi: this script puts the application source, both ``.joblib``
models, the pinned ExecuTorch LLM files, and a full set of ``linux_aarch64``
wheels on the stick.

Examples
--------
USB mounted at ``/media/me/NIDS``::

    python -m deploy.make_bundle --output /media/me/NIDS --with-llm

The target Python must be 3.12 or newer: the pinned numpy, xgboost and shap
have no wheels for older interpreters.  Raspberry Pi OS Trixie ships 3.13 and
is the supported image; Bookworm (3.11) is not.

The bundle is verified against ``MANIFEST.sha256`` by ``install.sh`` before
anything is written outside the USB stick.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = Path(__file__).resolve().parent

BUNDLE_FORMAT = 1
BUNDLE_MARKER = "BUNDLE.json"
MANIFEST_NAME = "MANIFEST.sha256"

#: Files copied verbatim to ``<bundle>/app``.  The Pi runs exactly this tree.
SOURCE_DIRS = ("capture", "features", "models", "explain", "ui", "bench", "tests")
SOURCE_FILES = (
    "app.py",
    "config.py",
    "pipeline.py",
    "requirements.txt",
    "pytest.ini",
    "README.md",
    "AGENTS.md",
)

#: Never copied into ``app/``: generated captures, caches, local environments.
EXCLUDED_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".venv",
    "pcaps",
    "flows",
    "archive",
    "testdata",
    "bundle",
    "models_llm",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pcap", ".pcapng", ".log"}

#: Files under ``deploy/`` that travel next to the app (installer + helpers).
DEPLOY_PAYLOAD = (
    "install.sh",
    "verify.sh",
    "build_executorch_runner.sh",
    "nids.service",
    "nids.env.example",
    "requirements-pi.txt",
    "README.md",
)

#: The complete pinned install set for the Pi (see the file header).
PI_REQUIREMENTS = DEPLOY_DIR / "requirements-pi.txt"

#: Wheels must cover the Pi's glibc.  Ordered newest first; pip accepts a list.
DEFAULT_PLATFORMS = (
    "manylinux_2_39_aarch64",
    "manylinux_2_28_aarch64",
    "manylinux2014_aarch64",
    "linux_aarch64",
)

LLM_FILES = (
    "xnnpack/Llama-3.2-1B-Instruct-8da4w-gptq-4k.pte",
    "tokenizer.json",
    "xnnpack/config.json",
)
LLM_REPO = "experimentalmachines/Llama-3.2-1B-Instruct-ExecuTorch"

#: Extensions whose line endings are normalised to LF.  Editors and some tools
#: happily write CRLF, and ``bash install.sh`` fails on ``\r``.
TEXT_SUFFIXES = {
    ".py",
    ".sh",
    ".md",
    ".txt",
    ".json",
    ".ini",
    ".service",
    ".example",
    ".cfg",
    ".toml",
    ".yaml",
    ".yml",
}

BINARY_SUFFIXES = {".joblib", ".pte", ".whl", ".deb", ".bin", ".so"}


class BundleError(RuntimeError):
    """Raised when the bundle cannot be built or is incomplete."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def log(message: str) -> None:
    print(f"[bundle] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[bundle] WARNING: {message}", file=sys.stderr, flush=True)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(8192)
            return b"\x00" in chunk or chunk.startswith(b"\x7fELF")
    except OSError:
        return False


def read_requirements(path: Path) -> list[str]:
    """Return requirement specifiers, ignoring comments and blank lines."""

    if not path.exists():
        raise BundleError(f"requirements file not found: {path}")
    items: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            items.append(line)
    return items


def copy_file(src: Path, dest: Path) -> None:
    """Copy one file, normalising text line endings to LF."""

    dest.parent.mkdir(parents=True, exist_ok=True)
    if _is_binary(src):
        shutil.copy2(src, dest)
        return
    data = src.read_bytes()
    dest.write_bytes(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))


def copy_tree(src: Path, dest: Path, *, skip: set[str]) -> int:
    """Copy *src* into *dest*, honouring the exclusion rules.  Returns count."""

    copied = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(src)
        if any(part in EXCLUDED_DIR_NAMES for part in relative.parts):
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if relative.as_posix() in skip:
            continue
        copy_file(path, dest / relative)
        copied += 1
    return copied


def git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def write_manifest(bundle: Path) -> int:
    """Write ``MANIFEST.sha256`` for every payload file (``sha256sum -c`` format)."""

    entries: list[str] = []
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(bundle).as_posix()
        if relative in {MANIFEST_NAME, BUNDLE_MARKER}:
            continue
        entries.append(f"{sha256_file(path)}  {relative}")
    (bundle / MANIFEST_NAME).write_text("\n".join(entries) + "\n", encoding="utf-8")
    return len(entries)


# ---------------------------------------------------------------------------
# wheels
# ---------------------------------------------------------------------------
def download_wheels(
    dest: Path,
    *,
    python_version: str,
    abi: str,
    platforms: tuple[str, ...],
    requirements: list[Path],
) -> int:
    """Download every wheel the Pi needs, for its Python and architecture."""

    dest.mkdir(parents=True, exist_ok=True)
    command: list[str] = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary=:all:",
        "--dest",
        str(dest),
        "--python-version",
        python_version,
        "--implementation",
        "cp",
        "--abi",
        abi,
    ]
    for platform in platforms:
        command += ["--platform", platform]
    for requirement_file in requirements:
        command += ["-r", str(requirement_file)]

    log("downloading wheels: " + " ".join(command))
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise BundleError(
            "pip could not download a complete wheel set for "
            f"Python {python_version} ({abi}) on {', '.join(platforms)}. "
            "Some package may lack a prebuilt aarch64 wheel for that Python; "
            "try --python-version with the Python your Pi actually runs."
        )
    return len(list(dest.glob("*.whl")))


# ---------------------------------------------------------------------------
# LLM files
# ---------------------------------------------------------------------------
def _hf_command(local_dir: Path) -> list[str]:
    executable = shutil.which("hf")
    if executable is None:
        raise BundleError(
            "The 'hf' command is missing. Install it with "
            "'pip install huggingface_hub', or download these files by hand "
            f"from {LLM_REPO} into --llm-dir:\n  "
            + "\n  ".join(LLM_FILES)
        )
    return [
        executable,
        "download",
        LLM_REPO,
        *LLM_FILES,
        "--local-dir",
        str(local_dir),
    ]


def _download_with_python_api(local_dir: Path) -> None:
    """Fallback for machines without the ``hf`` CLI."""

    try:
        from huggingface_hub import hf_hub_download  # type: ignore[import-not-found]
    except ImportError as exc:
        raise BundleError(
            "Neither the 'hf' command nor the huggingface_hub package is "
            "available. Run 'pip install huggingface_hub', or download these "
            f"files by hand from {LLM_REPO} into --llm-dir:\n  "
            + "\n  ".join(LLM_FILES)
        ) from exc

    log("the 'hf' command is missing; using huggingface_hub from Python")
    for name in LLM_FILES:
        hf_hub_download(
            repo_id=LLM_REPO,
            filename=name,
            local_dir=str(local_dir),
        )


def download_llm_files(llm_dir: Path) -> None:
    """Fetch the three model files, preferring the CLI over the Python API."""

    if shutil.which("hf") is not None:
        result = subprocess.run(_hf_command(llm_dir), check=False)
        if result.returncode != 0:
            raise BundleError("huggingface download failed (see output above)")
        return
    _download_with_python_api(llm_dir)


def ensure_llm_files(llm_dir: Path, *, download: bool) -> list[Path]:
    """Return the three model files, downloading them only when asked to."""

    missing = [name for name in LLM_FILES if not (llm_dir / name).is_file()]
    if missing and download:
        log(f"downloading {len(missing)} LLM file(s) from {LLM_REPO}")
        download_llm_files(llm_dir)
        missing = [name for name in LLM_FILES if not (llm_dir / name).is_file()]
    if missing:
        raise BundleError(
            "the bundle was asked to include the LLM, but these files are "
            f"missing from {llm_dir}: {', '.join(missing)}. Pass --download-llm "
            "to fetch them, or point --llm-dir at a folder that has them."
        )
    return [llm_dir / name for name in LLM_FILES]


def copy_llm_files(llm_dir: Path, bundle: Path) -> int:
    total = 0
    for src in ensure_llm_files(llm_dir, download=False):
        relative = src.relative_to(llm_dir)
        copy_file(src, bundle / "models_llm" / relative)
        total += 1
    return total


# ---------------------------------------------------------------------------
# staging
# ---------------------------------------------------------------------------
@dataclass
class BundlePlan:
    """Everything that will be placed on the USB stick."""

    bundle: Path
    python_version: str
    abi: str
    platforms: tuple[str, ...]
    with_llm: bool
    llm_dir: Path
    ntlflowlyzer: Path | None
    runner: Path | None
    with_wheels: bool = True
    dry_run: bool = False
    stats: dict[str, int] = field(default_factory=dict)


def _check_repo_inputs() -> None:
    required = [
        REPO_ROOT / "models" / "detector.joblib",
        REPO_ROOT / "models" / "classifier.joblib",
        REPO_ROOT / "explain" / "knowledge" / "attacks.json",
        REPO_ROOT / "explain" / "knowledge" / "feature_info.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise BundleError("repository is incomplete, missing: " + ", ".join(missing))


def prepare_output(path: Path, *, force: bool) -> None:
    """Create the bundle directory, replacing only files the bundle owns.

    ``--output`` is usually the USB root, so unrelated files are never
    deleted: only the entries this tool (or ``install.sh``) creates are
    removed before a rebuild.
    """

    managed = set(DEPLOY_PAYLOAD) | {
        "app",
        "wheels",
        "vendor",
        "models_llm",
        "bin",
        "START-HERE.txt",
        MANIFEST_NAME,
        BUNDLE_MARKER,
    }
    # ``debs/`` is filled in by the operator (see deploy/README.md), so it is
    # neither deleted nor treated as an unrelated file. The remaining names are
    # metadata the host OS puts on removable media by itself (any platform),
    # Linux fsck); they are never operator content, so they do not count as
    # strangers either -- and they live outside ``managed``, so they survive.
    tolerated = {
        "debs",
        "System Volume Information",
        "$RECYCLE.BIN",
        "$WinREAgent",
        "FOUND.000",
        ".Trashes",
        ".Spotlight-V100",
        ".fseventsd",
        "lost+found",
    }

    if path.exists():
        entries = [item for item in path.iterdir()]
        strangers = [
            item.name for item in entries
            if item.name not in managed and item.name not in tolerated
        ]
        if strangers and not force:
            raise BundleError(
                f"{path} contains files that are not part of a NIDS bundle "
                f"({', '.join(sorted(strangers)[:5])}). Point --output at an "
                "empty stick, or pass --force to add the bundle next to them."
            )
        for item in entries:
            if item.name not in managed:
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
    path.mkdir(parents=True, exist_ok=True)


def copy_application(bundle: Path) -> int:
    app_dir = bundle / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for name in SOURCE_DIRS:
        source = REPO_ROOT / name
        if not source.is_dir():
            raise BundleError(f"source package missing: {source}")
        copied += copy_tree(source, app_dir / name, skip=set())
    for name in SOURCE_FILES:
        source = REPO_ROOT / name
        if not source.is_file():
            raise BundleError(f"source file missing: {source}")
        copy_file(source, app_dir / name)
        copied += 1
    # The deploy helpers are needed on the Pi to re-run verify.sh / install.sh
    # after an upgrade; keep them inside app/ as well as at the bundle root.
    copied += copy_tree(DEPLOY_DIR, app_dir / "deploy", skip=set())
    return copied


def copy_installer_payload(bundle: Path) -> int:
    copied = 0
    for name in DEPLOY_PAYLOAD:
        source = DEPLOY_DIR / name
        if not source.is_file():
            raise BundleError(f"deploy payload missing: {source}")
        copy_file(source, bundle / name)
        copied += 1
    return copied


def copy_ntlflowlyzer(source: Path | None, bundle: Path) -> bool:
    if source is None:
        warn(
            "no --ntlflowlyzer checkout given: the Pi will read CSV rows but "
            "cannot turn pcap files into flows. Pass the NTLFlowLyzer folder."
        )
        return False
    source = source.expanduser().resolve()
    if not (source / "NTLFlowLyzer" / "__main__.py").is_file():
        raise BundleError(
            f"{source} does not look like an NTLFlowLyzer checkout "
            "(expected NTLFlowLyzer/__main__.py inside it)"
        )
    copied = copy_tree(source, bundle / "vendor" / "NTLFlowLyzer", skip=set())
    log(f"vendored NTLFlowLyzer ({copied} files)")
    return True


def copy_runner(source: Path | None, bundle: Path) -> bool:
    if source is None:
        return False
    source = source.expanduser().resolve()
    if not source.is_file():
        raise BundleError(f"--executorch-runner does not exist: {source}")
    copy_file(source, bundle / "bin" / "executorch_llama_runner")
    # If libllama_runner.so exists near the runner, copy it into bin/ alongside
    for candidate in (
        source.parent / "libllama_runner.so",
        source.parent / "runner" / "libllama_runner.so",
        source.parent / "executorch" / "cmake-out" / "examples" / "models" / "llama" / "runner" / "libllama_runner.so",
    ):
        if candidate.is_file():
            copy_file(candidate, bundle / "bin" / "libllama_runner.so")
            log(f"copied shared library: {candidate.name}")
            break
    return True


def write_start_here(bundle: Path, plan: BundlePlan) -> None:
    text = textwrap.dedent(
        f"""\
        NIDS offline installation bundle
        ================================

        Built {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        git commit: {git_commit()}
        target:     Raspberry Pi OS 64-bit, Python {plan.python_version} ({plan.abi})
        LLM files:  {"included" if plan.with_llm else "NOT included (fallback text only)"}

        On the Raspberry Pi, with this stick plugged in:

            ls /media/$USER/*/            # find the mount point
            sudo bash /media/$USER/NIDS/install.sh

        Then open a browser at  http://<pi-address>:8501

        The installer is idempotent: running it again upgrades the application
        and keeps /etc/nids/nids.env. Re-run it after copying a newer bundle.

        Read README.md on the stick (deploy/README.md in the repository) for
        the details, the flags, and what still needs verifying on the Pi.
        """
    )
    (bundle / "START-HERE.txt").write_text(text, encoding="utf-8")


def write_marker(bundle: Path, plan: BundlePlan) -> None:
    payload = {
        "format": BUNDLE_FORMAT,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": git_commit(),
        "python_version": plan.python_version,
        "abi": plan.abi,
        "platforms": list(plan.platforms),
        "includes_llm": plan.with_llm,
        "includes_ntlflowlyzer": plan.ntlflowlyzer is not None,
        "includes_runner": plan.runner is not None,
        "includes_wheels": plan.with_wheels,
        "stats": plan.stats,
    }
    (bundle / BUNDLE_MARKER).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def build(plan: BundlePlan, *, force: bool) -> Path:
    _check_repo_inputs()
    if plan.with_llm:
        # Fail before touching the USB stick if the model files are not here.
        ensure_llm_files(plan.llm_dir, download=False)

    if plan.dry_run:
        log("dry run: nothing is written")
        log(f"  target        {plan.bundle}")
        log(f"  app           {len(SOURCE_DIRS)} packages + {len(SOURCE_FILES)} files")
        log(f"  wheels        Python {plan.python_version} / {plan.abi} / "
            f"{', '.join(plan.platforms)}")
        log(f"  llm files     {'yes' if plan.with_llm else 'no'}")
        log(f"  ntlflowlyzer  {plan.ntlflowlyzer or 'no'}")
        log(f"  runner        {plan.runner or 'no'}")
        return plan.bundle

    prepare_output(plan.bundle, force=force)
    log(f"building bundle in {plan.bundle}")

    plan.stats["app_files"] = copy_application(plan.bundle)
    plan.stats["installer_files"] = copy_installer_payload(plan.bundle)
    plan.stats["ntlflowlyzer"] = int(copy_ntlflowlyzer(plan.ntlflowlyzer, plan.bundle))
    plan.stats["runner"] = int(copy_runner(plan.runner, plan.bundle))

    if plan.with_llm:
        plan.stats["llm_files"] = copy_llm_files(plan.llm_dir, plan.bundle)
        log("copied ExecuTorch model files")

    if plan.with_wheels:
        plan.stats["wheels"] = download_wheels(
            plan.bundle / "wheels",
            python_version=plan.python_version,
            abi=plan.abi,
            platforms=plan.platforms,
            requirements=[PI_REQUIREMENTS],
        )
    else:
        warn("building without wheels (--no-wheels): the Pi must be online")

    write_start_here(plan.bundle, plan)
    write_marker(plan.bundle, plan)
    plan.stats["manifest_entries"] = write_manifest(plan.bundle)
    log(f"manifest: {plan.stats['manifest_entries']} files hashed")

    return plan.bundle


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _check_python_version(value: str) -> None:
    """The pinned stack has no wheels below Python 3.12."""

    try:
        major, minor = (int(part) for part in value.split(".")[:2])
    except (ValueError, TypeError):
        raise BundleError(f"--python-version must look like 3.13, got {value!r}")
    if (major, minor) < (3, 12):
        raise BundleError(
            f"Python {value} is too old: the pinned numpy, xgboost and shap "
            "require 3.12 or newer. Raspberry Pi OS Trixie (3.13) is the "
            "supported image."
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m deploy.make_bundle",
        description="Build the offline USB installation bundle for the Pi 5.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Typical use:
              python -m deploy.make_bundle --output /media/$USER/NIDS --with-llm \\
                  --ntlflowlyzer ../NTLFlowLyzer
            """
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEPLOY_DIR / "bundle",
        help="Mounted USB stick (bundle goes directly in it).",
    )
    parser.add_argument(
        "--python-version",
        default="3.13",
        help="Python on the Pi: 3.13 (Trixie, default). Minimum 3.12.",
    )
    parser.add_argument("--abi", default="cp313", help="Wheel ABI, e.g. cp313.")
    parser.add_argument(
        "--platform",
        action="append",
        dest="platforms",
        help="Repeatable manylinux platform tag (defaults cover Debian 12/13).",
    )
    parser.add_argument(
        "--with-llm",
        action="store_true",
        help="Include the ExecuTorch .pte, tokenizer.json and xnnpack/config.json.",
    )
    parser.add_argument(
        "--llm-dir",
        type=Path,
        default=REPO_ROOT / "models_llm",
        help="Folder holding the downloaded LLM files (default: models_llm/).",
    )
    parser.add_argument(
        "--download-llm",
        action="store_true",
        help="Fetch missing LLM files from Hugging Face before bundling.",
    )
    parser.add_argument(
        "--ntlflowlyzer",
        type=Path,
        default=None,
        help="NTLFlowLyzer source checkout to vendor onto the stick.",
    )
    parser.add_argument(
        "--executorch-runner",
        type=Path,
        default=None,
        help="Prebuilt arm64 executorch_llama_runner binary to include.",
    )
    parser.add_argument(
        "--no-wheels",
        dest="with_wheels",
        action="store_false",
        help="Do not download wheels (the Pi then installs from the network).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite a non-empty output directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen; do not download or write.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _check_python_version(args.python_version)
    except BundleError as exc:
        print(f"[bundle] ERROR: {exc}", file=sys.stderr)
        return 1
    platforms = tuple(args.platforms) if args.platforms else DEFAULT_PLATFORMS
    plan = BundlePlan(
        bundle=args.output.expanduser().resolve(),
        python_version=args.python_version,
        abi=args.abi,
        platforms=platforms,
        with_llm=args.with_llm,
        llm_dir=args.llm_dir.expanduser().resolve(),
        ntlflowlyzer=args.ntlflowlyzer,
        runner=args.executorch_runner,
        with_wheels=args.with_wheels,
        dry_run=args.dry_run,
    )

    if plan.with_llm and args.download_llm:
        try:
            ensure_llm_files(plan.llm_dir, download=True)
        except BundleError as exc:
            warn(str(exc))
            return 1

    try:
        bundle = build(plan, force=args.force)
    except BundleError as exc:
        print(f"[bundle] ERROR: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        return 0

    total = sum(
        item.stat().st_size for item in bundle.rglob("*") if item.is_file()
    )
    log(f"done: {bundle} ({total / 1e9:.2f} GB)")
    log("next: plug the stick into the Pi and run  sudo bash install.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
