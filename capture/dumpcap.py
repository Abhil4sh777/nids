"""Linux dumpcap wrapper with rolling pcap files.

Only files that dumpcap has finished writing are exposed to the pipeline.  The
newest file is treated as active and skipped unless the caller explicitly asks
for it after capture has stopped.

Capture must work without running Python as root: give ``dumpcap`` the
``cap_net_raw,cap_net_admin`` capabilities (or add the user to the ``wireshark``
group) as described in README.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from config import Settings

logger = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """Raised when dumpcap/libpcap is missing or capture cannot start."""


_COMMON_DUMPCAP_PATHS = (
    Path("/usr/bin/dumpcap"),
    Path("/usr/sbin/dumpcap"),
    Path("/usr/local/bin/dumpcap"),
)


def find_dumpcap(configured: str | None = None) -> Path:
    if configured:
        path = Path(configured).expanduser()
        if path.exists():
            return path
        raise CaptureError(f"Configured dumpcap path does not exist: {path}")

    on_path = shutil.which("dumpcap")
    if on_path:
        return Path(on_path)

    for candidate in _COMMON_DUMPCAP_PATHS:
        if candidate.exists():
            return candidate

    raise CaptureError(
        "dumpcap was not found. Install Wireshark/tshark tools "
        "(sudo apt install wireshark-common), add dumpcap to PATH, or set "
        "NIDS_DUMPCAP to its full path. Live capture also needs packet "
        "capture permission for the current user; see README."
    )


@lru_cache(maxsize=8)
def _dumpcap_help_text(dumpcap: Path) -> str:
    """Return ``dumpcap -h`` output (cached; help printing is unprivileged)."""

    try:
        completed = subprocess.run(
            [str(dumpcap), "-h"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        logger.debug("Could not read dumpcap help: %s", exc)
        return ""
    # dumpcap writes its usage text to stderr in some versions.
    return f"{completed.stdout}\n{completed.stderr}"


def pcap_output_format_flags(dumpcap: Path) -> list[str]:
    """Return the flags that force classic pcap output for this dumpcap.

    NTLFlowLyzer only reads classic pcap.  Wireshark >= 4.0 spells this as
    ``-F pcap``; older dumpcap (e.g. 3.6.x) has no ``-F`` and uses ``-P``
    ("use libpcap format instead of pcapng").  Passing the wrong spelling makes
    dumpcap reject the entire command line and print its help.
    """

    help_text = _dumpcap_help_text(dumpcap)
    if re.search(r"(?m)^\s*-F\b", help_text):
        return ["-F", "pcap"]
    if re.search(r"(?m)^\s*-P\b", help_text):
        return ["-P"]
    # Unknown build: assume the modern spelling rather than silently writing
    # pcapng into a .pcap file.
    logger.warning(
        "Could not detect dumpcap's pcap output flag from its help text; "
        "assuming '-F pcap' (Wireshark >= 4.0)."
    )
    return ["-F", "pcap"]


def build_dumpcap_command(
    dumpcap: Path,
    *,
    interface: str,
    output_pattern: Path,
    rotation_seconds: int,
    ring_files: int,
    capture_filter: str = "",
    format_flags: Sequence[str] | None = None,
) -> list[str]:
    if format_flags is None:
        format_flags = pcap_output_format_flags(dumpcap)
    command = [
        str(dumpcap),
        "-i",
        interface,
        "-w",
        str(output_pattern),
        "-b",
        f"duration:{rotation_seconds}",
        "-b",
        f"files:{ring_files}",
        # NTLFlowLyzer consumes classic pcap; newer dumpcap versions would
        # otherwise default to pcapng despite the .pcap file name.
        *format_flags,
        "-q",
    ]
    if capture_filter:
        command.extend(["-f", capture_filter])
    return command


def completed_pcap_files(
    directory: Path,
    *,
    stable_seconds: float = 3.0,
    include_last: bool = False,
) -> list[Path]:
    """Return capture files that are no longer being written.

    dumpcap writes one file at a time.  The newest file is treated as active;
    older files must also have been untouched for ``stable_seconds``.
    """

    if not directory.exists():
        return []
    files = [
        path
        for pattern in ("*.pcap", "*.pcapng")
        for path in directory.glob(pattern)
        if path.is_file()
    ]
    files = sorted(files, key=lambda path: path.stat().st_mtime)
    if not include_last and files:
        files = files[:-1]

    now = time.time()
    return [
        path
        for path in files
        if now - path.stat().st_mtime >= stable_seconds
    ]


_USAGE_MARKER = "Usage: dumpcap [options]"


def _strip_usage_dump(text: str) -> str:
    """Collapse dumpcap's giant help/usage output into a short note.

    A rejected command line makes dumpcap print several screens of usage text,
    which is useless in a UI error message.  Keep whatever it printed first
    (usually ``dumpcap: unrecognized option: F``) and note the usage dump.
    """

    marker = text.find(_USAGE_MARKER)
    if marker < 0:
        return ""
    head = text[:marker].strip()
    note = "(dumpcap printed its usage text: it rejected the command line)"
    return f"{head} {note}".strip() if head else note


def retire_processed_pcap(
    pcap_path: Path, *, action: str, archive_dir: Path
) -> None:
    """Apply the configured post-extraction policy to a capture file.

    SD cards fill up and wear out, so the default is ``delete``.  ``archive``
    moves the file into ``archive_dir`` and ``keep`` leaves it in place.
    """

    normalized = (action or "keep").strip().lower()
    if normalized == "keep":
        return
    if normalized == "delete":
        pcap_path.unlink(missing_ok=True)
        logger.info("Deleted processed capture %s", pcap_path)
        return
    if normalized == "archive":
        archive_dir.mkdir(parents=True, exist_ok=True)
        target = archive_dir / pcap_path.name
        if target.exists():
            target = archive_dir / f"{pcap_path.stem}_{int(time.time())}{pcap_path.suffix}"
        shutil.move(str(pcap_path), str(target))
        logger.info("Archived processed capture %s -> %s", pcap_path, target)
        return
    raise CaptureError(
        f"Unknown NIDS_PCAP_AFTER_PROCESS value {action!r}; expected "
        "'delete', 'archive', or 'keep'"
    )


class DumpcapCapture:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._process: subprocess.Popen[bytes] | None = None
        self._log_handle = None
        self._output_pattern = settings.capture_dir / "nids_capture.pcap"
        self._log_path = settings.capture_dir / "dumpcap.log"
        self._started_at: float | None = None
        self._log_offset = 0

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> None:
        if self.is_running:
            return
        if not self.settings.interface:
            raise CaptureError(
                "No capture interface configured. Set NIDS_INTERFACE or pass an "
                "interface in the UI."
            )

        self.settings.capture_dir.mkdir(parents=True, exist_ok=True)
        dumpcap = find_dumpcap(self.settings.dumpcap_path)
        command = build_dumpcap_command(
            dumpcap,
            interface=self.settings.interface,
            output_pattern=self._output_pattern,
            rotation_seconds=self.settings.pcap_rotation_seconds,
            ring_files=self.settings.pcap_ring_files,
            capture_filter=self.settings.capture_filter,
        )

        self._log_offset = self._log_path.stat().st_size if self._log_path.exists() else 0
        self._log_handle = self._log_path.open("a", encoding="utf-8")
        logger.info("Starting capture: %s", " ".join(command))
        self._started_at = time.time()
        self._process = subprocess.Popen(
            command,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            exit_code = self._process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            exit_code = None
        if exit_code is not None:
            tail = self._tail_log()
            self.stop()
            raise CaptureError(
                f"dumpcap exited immediately with code {exit_code}. "
                "Check the interface name and packet-capture permissions "
                "(wireshark group or cap_net_raw/cap_net_admin capabilities). "
                f"Command: {' '.join(command)}. Log: {tail}"
            )

    def _tail_log(self, limit: int = 1500) -> str:
        """Return this session's dumpcap output, without giant usage dumps."""

        try:
            with self._log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._log_offset)
                text = handle.read()
        except OSError:
            return "(no dumpcap log available)"
        text = _strip_usage_dump(text) or text
        text = text.strip()
        return text[-limit:] if text else "(empty dumpcap log)"

    def log_tail(self, limit: int = 1500) -> str:
        return self._tail_log(limit=limit)

    def stop(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self._process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def completed_files(self, *, include_last: bool = False) -> list[Path]:
        running = self.is_running
        files = completed_pcap_files(
            self.settings.capture_dir,
            stable_seconds=self.settings.pcap_stable_seconds if running else 0.0,
            include_last=include_last or not running,
        )
        if self._started_at is None:
            return files
        # Do not replay captures left over from an earlier session.
        return [
            path
            for path in files
            if path.stat().st_mtime >= self._started_at - 1.0
        ]

    def __enter__(self) -> "DumpcapCapture":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
