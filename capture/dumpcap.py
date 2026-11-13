"""Windows dumpcap wrapper with rolling pcap files.

Only files that dumpcap has finished writing are exposed to the pipeline.  The
newest file is treated as active and skipped unless the caller explicitly asks
for it after capture has stopped.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

from config import Settings

logger = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """Raised when dumpcap/Npcap is missing or capture cannot start."""


_COMMON_DUMPCAP_PATHS = (
    Path(r"C:\Program Files\Wireshark\dumpcap.exe"),
    Path(r"C:\Program Files (x86)\Wireshark\dumpcap.exe"),
)


def find_dumpcap(configured: str | None = None) -> Path:
    if configured:
        path = Path(configured)
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
        "dumpcap.exe was not found. Install Npcap and Wireshark, then add "
        "dumpcap to PATH or set NIDS_DUMPCAP to its full path."
    )


def build_dumpcap_command(
    dumpcap: Path,
    *,
    interface: str,
    output_pattern: Path,
    rotation_seconds: int,
    ring_files: int,
    capture_filter: str = "",
) -> list[str]:
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
        "-F",
        "pcap",
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


class DumpcapCapture:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._process: subprocess.Popen[bytes] | None = None
        self._log_handle = None
        self._output_pattern = settings.capture_dir / "nids_capture.pcap"
        self._log_path = settings.capture_dir / "dumpcap.log"
        self._started_at: float | None = None

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

        self._log_handle = self._log_path.open("a", encoding="utf-8")
        creationflags = (
            subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        logger.info("Starting capture: %s", " ".join(command))
        self._started_at = time.time()
        self._process = subprocess.Popen(
            command,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
        time.sleep(0.5)
        if self._process.poll() is not None:
            tail = self._tail_log()
            self.stop()
            raise CaptureError(
                "dumpcap exited immediately. Check the interface name and Npcap "
                f"installation. Log: {tail}"
            )

    def _tail_log(self, limit: int = 1500) -> str:
        try:
            text = self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(no dumpcap log available)"
        return text[-limit:].strip() or "(empty dumpcap log)"

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
