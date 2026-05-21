"""
realtime_file_watcher.py — Real-time Filesystem Monitoring Sensor

This module provides continuous, real-time monitoring of the local filesystem
for suspicious file activity. It leverages the `watchdog` library to receive
OS-level filesystem notifications (via ReadDirectoryChangesW on Windows),
which is far more efficient than polling.

Security Rationale:
    Malware typically drops payloads to disk before execution. By intercepting
    file creation and modification events in real time, we can detect and
    quarantine threats before they execute — drastically reducing dwell time.
    This is the first line of defense in a defense-in-depth strategy.

Architecture:
    - A `SuspiciousFileHandler` (subclass of `FileSystemEventHandler`) receives
      raw filesystem events and filters them against configured extensions and
      exclusion paths.
    - When a suspicious file is detected, its bytes are read and forwarded to
      a callback function (typically the local AV/ML engine for scanning).
    - The `RealtimeFileWatcher` class orchestrates one or more `Observer`
      threads, each watching a configured directory recursively.

Thread Safety:
    - The watchdog Observer runs its own internal thread.
    - The callback is invoked from the Observer's thread; callers must ensure
      their callback is thread-safe.
    - Start/stop operations are guarded by a threading lock to prevent races.

Usage:
    from src.endpoint_agent.realtime_file_watcher import RealtimeFileWatcher

    def on_suspicious_file(filepath, file_bytes, event_type):
        print(f"Suspicious: {filepath}")

    watcher = RealtimeFileWatcher(callback=on_suspicious_file)
    watcher.start()
    # ... later ...
    watcher.stop()
"""

import os
import time
import threading
from typing import Callable, Optional, List, Set

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("RealtimeFileWatcher")


# ---------------------------------------------------------------------------
# Default configuration values (used when config keys are absent)
# ---------------------------------------------------------------------------
DEFAULT_WATCHED_EXTENSIONS: List[str] = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".scr", ".pif", ".msi", ".hta", ".cpl", ".jar", ".py",
]

DEFAULT_WATCHED_DIRECTORIES: List[str] = [
    os.environ.get("USERPROFILE", "C:\\Users"),
    os.environ.get("TEMP", "C:\\Windows\\Temp"),
    "C:\\ProgramData",
]

DEFAULT_EXCLUSIONS: List[str] = [
    "C:\\Windows\\WinSxS",
    "C:\\Windows\\servicing",
    "C:\\$Recycle.Bin",
]

# Maximum file size we'll read into memory for scanning (10 MB).
# Anything larger is logged but not forwarded — the AV engine should
# handle large-file scanning via memory-mapped I/O separately.
MAX_FILE_READ_SIZE: int = 10 * 1024 * 1024


class SuspiciousFileHandler(FileSystemEventHandler):
    """Watchdog event handler that filters for security-relevant file events.

    This handler intercepts file creation, modification, and move (destination)
    events. It checks the file extension against a configurable allow-list of
    suspicious extensions, skips excluded paths, and — if the file passes all
    filters — reads its bytes and invokes the registered callback.

    Attributes:
        watched_extensions: Set of lowercase file extensions to monitor.
        exclusions: List of directory prefixes to skip.
        callback: Function invoked with (filepath, file_bytes, event_type).
    """

    def __init__(
        self,
        watched_extensions: Set[str],
        exclusions: List[str],
        callback: Callable[[str, bytes, str], None],
    ) -> None:
        super().__init__()
        # Normalize extensions to lowercase with leading dot for fast lookup
        self.watched_extensions: Set[str] = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in watched_extensions
        }
        # Normalize exclusion paths to lowercase for case-insensitive comparison
        # (Windows filesystem is case-insensitive)
        self.exclusions: List[str] = [p.lower() for p in exclusions]
        self.callback = callback

    # ---- Internal helpers ------------------------------------------------

    def _is_excluded(self, path: str) -> bool:
        """Check whether *path* falls under any exclusion directory.

        We use a prefix match (case-insensitive) so that excluding
        'C:\\Windows\\WinSxS' also excludes all children.
        """
        path_lower = path.lower()
        return any(path_lower.startswith(exc) for exc in self.exclusions)

    def _has_suspicious_extension(self, path: str) -> bool:
        """Return True if the file's extension is in the watched set."""
        _, ext = os.path.splitext(path)
        return ext.lower() in self.watched_extensions

    def _read_file_safely(self, path: str) -> Optional[bytes]:
        """Attempt to read the file's bytes, handling common edge cases.

        Returns None if the file cannot be read (e.g., locked by another
        process, already deleted, or exceeds our size threshold).

        Security Note:
            We add a small delay before reading to handle the common case
            where the file is still being written by the dropping process.
            This is a best-effort approach — the AV engine should also
            support on-access scanning for complete coverage.
        """
        try:
            # Brief delay: the OS event fires as soon as the file is created,
            # but the writing process may not have finished flushing yet.
            time.sleep(0.1)

            file_size = os.path.getsize(path)
            if file_size > MAX_FILE_READ_SIZE:
                logger.warning(
                    "File exceeds max scan size (%d bytes): %s",
                    file_size,
                    path,
                )
                return None

            with open(path, "rb") as fh:
                return fh.read()

        except FileNotFoundError:
            # File was created then immediately deleted — common with temp files.
            logger.debug("File vanished before read: %s", path)
            return None
        except PermissionError:
            # File is locked by another process (e.g., installer, system process).
            logger.warning("Permission denied reading file: %s", path)
            return None
        except OSError as exc:
            logger.error("OS error reading file %s: %s", path, exc)
            return None

    def _process_event(self, event_path: str, event_type: str) -> None:
        """Core logic shared across all event types.

        Steps:
            1. Skip directories — we only care about files.
            2. Skip excluded paths.
            3. Check extension against the suspicious set.
            4. Read bytes and invoke callback.
        """
        if self._is_excluded(event_path):
            return

        if not self._has_suspicious_extension(event_path):
            return

        logger.info(
            "Suspicious file event [%s]: %s",
            event_type,
            event_path,
        )

        file_bytes = self._read_file_safely(event_path)
        if file_bytes is not None:
            try:
                self.callback(event_path, file_bytes, event_type)
            except Exception as exc:
                # Never let a callback exception crash the watcher thread.
                logger.error(
                    "Callback raised an exception for %s: %s",
                    event_path,
                    exc,
                )

    # ---- Watchdog event overrides ----------------------------------------

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        """Triggered when a new file is created in a watched directory."""
        if not event.is_directory:
            self._process_event(event.src_path, "created")

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        """Triggered when an existing file is modified.

        Security Rationale:
            Attackers often overwrite legitimate DLLs (DLL side-loading) or
            modify script files post-creation. Monitoring modifications
            catches these living-off-the-land techniques.
        """
        if not event.is_directory:
            self._process_event(event.src_path, "modified")

    def on_moved(self, event: FileMovedEvent) -> None:  # type: ignore[override]
        """Triggered when a file is moved/renamed into a watched directory.

        Security Rationale:
            A common evasion technique is to write a benign file and then
            rename it to a dangerous extension (e.g., .txt → .exe).
            Watching moves catches this pattern.
        """
        if not event.is_directory:
            self._process_event(event.dest_path, "moved")


class RealtimeFileWatcher:
    """Orchestrates real-time filesystem monitoring across multiple directories.

    This class manages one or more `watchdog.Observer` instances, each
    watching a configured directory tree recursively. It is designed to
    be started and stopped cleanly, and is safe for use in a multi-threaded
    agent environment.

    Args:
        callback: Function called when a suspicious file is detected.
                  Signature: callback(filepath: str, file_bytes: bytes,
                  event_type: str) -> None.
                  Must be thread-safe.

    Example:
        watcher = RealtimeFileWatcher(callback=my_scan_function)
        watcher.start()
        # ... agent runs ...
        watcher.stop()
    """

    def __init__(self, callback: Callable[[str, bytes, str], None]) -> None:
        self._callback = callback
        self._observers: List[Observer] = []
        self._lock = threading.Lock()
        self._running = False

        # Load configuration
        config = AgentConfig.load()
        self._watched_extensions: Set[str] = set(
            config.get("watched_extensions", DEFAULT_WATCHED_EXTENSIONS)
        )
        self._watched_directories: List[str] = config.get(
            "watched_directories", DEFAULT_WATCHED_DIRECTORIES
        )
        self._exclusions: List[str] = config.get(
            "watcher_exclusions", DEFAULT_EXCLUSIONS
        )

        logger.info(
            "RealtimeFileWatcher initialized — watching %d directories, "
            "%d extensions, %d exclusions",
            len(self._watched_directories),
            len(self._watched_extensions),
            len(self._exclusions),
        )

    def start(self) -> None:
        """Start filesystem monitoring on all configured directories.

        Creates one Observer per watched directory. Each Observer runs as
        a daemon thread so it won't block agent shutdown.

        Raises:
            RuntimeError: If the watcher is already running.
        """
        with self._lock:
            if self._running:
                logger.warning("RealtimeFileWatcher.start() called but already running")
                return

            handler = SuspiciousFileHandler(
                watched_extensions=self._watched_extensions,
                exclusions=self._exclusions,
                callback=self._callback,
            )

            for directory in self._watched_directories:
                if not os.path.isdir(directory):
                    logger.warning(
                        "Watched directory does not exist, skipping: %s",
                        directory,
                    )
                    continue

                observer = Observer()
                observer.daemon = True  # Ensure clean shutdown
                try:
                    observer.schedule(handler, directory, recursive=True)
                    observer.start()
                    self._observers.append(observer)
                    logger.info("Started watching directory: %s", directory)
                except PermissionError:
                    logger.error(
                        "Insufficient permissions to watch: %s", directory
                    )
                except OSError as exc:
                    logger.error(
                        "Failed to watch directory %s: %s", directory, exc
                    )

            self._running = True
            logger.info(
                "RealtimeFileWatcher started — %d observers active",
                len(self._observers),
            )

    def stop(self) -> None:
        """Stop all filesystem observers and wait for threads to join.

        This method is idempotent — calling it multiple times is safe.
        """
        with self._lock:
            if not self._running:
                logger.debug("RealtimeFileWatcher.stop() called but not running")
                return

            logger.info("Stopping RealtimeFileWatcher...")
            for observer in self._observers:
                try:
                    observer.stop()
                except Exception as exc:
                    logger.error("Error stopping observer: %s", exc)

            # Wait for observer threads to finish (with timeout to avoid hangs)
            for observer in self._observers:
                try:
                    observer.join(timeout=5.0)
                    if observer.is_alive():
                        logger.warning(
                            "Observer thread did not terminate within timeout"
                        )
                except Exception as exc:
                    logger.error("Error joining observer thread: %s", exc)

            self._observers.clear()
            self._running = False
            logger.info("RealtimeFileWatcher stopped")

    @property
    def is_running(self) -> bool:
        """Return True if the watcher is currently active."""
        with self._lock:
            return self._running
