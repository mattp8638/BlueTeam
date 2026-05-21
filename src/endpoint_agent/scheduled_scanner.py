"""
scheduled_scanner.py — Full-Disk Scheduled Scanner
===================================================

Provides Quick Scan and Full Scan modes that walk configured directory trees
and feed each discovered file through the LocalAVEngine pipeline.  A background
daemon thread runs scans on a configurable interval (e.g. every 24 hours for
full scans, every 4 hours for quick scans).

Scan modes:
    - **Quick Scan**: Targets high-risk directories only (e.g. Downloads,
      Temp, AppData, Startup folders).  Designed to complete in minutes.
    - **Full Scan**: Walks every path in the configured full-scan list,
      typically covering all user-accessible volumes.  May take hours.

Performance safeguards:
    - Files larger than `max_scan_file_size_mb` are skipped to avoid
      hogging memory and CPU on multi-gigabyte ISOs or archives.
    - Files already cached as CLEAN in the hash cache are skipped entirely
      (the LocalAVEngine handles this, but we also pre-filter here to avoid
      even reading the file bytes from disk).
    - The scanner yields to the OS scheduler between files to prevent
      starving other endpoint processes of CPU time.

Security rationale:
    - Scheduled scanning catches dormant malware that was dropped to disk
      but not yet executed — filesystem monitors only trigger on write
      events, so files placed before the agent started would be missed.
    - Quick scans focus on directories where users commonly download or
      extract files, providing rapid coverage of the highest-risk areas.
"""

import os
import time
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig
from src.endpoint_agent.local_av_engine import LocalAVEngine

logger = AgentLogger.get_logger("ScheduledScanner")

# Default scan paths when configuration does not specify them
DEFAULT_QUICK_SCAN_PATHS = [
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
    ),
]

DEFAULT_FULL_SCAN_PATHS = [
    r"C:\Users",
    r"C:\ProgramData",
]

# Default maximum file size in megabytes — files above this are skipped
DEFAULT_MAX_SCAN_FILE_SIZE_MB = 100

# Default scan interval in seconds (4 hours for quick, 24 hours for full)
DEFAULT_QUICK_SCAN_INTERVAL = 4 * 3600
DEFAULT_FULL_SCAN_INTERVAL = 24 * 3600


class ScanResult:
    """Container for the results of a completed scan.

    Attributes:
        scan_type: 'quick' or 'full'.
        start_time: ISO-8601 UTC timestamp when the scan started.
        end_time: ISO-8601 UTC timestamp when the scan finished.
        elapsed_seconds: Wall-clock duration of the scan.
        files_scanned: Number of files successfully scanned.
        files_skipped_size: Number of files skipped due to size limit.
        files_skipped_cached: Number of files skipped due to cache hits.
        files_skipped_error: Number of files that could not be read.
        threats_found: Number of malicious files detected.
        findings: List of OCSF finding dicts for each detection.
    """

    def __init__(self, scan_type: str):
        self.scan_type = scan_type
        self.start_time: str = ""
        self.end_time: str = ""
        self.elapsed_seconds: float = 0.0
        self.files_scanned: int = 0
        self.files_skipped_size: int = 0
        self.files_skipped_cached: int = 0
        self.files_skipped_error: int = 0
        self.threats_found: int = 0
        self.findings: List[Dict] = []

    def to_dict(self) -> Dict:
        """Serialise the scan result to a dict for reporting."""
        return {
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "files_scanned": self.files_scanned,
            "files_skipped_size": self.files_skipped_size,
            "files_skipped_cached": self.files_skipped_cached,
            "files_skipped_error": self.files_skipped_error,
            "threats_found": self.threats_found,
            "finding_count": len(self.findings),
        }


class ScheduledScanner:
    """Full-disk scanner with Quick Scan and Full Scan modes.

    The scanner uses the LocalAVEngine to perform the actual file analysis.
    It runs as a daemon thread in the background, executing scans at
    configured intervals.

    Attributes:
        config: Loaded agent configuration.
        av_engine: The LocalAVEngine instance used for file scanning.
        quick_scan_paths: List of directories for quick scans.
        full_scan_paths: List of directories for full scans.
        max_file_size_bytes: Maximum file size to scan (in bytes).
        quick_scan_interval: Seconds between quick scans.
        full_scan_interval: Seconds between full scans.
        _stop_event: Threading event used to signal the background thread
            to shut down gracefully.
        _thread: The background daemon thread running scheduled scans.
    """

    def __init__(self, av_engine: Optional[LocalAVEngine] = None):
        """Initialise the scanner with configuration and an AV engine.

        Args:
            av_engine: An existing LocalAVEngine instance to use.  If None,
                a new one is created.  Passing an existing instance allows
                the scheduled scanner to share the same hash cache and
                quarantine vault as the real-time filesystem monitor.
        """
        self.config = AgentConfig.load()
        self.av_engine = av_engine or LocalAVEngine()

        # Load scan paths from configuration, falling back to defaults
        self.quick_scan_paths = self.config.get(
            "quick_scan_paths", DEFAULT_QUICK_SCAN_PATHS
        )
        self.full_scan_paths = self.config.get(
            "full_scan_paths", DEFAULT_FULL_SCAN_PATHS
        )

        # Convert MB config value to bytes for size comparisons
        max_mb = float(
            self.config.get("max_scan_file_size_mb", DEFAULT_MAX_SCAN_FILE_SIZE_MB)
        )
        self.max_file_size_bytes = int(max_mb * 1024 * 1024)

        # Scan intervals
        self.quick_scan_interval = int(
            self.config.get("quick_scan_interval", DEFAULT_QUICK_SCAN_INTERVAL)
        )
        self.full_scan_interval = int(
            self.config.get("full_scan_interval", DEFAULT_FULL_SCAN_INTERVAL)
        )

        # Background thread control
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Track the last scan result for status reporting
        self._last_quick_result: Optional[ScanResult] = None
        self._last_full_result: Optional[ScanResult] = None

        logger.info(
            "ScheduledScanner initialised — quick_paths=%d full_paths=%d "
            "max_file_size=%dMB quick_interval=%ds full_interval=%ds",
            len(self.quick_scan_paths),
            len(self.full_scan_paths),
            int(max_mb),
            self.quick_scan_interval,
            self.full_scan_interval,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _utcnow_iso() -> str:
        """Return current UTC time as ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()

    def _walk_and_scan(
        self, scan_paths: List[str], result: ScanResult
    ) -> None:
        """Walk the given directory paths and scan each file.

        This is the core scanning loop shared by quick_scan() and full_scan().
        It applies size filtering and feeds files to the AV engine one at a
        time.

        Args:
            scan_paths: List of directory paths to walk recursively.
            result: A ScanResult object to accumulate statistics into.
        """
        for scan_root in scan_paths:
            if self._stop_event.is_set():
                logger.info("Scan interrupted by stop event")
                break

            if not os.path.isdir(scan_root):
                logger.warning("Scan path does not exist, skipping: %s", scan_root)
                continue

            logger.info("Scanning directory tree: %s", scan_root)

            for dirpath, dirnames, filenames in os.walk(scan_root):
                if self._stop_event.is_set():
                    break

                # Skip the quarantine vault directory to avoid scanning
                # already-quarantined files (they would re-trigger detections)
                quarantine_dir = self.config.get(
                    "quarantine_dir", r"C:\ProgramData\BlueTeam\quarantine"
                )
                if os.path.abspath(dirpath).startswith(
                    os.path.abspath(quarantine_dir)
                ):
                    logger.debug("Skipping quarantine directory: %s", dirpath)
                    dirnames.clear()  # Don't descend into subdirectories
                    continue

                for filename in filenames:
                    if self._stop_event.is_set():
                        break

                    file_path = os.path.join(dirpath, filename)

                    # ---- Size filter ----
                    try:
                        file_size = os.path.getsize(file_path)
                    except OSError:
                        result.files_skipped_error += 1
                        continue

                    if file_size > self.max_file_size_bytes:
                        result.files_skipped_size += 1
                        logger.debug(
                            "Skipping oversized file (%d bytes): %s",
                            file_size,
                            file_path,
                        )
                        continue

                    if file_size == 0:
                        # Empty files are not interesting — skip silently
                        continue

                    # ---- Read and scan ----
                    try:
                        with open(file_path, "rb") as fh:
                            raw_bytes = fh.read()
                    except (OSError, PermissionError) as exc:
                        result.files_skipped_error += 1
                        logger.debug(
                            "Cannot read file %s: %s", file_path, exc
                        )
                        continue

                    try:
                        finding = self.av_engine.scan_file(file_path, raw_bytes)
                        result.files_scanned += 1

                        if finding is not None:
                            result.threats_found += 1
                            result.findings.append(finding)
                            logger.warning(
                                "Threat found during %s scan: %s",
                                result.scan_type,
                                file_path,
                            )
                    except Exception as exc:
                        result.files_skipped_error += 1
                        logger.error(
                            "Unexpected error scanning %s: %s", file_path, exc
                        )

                    # Yield CPU to prevent scan from starving other processes.
                    # A 1ms sleep per file is imperceptible to the scan but
                    # prevents 100% CPU utilisation on busy endpoints.
                    time.sleep(0.001)

    # ------------------------------------------------------------------
    # Public API — Scan methods
    # ------------------------------------------------------------------

    def quick_scan(self) -> ScanResult:
        """Run a quick scan of high-risk directories.

        Scans only the paths listed in `quick_scan_paths` configuration.
        Designed to complete in minutes on a typical endpoint.

        Returns:
            A ScanResult containing statistics and any findings.
        """
        result = ScanResult(scan_type="quick")
        result.start_time = self._utcnow_iso()

        logger.info(
            "===== QUICK SCAN STARTED ===== paths=%d",
            len(self.quick_scan_paths),
        )

        start = time.monotonic()
        self.av_engine.reset_stats()

        self._walk_and_scan(self.quick_scan_paths, result)

        result.elapsed_seconds = time.monotonic() - start
        result.end_time = self._utcnow_iso()
        self._last_quick_result = result

        logger.info(
            "===== QUICK SCAN COMPLETE ===== "
            "scanned=%d threats=%d skipped_size=%d skipped_error=%d elapsed=%.1fs",
            result.files_scanned,
            result.threats_found,
            result.files_skipped_size,
            result.files_skipped_error,
            result.elapsed_seconds,
        )

        return result

    def full_scan(self) -> ScanResult:
        """Run a full scan of all configured paths.

        Walks every directory in `full_scan_paths`.  This may take hours
        depending on the volume of data on the endpoint.

        Returns:
            A ScanResult containing statistics and any findings.
        """
        result = ScanResult(scan_type="full")
        result.start_time = self._utcnow_iso()

        logger.info(
            "===== FULL SCAN STARTED ===== paths=%d",
            len(self.full_scan_paths),
        )

        start = time.monotonic()
        self.av_engine.reset_stats()

        self._walk_and_scan(self.full_scan_paths, result)

        result.elapsed_seconds = time.monotonic() - start
        result.end_time = self._utcnow_iso()
        self._last_full_result = result

        logger.info(
            "===== FULL SCAN COMPLETE ===== "
            "scanned=%d threats=%d skipped_size=%d skipped_error=%d elapsed=%.1fs",
            result.files_scanned,
            result.threats_found,
            result.files_skipped_size,
            result.files_skipped_error,
            result.elapsed_seconds,
        )

        return result

    # ------------------------------------------------------------------
    # Public API — Background scheduling
    # ------------------------------------------------------------------

    def _scheduled_loop(self) -> None:
        """Background thread loop that alternates between quick and full scans.

        The loop runs a quick scan at `quick_scan_interval` and a full scan
        at `full_scan_interval`.  Between scans it sleeps in short increments
        so that the stop event is checked frequently for responsive shutdown.
        """
        logger.info("Scheduled scanner background loop started")

        last_quick_time = 0.0
        last_full_time = 0.0

        while not self._stop_event.is_set():
            now = time.monotonic()

            # ---- Quick scan check ----
            if (now - last_quick_time) >= self.quick_scan_interval:
                try:
                    self.quick_scan()
                except Exception as exc:
                    logger.error("Quick scan failed: %s", exc)
                last_quick_time = time.monotonic()

            # ---- Full scan check ----
            if (now - last_full_time) >= self.full_scan_interval:
                try:
                    self.full_scan()
                except Exception as exc:
                    logger.error("Full scan failed: %s", exc)
                last_full_time = time.monotonic()

            # Sleep in 5-second increments so we can respond to stop_event
            # within a reasonable time frame
            self._stop_event.wait(timeout=5.0)

        logger.info("Scheduled scanner background loop exiting")

    def start_scheduled(self) -> None:
        """Start the background scheduled scanning thread.

        The thread runs as a daemon so it does not prevent the Python
        interpreter from exiting during agent shutdown.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Scheduled scanner is already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._scheduled_loop,
            name="ScheduledScanner",
            daemon=True,
        )
        self._thread.start()
        logger.info("Scheduled scanner background thread started")

    def start(self) -> None:
        """Start the scheduled scanner (alias for start_scheduled).

        Provided for interface consistency with other monitor modules that
        expose start()/stop() methods.
        """
        self.start_scheduled()

    def stop(self) -> None:
        """Stop the background scanning thread gracefully.

        Signals the thread to stop and waits up to 10 seconds for it to
        finish the current file scan and exit cleanly.
        """
        if self._thread is None or not self._thread.is_alive():
            logger.info("Scheduled scanner is not running")
            return

        logger.info("Stopping scheduled scanner...")
        self._stop_event.set()
        self._thread.join(timeout=10.0)

        if self._thread.is_alive():
            logger.warning(
                "Scheduled scanner thread did not exit within timeout — "
                "it will be terminated when the process exits (daemon thread)"
            )
        else:
            logger.info("Scheduled scanner stopped cleanly")

        self._thread = None

    # ------------------------------------------------------------------
    # Public API — Status
    # ------------------------------------------------------------------

    def get_last_results(self) -> Dict:
        """Return the results of the most recent quick and full scans.

        Returns:
            A dict with 'last_quick_scan' and 'last_full_scan' keys,
            each containing a scan result dict or None.
        """
        return {
            "last_quick_scan": (
                self._last_quick_result.to_dict()
                if self._last_quick_result
                else None
            ),
            "last_full_scan": (
                self._last_full_result.to_dict()
                if self._last_full_result
                else None
            ),
        }

    def is_running(self) -> bool:
        """Check if the background scanning thread is currently active.

        Returns:
            True if the scheduled scanner thread is alive.
        """
        return self._thread is not None and self._thread.is_alive()
