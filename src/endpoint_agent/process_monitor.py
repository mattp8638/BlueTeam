"""
process_monitor.py — Suspicious Process Detection Sensor

This module continuously monitors running processes on the endpoint,
detecting newly spawned processes that match known-suspicious names or
command-line patterns. It is a critical component of the agent's
behavioral detection pipeline.

Security Rationale:
    Many attack chains involve spawning recognizable processes — e.g.,
    `mimikatz.exe` for credential dumping, `powershell.exe -enc` for
    obfuscated script execution, or `certutil.exe -urlcache` for LOLBin
    file downloads. By monitoring the process table in near-real-time,
    we can detect these tools even when file-based detection is bypassed
    (e.g., fileless attacks, in-memory execution via process hollowing).

    The monitor only alerts on *newly seen* PIDs to avoid flooding the
    alert pipeline with repeated detections of the same long-running
    suspicious process.

Architecture:
    - A background daemon thread polls `psutil.process_iter()` every
      N seconds (default 5).
    - Each process's name is checked against a set of known-bad names.
    - Each process's command line is checked against a list of suspicious
      substring patterns (case-insensitive).
    - Previously-seen PIDs are tracked in a set to suppress duplicate alerts.
    - The PID tracking set is periodically pruned to remove dead PIDs,
      preventing unbounded memory growth on long-running systems.

Thread Safety:
    - The `_seen_pids` set is protected by a dedicated lock.
    - Start/stop lifecycle is protected by a separate lock.

Usage:
    from src.endpoint_agent.process_monitor import ProcessMonitor

    monitor = ProcessMonitor()
    monitor.start()
    # ... later ...
    monitor.stop()
"""

import time
import threading
from typing import List, Set, Optional, Dict, Any

import psutil

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("ProcessMonitor")


# ---------------------------------------------------------------------------
# Default configuration values
# ---------------------------------------------------------------------------
DEFAULT_POLL_INTERVAL: float = 5.0  # seconds

DEFAULT_SUSPICIOUS_NAMES: List[str] = [
    "mimikatz.exe",
    "lazagne.exe",
    "procdump.exe",
    "psexec.exe",
    "paexec.exe",
    "sharphound.exe",
    "bloodhound.exe",
    "rubeus.exe",
    "seatbelt.exe",
    "cobaltstrike.exe",
    "nc.exe",
    "ncat.exe",
    "netcat.exe",
    "wce.exe",
    "pwdump.exe",
    "fgdump.exe",
]

DEFAULT_SUSPICIOUS_CMDLINE_PATTERNS: List[str] = [
    # PowerShell obfuscation & download cradles
    "-encodedcommand",
    "-enc ",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "start-bitstransfer",
    # LOLBin abuse patterns
    "certutil -urlcache",
    "certutil -decode",
    "bitsadmin /transfer",
    "mshta vbscript",
    "mshta javascript",
    "regsvr32 /s /n /u /i:",
    "rundll32 javascript",
    "wmic process call create",
    "wmic /node:",
    # Credential access
    "sekurlsa::logonpasswords",
    "lsass.dmp",
    "comsvcs.dll, minidump",
    "comsvcs.dll,#24",
    # Reverse shells & tunneling
    "ncat -e",
    "nc -e",
    "socat tcp",
    "chisel client",
    "plink -ssh",
]

# How often to prune the seen-PID set to remove dead processes (seconds).
PID_PRUNE_INTERVAL: float = 60.0


class ProcessMonitor:
    """Monitors the system process table for suspicious activity.

    The monitor runs a daemon thread that periodically enumerates all
    running processes, compares them against configurable threat indicators,
    and logs critical alerts for any newly detected suspicious processes.

    Attributes:
        poll_interval: Seconds between process table scans.
    """

    def __init__(self, poll_interval: Optional[float] = None) -> None:
        # Load configuration
        config = AgentConfig.load()

        self._poll_interval: float = poll_interval or config.get(
            "process_poll_interval", DEFAULT_POLL_INTERVAL
        )

        # Build the set of suspicious process names (lowercase for matching)
        raw_names: List[str] = config.get(
            "suspicious_process_names", DEFAULT_SUSPICIOUS_NAMES
        )
        self._suspicious_names: Set[str] = {n.lower() for n in raw_names}

        # Build the list of suspicious command-line substrings (lowercase)
        raw_patterns: List[str] = config.get(
            "suspicious_cmdline_patterns", DEFAULT_SUSPICIOUS_CMDLINE_PATTERNS
        )
        self._suspicious_patterns: List[str] = [p.lower() for p in raw_patterns]

        # PID tracking: prevents duplicate alerts for the same process
        self._seen_pids: Set[int] = set()
        self._seen_pids_lock = threading.Lock()

        # Thread lifecycle management
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._last_prune_time: float = time.time()

        logger.info(
            "ProcessMonitor initialized — %d suspicious names, "
            "%d cmdline patterns, poll interval %.1fs",
            len(self._suspicious_names),
            len(self._suspicious_patterns),
            self._poll_interval,
        )

    # ---- Public API ------------------------------------------------------

    def start(self) -> None:
        """Start the process monitoring daemon thread.

        The thread runs until `stop()` is called. It is marked as a daemon
        thread so it won't prevent interpreter shutdown.
        """
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("ProcessMonitor.start() called but already running")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="ProcessMonitor-Worker",
                daemon=True,
            )
            self._thread.start()
            logger.info("ProcessMonitor started")

    def stop(self) -> None:
        """Signal the monitoring thread to stop and wait for it to exit.

        This method is idempotent and safe to call multiple times.
        """
        with self._lifecycle_lock:
            if self._thread is None or not self._thread.is_alive():
                logger.debug("ProcessMonitor.stop() called but not running")
                return

            logger.info("Stopping ProcessMonitor...")
            self._stop_event.set()
            self._thread.join(timeout=self._poll_interval + 2.0)

            if self._thread.is_alive():
                logger.warning("ProcessMonitor thread did not exit within timeout")
            else:
                logger.info("ProcessMonitor stopped")

            self._thread = None

    @property
    def is_running(self) -> bool:
        """Return True if the monitor thread is alive."""
        with self._lifecycle_lock:
            return self._thread is not None and self._thread.is_alive()

    # ---- Internal --------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Main loop executed by the daemon thread.

        Iterates through the process table, checks each process against
        threat indicators, and sleeps until the next poll interval.
        """
        logger.debug("ProcessMonitor worker thread started")
        while not self._stop_event.is_set():
            try:
                self._scan_processes()
            except Exception as exc:
                # Catch-all to keep the monitor alive through transient errors.
                # We log the full exception for forensic analysis.
                logger.error("Unhandled error in process scan: %s", exc, exc_info=True)

            # Periodic pruning of dead PIDs to prevent memory leaks
            if time.time() - self._last_prune_time > PID_PRUNE_INTERVAL:
                self._prune_dead_pids()

            # Use wait() instead of sleep() so we can be interrupted promptly
            self._stop_event.wait(timeout=self._poll_interval)

        logger.debug("ProcessMonitor worker thread exiting")

    def _scan_processes(self) -> None:
        """Enumerate all running processes and check for suspicious indicators.

        Uses `psutil.process_iter()` with `attrs` to batch-fetch process
        attributes in a single syscall per process, which is significantly
        faster than calling `.name()`, `.cmdline()` etc. individually.
        """
        for proc in psutil.process_iter(
            attrs=["pid", "name", "cmdline", "username"]
        ):
            try:
                info: Dict[str, Any] = proc.info  # type: ignore[attr-defined]
                pid: int = info["pid"]

                # Skip if we've already evaluated this PID
                with self._seen_pids_lock:
                    if pid in self._seen_pids:
                        continue

                proc_name: str = (info.get("name") or "").lower()
                cmdline_parts: List[str] = info.get("cmdline") or []
                cmdline_str: str = " ".join(cmdline_parts).lower()
                username: str = info.get("username") or "UNKNOWN"

                suspicious = False
                reason = ""

                # Check 1: Process name matches known-bad list
                if proc_name in self._suspicious_names:
                    suspicious = True
                    reason = f"Suspicious process name: {proc_name}"

                # Check 2: Command line contains suspicious pattern
                if not suspicious and cmdline_str:
                    for pattern in self._suspicious_patterns:
                        if pattern in cmdline_str:
                            suspicious = True
                            reason = f"Suspicious cmdline pattern: '{pattern}'"
                            break

                # Record the PID as seen regardless of suspicion, so we
                # don't re-evaluate it on every poll cycle.
                with self._seen_pids_lock:
                    self._seen_pids.add(pid)

                if suspicious:
                    # CRITICAL alert — this should trigger immediate response
                    logger.critical(
                        "SUSPICIOUS PROCESS DETECTED | "
                        "PID=%d | Name=%s | User=%s | "
                        "CmdLine=%s | Reason=%s",
                        pid,
                        info.get("name", "N/A"),
                        username,
                        " ".join(cmdline_parts) if cmdline_parts else "N/A",
                        reason,
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process died or we lack permissions — both are expected
                # in a dynamic process environment. Silently skip.
                pass
            except psutil.ZombieProcess:
                # Zombie processes have no useful info; skip them.
                pass

    def _prune_dead_pids(self) -> None:
        """Remove PIDs from the tracking set that are no longer running.

        This prevents unbounded growth of `_seen_pids` on systems that
        run for weeks or months without agent restart. We check each
        tracked PID against the current process table and remove any
        that no longer exist. This allows re-detection if a new process
        reuses the same PID (PID recycling).

        Security Note:
            PID recycling is a real concern — an attacker could exploit
            our PID tracking to evade detection by waiting for a benign
            process to exit and then launching a malicious process that
            inherits the same PID. Pruning dead PIDs mitigates this.
        """
        try:
            current_pids: Set[int] = set(psutil.pids())
            with self._seen_pids_lock:
                stale = self._seen_pids - current_pids
                if stale:
                    self._seen_pids -= stale
                    logger.debug("Pruned %d stale PIDs from tracking set", len(stale))
            self._last_prune_time = time.time()
        except Exception as exc:
            logger.error("Error pruning PID set: %s", exc)
