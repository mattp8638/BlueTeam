"""
event_log_collector.py — Windows Event Log Collection Sensor

This module reads Windows Event Logs (Security, System, Application) and
streams security-relevant events to a callback function for forwarding
to a SIEM or local analysis engine.

Security Rationale:
    Windows Event Logs are a goldmine of forensic data and real-time threat
    indicators. Key events monitored include:
    - Event ID 4624/4625: Successful/failed logon attempts
    - Event ID 4688: New process creation (with command line auditing)
    - Event ID 4697: Service installation
    - Event ID 4720: User account created
    - Event ID 7045: New service installed (System log)
    - Event ID 1102: Audit log cleared (potential evidence destruction)

    By collecting these events in near-real-time, we enable:
    1. Correlation with other sensor data (process, network, file)
    2. Forwarding to a centralized SIEM for enterprise-wide analysis
    3. Local detection rules for high-fidelity alerts

Architecture:
    - A background daemon thread polls event logs at configurable intervals.
    - For each configured log source, the collector reads new events since
      the last-processed record number.
    - Events are normalized into a standard dict format and forwarded to
      the registered callback.
    - When `win32evtlog` (pywin32) is unavailable, a simulated event
      generator produces realistic mock events for testing.

Platform Compatibility:
    - On Windows with pywin32: reads real event logs via the Win32 API.
    - Fallback: generates simulated events for development/testing.

Thread Safety:
    - `_last_record_numbers` dict is protected by a lock.
    - Lifecycle operations use a separate lock.

Usage:
    from src.endpoint_agent.event_log_collector import EventLogCollector

    def on_event(event_dict):
        print(f"Event: {event_dict}")

    collector = EventLogCollector(callback=on_event)
    collector.start()
    # ... later ...
    collector.stop()
"""

import time
import random
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Any

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("EventLogCollector")

# ---------------------------------------------------------------------------
# Attempt to import pywin32's event log module
# ---------------------------------------------------------------------------
_WIN32EVTLOG_AVAILABLE = False
try:
    import win32evtlog  # type: ignore[import]
    import win32con     # type: ignore[import]
    _WIN32EVTLOG_AVAILABLE = True
    logger.info("win32evtlog module available — using live event log access")
except ImportError:
    logger.warning(
        "win32evtlog (pywin32) not available — falling back to simulated events. "
        "Install pywin32 for real event log collection."
    )

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_POLL_INTERVAL: float = 10.0  # seconds
DEFAULT_LOG_SOURCES: List[str] = ["Security", "System", "Application"]

# Security-relevant Event IDs we specifically watch for.
# Events not in this set are still collected but at a lower log level.
HIGH_PRIORITY_EVENT_IDS: Dict[int, str] = {
    # Security log — Authentication & Account Management
    4624: "Successful logon",
    4625: "Failed logon attempt",
    4634: "Account logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned to logon",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempt",
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4756: "Member added to security-enabled universal group",
    # Security log — Process & Service Auditing
    4688: "New process created",
    4689: "Process exited",
    4697: "Service installed on the system",
    # Security log — Audit Policy & Log Tampering
    1102: "Audit log was cleared",
    4719: "System audit policy changed",
    # System log — Service Management
    7034: "Service crashed unexpectedly",
    7036: "Service entered running/stopped state",
    7040: "Service start type changed",
    7045: "New service installed",
}

# Event IDs that should trigger CRITICAL alerts (potential attack indicators)
CRITICAL_EVENT_IDS: set = {
    1102,   # Log clearing — evidence destruction
    4720,   # Account creation — persistence
    4697,   # Service installed — persistence
    7045,   # New service — persistence
    4625,   # Failed logon — brute force indicator
    4648,   # Explicit credentials — lateral movement
}


class EventLogCollector:
    """Collects and forwards Windows Event Log entries.

    The collector reads events from configured log sources (Security,
    System, Application), normalizes them into a standard dictionary
    format, and forwards them to a callback for SIEM integration.

    Args:
        callback: Function called with each event dict.
                  Signature: callback(event: Dict[str, Any]) -> None.
                  Must be thread-safe.
        poll_interval: Seconds between log poll cycles.
    """

    def __init__(
        self,
        callback: Callable[[Dict[str, Any]], None],
        poll_interval: Optional[float] = None,
    ) -> None:
        config = AgentConfig.load()

        self._callback = callback
        self._poll_interval: float = poll_interval or config.get(
            "eventlog_poll_interval", DEFAULT_POLL_INTERVAL
        )
        self._log_sources: List[str] = config.get(
            "eventlog_sources", DEFAULT_LOG_SOURCES
        )

        # Track last-read event record number per log source.
        # This prevents re-reading events we've already processed.
        self._last_record_numbers: Dict[str, int] = {}
        self._record_lock = threading.Lock()

        # Thread lifecycle
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()

        # Simulated event counter (only used in fallback mode)
        self._sim_counter: int = 1000

        logger.info(
            "EventLogCollector initialized — sources=%s, poll interval %.1fs, "
            "live=%s",
            self._log_sources,
            self._poll_interval,
            _WIN32EVTLOG_AVAILABLE,
        )

    # ---- Public API ------------------------------------------------------

    def start(self) -> None:
        """Start the event log collection daemon thread."""
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("EventLogCollector.start() called but already running")
                return

            self._stop_event.clear()

            # Initialize last record numbers to current position so we
            # only collect NEW events going forward (not historical).
            self._initialize_positions()

            self._thread = threading.Thread(
                target=self._collection_loop,
                name="EventLogCollector-Worker",
                daemon=True,
            )
            self._thread.start()
            logger.info("EventLogCollector started")

    def stop(self) -> None:
        """Stop the event log collection thread."""
        with self._lifecycle_lock:
            if self._thread is None or not self._thread.is_alive():
                logger.debug("EventLogCollector.stop() called but not running")
                return

            logger.info("Stopping EventLogCollector...")
            self._stop_event.set()
            self._thread.join(timeout=self._poll_interval + 2.0)

            if self._thread.is_alive():
                logger.warning("EventLogCollector thread did not exit within timeout")
            else:
                logger.info("EventLogCollector stopped")

            self._thread = None

    @property
    def is_running(self) -> bool:
        """Return True if the collector thread is alive."""
        with self._lifecycle_lock:
            return self._thread is not None and self._thread.is_alive()

    # ---- Initialization --------------------------------------------------

    def _initialize_positions(self) -> None:
        """Set the initial read position for each log source.

        We start at the current end of each log so we only process
        events that occur *after* the agent starts. This avoids
        flooding the pipeline with historical events on first run.

        For a full historical ingestion, set initial positions to 0
        via configuration.
        """
        with self._record_lock:
            for source in self._log_sources:
                if _WIN32EVTLOG_AVAILABLE:
                    try:
                        hand = win32evtlog.OpenEventLog(None, source)
                        flags = (
                            win32evtlog.EVENTLOG_BACKWARDS_READ
                            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        )
                        total = win32evtlog.GetNumberOfEventLogRecords(hand)
                        self._last_record_numbers[source] = total
                        win32evtlog.CloseEventLog(hand)
                        logger.info(
                            "Initialized %s log — %d existing records (skipped)",
                            source,
                            total,
                        )
                    except Exception as exc:
                        logger.error(
                            "Failed to initialize position for %s: %s",
                            source,
                            exc,
                        )
                        self._last_record_numbers[source] = 0
                else:
                    # Simulated mode — start at 0
                    self._last_record_numbers[source] = 0
                    logger.debug(
                        "Simulated mode — initialized %s at position 0", source
                    )

    # ---- Collection Loop -------------------------------------------------

    def _collection_loop(self) -> None:
        """Background thread: periodically poll event logs for new entries."""
        logger.debug("EventLogCollector worker thread started")

        while not self._stop_event.is_set():
            for source in self._log_sources:
                if self._stop_event.is_set():
                    break
                try:
                    if _WIN32EVTLOG_AVAILABLE:
                        self._collect_real_events(source)
                    else:
                        self._collect_simulated_events(source)
                except Exception as exc:
                    logger.error(
                        "Error collecting from %s log: %s",
                        source,
                        exc,
                        exc_info=True,
                    )

            self._stop_event.wait(timeout=self._poll_interval)

        logger.debug("EventLogCollector worker thread exiting")

    # ---- Real Event Log Collection (pywin32) -----------------------------

    def _collect_real_events(self, source: str) -> None:
        """Read new events from a real Windows Event Log source.

        Uses the Win32 API via pywin32 to read events sequentially from
        the last-known position forward.

        Args:
            source: Event log name (e.g., 'Security', 'System').
        """
        try:
            hand = win32evtlog.OpenEventLog(None, source)
        except Exception as exc:
            logger.error("Cannot open event log '%s': %s", source, exc)
            return

        try:
            flags = (
                win32evtlog.EVENTLOG_FORWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            events_processed = 0
            max_events_per_cycle = 500  # Cap to prevent blocking too long

            while events_processed < max_events_per_cycle:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                except Exception:
                    # No more events to read
                    break

                if not events:
                    break

                for event in events:
                    record_num = event.RecordNumber

                    # Skip events we've already processed
                    with self._record_lock:
                        last = self._last_record_numbers.get(source, 0)
                        if record_num <= last:
                            continue
                        self._last_record_numbers[source] = record_num

                    # Normalize the event into a standard dict
                    event_dict = self._normalize_win32_event(event, source)
                    self._dispatch_event(event_dict)
                    events_processed += 1

            if events_processed > 0:
                logger.debug(
                    "Collected %d new events from %s log",
                    events_processed,
                    source,
                )

        finally:
            win32evtlog.CloseEventLog(hand)

    def _normalize_win32_event(
        self, event: Any, source: str
    ) -> Dict[str, Any]:
        """Convert a win32evtlog event object to a normalized dictionary.

        The normalized format is designed for easy serialization and
        SIEM ingestion, with consistent field names across all event types.
        """
        event_id = event.EventID & 0xFFFF  # Mask to get the actual event ID

        # Determine severity based on event type
        severity = "INFO"
        if hasattr(event, "EventType"):
            if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                severity = "ERROR"
            elif event.EventType == win32con.EVENTLOG_WARNING_TYPE:
                severity = "WARNING"
            elif event.EventType == win32con.EVENTLOG_AUDIT_FAILURE:
                severity = "AUDIT_FAILURE"
            elif event.EventType == win32con.EVENTLOG_AUDIT_SUCCESS:
                severity = "AUDIT_SUCCESS"

        return {
            "timestamp": str(event.TimeGenerated),
            "source": source,
            "provider": event.SourceName or "Unknown",
            "event_id": event_id,
            "event_description": HIGH_PRIORITY_EVENT_IDS.get(event_id, ""),
            "record_number": event.RecordNumber,
            "severity": severity,
            "computer": event.ComputerName or "Unknown",
            "sid": str(event.Sid) if event.Sid else None,
            "strings": list(event.StringInserts) if event.StringInserts else [],
            "data": bytes(event.Data) if event.Data else None,
            "is_critical": event_id in CRITICAL_EVENT_IDS,
        }

    # ---- Simulated Event Collection (fallback) ---------------------------

    def _collect_simulated_events(self, source: str) -> None:
        """Generate simulated events for testing when pywin32 is unavailable.

        Produces a random selection of security-relevant events with
        realistic field values. This enables full pipeline testing
        without a Windows environment.
        """
        # Simulate 0-3 events per poll cycle per source
        num_events = random.randint(0, 3)
        if num_events == 0:
            return

        for _ in range(num_events):
            self._sim_counter += 1
            event_id = random.choice(list(HIGH_PRIORITY_EVENT_IDS.keys()))

            event_dict: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "provider": self._get_simulated_provider(source),
                "event_id": event_id,
                "event_description": HIGH_PRIORITY_EVENT_IDS.get(event_id, ""),
                "record_number": self._sim_counter,
                "severity": self._get_simulated_severity(event_id),
                "computer": "WORKSTATION-01",
                "sid": "S-1-5-21-SIMULATED",
                "strings": self._get_simulated_strings(event_id),
                "data": None,
                "is_critical": event_id in CRITICAL_EVENT_IDS,
                "simulated": True,  # Flag so consumers know this is mock data
            }

            # Update last record number
            with self._record_lock:
                self._last_record_numbers[source] = self._sim_counter

            self._dispatch_event(event_dict)

        logger.debug(
            "Generated %d simulated events for %s log", num_events, source
        )

    @staticmethod
    def _get_simulated_provider(source: str) -> str:
        """Return a realistic provider name for simulated events."""
        providers = {
            "Security": "Microsoft-Windows-Security-Auditing",
            "System": "Service Control Manager",
            "Application": "Application Error",
        }
        return providers.get(source, "SimulatedProvider")

    @staticmethod
    def _get_simulated_severity(event_id: int) -> str:
        """Map an event ID to an appropriate severity level."""
        if event_id in CRITICAL_EVENT_IDS:
            return "AUDIT_FAILURE" if event_id == 4625 else "WARNING"
        return "AUDIT_SUCCESS" if event_id in {4624, 4634, 4672} else "INFO"

    @staticmethod
    def _get_simulated_strings(event_id: int) -> List[str]:
        """Generate realistic StringInserts data for simulated events.

        These mimic the actual data fields that Windows includes in
        event log entries, enabling realistic testing of parsing logic.
        """
        templates: Dict[int, List[str]] = {
            4624: [
                "S-1-5-21-3623811015-3361044348-30300820-1013",
                "admin",
                "WORKSTATION-01",
                "10",  # Logon type (RemoteInteractive)
                "NTLM",
                "192.168.1.50",
            ],
            4625: [
                "S-1-0-0",
                "administrator",
                "WORKSTATION-01",
                "3",   # Logon type (Network)
                "NtLmSsp",
                "10.0.0.100",
                "0xc000006d",  # STATUS_LOGON_FAILURE
            ],
            4688: [
                "0x00000001",  # Token elevation type
                r"C:\Windows\System32\cmd.exe",
                "WORKSTATION-01\\admin",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "cmd.exe /c whoami",
            ],
            4720: [
                "backdoor_user",
                "WORKSTATION-01",
                "S-1-5-21-3623811015-3361044348-30300820-1014",
                "admin",
            ],
            1102: [
                "Security",
                "admin",
                "WORKSTATION-01",
            ],
            7045: [
                "MaliciousService",
                r"C:\Windows\Temp\payload.exe",
                "LocalSystem",
                "auto start",
            ],
        }
        return templates.get(event_id, ["SimulatedData"])

    # ---- Event Dispatch --------------------------------------------------

    def _dispatch_event(self, event_dict: Dict[str, Any]) -> None:
        """Forward a normalized event to the registered callback.

        High-priority and critical events are also logged locally for
        immediate visibility in the agent's own logs.
        """
        event_id = event_dict.get("event_id", 0)
        is_critical = event_dict.get("is_critical", False)

        # Log critical events at the CRITICAL level for immediate attention
        if is_critical:
            logger.critical(
                "CRITICAL EVENT | Source=%s | EventID=%d | Description=%s | "
                "Computer=%s | Strings=%s",
                event_dict.get("source"),
                event_id,
                event_dict.get("event_description", ""),
                event_dict.get("computer"),
                str(event_dict.get("strings", []))[:300],
            )
        elif event_id in HIGH_PRIORITY_EVENT_IDS:
            logger.info(
                "Security Event | Source=%s | EventID=%d | Description=%s",
                event_dict.get("source"),
                event_id,
                event_dict.get("event_description", ""),
            )

        # Forward to the callback (e.g., SIEM forwarder)
        try:
            self._callback(event_dict)
        except Exception as exc:
            # Never let a callback exception crash the collector thread
            logger.error(
                "Event callback raised exception for EventID=%d: %s",
                event_id,
                exc,
            )
