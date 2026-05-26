"""
network_monitor.py — Network Connection Analysis Sensor

This module provides continuous monitoring of active network connections
on the endpoint, detecting suspicious outbound communication patterns
that may indicate command-and-control (C2) activity, data exfiltration,
or unauthorized lateral movement.

Security Rationale:
    Network-based indicators are often the last line of defense when
    file-based and process-based detection are evaded. Key detection
    strategies implemented here:

    1. **Known-Bad Ports**: Many C2 frameworks default to specific ports
       (e.g., 4444 for Metasploit, 8443 for Cobalt Strike). While trivially
       changeable, many commodity malware and red-team engagements still
       use default configurations.

    2. **C2 Beaconing Detection**: Advanced persistent threats (APTs)
       establish periodic callbacks to their C2 infrastructure. By tracking
       the timing of connections to each remote endpoint, we can detect
       regular intervals (beaconing) that are characteristic of implants
       like Cobalt Strike, Covenant, and similar frameworks.

    3. **High-Rate External Connections**: Sudden spikes in outbound data
       (simulated here via connection counts) may indicate data exfiltration.

Architecture:
    - A background daemon thread polls `psutil.net_connections()` at a
      configurable interval.
    - Each connection is evaluated against threat indicators.
    - A `_connection_history` dict tracks timestamps of connections per
      remote endpoint for beaconing analysis.
    - History is periodically pruned to prevent unbounded memory growth.

Thread Safety:
    - `_connection_history` is protected by a dedicated lock.
    - Lifecycle operations are protected by a separate lock.

Usage:
    from src.endpoint_agent.network_monitor import NetworkMonitor

    monitor = NetworkMonitor()
    monitor.start()
    # ... later ...
    monitor.stop()
"""

import time
import ipaddress
import threading
import statistics
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

import psutil

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("NetworkMonitor")


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_POLL_INTERVAL: float = 10.0  # seconds

# Ports commonly used by C2 frameworks, reverse shells, and attack tools.
# This is NOT a blocklist — it's an alert trigger for deeper investigation.
DEFAULT_KNOWN_BAD_PORTS: List[int] = [
    4444,   # Metasploit default handler
    4445,   # Metasploit HTTPS
    5555,   # Common reverse shell / Android ADB
    8443,   # Cobalt Strike default HTTPS
    8080,   # Common alternative HTTP (not inherently bad, but worth watching)
    1080,   # SOCKS proxy
    9001,   # Tor default
    9050,   # Tor SOCKS
    9051,   # Tor control
    6666,   # IRC (common old-school C2)
    6667,   # IRC
    3389,   # RDP — suspicious if outbound from a workstation
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    445,    # SMB — suspicious if going to external IPs
    135,    # RPC — lateral movement indicator
    31337,  # Classic "elite" backdoor port
]

# Beaconing detection parameters
BEACON_MIN_SAMPLES: int = 5       # Minimum connections before analyzing pattern
BEACON_MAX_JITTER: float = 0.35   # Maximum coefficient of variation for beaconing
BEACON_WINDOW_SECONDS: float = 600.0  # Only analyze connections within this window

# History pruning: remove entries older than this
HISTORY_MAX_AGE: float = 1800.0  # 30 minutes


class NetworkMonitor:
    """Monitors active network connections for suspicious activity.

    The monitor detects connections to known-bad ports, flags suspicious
    external endpoints, and performs statistical analysis of connection
    timing patterns to identify C2 beaconing behavior.

    Args:
        poll_interval: Seconds between connection table scans.
    """

    def __init__(self, poll_interval: Optional[float] = None) -> None:
        config = AgentConfig.load()

        self._poll_interval: float = poll_interval or config.get(
            "network_poll_interval", DEFAULT_POLL_INTERVAL
        )

        # Known-bad ports loaded from config
        raw_ports: List[int] = config.get(
            "known_bad_ports", DEFAULT_KNOWN_BAD_PORTS
        )
        self._known_bad_ports: Set[int] = set(raw_ports)

        # Connection history for beaconing detection:
        #   { (remote_ip, remote_port): [timestamp1, timestamp2, ...] }
        self._connection_history: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        self._history_lock = threading.Lock()

        # Track already-alerted connections to avoid per-poll noise.
        # Key is (local_port, remote_ip, remote_port).
        self._alerted_connections: Set[Tuple[int, str, int]] = set()
        self._alerted_lock = threading.Lock()

        # Thread lifecycle
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._last_prune_time: float = time.time()

        logger.info(
            "NetworkMonitor initialized — %d known-bad ports, poll interval %.1fs",
            len(self._known_bad_ports),
            self._poll_interval,
        )

    # ---- Public API ------------------------------------------------------

    def start(self) -> None:
        """Start the network monitoring daemon thread."""
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("NetworkMonitor.start() called but already running")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="NetworkMonitor-Worker",
                daemon=True,
            )
            self._thread.start()
            logger.info("NetworkMonitor started")

    def stop(self) -> None:
        """Stop the network monitoring thread."""
        with self._lifecycle_lock:
            if self._thread is None or not self._thread.is_alive():
                logger.debug("NetworkMonitor.stop() called but not running")
                return

            logger.info("Stopping NetworkMonitor...")
            self._stop_event.set()
            self._thread.join(timeout=self._poll_interval + 2.0)

            if self._thread.is_alive():
                logger.warning("NetworkMonitor thread did not exit within timeout")
            else:
                logger.info("NetworkMonitor stopped")

            self._thread = None

    @property
    def is_running(self) -> bool:
        """Return True if the monitor thread is alive."""
        with self._lifecycle_lock:
            return self._thread is not None and self._thread.is_alive()

    # ---- Internal --------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Main loop: poll connections, analyze, and sleep."""
        logger.debug("NetworkMonitor worker thread started")

        while not self._stop_event.is_set():
            try:
                self._scan_connections()
            except Exception as exc:
                logger.error(
                    "Unhandled error in network scan: %s", exc, exc_info=True
                )

            # Periodic cleanup
            now = time.time()
            if now - self._last_prune_time > 120.0:
                self._prune_history()
                self._prune_alerted_connections()
                self._last_prune_time = now

            self._stop_event.wait(timeout=self._poll_interval)

        logger.debug("NetworkMonitor worker thread exiting")

    def _scan_connections(self) -> None:
        """Enumerate active TCP connections and evaluate each one.

        We focus on ESTABLISHED connections since those represent active
        data channels. LISTEN sockets are checked separately for
        unauthorized services.
        """
        now = time.time()

        try:
            connections = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            logger.warning(
                "Access denied enumerating connections — "
                "agent may need elevated privileges"
            )
            return
        except OSError as exc:
            logger.error("OS error enumerating connections: %s", exc)
            return

        for conn in connections:
            try:
                self._evaluate_connection(conn, now)
            except Exception as exc:
                # Per-connection errors should not abort the entire scan
                logger.debug("Error evaluating connection: %s", exc)

    def _evaluate_connection(self, conn: "any", now: float) -> None:
        """Evaluate a single connection against all threat indicators.

        Args:
            conn: A psutil connection named tuple.
            now: Current timestamp for history tracking.
        """
        # Only analyze connections with remote addresses
        if not conn.raddr:
            return

        remote_ip: str = conn.raddr.ip
        remote_port: int = conn.raddr.port
        local_port: int = conn.laddr.port if conn.laddr else 0
        status: str = conn.status

        # Build a connection key for dedup
        conn_key = (local_port, remote_ip, remote_port)

        # --- Record connection timestamp for beaconing analysis ---
        with self._history_lock:
            self._connection_history[(remote_ip, remote_port)].append(now)

        # --- Check 1: Known-bad destination port ---
        if remote_port in self._known_bad_ports:
            with self._alerted_lock:
                if conn_key not in self._alerted_connections:
                    self._alerted_connections.add(conn_key)
                    logger.critical(
                        "SUSPICIOUS CONNECTION — KNOWN-BAD PORT | "
                        "LocalPort=%d | RemoteIP=%s | RemotePort=%d | "
                        "Status=%s | PID=%s",
                        local_port,
                        remote_ip,
                        remote_port,
                        status,
                        conn.pid or "N/A",
                    )

        # --- Check 2: Outbound to external IP on unusual port ---
        if self._is_external_ip(remote_ip) and status == "ESTABLISHED":
            # Flag connections to external IPs on high ports (>= 10000)
            # that are not standard HTTPS/HTTP — this is a common C2 pattern
            if remote_port >= 10000 and remote_port not in {10443, 18443}:
                with self._alerted_lock:
                    if conn_key not in self._alerted_connections:
                        self._alerted_connections.add(conn_key)
                        logger.warning(
                            "UNUSUAL EXTERNAL CONNECTION — HIGH PORT | "
                            "RemoteIP=%s | RemotePort=%d | PID=%s",
                            remote_ip,
                            remote_port,
                            conn.pid or "N/A",
                        )

        # --- Check 3: C2 Beaconing detection ---
        # Only run the statistical analysis periodically (not on every connection)
        with self._history_lock:
            history = self._connection_history.get((remote_ip, remote_port), [])
            if len(history) >= BEACON_MIN_SAMPLES:
                if self._detect_beaconing(history, remote_ip, remote_port):
                    # Clear history after alerting to avoid repeated alerts
                    self._connection_history[(remote_ip, remote_port)] = [now]

    @staticmethod
    def _is_external_ip(ip_str: str) -> bool:
        """Determine if an IP address is external (non-RFC1918, non-loopback).

        Security Rationale:
            Internal connections (e.g., to domain controllers, file servers)
            are generally expected. External connections are higher risk and
            warrant closer scrutiny, especially on endpoints that should
            primarily communicate with internal infrastructure.
        """
        try:
            addr = ipaddress.ip_address(ip_str)
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
            )
        except ValueError:
            # Invalid IP string — treat as external (fail-safe)
            return True

    @staticmethod
    def _detect_beaconing(
        timestamps: List[float],
        remote_ip: str,
        remote_port: int,
    ) -> bool:
        """Analyze connection timestamps for periodic (beaconing) patterns.

        C2 implants typically call home at regular intervals (e.g., every
        60 seconds). Even with jitter, the intervals exhibit low variance
        compared to legitimate traffic, which tends to be bursty.

        We compute the coefficient of variation (CV = stdev / mean) of
        the inter-connection intervals. A low CV indicates regular timing,
        which is suspicious.

        Args:
            timestamps: Sorted list of connection timestamps.
            remote_ip: Remote IP for logging.
            remote_port: Remote port for logging.

        Returns:
            True if beaconing pattern detected, False otherwise.
        """
        # Only consider recent timestamps within the analysis window
        cutoff = time.time() - BEACON_WINDOW_SECONDS
        recent = [t for t in timestamps if t > cutoff]

        if len(recent) < BEACON_MIN_SAMPLES:
            return False

        # Sort and compute inter-arrival intervals
        recent.sort()
        intervals = [
            recent[i + 1] - recent[i] for i in range(len(recent) - 1)
        ]

        if not intervals:
            return False

        mean_interval = statistics.mean(intervals)
        if mean_interval < 1.0:
            # Sub-second intervals are likely legitimate burst traffic
            # (e.g., HTTP/2 multiplexing), not beaconing
            return False

        try:
            stdev_interval = statistics.stdev(intervals)
        except statistics.StatisticsError:
            return False

        # Coefficient of variation: low = regular = suspicious
        cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

        if cv < BEACON_MAX_JITTER:
            logger.critical(
                "C2 BEACONING PATTERN DETECTED | "
                "RemoteIP=%s | RemotePort=%d | "
                "MeanInterval=%.1fs | CV=%.3f | Samples=%d | "
                "Detection='Regular callback interval with low jitter'",
                remote_ip,
                remote_port,
                mean_interval,
                cv,
                len(recent),
            )
            return True

        return False

    def _prune_history(self) -> None:
        """Remove old entries from connection history to bound memory usage.

        We remove individual timestamps older than HISTORY_MAX_AGE and
        remove entire endpoint entries that have no remaining timestamps.
        """
        cutoff = time.time() - HISTORY_MAX_AGE
        with self._history_lock:
            empty_keys = []
            for key, timestamps in self._connection_history.items():
                # Filter to only recent timestamps
                self._connection_history[key] = [
                    t for t in timestamps if t > cutoff
                ]
                if not self._connection_history[key]:
                    empty_keys.append(key)

            for key in empty_keys:
                del self._connection_history[key]

            if empty_keys:
                logger.debug(
                    "Pruned %d stale endpoints from connection history",
                    len(empty_keys),
                )

    def _prune_alerted_connections(self) -> None:
        """Clear the alerted-connections set periodically.

        We clear the entire set rather than tracking per-entry ages,
        because connection tuples are cheap and re-alerting after a
        cooldown period is acceptable. This prevents the set from
        growing unboundedly on systems with many connections.
        """
        with self._alerted_lock:
            count = len(self._alerted_connections)
            if count > 0:
                self._alerted_connections.clear()
                logger.debug("Cleared %d entries from alerted connections set", count)
