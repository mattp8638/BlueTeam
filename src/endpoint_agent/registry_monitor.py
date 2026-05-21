"""
registry_monitor.py — Windows Registry Change Detection Sensor

This module monitors Windows Registry keys that are commonly abused by
malware for persistence, privilege escalation, and defense evasion. It
periodically snapshots the values under watched keys and compares them
against a stored baseline to detect unauthorized modifications.

Security Rationale:
    The Windows Registry is the #1 persistence mechanism for malware.
    Common techniques include:
    - Run/RunOnce keys for auto-start programs
    - Image File Execution Options (IFEO) for debugger hijacking
    - AppInit_DLLs for DLL injection into every GUI process
    - Services registry entries for service-based persistence
    - Winlogon Notify/Userinit for logon-triggered execution
    - COM object hijacking via InprocServer32

    By monitoring these keys in near-real-time, we can detect persistence
    implants shortly after they are installed — often before the attacker's
    payload has had a chance to execute via the persistence mechanism.

Architecture:
    - A background daemon thread wakes up every N seconds (configurable).
    - For each watched registry key, `_take_snapshot()` reads all values.
    - The snapshot is compared against the previous baseline.
    - New, modified, or deleted values generate alerts.
    - The baseline is then updated to the current snapshot.

Platform Compatibility:
    - On Windows: uses `winreg` (standard library) for real registry access.
    - On non-Windows / if winreg is unavailable: uses mock data so the
      module can be developed and tested on any platform.

Thread Safety:
    - The baseline dict and snapshot operations are protected by a lock.
    - Start/stop lifecycle is protected by a separate lock.

Usage:
    from src.endpoint_agent.registry_monitor import RegistryMonitor

    monitor = RegistryMonitor()
    monitor.start()
    # ... later ...
    monitor.stop()
"""

import time
import threading
from typing import Dict, List, Optional, Tuple, Any

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("RegistryMonitor")

# ---------------------------------------------------------------------------
# Attempt to import winreg — graceful fallback for non-Windows environments
# ---------------------------------------------------------------------------
_WINREG_AVAILABLE = False
try:
    import winreg  # type: ignore[import]
    _WINREG_AVAILABLE = True
    logger.info("winreg module available — using live registry access")
except ImportError:
    logger.warning(
        "winreg module not available — falling back to simulated registry data. "
        "This is expected on non-Windows platforms."
    )

# Type alias for a registry snapshot:
#   { "HKLM\\...\\Run": { "ValueName": (data, type_int), ... }, ... }
RegistrySnapshot = Dict[str, Dict[str, Tuple[Any, int]]]


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_POLL_INTERVAL: float = 15.0  # seconds

DEFAULT_WATCHED_KEYS: List[str] = [
    # Auto-start locations (MITRE ATT&CK T1547.001)
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    # Image File Execution Options — debugger hijacking (T1546.012)
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    # AppInit DLLs — DLL injection (T1546.010)
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    # Winlogon persistence (T1547.004)
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    # Services (T1543.003)
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]

# Map of hive name strings to winreg constants (only populated when winreg is available)
_HIVE_MAP: Dict[str, Any] = {}
if _WINREG_AVAILABLE:
    _HIVE_MAP = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
    }


# ---------------------------------------------------------------------------
# Mock registry data for non-Windows environments
# ---------------------------------------------------------------------------
_MOCK_REGISTRY: Dict[str, Dict[str, Tuple[str, int]]] = {
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": {
        "SecurityHealth": (r"C:\Windows\System32\SecurityHealth.exe", 1),
        "WindowsDefender": (r"C:\Program Files\Windows Defender\MSASCuiL.exe", 1),
    },
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": {
        "OneDrive": (r"C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 1),
    },
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {
        "Shell": ("explorer.exe", 1),
        "Userinit": (r"C:\Windows\system32\userinit.exe,", 1),
    },
}


def _parse_key_path(key_path: str) -> Tuple[Optional[Any], str]:
    """Split a registry key path into (hive_constant, subkey_path).

    Example:
        'HKLM\\SOFTWARE\\Microsoft\\...' → (HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\...')

    Returns (None, '') if the hive is unrecognized or winreg is unavailable.
    """
    parts = key_path.split("\\", 1)
    if len(parts) != 2:
        return None, ""

    hive_name, subkey = parts
    hive = _HIVE_MAP.get(hive_name.upper())
    return hive, subkey


class RegistryMonitor:
    """Monitors Windows Registry keys for unauthorized changes.

    The monitor maintains a baseline snapshot of all watched keys and
    periodically compares the current state against it. Any additions,
    modifications, or deletions are logged as security alerts.

    Args:
        poll_interval: Seconds between registry scans. Defaults to config
                       value or 15 seconds.
    """

    def __init__(self, poll_interval: Optional[float] = None) -> None:
        config = AgentConfig.load()

        self._poll_interval: float = poll_interval or config.get(
            "registry_poll_interval", DEFAULT_POLL_INTERVAL
        )
        self._watched_keys: List[str] = config.get(
            "watched_registry_keys", DEFAULT_WATCHED_KEYS
        )

        # Baseline snapshot — populated on first scan
        self._baseline: RegistrySnapshot = {}
        self._baseline_lock = threading.Lock()

        # Thread lifecycle
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()

        logger.info(
            "RegistryMonitor initialized — watching %d keys, poll interval %.1fs",
            len(self._watched_keys),
            self._poll_interval,
        )

    # ---- Public API ------------------------------------------------------

    def start(self) -> None:
        """Start the registry monitoring daemon thread."""
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("RegistryMonitor.start() called but already running")
                return

            self._stop_event.clear()

            # Take initial baseline before starting the comparison loop
            logger.info("Taking initial registry baseline...")
            with self._baseline_lock:
                self._baseline = self._take_snapshot()
            logger.info(
                "Baseline captured — %d keys with %d total values",
                len(self._baseline),
                sum(len(v) for v in self._baseline.values()),
            )

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="RegistryMonitor-Worker",
                daemon=True,
            )
            self._thread.start()
            logger.info("RegistryMonitor started")

    def stop(self) -> None:
        """Stop the registry monitoring thread."""
        with self._lifecycle_lock:
            if self._thread is None or not self._thread.is_alive():
                logger.debug("RegistryMonitor.stop() called but not running")
                return

            logger.info("Stopping RegistryMonitor...")
            self._stop_event.set()
            self._thread.join(timeout=self._poll_interval + 2.0)

            if self._thread.is_alive():
                logger.warning("RegistryMonitor thread did not exit within timeout")
            else:
                logger.info("RegistryMonitor stopped")

            self._thread = None

    @property
    def is_running(self) -> bool:
        """Return True if the monitor thread is alive."""
        with self._lifecycle_lock:
            return self._thread is not None and self._thread.is_alive()

    # ---- Snapshot Logic --------------------------------------------------

    def _take_snapshot(self) -> RegistrySnapshot:
        """Capture the current state of all watched registry keys.

        Returns:
            A dict mapping key paths to their current name→(data, type) dicts.
        """
        snapshot: RegistrySnapshot = {}

        for key_path in self._watched_keys:
            try:
                if _WINREG_AVAILABLE:
                    values = self._read_registry_key(key_path)
                else:
                    values = self._read_mock_key(key_path)
                snapshot[key_path] = values
            except Exception as exc:
                logger.error(
                    "Failed to snapshot registry key %s: %s", key_path, exc
                )
                # Store empty dict so we don't lose track of this key
                snapshot[key_path] = {}

        return snapshot

    def _read_registry_key(self, key_path: str) -> Dict[str, Tuple[Any, int]]:
        """Read all values under a real Windows registry key.

        Args:
            key_path: Full path like 'HKLM\\SOFTWARE\\...'.

        Returns:
            Dict mapping value names to (data, type) tuples.
        """
        hive, subkey = _parse_key_path(key_path)
        if hive is None:
            logger.warning("Unknown registry hive in path: %s", key_path)
            return {}

        values: Dict[str, Tuple[Any, int]] = {}
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as handle:
                index = 0
                while True:
                    try:
                        name, data, val_type = winreg.EnumValue(handle, index)
                        values[name] = (data, val_type)
                        index += 1
                    except OSError:
                        # No more values to enumerate
                        break
        except FileNotFoundError:
            # Key does not exist — not necessarily an error, some keys are
            # created on demand (e.g., RunOnce is often empty)
            logger.debug("Registry key not found (may be normal): %s", key_path)
        except PermissionError:
            logger.warning(
                "Access denied reading registry key: %s (may need SYSTEM privileges)",
                key_path,
            )
        except OSError as exc:
            logger.error("OS error reading registry key %s: %s", key_path, exc)

        return values

    @staticmethod
    def _read_mock_key(key_path: str) -> Dict[str, Tuple[Any, int]]:
        """Return simulated registry values for testing/non-Windows environments.

        The mock data represents a typical clean Windows baseline. During
        testing, you can modify `_MOCK_REGISTRY` to simulate attack scenarios.
        """
        return dict(_MOCK_REGISTRY.get(key_path, {}))

    # ---- Monitor Loop ----------------------------------------------------

    def _monitor_loop(self) -> None:
        """Background thread: periodically compare registry state to baseline."""
        logger.debug("RegistryMonitor worker thread started")

        while not self._stop_event.is_set():
            # Wait first, then scan — the baseline was already taken at start()
            self._stop_event.wait(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break

            try:
                current = self._take_snapshot()
                self._compare_and_alert(current)
            except Exception as exc:
                logger.error(
                    "Unhandled error in registry scan: %s", exc, exc_info=True
                )

        logger.debug("RegistryMonitor worker thread exiting")

    def _compare_and_alert(self, current: RegistrySnapshot) -> None:
        """Compare the current snapshot against the baseline and generate alerts.

        Detects three types of changes:
            1. New values added to a key (potential persistence implant)
            2. Existing values modified (potential hijacking)
            3. Values deleted (potential defense evasion / cleanup)

        After alerting, the baseline is updated to the current state to
        avoid re-alerting on the same change.
        """
        with self._baseline_lock:
            for key_path in self._watched_keys:
                baseline_values = self._baseline.get(key_path, {})
                current_values = current.get(key_path, {})

                # --- Detect new values (most common persistence indicator) ---
                new_names = set(current_values.keys()) - set(baseline_values.keys())
                for name in new_names:
                    data, val_type = current_values[name]
                    logger.critical(
                        "REGISTRY CHANGE DETECTED | Type=NEW_VALUE | "
                        "Key=%s | ValueName=%s | Data=%s | RegType=%d",
                        key_path,
                        name,
                        str(data)[:200],  # Truncate to prevent log injection
                        val_type,
                    )

                # --- Detect modified values ---
                common_names = set(current_values.keys()) & set(baseline_values.keys())
                for name in common_names:
                    if current_values[name] != baseline_values[name]:
                        old_data, old_type = baseline_values[name]
                        new_data, new_type = current_values[name]
                        logger.critical(
                            "REGISTRY CHANGE DETECTED | Type=MODIFIED_VALUE | "
                            "Key=%s | ValueName=%s | "
                            "OldData=%s | NewData=%s",
                            key_path,
                            name,
                            str(old_data)[:200],
                            str(new_data)[:200],
                        )

                # --- Detect deleted values ---
                deleted_names = set(baseline_values.keys()) - set(current_values.keys())
                for name in deleted_names:
                    old_data, old_type = baseline_values[name]
                    logger.warning(
                        "REGISTRY CHANGE DETECTED | Type=DELETED_VALUE | "
                        "Key=%s | ValueName=%s | PreviousData=%s",
                        key_path,
                        name,
                        str(old_data)[:200],
                    )

            # Update baseline to current state
            self._baseline = current
