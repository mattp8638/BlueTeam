"""
vuln_assessor.py — Comprehensive Local Vulnerability Assessment
================================================================

Performs a multi-faceted audit of the endpoint's security posture and
packages the results into a structured report dict that can be sent to
the Nerve Center for centralised risk scoring and compliance tracking.

Assessment checks
-----------------
1. **OS patch level** — Simulates ``wmic qfe`` output to enumerate
   installed hotfixes and their installation dates.  In production this
   would shell out to ``wmic`` or use WMI via ``comtypes``/``wmi`` package.
2. **Installed software versions** — Simulates reading the Uninstall
   registry hive to catalogue all installed applications.
3. **Open ports** — Uses ``psutil.net_connections()`` to discover all
   TCP ports in LISTEN state, flagging any that appear on the known-bad
   ports list from the agent config.
4. **Weak registry configurations** — Simulated checks for common
   misconfigurations that attackers exploit (RDP enabled, guest account
   active, NLA disabled, WDigest plaintext caching, etc.).
5. **Windows Defender status** — Simulates querying Defender's real-time
   protection, signature version, and last scan time.

Security notes
--------------
* Every check runs inside its own ``try/except`` so that a failure in
  one area does not abort the entire assessment.
* Results are timestamped to allow the Nerve Center to track drift over
  time.
"""

from __future__ import annotations

import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("VulnAssessor")


class VulnAssessor:
    """Local endpoint vulnerability and configuration assessor.

    Parameters
    ----------
    nerve_center : object, optional
        Reference to a local Nerve Center stub for in-process reporting.
    """

    def __init__(self, nerve_center: object = None):
        self.config = AgentConfig.load()
        self.nerve_center = nerve_center
        self._agent_id: str = self.config.get("agent_id", "AGENT-UNREGISTERED")
        self._known_bad_ports: list[int] = self.config.get("known_bad_ports", [])

        logger.info("VulnAssessor initialised for agent '%s'", self._agent_id)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run_assessment(self) -> Dict[str, Any]:
        """Execute all assessment checks and return a unified report.

        Returns
        -------
        dict
            Top-level keys: ``agent_id``, ``hostname``, ``timestamp``,
            ``os_info``, ``patches``, ``installed_software``,
            ``open_ports``, ``registry_weaknesses``, ``defender_status``,
            ``risk_score``.
        """
        logger.info("Starting comprehensive vulnerability assessment…")
        start = time.monotonic()

        report: Dict[str, Any] = {
            "agent_id": self._agent_id,
            "hostname": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "os_info": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
            },
        }

        # Each section is isolated so one failure doesn't block the rest.
        report["patches"] = self._safe_call(self.check_patches, "patches")
        report["installed_software"] = self._safe_call(
            self._check_installed_software, "installed_software"
        )
        report["open_ports"] = self._safe_call(self.check_open_ports, "open_ports")
        report["registry_weaknesses"] = self._safe_call(
            self.check_registry_weaknesses, "registry_weaknesses"
        )
        report["defender_status"] = self._safe_call(
            self._check_defender_status, "defender_status"
        )

        # Compute a simple risk score based on findings.
        report["risk_score"] = self._compute_risk_score(report)

        elapsed = round(time.monotonic() - start, 3)
        report["assessment_duration_seconds"] = elapsed

        logger.info(
            "Assessment complete in %.3fs — risk_score=%d/100",
            elapsed,
            report["risk_score"],
        )

        # Report to Nerve Center if available.
        self._send_to_nerve_center(report)

        return report

    # ------------------------------------------------------------------ #
    #  Individual checks                                                   #
    # ------------------------------------------------------------------ #

    def check_patches(self) -> List[Dict[str, str]]:
        """Enumerate installed OS patches (simulated ``wmic qfe`` output).

        In production this would invoke::

            subprocess.run(
                ["wmic", "qfe", "get", "HotFixID,InstalledOn,Description",
                 "/format:csv"],
                capture_output=True, text=True
            )

        and parse the CSV output.

        Returns
        -------
        list[dict]
            Each dict has keys ``hotfix_id``, ``installed_on``, and
            ``description``.
        """
        logger.info("Checking OS patch level (simulated wmic qfe)…")

        # Simulated hotfix data — representative of a typical Windows 10/11
        # endpoint that is mostly up-to-date but missing the latest CU.
        patches = [
            {
                "hotfix_id": "KB5034441",
                "installed_on": "2026-01-15",
                "description": "Security Update",
            },
            {
                "hotfix_id": "KB5035845",
                "installed_on": "2026-03-12",
                "description": "Cumulative Update",
            },
            {
                "hotfix_id": "KB5037019",
                "installed_on": "2026-04-09",
                "description": "Security Update",
            },
            {
                "hotfix_id": "KB5038500",
                "installed_on": "2026-05-14",
                "description": "Cumulative Update Preview",
            },
        ]

        logger.info("Found %d installed patches", len(patches))
        return patches

    def check_open_ports(self) -> List[Dict[str, Any]]:
        """Detect TCP ports in LISTEN state using ``psutil``.

        Flags any port that appears in the ``known_bad_ports`` list from
        the agent configuration — these are commonly used by C2 frameworks,
        RATs, and exploit kits.

        Returns
        -------
        list[dict]
            Each dict has keys ``port``, ``address``, ``pid``,
            ``process_name``, ``flagged``.
        """
        logger.info("Scanning for open TCP ports…")
        open_ports: List[Dict[str, Any]] = []

        try:
            connections = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            logger.warning("Access denied reading network connections — running without admin?")
            return open_ports

        for conn in connections:
            if conn.status != "LISTEN":
                continue

            local_addr = conn.laddr
            port = local_addr.port if local_addr else 0
            address = local_addr.ip if local_addr else "0.0.0.0"

            # Resolve the owning process name.
            proc_name = "unknown"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = f"<pid:{conn.pid}>"

            flagged = port in self._known_bad_ports

            entry = {
                "port": port,
                "address": address,
                "pid": conn.pid,
                "process_name": proc_name,
                "flagged": flagged,
            }
            open_ports.append(entry)

            if flagged:
                logger.warning(
                    "FLAGGED open port %d (process=%s, pid=%s) — matches known-bad list",
                    port,
                    proc_name,
                    conn.pid,
                )

        logger.info(
            "Discovered %d listening ports (%d flagged)",
            len(open_ports),
            sum(1 for p in open_ports if p["flagged"]),
        )
        return open_ports

    def check_registry_weaknesses(self) -> List[Dict[str, Any]]:
        """Check for common insecure registry configurations (simulated).

        Each check represents a well-known misconfiguration that attackers
        exploit.  In production these would use ``winreg`` to read the
        actual registry values.

        Returns
        -------
        list[dict]
            Each dict has keys ``check_name``, ``registry_key``,
            ``expected_value``, ``actual_value``, ``status`` (pass/fail),
            ``severity`` (low/medium/high/critical).
        """
        logger.info("Checking registry for weak configurations (simulated)…")

        # Define the checks as tuples:
        # (name, key, expected, simulated_actual, severity)
        checks_definition = [
            (
                "RDP Enabled",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
                1,   # 1 = RDP denied (secure)
                0,   # Simulated: RDP is enabled (insecure)
                "high",
            ),
            (
                "Guest Account Active",
                r"HKLM\SAM\SAM\Domains\Account\Users\000001F5\F",
                "disabled",
                "enabled",  # Simulated: guest is active (insecure)
                "critical",
            ),
            (
                "NLA Disabled for RDP",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication",
                1,   # 1 = NLA required (secure)
                1,   # Simulated: NLA is enabled (secure)
                "high",
            ),
            (
                "WDigest Plaintext Credential Caching",
                r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential",
                0,   # 0 = disabled (secure)
                0,   # Simulated: disabled (secure)
                "critical",
            ),
            (
                "SMBv1 Enabled",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1",
                0,   # 0 = disabled (secure)
                1,   # Simulated: SMBv1 still enabled (insecure)
                "critical",
            ),
            (
                "AutoRun Enabled",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun",
                255, # 0xFF = all drives disabled (secure)
                255, # Simulated: correctly disabled
                "medium",
            ),
            (
                "Windows Script Host Enabled",
                r"HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled",
                0,   # 0 = disabled (secure)
                1,   # Simulated: WSH enabled (insecure)
                "medium",
            ),
            (
                "PowerShell Script Block Logging",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
                1,   # 1 = enabled (secure)
                0,   # Simulated: logging disabled (insecure)
                "high",
            ),
        ]

        results: List[Dict[str, Any]] = []
        for name, key, expected, actual, severity in checks_definition:
            status = "pass" if actual == expected else "fail"
            entry = {
                "check_name": name,
                "registry_key": key,
                "expected_value": expected,
                "actual_value": actual,
                "status": status,
                "severity": severity,
            }
            results.append(entry)

            if status == "fail":
                logger.warning(
                    "Registry weakness: %s — expected=%s, actual=%s [%s]",
                    name,
                    expected,
                    actual,
                    severity.upper(),
                )
            else:
                logger.debug("Registry check PASS: %s", name)

        fail_count = sum(1 for r in results if r["status"] == "fail")
        logger.info(
            "Registry checks complete: %d/%d passed",
            len(results) - fail_count,
            len(results),
        )
        return results

    # ------------------------------------------------------------------ #
    #  Private check helpers                                               #
    # ------------------------------------------------------------------ #

    def _check_installed_software(self) -> List[Dict[str, str]]:
        """Enumerate installed software and versions (simulated).

        In production this would read from:
        ``HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall``
        and the Wow6432Node counterpart.

        Returns
        -------
        list[dict]
            Each dict has keys ``name``, ``version``, ``publisher``.
        """
        logger.info("Enumerating installed software (simulated)…")

        software = [
            {"name": "Google Chrome", "version": "126.0.6478.127", "publisher": "Google LLC"},
            {"name": "Mozilla Firefox", "version": "128.0", "publisher": "Mozilla"},
            {"name": "Microsoft Office 365", "version": "16.0.17726.20160", "publisher": "Microsoft"},
            {"name": "Adobe Acrobat Reader", "version": "24.002.20933", "publisher": "Adobe Inc."},
            {"name": "7-Zip", "version": "24.07", "publisher": "Igor Pavlov"},
            {"name": "Python 3.12.4", "version": "3.12.4", "publisher": "Python Software Foundation"},
            {"name": "Notepad++", "version": "8.6.9", "publisher": "Don Ho"},
            {"name": "PuTTY", "version": "0.81", "publisher": "Simon Tatham"},
            {"name": "WinSCP", "version": "6.3.3", "publisher": "Martin Prikryl"},
            {"name": "Visual Studio Code", "version": "1.91.0", "publisher": "Microsoft"},
        ]

        logger.info("Found %d installed applications", len(software))
        return software

    def _check_defender_status(self) -> Dict[str, Any]:
        """Query Windows Defender status (simulated).

        In production this would use ``Get-MpComputerStatus`` via
        PowerShell or the WMI ``MSFT_MpComputerStatus`` class.

        Returns
        -------
        dict
            Keys: ``real_time_protection``, ``behavior_monitoring``,
            ``signature_version``, ``signature_age_days``,
            ``last_quick_scan``, ``last_full_scan``,
            ``tamper_protection``.
        """
        logger.info("Querying Windows Defender status (simulated)…")

        status = {
            "real_time_protection": True,
            "behavior_monitoring": True,
            "signature_version": "1.413.348.0",
            "signature_age_days": 1,
            "last_quick_scan": "2026-05-20T14:30:00Z",
            "last_full_scan": "2026-05-18T02:00:00Z",
            "tamper_protection": True,
        }

        if not status["real_time_protection"]:
            logger.warning("Windows Defender real-time protection is DISABLED")
        else:
            logger.info("Windows Defender real-time protection is enabled")

        if status["signature_age_days"] > 3:
            logger.warning(
                "Defender signatures are %d days old — update recommended",
                status["signature_age_days"],
            )

        return status

    # ------------------------------------------------------------------ #
    #  Risk scoring                                                        #
    # ------------------------------------------------------------------ #

    def _compute_risk_score(self, report: Dict[str, Any]) -> int:
        """Compute a 0-100 risk score based on assessment findings.

        Higher score = higher risk.  The scoring is deliberately simple
        and is intended to be overridden by the Nerve Center's ML-based
        risk engine — this local score is a quick triage indicator only.

        Scoring breakdown:
        * +5  per flagged open port
        * +8  per FAIL registry check at severity=high
        * +15 per FAIL registry check at severity=critical
        * +3  per FAIL registry check at severity=medium
        * +20 if Defender real-time protection is disabled
        * +10 if Defender signatures are stale (> 3 days)
        """
        score = 0

        # Flagged ports.
        open_ports = report.get("open_ports", [])
        if isinstance(open_ports, list):
            flagged_ports = sum(1 for p in open_ports if isinstance(p, dict) and p.get("flagged"))
            score += flagged_ports * 5

        # Registry weaknesses.
        reg_checks = report.get("registry_weaknesses", [])
        severity_weights = {"low": 1, "medium": 3, "high": 8, "critical": 15}
        if isinstance(reg_checks, list):
            for check in reg_checks:
                if isinstance(check, dict) and check.get("status") == "fail":
                    weight = severity_weights.get(check.get("severity", "low"), 1)
                    score += weight

        # Defender status.
        defender = report.get("defender_status", {})
        if isinstance(defender, dict):
            if not defender.get("real_time_protection", True):
                score += 20
            if defender.get("signature_age_days", 0) > 3:
                score += 10

        # Clamp to 0–100.
        score = max(0, min(100, score))

        logger.info("Computed local risk score: %d/100", score)
        return score

    # ------------------------------------------------------------------ #
    #  Utility methods                                                     #
    # ------------------------------------------------------------------ #

    def _safe_call(self, func, section_name: str) -> Any:
        """Call *func* and return its result, or an error dict on failure.

        Wraps each assessment section so that one failure does not abort
        the entire report.
        """
        try:
            return func()
        except Exception as exc:
            logger.exception("Assessment section '%s' failed", section_name)
            return {"error": str(exc)}

    def _send_to_nerve_center(self, report: Dict[str, Any]) -> None:
        """Forward the assessment report to the Nerve Center.

        In production this would be an HTTPS POST to
        ``/api/v1/assessments``.  During integration testing we use the
        local stub.
        """
        logger.info(
            "Reporting assessment to Nerve Center (risk_score=%d)",
            report.get("risk_score", -1),
        )

        if self.nerve_center and hasattr(self.nerve_center, "receive_assessment"):
            try:
                self.nerve_center.receive_assessment(report)
            except Exception as exc:
                logger.error("Failed to report assessment to Nerve Center: %s", exc)
        elif self.nerve_center and hasattr(self.nerve_center, "route_event"):
            # Backwards-compatible with the old Nerve Center API.
            try:
                self.nerve_center.route_event(
                    source_type="ENDPOINT_SCAN",
                    raw_data=report,
                    device_context={"agent_id": self._agent_id},
                )
            except Exception as exc:
                logger.error("Failed to route assessment event: %s", exc)
