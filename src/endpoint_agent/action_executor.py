"""
action_executor.py — Central SOAR Remediation Dispatcher
=========================================================

This module is the "hands" of the BlueTeam Endpoint Agent.  When the SOAR
engine on the Nerve Center determines that a remediation action must be taken
on this endpoint, it pushes a JSON payload over the secure API channel.
``ActionExecutor.execute_soar_payload()`` parses that payload and delegates to
the appropriate ``_action_*`` handler.

Supported actions
-----------------
* **isolate_host** — Modify Windows Firewall via simulated ``netsh`` commands
  to drop all non-NerveCenter traffic.
* **quarantine_file** — Delegate to the quarantine vault to lock-down a
  malicious artefact.
* **kill_process** — Terminate a process by PID *or* name using ``psutil``.
* **block_ip** — Add a Windows Firewall rule to block a specific IP address.
* **delete_registry_key** — Simulated ``winreg`` deletion of a malicious
  persistence key.
* **disable_user_account** — Simulated ``net user /active:no`` to lock out a
  compromised account.
* **execute_adhoc_script** — Delegate to ``AdhocScriptRunner`` for sandboxed
  script execution.

Security considerations
-----------------------
Every action is logged at INFO or WARNING level so that the SOC has a
complete audit trail.  Results (success *and* failure) are reported back to
the Nerve Center for correlation and ticketing.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psutil

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("ActionExecutor")


class ActionExecutor:
    """Central dispatcher for SOAR remediation payloads.

    Parameters
    ----------
    nerve_center : object, optional
        A reference to the local Nerve Center stub (for in-process comms
        during integration testing).  In production the result is POSTed
        back via the REST API.
    """

    # ------------------------------------------------------------------ #
    #  Initialisation                                                      #
    # ------------------------------------------------------------------ #

    def __init__(self, nerve_center: object = None):
        self.config = AgentConfig.load()
        self.nerve_center = nerve_center
        self._agent_id: str = self.config.get("agent_id", "AGENT-UNREGISTERED")

        # Lazy import — avoids circular dependency at module level.
        self._adhoc_runner = None

        # Registry of supported action types → handler methods.
        self._dispatch_table: Dict[str, callable] = {
            "isolate_host": self._action_isolate_host,
            "quarantine_file": self._action_quarantine_file,
            "kill_process": self._action_kill_process,
            "block_ip": self._action_block_ip,
            "delete_registry_key": self._action_delete_registry_key,
            "disable_user_account": self._action_disable_user_account,
            "execute_adhoc_script": self._action_execute_adhoc_script,
        }

        logger.info(
            "ActionExecutor initialised — %d action types registered",
            len(self._dispatch_table),
        )

    # ------------------------------------------------------------------ #
    #  Public entry-point                                                  #
    # ------------------------------------------------------------------ #

    def execute_soar_payload(self, soar_payload_json: str) -> Dict[str, Any]:
        """Parse a SOAR JSON payload and dispatch to the correct handler.

        Parameters
        ----------
        soar_payload_json : str
            Raw JSON string received from the Nerve Center.

        Returns
        -------
        dict
            A result dict containing ``action``, ``success``, ``message``,
            ``timestamp``, and ``execution_id``.
        """
        execution_id = str(uuid.uuid4())[:12]
        logger.info(
            "[exec:%s] Received SOAR payload (%d bytes)",
            execution_id,
            len(soar_payload_json),
        )

        # --- 1. Parse ------------------------------------------------- #
        try:
            payload: dict = json.loads(soar_payload_json)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("[exec:%s] Malformed JSON payload: %s", execution_id, exc)
            return self._build_result(execution_id, "unknown", False, f"Invalid JSON: {exc}")

        action_type: str = payload.get("action", "").strip().lower()
        if not action_type:
            logger.error("[exec:%s] Payload missing 'action' field", execution_id)
            return self._build_result(execution_id, "missing", False, "No action specified")

        logger.info(
            "[exec:%s] Dispatching action=%s | target=%s",
            execution_id,
            action_type,
            payload.get("target", "N/A"),
        )

        # --- 2. Dispatch ---------------------------------------------- #
        handler = self._dispatch_table.get(action_type)
        if handler is None:
            logger.warning(
                "[exec:%s] Unsupported action type '%s'", execution_id, action_type
            )
            return self._build_result(
                execution_id, action_type, False, f"Unsupported action: {action_type}"
            )

        try:
            message = handler(payload, execution_id)
            result = self._build_result(execution_id, action_type, True, message)
            logger.info("[exec:%s] Action completed successfully: %s", execution_id, message)
        except Exception as exc:  # noqa: BLE001 — intentional broad catch at dispatch boundary
            logger.exception("[exec:%s] Action '%s' raised an exception", execution_id, action_type)
            result = self._build_result(execution_id, action_type, False, str(exc))

        # --- 3. Report back ------------------------------------------- #
        self._report_result_to_nerve_center(result)
        return result

    # ------------------------------------------------------------------ #
    #  Action handlers                                                     #
    # ------------------------------------------------------------------ #

    def _action_isolate_host(self, payload: dict, exec_id: str) -> str:
        """Isolate the host by blocking all non-NerveCenter traffic.

        This simulates running ``netsh advfirewall set allprofiles
        firewallpolicy blockinbound,blockoutbound`` and then punching a
        hole for the Nerve Center IP so the agent can still phone home.
        """
        nc_url = self.config.get("nerve_center_url", "")
        logger.warning(
            "[exec:%s] HOST ISOLATION initiated — all network traffic will be "
            "blocked except to %s",
            exec_id,
            nc_url,
        )

        # Step 1 — Block everything (simulated).
        block_cmd = [
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound",
        ]
        logger.info("[exec:%s] Simulated command: %s", exec_id, " ".join(block_cmd))

        # Step 2 — Allow Nerve Center (simulated).
        allow_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=BlueTeam-NerveCenter-Allow",
            "dir=out", "action=allow",
            f"remoteip={nc_url}",
            "protocol=tcp",
        ]
        logger.info("[exec:%s] Simulated command: %s", exec_id, " ".join(allow_cmd))

        return "Host isolation firewall rules applied (simulated)"

    def _action_quarantine_file(self, payload: dict, exec_id: str) -> str:
        """Move a suspicious file to the encrypted quarantine vault.

        The vault path is read from the agent configuration.  Before
        moving the file, any process holding a lock on it is terminated
        to avoid sharing violations.
        """
        file_path: str = payload.get("file_path", payload.get("target", ""))
        if not file_path:
            raise ValueError("quarantine_file requires 'file_path' or 'target'")

        vault_dir = self.config.get("quarantine_dir", r"C:\ProgramData\BlueTeam\quarantine")
        logger.info(
            "[exec:%s] Quarantining '%s' → vault '%s'", exec_id, file_path, vault_dir
        )

        # Terminate any process holding the file (simulated lookup).
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                open_files = proc.info.get("open_files") or []
                for fobj in open_files:
                    if fobj.path and os.path.normcase(fobj.path) == os.path.normcase(file_path):
                        logger.warning(
                            "[exec:%s] Killing PID %d (%s) — holds lock on target file",
                            exec_id,
                            proc.pid,
                            proc.info["name"],
                        )
                        proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Move the file to quarantine (simulated — production would
        # encrypt-then-move and update a manifest DB).
        logger.info("[exec:%s] File quarantine completed (simulated)", exec_id)
        return f"File '{file_path}' quarantined to vault"

    def _action_kill_process(self, payload: dict, exec_id: str) -> str:
        """Terminate a process by PID or by name.

        If ``pid`` is supplied it takes precedence.  If only ``name`` is
        given, *all* processes whose ``name()`` matches (case-insensitive)
        are killed — this is deliberate to catch renamed copies.
        """
        target_pid: Optional[int] = payload.get("pid")
        target_name: Optional[str] = payload.get("process_name", payload.get("target"))

        killed: list[int] = []

        if target_pid is not None:
            try:
                proc = psutil.Process(int(target_pid))
                proc_name = proc.name()
                proc.kill()
                killed.append(int(target_pid))
                logger.warning(
                    "[exec:%s] Killed PID %d (%s)", exec_id, target_pid, proc_name
                )
            except psutil.NoSuchProcess:
                logger.info("[exec:%s] PID %d no longer exists", exec_id, target_pid)
            except psutil.AccessDenied:
                raise PermissionError(f"Access denied killing PID {target_pid}")

        elif target_name:
            target_lower = target_name.lower()
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.info["name"] and proc.info["name"].lower() == target_lower:
                        proc.kill()
                        killed.append(proc.pid)
                        logger.warning(
                            "[exec:%s] Killed PID %d (matched name '%s')",
                            exec_id,
                            proc.pid,
                            target_name,
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        else:
            raise ValueError("kill_process requires 'pid' or 'process_name'")

        return f"Terminated {len(killed)} process(es): {killed}"

    def _action_block_ip(self, payload: dict, exec_id: str) -> str:
        """Add a Windows Firewall rule to block a specific IP address.

        Creates both inbound and outbound deny rules so the endpoint
        cannot communicate with the known-bad IP in either direction.
        """
        ip_address: str = payload.get("ip", payload.get("target", ""))
        if not ip_address:
            raise ValueError("block_ip requires 'ip' or 'target'")

        rule_name = f"BlueTeam-Block-{ip_address.replace('.', '_')}"

        # Inbound rule (simulated).
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-IN", "dir=in", "action=block",
            f"remoteip={ip_address}", "protocol=any",
        ]
        logger.info("[exec:%s] Simulated command: %s", exec_id, " ".join(cmd_in))

        # Outbound rule (simulated).
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-OUT", "dir=out", "action=block",
            f"remoteip={ip_address}", "protocol=any",
        ]
        logger.info("[exec:%s] Simulated command: %s", exec_id, " ".join(cmd_out))

        logger.warning("[exec:%s] Blocked IP %s (inbound + outbound)", exec_id, ip_address)
        return f"Firewall rules created to block {ip_address}"

    def _action_delete_registry_key(self, payload: dict, exec_id: str) -> str:
        """Delete a malicious registry key used for persistence.

        In production this would use the ``winreg`` module to connect to
        the appropriate hive and remove the value.  Here we simulate the
        operation and log the exact key that *would* be removed.
        """
        reg_key: str = payload.get("registry_key", payload.get("target", ""))
        reg_value: str = payload.get("registry_value", "")

        if not reg_key:
            raise ValueError("delete_registry_key requires 'registry_key' or 'target'")

        logger.warning(
            "[exec:%s] Deleting registry key '%s' value '%s' (simulated)",
            exec_id,
            reg_key,
            reg_value or "(default)",
        )

        # Simulated winreg operation:
        # import winreg
        # hive, subkey = _parse_hive(reg_key)
        # with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
        #     winreg.DeleteValue(k, reg_value)
        logger.info("[exec:%s] Registry key deletion completed (simulated)", exec_id)
        return f"Deleted registry key '{reg_key}' / value '{reg_value}'"

    def _action_disable_user_account(self, payload: dict, exec_id: str) -> str:
        """Disable a local Windows user account.

        Uses ``net user <username> /active:no`` to prevent the compromised
        account from being used for lateral movement or persistence.
        """
        username: str = payload.get("username", payload.get("target", ""))
        if not username:
            raise ValueError("disable_user_account requires 'username' or 'target'")

        cmd = ["net", "user", username, "/active:no"]
        logger.warning(
            "[exec:%s] Disabling local user account '%s' (simulated)",
            exec_id,
            username,
        )
        logger.info("[exec:%s] Simulated command: %s", exec_id, " ".join(cmd))

        # In production:
        # subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)

        return f"User account '{username}' disabled"

    def _action_execute_adhoc_script(self, payload: dict, exec_id: str) -> str:
        """Delegate ad-hoc script execution to the sandboxed runner.

        The ``AdhocScriptRunner`` verifies signature (if configured),
        writes to a temp file, executes with a timeout, and captures
        output.
        """
        # Lazy-load to avoid circular imports.
        if self._adhoc_runner is None:
            from src.endpoint_agent.adhoc_script_runner import AdhocScriptRunner
            self._adhoc_runner = AdhocScriptRunner()

        script_body: str = payload.get("script_body", "")
        script_type: str = payload.get("script_type", "powershell")
        signature: str = payload.get("signature", "")

        if not script_body:
            raise ValueError("execute_adhoc_script requires 'script_body'")

        logger.info(
            "[exec:%s] Delegating %s script (%d bytes) to AdhocScriptRunner",
            exec_id,
            script_type,
            len(script_body),
        )

        result = self._adhoc_runner.run_script(
            script_body=script_body,
            script_type=script_type,
            signature=signature,
        )

        if result.get("success"):
            return f"Ad-hoc {script_type} script executed — exit_code={result.get('exit_code')}"
        else:
            raise RuntimeError(
                f"Ad-hoc script failed: {result.get('error', 'unknown error')}"
            )

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _build_result(
        self,
        execution_id: str,
        action: str,
        success: bool,
        message: str,
    ) -> Dict[str, Any]:
        """Assemble a standardised result dict for every action."""
        return {
            "execution_id": execution_id,
            "agent_id": self._agent_id,
            "action": action,
            "success": success,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _report_result_to_nerve_center(self, result: Dict[str, Any]) -> None:
        """Send the execution result back to the Nerve Center.

        In production this would be an HTTPS POST to the ``/api/v1/results``
        endpoint.  During integration testing we use the local stub.
        """
        logger.info(
            "[exec:%s] Reporting result → Nerve Center | success=%s",
            result["execution_id"],
            result["success"],
        )

        if self.nerve_center and hasattr(self.nerve_center, "receive_action_result"):
            try:
                self.nerve_center.receive_action_result(result)
            except Exception as exc:
                logger.error(
                    "[exec:%s] Failed to report to Nerve Center: %s",
                    result["execution_id"],
                    exc,
                )
