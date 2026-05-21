"""
adhoc_script_runner.py — Sandboxed Ad-Hoc Script Executor
==========================================================

When the SOAR engine needs to run a custom remediation script on an endpoint
(e.g., a one-off forensic collection or a targeted cleanup), it pushes the
script body, type, and an HMAC-SHA256 signature to the agent.  This module
handles the safe execution of that script.

Execution pipeline
------------------
1. **Signature verification** — If ``adhoc_script_require_signature`` is
   ``True`` in the agent config, the script body is verified against its
   HMAC-SHA256 signature using a shared secret.  This prevents an attacker
   who compromises the transport layer from injecting arbitrary code.
2. **Temp file creation** — The script is written to a uniquely-named
   temporary file in the agent's working directory so the OS can execute it
   directly (avoids ``exec()`` / ``Invoke-Expression`` pitfalls).
3. **Subprocess execution** — The script is executed via ``subprocess.run``
   with a configurable timeout (default 300 s).  stdout and stderr are
   captured separately for forensic logging.
4. **Cleanup** — The temp file is removed regardless of success or failure.
5. **Result packaging** — A result dict containing success flag, exit code,
   stdout, stderr, and execution duration is returned to the caller.

Supported script types
----------------------
* ``python``      — executed with the current interpreter (``sys.executable``)
* ``powershell``  — executed with ``powershell.exe -ExecutionPolicy Bypass``
* ``batch``       — executed with ``cmd.exe /C``

Security notes
--------------
* **Never** call ``exec()`` or ``eval()`` on untrusted code.  Always use a
  subprocess so that the script runs in its own process and can be killed on
  timeout.
* Temp files are created with restrictive names under ProgramData to limit
  filesystem traversal attacks.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Dict, Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("AdhocScriptRunner")

# Mapping of script type → (file extension, command builder).
_SCRIPT_TYPE_MAP = {
    "python": ".py",
    "powershell": ".ps1",
    "batch": ".bat",
}


class AdhocScriptRunner:
    """Execute ad-hoc remediation scripts pushed from the SOAR engine.

    The runner is intentionally stateless — each invocation of
    :meth:`run_script` is fully self-contained so that multiple SOAR
    payloads can be processed concurrently without interference.
    """

    def __init__(self):
        self.config = AgentConfig.load()
        self._require_signature: bool = self.config.get(
            "adhoc_script_require_signature", True
        )
        self._timeout: int = int(self.config.get("adhoc_script_timeout", 300))
        # Shared secret for HMAC verification.  In production this would be
        # provisioned during agent enrolment and stored encrypted on disk.
        self._shared_secret: str = self.config.get(
            "adhoc_script_shared_secret", "BLUETEAM_DEFAULT_SECRET"
        )
        # Directory for temporary script files — use the agent's own data dir.
        self._temp_dir: str = self.config.get(
            "adhoc_script_temp_dir",
            os.path.join(
                self.config.get("log_dir", r"C:\ProgramData\BlueTeam\logs"),
                "script_tmp",
            ),
        )

        logger.info(
            "AdhocScriptRunner initialised — signature_required=%s, timeout=%ds",
            self._require_signature,
            self._timeout,
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run_script(
        self,
        script_body: str,
        script_type: str = "powershell",
        signature: str = "",
    ) -> Dict[str, Any]:
        """Execute a script and return the captured result.

        Parameters
        ----------
        script_body : str
            The raw script source code.
        script_type : str
            One of ``'python'``, ``'powershell'``, ``'batch'``.
        signature : str
            HMAC-SHA256 hex digest of *script_body* using the shared secret.

        Returns
        -------
        dict
            Keys: ``success``, ``exit_code``, ``stdout``, ``stderr``,
            ``duration_seconds``, ``error``.
        """
        run_id = str(uuid.uuid4())[:8]
        logger.info(
            "[run:%s] Received %s script (%d bytes) for execution",
            run_id,
            script_type,
            len(script_body),
        )

        # --- 1. Validate script type ---------------------------------- #
        script_type_lower = script_type.strip().lower()
        if script_type_lower not in _SCRIPT_TYPE_MAP:
            error_msg = (
                f"Unsupported script type '{script_type}'. "
                f"Supported: {list(_SCRIPT_TYPE_MAP.keys())}"
            )
            logger.error("[run:%s] %s", run_id, error_msg)
            return self._error_result(error_msg)

        # --- 2. Signature verification -------------------------------- #
        if self._require_signature:
            if not self._verify_signature(script_body, signature, run_id):
                error_msg = "Script signature verification FAILED — refusing to execute"
                logger.error("[run:%s] %s", run_id, error_msg)
                return self._error_result(error_msg)
            logger.info("[run:%s] Signature verification passed", run_id)
        else:
            logger.warning(
                "[run:%s] Signature verification is DISABLED — executing unsigned script",
                run_id,
            )

        # --- 3. Write to temp file ------------------------------------ #
        tmp_path: Optional[str] = None
        try:
            tmp_path = self._write_temp_file(script_body, script_type_lower, run_id)

            # --- 4. Execute ------------------------------------------- #
            result = self._execute(tmp_path, script_type_lower, run_id)
            return result

        except Exception as exc:
            logger.exception("[run:%s] Unhandled error during script execution", run_id)
            return self._error_result(str(exc))

        finally:
            # --- 5. Cleanup ------------------------------------------- #
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                    logger.debug("[run:%s] Temp file '%s' cleaned up", run_id, tmp_path)
                except OSError as exc:
                    logger.warning(
                        "[run:%s] Failed to remove temp file '%s': %s",
                        run_id,
                        tmp_path,
                        exc,
                    )

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _verify_signature(self, script_body: str, signature: str, run_id: str) -> bool:
        """Verify the HMAC-SHA256 signature of the script body.

        The expected digest is computed using the shared secret provisioned
        during agent enrolment.  A constant-time comparison is used to
        prevent timing-based side-channel attacks.
        """
        if not signature:
            logger.warning("[run:%s] No signature provided", run_id)
            return False

        expected = hmac.new(
            key=self._shared_secret.encode("utf-8"),
            msg=script_body.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        is_valid = hmac.compare_digest(expected, signature)
        logger.debug(
            "[run:%s] HMAC comparison: expected=%s…, received=%s… → %s",
            run_id,
            expected[:12],
            signature[:12],
            "PASS" if is_valid else "FAIL",
        )
        return is_valid

    def _write_temp_file(self, script_body: str, script_type: str, run_id: str) -> str:
        """Write the script body to a uniquely-named temp file.

        The file is placed in a dedicated subdirectory under the agent's
        data path to avoid polluting system-wide temp directories and to
        make auditing easier.
        """
        os.makedirs(self._temp_dir, exist_ok=True)

        extension = _SCRIPT_TYPE_MAP[script_type]
        filename = f"blueteam_adhoc_{run_id}{extension}"
        filepath = os.path.join(self._temp_dir, filename)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(script_body)

        logger.debug("[run:%s] Script written to '%s'", run_id, filepath)
        return filepath

    def _execute(self, script_path: str, script_type: str, run_id: str) -> Dict[str, Any]:
        """Run the script in a subprocess and capture output."""
        cmd = self._build_command(script_path, script_type)
        logger.info("[run:%s] Executing: %s (timeout=%ds)", run_id, cmd, self._timeout)

        start_time = time.monotonic()

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                # Do NOT use shell=True — pass a list to avoid injection.
                shell=False,
            )
            duration = round(time.monotonic() - start_time, 3)

            logger.info(
                "[run:%s] Script exited with code %d in %.3fs",
                run_id,
                completed.returncode,
                duration,
            )
            if completed.stdout:
                logger.debug("[run:%s] stdout: %s", run_id, completed.stdout[:500])
            if completed.stderr:
                logger.warning("[run:%s] stderr: %s", run_id, completed.stderr[:500])

            return {
                "success": completed.returncode == 0,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "duration_seconds": duration,
                "error": None,
            }

        except subprocess.TimeoutExpired:
            duration = round(time.monotonic() - start_time, 3)
            logger.error(
                "[run:%s] Script TIMED OUT after %ds", run_id, self._timeout
            )
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Script timed out after {self._timeout}s",
                "duration_seconds": duration,
                "error": "timeout",
            }

        except FileNotFoundError as exc:
            logger.error("[run:%s] Interpreter not found: %s", run_id, exc)
            return self._error_result(f"Interpreter not found: {exc}")

    def _build_command(self, script_path: str, script_type: str) -> list[str]:
        """Build the command list for ``subprocess.run``.

        Each script type uses a different interpreter and argument set:
        * Python  → ``sys.executable`` (same interpreter as the agent)
        * PowerShell → ``powershell.exe -ExecutionPolicy Bypass -File``
        * Batch → ``cmd.exe /C``
        """
        if script_type == "python":
            return [sys.executable, script_path]
        elif script_type == "powershell":
            return [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", script_path,
            ]
        elif script_type == "batch":
            return ["cmd.exe", "/C", script_path]
        else:
            # Should never be reached due to earlier validation.
            raise ValueError(f"Unknown script type: {script_type}")

    @staticmethod
    def _error_result(error_msg: str) -> Dict[str, Any]:
        """Return a standardised error result dict."""
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_seconds": 0.0,
            "error": error_msg,
        }
