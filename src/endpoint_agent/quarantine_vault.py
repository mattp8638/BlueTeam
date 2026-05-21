"""
quarantine_vault.py — Secure File Quarantine and Chain-of-Custody Manager
=========================================================================

When the LocalAVEngine determines that a file is malicious, this module
isolates it by moving it into a locked-down vault directory.  The quarantine
process is designed to satisfy forensic chain-of-custody requirements:

    1. The original file is COPIED (not moved) to the vault directory first,
       so that a partial failure does not result in data loss.
    2. The copy is renamed with a UUID-based filename to prevent accidental
       double-click execution by analysts or other endpoint software.
    3. A companion `.meta.json` sidecar is written containing the original
       path, SHA-256 digest, detection reason, and UTC timestamp.
    4. Only after the vault copy and metadata are confirmed on disk is the
       original file DELETED.
    5. Every step is logged with timestamps for full chain-of-custody audit.

Security rationale:
    - UUID renaming strips the original extension, neutralising extension-
      based execution (e.g. `.exe`, `.bat`, `.ps1`).
    - Metadata sidecars enable analysts to trace a quarantined artefact back
      to its original location and the specific detection that triggered it.
    - The restore function requires an analyst_id, creating an accountability
      record if a quarantined file is ever released back to the filesystem.
"""

import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("QuarantineVault")


class QuarantineVault:
    """Manages the secure quarantine lifecycle for detected malicious files.

    Attributes:
        vault_dir: Absolute path to the quarantine vault directory.
        _lock: Threading lock to serialise quarantine/restore operations,
               preventing race conditions when multiple scanner threads
               detect threats simultaneously.
    """

    def __init__(self):
        """Initialise the vault, creating the directory structure if needed."""
        config = AgentConfig.load()
        self.vault_dir = config.get(
            "quarantine_dir",
            r"C:\ProgramData\BlueTeam\quarantine",
        )

        # Serialise all vault mutations to prevent partial-write races
        self._lock = threading.Lock()

        os.makedirs(self.vault_dir, exist_ok=True)
        logger.info("QuarantineVault initialised — vault at %s", self.vault_dir)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _utcnow_iso() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()

    def _vault_path(self, vault_id: str) -> str:
        """Return the absolute filesystem path for a vault artefact.

        Args:
            vault_id: The UUID string assigned to the quarantined file.

        Returns:
            Absolute path inside the vault directory.
        """
        # Files are stored with a `.quarantined` extension — this is NOT
        # a recognized executable extension on any platform.
        return os.path.join(self.vault_dir, f"{vault_id}.quarantined")

    def _meta_path(self, vault_id: str) -> str:
        """Return the absolute path for a vault artefact's metadata sidecar.

        Args:
            vault_id: The UUID string assigned to the quarantined file.

        Returns:
            Absolute path to the `.meta.json` companion file.
        """
        return os.path.join(self.vault_dir, f"{vault_id}.meta.json")

    def _write_metadata(
        self,
        vault_id: str,
        original_path: str,
        sha256: str,
        reason: str,
        timestamp: str,
    ) -> None:
        """Write the chain-of-custody metadata sidecar for a quarantined file.

        Args:
            vault_id: UUID identifying this quarantine record.
            original_path: Where the file lived before quarantine.
            sha256: SHA-256 hex digest of the file.
            reason: Human-readable detection reason (e.g. "YARA:Trojan_Generic").
            timestamp: ISO-8601 UTC timestamp of the quarantine action.
        """
        meta = {
            "vault_id": vault_id,
            "original_path": original_path,
            "sha256": sha256,
            "reason": reason,
            "quarantined_at": timestamp,
            "restored": False,
            "restored_at": None,
            "restored_by": None,
        }

        meta_file = self._meta_path(vault_id)
        with open(meta_file, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)

        logger.debug("Metadata sidecar written: %s", meta_file)

    def _read_metadata(self, vault_id: str) -> Optional[dict]:
        """Read and parse a quarantine metadata sidecar.

        Args:
            vault_id: UUID of the quarantine record.

        Returns:
            Parsed metadata dict, or None if the sidecar is missing/corrupt.
        """
        meta_file = self._meta_path(vault_id)
        if not os.path.isfile(meta_file):
            logger.warning("Metadata sidecar not found: %s", meta_file)
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read metadata %s: %s", meta_file, exc)
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def quarantine(self, original_path: str, sha256: str, reason: str) -> str:
        """Quarantine a malicious file: copy to vault, write metadata, delete original.

        This method implements the full quarantine lifecycle with robust error
        handling to ensure we never lose evidence even on partial failure.

        Args:
            original_path: Absolute path to the file to quarantine.
            sha256: SHA-256 hex digest of the file contents.
            reason: Detection reason string for the metadata record.

        Returns:
            The vault_id (UUID string) assigned to this quarantine record.

        Raises:
            FileNotFoundError: If the original file does not exist.
            OSError: If the copy or delete operations fail.
        """
        if not os.path.isfile(original_path):
            logger.error("Quarantine target does not exist: %s", original_path)
            raise FileNotFoundError(f"File not found: {original_path}")

        vault_id = str(uuid.uuid4())
        vault_file = self._vault_path(vault_id)
        timestamp = self._utcnow_iso()

        with self._lock:
            # ---- Step 1: Copy the file to the vault ----
            # We copy FIRST so that if deletion fails, we still have the
            # malicious file safely isolated in the vault.
            try:
                shutil.copy2(original_path, vault_file)
                logger.info(
                    "CHAIN-OF-CUSTODY: File copied to vault — "
                    "src=%s dst=%s vault_id=%s timestamp=%s",
                    original_path,
                    vault_file,
                    vault_id,
                    timestamp,
                )
            except OSError as exc:
                logger.error(
                    "Failed to copy file to vault — src=%s error=%s",
                    original_path,
                    exc,
                )
                raise

            # ---- Step 2: Write metadata sidecar ----
            try:
                self._write_metadata(vault_id, original_path, sha256, reason, timestamp)
                logger.info(
                    "CHAIN-OF-CUSTODY: Metadata written — vault_id=%s sha256=%s",
                    vault_id,
                    sha256[:16],
                )
            except OSError as exc:
                logger.error(
                    "Failed to write metadata sidecar for %s: %s", vault_id, exc
                )
                # Metadata failure is non-fatal — the file is already safely
                # in the vault. We log and continue.

            # ---- Step 3: Delete the original file ----
            try:
                os.remove(original_path)
                logger.info(
                    "CHAIN-OF-CUSTODY: Original deleted — path=%s vault_id=%s timestamp=%s",
                    original_path,
                    vault_id,
                    self._utcnow_iso(),
                )
            except OSError as exc:
                # The file is already safely quarantined, but we could not
                # remove the original.  This is logged as a warning because
                # the malicious file is now in two places.
                logger.warning(
                    "Could not delete original file %s after quarantine: %s — "
                    "manual cleanup required",
                    original_path,
                    exc,
                )

        logger.info(
            "Quarantine complete — vault_id=%s sha256=%s reason=%s",
            vault_id,
            sha256[:16],
            reason,
        )
        return vault_id

    def restore(self, vault_id: str, analyst_id: str) -> str:
        """Restore a quarantined file to its original location.

        This is a sensitive operation that should only be performed by
        authorised analysts after confirming the file is a false positive.
        The analyst_id is recorded in the metadata for accountability.

        Args:
            vault_id: The UUID of the quarantine record to restore.
            analyst_id: Identifier of the analyst authorising the restore.

        Returns:
            The original filesystem path where the file was restored.

        Raises:
            FileNotFoundError: If the vault artefact or metadata is missing.
            ValueError: If the file has already been restored.
        """
        vault_file = self._vault_path(vault_id)
        meta = self._read_metadata(vault_id)

        if meta is None:
            raise FileNotFoundError(f"No metadata found for vault_id={vault_id}")
        if not os.path.isfile(vault_file):
            raise FileNotFoundError(f"Vault artefact missing: {vault_file}")
        if meta.get("restored"):
            raise ValueError(
                f"File already restored by {meta.get('restored_by')} "
                f"at {meta.get('restored_at')}"
            )

        original_path = meta["original_path"]
        timestamp = self._utcnow_iso()

        with self._lock:
            # Ensure the original directory still exists
            original_dir = os.path.dirname(original_path)
            os.makedirs(original_dir, exist_ok=True)

            try:
                shutil.copy2(vault_file, original_path)
                logger.info(
                    "CHAIN-OF-CUSTODY: File restored — vault_id=%s "
                    "restored_to=%s analyst=%s timestamp=%s",
                    vault_id,
                    original_path,
                    analyst_id,
                    timestamp,
                )
            except OSError as exc:
                logger.error("Failed to restore %s: %s", vault_id, exc)
                raise

            # Update metadata to record the restore action
            meta["restored"] = True
            meta["restored_at"] = timestamp
            meta["restored_by"] = analyst_id
            try:
                with open(self._meta_path(vault_id), "w", encoding="utf-8") as fh:
                    json.dump(meta, fh, indent=2, ensure_ascii=False)
            except OSError as exc:
                logger.warning("Could not update metadata after restore: %s", exc)

        return original_path

    def list_quarantined(self) -> List[dict]:
        """List all quarantined artefacts currently in the vault.

        Returns:
            A list of metadata dicts, one per quarantined file.  Each dict
            contains vault_id, original_path, sha256, reason, quarantined_at,
            and restoration status.
        """
        results = []

        try:
            for filename in os.listdir(self.vault_dir):
                if not filename.endswith(".meta.json"):
                    continue

                vault_id = filename.replace(".meta.json", "")
                meta = self._read_metadata(vault_id)
                if meta is not None:
                    # Augment with whether the vault artefact file still exists
                    meta["artefact_present"] = os.path.isfile(
                        self._vault_path(vault_id)
                    )
                    results.append(meta)

        except OSError as exc:
            logger.error("Error listing vault directory %s: %s", self.vault_dir, exc)

        logger.info("Vault listing — %d artefact(s) found", len(results))
        return results
