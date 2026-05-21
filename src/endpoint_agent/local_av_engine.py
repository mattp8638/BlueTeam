"""
local_av_engine.py — On-Device Antivirus Orchestrator
=====================================================

Central orchestration layer for the endpoint's local antivirus pipeline.
When a file event is detected (new file written, process spawned, scheduled
scan), the `scan_file()` method drives a multi-stage analysis pipeline:

    1. **Hash cache lookup** — consult the local SQLite cache of known file
       hashes.  If the hash is already classified as CLEAN the file is skipped
       immediately (fast path).  If classified as MALICIOUS the file is
       quarantined without further analysis (blocking path).

    2. **Entropy analysis** — uses Shannon entropy to flag files with
       suspiciously high entropy, which is a hallmark of packed, encrypted,
       or obfuscated malware.

    3. **YARA signature scan** — matches file contents against a library of
       YARA rules loaded by `YaraRuleLoader`.  Rules cover known malware
       families, suspicious API imports, packer stubs, etc.

    4. **Hash lookup** — checks the file's SHA-256 against the hash cache
       for any backend-synced threat intelligence.

    5. **Correlation** — if two or more detection backends flag the file,
       it is classified as malicious.  A single hit is treated as suspicious
       and logged but not auto-quarantined (reduces false positives).

    6. **Action** — malicious files are quarantined via `QuarantineVault`
       and their hash is recorded in `HashCache` as MALICIOUS.  Clean files
       are cached as CLEAN to accelerate future lookups.

    7. **Reporting** — malicious findings are returned as OCSF Class 1001
       (Security Finding) dicts, ready for transmission to the Nerve Center.

Security rationale:
    - The multi-engine correlation approach reduces false positives compared
      to any single detection method.  Two independent signals provide much
      higher confidence than one.
    - Cache-first architecture ensures that repeated encounters with the same
      file (e.g. during scheduled scans) have near-zero CPU cost.
    - OCSF-compliant output normalises findings for the Nerve Center's SIEM
      ingestion pipeline.
"""

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

# Backend AV detection engines
from src.av_core.shannon_entropy import ShannonEntropyCalculator
from src.av_core.yara_scanner import YaraScanner

# Local support modules
from src.endpoint_agent.hash_cache import HashCache
from src.endpoint_agent.quarantine_vault import QuarantineVault

logger = AgentLogger.get_logger("LocalAVEngine")

# OCSF schema constants
OCSF_CLASS_SECURITY_FINDING = 1001
OCSF_SEVERITY_HIGH = 4
OCSF_SEVERITY_MEDIUM = 3
OCSF_ACTIVITY_CREATE = 1

# Entropy threshold — files above this are flagged as suspicious.
# Typical executables have entropy ~6.0; packed/encrypted files are >7.2.
DEFAULT_ENTROPY_THRESHOLD = 7.2

# Minimum number of detection hits required to classify as malware.
# Set to 2 to require corroboration from multiple engines.
CORRELATION_THRESHOLD = 2


class LocalAVEngine:
    """On-device antivirus engine that orchestrates multi-backend file scanning.

    This class wires together the hash cache, entropy calculator, YARA scanner,
    and quarantine vault into a single `scan_file()` entry point.

    Attributes:
        config: The loaded agent configuration dict.
        hash_cache: Local SQLite hash verdict cache.
        quarantine_vault: Secure file quarantine manager.
        entropy_calculator: Shannon entropy analysis engine.
        yara_scanner: YARA signature matching engine.
        entropy_threshold: Entropy value above which a file is flagged.
        hostname: Local machine hostname for OCSF finding attribution.
    """

    def __init__(self):
        """Initialise all sub-engines and load configuration."""
        self.config = AgentConfig.load()

        # Sub-engine initialisation — each has its own error handling and
        # logging, so failures here surface clearly in the agent log.
        self.hash_cache = HashCache()
        self.quarantine_vault = QuarantineVault()
        self.entropy_calculator = ShannonEntropyCalculator()
        self.yara_scanner = YaraScanner()

        self.entropy_threshold = float(
            self.config.get("entropy_threshold", DEFAULT_ENTROPY_THRESHOLD)
        )
        self.hostname = os.environ.get("COMPUTERNAME", "unknown-host")

        # Scan statistics — accumulate across the engine's lifetime
        self._stats = {
            "files_scanned": 0,
            "cache_hits": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "errors": 0,
        }

        logger.info(
            "LocalAVEngine initialised — entropy_threshold=%.2f host=%s",
            self.entropy_threshold,
            self.hostname,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_sha256(raw_bytes: bytes) -> str:
        """Compute the SHA-256 hex digest of raw file bytes.

        Args:
            raw_bytes: The file content.

        Returns:
            Lowercase hex digest string.
        """
        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def _utcnow_iso() -> str:
        """Return current UTC time as ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()

    def _build_ocsf_finding(
        self,
        file_path: str,
        sha256: str,
        detections: List[str],
        severity: int,
        vault_id: Optional[str] = None,
    ) -> Dict:
        """Build an OCSF Class 1001 Security Finding dict.

        The Open Cybersecurity Schema Framework (OCSF) defines a vendor-
        neutral format for security telemetry.  Class 1001 represents a
        security finding — a discrete detection of malicious or suspicious
        activity.

        Args:
            file_path: The original filesystem path of the scanned file.
            sha256: SHA-256 hash of the file.
            detections: List of detection engine names that flagged the file.
            severity: OCSF severity level (1=Info … 5=Critical).
            vault_id: UUID of the quarantine record, if the file was quarantined.

        Returns:
            An OCSF-compliant finding dict.
        """
        finding = {
            "class_uid": OCSF_CLASS_SECURITY_FINDING,
            "class_name": "Security Finding",
            "activity_id": OCSF_ACTIVITY_CREATE,
            "activity_name": "Create",
            "severity_id": severity,
            "severity": "High" if severity >= OCSF_SEVERITY_HIGH else "Medium",
            "status": "New",
            "time": self._utcnow_iso(),
            "message": f"Malware detected: {', '.join(detections)}",
            "finding": {
                "title": f"Malicious file detected on {self.hostname}",
                "desc": (
                    f"File at '{file_path}' flagged by {len(detections)} "
                    f"detection engine(s): {', '.join(detections)}."
                ),
                "types": ["Malware"],
                "src_url": file_path,
            },
            "resources": [
                {
                    "type": "File",
                    "name": os.path.basename(file_path),
                    "uid": sha256,
                    "data": {
                        "path": file_path,
                        "sha256": sha256,
                        "detections": detections,
                    },
                }
            ],
            "metadata": {
                "product": {
                    "name": "BlueTeam Endpoint Agent",
                    "vendor_name": "BlueTeam",
                    "feature": {"name": "LocalAVEngine"},
                },
                "version": "1.0.0",
                "logged_time": self._utcnow_iso(),
            },
        }

        if vault_id:
            finding["remediation"] = {
                "desc": "File quarantined automatically",
                "vault_id": vault_id,
            }

        return finding

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(
        self, file_path: str, raw_bytes: Optional[bytes] = None
    ) -> Optional[Dict]:
        """Run the full multi-engine AV scan pipeline on a single file.

        This is the main entry point called by filesystem monitors and the
        scheduled scanner.  It implements the cache-first, multi-engine
        correlation strategy described in the module docstring.

        Args:
            file_path: Absolute path to the file being scanned.
            raw_bytes: Pre-read file contents.  If None, the file is read
                from disk.  Passing raw_bytes avoids a redundant disk read
                when the caller has already loaded the file.

        Returns:
            An OCSF Class 1001 finding dict if the file is malicious,
            or None if the file is clean.
        """
        self._stats["files_scanned"] += 1
        start_time = time.monotonic()

        logger.debug("Scanning file: %s", file_path)

        # ---- Read file bytes if not provided ----
        if raw_bytes is None:
            try:
                with open(file_path, "rb") as fh:
                    raw_bytes = fh.read()
            except OSError as exc:
                logger.error("Cannot read file %s: %s", file_path, exc)
                self._stats["errors"] += 1
                return None

        if not raw_bytes:
            logger.debug("File is empty, skipping: %s", file_path)
            return None

        # ---- Compute hash ----
        sha256 = self._compute_sha256(raw_bytes)

        # ====================================================================
        # STAGE 1: Hash cache lookup (fast path)
        # ====================================================================
        cached_verdict = self.hash_cache.lookup(sha256)

        if cached_verdict == "CLEAN":
            # Known-good — skip all further analysis
            self._stats["cache_hits"] += 1
            logger.debug("Cache HIT (CLEAN) for %s — skipping", file_path)
            return None

        if cached_verdict == "MALICIOUS":
            # Known-bad — quarantine immediately without re-scanning
            self._stats["cache_hits"] += 1
            self._stats["threats_detected"] += 1
            logger.warning(
                "Cache HIT (MALICIOUS) for %s — quarantining immediately",
                file_path,
            )

            vault_id = None
            try:
                vault_id = self.quarantine_vault.quarantine(
                    original_path=file_path,
                    sha256=sha256,
                    reason="hash_cache:MALICIOUS",
                )
                self._stats["files_quarantined"] += 1
            except (FileNotFoundError, OSError) as exc:
                logger.error("Quarantine failed for %s: %s", file_path, exc)

            return self._build_ocsf_finding(
                file_path=file_path,
                sha256=sha256,
                detections=["hash_cache"],
                severity=OCSF_SEVERITY_HIGH,
                vault_id=vault_id,
            )

        # ====================================================================
        # STAGE 2: Multi-engine analysis (unknown file)
        # ====================================================================
        detections: List[str] = []

        # ---- 2a: Shannon entropy analysis ----
        try:
            entropy_value = self.entropy_calculator.calculate(raw_bytes)
            if entropy_value >= self.entropy_threshold:
                detections.append(f"entropy:{entropy_value:.4f}")
                logger.info(
                    "High entropy detected — file=%s entropy=%.4f threshold=%.2f",
                    file_path,
                    entropy_value,
                    self.entropy_threshold,
                )
            else:
                logger.debug(
                    "Entropy within normal range — file=%s entropy=%.4f",
                    file_path,
                    entropy_value,
                )
        except Exception as exc:
            logger.error("Entropy analysis failed for %s: %s", file_path, exc)
            self._stats["errors"] += 1

        # ---- 2b: YARA signature scan ----
        try:
            yara_matches = self.yara_scanner.scan(raw_bytes)
            if yara_matches:
                for match_name in yara_matches:
                    detections.append(f"yara:{match_name}")
                logger.info(
                    "YARA matches found — file=%s rules=%s",
                    file_path,
                    ", ".join(yara_matches),
                )
            else:
                logger.debug("No YARA matches for %s", file_path)
        except Exception as exc:
            logger.error("YARA scan failed for %s: %s", file_path, exc)
            self._stats["errors"] += 1

        # ---- 2c: Hash lookup (backend-synced threat intel) ----
        # The hash cache may have been populated by sync_from_backend() with
        # hashes that were not in the cache when we checked in Stage 1 (race
        # condition window is intentionally accepted for performance).  This
        # secondary check catches hashes synced from the Nerve Center's
        # threat intel feed.
        try:
            backend_verdict = self.hash_cache.lookup(sha256)
            if backend_verdict == "MALICIOUS":
                detections.append("hash_lookup:backend_intel")
                logger.info(
                    "Hash matched backend threat intel — sha256=%s", sha256[:16]
                )
        except Exception as exc:
            logger.error("Hash lookup failed for %s: %s", sha256[:16], exc)
            self._stats["errors"] += 1

        # ====================================================================
        # STAGE 3: Correlation — 2+ hits = malware
        # ====================================================================
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if len(detections) >= CORRELATION_THRESHOLD:
            # ------ MALICIOUS — quarantine and record ------
            self._stats["threats_detected"] += 1
            logger.warning(
                "MALWARE DETECTED — file=%s sha256=%s detections=%s elapsed=%.1fms",
                file_path,
                sha256[:16],
                detections,
                elapsed_ms,
            )

            # Quarantine the file
            vault_id = None
            try:
                reason = "; ".join(detections)
                vault_id = self.quarantine_vault.quarantine(
                    original_path=file_path,
                    sha256=sha256,
                    reason=reason,
                )
                self._stats["files_quarantined"] += 1
            except (FileNotFoundError, OSError) as exc:
                logger.error("Quarantine failed for %s: %s", file_path, exc)

            # Cache as known-bad for future fast-path lookups
            self.hash_cache.add(sha256, "MALICIOUS", file_path)

            return self._build_ocsf_finding(
                file_path=file_path,
                sha256=sha256,
                detections=detections,
                severity=OCSF_SEVERITY_HIGH,
                vault_id=vault_id,
            )

        elif len(detections) == 1:
            # ------ SUSPICIOUS — log but do not quarantine ------
            logger.info(
                "SUSPICIOUS file (single-engine hit, below correlation threshold) — "
                "file=%s sha256=%s detection=%s elapsed=%.1fms",
                file_path,
                sha256[:16],
                detections[0],
                elapsed_ms,
            )
            # Mark as UNKNOWN so it gets re-scanned on the next encounter
            self.hash_cache.add(sha256, "UNKNOWN", file_path)
            return None

        else:
            # ------ CLEAN — no detections ------
            logger.debug(
                "File is clean — file=%s sha256=%s elapsed=%.1fms",
                file_path,
                sha256[:16],
                elapsed_ms,
            )
            self.hash_cache.add(sha256, "CLEAN", file_path)
            return None

    def get_stats(self) -> Dict:
        """Return accumulated scan statistics.

        Returns:
            Dict with keys: files_scanned, cache_hits, threats_detected,
            files_quarantined, errors.
        """
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset all scan statistics to zero.

        Typically called at the start of a scheduled scan so that per-scan
        statistics are tracked independently.
        """
        for key in self._stats:
            self._stats[key] = 0
        logger.debug("Scan statistics reset")
