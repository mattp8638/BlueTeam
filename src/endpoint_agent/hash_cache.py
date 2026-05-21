"""
hash_cache.py — Local SQLite Hash Cache for File Verdicts
=========================================================

Maintains a persistent, thread-safe SQLite database of file hashes and their
associated verdicts (CLEAN, MALICIOUS, UNKNOWN). This cache sits at the front
of the AV scanning pipeline: before running expensive entropy analysis or YARA
scans, the LocalAVEngine checks this cache to see if the file's SHA-256 hash
has already been classified.

Security rationale:
    - Avoiding redundant scans dramatically reduces CPU load on the endpoint,
      which is critical for maintaining system responsiveness.
    - The cache supports bulk-sync of known-bad hashes from the Nerve Center,
      enabling rapid threat intelligence distribution across all endpoints.
    - WAL (Write-Ahead Logging) mode is used for safe concurrent access from
      multiple scanner threads without database locking issues.
    - All timestamps are stored in UTC ISO-8601 format for forensic consistency.

Database schema:
    file_hashes (
        sha256      TEXT PRIMARY KEY,   -- SHA-256 hex digest
        verdict     TEXT NOT NULL,       -- 'CLEAN', 'MALICIOUS', or 'UNKNOWN'
        first_seen  TEXT NOT NULL,       -- ISO-8601 UTC timestamp of first observation
        last_seen   TEXT NOT NULL,       -- ISO-8601 UTC timestamp of most recent observation
        file_path   TEXT                 -- Last known filesystem path (for audit trail)
    )
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("HashCache")

# Valid verdict values — enforced on all writes to prevent data corruption
VALID_VERDICTS = {"CLEAN", "MALICIOUS", "UNKNOWN"}


class HashCache:
    """Thread-safe SQLite cache mapping SHA-256 hashes to AV verdicts.

    The cache is designed for high-throughput lookups with infrequent writes.
    SQLite WAL mode allows concurrent readers while a single writer commits
    new verdicts without blocking scan operations.

    Attributes:
        db_path: Absolute path to the SQLite database file.
        _lock: Threading lock for serialising write operations.
        _local: Thread-local storage for per-thread database connections.
    """

    def __init__(self):
        """Initialise the hash cache, creating the database if it doesn't exist.

        The database path is read from agent configuration. Parent directories
        are created automatically to support first-run bootstrapping.
        """
        config = AgentConfig.load()
        self.db_path = config.get(
            "hash_db_path",
            r"C:\ProgramData\BlueTeam\data\hash_cache.db",
        )

        # Serialise all write operations to avoid SQLite "database is locked" errors
        self._lock = threading.Lock()

        # Each thread gets its own connection — SQLite connections are NOT
        # thread-safe and must not be shared across threads.
        self._local = threading.local()

        # Ensure the parent directory exists before attempting to open the DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # Bootstrap the schema on first run
        self._init_db()
        logger.info("HashCache initialised — database at %s", self.db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        """Return a per-thread SQLite connection, creating one if necessary.

        Using thread-local storage guarantees that each scanner thread gets
        its own connection, avoiding cross-thread corruption.

        Returns:
            A sqlite3.Connection bound to the current thread.
        """
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            # WAL mode allows concurrent reads during writes — essential for
            # real-time scanning where lookup and insert happen in parallel.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        """Create the file_hashes table if it doesn't already exist.

        This is idempotent and safe to call on every startup.
        """
        conn = self._get_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_hashes (
                sha256     TEXT PRIMARY KEY,
                verdict    TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                file_path  TEXT
            )
            """
        )
        # Index on verdict speeds up get_stats() aggregation queries
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_verdict
            ON file_hashes (verdict)
            """
        )
        conn.commit()

    @staticmethod
    def _utcnow_iso() -> str:
        """Return the current UTC time as an ISO-8601 string.

        All timestamps are normalised to UTC so that logs and forensic
        artefacts from endpoints in different time zones remain comparable.
        """
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, sha256: str) -> Optional[str]:
        """Look up a file hash and return its cached verdict.

        This is the hot path — called for every file event before any
        heavyweight analysis is performed. It must be as fast as possible.

        Args:
            sha256: The SHA-256 hex digest of the file to look up.

        Returns:
            The verdict string ('CLEAN', 'MALICIOUS', or 'UNKNOWN') if the
            hash is in the cache, or None if it has never been seen.
        """
        if not sha256:
            logger.warning("lookup() called with empty SHA-256 — skipping")
            return None

        sha256 = sha256.lower().strip()

        try:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT verdict FROM file_hashes WHERE sha256 = ?",
                (sha256,),
            )
            row = cursor.fetchone()

            if row is not None:
                verdict = row["verdict"]
                logger.debug("Cache HIT for %s — verdict: %s", sha256[:16], verdict)

                # Update last_seen timestamp on every lookup so we can age-out
                # stale entries in future maintenance sweeps.
                with self._lock:
                    conn.execute(
                        "UPDATE file_hashes SET last_seen = ? WHERE sha256 = ?",
                        (self._utcnow_iso(), sha256),
                    )
                    conn.commit()

                return verdict

            logger.debug("Cache MISS for %s", sha256[:16])
            return None

        except sqlite3.Error as exc:
            logger.error("SQLite error during lookup for %s: %s", sha256[:16], exc)
            return None

    def add(self, sha256: str, verdict: str, file_path: str = "") -> None:
        """Insert or update a hash verdict in the cache.

        If the hash already exists, the verdict and last_seen timestamp are
        updated but first_seen is preserved for forensic integrity.

        Args:
            sha256: The SHA-256 hex digest.
            verdict: One of 'CLEAN', 'MALICIOUS', or 'UNKNOWN'.
            file_path: The filesystem path where this file was observed.

        Raises:
            ValueError: If verdict is not one of the allowed values.
        """
        verdict = verdict.upper().strip()
        if verdict not in VALID_VERDICTS:
            raise ValueError(
                f"Invalid verdict '{verdict}' — must be one of {VALID_VERDICTS}"
            )

        sha256 = sha256.lower().strip()
        now = self._utcnow_iso()

        try:
            with self._lock:
                conn = self._get_connection()
                # UPSERT — insert if new, update verdict + last_seen if existing.
                # first_seen is only set on initial insertion (COALESCE preserves it).
                conn.execute(
                    """
                    INSERT INTO file_hashes (sha256, verdict, first_seen, last_seen, file_path)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        verdict   = excluded.verdict,
                        last_seen = excluded.last_seen,
                        file_path = excluded.file_path
                    """,
                    (sha256, verdict, now, now, file_path),
                )
                conn.commit()

            logger.info(
                "Cache ADD — sha256=%s verdict=%s path=%s",
                sha256[:16],
                verdict,
                file_path,
            )

        except sqlite3.Error as exc:
            logger.error("SQLite error adding hash %s: %s", sha256[:16], exc)

    def get_stats(self) -> dict:
        """Return aggregate counts of cached verdicts.

        Useful for dashboard reporting and health checks — the Nerve Center
        periodically polls this to assess endpoint cache effectiveness.

        Returns:
            A dict with keys 'clean', 'malicious', 'unknown', and 'total',
            each mapping to an integer count.
        """
        stats = {"clean": 0, "malicious": 0, "unknown": 0, "total": 0}

        try:
            conn = self._get_connection()
            cursor = conn.execute(
                """
                SELECT verdict, COUNT(*) AS cnt
                FROM file_hashes
                GROUP BY verdict
                """
            )
            for row in cursor.fetchall():
                key = row["verdict"].lower()
                if key in stats:
                    stats[key] = row["cnt"]

            stats["total"] = stats["clean"] + stats["malicious"] + stats["unknown"]
            logger.debug("Cache stats: %s", stats)

        except sqlite3.Error as exc:
            logger.error("SQLite error fetching stats: %s", exc)

        return stats

    def sync_from_backend(self, malicious_hashes: list) -> int:
        """Bulk-insert known-bad hashes received from the Nerve Center.

        This is the primary mechanism for distributing threat intelligence
        from the central server to all endpoints.  Hashes are inserted with
        verdict 'MALICIOUS' so that any subsequent file matching one of these
        hashes is immediately quarantined without running local analysis.

        Args:
            malicious_hashes: A list of SHA-256 hex digest strings that the
                Nerve Center has classified as malicious.

        Returns:
            The number of new hashes inserted (excluding duplicates).
        """
        if not malicious_hashes:
            logger.info("sync_from_backend called with empty hash list — nothing to do")
            return 0

        now = self._utcnow_iso()
        inserted = 0

        try:
            with self._lock:
                conn = self._get_connection()
                for sha256 in malicious_hashes:
                    sha256 = sha256.lower().strip()
                    if not sha256:
                        continue

                    # INSERT OR IGNORE — if the hash is already cached we
                    # don't overwrite a potentially richer local record.
                    cursor = conn.execute(
                        """
                        INSERT OR IGNORE INTO file_hashes
                            (sha256, verdict, first_seen, last_seen, file_path)
                        VALUES (?, 'MALICIOUS', ?, ?, 'backend_sync')
                        """,
                        (sha256, now, now),
                    )
                    inserted += cursor.rowcount

                conn.commit()

            logger.info(
                "Backend sync complete — %d/%d new malicious hashes ingested",
                inserted,
                len(malicious_hashes),
            )

        except sqlite3.Error as exc:
            logger.error("SQLite error during backend sync: %s", exc)

        return inserted

    def close(self) -> None:
        """Close the current thread's database connection.

        Should be called during agent shutdown to ensure all WAL pages are
        flushed to the main database file.
        """
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
                self._local.conn = None
                logger.info("HashCache connection closed")
            except sqlite3.Error as exc:
                logger.error("Error closing HashCache connection: %s", exc)
