import sqlite3
import threading

class IRDatabase:
    """
    Handles the operational state database connection.
    Designed to easily swap SQLite for PostgreSQL via SQLAlchemy in production.
    """
    _local = threading.local()

    @classmethod
    def get_connection(cls, db_path="ir_operational.db"):
        if not hasattr(cls._local, "conn"):
            cls._local.conn = sqlite3.connect(db_path, check_same_thread=False)
            cls.init_schema(cls._local.conn)
        return cls._local.conn

    @classmethod
    def init_schema(cls, conn):
        cursor = conn.cursor()
        
        # Operational Ticket Map
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id TEXT PRIMARY KEY,
                title TEXT,
                status TEXT,
                severity TEXT,
                created_at TEXT,
                sla_deadline TEXT,
                assignee TEXT
            )
        ''')
        
        # Dynamically upgrade schema for existing DBs
        try:
            cursor.execute("ALTER TABLE tickets ADD COLUMN assignee TEXT")
        except sqlite3.OperationalError:
            pass

        
        # Merkle Ledger Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ledger (
                transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT,
                action_type TEXT,
                payload TEXT,
                timestamp TEXT,
                hash_state TEXT
            )
        ''')
        
        # Evidence Vault Metadata Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_vault (
                file_hash TEXT PRIMARY KEY,
                ticket_id TEXT,
                pki_signature TEXT,
                encrypted_path TEXT,
                timestamp TEXT
            )
        ''')

        # Quarantined Files Threat Vault
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                file_hash TEXT PRIMARY KEY,
                file_name TEXT,
                file_path TEXT,
                device_id TEXT,
                hostname TEXT,
                ip_address TEXT,
                status TEXT,
                threat_name TEXT,
                confidence REAL,
                timestamp TEXT,
                sandbox_report TEXT
            )
        ''')

        # SOAR Execution Logs History
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS soar_history (
                execution_id TEXT PRIMARY KEY,
                playbook_name TEXT,
                target_ip TEXT,
                status TEXT,
                started_at TEXT,
                completed_at TEXT,
                log_output TEXT
            )
        ''')
        
        conn.commit()
