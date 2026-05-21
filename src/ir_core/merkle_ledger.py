import hashlib
import json
import uuid
from datetime import datetime, timezone
from src.ir_core.database import IRDatabase

class MerkleLedger:
    """
    Cryptographic append-only transaction ledger.
    H(T_n) = SHA-256(T_n || H(T_n-1))
    """
    
    @staticmethod
    def _calculate_hash(payload: str, previous_hash: str) -> str:
        combined = f"{payload}||{previous_hash}".encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def _get_previous_hash(cursor, ticket_id: str) -> str:
        cursor.execute(
            "SELECT hash_state FROM ledger WHERE ticket_id = ? ORDER BY transaction_id DESC LIMIT 1",
            (ticket_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else "0000000000000000000000000000000000000000000000000000000000000000"

    @classmethod
    def append_transaction(cls, ticket_id: str, action_type: str, payload_dict: dict):
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        now = datetime.now(timezone.utc).isoformat()
        payload_str = json.dumps(payload_dict, sort_keys=True)
        
        prev_hash = cls._get_previous_hash(cursor, ticket_id)
        new_hash = cls._calculate_hash(payload_str, prev_hash)
        
        cursor.execute(
            "INSERT INTO ledger (ticket_id, action_type, payload, timestamp, hash_state) VALUES (?, ?, ?, ?, ?)",
            (ticket_id, action_type, payload_str, now, new_hash)
        )
        conn.commit()

    @classmethod
    def verify_integrity(cls, ticket_id: str) -> bool:
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT payload, hash_state FROM ledger WHERE ticket_id = ? ORDER BY transaction_id ASC",
            (ticket_id,)
        )
        rows = cursor.fetchall()
        
        current_prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        
        for i, (payload, stored_hash) in enumerate(rows):
            expected_hash = cls._calculate_hash(payload, current_prev_hash)
            
            if expected_hash != stored_hash:
                print(f"[CRITICAL] Chain broken at index {i}. Expected {expected_hash}, got {stored_hash}")
                return False
                
            current_prev_hash = stored_hash
            
        return True
