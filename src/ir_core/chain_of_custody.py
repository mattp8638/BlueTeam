import hashlib
import os
from datetime import datetime, timezone
from src.ir_core.database import IRDatabase
from src.ir_core.merkle_ledger import MerkleLedger

class ForensicVault:
    """
    Cryptographically secure evidence vault.
    Enforces Chain-of-Custody (CoC) via PKI verification and hashing.
    """
    
    @staticmethod
    def _verify_pki_signature(file_data: bytes, signature: str, agent_pub_key: str) -> bool:
        """
        MOCK FUNCTION: Verifies the cryptographic signature of the submitting agent.
        In production, this would use pycryptodome and RSA/ECDSA verification.
        """
        print(f"[Vault] Verifying PKI signature using Agent Key: {agent_pub_key}...")
        return signature.startswith("VALID_SIG_")

    @staticmethod
    def _encrypt_for_storage(file_data: bytes) -> bytes:
        """
        MOCK FUNCTION: Encrypts the raw binary blob before writing to disk.
        """
        # Simple XOR for mock purposes to obscure the blob
        return bytes(b ^ 0xAA for b in file_data)

    @classmethod
    def upload_evidence(cls, ticket_id: str, file_name: str, file_data: bytes, pki_signature: str, agent_key: str):
        """
        The required Chain-of-Custody pipeline for artifact uploads.
        """
        # 1. Verify PKI
        if not cls._verify_pki_signature(file_data, pki_signature, agent_key):
            print(f"[Vault Error] Invalid PKI Signature! Rejecting upload for {file_name}.")
            return False
            
        # 2. Calculate Hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # 3. Register Metadata block to the Merkle Ledger *before* storage
        vault_metadata = {
            "file_name": file_name,
            "sha256": file_hash,
            "pki_verified": True,
            "agent_key": agent_key
        }
        MerkleLedger.append_transaction(ticket_id, "EVIDENCE_UPLOAD", vault_metadata)
        
        # 4. Encrypt and Store
        encrypted_data = cls._encrypt_for_storage(file_data)
        
        # Ensure vault directory exists
        os.makedirs("vault_storage", exist_ok=True)
        storage_path = os.path.join("vault_storage", f"{file_hash}.enc")
        
        with open(storage_path, "wb") as f:
            f.write(encrypted_data)
            
        # 5. Record to DB
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute(
            "INSERT INTO evidence_vault (file_hash, ticket_id, pki_signature, encrypted_path, timestamp) VALUES (?, ?, ?, ?, ?)",
            (file_hash, ticket_id, pki_signature, storage_path, now)
        )
        conn.commit()
        
        print(f"[Vault] Evidence {file_name} securely stored. Hash: {file_hash}")
        return True

if __name__ == "__main__":
    # Test the vault
    from src.ir_core.ingestion_clustering import TokenClusteringEngine
    
    # Create mock ticket
    ticket_id = TokenClusteringEngine._create_root_ticket({"class_id": 6001})
    
    # Mock Memory Dump
    mock_memory_dump = b"MZ\x90\x00\x03\x00\x00\x00... MALICIOUS SHELLCODE ..."
    
    print("\n--- Uploading Valid Evidence ---")
    ForensicVault.upload_evidence(
        ticket_id=ticket_id,
        file_name="memory_dump_pid_1234.dmp",
        file_data=mock_memory_dump,
        pki_signature="VALID_SIG_8F3A2",
        agent_key="PUB_KEY_ENDPOINT_01"
    )
    
    print("\n--- Uploading Invalid Evidence (Spoofed) ---")
    ForensicVault.upload_evidence(
        ticket_id=ticket_id,
        file_name="fake_dump.dmp",
        file_data=b"Just some fake data",
        pki_signature="INVALID_SIG",
        agent_key="PUB_KEY_ENDPOINT_01"
    )
