import os
import time
import hashlib

class OOBAuthSandbox:
    """
    Out-of-Band (OOB) Authentication Sandbox.
    Decoupled from production Active Directory, it generates localized
    end-to-end encryption keys in-memory per analyst session.
    """
    
    _active_sessions = {}

    @classmethod
    def authenticate_analyst(cls, username: str, credentials_hash: str) -> str:
        """
        Authenticates an analyst using the isolated Zero-Trust directory.
        Generates a volatile AES-GCM session key.
        """
        # MOCK Directory Check (In production, this queries the isolated IAM database)
        if username == "admin" and credentials_hash == "valid_hash":
            
            # Generate volatile session key (Mocking AES-256-GCM key generation)
            session_id = os.urandom(16).hex()
            volatile_key = hashlib.sha256(os.urandom(32)).hexdigest()
            
            cls._active_sessions[session_id] = {
                "username": username,
                "key": volatile_key,
                "expires": time.time() + 3600 # 1 hour expiry
            }
            
            print(f"[OOB Sandbox] Authenticated {username}.")
            print(f" -> Session ID: {session_id}")
            print(f" -> Volatile E2E Key Generated (In-Memory Only)")
            
            return session_id
        else:
            print("[OOB Sandbox] Authentication Failed: Invalid credentials.")
            return None

    @classmethod
    def validate_session(cls, session_id: str) -> bool:
        session = cls._active_sessions.get(session_id)
        if not session:
            return False
            
        if time.time() > session["expires"]:
            print(f"[OOB Sandbox] Session {session_id} expired. Purging key.")
            del cls._active_sessions[session_id]
            return False
            
        return True

    @classmethod
    def get_session_key(cls, session_id: str) -> str:
        if cls.validate_session(session_id):
            return cls._active_sessions[session_id]["key"]
        return None

if __name__ == "__main__":
    # Test Auth
    print("--- Authenticating Valid User ---")
    sess_id = OOBAuthSandbox.authenticate_analyst("admin", "valid_hash")
    
    print("\n--- Requesting E2E Key via Session ID ---")
    key = OOBAuthSandbox.get_session_key(sess_id)
    print(f"Retrieved Volatile Key: {key[:10]}... (Truncated)")
    
    print("\n--- Authenticating Invalid User ---")
    OOBAuthSandbox.authenticate_analyst("hacker", "invalid")
