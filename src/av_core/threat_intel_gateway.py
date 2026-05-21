import hashlib
import time

class ThreatIntelGateway:
    """
    External Reputation Engine.
    Calculates the cryptographic hash of a file and queries an external
    database (e.g., VirusTotal, AlienVault) to check for community flags.
    """
    
    # Mock external database
    _known_malicious_hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Empty file hash (Mock example)
        "d2d2c1e7a85c4b54fa578c7c9f80a221f7c7849e79d1a3c5df0ed0e2c0199e4b"  # Mock ransomware hash
    ]

    @classmethod
    def analyze(cls, file_name: str, raw_bytes: bytes) -> dict:
        print(f"[Threat Intel Engine] Calculating SHA-256 for {file_name}...")
        
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        print(f" -> Hash: {sha256_hash}")
        
        print("[Threat Intel Engine] Querying external reputation APIs...")
        time.sleep(1.0) # Simulate API latency
        
        is_malicious = sha256_hash in cls._known_malicious_hashes
        
        if is_malicious:
            print(" -> [ALERT] File hash flagged by 42/70 security vendors!")
        else:
            print(" -> File hash is unknown/clean.")
            
        return {
            "engine": "Reputation",
            "hash": sha256_hash,
            "is_malicious": is_malicious,
            "details": "Flagged by external threat intel." if is_malicious else "Clean"
        }
