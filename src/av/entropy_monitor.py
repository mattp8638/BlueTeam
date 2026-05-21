import math
import os
import json
import uuid
import time
from datetime import datetime, timezone
from collections import Counter

class RansomwareEntropyMonitor:
    def __init__(self):
        self.entropy_threshold = 7.95

    def calculate_shannon_entropy(self, data: bytes) -> float:
        """
        Calculates the Shannon Entropy (H) of a byte sequence.
        H(X) = - sum( P(x_i) * log2(P(x_i)) )
        """
        if not data:
            return 0.0
            
        entropy = 0
        length = len(data)
        
        # Count byte frequencies
        occurrences = Counter(data)
        
        for count in occurrences.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
            
        return entropy

    def evaluate_file(self, filepath: str):
        """
        Reads a file and evaluates its entropy against the ransomware threshold.
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            entropy = self.calculate_shannon_entropy(data)
            print(f"File: {os.path.basename(filepath)} | Entropy: {entropy:.4f}")
            
            if entropy >= self.entropy_threshold:
                self._trigger_kernel_block(filepath, entropy)
                
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")

    def _trigger_kernel_block(self, filepath: str, entropy: float):
        """
        Mocks the kernel-level process suspension and generates an OCSF 1001 alert.
        """
        print(f"\n[!!!] RANSOMWARE BEHAVIOR DETECTED! Entropy {entropy:.4f} exceeds threshold {self.entropy_threshold}")
        print("[!]   Simulating Kernel Hook: Killing process handle and preserving volume shadow state...\n")
        
        # Generate OCSF Class 1001 payload
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "class_id": 1001,
            "class_name": "Malware Finding",
            "severity_id": 4,
            "severity": "Critical",
            "file_name": os.path.basename(filepath),
            "file_path": filepath,
            "metadata_product_vendor": "BlueTeam_NGAV_Kernel_Agent",
            "raw_message": f"High entropy write detected: H={entropy:.4f}"
        }
        
        print("Dispatching OCSF Alert to SIEM Ingestion Pipeline:")
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    monitor = RansomwareEntropyMonitor()
    
    # Setup test directory (Canary Trap)
    os.makedirs("canary_trap", exist_ok=True)
    
    # Create a normal text file (Low Entropy)
    normal_file = "canary_trap/normal_doc.txt"
    with open(normal_file, "w") as f:
        f.write("This is a normal text file. " * 50)
        
    # Create an encrypted/compressed file (High Entropy)
    # We simulate this using random byte generation
    encrypted_file = "canary_trap/encrypted_doc.locked"
    with open(encrypted_file, "wb") as f:
        f.write(os.urandom(10240)) # 10KB of purely random bytes
        
    print("--- Evaluating Canary Trap Files ---")
    monitor.evaluate_file(normal_file)
    time.sleep(1)
    monitor.evaluate_file(encrypted_file)
    
    # Cleanup
    os.remove(normal_file)
    os.remove(encrypted_file)
    os.rmdir("canary_trap")
