import json
from src.av_core.av_orchestrator import AVOrchestrator
from src.av_core.threat_intel_gateway import ThreatIntelGateway

def run_integration_test():
    print("="*60)
    print("COMPREHENSIVE AV ENGINE: END-TO-END VERIFICATION")
    print("="*60)
    
    orchestrator = AVOrchestrator()
    
    # 1. Simulate a malicious payload
    # - High Entropy (Random bytes mixed with specific strings)
    # - Contains a YARA signature (b"WannaDecryptor")
    # - Has a hash matching our mock Threat Intel database
    
    import random
    high_entropy_bytes = bytearray(random.getrandbits(8) for _ in range(10000))
    mock_malicious_bytes = high_entropy_bytes + b"WannaDecryptor.wnry" * 50
    
    # Inject this payload's dynamic hash into the known malicious list for the test
    import hashlib
    dynamic_hash = hashlib.sha256(mock_malicious_bytes).hexdigest()
    ThreatIntelGateway._known_malicious_hashes.append(dynamic_hash)
    
    print("\n[Phase 1] Dropping suspicious executable onto simulated endpoint...")
    
    # 2. Run the orchestrator
    print("\n[Phase 2] Orchestrator Correlation")
    ocsf_finding = orchestrator.scan_file("C:\\Users\\admin\\Downloads\\invoice_urgent.exe", mock_malicious_bytes, "10.0.0.50")
    
    # 3. Verify the output
    print("\n[Phase 3] Verification")
    assert ocsf_finding is not None, "AV Failed to detect the mock malware!"
    assert ocsf_finding["severity"] == "Critical", f"AV did not correctly correlate all 3 layers to reach Critical severity. Result: {json.dumps(ocsf_finding)}"
    
    print("\n--- Final OCSF Class 1001 Payload ---")
    print(json.dumps(ocsf_finding, indent=2))
    
    print("\n" + "="*60)
    print("ALL AV COMPREHENSIVE ENGINE TESTS PASSED SUCCESSFULLY.")
    print("="*60)

if __name__ == "__main__":
    run_integration_test()
