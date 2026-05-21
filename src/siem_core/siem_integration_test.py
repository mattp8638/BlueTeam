import json
from src.siem_core.ingestion_api import MockFastAPIClient
from src.siem_core.ingestion_api import monitor, datalake

def run_integration_test():
    print("="*60)
    print("COMPREHENSIVE SIEM ENGINE: END-TO-END VERIFICATION")
    print("="*60)
    
    client = MockFastAPIClient()
    
    # --- Test 1: Standard Structured OCSF Ingestion ---
    print("\n[Phase 1] Valid OCSF JSON Ingestion")
    valid_payload = json.dumps({
        "time": "2026-05-21T10:00:00Z",
        "class_id": 1001, # Malware
        "severity": "High",
        "file_name": "malware.exe"
    })
    res = client.post({"Content-Type": "application/json"}, valid_payload)
    assert res.get("status") == "Success"
    
    # --- Test 2: Unstructured Zero-Shot LLM Parsing ---
    print("\n[Phase 2] Unstructured Legacy Syslog Ingestion (Zero-Shot AI Parsing)")
    messy_syslog = "<14>Jan 12 10:15:33 firewall01 auth_daemon: User ADMIN failed login from 192.168.1.55 via SSH"
    res = client.post({"Content-Type": "text/plain"}, messy_syslog)
    assert res.get("status") == "Success"
    
    # --- Test 3: Data Lake Investigation (BlueTeam Query) ---
    print("\n[Phase 3] Data Lake Investigation Search")
    print("Querying for MITRE Tag 'T1110' (Brute Force)...")
    results = datalake.investigate({"tag": "T1110"})
    
    # We expect 1 result (The unstructured syslog that the AI parsed into 3002, 
    # which the Detection Engine then scanned and tagged as T1110).
    assert len(results) == 1, "Failed to find the AI-parsed and automatically-tagged event!"
    print(f"Verified Event Tagging: {results[0]['enrichment']['mitre_tags']}")
    
    # --- Test 4: Pipeline Health SLA ---
    print("\n[Phase 4] Pipeline Health Metrics")
    monitor.print_report()
    
    print("\n" + "="*60)
    print("ALL COMPREHENSIVE SIEM ENGINE TESTS PASSED SUCCESSFULLY.")
    print("="*60)

if __name__ == "__main__":
    run_integration_test()
