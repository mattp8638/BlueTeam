import datetime
from src.av_core.shannon_entropy import ShannonEntropyCalculator
from src.av_core.yara_scanner import YaraScanner
from src.av_core.threat_intel_gateway import ThreatIntelGateway

class AVOrchestrator:
    """
    The Core Antivirus Daemon.
    Takes a suspicious file, runs it simultaneously through the Heuristics,
    Signature, and Reputation engines, and correlates the results.
    Generates standard OCSF Class 1001 payloads.
    """
    
    def __init__(self):
        self.yara_scanner = YaraScanner()

    def scan_file(self, file_path: str, raw_bytes: bytes, device_ip: str) -> dict:
        print(f"\n[AV Orchestrator] Intercepted suspicious file: {file_path}")
        print(" -> Dispatching to multi-layered detection engines...")
        
        # 1. Run all 3 detection layers
        entropy_result = ShannonEntropyCalculator.analyze(file_path, raw_bytes)
        yara_result = self.yara_scanner.analyze(file_path, raw_bytes)
        reputation_result = ThreatIntelGateway.analyze(file_path, raw_bytes)
        
        # 2. Correlate Results
        malicious_hits = 0
        if entropy_result["is_malicious"]: malicious_hits += 1
        if yara_result["is_malicious"]: malicious_hits += 1
        if reputation_result["is_malicious"]: malicious_hits += 1
        
        if malicious_hits == 0:
            print("\n[AV Orchestrator] File is benign. Allowing execution.")
            return None
            
        print(f"\n[AV Orchestrator] CRITICAL: File flagged by {malicious_hits}/3 detection layers!")
        
        # 3. Format OCSF Class 1001 (Malware Finding) Payload
        severity = "High" if malicious_hits < 3 else "Critical"
        
        ocsf_payload = {
            "class_id": 1001,
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "severity": severity,
            "device": {"ip": device_ip},
            "malware": {
                "name": yara_result.get("matched_rules", ["Unknown"])[0] if yara_result["matched_rules"] else "Unknown Obfuscated Payload",
                "path": file_path,
                "hashes": [{"algorithm": "SHA-256", "value": reputation_result["hash"]}]
            },
            "enrichments": [
                {"name": "Detection Layer: Heuristics", "value": entropy_result["details"]},
                {"name": "Detection Layer: Signatures", "value": yara_result["details"]},
                {"name": "Detection Layer: Reputation", "value": reputation_result["details"]}
            ]
        }
        
        return ocsf_payload
