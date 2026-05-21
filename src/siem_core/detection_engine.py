import re

class DetectionEngine:
    """
    Real-Time Threat Detection Engine.
    Filters, tags, and investigates incoming OCSF telemetry against Sigma-style rules
    before they are committed to the data lake.
    """
    
    def __init__(self):
        # Local repository of Sigma-style detection rules
        self.rules = [
            {
                "rule_id": "SIG-001",
                "title": "Brute Force Suspected",
                "condition": lambda event: event.get("class_id") == 3002 and event.get("status") == "Failure",
                "tags": ["T1110", "Credential Access", "Brute Force"],
                "severity": "Medium",
                "action": "Alert"
            },
            {
                "rule_id": "SIG-002",
                "title": "Critical Malware Detection",
                "condition": lambda event: event.get("class_id") == 1001,
                "tags": ["T1204", "Execution", "Malware"],
                "severity": "Critical",
                "action": "Route_To_SOAR"
            }
        ]

    def scan_event(self, ocsf_event: dict) -> dict:
        """
        Scans an incoming OCSF event against all rules.
        Applies filtering, MITRE ATT&CK tagging, and alerting metadata.
        """
        matched_rules = []
        tags = set()
        highest_severity = "Low"
        
        for rule in self.rules:
            try:
                if rule["condition"](ocsf_event):
                    matched_rules.append(rule["rule_id"])
                    tags.update(rule["tags"])
                    
                    # Elevate severity if rule demands it
                    if rule["severity"] == "Critical":
                        highest_severity = "Critical"
                    elif rule["severity"] == "High" and highest_severity not in ["Critical"]:
                        highest_severity = "High"
                    elif rule["severity"] == "Medium" and highest_severity in ["Low", "Info"]:
                        highest_severity = "Medium"
                        
            except Exception as e:
                # Malformed event or rule error, skip safely
                continue
                
        # Annotate the event with investigative context
        ocsf_event["enrichment"] = {
            "matched_rules": matched_rules,
            "mitre_tags": list(tags)
        }
        
        if matched_rules:
            ocsf_event["severity"] = highest_severity
            print(f"[Detection Engine] Hit! Rules: {matched_rules} | Tags: {list(tags)} | Sev: {highest_severity}")
            
        return ocsf_event

if __name__ == "__main__":
    engine = DetectionEngine()
    
    # Test scanning an authentication failure
    mock_auth_fail = {
        "class_id": 3002,
        "status": "Failure",
        "user": {"name": "admin"},
        "src_endpoint": {"ip": "10.0.0.5"}
    }
    
    enriched_event = engine.scan_event(mock_auth_fail)
    import json
    print("\n--- Enriched Event ---")
    print(json.dumps(enriched_event, indent=2))
