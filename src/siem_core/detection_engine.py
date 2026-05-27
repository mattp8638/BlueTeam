import re
import json
from src.siem_core.ai_classifier import LocalAIClassifier

class DetectionEngine:
    """
    Real-Time Threat Detection Engine.
    Filters, tags, and investigates incoming OCSF telemetry against Sigma-style rules
    AND the local HuggingFace AI classification model.
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
        Scans an incoming OCSF event against all static rules and the AI model.
        Applies filtering, MITRE ATT&CK tagging, and alerting metadata.
        """
        matched_rules = []
        tags = set()
        highest_severity = "Low"
        
        # 1. Static Rule Evaluation
        for rule in self.rules:
            try:
                if rule["condition"](ocsf_event):
                    matched_rules.append(rule["rule_id"])
                    tags.update(rule["tags"])
                    
                    if rule["severity"] == "Critical":
                        highest_severity = "Critical"
                    elif rule["severity"] == "High" and highest_severity not in ["Critical"]:
                        highest_severity = "High"
                    elif rule["severity"] == "Medium" and highest_severity in ["Low", "Info"]:
                        highest_severity = "Medium"
                        
            except Exception as e:
                continue
                
        # 2. AI Model Evaluation
        # Convert the event to a string representation for the NLP model
        log_text = json.dumps(ocsf_event)
        ai_result = LocalAIClassifier.classify_log(log_text)

        if ai_result:
            label = ai_result.get("label", "").upper()
            score = ai_result.get("score", 0.0)

            # Assuming the model returns labels like 'MALICIOUS', 'ANOMALY', etc.
            if label in ["MALICIOUS", "ANOMALY", "ATTACK"] and score > 0.85:
                print(f"[Detection Engine] AI Model flagged event! Label: {label} (Confidence: {score:.2f})")
                matched_rules.append(f"AI_MODEL_{label}")
                tags.add("AI_Generated")

                # AI overrides to High severity if it wasn't already Critical
                if highest_severity not in ["Critical", "High"]:
                    highest_severity = "High"

                # Annotate the specific AI score into the event
                if "ai_analysis" not in ocsf_event:
                    ocsf_event["ai_analysis"] = {}
                ocsf_event["ai_analysis"]["classification"] = label
                ocsf_event["ai_analysis"]["confidence"] = score

        # 3. Final Annotation
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
    print("\n--- Enriched Event ---")
    print(json.dumps(enriched_event, indent=2))
