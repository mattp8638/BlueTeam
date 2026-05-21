import json
from datetime import datetime, timezone

class ZeroShotParser:
    """
    Simulates a Small Language Model (SLM) performing zero-shot parsing.
    Maps completely unrecognized, proprietary log strings into the strict OCSF schema.
    """
    
    @classmethod
    def parse_unstructured_log(cls, raw_log: str) -> dict:
        """
        MOCK SLM INFERENCE
        In production, this queries the local fine-tuned 8B model to extract entities.
        """
        print("\n[Zero-Shot SLM] Analyzing unstructured proprietary log...")
        
        # Simulated extraction logic
        ocsf_event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "class_id": 0,  # Unknown base
            "activity_id": 0,
            "raw_data": raw_log
        }
        
        lower_log = raw_log.lower()
        
        # Simulated AI reasoning: Entity Extraction
        if "login" in lower_log or "auth" in lower_log:
            ocsf_event["class_id"] = 3002 # Authentication
            if "failed" in lower_log or "denied" in lower_log:
                ocsf_event["activity_id"] = 2 # Logon Failed
                ocsf_event["status"] = "Failure"
            else:
                ocsf_event["activity_id"] = 1 # Logon
                ocsf_event["status"] = "Success"
                
            # Naive IP extraction for mock
            import re
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw_log)
            if ip_match:
                ocsf_event["src_endpoint"] = {"ip": ip_match.group(0)}
                
            user_match = re.search(r'user[:\s]+(\w+)', lower_log)
            if user_match:
                ocsf_event["user"] = {"name": user_match.group(1)}
                
            print("[Zero-Shot SLM] Successfully mapped raw log to OCSF Class 3002 (Authentication).")
            
        elif "malware" in lower_log or "virus" in lower_log:
            ocsf_event["class_id"] = 1001 # Malware Finding
            ocsf_event["severity"] = "High"
            print("[Zero-Shot SLM] Successfully mapped raw log to OCSF Class 1001 (Malware Finding).")
            
        else:
            ocsf_event["class_id"] = 9999 # Unmapped
            print("[Zero-Shot SLM] Unable to confidently map event. Storing as raw.")

        return ocsf_event

if __name__ == "__main__":
    parser = ZeroShotParser()
    
    # Test unstructured legacy syslog
    messy_log = "<14>Jan 12 10:15:33 firewall01 auth_daemon: User ADMIN failed login from 192.168.1.55 via SSH"
    
    parsed_ocsf = parser.parse_unstructured_log(messy_log)
    print("\n--- Translated OCSF Payload ---")
    print(json.dumps(parsed_ocsf, indent=2))
