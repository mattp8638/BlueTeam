import json
import re
import requests
import os
from datetime import datetime, timezone

class ZeroShotParser:
    """
    Simulates a Small Language Model (SLM) performing zero-shot parsing.
    Maps completely unrecognized, proprietary log strings into the strict OCSF schema.
    """
    
    # Allow URL to be configurable via environment variable
    LLM_API_URL = os.environ.get("LLM_API_URL", "http://localhost:11434/api/generate")

    @classmethod
    def _call_llm(cls, prompt: str) -> str:
        """Helper method to invoke the configured local/remote LLM."""
        try:
            response = requests.post(
                cls.LLM_API_URL,
                json={
                    "model": "blueteam-llm", # Assumed model name
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=5
            )
            response.raise_for_status()
            return response.json().get("response", "{}")
        except requests.exceptions.RequestException as e:
            # Fallback to simulation if AI is offline
            return None

    @classmethod
    def parse_unstructured_log(cls, raw_log: str) -> dict:
        """
        Queries the local fine-tuned 8B model to extract entities.
        """
        print("\n[Zero-Shot SLM] Analyzing unstructured proprietary log...")
        
        # 1. Attempt to use the real AI Model
        prompt = f"""
        Act as an expert cybersecurity parser. Extract entities from the following syslog and format it as a valid OCSF JSON payload.
        Only output the JSON.
        Log: {raw_log}
        """

        ai_response = cls._call_llm(prompt)
        if ai_response:
            try:
                print("[Zero-Shot SLM] Successfully mapped raw log using LLM.")
                return json.loads(ai_response)
            except json.JSONDecodeError:
                print("[Zero-Shot SLM] Warning: LLM returned invalid JSON. Falling back to rules.")

        # 2. Simulated Fallback extraction logic
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
