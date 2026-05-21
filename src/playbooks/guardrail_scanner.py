import json
import re

class PlaybookGuardrailScanner:
    """
    Static analysis scanner that intercepts dynamically generated playbooks
    to prevent AI hallucination or indirect prompt injections (OWASP LLM01).
    """
    
    def __init__(self):
        # List of strictly prohibited strings/commands in any dynamic payload
        self.forbidden_signatures = [
            r"rm\s+-rf",
            r"del\s+/f\s+/s\s+/q",
            r"curl\s+",
            r"wget\s+",
            r"netcat",
            r"nc\s+",
            r">\s*/dev/null",
            r"chmod\s+777",
            r"mkfs",
            r"drop\s+table"
        ]

    def scan_playbook(self, playbook: dict) -> bool:
        """
        Scans all commands within the playbook DAG. 
        Returns True if safe, False if malicious/hallucinated payload detected.
        """
        print("[Guardrail Scanner] Initiating Static Analysis of Dynamic Playbook...")
        
        workflow = playbook.get("workflow", {})
        
        for step_id, step_data in workflow.items():
            if step_data.get("type") == "action":
                command = step_data.get("command", "")
                
                # Check against forbidden signatures
                for sig in self.forbidden_signatures:
                    if re.search(sig, command, re.IGNORECASE):
                        print(f"\n[!!!] GUARDRAIL VIOLATION DETECTED [!!!]")
                        print(f" -> Step: {step_id}")
                        print(f" -> Unauthorized Signature Matched: {sig}")
                        print(f" -> Raw Payload: {command}")
                        print("[!!!] Playbook Execution Terminated.")
                        return False
                        
        print("[Guardrail Scanner] Analysis Complete. Payload is SAFE.")
        return True

if __name__ == "__main__":
    scanner = PlaybookGuardrailScanner()
    
    # Safe Playbook Test
    safe_playbook = {
        "workflow": {
            "step1": {
                "type": "action",
                "command": "agent_control --isolate --host_ip 10.0.0.5"
            }
        }
    }
    
    # Malicious Playbook Test (Simulating an AI hallucination or Prompt Injection)
    malicious_playbook = {
        "workflow": {
            "step1": {
                "type": "action",
                "command": "agent_control --isolate; rm -rf /etc/*"
            }
        }
    }
    
    print("\n--- Scanning Safe Payload ---")
    scanner.scan_playbook(safe_playbook)
    
    print("\n--- Scanning Malicious Payload ---")
    scanner.scan_playbook(malicious_playbook)
