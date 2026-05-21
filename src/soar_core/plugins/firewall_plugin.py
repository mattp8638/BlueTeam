import json
import time
from src.soar_core.plugins.base_plugin import BaseActionPlugin

class FirewallPlugin(BaseActionPlugin):
    """
    Simulates integration with a Network Firewall API.
    Handles actions like blocking IP addresses or domains.
    """
    
    @property
    def plugin_name(self) -> str:
        return "NETWORK_FIREWALL"

    def execute_action(self, command: str, parameters: dict) -> dict:
        print(f"[{self.plugin_name}] Initiating API request for '{command}'...")
        time.sleep(1.0) # Simulate API latency
        
        if "block_ip" in command:
            target_ip = parameters.get("ip", "UNKNOWN_IP")
            payload = {
                "action": "block_inbound_outbound",
                "target_ip": target_ip,
                "rule_name": "SOAR_DYNAMIC_BLOCK"
            }
            print(f"[{self.plugin_name}] Pushing rule to Firewall API:\n  {json.dumps(payload)}")
            return {"status": "SUCCESS", "message": f"IP {target_ip} blocked at the perimeter."}
            
        else:
            return {"status": "ERROR", "message": f"Unsupported Firewall command: {command}"}
