import time
import threading
from concurrent.futures import ThreadPoolExecutor
from src.soar_core.approval_gateway import ApprovalGateway

# Import Plugins
from src.soar_core.plugins.edr_plugin import EDRPlugin
from src.soar_core.plugins.firewall_plugin import FirewallPlugin

class MicroRunnerPool:
    """
    Asynchronous Executor utilizing Python Threading.
    Now dispatches commands dynamically through the Plugin Architecture.
    """
    
    def __init__(self, max_workers=5):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Load available plugins
        self.plugins = {
            "ANTIVIRUS_CORE": EDRPlugin(),
            "ANALYSIS_ENGINE": EDRPlugin(), # Reusing EDR plugin for entropy check mock
            "NETWORK_FIREWALL": FirewallPlugin()
        }
        
    def execute_node(self, step_id: str, step_data: dict, ticket_id: str):
        """
        Submits a single DAG node to the thread pool for execution.
        Returns a Future object.
        """
        return self.executor.submit(self._run_task, step_id, step_data, ticket_id)
        
    def _run_task(self, step_id: str, step_data: dict, ticket_id: str):
        command_str = step_data.get("command", "UNKNOWN_CMD")
        target_service = step_data.get("target_service", "UNKNOWN_SVC")
        
        # Parse simplistic command string into command + params for the plugin
        # e.g., "agent_control --isolate --host_ip 10.0.0.50"
        parts = command_str.split(" ")
        base_command = parts[0]
        params = {}
        for i, part in enumerate(parts):
            if part.startswith("--") and i + 1 < len(parts):
                key = part.strip("-")
                val = parts[i+1]
                # Try replacing event variables
                if val.startswith("$.event."):
                    # In a real setup, we pass the event dict to the runner. 
                    # For this mock string parsing, we'll just hardcode the extracted value.
                    val = "10.0.0.50"
                params[key] = val
        
        # 1. Check for High-Risk Actions
        if "isolate" in base_command or "quarantine" in base_command:
            approved = ApprovalGateway.request_approval(step_id, command_str, ticket_id)
            if not approved:
                return {"status": "ABORTED", "step": step_id, "reason": "Approval Denied"}
                
        # 2. Plugin Dispatch
        plugin = self.plugins.get(target_service)
        if not plugin:
            print(f"[Micro-Runner Error] No plugin installed for service: {target_service}")
            return {"status": "ERROR", "step": step_id, "reason": f"Missing Plugin {target_service}"}
            
        print(f"\n[Micro-Runner Thread {threading.get_ident()}] Dispatching task to {plugin.plugin_name}...")
        
        try:
            result = plugin.execute_action(command_str, params)
            print(f"[Micro-Runner Thread {threading.get_ident()}] Result: {result.get('message')}")
            
            return {
                "status": result.get("status"), 
                "step": step_id, 
                "next": step_data.get("on_completion", "end"),
                "message": result.get("message")
            }
        except Exception as e:
            return {"status": "ERROR", "step": step_id, "reason": str(e)}
        
    def shutdown(self):
        self.executor.shutdown(wait=True)
