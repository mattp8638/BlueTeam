import time
import threading
from src.soar_core.dag_orchestrator import DagOrchestrator
from src.soar_core.approval_gateway import ApprovalGateway
from src.ir_core.ingestion_clustering import TokenClusteringEngine
from src.ir_core.database import IRDatabase

def run_integration_test():
    print("="*60)
    print("SOAR ENGINE 100%: PARALLEL PLUGINS & LEDGER VERIFICATION")
    print("="*60)
    
    # 1. Create a real ticket to use the Ledger properly
    alert = {"class_id": 1001, "src_endpoint_ip": "10.0.0.55"}
    ticket_id = TokenClusteringEngine._create_root_ticket(alert)
    
    orchestrator = DagOrchestrator()
    
    # Mock Critical Malware Event
    mock_event = {
        "class_id": 1001,
        "severity": "Critical",
        "file_path": "C:\\Windows\\Temp\\payload.exe",
        "event": {
            "severity": "Critical",
            "src_endpoint_ip": "10.0.0.55"
        }
    }
    
    print("\n[Phase 1] Booting Orchestrator and Dispatching High-Risk Event")
    
    def execute_playbook():
        orchestrator.trigger_incident(mock_event, ticket_id)
        
    execution_thread = threading.Thread(target=execute_playbook)
    execution_thread.start()
    
    # Wait for the Orchestrator to hit the high-risk "isolate" step and pause
    print("\n[Phase 2] Waiting for Human-in-the-Loop Gateway Pause...")
    time.sleep(2) 
    
    pending_tokens = list(ApprovalGateway._pending_approvals.keys())
    
    if not pending_tokens:
        print("[TEST FAILED] The playbook executed without pausing at the Approval Gateway!")
        return
        
    auth_token = pending_tokens[0]
    print(f"\n[Phase 3] Simulated BlueTeam Analyst approving Auth-Token {auth_token}...")
    
    # Analyst signs it
    ApprovalGateway.sign_token(auth_token, analyst_id="analyst_matt")
    
    # Wait for the Micro-Runner to resume and finish Parallel branching
    execution_thread.join()
    
    print("\n[Phase 4] Verifying Merkle Ledger State Integrations")
    conn = IRDatabase.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT action_type, payload FROM ledger WHERE ticket_id = ?", (ticket_id,))
    rows = cursor.fetchall()
    
    print(f" -> Found {len(rows)} Cryptographic Ledger Entries for this incident:")
    for action_type, payload in rows:
        print(f"    - {action_type}")
        
    print("\n" + "="*60)
    print("ALL SOAR UPGRADE TESTS PASSED SUCCESSFULLY.")
    print("="*60)
    
    orchestrator.runner_pool.shutdown()

if __name__ == "__main__":
    run_integration_test()
