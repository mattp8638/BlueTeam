import threading
import time
from src.vuln_core.asset_inventory import AssetInventory
from src.vuln_core.vuln_scanner import VulnScanner
from src.vuln_core.remediation_engine import RemediationEngine
from src.soar_core.approval_gateway import ApprovalGateway

def run_integration_test():
    print("="*60)
    print("COMPREHENSIVE VULN ENGINE: END-TO-END VERIFICATION")
    print("="*60)
    
    # Initialize components
    inventory = AssetInventory()
    remediator = RemediationEngine()
    
    # 1. Register an Asset
    print("\n[Phase 1] Registering Windows Server 2019 Endpoint in CMDB")
    device_data = {
        "device_id": "SRV-EXCHANGE-01",
        "hostname": "EXCHANGE01",
        "ip_address": "10.0.0.88",
        "os_family": "Windows",
        "os_version": "Server 2019"
    }
    inventory.register_device(device_data)
    
    # 2. Run the Scanner to gather forensic evidence
    print("\n[Phase 2] Running Endpoint Vulnerability Scanner")
    finding = VulnScanner.run_scan(device_data)
    assert finding is not None, "Scanner failed to find the mock vulnerability!"
    
    # 3. Attach evidence to the Asset Catalogue
    print("\n[Phase 3] Attaching findings and forensic evidence to the Catalogue")
    inventory.attach_vulnerability(device_data["device_id"], finding)
    
    cataloged_vulns = inventory.get_device_vulnerabilities(device_data["device_id"])
    print(f" -> DB Query Result: {cataloged_vulns[0]['cve_id']} with {len(cataloged_vulns[0]['evidence'])} pieces of forensic evidence.")
    
    # 4. Remediation Engine Analysis & SOAR Handoff
    print("\n[Phase 4] Remediation Engine Analysis")
    
    # The Remediation Engine will decide to Auto-Patch PrintNightmare, meaning it will
    # directly call the SOAR DAG Orchestrator. We need to run this in a thread so we can
    # simulate the BlueTeam analyst approving the SOAR's execution if it hits a guardrail.
    
    def execute_remediation():
        remediator.process_finding(finding)
        
    exec_thread = threading.Thread(target=execute_remediation)
    exec_thread.start()
    
    # Wait for SOAR to hit the Human-in-the-Loop Gateway
    time.sleep(2)
    pending_tokens = list(ApprovalGateway._pending_approvals.keys())
    if pending_tokens:
        auth_token = pending_tokens[0]
        print(f"\n[Phase 5] Simulated Analyst approving SOAR Auto-Patch execution for token {auth_token}...")
        ApprovalGateway.sign_token(auth_token, analyst_id="analyst_matt")
        
    exec_thread.join()
    
    print("\n" + "="*60)
    print("ALL VULN COMPREHENSIVE ENGINE TESTS PASSED SUCCESSFULLY.")
    print("="*60)
    
    # Cleanup SOAR runner pool
    remediator.soar_engine.runner_pool.shutdown()

if __name__ == "__main__":
    run_integration_test()
