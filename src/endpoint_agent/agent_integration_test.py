import time
import json
import os
from src.endpoint_agent.agent_daemon import EndpointAgentDaemon

def run_test():
    print("*"*80)
    print("BLUE TEAM AGENT V2.0 INTEGRATION TEST")
    print("*"*80)
    
    agent = EndpointAgentDaemon()
    agent.start_all_services()
    
    print("\n--- Testing SOAR Action Executor (Adhoc Scripting) ---")
    
    payload = json.dumps({
        "action": "execute_adhoc_script",
        "script_type": "python",
        "script_body": "print('Hello from sandboxed adhoc script!')",
        "signature": ""
    })
    
    try:
        agent.action_executor.execute_soar_payload(payload)
    except Exception as e:
        print(f"Test Action Error: {e}")
        
    print("\n--- Testing Vuln Assessor ---")
    try:
        report = agent.vuln_assessor.run_assessment()
        print(f"Risk Score: {report.get('risk_score', 'N/A')}")
    except Exception as e:
        print(f"Test Vuln Assessor Error: {e}")
        
    print("\nShutting down in 3 seconds...")
    time.sleep(3)
    agent.stop_all_services()
    print("Test complete.")

if __name__ == "__main__":
    run_test()
