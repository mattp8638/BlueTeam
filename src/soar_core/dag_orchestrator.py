from concurrent.futures import as_completed
from src.playbooks.dynamic_playbook_generator import DynamicPlaybookSynthesizer, PlaybookTranslator
from src.playbooks.guardrail_scanner import PlaybookGuardrailScanner
from src.soar_core.micro_runner import MicroRunnerPool
from src.ir_core.merkle_ledger import MerkleLedger

class DagOrchestrator:
    """
    The Core SOAR Engine. 
    Now features Parallel DAG Traversal and Stateful Ledger Integration.
    """
    
    def __init__(self):
        self.synthesizer = DynamicPlaybookSynthesizer()
        self.guardrail = PlaybookGuardrailScanner()
        self.runner_pool = MicroRunnerPool(max_workers=10)

    def trigger_incident(self, ocsf_event: dict, ticket_id: str):
        print(f"\n[Orchestrator] Incident Triggered for Ticket {ticket_id}")
        
        # 1. Synthesize Playbook
        playbook = self.synthesizer.synthesize_playbook(ocsf_event)
        
        # Log state to IR Ledger
        MerkleLedger.append_transaction(ticket_id, "SOAR_PLAYBOOK_GENERATED", {"playbook_name": playbook.get("name")})
        
        # 2. Guardrail Scan
        is_safe = self.guardrail.scan_playbook(playbook)
        if not is_safe:
            print("[Orchestrator] Playbook blocked by Guardrails. Terminating.")
            MerkleLedger.append_transaction(ticket_id, "SOAR_PLAYBOOK_BLOCKED", {"reason": "Guardrail Violation"})
            return
            
        # 3. Parallel DAG Traversal
        workflow = playbook.get("workflow", {})
        if not workflow:
            return
            
        print("\n[Orchestrator] Initiating Parallel DAG Traversal...")
        MerkleLedger.append_transaction(ticket_id, "SOAR_EXECUTION_STARTED", {"playbook_id": playbook.get("id")})
        
        # For simplicity in this mock, we will dispatch the first node, and if it's a switch,
        # we will simulate it branching into multiple parallel actions to demonstrate the capability.
        current_step = list(workflow.keys())[0]
        self._traverse_graph(workflow, current_step, ticket_id, ocsf_event)
        
        print("\n[Orchestrator] Playbook execution finished.")
        MerkleLedger.append_transaction(ticket_id, "SOAR_EXECUTION_COMPLETED", {"playbook_id": playbook.get("id")})

    def _traverse_graph(self, workflow: dict, start_node: str, ticket_id: str, ocsf_event: dict):
        """Recursively traverses the DAG, supporting parallel branch execution."""
        nodes_to_process = [start_node]
        
        while nodes_to_process:
            futures = []
            next_nodes = []
            
            # Dispatch all independent nodes in the current layer simultaneously
            for node_id in nodes_to_process:
                step_data = workflow.get(node_id)
                if not step_data or node_id == "end":
                    continue
                    
                step_type = step_data.get("type")
                
                if step_type == "action":
                    # Record node start
                    MerkleLedger.append_transaction(ticket_id, "SOAR_NODE_STARTED", {"node": node_id})
                    
                    # Dispatch to ThreadPool (Non-blocking)
                    future = self.runner_pool.execute_node(node_id, step_data, ticket_id)
                    futures.append(future)
                    
                elif step_type == "switch":
                    # Evaluate logic
                    print(f"[Orchestrator] Evaluating switch node {node_id}...")
                    
                    # Simulated "Parallel" branching: For this demo, if it's a switch, we will
                    # trigger BOTH cases simultaneously to demonstrate the Micro-Runner's concurrent threading.
                    # (In a real scenario, you only follow the matching path, or use a "parallel" node type).
                    cases = step_data.get("cases", {})
                    for case_val, branch_node in cases.items():
                        if branch_node != "end":
                            next_nodes.append(branch_node)
                            
            # Wait for the current layer of parallel futures to complete
            for future in as_completed(futures):
                result = future.result()
                
                if result["status"] == "SUCCESS":
                    MerkleLedger.append_transaction(ticket_id, "SOAR_NODE_SUCCESS", {"node": result["step"], "message": result.get("message")})
                    if result["next"] != "end":
                        next_nodes.append(result["next"])
                else:
                    MerkleLedger.append_transaction(ticket_id, "SOAR_NODE_FAILED", {"node": result["step"], "reason": result.get("reason")})
                    
            # Move to the next layer of the graph
            nodes_to_process = list(set(next_nodes)) # Deduplicate next nodes
