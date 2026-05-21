import uuid
from datetime import datetime, timezone

class DynamicPlaybookSynthesizer:
    """
    Simulates the cognitive LLM engine that ingests an OCSF alert and
    dynamically constructs a CACAO DAG playbook in memory.
    """
    
    def synthesize_playbook(self, alert: dict) -> dict:
        print("[AI Synthesizer] Analyzing incoming OCSF context...")
        class_id = alert.get("class_id")
        
        # Base DAG structure
        playbook = {
            "type": "playbook",
            "id": f"playbook--{uuid.uuid4()}",
            "name": "Dynamic Mitigation Playbook",
            "created": datetime.now(timezone.utc).isoformat(),
            "workflow": {}
        }
        
        if class_id == 1001:  # Malware Finding
            print("[AI Synthesizer] Context: Malware. Assembling isolation and forensics DAG.")
            playbook["name"] = "Dynamic Malware Containment"
            playbook["workflow"] = self._build_malware_dag(alert)
            
        elif class_id == 2002:  # Vulnerability Finding
            print("[AI Synthesizer] Context: Vulnerability. Assembling patching and rollback DAG.")
            playbook["name"] = "Dynamic Vulnerability Remediation"
            playbook["workflow"] = self._build_vulnerability_dag(alert)
            
        else:
            print(f"[AI Synthesizer] Context Unknown (Class {class_id}). Assembling generic triage DAG.")
            playbook["name"] = "Generic Triage"
            playbook["workflow"] = {
                "step--log": {
                    "type": "action",
                    "target_service": "TICKETING_CORE",
                    "command": "ticket_update --note 'Unknown event ingested.'",
                    "on_completion": "end"
                }
            }
            
        return playbook

    def _build_malware_dag(self, alert: dict) -> dict:
        """Dynamically builds a DAG for malware containment."""
        file_path = alert.get("file_path", "unknown")
        return {
            "step--verify-entropy": {
                "type": "action",
                "target_service": "ANALYSIS_ENGINE",
                "command": f"verify_entropy --file {file_path}",
                "on_completion": "step--evaluate-risk"
            },
            "step--evaluate-risk": {
                "type": "switch",
                "switch_variable": "$.event.severity", # Will be resolved at runtime
                "cases": {
                    "Critical": "step--isolate-host",
                    "default": "step--quarantine-file"
                }
            },
            "step--quarantine-file": {
                "type": "action",
                "target_service": "ANTIVIRUS_CORE",
                "command": f"agent_control --quarantine --target {file_path}",
                "on_completion": "end"
            },
            "step--isolate-host": {
                "type": "action",
                "target_service": "ANTIVIRUS_CORE",
                "command": "agent_control --isolate --host_ip $.event.src_endpoint_ip",
                "on_completion": "end"
            }
        }

    def _build_vulnerability_dag(self, alert: dict) -> dict:
        """Dynamically builds a DAG for vulnerability patching."""
        cve = alert.get("vulnerability", {}).get("cve_id", "UNKNOWN")
        return {
            "step--evaluate-patch-availability": {
                "type": "action",
                "target_service": "VULN_ENGINE",
                "command": f"check_patch --cve {cve}",
                "on_completion": "step--deploy-patch"
            },
            "step--deploy-patch": {
                "type": "action",
                "target_service": "VULN_ENGINE",
                "command": f"deploy_patch --cve {cve} --monitor 300s", # 300s safe-rollback
                "on_completion": "end"
            }
        }

class PlaybookTranslator:
    """
    Translates machine-readable CACAO DAG JSON playbooks into human-readable
    Markdown for BlueTeam analysts to review.
    """
    @staticmethod
    def to_markdown(playbook: dict, alert_context: dict) -> str:
        md = []
        md.append(f"# 🛡️ BlueTeam Playbook: {playbook.get('name', 'Unknown')}")
        md.append(f"**Playbook ID:** `{playbook.get('id')}`")
        md.append(f"**Generated:** {playbook.get('created')}\n")
        
        md.append("## 🚨 Threat Context")
        md.append(f"- **Trigger:** OCSF Class ID {alert_context.get('class_id')}")
        if "src_endpoint_ip" in alert_context:
            md.append(f"- **Target IP:** `{alert_context.get('src_endpoint_ip')}`")
        if "file_path" in alert_context:
            md.append(f"- **Target File:** `{alert_context.get('file_path')}`")
        if "vulnerability" in alert_context:
            md.append(f"- **CVE:** `{alert_context.get('vulnerability', {}).get('cve_id')}`")
            
        md.append("\n## ⚙️ Execution Flow (DAG Steps)")
        
        workflow = playbook.get("workflow", {})
        if not workflow:
            md.append("*No execution steps defined.*")
            return "\n".join(md)
            
        step_num = 1
        current_step = list(workflow.keys())[0] # Very simplified DAG traversal for readability
        
        while current_step and current_step != "end":
            step_data = workflow.get(current_step)
            if not step_data:
                break
                
            md.append(f"### Step {step_num}: `{current_step}`")
            step_type = step_data.get("type")
            
            if step_type == "action":
                md.append(f"- **Action Required:** Execute command on `{step_data.get('target_service')}`")
                md.append(f"- **Command:** `{step_data.get('command')}`")
                current_step = step_data.get("on_completion", "end")
                if current_step != "end":
                    md.append(f"- **Next Step:** Routes to `{current_step}`")
                    
            elif step_type == "switch":
                md.append(f"- **Decision Logic:** Evaluate variable `{step_data.get('switch_variable')}`")
                md.append("- **Routing Cases:**")
                for case_val, next_node in step_data.get("cases", {}).items():
                    md.append(f"  - If **{case_val}** ➔ Go to `{next_node}`")
                # Simplified traversal: arbitrarily pick a branch to continue printing or just break 
                # (For a true Markdown DAG, we'd loop through all nodes, not just follow one path).
                current_step = None # End simple traversal to prevent looping, in a real translator we'd print all nodes.
                md.append("\n*(Execution branches dynamically from here based on telemetry)*")
                
            step_num += 1

        md.append("\n---")
        md.append("*This playbook was dynamically synthesized by the Cognitive SOAR Engine.*")
        return "\n".join(md)

if __name__ == "__main__":
    synthesizer = DynamicPlaybookSynthesizer()
    translator = PlaybookTranslator()
    
    # Mock Malware Alert
    mock_malware_alert = {
        "class_id": 1001,
        "severity": "Critical",
        "file_path": "C:\\Windows\\Temp\\payload.exe",
        "src_endpoint_ip": "10.0.0.50"
    }
    
    dag = synthesizer.synthesize_playbook(mock_malware_alert)
    readable_md = translator.to_markdown(dag, mock_malware_alert)
    
    print("\n\n")
    print(readable_md)
