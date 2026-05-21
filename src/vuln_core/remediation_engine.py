import json
from src.soar_core.dag_orchestrator import DagOrchestrator
from src.ir_core.ingestion_clustering import TokenClusteringEngine

class RemediationEngine:
    """
    Analyzes vulnerability findings and determines the best course of action.
    If complex, generates BlueTeam Markdown guidance.
    If simple/auto-patchable, generates an OCSF payload and hands off directly to the SOAR Engine.
    """
    
    def __init__(self):
        # We hook directly into the SOAR engine to trigger automated patches
        self.soar_engine = DagOrchestrator()

    def process_finding(self, ocsf_finding: dict):
        vulnerabilities = ocsf_finding.get("vulnerabilities", [])
        if not vulnerabilities:
            return
            
        cve_id = vulnerabilities[0].get("cve", {}).get("uid", "UNKNOWN")
        device_ip = ocsf_finding.get("device", {}).get("ip")
        
        print(f"\n[Vuln Remediation Engine] Analyzing finding: {cve_id} on {device_ip}")
        
        # Analyze specific CVEs
        if cve_id == "CVE-2021-34527":
            # PrintNightmare is a known registry/service fix. We can auto-patch this!
            print(f"[Vuln Remediation Engine] Classification: AUTO-PATCHABLE")
            self._trigger_automated_patch(ocsf_finding, "Disable Print Spooler and Fix Registry")
            
        elif cve_id == "CVE-2021-44228":
            # Log4Shell often requires deep application updates. Manual guidance needed.
            print(f"[Vuln Remediation Engine] Classification: MANUAL GUIDANCE REQUIRED")
            self._generate_guidance(ocsf_finding)
            
        else:
            print(f"[Vuln Remediation Engine] Classification: UNKNOWN. Escalating to analyst.")

    def _trigger_automated_patch(self, finding: dict, patch_intent: str):
        """Constructs an Incident payload and hands it directly to SOAR."""
        print(f"[Vuln Remediation Engine] Synthesizing Incident payload to trigger SOAR...")
        
        # Convert Vulnerability finding into a SOAR-actionable Incident
        incident_payload = {
            "class_id": 2002,
            "severity": finding.get("severity"),
            "event": {
                "src_endpoint_ip": finding.get("device", {}).get("ip"),
                "intent": patch_intent,
                "evidence": finding.get("enrichments", [])
            }
        }
        
        # Create an IR Ticket for tracking the SOAR action
        ticket_id = TokenClusteringEngine._create_root_ticket(incident_payload)
        
        print(f"[Vuln Remediation Engine] Handoff successful. Triggering SOAR for Ticket {ticket_id}")
        self.soar_engine.trigger_incident(incident_payload, ticket_id)

    def _generate_guidance(self, finding: dict):
        """Generates human-readable Markdown for complex remediations."""
        evidence = finding.get("enrichments", [])
        md = f"## Remediation Guidance: {finding['vulnerabilities'][0]['cve']['uid']}\n"
        md += "> [!WARNING]\n> This vulnerability requires application-level architectural changes. Automated patching is disabled.\n\n"
        md += "### Evidence Found\n"
        for ev in evidence:
            md += f"- **{ev['name']}**: `{ev['value']}`\n"
        md += "\n### Required Steps\n1. Update the dependency layer.\n2. Restart the application cluster."
        
        print("\n" + "="*50)
        print("[BlueTeam Dashboard] Generated Remediation Guidance:")
        print(md)
        print("="*50 + "\n")
