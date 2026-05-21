from src.siem_core.zero_shot_parser import ZeroShotParser
from src.siem_core.detection_engine import DetectionEngine
from src.siem_core.clickhouse_client import ClickHouseDataLakeMock

from src.av_core.av_orchestrator import AVOrchestrator
from src.vuln_core.vuln_scanner import VulnScanner
from src.vuln_core.asset_inventory import AssetInventory
from src.vuln_core.remediation_engine import RemediationEngine

from src.ir_core.ingestion_clustering import TokenClusteringEngine
from src.soar_core.dag_orchestrator import DagOrchestrator

class NerveCenter:
    """
    The Central Nervous System of the Unified Cybersecurity Platform.
    Acts as the main message bus, wiring all 5 backend engines together.
    """
    
    def __init__(self):
        # 1. Initialize Edge Sensors
        self.siem_parser = ZeroShotParser()
        self.siem_detector = DetectionEngine()
        self.siem_datalake = ClickHouseDataLakeMock()
        
        self.av_engine = AVOrchestrator()
        
        self.vuln_inventory = AssetInventory()
        self.vuln_remediator = RemediationEngine()
        
        # 2. Initialize Core Engines
        self.soar_engine = DagOrchestrator()
        
        # Wire the Vuln Remediator to use our central SOAR engine
        self.vuln_remediator.soar_engine = self.soar_engine

    def route_event(self, source_type: str, raw_data: any, device_context: dict = None):
        """
        The Universal Entrypoint for the entire platform.
        """
        print(f"\n{'='*80}")
        print(f"[Nerve Center] Intercepted new event from source: {source_type}")
        print(f"{'='*80}")
        
        ocsf_payload = None
        
        # Phase 1: Edge Processing & Translation
        if source_type == "SYSLOG":
            # Pass to SIEM for unstructured translation
            parsed = self.siem_parser.parse_unstructured_log(raw_data)
            ocsf_payload = self.siem_detector.scan_event(parsed)
            self.siem_datalake.batch_insert([ocsf_payload])
            
        elif source_type == "FILE_DROP":
            # Pass to AV Engine (Multi-layered Correlation)
            file_path, file_bytes = raw_data
            device_ip = device_context.get("ip_address") if device_context else "UNKNOWN"
            ocsf_payload = self.av_engine.scan_file(file_path, file_bytes, device_ip)
            
            if ocsf_payload:
                self.siem_datalake.batch_insert([ocsf_payload])
            else:
                print("[Nerve Center] AV Engine marked file as benign. Processing halted.")
                return
                
        elif source_type == "ENDPOINT_SCAN":
            # Pass to Vuln Engine (CMDB & Evidence Gathering)
            if not device_context:
                print("[Nerve Center] ERROR: Endpoint scan requires device context.")
                return
                
            self.vuln_inventory.register_device(device_context)
            ocsf_payload = VulnScanner.run_scan(device_context)
            
            if ocsf_payload:
                self.vuln_inventory.attach_vulnerability(device_context["device_id"], ocsf_payload)
                # Vuln Engine handles its own Remediation/SOAR handoff logic directly
                self.vuln_remediator.process_finding(ocsf_payload)
            else:
                print("[Nerve Center] Vuln Engine scan returned clean. Processing halted.")
                
            return # Exit early as Vuln handles its own complex IR/SOAR logic internally
            
        else:
            print(f"[Nerve Center] ERROR: Unknown source type {source_type}")
            return
            
        # Phase 2: Core Routing (IR & SOAR)
        if ocsf_payload and ocsf_payload.get("severity") in ["High", "Critical"]:
            print("\n[Nerve Center] High Severity Event Detected. Routing to Incident Response Engine...")
            ticket_id = TokenClusteringEngine._create_root_ticket(ocsf_payload)
            
            print(f"\n[Nerve Center] IR Ticket {ticket_id} created. Routing to SOAR Engine...")
            self.soar_engine.trigger_incident(ocsf_payload, ticket_id)
            
        else:
            print("\n[Nerve Center] Event severity is low. Stored in Data Lake, but no active response triggered.")

    def shutdown(self):
        print("\n[Nerve Center] Shutting down thread pools...")
        self.soar_engine.runner_pool.shutdown()
