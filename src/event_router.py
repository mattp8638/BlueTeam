from src.siem_core.zero_shot_parser import ZeroShotParser
from src.siem_core.detection_engine import DetectionEngine
from src.siem_core.clickhouse_client import ClickHouseDataLakeMock

from src.av_core.av_orchestrator import AVOrchestrator
from src.vuln_core.vuln_scanner import VulnScanner
from src.vuln_core.asset_inventory import AssetInventory
from src.vuln_core.remediation_engine import RemediationEngine

from src.ir_core.ingestion_clustering import TokenClusteringEngine
from src.soar_core.dag_orchestrator import DagOrchestrator

# Import RedTeam components
try:
    from src.redteam_core.attack_orchestrator import AttackOrchestrator
    from src.redteam_core.blue_team_integration import BlueTeamIntegration
    REDTEAM_AVAILABLE = True
except ImportError:
    REDTEAM_AVAILABLE = False

class NerveCenter:
    """
    The Central Nervous System of the Unified Cybersecurity Platform.
    Acts as the main message bus, wiring all 5 backend engines together.
    
    Now with AI-RedTeaming integration for collaborative purple teaming exercises.
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
        
        # 3. Initialize RedTeam Integration (if available)
        self.redteam_orchestrator = None
        self.blue_team_integration = None
        
        if REDTEAM_AVAILABLE:
            self._initialize_redteam_integration()

    def _initialize_redteam_integration(self):
        """Initialize RedTeam integration components"""
        try:
            self.redteam_orchestrator = AttackOrchestrator(blue_team_integration=self)
            self.blue_team_integration = BlueTeamIntegration(nerve_center=self)
            
            # Connect components
            self.redteam_orchestrator.blue_team = self.blue_team_integration
            
            print("[Nerve Center] AI-RedTeaming integration initialized")
        except Exception as e:
            print(f"[Nerve Center] Warning: Failed to initialize RedTeam integration: {e}")
            self.redteam_orchestrator = None
            self.blue_team_integration = None

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
            
        elif source_type == "REDTEAM_NOTIFICATION":
            # Handle RedTeam notification events
            self._handle_redteam_notification(raw_data, device_context)
            return
            
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
    
    def _handle_redteam_notification(self, raw_data: dict, device_context: dict = None):
        """
        Handle RedTeam notification events.
        
        This method processes notifications from the AI-RedTeaming platform
        and routes them appropriately for detection validation.
        """
        print(f"\n[Nerve Center] Processing RedTeam notification")
        
        # Extract information from the notification
        attack_id = raw_data.get('redteam_operation', 'unknown')
        module_name = raw_data.get('redteam_module', 'unknown')
        action = raw_data.get('redteam_action', 'unknown')
        target = raw_data.get('src_endpoint_ip', 'unknown')
        
        print(f"[Nerve Center] RedTeam Operation: {attack_id}")
        print(f"[Nerve Center] Module: {module_name}")
        print(f"[Nerve Center] Action: {action}")
        print(f"[Nerve Center] Target: {target}")
        
        # Check if this is a known RedTeam activity
        if self.blue_team_integration:
            # Record the detection (since it came through the SIEM)
            detection_event = self.blue_team_integration.record_detection_event(
                attack_id=attack_id,
                detection_type="SIEM",
                details={
                    'module': module_name,
                    'action': action,
                    'target': target,
                    'source': 'REDTEAM_NOTIFICATION'
                },
                severity=raw_data.get('severity', 'Medium'),
                confidence=0.9
            )
            
            print(f"[Nerve Center] Detection recorded: {detection_event.event_id}")
        
        # Also process as a regular SIEM event for correlation
        # This allows the BlueTeam to detect and respond to RedTeam activities
        ocsf_payload = {
            'class_id': 1001,  # Malware Finding (for testing)
            'severity': raw_data.get('severity', 'High'),
            'activity_name': f'RedTeam Activity: {action}',
            'src_endpoint_ip': target,
            'file_path': f'/redteam/{module_name}',
            'redteam_operation': attack_id,
            'redteam_module': module_name,
            'redteam_action': action,
            'timestamp': raw_data.get('timestamp', datetime.now(timezone.utc).isoformat())
        }
        
        # Route through normal SIEM processing
        self.siem_datalake.batch_insert([ocsf_payload])
        
        # Trigger SOAR if high severity
        if ocsf_payload.get("severity") in ["High", "Critical"]:
            print("\n[Nerve Center] High Severity RedTeam Event. Routing to SOAR Engine...")
            ticket_id = TokenClusteringEngine._create_root_ticket(ocsf_payload)
            self.soar_engine.trigger_incident(ocsf_payload, ticket_id)
    
    def get_redteam_orchestrator(self):
        """Get the RedTeam orchestrator instance"""
        return self.redteam_orchestrator
    
    def get_blue_team_integration(self):
        """Get the BlueTeam integration instance"""
        return self.blue_team_integration
    
    def shutdown(self):
        print("\n[Nerve Center] Shutting down thread pools...")
        self.soar_engine.runner_pool.shutdown()
        
        # Shutdown RedTeam components if available
        if self.redteam_orchestrator:
            print("[Nerve Center] Shutting down RedTeam components...")
            # Additional cleanup if needed
