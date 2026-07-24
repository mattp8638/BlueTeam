from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Attack Orchestrator - Central Command for AI-RedTeaming Operations

This module coordinates all offensive security testing activities with
mandatory human verification at every critical decision point.
"""

import uuid
import json
from datetime import datetime, timezone
from enum import Enum

from .verification_gateways.human_approval_gateway import HumanApprovalGateway
from .verification_gateways.safety_validator import SafetyValidator
from .verification_gateways.legal_compliance import LegalComplianceChecker
from .reporting.attack_ledger import AttackLedger
from .reporting.evidence_collector import EvidenceCollector


class AttackPhase(Enum):
    """Standard penetration testing phases"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class AttackStatus(Enum):
    """Status of an attack operation"""
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"
    BLOCKED = "blocked"


class RiskLevel(Enum):
    """Risk classification for attack actions"""
    INFO = "info"           # Information gathering only
    LOW = "low"             # Non-destructive, low impact
    MEDIUM = "medium"       # Potentially disruptive
    HIGH = "high"           # Destructive or high impact
    CRITICAL = "critical"   # Extreme risk, requires executive approval


class AttackOrchestrator:
    """
    Central orchestrator for AI-RedTeaming operations.
    
    Features:
    - Multi-phase attack coordination
    - Mandatory human verification at critical points
    - Safety validation for all actions
    - Legal compliance checking
    - Cryptographic audit trail
    - Integration with BlueTeam for detection validation
    """
    
    def __init__(self, blue_team_integration=None):
        """
        Initialize the Attack Orchestrator.
        
        Args:
            blue_team_integration: Optional integration with AI-BlueTeaming platform
        """
        self.attack_id = None
        self.operation_name = "AI-RedTeam Operation"
        self.current_phase = None
        self.status = AttackStatus.PENDING
        self.target_scope = {}
        self.rules_of_engagement = {}
        
        # Verification gateways
        self.approval_gateway = HumanApprovalGateway()
        self.safety_validator = SafetyValidator()
        self.legal_checker = LegalComplianceChecker()
        
        # Reporting components
        self.attack_ledger = AttackLedger()
        self.evidence_collector = EvidenceCollector()
        
        # Blue team integration
        self.blue_team = blue_team_integration
        
        # Attack modules (lazy loaded)
        self._attack_modules = {}
        
        # Operation state
        self.operation_start = None
        self.operation_end = None
        self.findings = []
        
    def initialize_operation(
        self, 
        operation_name: str, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> str:
        """
        Initialize a new red team operation.
        
        Args:
            operation_name: Human-readable name for the operation
            target_scope: Dictionary defining authorized targets
            rules_of_engagement: ROE including timing, methods, exclusions
            
        Returns:
            attack_id: Unique identifier for the operation
        """
        # Generate unique attack ID
        self.attack_id = f"redteam-op-{uuid.uuid4().hex[:12].upper()}"
        self.operation_name = operation_name
        self.target_scope = target_scope
        self.rules_of_engagement = rules_of_engagement
        self.status = AttackStatus.PENDING
        self.current_phase = None
        self.findings = []
        
        # Log initialization
        self.attack_ledger.log_operation_init(
            self.attack_id, 
            operation_name, 
            target_scope, 
            rules_of_engagement
        )
        
        print(f"\n[Attack Orchestrator] Operation {self.attack_id} initialized: {operation_name}")
        print(f"[Attack Orchestrator] Target Scope: {json.dumps(target_scope, indent=2)}")
        print(f"[Attack Orchestrator] Rules of Engagement: {json.dumps(rules_of_engagement, indent=2)}")
        
        return self.attack_id
    
    def request_operation_approval(self, analyst_id: str, justification: str) -> bool:
        """
        Request human approval to start the operation.
        
        This is the first mandatory verification gateway.
        
        Args:
            analyst_id: ID of the red team analyst requesting approval
            justification: Business justification for the operation
            
        Returns:
            bool: True if approved, False otherwise
        """
        print(f"\n{'='*80}")
        print(f"[VERIFICATION GATEWAY] OPERATION APPROVAL REQUIRED")
        print(f"{'='*80}")
        print(f"Operation: {self.operation_name} ({self.attack_id})")
        print(f"Analyst: {analyst_id}")
        print(f"Justification: {justification}")
        print(f"Target Scope: {json.dumps(self.target_scope, indent=2)}")
        print(f"Rules of Engagement: {json.dumps(self.rules_of_engagement, indent=2)}")
        
        # Perform safety validation
        safety_check = self.safety_validator.validate_operation(
            self.target_scope, 
            self.rules_of_engagement
        )
        
        if not safety_check['valid']:
            print(f"\n[SAFETY VALIDATION FAILED]")
            print(f"Reason: {safety_check['reason']}")
            self.status = AttackStatus.BLOCKED
            self.attack_ledger.log_safety_violation(
                self.attack_id, 
                safety_check['reason']
            )
            return False
        
        # Perform legal compliance check
        legal_check = self.legal_checker.check_operation_compliance(
            self.target_scope, 
            self.rules_of_engagement
        )
        
        if not legal_check['compliant']:
            print(f"\n[LEGAL COMPLIANCE FAILED]")
            print(f"Reason: {legal_check['reason']}")
            self.status = AttackStatus.BLOCKED
            self.attack_ledger.log_compliance_violation(
                self.attack_id, 
                legal_check['reason']
            )
            return False
        
        # Request human approval
        approval_token = self.approval_gateway.request_approval(
            action_type="OPERATION_START",
            operation_id=self.attack_id,
            analyst_id=analyst_id,
            justification=justification,
            scope=self.target_scope,
            roe=self.rules_of_engagement
        )
        
        # Wait for approval (this blocks until approved or timeout)
        approved = self.approval_gateway.wait_for_approval(
            approval_token, 
            timeout=300  # 5 minutes
        )
        
        if approved:
            self.status = AttackStatus.APPROVED
            self.attack_ledger.log_approval(
                self.attack_id, 
                "OPERATION_START",
                analyst_id,
                approval_token
            )
            print(f"\n[Attack Orchestrator] Operation {self.attack_id} APPROVED. Ready to begin.")
        else:
            self.status = AttackStatus.ABORTED
            self.attack_ledger.log_abort(
                self.attack_id, 
                "Approval timeout or denial"
            )
            print(f"\n[Attack Orchestrator] Operation {self.attack_id} ABORTED. Approval not received.")
        
        return approved
    
    def start_operation(self, analyst_id: str) -> bool:
        """
        Start the approved operation.
        
        Args:
            analyst_id: ID of the analyst starting the operation
            
        Returns:
            bool: True if started successfully
        """
        if self.status != AttackStatus.APPROVED:
            print(f"[Attack Orchestrator] Cannot start: Operation not approved. Status: {self.status}")
            return False
        
        self.operation_start = datetime.now(timezone.utc)
        self.status = AttackStatus.RUNNING
        self.current_phase = AttackPhase.RECONNAISSANCE
        
        self.attack_ledger.log_operation_start(
            self.attack_id, 
            analyst_id
        )
        
        print(f"\n[Attack Orchestrator] Operation {self.attack_id} STARTED at {self.operation_start.isoformat()}")
        print(f"[Attack Orchestrator] Current Phase: {self.current_phase.value}")
        
        return True
    
    def transition_to_phase(self, new_phase: AttackPhase, analyst_id: str) -> bool:
        """
        Transition to a new attack phase with verification.
        
        Args:
            new_phase: The phase to transition to
            analyst_id: ID of the analyst requesting the transition
            
        Returns:
            bool: True if transition approved and successful
        """
        if self.status != AttackStatus.RUNNING:
            print(f"[Attack Orchestrator] Cannot transition: Operation not running. Status: {self.status}")
            return False
        
        # Determine risk level of the new phase
        risk_level = self._get_phase_risk_level(new_phase)
        
        print(f"\n{'='*80}")
        print(f"[PHASE TRANSITION] {self.current_phase.value} -> {new_phase.value}")
        print(f"[RISK LEVEL] {risk_level.value}")
        print(f"{'='*80}")
        
        # High and Critical risk phases require explicit approval
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            approval_token = self.approval_gateway.request_approval(
                action_type="PHASE_TRANSITION",
                operation_id=self.attack_id,
                analyst_id=analyst_id,
                details=f"Transition from {self.current_phase.value} to {new_phase.value}",
                risk_level=risk_level.value
            )
            
            approved = self.approval_gateway.wait_for_approval(
                approval_token, 
                timeout=300
            )
            
            if not approved:
                print(f"[Attack Orchestrator] Phase transition DENIED or TIMED OUT")
                self.attack_ledger.log_denial(
                    self.attack_id,
                    "PHASE_TRANSITION",
                    f"{self.current_phase.value} -> {new_phase.value}",
                    analyst_id
                )
                return False
            
            self.attack_ledger.log_approval(
                self.attack_id,
                "PHASE_TRANSITION",
                analyst_id,
                approval_token
            )
        
        # Medium risk phases require safety validation
        elif risk_level == RiskLevel.MEDIUM:
            safety_check = self.safety_validator.validate_phase_transition(
                self.current_phase,
                new_phase,
                self.target_scope
            )
            
            if not safety_check['valid']:
                print(f"[Attack Orchestrator] Phase transition BLOCKED by safety validation")
                print(f"Reason: {safety_check['reason']}")
                self.attack_ledger.log_safety_violation(
                    self.attack_id,
                    safety_check['reason']
                )
                return False
        
        # Log the transition
        self.attack_ledger.log_phase_transition(
            self.attack_id,
            self.current_phase.value,
            new_phase.value,
            analyst_id
        )
        
        self.current_phase = new_phase
        print(f"[Attack Orchestrator] Transitioned to phase: {new_phase.value}")
        
        return True
    
    def execute_attack_module(
        self, 
        module_name: str, 
        module_params: Dict[str, Any],
        analyst_id: str
    ) -> Dict[str, Any]:
        """
        Execute a specific attack module with all verification checks.
        
        Args:
            module_name: Name of the attack module to execute
            module_params: Parameters for the module
            analyst_id: ID of the analyst executing the module
            
        Returns:
            Dict: Execution result with status and findings
        """
        if self.status != AttackStatus.RUNNING:
            return {
                'status': 'error',
                'reason': f'Operation not running. Status: {self.status.value}'
            }
        
        # Load the attack module
        module = self._load_attack_module(module_name)
        if not module:
            return {
                'status': 'error',
                'reason': f'Attack module {module_name} not found'
            }
        
        # Get module risk level
        module_risk = module.get_risk_level()
        
        print(f"\n{'='*80}")
        print(f"[MODULE EXECUTION] {module_name}")
        print(f"[RISK LEVEL] {module_risk.value}")
        print(f"[PHASE] {self.current_phase.value}")
        print(f"{'='*80}")
        
        # Validate module can run in current phase
        allowed_phases = module.get_allowed_phases()
        if self.current_phase not in allowed_phases:
            return {
                'status': 'error',
                'reason': f'Module {module_name} cannot run in phase {self.current_phase.value}. Allowed: {[p.value for p in allowed_phases]}'
            }
        
        # Safety validation
        safety_check = self.safety_validator.validate_module_execution(
            module_name,
            module_params,
            self.target_scope,
            self.current_phase
        )
        
        if not safety_check['valid']:
            print(f"[SAFETY VALIDATION FAILED] {safety_check['reason']}")
            self.attack_ledger.log_safety_violation(
                self.attack_id,
                safety_check['reason']
            )
            return {
                'status': 'blocked',
                'reason': safety_check['reason']
            }
        
        # Legal compliance check
        legal_check = self.legal_checker.check_module_compliance(
            module_name,
            module_params,
            self.target_scope
        )
        
        if not legal_check['compliant']:
            print(f"[LEGAL COMPLIANCE FAILED] {legal_check['reason']}")
            self.attack_ledger.log_compliance_violation(
                self.attack_id,
                legal_check['reason']
            )
            return {
                'status': 'blocked',
                'reason': legal_check['reason']
            }
        
        # Request human approval for high/critical risk modules
        if module_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            approval_token = self.approval_gateway.request_approval(
                action_type="MODULE_EXECUTION",
                operation_id=self.attack_id,
                analyst_id=analyst_id,
                details=f"Execute {module_name} with params: {json.dumps(module_params, indent=2)}",
                risk_level=module_risk.value
            )
            
            approved = self.approval_gateway.wait_for_approval(
                approval_token,
                timeout=300
            )
            
            if not approved:
                print(f"[MODULE EXECUTION DENIED] Approval not received")
                self.attack_ledger.log_denial(
                    self.attack_id,
                    "MODULE_EXECUTION",
                    module_name,
                    analyst_id
                )
                return {
                    'status': 'denied',
                    'reason': 'Human approval not received'
                }
            
            self.attack_ledger.log_approval(
                self.attack_id,
                "MODULE_EXECUTION",
                analyst_id,
                approval_token
            )
        
        # Execute the module
        print(f"[Attack Orchestrator] Executing {module_name}...")
        
        try:
            result = module.execute(
                target_scope=self.target_scope,
                params=module_params,
                evidence_collector=self.evidence_collector
            )
            
            # Log the execution
            self.attack_ledger.log_module_execution(
                self.attack_id,
                module_name,
                module_params,
                result,
                analyst_id
            )
            
            # Collect findings
            if result.get('findings'):
                self.findings.extend(result['findings'])
            
            # If blue team integration is available, notify for detection validation
            if self.blue_team:
                self._notify_blue_team(module_name, result)
            
            return {
                'status': 'success',
                'module': module_name,
                'result': result,
                'findings': result.get('findings', [])
            }
            
        except Exception as e:
            error_msg = str(e)
            print(f"[MODULE EXECUTION ERROR] {error_msg}")
            
            self.attack_ledger.log_error(
                self.attack_id,
                module_name,
                error_msg,
                analyst_id
            )
            
            return {
                'status': 'error',
                'module': module_name,
                'error': error_msg
            }
    
    def pause_operation(self, analyst_id: str, reason: str) -> bool:
        """
        Pause the current operation.
        
        Args:
            analyst_id: ID of the analyst pausing the operation
            reason: Reason for pausing
            
        Returns:
            bool: True if paused successfully
        """
        if self.status != AttackStatus.RUNNING:
            print(f"[Attack Orchestrator] Cannot pause: Operation not running. Status: {self.status}")
            return False
        
        self.status = AttackStatus.PAUSED
        
        self.attack_ledger.log_pause(
            self.attack_id,
            analyst_id,
            reason
        )
        
        print(f"[Attack Orchestrator] Operation {self.attack_id} PAUSED. Reason: {reason}")
        return True
    
    def resume_operation(self, analyst_id: str) -> bool:
        """
        Resume a paused operation.
        
        Args:
            analyst_id: ID of the analyst resuming the operation
            
        Returns:
            bool: True if resumed successfully
        """
        if self.status != AttackStatus.PAUSED:
            print(f"[Attack Orchestrator] Cannot resume: Operation not paused. Status: {self.status}")
            return False
        
        self.status = AttackStatus.RUNNING
        
        self.attack_ledger.log_resume(
            self.attack_id,
            analyst_id
        )
        
        print(f"[Attack Orchestrator] Operation {self.attack_id} RESUMED")
        return True
    
    def abort_operation(self, analyst_id: str, reason: str) -> bool:
        """
        Abort the current operation.
        
        Args:
            analyst_id: ID of the analyst aborting the operation
            reason: Reason for aborting
            
        Returns:
            bool: True if aborted successfully
        """
        if self.status in [AttackStatus.COMPLETED, AttackStatus.ABORTED]:
            print(f"[Attack Orchestrator] Cannot abort: Operation already {self.status.value}")
            return False
        
        self.status = AttackStatus.ABORTED
        self.operation_end = datetime.now(timezone.utc)
        
        self.attack_ledger.log_abort(
            self.attack_id,
            reason,
            analyst_id
        )
        
        print(f"[Attack Orchestrator] Operation {self.attack_id} ABORTED. Reason: {reason}")
        return True
    
    def complete_operation(self, analyst_id: str) -> bool:
        """
        Mark the operation as completed.
        
        Args:
            analyst_id: ID of the analyst completing the operation
            
        Returns:
            bool: True if completed successfully
        """
        if self.status != AttackStatus.RUNNING:
            print(f"[Attack Orchestrator] Cannot complete: Operation not running. Status: {self.status}")
            return False
        
        self.status = AttackStatus.COMPLETED
        self.operation_end = datetime.now(timezone.utc)
        
        self.attack_ledger.log_operation_complete(
            self.attack_id,
            analyst_id,
            self.findings
        )
        
        print(f"[Attack Orchestrator] Operation {self.attack_id} COMPLETED")
        print(f"[Attack Orchestrator] Duration: {self.operation_end - self.operation_start}")
        print(f"[Attack Orchestrator] Total Findings: {len(self.findings)}")
        
        return True
    
    def generate_report(self, report_type: str = "full") -> Dict[str, Any]:
        """
        Generate a comprehensive report of the operation.
        
        Args:
            report_type: Type of report ('full', 'summary', 'technical', 'executive')
            
        Returns:
            Dict: Report data
        """
        return self.attack_ledger.generate_report(
            self.attack_id,
            self.operation_name,
            self.operation_start,
            self.operation_end,
            self.status,
            self.findings,
            self.target_scope,
            self.rules_of_engagement,
            report_type
        )
    
    def _get_phase_risk_level(self, phase: AttackPhase) -> RiskLevel:
        """Map attack phase to risk level"""
        phase_risk = {
            AttackPhase.RECONNAISSANCE: RiskLevel.INFO,
            AttackPhase.SCANNING: RiskLevel.LOW,
            AttackPhase.EXPLOITATION: RiskLevel.MEDIUM,
            AttackPhase.POST_EXPLOITATION: RiskLevel.HIGH,
            AttackPhase.PERSISTENCE: RiskLevel.HIGH,
            AttackPhase.EXFILTRATION: RiskLevel.CRITICAL,
            AttackPhase.CLEANUP: RiskLevel.LOW
        }
        return phase_risk.get(phase, RiskLevel.INFO)
    
    def _load_attack_module(self, module_name: str):
        """Lazy load attack modules"""
        if module_name not in self._attack_modules:
            try:
                # Dynamic import based on module name
                # Try both the module name and lowercase version
                module_path = f"src.redteam_core.attack_modules.{module_name}"
                module_class = module_name.replace('_', '').capitalize()
                
                import importlib
                try:
                    module = importlib.import_module(module_path)
                    self._attack_modules[module_name] = getattr(module, f"{module_class}Module")()
                except ImportError:
                    # Try lowercase
                    module_path_lower = f"src.redteam_core.attack_modules.{module_name.lower()}"
                    module = importlib.import_module(module_path_lower)
                    self._attack_modules[module_name] = getattr(module, f"{module_class}Module")()
                
            except ImportError as e:
                print(f"[Attack Orchestrator] Failed to load module {module_name}: {e}")
                return None
        
        return self._attack_modules.get(module_name)
    
    def _notify_blue_team(self, module_name: str, result: Dict[str, Any]):
        """Notify BlueTeam for detection validation"""
        if self.blue_team:
            notification = {
                'attack_id': self.attack_id,
                'module': module_name,
                'phase': self.current_phase.value,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'result': result
            }
            # This would integrate with the existing BlueTeam event router
            print(f"[BlueTeam Integration] Notifying BlueTeam of attack activity: {module_name}")
