from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
AI-RedTeaming Integration Test

Comprehensive test demonstrating the AI-RedTeaming platform with human verification.
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.redteam_core.attack_orchestrator import AttackOrchestrator, AttackPhase, RiskLevel, AttackStatus
from src.redteam_core.verification_gateways.human_approval_gateway import HumanApprovalGateway
from src.redteam_core.verification_gateways.safety_validator import SafetyValidator
from src.redteam_core.verification_gateways.legal_compliance import LegalComplianceChecker, ComplianceFramework
from src.redteam_core.reporting.attack_ledger import AttackLedger
from src.redteam_core.reporting.evidence_collector import EvidenceCollector
from src.redteam_core.blue_team_integration import BlueTeamIntegration


def test_human_approval_gateway():
    """Test the Human Approval Gateway"""
    print("\n" + "="*80)
    print("TESTING: Human Approval Gateway")
    print("="*80)
    
    gateway = HumanApprovalGateway()
    
    # Test 1: Request approval
    print("\nTest 1: Requesting approval...")
    token_id = gateway.request_approval(
        action_type="OPERATION_START",
        operation_id="test-op-001",
        analyst_id="analyst-001",
        details="Starting test operation",
        risk_level="high",
        scope={"targets": ["10.0.0.1", "10.0.0.2"]}
    )
    
    print(f"Token ID: {token_id}")
    
    # Test 2: Check pending approvals
    print("\nTest 2: Checking pending approvals...")
    pending = gateway.get_pending_approvals()
    print(f"Pending approvals: {len(pending)}")
    
    # Test 3: Approve the token (in a real scenario, this would be done by a human)
    print("\nTest 3: Approving token...")
    approved = gateway.approve_token(token_id, "supervisor-001")
    print(f"Approval successful: {approved}")
    
    # Test 4: Check status
    print("\nTest 4: Checking approval status...")
    status = gateway.get_approval_status(token_id)
    print(f"Status: {status['status'] if status else 'Not found'}")
    
    print("\n✅ Human Approval Gateway tests completed")


def test_safety_validator():
    """Test the Safety Validator"""
    print("\n" + "="*80)
    print("TESTING: Safety Validator")
    print("="*80)
    
    validator = SafetyValidator()
    
    # Test 1: Validate operation
    print("\nTest 1: Validating operation...")
    target_scope = {
        'targets': ['10.0.0.1', '10.0.0.2'],
        'exclusions': ['10.0.0.3'],
        'authorized_for_destructive': False
    }
    
    roe = {
        'allowed_methods': ['scanning', 'reconnaissance'],
        'business_justification': 'Security testing',
        'consent_obtained': True
    }
    
    result = validator.validate_operation(target_scope, roe)
    print(f"Operation validation: {'PASS' if result.valid else 'FAIL'} - {result.reason}")
    
    # Test 2: Validate with destructive methods
    print("\nTest 2: Validating with destructive methods...")
    roe_destructive = {
        'allowed_methods': ['exploitation', 'destructive'],
        'business_justification': 'Security testing',
        'consent_obtained': True
    }
    
    result = validator.validate_operation(target_scope, roe_destructive)
    print(f"Destructive operation validation: {'PASS' if result.valid else 'FAIL'} - {result.reason}")
    
    # Test 3: Validate module execution
    print("\nTest 3: Validating module execution...")
    module_params = {
        'targets': ['10.0.0.1'],
        'type': 'dns'
    }
    
    result = validator.validate_module_execution(
        'reconnaissance',
        module_params,
        target_scope,
        'reconnaissance'
    )
    print(f"Module execution validation: {'PASS' if result.valid else 'FAIL'} - {result.reason}")
    
    print("\n✅ Safety Validator tests completed")


def test_legal_compliance():
    """Test the Legal Compliance Checker"""
    print("\n" + "="*80)
    print("TESTING: Legal Compliance Checker")
    print("="*80)
    
    checker = LegalComplianceChecker()
    
    # Configure frameworks
    checker.configure_frameworks([
        ComplianceFramework.GDPR,
        ComplianceFramework.HIPAA
    ])
    
    # Test 1: Check operation compliance
    print("\nTest 1: Checking operation compliance...")
    target_scope = {
        'targets': ['10.0.0.1', '10.0.0.2'],
        'authorization': 'written_consent_obtained',
        'data_classification': 'internal'
    }
    
    roe = {
        'allowed_methods': ['scanning', 'reconnaissance'],
        'business_justification': 'Security testing',
        'consent_obtained': True,
        'proportionality_justification': 'Necessary for security assessment'
    }
    
    result = checker.check_operation_compliance(target_scope, roe)
    print(f"Operation compliance: {'PASS' if result.compliant else 'FAIL'}")
    if not result.compliant:
        print(f"Violations: {result.violations}")
    
    # Test 2: Check module compliance
    print("\nTest 2: Checking module compliance...")
    module_params = {
        'targets': ['10.0.0.1'],
        'type': 'dns'
    }
    
    result = checker.check_module_compliance(
        'reconnaissance',
        module_params,
        target_scope
    )
    print(f"Module compliance: {'PASS' if result.compliant else 'FAIL'}")
    
    print("\n✅ Legal Compliance Checker tests completed")


def test_attack_orchestrator():
    """Test the Attack Orchestrator"""
    print("\n" + "="*80)
    print("TESTING: Attack Orchestrator")
    print("="*80)
    
    # Create orchestrator
    orchestrator = AttackOrchestrator()
    
    # Test 1: Initialize operation
    print("\nTest 1: Initializing operation...")
    target_scope = {
        'targets': ['10.0.0.1', '10.0.0.2'],
        'exclusions': ['10.0.0.3'],
        'authorized_for_destructive': False
    }
    
    roe = {
        'allowed_methods': ['reconnaissance', 'scanning'],
        'business_justification': 'Security testing',
        'consent_obtained': True,
        'start_time': datetime.now(timezone.utc).isoformat(),
        'end_time': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    }
    
    attack_id = orchestrator.initialize_operation(
        operation_name="Test Security Assessment",
        target_scope=target_scope,
        rules_of_engagement=roe
    )
    
    print(f"Operation initialized with ID: {attack_id}")
    
    # Test 2: Request approval (this will block, so we'll skip in automated test)
    print("\nTest 2: Requesting operation approval...")
    print("(Skipping actual approval request in automated test)")
    
    # Manually set status to approved for testing
    orchestrator.status = AttackStatus.APPROVED
    
    # Test 3: Start operation
    print("\nTest 3: Starting operation...")
    started = orchestrator.start_operation("analyst-001")
    print(f"Operation started: {started}")
    
    # Test 4: Transition to scanning phase
    print("\nTest 4: Transitioning to scanning phase...")
    transitioned = orchestrator.transition_to_phase(
        AttackPhase.SCANNING,
        "analyst-001"
    )
    print(f"Phase transition successful: {transitioned}")
    
    # Test 5: Execute a module
    print("\nTest 5: Executing reconnaissance module...")
    result = orchestrator.execute_attack_module(
        module_name="reconnaissance",
        module_params={'targets': ['10.0.0.1'], 'type': 'dns'},
        analyst_id="analyst-001"
    )
    print(f"Module execution status: {result.get('status')}")
    print(f"Findings: {len(result.get('findings', []))}")
    
    # Test 6: Complete operation
    print("\nTest 6: Completing operation...")
    completed = orchestrator.complete_operation("analyst-001")
    print(f"Operation completed: {completed}")
    
    # Test 7: Generate report
    print("\nTest 7: Generating report...")
    report = orchestrator.generate_report(report_type="summary")
    print(f"Report generated: {report.get('report_type')}")
    print(f"Attack ID: {report.get('attack_id')}")
    print(f"Findings: {report.get('findings_count')}")
    
    print("\n✅ Attack Orchestrator tests completed")


def test_evidence_collector():
    """Test the Evidence Collector"""
    print("\n" + "="*80)
    print("TESTING: Evidence Collector")
    print("="*80)
    
    collector = EvidenceCollector(evidence_dir="/tmp/redteam_evidence")
    
    # Test 1: Collect log evidence
    print("\nTest 1: Collecting log evidence...")
    evidence = collector.collect_log(
        attack_id="test-attack-001",
        log_data="This is a test log entry",
        log_type="system",
        description="Test system log"
    )
    print(f"Evidence collected: {evidence.evidence_id}")
    print(f"File path: {evidence.file_path}")
    print(f"Hash: {evidence.file_hash}")
    
    # Test 2: Collect command output
    print("\nTest 2: Collecting command output...")
    evidence = collector.collect_command_output(
        attack_id="test-attack-001",
        command="ls -la",
        output="total 24\n-rw-r--r-- 1 user group 1024 Jan 1 00:00 test.txt",
        description="Directory listing"
    )
    print(f"Evidence collected: {evidence.evidence_id}")
    
    # Test 3: Verify evidence integrity
    print("\nTest 3: Verifying evidence integrity...")
    integrity = collector.verify_evidence_integrity(evidence.evidence_id)
    print(f"Evidence integrity: {'VALID' if integrity else 'INVALID'}")
    
    # Test 4: Get chain of custody
    print("\nTest 4: Getting chain of custody...")
    chain = collector.get_chain_of_custody("test-attack-001")
    print(f"Chain of custody entries: {len(chain)}")
    
    print("\n✅ Evidence Collector tests completed")


def test_attack_ledger():
    """Test the Attack Ledger"""
    print("\n" + "="*80)
    print("TESTING: Attack Ledger")
    print("="*80)
    
    ledger = AttackLedger(db_path="/tmp/redteam_ledger_test.db")
    
    # Test 1: Log operation init
    print("\nTest 1: Logging operation initialization...")
    ledger.log_operation_init(
        attack_id="test-attack-001",
        operation_name="Test Operation",
        target_scope={'targets': ['10.0.0.1']},
        rules_of_engagement={'allowed_methods': ['reconnaissance']}
    )
    
    # Test 2: Log operation start
    print("\nTest 2: Logging operation start...")
    ledger.log_operation_start("test-attack-001", "analyst-001")
    
    # Test 3: Log module execution
    print("\nTest 3: Logging module execution...")
    ledger.log_module_execution(
        attack_id="test-attack-001",
        module_name="reconnaissance",
        module_params={'targets': ['10.0.0.1']},
        result={'status': 'success', 'findings': []},
        analyst_id="analyst-001"
    )
    
    # Test 4: Log operation complete
    print("\nTest 4: Logging operation completion...")
    ledger.log_operation_complete(
        attack_id="test-attack-001",
        analyst_id="analyst-001",
        findings=[]
    )
    
    # Test 5: Verify integrity
    print("\nTest 5: Verifying ledger integrity...")
    is_valid, violations = ledger.verify_integrity("test-attack-001")
    print(f"Ledger integrity: {'VALID' if is_valid else 'INVALID'}")
    if violations:
        print(f"Violations: {violations}")
    
    # Test 6: Generate report
    print("\nTest 6: Generating report...")
    report = ledger.generate_report(
        attack_id="test-attack-001",
        operation_name="Test Operation",
        operation_start=datetime.now(timezone.utc),
        operation_end=datetime.now(timezone.utc),
        status="COMPLETED",
        findings=[],
        target_scope={'targets': ['10.0.0.1']},
        rules_of_engagement={'allowed_methods': ['reconnaissance']},
        report_type="summary"
    )
    print(f"Report generated: {report.get('report_type')}")
    
    print("\n✅ Attack Ledger tests completed")


def test_blue_team_integration():
    """Test the Blue Team Integration"""
    print("\n" + "="*80)
    print("TESTING: Blue Team Integration")
    print("="*80)
    
    integration = BlueTeamIntegration()
    
    # Test 1: Notify BlueTeam
    print("\nTest 1: Notifying BlueTeam...")
    notification_id = integration.notify_blue_team(
        attack_id="test-attack-001",
        module_name="reconnaissance",
        action="dns_enumeration",
        target="10.0.0.1",
        details={'type': 'dns', 'targets': ['10.0.0.1']}
    )
    print(f"Notification sent: {notification_id}")
    
    # Test 2: Record detection event
    print("\nTest 2: Recording detection event...")
    detection = integration.record_detection_event(
        attack_id="test-attack-001",
        detection_type="SIEM",
        details={'rule': 'suspicious_dns_activity', 'severity': 'Medium'},
        severity="Medium",
        confidence=0.9
    )
    print(f"Detection recorded: {detection.event_id}")
    
    # Test 3: Validate detection
    print("\nTest 3: Validating detection...")
    validation = integration.validate_detection(
        attack_id="test-attack-001",
        expected_detections=["SIEM", "EDR"]
    )
    print(f"Detection rate: {validation['detection_rate']:.1%}")
    print(f"Detected: {validation['detected_detections']}")
    print(f"Missed: {validation['missed_detections']}")
    
    # Test 4: Get metrics
    print("\nTest 4: Getting purple team metrics...")
    metrics = integration.get_purple_team_metrics()
    print(f"Detection rate: {metrics['detection_rate']:.1%}")
    print(f"Total attacks: {metrics['total_attacks']}")
    
    print("\n✅ Blue Team Integration tests completed")


def main():
    """Run all integration tests"""
    print("\n" + "="*80)
    print("AI-RedTeaming Integration Test Suite")
    print("="*80)
    
    try:
        # Run all tests
        test_human_approval_gateway()
        test_safety_validator()
        test_legal_compliance()
        test_attack_orchestrator()
        test_evidence_collector()
        test_attack_ledger()
        test_blue_team_integration()
        
        print("\n" + "="*80)
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY")
        print("="*80)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
