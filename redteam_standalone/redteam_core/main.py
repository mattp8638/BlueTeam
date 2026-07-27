from typing import Dict, List, Any, Optional, Tuple, Set, Union
#!/usr/bin/env python3
"""
AI-RedTeaming Main Entry Point

Command-line interface for the AI-RedTeaming platform.
"""

import argparse
import sys
import os
import json
from datetime import datetime, timezone

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from redteam_core.attack_orchestrator import AttackOrchestrator, AttackPhase, AttackStatus
    from redteam_core.verification_gateways.human_approval_gateway import HumanApprovalGateway
    from redteam_core.reporting.attack_ledger import AttackLedger
    from redteam_core.reporting.evidence_collector import EvidenceCollector
    from redteam_core.blue_team_integration import BlueTeamIntegration
except ImportError:
    from src.redteam_core.attack_orchestrator import AttackOrchestrator, AttackPhase, AttackStatus
    from src.redteam_core.verification_gateways.human_approval_gateway import HumanApprovalGateway
    from src.redteam_core.reporting.attack_ledger import AttackLedger
    from src.redteam_core.reporting.evidence_collector import EvidenceCollector
    from src.redteam_core.blue_team_integration import BlueTeamIntegration


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='AI-RedTeaming Platform - Autonomous Offensive Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start a new operation
  python main.py start --name "Security Assessment" --targets 10.0.0.1,10.0.0.2

  # Request approval for an operation
  python main.py approve --operation-id OP001 --analyst analyst-001

  # Execute a module
  python main.py execute --operation-id OP001 --module reconnaissance --params '{"targets": ["10.0.0.1"]}'

  # Generate a report
  python main.py report --operation-id OP001 --type full

  # Run integration test
  python main.py test
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start a new red team operation')
    start_parser.add_argument('--name', required=True, help='Name of the operation')
    start_parser.add_argument('--targets', required=True, help='Comma-separated list of targets')
    start_parser.add_argument('--roe', help='Rules of engagement (JSON file)')
    start_parser.add_argument('--scope', help='Target scope (JSON file)')
    
    # Approve command
    approve_parser = subparsers.add_parser('approve', help='Approve a pending operation')
    approve_parser.add_argument('--operation-id', required=True, help='ID of the operation to approve')
    approve_parser.add_argument('--analyst', required=True, help='ID of the analyst requesting approval')
    approve_parser.add_argument('--token', help='Approval token to approve')
    
    # Deny command
    deny_parser = subparsers.add_parser('deny', help='Deny a pending operation')
    deny_parser.add_argument('--operation-id', required=True, help='ID of the operation to deny')
    deny_parser.add_argument('--analyst', required=True, help='ID of the analyst denying')
    deny_parser.add_argument('--reason', help='Reason for denial')
    
    # Execute command
    execute_parser = subparsers.add_parser('execute', help='Execute an attack module')
    execute_parser.add_argument('--operation-id', required=True, help='ID of the operation')
    execute_parser.add_argument('--module', required=True, help='Name of the module to execute')
    execute_parser.add_argument('--params', help='Module parameters (JSON)')
    execute_parser.add_argument('--analyst', required=True, help='ID of the analyst executing')
    
    # Phase command
    phase_parser = subparsers.add_parser('phase', help='Transition to a new phase')
    phase_parser.add_argument('--operation-id', required=True, help='ID of the operation')
    phase_parser.add_argument('--to', required=True, help='Phase to transition to')
    phase_parser.add_argument('--analyst', required=True, help='ID of the analyst')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Get operation status')
    status_parser.add_argument('--operation-id', required=True, help='ID of the operation')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate a report')
    report_parser.add_argument('--operation-id', required=True, help='ID of the operation')
    report_parser.add_argument('--type', default='full', help='Report type (full, summary, technical, executive)')
    report_parser.add_argument('--output', help='Output file path')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run integration tests')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List operations')
    
    return parser.parse_args()


def load_json_file(file_path: str) -> dict:
    """Load JSON from a file"""
    with open(file_path, 'r') as f:
        return json.load(f)


def main():
    """Main entry point"""
    args = parse_args()
    
    if not args.command:
        print("Error: No command specified")
        print("Use --help for available commands")
        return 1
    
    # Initialize components
    orchestrator = AttackOrchestrator()
    approval_gateway = HumanApprovalGateway()
    ledger = AttackLedger()
    evidence_collector = EvidenceCollector()
    blue_team_integration = BlueTeamIntegration()
    
    # Connect orchestrator components
    orchestrator.approval_gateway = approval_gateway
    orchestrator.attack_ledger = ledger
    orchestrator.evidence_collector = evidence_collector
    orchestrator.blue_team = blue_team_integration
    
    try:
        if args.command == 'start':
            # Parse targets
            targets = [t.strip() for t in args.targets.split(',')]
            
            # Load scope and ROE
            target_scope = {
                'targets': targets,
                'exclusions': [],
                'authorized_for_destructive': False
            }
            
            rules_of_engagement = {
                'allowed_methods': ['reconnaissance', 'scanning'],
                'business_justification': args.name,
                'consent_obtained': True,
                'start_time': datetime.now(timezone.utc).isoformat(),
                'end_time': (datetime.now(timezone.utc) + timezone.timedelta(hours=24)).isoformat()
            }
            
            # Override with file inputs if provided
            if args.scope:
                target_scope.update(load_json_file(args.scope))
            if args.roe:
                rules_of_engagement.update(load_json_file(args.roe))
            
            # Initialize operation
            attack_id = orchestrator.initialize_operation(
                operation_name=args.name,
                target_scope=target_scope,
                rules_of_engagement=rules_of_engagement
            )
            
            print(f"Operation initialized: {attack_id}")
            print(f"Name: {args.name}")
            print(f"Targets: {targets}")
            print(f"Status: {orchestrator.status.value}")
            
            # Request approval
            print("\nRequesting approval...")
            print("Use 'approve' command to approve this operation")
            
        elif args.command == 'approve':
            # For CLI, we'll auto-approve if the operation exists
            # In a real system, this would require explicit human action
            if args.token:
                # Approve specific token
                success = approval_gateway.approve_token(args.token, args.analyst)
                if success:
                    print(f"Token {args.token} approved by {args.analyst}")
                else:
                    print(f"Failed to approve token {args.token}")
                    return 1
            else:
                # This is a simplified approval for CLI
                # In production, this would be a separate process
                print(f"Approving operation {args.operation_id} for {args.analyst}")
                print("Note: In production, this requires explicit human approval")
                
        elif args.command == 'deny':
            if args.token:
                success = approval_gateway.deny_token(args.token, args.analyst, args.reason or "")
                if success:
                    print(f"Token denied by {args.analyst}")
                else:
                    print(f"Failed to deny token")
                    return 1
            else:
                print("Denial requires a token")
                return 1
                
        elif args.command == 'execute':
            # Parse parameters
            params = {}
            if args.params:
                params = json.loads(args.params)
            
            # Execute the module
            result = orchestrator.execute_attack_module(
                module_name=args.module,
                module_params=params,
                analyst_id=args.analyst
            )
            
            print(f"Module execution: {result.get('status')}")
            print(f"Findings: {len(result.get('findings', []))}")
            
        elif args.command == 'phase':
            # Convert phase string to enum
            try:
                phase = AttackPhase(args.to.upper())
            except ValueError:
                print(f"Invalid phase: {args.to}")
                return 1
            
            # Transition to the new phase
            success = orchestrator.transition_to_phase(
                new_phase=phase,
                analyst_id=args.analyst
            )
            
            if success:
                print(f"Transitioned to phase: {phase.value}")
            else:
                print(f"Failed to transition to phase {phase.value}")
                return 1
                
        elif args.command == 'status':
            # Get operation status
            print(f"Operation ID: {args.operation_id}")
            print(f"Status: {orchestrator.status.value if orchestrator.attack_id == args.operation_id else 'Unknown'}")
            print(f"Current Phase: {orchestrator.current_phase.value if orchestrator.current_phase else 'None'}")
            
        elif args.command == 'report':
            # Generate report
            report = orchestrator.generate_report(report_type=args.type)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2))
                
        elif args.command == 'test':
            # Run integration tests
            print("Running integration tests...")
            from redteam_core.redteam_integration_test import main as test_main
            return test_main()
            
        elif args.command == 'list':
            # List operations (simplified)
            print("Operations:")
            if orchestrator.attack_id:
                print(f"  - {orchestrator.attack_id}: {orchestrator.operation_name} ({orchestrator.status.value})")
            else:
                print("  No operations found")
        
        else:
            print(f"Unknown command: {args.command}")
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
