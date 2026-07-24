from typing import Dict, List, Any, Optional, Tuple, Set, Union
# AI-RedTeaming Core
# Enterprise-grade Offensive Security Testing Platform
# with Human Verification Guardrails at Every Step

"""
AI-RedTeaming Framework
=======================

An autonomous offensive security testing platform that complements the AI-BlueTeaming
defense system. Features human verification gateways at every critical decision point.

Architecture:
- Attack Orchestrator: Central command for offensive operations
- Attack Modules: Modular offensive capabilities (recon, exploitation, post-exploitation)
- Verification Gateways: Human approval required for all high-risk actions
- Payload Generator: Safe, controlled payload creation with validation
- Evidence Collector: Forensic data collection for purple team validation
- Reporting Engine: Comprehensive attack reporting and blue team integration

Security Features:
- Human-in-the-loop verification for all destructive actions
- Cryptographic audit trail of all red team activities
- Safe payload generation with automatic validation
- Integration with existing BlueTeam SIEM for detection validation
- Role-based access control and authentication
"""

from .attack_orchestrator import AttackOrchestrator
from .verification_gateways.human_approval_gateway import HumanApprovalGateway
from .verification_gateways.safety_validator import SafetyValidator
from .verification_gateways.legal_compliance import LegalComplianceChecker
from .reporting.attack_ledger import AttackLedger
from .reporting.evidence_collector import EvidenceCollector

__version__ = "1.0.0"
__all__ = [
    'AttackOrchestrator',
    'HumanApprovalGateway',
    'SafetyValidator',
    'LegalComplianceChecker',
    'AttackLedger',
    'EvidenceCollector'
]
