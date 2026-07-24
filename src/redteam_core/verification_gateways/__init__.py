from typing import Dict, List, Any, Optional, Tuple, Set, Union
# Verification Gateways for AI-RedTeaming
# Human-in-the-loop verification at every critical decision point

"""
Verification Gateways Module
===========================

This module provides multiple layers of verification for AI-RedTeaming operations:

1. Human Approval Gateway: Mandatory human approval for high-risk actions
2. Safety Validator: Automated safety checks for all operations
3. Legal Compliance Checker: Ensures operations comply with legal frameworks

All verification gateways are designed to prevent:
- Unauthorized destructive actions
- Out-of-scope targeting
- Legal violations
- Safety incidents
- Accidental data loss
"""

from .human_approval_gateway import HumanApprovalGateway
from .safety_validator import SafetyValidator
from .legal_compliance import LegalComplianceChecker

__all__ = [
    'HumanApprovalGateway',
    'SafetyValidator', 
    'LegalComplianceChecker'
]
