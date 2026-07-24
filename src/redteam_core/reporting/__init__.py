from typing import Dict, List, Any, Optional, Tuple, Set, Union
# Reporting Components for AI-RedTeaming

"""
Reporting Module
===============

This module provides comprehensive reporting capabilities for AI-RedTeaming operations:

1. Attack Ledger: Cryptographic audit trail of all red team activities
2. Evidence Collector: Forensic data collection and preservation
3. Report Generator: Comprehensive attack reports in multiple formats

All reporting components are designed to:
- Maintain cryptographic integrity of all records
- Support forensic investigations
- Enable purple team validation
- Provide audit trails for compliance
- Generate actionable intelligence for blue teams
"""

from .attack_ledger import AttackLedger
from .evidence_collector import EvidenceCollector

__all__ = [
    'AttackLedger',
    'EvidenceCollector'
]
