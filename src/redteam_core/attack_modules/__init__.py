from typing import Dict, List, Any, Optional, Tuple, Set, Union
# Attack Modules for AI-RedTeaming

"""
Attack Modules
==============

This module provides various attack capabilities for AI-RedTeaming operations.
Each module is designed with safety in mind and requires appropriate verification.

Available Modules:
- Reconnaissance: Information gathering and target discovery
- Vulnerability Scanning: Automated vulnerability detection
- Exploitation: Controlled exploitation of known vulnerabilities
- Post Exploitation: Privilege escalation and lateral movement
- Persistence: Establishing long-term access
- Evidence Collection: Forensic data collection
- Social Engineering: Phishing and user targeting simulations

All modules:
- Require explicit authorization
- Have defined risk levels
- Support human verification
- Collect forensic evidence
- Integrate with the attack ledger
"""

from .base_module import BaseAttackModule
from .reconnaissance import ReconnaissanceModule
from .vulnerability_scanner import VulnerabilityScannerModule
from .exploitation import ExploitationModule
from .post_exploitation import PostExploitationModule
from .persistence import PersistenceModule

__all__ = [
    'BaseAttackModule',
    'ReconnaissanceModule',
    'VulnerabilityScannerModule',
    'ExploitationModule',
    'PostExploitationModule',
    'PersistenceModule'
]
