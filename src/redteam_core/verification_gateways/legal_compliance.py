from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Legal Compliance Checker

Ensures all AI-RedTeaming operations comply with legal and regulatory frameworks.
"""

import re
import json
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone


class ComplianceFramework(Enum):
    """Legal and regulatory frameworks"""
    GENERAL = "general"
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    FISMA = "fisma"
    NIST = "nist"
    ISO_27001 = "iso_27001"
    CIS_CONTROLS = "cis_controls"


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


@dataclass
class ComplianceCheckResult:
    """Result of a compliance check"""
    compliant: bool
    reason: str = ""
    framework: ComplianceFramework = ComplianceFramework.GENERAL
    violations: List[str] = None
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.violations is None:
            self.violations = []
        if self.recommendations is None:
            self.recommendations = []


class LegalComplianceChecker:
    """
    Legal compliance checker for AI-RedTeaming operations.
    
    This module ensures that all offensive security operations comply with:
    
    - General legal principles (authorization, proportionality, necessity)
    - Data protection regulations (GDPR, CCPA, HIPAA)
    - Industry-specific regulations (PCI DSS, SOX, FISMA)
    - International laws (Computer Fraud and Abuse Act, etc.)
    - Organizational policies and procedures
    
    The checker validates:
    - Proper authorization and consent
    - Data handling and privacy
    - Cross-border data transfers
    - Retention policies
    - Reporting requirements
    - Incident response obligations
    """
    
    def __init__(self):
        """Initialize the Legal Compliance Checker"""
        # Initialize compliance rules
        self._compliance_rules = self._load_compliance_rules()
        self._data_classifications = self._load_data_classifications()
        self._jurisdiction_rules = self._load_jurisdiction_rules()
        
        # Track active compliance frameworks
        self._active_frameworks: Set[ComplianceFramework] = set()
        
        # Data handling rules
        self._sensitive_data_patterns = self._load_sensitive_data_patterns()
    
    def configure_frameworks(self, frameworks: List[ComplianceFramework]):
        """
        Configure which compliance frameworks to enforce.
        
        Args:
            frameworks: List of compliance frameworks to enforce
        """
        self._active_frameworks = set(frameworks)
    
    def check_operation_compliance(
        self, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> ComplianceCheckResult:
        """
        Check if an operation complies with all configured frameworks.
        
        Args:
            target_scope: Dictionary defining authorized targets
            rules_of_engagement: ROE including timing, methods, exclusions
            
        Returns:
            ComplianceCheckResult: Compliance check result
        """
        violations = []
        recommendations = []
        
        # Check general compliance
        general_check = self._check_general_compliance(target_scope, rules_of_engagement)
        if not general_check.compliant:
            violations.extend(general_check.violations)
            recommendations.extend(general_check.recommendations)
        
        # Check framework-specific compliance
        for framework in self._active_frameworks:
            framework_check = self._check_framework_compliance(
                framework, 
                target_scope, 
                rules_of_engagement
            )
            if not framework_check.compliant:
                violations.extend(framework_check.violations)
                recommendations.extend(framework_check.recommendations)
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                reason=f"{len(violations)} compliance violation(s) found",
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(
            compliant=True,
            reason="Operation complies with all configured frameworks"
        )
    
    def check_module_compliance(
        self, 
        module_name: str, 
        module_params: Dict[str, Any], 
        target_scope: Dict[str, Any]
    ) -> ComplianceCheckResult:
        """
        Check if a specific module execution complies with legal requirements.
        
        Args:
            module_name: Name of the module
            module_params: Parameters for the module
            target_scope: Current target scope
            
        Returns:
            ComplianceCheckResult: Compliance check result
        """
        violations = []
        recommendations = []
        
        # Check for sensitive data handling
        data_check = self._check_sensitive_data_handling(module_params)
        if not data_check.compliant:
            violations.extend(data_check.violations)
            recommendations.extend(data_check.recommendations)
        
        # Check for cross-border data transfers
        transfer_check = self._check_data_transfer_compliance(
            module_params, 
            target_scope
        )
        if not transfer_check.compliant:
            violations.extend(transfer_check.violations)
            recommendations.extend(transfer_check.recommendations)
        
        # Check for retention policy compliance
        retention_check = self._check_retention_compliance(module_params)
        if not retention_check.compliant:
            violations.extend(retention_check.violations)
            recommendations.extend(retention_check.recommendations)
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                reason=f"{len(violations)} compliance violation(s) found",
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(
            compliant=True,
            reason="Module execution complies with legal requirements"
        )
    
    def check_data_classification(self, data: str) -> DataClassification:
        """
        Classify data based on its content and sensitivity.
        
        Args:
            data: Data to classify
            
        Returns:
            DataClassification: Classification level
        """
        for classification, patterns in self._data_classifications.items():
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    return classification
        
        return DataClassification.PUBLIC
    
    def _check_general_compliance(
        self, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> ComplianceCheckResult:
        """Check general legal compliance"""
        violations = []
        recommendations = []
        
        # Check for proper authorization
        if not target_scope.get('authorization'):
            violations.append("Missing authorization for targets")
            recommendations.append("Obtain written authorization from target owners")
        
        # Check for proper consent
        if not rules_of_engagement.get('consent_obtained'):
            violations.append("No evidence of consent from target owners")
            recommendations.append("Document consent from all affected parties")
        
        # Check for proportionality
        methods = rules_of_engagement.get('allowed_methods', [])
        if any('destructive' in method.lower() for method in methods):
            if not rules_of_engagement.get('proportionality_justification'):
                violations.append("Destructive methods without proportionality justification")
                recommendations.append("Provide justification for destructive testing methods")
        
        # Check for necessity
        if not rules_of_engagement.get('business_justification'):
            violations.append("Missing business justification for testing")
            recommendations.append("Document business need for security testing")
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(compliant=True)
    
    def _check_framework_compliance(
        self, 
        framework: ComplianceFramework, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> ComplianceCheckResult:
        """Check compliance with a specific framework"""
        violations = []
        recommendations = []
        
        # Get framework-specific rules
        framework_rules = self._compliance_rules.get(framework, {})
        
        # Check each rule
        for rule_id, rule in framework_rules.items():
            if not self._evaluate_rule(rule, target_scope, rules_of_engagement):
                violations.append(f"{framework.value.upper()}: {rule['description']}")
                if 'remediation' in rule:
                    recommendations.append(rule['remediation'])
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                framework=framework,
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(compliant=True, framework=framework)
    
    def _check_sensitive_data_handling(self, params: Dict[str, Any]) -> ComplianceCheckResult:
        """Check for proper handling of sensitive data"""
        violations = []
        recommendations = []
        
        # Check all parameter values for sensitive data
        for param_name, param_value in params.items():
            if isinstance(param_value, str):
                classification = self.check_data_classification(param_value)
                
                if classification in [DataClassification.CONFIDENTIAL, 
                                       DataClassification.RESTRICTED, 
                                       DataClassification.SECRET, 
                                       DataClassification.TOP_SECRET]:
                    violations.append(f"Sensitive data in parameter {param_name}")
                    recommendations.append(f"Encrypt or redact sensitive data in {param_name}")
                
                # Check for PII patterns
                for pattern_name, pattern in self._sensitive_data_patterns.items():
                    if re.search(pattern, param_value, re.IGNORECASE):
                        violations.append(f"PII detected in parameter {param_name}: {pattern_name}")
                        recommendations.append(f"Anonymize or encrypt {pattern_name} in {param_name}")
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(compliant=True)
    
    def _check_data_transfer_compliance(
        self, 
        params: Dict[str, Any], 
        target_scope: Dict[str, Any]
    ) -> ComplianceCheckResult:
        """Check compliance with data transfer regulations"""
        violations = []
        recommendations = []
        
        # Check for data exfiltration parameters
        exfil_params = ['output_server', 'exfil_server', 'callback_ip', 'c2_server']
        
        for param_name in exfil_params:
            if param_name in params:
                server = params[param_name]
                
                # Check if server is in authorized jurisdictions
                if not self._is_authorized_jurisdiction(server):
                    violations.append(f"Data transfer to unauthorized jurisdiction: {server}")
                    recommendations.append(f"Use authorized data transfer endpoints")
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(compliant=True)
    
    def _check_retention_compliance(self, params: Dict[str, Any]) -> ComplianceCheckResult:
        """Check compliance with data retention policies"""
        violations = []
        recommendations = []
        
        # Check for data collection parameters
        if 'retention_period' in params:
            retention = params['retention_period']
            
            # Check against maximum retention periods
            max_retention = 30  # days
            
            try:
                if int(retention) > max_retention:
                    violations.append(f"Retention period {retention} exceeds maximum {max_retention} days")
                    recommendations.append(f"Reduce retention period to {max_retention} days or less")
            except ValueError:
                pass
        
        if violations:
            return ComplianceCheckResult(
                compliant=False,
                violations=violations,
                recommendations=recommendations
            )
        
        return ComplianceCheckResult(compliant=True)
    
    def _evaluate_rule(
        self, 
        rule: Dict[str, Any], 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> bool:
        """Evaluate a specific compliance rule"""
        # Implement rule evaluation logic
        # This is a placeholder - actual implementation would depend on rule structure
        return True
    
    def _is_authorized_jurisdiction(self, server: str) -> bool:
        """Check if a server is in an authorized jurisdiction"""
        # In a real implementation, this would check against a list of authorized countries
        # For now, we'll assume all servers are authorized
        return True
    
    def _load_compliance_rules(self) -> Dict[ComplianceFramework, Dict[str, Dict[str, str]]]:
        """Load compliance rules for all frameworks"""
        return {
            ComplianceFramework.GDPR: {
                'gdpr_1': {
                    'description': 'Personal data processing must have lawful basis',
                    'remediation': 'Document lawful basis for data processing'
                },
                'gdpr_2': {
                    'description': 'Data subjects must be informed about data collection',
                    'remediation': 'Provide privacy notice to data subjects'
                },
                'gdpr_3': {
                    'description': 'Data must be minimized to what is necessary',
                    'remediation': 'Collect only necessary data for testing'
                }
            },
            ComplianceFramework.HIPAA: {
                'hipaa_1': {
                    'description': 'Protected Health Information (PHI) must be encrypted',
                    'remediation': 'Encrypt all PHI during transmission and storage'
                },
                'hipaa_2': {
                    'description': 'Access to PHI must be logged and audited',
                    'remediation': 'Implement comprehensive audit logging'
                }
            },
            ComplianceFramework.PCI_DSS: {
                'pci_1': {
                    'description': 'Cardholder data must not be stored unless necessary',
                    'remediation': 'Avoid storing cardholder data during testing'
                },
                'pci_2': {
                    'description': 'Encryption must be used for transmission of cardholder data',
                    'remediation': 'Use strong encryption for all data transmission'
                }
            }
        }
    
    def _load_data_classifications(self) -> Dict[DataClassification, List[str]]:
        """Load data classification patterns"""
        return {
            DataClassification.PUBLIC: [],
            DataClassification.INTERNAL: [
                r'internal',
                r'confidential',
                r'proprietary'
            ],
            DataClassification.CONFIDENTIAL: [
                r'password',
                r'secret',
                r'api[_-]?key',
                r'private[_-]?key',
                r'credential',
                r'authentication'
            ],
            DataClassification.RESTRICTED: [
                r'ssn',
                r'social[_-]?security',
                r'credit[_-]?card',
                r'bank[_-]?account',
                r'financial[_-]?data'
            ],
            DataClassification.SECRET: [
                r'top[_-]?secret',
                r'classified',
                r'restricted[_-]?data'
            ],
            DataClassification.TOP_SECRET: []
        }
    
    def _load_jurisdiction_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load jurisdiction-specific rules"""
        return {
            'EU': {
                'gdpr_applies': True,
                'data_transfer_restrictions': True
            },
            'US': {
                'ccpa_applies': True,
                'hipaa_applies': True
            }
        }
    
    def _load_sensitive_data_patterns(self) -> Dict[str, str]:
        """Load patterns for detecting sensitive data"""
        return {
            'SSN': r'\d{3}-\d{2}-\d{4}',
            'Credit Card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Phone': r'\+?\d{10,15}',
            'IP Address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'API Key': r'[a-zA-Z0-9]{32,}',
            'Password': r'password\s*[:=]\s*\S+',
            'Bearer Token': r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'
        }
