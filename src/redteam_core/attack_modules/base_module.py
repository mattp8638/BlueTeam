from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Base Attack Module

Abstract base class for all AI-RedTeaming attack modules.
"""

from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime, timezone


class RiskLevel(Enum):
    """Risk level for attack modules"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPhase(Enum):
    """Attack phases that modules can operate in"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class FindingSeverity(Enum):
    """Severity levels for findings"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding:
    """Represents a security finding from an attack module"""
    
    def __init__(
        self, 
        finding_id: str, 
        title: str, 
        description: str, 
        severity: FindingSeverity, 
        module_name: str, 
        evidence: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None
    ):
        self.finding_id = finding_id
        self.title = title
        self.description = description
        self.severity = severity
        self.module_name = module_name
        self.timestamp = datetime.now(timezone.utc)
        self.evidence = evidence or {}
        self.remediation = remediation or ""
        self.references = references or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'module_name': self.module_name,
            'timestamp': self.timestamp.isoformat(),
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references
        }


class BaseAttackModule(ABC):
    """
    Abstract base class for all attack modules.
    
    All attack modules must inherit from this class and implement the required methods.
    """
    
    def __init__(self):
        """Initialize the attack module"""
        self.module_name = self.__class__.__name__
        self.findings: List[Finding] = []
        self.execution_log: List[str] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    @property
    @abstractmethod
    def risk_level(self) -> RiskLevel:
        """Get the risk level of this module"""
        pass
    
    @property
    @abstractmethod
    def allowed_phases(self) -> List[AttackPhase]:
        """Get the list of phases this module can operate in"""
        pass
    
    @abstractmethod
    def execute(
        self, 
        target_scope: Dict[str, Any], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ) -> Dict[str, Any]:
        """
        Execute the attack module.
        
        Args:
            target_scope: Dictionary defining authorized targets
            params: Parameters for the module execution
            evidence_collector: Optional evidence collector instance
            
        Returns:
            Dict: Execution result with status and findings
        """
        pass
    
    def get_risk_level(self) -> RiskLevel:
        """Get the risk level of this module"""
        return self.risk_level
    
    def get_allowed_phases(self) -> List[AttackPhase]:
        """Get the list of phases this module can operate in"""
        return self.allowed_phases
    
    def add_finding(
        self, 
        finding_id: str, 
        title: str, 
        description: str, 
        severity: FindingSeverity, 
        evidence: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None
    ):
        """
        Add a finding to the module's results.
        
        Args:
            finding_id: Unique identifier for the finding
            title: Title of the finding
            description: Description of the finding
            severity: Severity level
            evidence: Evidence supporting the finding
            remediation: Recommended remediation
            references: References to additional information
        """
        finding = Finding(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            module_name=self.module_name,
            evidence=evidence,
            remediation=remediation,
            references=references
        )
        self.findings.append(finding)
        
        # Log the finding
        self._log(f"FINDING: {title} ({severity.value})")
    
    def _log(self, message: str):
        """Log a message to the execution log"""
        timestamp = datetime.now(timezone.utc).isoformat()
        log_entry = f"[{timestamp}] {self.module_name}: {message}"
        self.execution_log.append(log_entry)
        print(log_entry)
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get a summary of the module's execution"""
        return {
            'module_name': self.module_name,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': str(self.end_time - self.start_time) if self.start_time and self.end_time else None,
            'findings_count': len(self.findings),
            'findings': [f.to_dict() for f in self.findings],
            'log_count': len(self.execution_log),
            'risk_level': self.risk_level.value
        }
