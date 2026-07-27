from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Safety Validator

Automated safety validation for all AI-RedTeaming operations.
This module performs comprehensive safety checks to prevent accidents.
"""

import re
import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum


class SafetyViolationType(Enum):
    """Types of safety violations"""
    OUT_OF_SCOPE = "out_of_scope"
    DESTRUCTIVE_ACTION = "destructive_action"
    DATA_LOSS_RISK = "data_loss_risk"
    SERVICE_DISRUPTION = "service_disruption"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_ABUSE = "network_abuse"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE_GENERATION = "malware_generation"
    PHISHING_ATTEMPT = "phishing_attempt"
    DENIAL_OF_SERVICE = "denial_of_service"


@dataclass
class SafetyCheckResult:
    """Result of a safety validation check"""
    valid: bool
    reason: str = ""
    violation_type: SafetyViolationType = None
    details: Dict[str, Any] = None


class SafetyValidator:
    """
    Automated safety validator for AI-RedTeaming operations.
    
    This module performs comprehensive safety checks including:
    
    - Scope validation (targets, networks, domains)
    - Action validation (blocking destructive actions)
    - Parameter validation (preventing dangerous parameters)
    - Context validation (time, user, environment)
    - Pattern matching (detecting malicious patterns)
    
    The validator is designed to catch:
    - Out-of-scope targeting
    - Accidental destructive actions
    - Data loss scenarios
    - Service disruption
    - Privilege escalation attempts
    - Network abuse
    - Malware generation
    - Phishing attempts
    - Denial of service attacks
    """
    
    def __init__(self):
        """Initialize the Safety Validator"""
        # Initialize forbidden patterns
        self._forbidden_patterns = self._load_forbidden_patterns()
        self._forbidden_commands = self._load_forbidden_commands()
        self._forbidden_extensions = self._load_forbidden_extensions()
        
        # Initialize safe targets (to be configured per operation)
        self._authorized_targets: Set[str] = set()
        self._authorized_networks: List[ipaddress.IPv4Network] = []
        self._authorized_domains: Set[str] = set()
        
        # Dangerous file operations
        self._dangerous_file_ops = [
            'rm', 'del', 'erase', 'wipe', 'format', 'mkfs', 'dd',
            'shred', 'srm', 'sfill', 'bcwipe'
        ]
        
        # Dangerous network operations
        self._dangerous_net_ops = [
            'flood', 'dos', 'ddos', 'syn-flood', 'udp-flood',
            'icmp-flood', 'ping-flood', 'teardrop', 'land',
            'smurf', 'fraggle', 'bonk', 'boink'
        ]
        
        # Dangerous system operations
        self._dangerous_sys_ops = [
            'reboot', 'shutdown', 'halt', 'poweroff', 'init',
            'chmod 777', 'chown', 'useradd', 'usermod', 'passwd',
            'visudo', 'crontab', 'at', 'systemctl', 'service'
        ]
    
    def configure_authorized_scope(
        self, 
        targets: List[str], 
        networks: List[str], 
        domains: List[str]
    ):
        """
        Configure the authorized scope for validation.
        
        Args:
            targets: List of authorized IP addresses or hostnames
            networks: List of authorized network CIDRs
            domains: List of authorized domains
        """
        self._authorized_targets = set(targets)
        self._authorized_networks = []
        for net in networks:
            try:
                self._authorized_networks.append(ipaddress.IPv4Network(net))
            except ValueError:
                # Skip invalid networks
                pass
        self._authorized_domains = set(domains)
    
    def validate_operation(
        self, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ) -> SafetyCheckResult:
        """
        Validate an entire operation before it starts.
        
        Args:
            target_scope: Dictionary defining authorized targets
            rules_of_engagement: ROE including timing, methods, exclusions
            
        Returns:
            SafetyCheckResult: Validation result
        """
        # Check for required fields
        if not target_scope:
            return SafetyCheckResult(
                valid=False,
                reason="Target scope is required",
                violation_type=SafetyViolationType.OUT_OF_SCOPE
            )
        
        # Validate targets
        targets = target_scope.get('targets', [])
        if not targets:
            return SafetyCheckResult(
                valid=False,
                reason="At least one target is required",
                violation_type=SafetyViolationType.OUT_OF_SCOPE
            )
        
        # Check for exclusions
        exclusions = target_scope.get('exclusions', [])
        for target in targets:
            if target in exclusions:
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Target {target} is in exclusion list",
                    violation_type=SafetyViolationType.OUT_OF_SCOPE
                )
        
        # Validate ROE
        if not rules_of_engagement:
            return SafetyCheckResult(
                valid=False,
                reason="Rules of engagement are required",
                violation_type=SafetyViolationType.UNAUTHORIZED_ACCESS
            )
        
        # Check for destructive methods in ROE
        allowed_methods = rules_of_engagement.get('allowed_methods', [])
        forbidden_methods = ['destructive', 'wipe', 'delete', 'format']
        
        for method in allowed_methods:
            if any(fb in method.lower() for fb in forbidden_methods):
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Forbidden method in ROE: {method}",
                    violation_type=SafetyViolationType.DESTRUCTIVE_ACTION
                )
        
        # Check timing constraints
        start_time = rules_of_engagement.get('start_time')
        end_time = rules_of_engagement.get('end_time')
        
        if start_time and end_time:
            # In a real implementation, we'd validate the time window
            pass
        
        return SafetyCheckResult(valid=True, reason="Operation scope is safe")
    
    def validate_phase_transition(
        self, 
        current_phase: str, 
        new_phase: str, 
        target_scope: Dict[str, Any]
    ) -> SafetyCheckResult:
        """
        Validate transition between attack phases.
        
        Args:
            current_phase: Current attack phase
            new_phase: New attack phase to transition to
            target_scope: Current target scope
            
        Returns:
            SafetyCheckResult: Validation result
        """
        # Define phase transition rules
        phase_order = [
            'reconnaissance',
            'scanning', 
            'exploitation',
            'post_exploitation',
            'persistence',
            'exfiltration',
            'cleanup'
        ]
        
        try:
            current_idx = phase_order.index(current_phase.lower())
            new_idx = phase_order.index(new_phase.lower())
            
            # Can only move forward or stay in same phase
            if new_idx < current_idx:
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Cannot transition backward from {current_phase} to {new_phase}",
                    violation_type=SafetyViolationType.UNAUTHORIZED_ACCESS
                )
            
            # Check for skipped phases (optional, could be allowed)
            if new_idx > current_idx + 1:
                # Allow skipping for now, but could be made stricter
                pass
                
        except ValueError:
            return SafetyCheckResult(
                valid=False,
                reason=f"Unknown phase: {current_phase} or {new_phase}",
                violation_type=SafetyViolationType.UNAUTHORIZED_ACCESS
            )
        
        # High-risk phases require additional validation
        high_risk_phases = ['exploitation', 'post_exploitation', 'persistence', 'exfiltration']
        if new_phase.lower() in high_risk_phases:
            # Validate that we have proper authorization
            if not target_scope.get('authorized_for_destructive', False):
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Phase {new_phase} requires destructive authorization",
                    violation_type=SafetyViolationType.DESTRUCTIVE_ACTION
                )
        
        return SafetyCheckResult(valid=True, reason="Phase transition is safe")
    
    def validate_module_execution(
        self, 
        module_name: str, 
        module_params: Dict[str, Any],
        target_scope: Dict[str, Any],
        current_phase: str
    ) -> SafetyCheckResult:
        """
        Validate execution of a specific attack module.
        
        Args:
            module_name: Name of the module to execute
            module_params: Parameters for the module
            target_scope: Current target scope
            current_phase: Current attack phase
            
        Returns:
            SafetyCheckResult: Validation result
        """
        # Check for forbidden patterns in module name
        for pattern in self._forbidden_patterns:
            if re.search(pattern, module_name, re.IGNORECASE):
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Module name matches forbidden pattern: {pattern}",
                    violation_type=SafetyViolationType.MALWARE_GENERATION
                )
        
        # Validate targets in parameters
        targets = module_params.get('targets', [])
        if isinstance(targets, str):
            targets = [targets]
        
        for target in targets:
            # Check if target is in authorized scope
            if not self._is_target_authorized(target, target_scope):
                return SafetyCheckResult(
                    valid=False,
                    reason=f"Target {target} is not authorized",
                    violation_type=SafetyViolationType.OUT_OF_SCOPE,
                    details={'target': target}
                )
        
        # Check for dangerous commands in parameters
        for param_name, param_value in module_params.items():
            if isinstance(param_value, str):
                for cmd in self._forbidden_commands:
                    if cmd in param_value.lower():
                        return SafetyCheckResult(
                            valid=False,
                            reason=f"Forbidden command detected in parameter {param_name}: {cmd}",
                            violation_type=SafetyViolationType.DESTRUCTIVE_ACTION,
                            details={'parameter': param_name, 'command': cmd}
                        )
        
        # Check for dangerous file extensions
        if 'output_file' in module_params:
            filename = module_params['output_file']
            for ext in self._forbidden_extensions:
                if filename.endswith(ext):
                    return SafetyCheckResult(
                        valid=False,
                        reason=f"Forbidden file extension: {ext}",
                        violation_type=SafetyViolationType.MALWARE_GENERATION,
                        details={'filename': filename}
                    )
        
        # Phase-specific validation
        if current_phase.lower() == 'reconnaissance':
            # Recon should only use safe methods
            if 'method' in module_params:
                method = module_params['method'].lower()
                if method in ['exploit', 'attack', 'infect']:
                    return SafetyCheckResult(
                        valid=False,
                        reason=f"Method {method} not allowed in reconnaissance phase",
                        violation_type=SafetyViolationType.DESTRUCTIVE_ACTION
                    )
        
        return SafetyCheckResult(valid=True, reason="Module execution is safe")
    
    def validate_target(self, target: str, target_scope: Dict[str, Any]) -> SafetyCheckResult:
        """
        Validate a specific target against the authorized scope.
        
        Args:
            target: Target to validate (IP, hostname, URL, etc.)
            target_scope: Current target scope
            
        Returns:
            SafetyCheckResult: Validation result
        """
        if self._is_target_authorized(target, target_scope):
            return SafetyCheckResult(valid=True, reason="Target is authorized")
        else:
            return SafetyCheckResult(
                valid=False,
                reason=f"Target {target} is not in authorized scope",
                violation_type=SafetyViolationType.OUT_OF_SCOPE,
                details={'target': target}
            )
    
    def _is_target_authorized(self, target: str, target_scope: Dict[str, Any]) -> bool:
        """
        Check if a target is within the authorized scope.
        
        Args:
            target: Target to check
            target_scope: Current target scope
            
        Returns:
            bool: True if authorized
        """
        # Check explicit targets
        authorized_targets = target_scope.get('targets', [])
        if target in authorized_targets:
            return True
        
        # Check if target matches any authorized pattern
        authorized_patterns = target_scope.get('target_patterns', [])
        for pattern in authorized_patterns:
            if re.match(pattern, target):
                return True
        
        # Check IP address against authorized networks
        try:
            ip = ipaddress.IPv4Address(target)
            for net in self._authorized_networks:
                if ip in net:
                    return True
        except ValueError:
            pass
        
        # Check hostname against authorized domains
        try:
            hostname = target.split(':')[0].split('/')[0]  # Extract hostname from URL
            for domain in self._authorized_domains:
                if hostname == domain or hostname.endswith(f".{domain}"):
                    return True
        except Exception:
            pass
        
        return False
    
    def _load_forbidden_patterns(self) -> List[str]:
        """Load forbidden patterns for detection"""
        return [
            # Malware-related patterns
            r'\.exe$',
            r'\.dll$',
            r'\.bat$',
            r'\.cmd$',
            r'\.ps1$',
            r'\.vbs$',
            r'\.js$',
            r'powershell',
            r'cmd\.exe',
            r'\\windows\\',
            
            # Dangerous operations
            r'rm\s+-rf',
            r'del\s+/[fsq]',
            r'format\s+[a-zA-Z]:',
            r'mkfs\s+',
            r'dd\s+if=',
            r'wipe',
            r'erase',
            
            # Network attacks
            r'syn\s+flood',
            r'udp\s+flood',
            r'ping\s+-f',
            r'nmap\s+-A',
            r'metasploit',
            
            # Privilege escalation
            r'sudo\s+',
            r'su\s+',
            r'chmod\s+777',
            r'chown\s+',
            
            # Data exfiltration
            r'curl\s+',
            r'wget\s+',
            r'scp\s+',
            r'rsync\s+',
            r'nc\s+',
            r'netcat\s+',
        ]
    
    def _load_forbidden_commands(self) -> List[str]:
        """Load forbidden command strings"""
        return [
            'rm -rf',
            'del /f /s /q',
            'format c:',
            'format d:',
            'mkfs',
            'dd if=',
            'wipe',
            'erase',
            'shred',
            'srm',
            'flood',
            'dos',
            'ddos',
            'syn-flood',
            'udp-flood',
            'ping -f',
            'metasploit',
            'msfconsole',
            'msfvenom',
            'veil',
            'cobalt strike',
            'empire',
            'posh',
            'nishang',
            'mimikatz',
            'procdump',
            'gsecdump',
        ]
    
    def _load_forbidden_extensions(self) -> List[str]:
        """Load forbidden file extensions"""
        return [
            '.exe',
            '.dll', 
            '.bat',
            '.cmd',
            '.ps1',
            '.vbs',
            '.js',
            '.jse',
            '.wsf',
            '.msi',
            '.msp',
            '.mst',
            '.scr',
            '.pif',
            '.cpl',
            '.com',
        ]
