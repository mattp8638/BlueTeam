"""
APT29 (Cozy Bear) Playbook

Simulates APT29 TTPs (Tactics, Techniques, and Procedures).
Based on MITRE ATT&CK framework.
"""

import time
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum

from src.redteam_core.attack_orchestrator import AttackOrchestrator, AttackPhase
from src.redteam_core.attack_modules.reconnaissance import ReconnaissanceModule
from src.redteam_core.attack_modules.exploitation import ExploitationModule
from src.redteam_core.attack_modules.post_exploitation import PostExploitationModule
from src.redteam_core.attack_modules.persistence import PersistenceModule


class Tactic(Enum):
    """MITRE ATT&CK Tactics"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Technique:
    """Represents a MITRE ATT&CK Technique"""
    id: str
    name: str
    tactic: Tactic
    description: str
    platforms: List[str]
    permissions_required: List[str]
    data_sources: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'tactic': self.tactic.value,
            'description': self.description,
            'platforms': self.platforms,
            'permissions_required': self.permissions_required,
            'data_sources': self.data_sources
        }


@dataclass
class PlaybookStep:
    """A single step in the APT playbook"""
    step_id: str
    name: str
    description: str
    tactic: Tactic
    techniques: List[Technique]
    module: str
    params: Dict[str, Any]
    delay_min: int = 0
    delay_max: int = 0
    success_probability: float = 0.8
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'step_id': self.step_id,
            'name': self.name,
            'description': self.description,
            'tactic': self.tactic.value,
            'techniques': [t.to_dict() for t in self.techniques],
            'module': self.module,
            'params': self.params,
            'delay_min': self.delay_min,
            'delay_max': self.delay_max,
            'success_probability': self.success_probability
        }


class APT29Playbook:
    """
    APT29 (Cozy Bear) simulation playbook.
    
    APT29 is a Russian state-sponsored threat group that has been active since at least 2008.
    They are known for targeting government organizations, think tanks, universities,
    and energy sector entities.
    
    This playbook simulates APT29 TTPs including:
    - Spear-phishing with malicious attachments
    - PowerShell-based malware
    - Credential harvesting
    - Lateral movement via SMB
    - Data exfiltration via C2 channels
    
    MITRE ATT&CK ID: G0016
    
    Usage:
    >>> playbook = APT29Playbook()
    >>> playbook.execute(orchestrator, target_scope, rules_of_engagement)
    """
    
    def __init__(self):
        """Initialize the APT29 playbook"""
        self.playbook_id = "APT29-CozyBear-2024"
        self.name = "APT29 (Cozy Bear) Simulation"
        self.description = "Simulates APT29 TTPs including spear-phishing, PowerShell malware, and data exfiltration"
        self.author = "AI-RedTeam"
        self.version = "1.0"
        self.created = datetime.now(timezone.utc)
        self.steps = self._define_playbook()
    
    def _define_playbook(self) -> List[PlaybookStep]:
        """Define the APT29 playbook steps"""
        steps = []
        
        # Step 1: Initial Access - Spear-phishing with malicious attachment
        steps.append(PlaybookStep(
            step_id="apt29-001",
            name="Spear-phishing Campaign",
            description="Send spear-phishing emails with malicious Word documents to targeted individuals",
            tactic=Tactic.INITIAL_ACCESS,
            techniques=[
                Technique(
                    id="T1566.001",
                    name="Phishing: Spearphishing Attachment",
                    tactic=Tactic.INITIAL_ACCESS,
                    description="Spearphishing attachments are used to gain initial access to victim systems",
                    platforms=["Windows", "macOS"],
                    permissions_required=["User"],
                    data_sources=["Email", "File"]
                )
            ],
            module="social_engineering",
            params={
                'campaign_type': 'spear_phishing',
                'attachment_type': 'word_document',
                'payload': 'APT29_Macro_Downloader',
                'targets': ['executives', 'hr_personnel', 'it_staff']
            },
            delay_min=3600,  # 1 hour
            delay_max=7200,  # 2 hours
            success_probability=0.6
        ))
        
        # Step 2: Execution - Macro-based PowerShell downloader
        steps.append(PlaybookStep(
            step_id="apt29-002",
            name="Macro Execution",
            description="Execute VBA macro in Word document to download and run PowerShell script",
            tactic=Tactic.EXECUTION,
            techniques=[
                Technique(
                    id="T1059.001",
                    name="Command and Scripting Interpreter: PowerShell",
                    tactic=Tactic.EXECUTION,
                    description="Adversaries may abuse PowerShell commands and scripts for execution",
                    platforms=["Windows"],
                    permissions_required=["User"],
                    data_sources=["Command", "Process", "Module"]
                ),
                Technique(
                    id="T1055.001",
                    name="Process Injection: Dynamic Link Library Injection",
                    tactic=Tactic.DEFENSE_EVASION,
                    description="Inject code into legitimate processes to hide malicious activity",
                    platforms=["Windows"],
                    permissions_required=["User", "Administrator"],
                    data_sources=["Process", "Module"]
                )
            ],
            module="exploitation",
            params={
                'cve_id': 'APT29-MACRO-DOWNLOADER',
                'targets': ['local'],
                'payload': 'PowerShell_Downloader'
            },
            delay_min=60,
            delay_max=300,
            success_probability=0.75
        ))
        
        # Step 3: Persistence - Registry modification for persistence
        steps.append(PlaybookStep(
            step_id="apt29-003",
            name="Registry Persistence",
            description="Add registry key to maintain persistence across reboots",
            tactic=Tactic.PERSISTENCE,
            techniques=[
                Technique(
                    id="T1547.001",
                    name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                    tactic=Tactic.PERSISTENCE,
                    description="Adversaries may achieve persistence by adding programs to registry run keys",
                    platforms=["Windows"],
                    permissions_required=["Administrator"],
                    data_sources=["Registry", "Process"]
                )
            ],
            module="persistence",
            params={
                'mechanisms': ['registry_run'],
                'targets': ['local']
            },
            delay_min=60,
            delay_max=180,
            success_probability=0.85
        ))
        
        # Step 4: Privilege Escalation - Token manipulation
        steps.append(PlaybookStep(
            step_id="apt29-004",
            name="Token Manipulation",
            description="Use token manipulation to escalate privileges to SYSTEM",
            tactic=Tactic.PRIVILEGE_ESCALATION,
            techniques=[
                Technique(
                    id="T1134.001",
                    name="Access Token Manipulation: Token Impersonation/Theft",
                    tactic=Tactic.PRIVILEGE_ESCALATION,
                    description="Adversaries may duplicate then impersonate another token to escalate privileges",
                    platforms=["Windows"],
                    permissions_required=["User"],
                    data_sources=["Process", "Authentication"]
                )
            ],
            module="post_exploitation",
            params={
                'actions': ['escalate'],
                'targets': ['local']
            },
            delay_min=120,
            delay_max=600,
            success_probability=0.7
        ))
        
        # Step 5: Defense Evasion - Process injection
        steps.append(PlaybookStep(
            step_id="apt29-005",
            name="Process Injection",
            description="Inject malicious code into legitimate processes (e.g., svchost.exe)",
            tactic=Tactic.DEFENSE_EVASION,
            techniques=[
                Technique(
                    id="T1055.001",
                    name="Process Injection: Dynamic Link Library Injection",
                    tactic=Tactic.DEFENSE_EVASION,
                    description="Inject code into legitimate processes to hide malicious activity",
                    platforms=["Windows"],
                    permissions_required=["Administrator"],
                    data_sources=["Process", "Module"]
                )
            ],
            module="evasion",
            params={
                'technique': 'process_injection',
                'target_process': 'svchost.exe',
                'targets': ['local']
            },
            delay_min=60,
            delay_max=300,
            success_probability=0.8
        ))
        
        # Step 6: Credential Access - LSASS memory dump
        steps.append(PlaybookStep(
            step_id="apt29-006",
            name="Credential Harvesting",
            description="Dump LSASS memory to harvest credentials from the system",
            tactic=Tactic.CREDENTIAL_ACCESS,
            techniques=[
                Technique(
                    id="T1003.001",
                    name="OS Credential Dumping: LSASS Memory",
                    tactic=Tactic.CREDENTIAL_ACCESS,
                    description="Adversaries may attempt to extract user credentials from the LSASS process",
                    platforms=["Windows"],
                    permissions_required=["Administrator"],
                    data_sources=["Process", "Memory"]
                )
            ],
            module="post_exploitation",
            params={
                'actions': ['harvest'],
                'targets': ['local']
            },
            delay_min=120,
            delay_max=600,
            success_probability=0.85
        ))
        
        # Step 7: Discovery - System enumeration
        steps.append(PlaybookStep(
            step_id="apt29-007",
            name="System Enumeration",
            description="Perform comprehensive system enumeration to identify valuable assets",
            tactic=Tactic.DISCOVERY,
            techniques=[
                Technique(
                    id="T1082",
                    name="System Information Discovery",
                    tactic=Tactic.DISCOVERY,
                    description="Adversaries may attempt to get detailed information about the operating system",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["System Calls", "Process"]
                ),
                Technique(
                    id="T1083",
                    name="File and Directory Discovery",
                    tactic=Tactic.DISCOVERY,
                    description="Adversaries may enumerate files and directories to learn about the environment",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["File", "Process"]
                )
            ],
            module="post_exploitation",
            params={
                'actions': ['enumerate'],
                'targets': ['local']
            },
            delay_min=300,
            delay_max=1800,
            success_probability=0.9
        ))
        
        # Step 8: Lateral Movement - SMB pass-the-hash
        steps.append(PlaybookStep(
            step_id="apt29-008",
            name="Lateral Movement via SMB",
            description="Use harvested credentials to move laterally via SMB to other systems",
            tactic=Tactic.LATERAL_MOVEMENT,
            techniques=[
                Technique(
                    id="T1021.002",
                    name="Remote Services: SMB/Windows Admin Shares",
                    tactic=Tactic.LATERAL_MOVEMENT,
                    description="Adversaries may use SMB to move laterally and access remote systems",
                    platforms=["Windows"],
                    permissions_required=["User", "Administrator"],
                    data_sources=["Network Traffic", "Process"]
                ),
                Technique(
                    id="T1550.002",
                    name="Use Alternate Authentication Material: Pass the Hash",
                    tactic=Tactic.LATERAL_MOVEMENT,
                    description="Adversaries may use Pass the Hash to move laterally within an environment",
                    platforms=["Windows"],
                    permissions_required=["User"],
                    data_sources=["Authentication", "Process"]
                )
            ],
            module="post_exploitation",
            params={
                'actions': ['lateral'],
                'lateral_targets': ['network_shares'],
                'targets': ['local']
            },
            delay_min=600,
            delay_max=3600,
            success_probability=0.65
        ))
        
        # Step 9: Collection - Data staging
        steps.append(PlaybookStep(
            step_id="apt29-009",
            name="Data Collection and Staging",
            description="Identify and stage sensitive data for exfiltration",
            tactic=Tactic.COLLECTION,
            techniques=[
                Technique(
                    id="T1005",
                    name="Data from Local System",
                    tactic=Tactic.COLLECTION,
                    description="Adversaries may collect data from the local system before exfiltrating it",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["File", "Process"]
                ),
                Technique(
                    id="T1074.001",
                    name="Data Staged: Local Data Staging",
                    tactic=Tactic.COLLECTION,
                    description="Adversaries may stage collected data in a central location or directory",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["File"]
                )
            ],
            module="collection",
            params={
                'data_types': ['documents', 'emails', 'databases'],
                'staging_dir': '/Temp/StagedData',
                'targets': ['local']
            },
            delay_min=1800,
            delay_max=7200,
            success_probability=0.8
        ))
        
        # Step 10: Command and Control - Establish C2 channel
        steps.append(PlaybookStep(
            step_id="apt29-010",
            name="C2 Channel Establishment",
            description="Establish command and control channel using domain fronting",
            tactic=Tactic.COMMAND_AND_CONTROL,
            techniques=[
                Technique(
                    id="T1071.004",
                    name="Application Layer Protocol: DNS",
                    tactic=Tactic.COMMAND_AND_CONTROL,
                    description="Adversaries may use DNS for command and control",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["Network Traffic"]
                ),
                Technique(
                    id="T1090.003",
                    name="Proxy: Multi-hop Proxy",
                    tactic=Tactic.COMMAND_AND_CONTROL,
                    description="Adversaries may use multi-hop proxies to obfuscate C2 traffic",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["Network Traffic"]
                )
            ],
            module="c2_framework",
            params={
                'protocol': 'dns',
                'domain': 'legitimate-looking-domain.com',
                'targets': ['local']
            },
            delay_min=60,
            delay_max=300,
            success_probability=0.9
        ))
        
        # Step 11: Exfiltration - Data exfiltration
        steps.append(PlaybookStep(
            step_id="apt29-011",
            name="Data Exfiltration",
            description="Exfiltrate staged data via encrypted C2 channel",
            tactic=Tactic.EXFILTRATION,
            techniques=[
                Technique(
                    id="T1048.002",
                    name="Exfiltration Over Alternative Protocol: Exfiltration Over DNS",
                    tactic=Tactic.EXFILTRATION,
                    description="Adversaries may exfiltrate data over the DNS protocol",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["Network Traffic"]
                ),
                Technique(
                    id="T1048.003",
                    name="Exfiltration Over Alternative Protocol: Exfiltration Over HTTP/HTTPS",
                    tactic=Tactic.EXFILTRATION,
                    description="Adversaries may exfiltrate data over HTTP/HTTPS",
                    platforms=["Windows", "Linux", "macOS"],
                    permissions_required=["User"],
                    data_sources=["Network Traffic"]
                )
            ],
            module="exfiltration",
            params={
                'method': 'encrypted_dns',
                'targets': ['local']
            },
            delay_min=3600,
            delay_max=10800,
            success_probability=0.75
        ))
        
        return steps
    
    def execute(
        self,
        orchestrator: AttackOrchestrator,
        target_scope: Dict[str, Any],
        rules_of_engagement: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute the APT29 playbook.
        
        Args:
            orchestrator: Attack orchestrator instance
            target_scope: Target scope for the operation
            rules_of_engagement: Rules of engagement
            
        Returns:
            Dict: Execution results
        """
        results = {
            'playbook_id': self.playbook_id,
            'name': self.name,
            'start_time': datetime.now(timezone.utc).isoformat(),
            'steps': [],
            'findings': [],
            'success': True
        }
        
        # Initialize operation
        attack_id = orchestrator.initialize_operation(
            operation_name=self.name,
            target_scope=target_scope,
            rules_of_engagement=rules_of_engagement
        )
        
        # Request approval
        approved = orchestrator.request_operation_approval(
            analyst_id="apt29-operator",
            justification="APT29 simulation for security testing"
        )
        
        if not approved:
            results['success'] = False
            results['error'] = "Operation not approved"
            return results
        
        # Start operation
        orchestrator.start_operation("apt29-operator")
        
        # Execute each step
        for step in self.steps:
            step_result = self._execute_step(orchestrator, step, attack_id)
            results['steps'].append(step_result)
            
            # Add delay between steps
            if step.delay_min > 0 or step.delay_max > 0:
                delay = random.randint(step.delay_min, step.delay_max)
                time.sleep(delay)
            
            # Check if we should continue
            if not step_result['success'] and step_result.get('critical', False):
                results['success'] = False
                break
        
        # Complete operation
        orchestrator.complete_operation("apt29-operator")
        
        results['end_time'] = datetime.now(timezone.utc).isoformat()
        results['findings'] = orchestrator.findings
        
        return results
    
    def _execute_step(
        self,
        orchestrator: AttackOrchestrator,
        step: PlaybookStep,
        attack_id: str
    ) -> Dict[str, Any]:
        """
        Execute a single playbook step.
        
        Args:
            orchestrator: Attack orchestrator instance
            step: Playbook step to execute
            attack_id: Attack ID
            
        Returns:
            Dict: Step execution result
        """
        result = {
            'step_id': step.step_id,
            'name': step.name,
            'start_time': datetime.now(timezone.utc).isoformat(),
            'success': False,
            'error': None,
            'findings': []
        }
        
        try:
            # Transition to appropriate phase if needed
            phase_map = {
                Tactic.INITIAL_ACCESS: AttackPhase.RECONNAISSANCE,
                Tactic.EXECUTION: AttackPhase.EXPLOITATION,
                Tactic.PERSISTENCE: AttackPhase.PERSISTENCE,
                Tactic.PRIVILEGE_ESCALATION: AttackPhase.POST_EXPLOITATION,
                Tactic.DEFENSE_EVASION: AttackPhase.POST_EXPLOITATION,
                Tactic.CREDENTIAL_ACCESS: AttackPhase.POST_EXPLOITATION,
                Tactic.DISCOVERY: AttackPhase.POST_EXPLOITATION,
                Tactic.LATERAL_MOVEMENT: AttackPhase.POST_EXPLOITATION,
                Tactic.COLLECTION: AttackPhase.POST_EXPLOITATION,
                Tactic.COMMAND_AND_CONTROL: AttackPhase.PERSISTENCE,
                Tactic.EXFILTRATION: AttackPhase.EXFILTRATION
            }
            
            target_phase = phase_map.get(step.tactic, orchestrator.current_phase)
            if target_phase != orchestrator.current_phase:
                orchestrator.transition_to_phase(target_phase, "apt29-operator")
            
            # Execute the module
            module_result = orchestrator.execute_attack_module(
                module_name=step.module,
                module_params=step.params,
                analyst_id="apt29-operator"
            )
            
            result['success'] = module_result.get('status') == 'success'
            result['findings'] = module_result.get('findings', [])
            
            if not result['success']:
                result['error'] = module_result.get('message', 'Unknown error')
            
        except Exception as e:
            result['error'] = str(e)
        
        result['end_time'] = datetime.now(timezone.utc).isoformat()
        return result
    
    def get_technique_matrix(self) -> Dict[str, List[str]]:
        """
        Get the technique matrix for this playbook.
        
        Returns:
            Dict: Mapping of tactics to technique IDs
        """
        matrix = {}
        
        for step in self.steps:
            tactic = step.tactic.value
            if tactic not in matrix:
                matrix[tactic] = []
            
            for technique in step.techniques:
                if technique.id not in matrix[tactic]:
                    matrix[tactic].append(technique.id)
        
        return matrix
    
    def get_attack_flow(self) -> List[Dict[str, Any]]:
        """
        Get the attack flow visualization.
        
        Returns:
            List: Attack flow steps
        """
        flow = []
        
        for step in self.steps:
            flow.append({
                'step_id': step.step_id,
                'name': step.name,
                'tactic': step.tactic.value,
                'techniques': [t.id for t in step.techniques],
                'delay': f"{step.delay_min}-{step.delay_max} seconds"
            })
        
        return flow
