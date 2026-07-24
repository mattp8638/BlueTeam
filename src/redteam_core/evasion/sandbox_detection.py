"""
Sandbox Detection

Detect virtual machines, sandboxes, and analysis environments.
"""

import os
import sys
import time
import platform
import subprocess
import hashlib
import psutil
import socket
import uuid
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class SandboxType(Enum):
    """Types of sandbox environments"""
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    SANDBOX = "sandbox"
    DEBUGGER = "debugger"
    ANALYSIS_TOOL = "analysis_tool"
    CLOUD_ENVIRONMENT = "cloud_environment"
    UNKNOWN = "unknown"


@dataclass
class SandboxDetectionResult:
    """Result of sandbox detection"""
    is_sandbox: bool
    sandbox_type: SandboxType
    confidence: float  # 0.0 to 1.0
    indicators: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_sandbox': self.is_sandbox,
            'sandbox_type': self.sandbox_type.value,
            'confidence': self.confidence,
            'indicators': self.indicators
        }


class SandboxDetector:
    """
    Detect various types of sandbox and analysis environments.
    
    Detection Methods:
    - Virtual Machine Detection (CPU, MAC, SMBIOS, Hypervisor)
    - Container Detection (Docker, LXC, Kubernetes)
    - Sandbox Detection (Cuckoo, Joe Sandbox, Any.run)
    - Debugger Detection (ptrace, gdb, lldb)
    - Analysis Tool Detection (Wireshark, Process Monitor, etc.)
    - Cloud Environment Detection (AWS, Azure, GCP)
    - Behavioral Detection (CPU cores, memory, disk size)
    - Time-based Detection (uptime, boot time)
    
    Usage:
    >>> detector = SandboxDetector()
    >>> result = detector.detect()
    >>> if result.is_sandbox:
    ...     print(f"Sandbox detected: {result.sandbox_type.value}")
    """
    
    def __init__(self):
        """Initialize the sandbox detector"""
        self.indicators: List[Dict[str, Any]] = []
    
    def detect(self) -> SandboxDetectionResult:
        """
        Detect if running in a sandbox environment.
        
        Returns:
            SandboxDetectionResult: Detection result
        """
        self.indicators = []
        
        # Run all detection methods
        vm_result = self._detect_virtual_machine()
        container_result = self._detect_container()
        sandbox_result = self._detect_sandbox()
        debugger_result = self._detect_debugger()
        analysis_result = self._detect_analysis_tools()
        cloud_result = self._detect_cloud_environment()
        behavioral_result = self._detect_behavioral()
        time_result = self._detect_time_based()
        
        # Aggregate results
        all_results = [
            vm_result, container_result, sandbox_result, debugger_result,
            analysis_result, cloud_result, behavioral_result, time_result
        ]
        
        # Find the highest confidence detection
        max_confidence = 0.0
        detected_type = SandboxType.UNKNOWN
        
        for result in all_results:
            if result['confidence'] > max_confidence:
                max_confidence = result['confidence']
                detected_type = result['type']
        
        # Determine if sandbox
        is_sandbox = max_confidence > 0.5
        
        return SandboxDetectionResult(
            is_sandbox=is_sandbox,
            sandbox_type=detected_type,
            confidence=max_confidence,
            indicators=self.indicators
        )
    
    def _detect_virtual_machine(self) -> Dict[str, Any]:
        """Detect virtual machine environments"""
        indicators = []
        confidence = 0.0
        
        # Check CPU information
        cpu_info = self._get_cpu_info()
        if cpu_info:
            # Check for known VM CPU strings
            vm_strings = [
                'vmware', 'virtual', 'vbox', 'qemu', 'kvm',
                'xen', 'hyper-v', 'parallels', 'virtualbox'
            ]
            
            for vm_string in vm_strings:
                if vm_string.lower() in cpu_info.lower():
                    indicators.append({
                        'type': 'cpu_vendor',
                        'value': cpu_info,
                        'confidence': 0.9,
                        'description': f'CPU vendor contains {vm_string}'
                    })
                    confidence = max(confidence, 0.9)
        
        # Check MAC address
        mac_addresses = self._get_mac_addresses()
        for mac in mac_addresses:
            # Check for known VM MAC prefixes
            vm_mac_prefixes = [
                '00:05:69',    # VMware
                '00:0C:29',    # VMware
                '00:50:56',    # VMware
                '00:03:FF',    # Microsoft Hyper-V
                '00:1C:42',    # Parallels
                '08:00:27',    # VirtualBox
                '0A:00:27',    # VirtualBox
                '00:16:3E',    # Xen
                '00:1A:4A',    # QEMU
            ]
            
            for prefix in vm_mac_prefixes:
                if mac.upper().startswith(prefix):
                    indicators.append({
                        'type': 'mac_address',
                        'value': mac,
                        'confidence': 0.85,
                        'description': f'MAC address prefix {prefix} indicates VM'
                    })
                    confidence = max(confidence, 0.85)
        
        # Check SMBIOS information
        smbios_info = self._get_smbios_info()
        if smbios_info:
            vm_manufacturers = [
                'vmware', 'virtualbox', 'qemu', 'xen',
                'microsoft corporation', 'parallels'
            ]
            
            for manufacturer in vm_manufacturers:
                if manufacturer.lower() in smbios_info.lower():
                    indicators.append({
                        'type': 'smbios_manufacturer',
                        'value': smbios_info,
                        'confidence': 0.8,
                        'description': f'SMBIOS manufacturer contains {manufacturer}'
                    })
                    confidence = max(confidence, 0.8)
        
        # Check hypervisor presence
        if self._check_hypervisor():
            indicators.append({
                'type': 'hypervisor',
                'value': 'detected',
                'confidence': 0.95,
                'description': 'Hypervisor detected via CPUID'
            })
            confidence = max(confidence, 0.95)
        
        # Check for VM-specific files
        vm_files = [
            '/usr/sbin/vmware-toolbox-cmd',
            '/usr/sbin/vboxadd',
            '/usr/sbin/vboxadd-service',
            '/usr/bin/VBoxClient',
            '/usr/bin/vmware-toolbox-cmd',
            '/usr/sbin/xenstore-read'
        ]
        
        for vm_file in vm_files:
            if os.path.exists(vm_file):
                indicators.append({
                    'type': 'vm_file',
                    'value': vm_file,
                    'confidence': 0.9,
                    'description': f'VM-specific file detected: {vm_file}'
                })
                confidence = max(confidence, 0.9)
        
        # Check for VM-specific processes
        vm_processes = [
            'vmtoolsd',
            'vboxservice',
            'vmsrvc',
            'xenbus'
        ]
        
        for process in vm_processes:
            if self._check_process_running(process):
                indicators.append({
                    'type': 'vm_process',
                    'value': process,
                    'confidence': 0.85,
                    'description': f'VM-specific process running: {process}'
                })
                confidence = max(confidence, 0.85)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.VIRTUAL_MACHINE,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_container(self) -> Dict[str, Any]:
        """Detect container environments"""
        indicators = []
        confidence = 0.0
        
        # Check for Docker
        if self._check_docker():
            indicators.append({
                'type': 'docker',
                'value': 'detected',
                'confidence': 0.95,
                'description': 'Docker container detected'
            })
            confidence = max(confidence, 0.95)
        
        # Check for LXC
        if self._check_lxc():
            indicators.append({
                'type': 'lxc',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'LXC container detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for Kubernetes
        if self._check_kubernetes():
            indicators.append({
                'type': 'kubernetes',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Kubernetes pod detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for container-specific files
        container_files = [
            '/.dockerenv',
            '/.dockerinit',
            '/run/.containerenv'
        ]
        
        for container_file in container_files:
            if os.path.exists(container_file):
                indicators.append({
                    'type': 'container_file',
                    'value': container_file,
                    'confidence': 0.95,
                    'description': f'Container-specific file detected: {container_file}'
                })
                confidence = max(confidence, 0.95)
        
        # Check for cgroups
        if self._check_cgroups():
            indicators.append({
                'type': 'cgroups',
                'value': 'detected',
                'confidence': 0.85,
                'description': 'Control groups detected (container environment)'
            })
            confidence = max(confidence, 0.85)
        
        # Check for container-specific environment variables
        container_envs = [
            'KUBERNETES_SERVICE_HOST',
            'KUBERNETES_SERVICE_PORT',
            'CONTAINER_ID',
            'DOCKER_CONTAINER_ID'
        ]
        
        for env_var in container_envs:
            if env_var in os.environ:
                indicators.append({
                    'type': 'container_env',
                    'value': env_var,
                    'confidence': 0.8,
                    'description': f'Container-specific environment variable: {env_var}'
                })
                confidence = max(confidence, 0.8)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.CONTAINER,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_sandbox(self) -> Dict[str, Any]:
        """Detect sandbox environments"""
        indicators = []
        confidence = 0.0
        
        # Check for Cuckoo Sandbox
        if self._check_cuckoo():
            indicators.append({
                'type': 'cuckoo',
                'value': 'detected',
                'confidence': 0.95,
                'description': 'Cuckoo Sandbox detected'
            })
            confidence = max(confidence, 0.95)
        
        # Check for Joe Sandbox
        if self._check_joe_sandbox():
            indicators.append({
                'type': 'joe_sandbox',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Joe Sandbox detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for Any.run
        if self._check_anyrun():
            indicators.append({
                'type': 'anyrun',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Any.run sandbox detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for Hybrid Analysis
        if self._check_hybrid_analysis():
            indicators.append({
                'type': 'hybrid_analysis',
                'value': 'detected',
                'confidence': 0.85,
                'description': 'Hybrid Analysis sandbox detected'
            })
            confidence = max(confidence, 0.85)
        
        # Check for sandbox-specific files
        sandbox_files = [
            '/cuckoo',
            '/joebox',
            '/any.run',
            '/hybrid-analysis'
        ]
        
        for sandbox_file in sandbox_files:
            if os.path.exists(sandbox_file):
                indicators.append({
                    'type': 'sandbox_file',
                    'value': sandbox_file,
                    'confidence': 0.9,
                    'description': f'Sandbox-specific file detected: {sandbox_file}'
                })
                confidence = max(confidence, 0.9)
        
        # Check for sandbox-specific processes
        sandbox_processes = [
            'cuckoo',
            'joebox',
            'analyzer',
            'sandbox'
        ]
        
        for process in sandbox_processes:
            if self._check_process_running(process):
                indicators.append({
                    'type': 'sandbox_process',
                    'value': process,
                    'confidence': 0.85,
                    'description': f'Sandbox-specific process running: {process}'
                })
                confidence = max(confidence, 0.85)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.SANDBOX,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_debugger(self) -> Dict[str, Any]:
        """Detect debugger presence"""
        indicators = []
        confidence = 0.0
        
        # Check for ptrace
        if self._check_ptrace():
            indicators.append({
                'type': 'ptrace',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Debugger detected via ptrace'
            })
            confidence = max(confidence, 0.9)
        
        # Check for gdb
        if self._check_gdb():
            indicators.append({
                'type': 'gdb',
                'value': 'detected',
                'confidence': 0.95,
                'description': 'GDB debugger detected'
            })
            confidence = max(confidence, 0.95)
        
        # Check for lldb
        if self._check_lldb():
            indicators.append({
                'type': 'lldb',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'LLDB debugger detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for Windows debuggers
        if platform.system() == 'Windows':
            if self._check_windows_debugger():
                indicators.append({
                    'type': 'windows_debugger',
                    'value': 'detected',
                    'confidence': 0.9,
                    'description': 'Windows debugger detected'
                })
                confidence = max(confidence, 0.9)
        
        # Check for debugger-specific files
        debugger_files = [
            '/proc/self/status',  # Check for TracerPid
            '/.gdb_history',
            '/.lldb'
        ]
        
        for debugger_file in debugger_files:
            if os.path.exists(debugger_file):
                indicators.append({
                    'type': 'debugger_file',
                    'value': debugger_file,
                    'confidence': 0.7,
                    'description': f'Debugger-specific file detected: {debugger_file}'
                })
                confidence = max(confidence, 0.7)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.DEBUGGER,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_analysis_tools(self) -> Dict[str, Any]:
        """Detect analysis tools"""
        indicators = []
        confidence = 0.0
        
        # Check for Wireshark
        if self._check_wireshark():
            indicators.append({
                'type': 'wireshark',
                'value': 'detected',
                'confidence': 0.85,
                'description': 'Wireshark detected'
            })
            confidence = max(confidence, 0.85)
        
        # Check for Process Monitor
        if self._check_process_monitor():
            indicators.append({
                'type': 'process_monitor',
                'value': 'detected',
                'confidence': 0.8,
                'description': 'Process Monitor detected'
            })
            confidence = max(confidence, 0.8)
        
        # Check for Process Explorer
        if self._check_process_explorer():
            indicators.append({
                'type': 'process_explorer',
                'value': 'detected',
                'confidence': 0.8,
                'description': 'Process Explorer detected'
            })
            confidence = max(confidence, 0.8)
        
        # Check for TCPdump
        if self._check_tcpdump():
            indicators.append({
                'type': 'tcpdump',
                'value': 'detected',
                'confidence': 0.75,
                'description': 'TCPdump detected'
            })
            confidence = max(confidence, 0.75)
        
        # Check for analysis tool processes
        analysis_processes = [
            'wireshark',
            'tshark',
            'tcpdump',
            'procmon',
            'procexp',
            'fiddler',
            'burp',
            'charles'
        ]
        
        for process in analysis_processes:
            if self._check_process_running(process):
                indicators.append({
                    'type': 'analysis_process',
                    'value': process,
                    'confidence': 0.8,
                    'description': f'Analysis tool process running: {process}'
                })
                confidence = max(confidence, 0.8)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.ANALYSIS_TOOL,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_cloud_environment(self) -> Dict[str, Any]:
        """Detect cloud environments"""
        indicators = []
        confidence = 0.0
        
        # Check for AWS
        if self._check_aws():
            indicators.append({
                'type': 'aws',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'AWS cloud environment detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for Azure
        if self._check_azure():
            indicators.append({
                'type': 'azure',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Azure cloud environment detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for GCP
        if self._check_gcp():
            indicators.append({
                'type': 'gcp',
                'value': 'detected',
                'confidence': 0.9,
                'description': 'Google Cloud Platform detected'
            })
            confidence = max(confidence, 0.9)
        
        # Check for cloud-specific files
        cloud_files = [
            '/etc/ec2_version',  # AWS
            '/etc/azure_version',  # Azure
            '/etc/google_version',  # GCP
        ]
        
        for cloud_file in cloud_files:
            if os.path.exists(cloud_file):
                indicators.append({
                    'type': 'cloud_file',
                    'value': cloud_file,
                    'confidence': 0.85,
                    'description': f'Cloud-specific file detected: {cloud_file}'
                })
                confidence = max(confidence, 0.85)
        
        # Check for cloud-specific environment variables
        cloud_envs = [
            'EC2_INSTANCE_ID',
            'AWS_REGION',
            'AZURE_INSTANCE_ID',
            'GOOGLE_CLOUD_PROJECT'
        ]
        
        for env_var in cloud_envs:
            if env_var in os.environ:
                indicators.append({
                    'type': 'cloud_env',
                    'value': env_var,
                    'confidence': 0.8,
                    'description': f'Cloud-specific environment variable: {env_var}'
                })
                confidence = max(confidence, 0.8)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.CLOUD_ENVIRONMENT,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_behavioral(self) -> Dict[str, Any]:
        """Detect sandbox via behavioral analysis"""
        indicators = []
        confidence = 0.0
        
        # Check CPU cores
        cpu_cores = self._get_cpu_cores()
        if cpu_cores <= 2:
            indicators.append({
                'type': 'low_cpu_cores',
                'value': cpu_cores,
                'confidence': 0.7,
                'description': f'Low CPU cores ({cpu_cores}) suggests sandbox'
            })
            confidence = max(confidence, 0.7)
        
        # Check memory
        total_memory = self._get_total_memory()
        if total_memory < 4 * 1024 * 1024 * 1024:  # Less than 4GB
            indicators.append({
                'type': 'low_memory',
                'value': f"{total_memory / (1024**3):.2f} GB",
                'confidence': 0.6,
                'description': f'Low memory ({total_memory / (1024**3):.2f} GB) suggests sandbox'
            })
            confidence = max(confidence, 0.6)
        
        # Check disk size
        disk_size = self._get_disk_size()
        if disk_size < 50 * 1024 * 1024 * 1024:  # Less than 50GB
            indicators.append({
                'type': 'small_disk',
                'value': f"{disk_size / (1024**3):.2f} GB",
                'confidence': 0.65,
                'description': f'Small disk ({disk_size / (1024**3):.2f} GB) suggests sandbox'
            })
            confidence = max(confidence, 0.65)
        
        # Check uptime
        uptime = self._get_uptime()
        if uptime < 3600:  # Less than 1 hour
            indicators.append({
                'type': 'short_uptime',
                'value': f"{uptime} seconds",
                'confidence': 0.75,
                'description': f'Short uptime ({uptime} seconds) suggests sandbox'
            })
            confidence = max(confidence, 0.75)
        
        # Check for mouse movement
        if not self._check_mouse_movement():
            indicators.append({
                'type': 'no_mouse_movement',
                'value': 'detected',
                'confidence': 0.5,
                'description': 'No mouse movement detected (possible sandbox)'
            })
            confidence = max(confidence, 0.5)
        
        # Check for user interaction
        if not self._check_user_interaction():
            indicators.append({
                'type': 'no_user_interaction',
                'value': 'detected',
                'confidence': 0.4,
                'description': 'No user interaction detected (possible sandbox)'
            })
            confidence = max(confidence, 0.4)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.SANDBOX,
            'confidence': confidence,
            'indicators': indicators
        }
    
    def _detect_time_based(self) -> Dict[str, Any]:
        """Detect sandbox via time-based analysis"""
        indicators = []
        confidence = 0.0
        
        # Check if time is suspicious
        current_time = time.time()
        boot_time = self._get_boot_time()
        
        if boot_time and (current_time - boot_time) < 300:  # Booted less than 5 minutes ago
            indicators.append({
                'type': 'recent_boot',
                'value': f"{current_time - boot_time} seconds",
                'confidence': 0.8,
                'description': f'Recent boot ({current_time - boot_time} seconds ago) suggests sandbox'
            })
            confidence = max(confidence, 0.8)
        
        # Check for time anomalies
        if self._check_time_anomalies():
            indicators.append({
                'type': 'time_anomaly',
                'value': 'detected',
                'confidence': 0.7,
                'description': 'Time anomaly detected (possible sandbox)'
            })
            confidence = max(confidence, 0.7)
        
        # Store indicators
        self.indicators.extend(indicators)
        
        return {
            'type': SandboxType.SANDBOX,
            'confidence': confidence,
            'indicators': indicators
        }
    
    # Helper methods
    def _get_cpu_info(self) -> Optional[str]:
        """Get CPU information"""
        try:
            if platform.system() == 'Windows':
                import wmi
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    return processor.Name
            else:
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('model name'):
                            return line.split(':')[1].strip()
        except:
            pass
        return None
    
    def _get_mac_addresses(self) -> List[str]:
        """Get MAC addresses"""
        macs = []
        try:
            if platform.system() == 'Windows':
                import wmi
                c = wmi.WMI()
                for interface in c.Win32_NetworkAdapterConfiguration():
                    if interface.MACAddress:
                        macs.append(interface.MACAddress)
            else:
                for interface in psutil.net_if_addrs():
                    for addr in interface:
                        if addr.family == socket.AF_PACKET:
                            macs.append(addr.address)
        except:
            pass
        return macs
    
    def _get_smbios_info(self) -> Optional[str]:
        """Get SMBIOS information"""
        try:
            if platform.system() == 'Windows':
                import wmi
                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    return bios.Manufacturer
            else:
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    return f.read().strip()
        except:
            pass
        return None
    
    def _check_hypervisor(self) -> bool:
        """Check for hypervisor via CPUID"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                # CPUID function
                def cpuid(func, eax):
                    import ctypes
                    cpuid_func = ctypes.windll.kernel32
                    cpuid_func.__stdcall_restype = ctypes.c_uint32
                    cpuid_func.__stdcall_argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
                    
                    regs = (ctypes.c_uint32 * 4)()
                    cpuid_func(func, ctypes.byref(regs))
                    return regs
                
                # Check hypervisor bit
                regs = cpuid(1, 0)
                return (regs[2] & (1 << 31)) != 0
            else:
                # Check /proc/cpuinfo for hypervisor flag
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if 'hypervisor' in line.lower():
                            return True
        except:
            pass
        return False
    
    def _check_process_running(self, process_name: str) -> bool:
        """Check if a process is running"""
        try:
            for proc in psutil.process_iter(['name']):
                if process_name.lower() in proc.info['name'].lower():
                    return True
        except:
            pass
        return False
    
    def _check_docker(self) -> bool:
        """Check for Docker"""
        # Check for .dockerenv
        if os.path.exists('/.dockerenv'):
            return True
        
        # Check for Docker environment variables
        if 'DOCKER_CONTAINER_ID' in os.environ:
            return True
        
        # Check for Docker-specific files
        docker_files = [
            '/.dockerinit',
            '/run/.containerenv'
        ]
        
        for docker_file in docker_files:
            if os.path.exists(docker_file):
                return True
        
        return False
    
    def _check_lxc(self) -> bool:
        """Check for LXC"""
        # Check for LXC environment variables
        if 'LXC_CONTAINER_ID' in os.environ:
            return True
        
        # Check for LXC-specific files
        if os.path.exists('/.lxc_config'):
            return True
        
        return False
    
    def _check_kubernetes(self) -> bool:
        """Check for Kubernetes"""
        # Check for Kubernetes environment variables
        k8s_envs = [
            'KUBERNETES_SERVICE_HOST',
            'KUBERNETES_SERVICE_PORT',
            'KUBERNETES_POD_NAME'
        ]
        
        for env_var in k8s_envs:
            if env_var in os.environ:
                return True
        
        # Check for Kubernetes-specific files
        if os.path.exists('/.kubernetes'):
            return True
        
        return False
    
    def _check_cgroups(self) -> bool:
        """Check for control groups"""
        try:
            if os.path.exists('/proc/1/cgroup'):
                with open('/proc/1/cgroup', 'r') as f:
                    content = f.read()
                    if 'docker' in content or 'lxc' in content or 'kubepods' in content:
                        return True
        except:
            pass
        return False
    
    def _check_cuckoo(self) -> bool:
        """Check for Cuckoo Sandbox"""
        # Check for Cuckoo-specific files
        cuckoo_files = [
            '/cuckoo',
            '/cuckoo/conf',
            '/cuckoo/logs'
        ]
        
        for cuckoo_file in cuckoo_files:
            if os.path.exists(cuckoo_file):
                return True
        
        # Check for Cuckoo-specific processes
        if self._check_process_running('cuckoo'):
            return True
        
        return False
    
    def _check_joe_sandbox(self) -> bool:
        """Check for Joe Sandbox"""
        # Check for Joe Sandbox-specific files
        joe_files = [
            '/joebox',
            '/joebox/server'
        ]
        
        for joe_file in joe_files:
            if os.path.exists(joe_file):
                return True
        
        return False
    
    def _check_anyrun(self) -> bool:
        """Check for Any.run"""
        # Check for Any.run-specific environment variables
        if 'ANYRUN' in os.environ:
            return True
        
        # Check for Any.run-specific files
        if os.path.exists('/any.run'):
            return True
        
        return False
    
    def _check_hybrid_analysis(self) -> bool:
        """Check for Hybrid Analysis"""
        # Check for Hybrid Analysis-specific environment variables
        if 'HYBRID_ANALYSIS' in os.environ:
            return True
        
        return False
    
    def _check_ptrace(self) -> bool:
        """Check for ptrace"""
        try:
            # Try to ptrace ourselves
            import ctypes
            libc = ctypes.CDLL('libc.so.6')
            if libc.ptrace(0, 0, 1, 0) == -1:
                return True
        except:
            pass
        return False
    
    def _check_gdb(self) -> bool:
        """Check for GDB"""
        # Check for GDB-specific files
        if os.path.exists('/.gdb_history'):
            return True
        
        # Check for GDB process
        if self._check_process_running('gdb'):
            return True
        
        return False
    
    def _check_lldb(self) -> bool:
        """Check for LLDB"""
        # Check for LLDB process
        if self._check_process_running('lldb'):
            return True
        
        return False
    
    def _check_windows_debugger(self) -> bool:
        """Check for Windows debuggers"""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            
            # Check for debugger
            is_debugger_present = ctypes.c_bool(False)
            kernel32.IsDebuggerPresent(ctypes.byref(is_debugger_present))
            if is_debugger_present.value:
                return True
            
            # Check for NtGlobalFlag
            import win32api
            import win32con
            try:
                hProcess = kernel32.GetCurrentProcess()
                nt_global_flag = win32api.GetProcessHeap()
                if nt_global_flag & 0x70:
                    return True
            except:
                pass
        except:
            pass
        return False
    
    def _check_wireshark(self) -> bool:
        """Check for Wireshark"""
        # Check for Wireshark process
        if self._check_process_running('wireshark'):
            return True
        if self._check_process_running('tshark'):
            return True
        
        return False
    
    def _check_process_monitor(self) -> bool:
        """Check for Process Monitor"""
        # Check for Process Monitor process
        if self._check_process_running('procmon'):
            return True
        
        return False
    
    def _check_process_explorer(self) -> bool:
        """Check for Process Explorer"""
        # Check for Process Explorer process
        if self._check_process_running('procexp'):
            return True
        
        return False
    
    def _check_tcpdump(self) -> bool:
        """Check for TCPdump"""
        # Check for TCPdump process
        if self._check_process_running('tcpdump'):
            return True
        
        return False
    
    def _check_aws(self) -> bool:
        """Check for AWS"""
        # Check for AWS-specific files
        if os.path.exists('/etc/ec2_version'):
            return True
        
        # Check for AWS-specific environment variables
        if 'EC2_INSTANCE_ID' in os.environ:
            return True
        
        return False
    
    def _check_azure(self) -> bool:
        """Check for Azure"""
        # Check for Azure-specific files
        if os.path.exists('/etc/azure_version'):
            return True
        
        # Check for Azure-specific environment variables
        if 'AZURE_INSTANCE_ID' in os.environ:
            return True
        
        return False
    
    def _check_gcp(self) -> bool:
        """Check for GCP"""
        # Check for GCP-specific files
        if os.path.exists('/etc/google_version'):
            return True
        
        # Check for GCP-specific environment variables
        if 'GOOGLE_CLOUD_PROJECT' in os.environ:
            return True
        
        return False
    
    def _get_cpu_cores(self) -> int:
        """Get number of CPU cores"""
        try:
            return psutil.cpu_count(logical=False)
        except:
            return 1
    
    def _get_total_memory(self) -> int:
        """Get total memory in bytes"""
        try:
            return psutil.virtual_memory().total
        except:
            return 0
    
    def _get_disk_size(self) -> int:
        """Get total disk size in bytes"""
        try:
            return psutil.disk_usage('/').total
        except:
            return 0
    
    def _get_uptime(self) -> int:
        """Get system uptime in seconds"""
        try:
            return int(time.time() - psutil.boot_time())
        except:
            return 0
    
    def _get_boot_time(self) -> Optional[float]:
        """Get system boot time"""
        try:
            return psutil.boot_time()
        except:
            return None
    
    def _check_mouse_movement(self) -> bool:
        """Check for mouse movement"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                last_input_info = ctypes.c_ulong()
                ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input_info))
                last_input_tick = last_input_info.value
                current_tick = ctypes.windll.kernel32.GetTickCount()
                idle_time = current_tick - last_input_tick
                return idle_time < 5000  # Less than 5 seconds
            else:
                # Linux: check /dev/input/mice
                try:
                    with open('/dev/input/mice', 'rb') as f:
                        import select
                        ready, _, _ = select.select([f], [], [], 0)
                        return len(ready) > 0
                except:
                    return True  # Assume mouse movement if we can't check
        except:
            return True
    
    def _check_user_interaction(self) -> bool:
        """Check for user interaction"""
        try:
            # Check for recent keyboard/mouse activity
            if platform.system() == 'Windows':
                import ctypes
                last_input_info = ctypes.c_ulong()
                ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input_info))
                last_input_tick = last_input_info.value
                current_tick = ctypes.windll.kernel32.GetTickCount()
                idle_time = current_tick - last_input_tick
                return idle_time < 30000  # Less than 30 seconds
            else:
                # Check for recent process starts
                boot_time = self._get_boot_time()
                if boot_time:
                    for proc in psutil.process_iter(['create_time']):
                        try:
                            create_time = proc.info['create_time']
                            if create_time > boot_time + 60:  # Started more than 1 minute after boot
                                return True
                        except:
                            pass
        except:
            pass
        return False
    
    def _check_time_anomalies(self) -> bool:
        """Check for time anomalies"""
        try:
            # Check if system time is reasonable
            current_time = time.time()
            if current_time < 0 or current_time > 2**31:  # Unreasonable time
                return True
            
            # Check if time is moving too fast or too slow
            start_time = time.time()
            time.sleep(1)
            end_time = time.time()
            elapsed = end_time - start_time
            
            if elapsed < 0.9 or elapsed > 1.1:  # Time anomaly
                return True
        except:
            pass
        return False
