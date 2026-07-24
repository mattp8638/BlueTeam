from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Reconnaissance Module

Information gathering and target discovery for AI-RedTeaming operations.
"""

import socket
import json
import dns.resolver
from datetime import datetime, timezone
import requests

from .base_module import BaseAttackModule, RiskLevel, AttackPhase, Finding, FindingSeverity


class ReconnaissanceModule(BaseAttackModule):
    """
    Reconnaissance module for information gathering and target discovery.
    
    This module performs:
    - DNS enumeration
    - Port scanning (limited)
    - Service discovery
    - Web application fingerprinting
    - Network topology mapping
    - Public information gathering
    
    Risk Level: LOW (information gathering only)
    Allowed Phases: RECONNAISSANCE, SCANNING
    """
    
    @property
    def risk_level(self) -> RiskLevel:
        return RiskLevel.LOW
    
    @property
    def allowed_phases(self) -> List[AttackPhase]:
        return [AttackPhase.RECONNAISSANCE, AttackPhase.SCANNING]
    
    def __init__(self):
        super().__init__()
        self.timeout = 10  # seconds
        self.max_ports = 100  # Maximum ports to scan per target
    
    def execute(
        self, 
        target_scope: Dict[str, Any], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ) -> Dict[str, Any]:
        """
        Execute reconnaissance operations.
        
        Args:
            target_scope: Dictionary defining authorized targets
            params: Parameters for reconnaissance
            evidence_collector: Optional evidence collector instance
            
        Returns:
            Dict: Execution result with status and findings
        """
        self.start_time = datetime.now(timezone.utc)
        self._log("Starting reconnaissance operations")
        
        # Get targets from scope or params
        targets = params.get('targets', target_scope.get('targets', []))
        
        if not targets:
            self._log("ERROR: No targets specified")
            self.end_time = datetime.now(timezone.utc)
            return {
                'status': 'error',
                'message': 'No targets specified',
                'findings': []
            }
        
        # Get reconnaissance type from params
        recon_type = params.get('type', 'full')
        
        # Execute appropriate reconnaissance
        if recon_type == 'dns':
            self._execute_dns_recon(targets, evidence_collector)
        elif recon_type == 'port':
            self._execute_port_scan(targets, params, evidence_collector)
        elif recon_type == 'web':
            self._execute_web_recon(targets, params, evidence_collector)
        elif recon_type == 'network':
            self._execute_network_recon(targets, params, evidence_collector)
        else:
            # Full reconnaissance
            self._execute_dns_recon(targets, evidence_collector)
            self._execute_port_scan(targets, params, evidence_collector)
            self._execute_web_recon(targets, params, evidence_collector)
        
        self.end_time = datetime.now(timezone.utc)
        
        result = {
            'status': 'success',
            'message': f'Reconnaissance completed on {len(targets)} targets',
            'findings': [f.to_dict() for f in self.findings],
            'summary': self.get_execution_summary()
        }
        
        self._log("Reconnaissance operations completed")
        return result
    
    def _execute_dns_recon(
        self, 
        targets: List[str], 
        evidence_collector: Any = None
    ):
        """Execute DNS reconnaissance"""
        self._log("Starting DNS reconnaissance")
        
        for target in targets:
            # Skip if it's an IP address
            if self._is_ip_address(target):
                continue
            
            try:
                # Try to resolve A records
                self._log(f"Resolving A records for {target}")
                try:
                    answers = dns.resolver.resolve(target, 'A')
                    for rdata in answers:
                        self._log(f"  A Record: {rdata.to_text()}")
                        
                        # Add finding for each resolved IP
                        self.add_finding(
                            finding_id=f"dns-a-{target}-{rdata.to_text()}",
                            title=f"DNS A Record: {target}",
                            description=f"Domain {target} resolves to {rdata.to_text()}",
                            severity=FindingSeverity.INFO,
                            evidence={'target': target, 'record_type': 'A', 'value': rdata.to_text()}
                        )
                        
                        # Collect evidence
                        if evidence_collector:
                            evidence_collector.collect_log(
                                attack_id="current",  # Will be set by orchestrator
                                log_data=f"DNS A: {target} -> {rdata.to_text()}",
                                log_type="dns",
                                description=f"DNS A record resolution for {target}"
                            )
                except Exception as e:
                    self._log(f"  Error resolving A records: {e}")
                
                # Try to resolve MX records
                try:
                    answers = dns.resolver.resolve(target, 'MX')
                    for rdata in answers:
                        self._log(f"  MX Record: {rdata.exchange} (preference: {rdata.preference})")
                        
                        self.add_finding(
                            finding_id=f"dns-mx-{target}-{rdata.exchange}",
                            title=f"DNS MX Record: {target}",
                            description=f"Domain {target} has MX record: {rdata.exchange} (preference: {rdata.preference})",
                            severity=FindingSeverity.INFO,
                            evidence={'target': target, 'record_type': 'MX', 'value': rdata.exchange, 'preference': rdata.preference}
                        )
                except Exception as e:
                    self._log(f"  Error resolving MX records: {e}")
                
                # Try to resolve NS records
                try:
                    answers = dns.resolver.resolve(target, 'NS')
                    for rdata in answers:
                        self._log(f"  NS Record: {rdata.to_text()}")
                        
                        self.add_finding(
                            finding_id=f"dns-ns-{target}-{rdata.to_text()}",
                            title=f"DNS NS Record: {target}",
                            description=f"Domain {target} has NS record: {rdata.to_text()}",
                            severity=FindingSeverity.INFO,
                            evidence={'target': target, 'record_type': 'NS', 'value': rdata.to_text()}
                        )
                except Exception as e:
                    self._log(f"  Error resolving NS records: {e}")
                
                # Try to resolve TXT records
                try:
                    answers = dns.resolver.resolve(target, 'TXT')
                    for rdata in answers:
                        for txt_string in rdata.strings:
                            self._log(f"  TXT Record: {txt_string}")
                            
                            self.add_finding(
                                finding_id=f"dns-txt-{target}-{txt_string[:20]}",
                                title=f"DNS TXT Record: {target}",
                                description=f"Domain {target} has TXT record: {txt_string}",
                                severity=FindingSeverity.INFO,
                                evidence={'target': target, 'record_type': 'TXT', 'value': txt_string}
                            )
                except Exception as e:
                    self._log(f"  Error resolving TXT records: {e}")
                    
            except Exception as e:
                self._log(f"Error processing DNS for {target}: {e}")
    
    def _execute_port_scan(
        self, 
        targets: List[str], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ):
        """Execute port scanning"""
        self._log("Starting port scanning")
        
        # Get port range from params
        start_port = params.get('start_port', 1)
        end_port = params.get('end_port', 1024)
        
        # Limit the number of ports
        if end_port - start_port > self.max_ports:
            end_port = start_port + self.max_ports
            self._log(f"Limiting port range to {self.max_ports} ports")
        
        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        
        for target in targets:
            self._log(f"Scanning target: {target}")
            
            # Check if target is a domain or IP
            if not self._is_ip_address(target):
                # Try to resolve the domain
                try:
                    target = socket.gethostbyname(target)
                    self._log(f"Resolved {target} to IP")
                except Exception as e:
                    self._log(f"Could not resolve {target}: {e}")
                    continue
            
            # Scan ports
            open_ports = []
            
            # First check common ports
            for port in common_ports:
                if start_port <= port <= end_port:
                    if self._check_port(target, port):
                        open_ports.append(port)
                        self._log(f"  Port {port}/tcp is open")
                        
                        # Add finding for open port
                        self.add_finding(
                            finding_id=f"port-open-{target}-{port}",
                            title=f"Open Port: {port}/tcp on {target}",
                            description=f"Port {port}/tcp is open on {target}",
                            severity=self._get_port_severity(port),
                            evidence={'target': target, 'port': port, 'protocol': 'tcp', 'status': 'open'}
                        )
                        
                        # Collect evidence
                        if evidence_collector:
                            evidence_collector.collect_log(
                                attack_id="current",
                                log_data=f"Port open: {target}:{port}/tcp",
                                log_type="port_scan",
                                description=f"Open port {port}/tcp on {target}"
                            )
            
            # Then scan the full range if we have time
            if end_port > max(common_ports):
                for port in range(max(common_ports) + 1, end_port + 1):
                    if self._check_port(target, port):
                        open_ports.append(port)
                        self._log(f"  Port {port}/tcp is open")
                        
                        self.add_finding(
                            finding_id=f"port-open-{target}-{port}",
                            title=f"Open Port: {port}/tcp on {target}",
                            description=f"Port {port}/tcp is open on {target}",
                            severity=FindingSeverity.INFO,
                            evidence={'target': target, 'port': port, 'protocol': 'tcp', 'status': 'open'}
                        )
            
            self._log(f"Found {len(open_ports)} open ports on {target}")
    
    def _execute_web_recon(
        self, 
        targets: List[str], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ):
        """Execute web application reconnaissance"""
        self._log("Starting web reconnaissance")
        
        for target in targets:
            # Skip if it's not a web target
            if not (target.startswith('http://') or target.startswith('https://')):
                # Try to construct URL
                if not self._is_ip_address(target) and '.' in target:
                    url = f"https://{target}"
                else:
                    continue
            else:
                url = target
            
            self._log(f"Probing web target: {url}")
            
            try:
                # Try HTTPS first
                if not url.startswith('https://'):
                    url = f"https://{url}"
                
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                self._log(f"  Status: {response.status_code}")
                self._log(f"  Server: {response.headers.get('Server', 'Unknown')}")
                self._log(f"  Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
                
                # Add finding for web server
                self.add_finding(
                    finding_id=f"web-server-{target}",
                    title=f"Web Server: {url}",
                    description=f"Web server at {url} returned status {response.status_code}. Server: {response.headers.get('Server', 'Unknown')}",
                    severity=FindingSeverity.INFO,
                    evidence={
                        'url': url,
                        'status_code': response.status_code,
                        'server': response.headers.get('Server'),
                        'content_type': response.headers.get('Content-Type')
                    }
                )
                
                # Collect evidence
                if evidence_collector:
                    evidence_collector.collect_log(
                        attack_id="current",
                        log_data=f"Web server: {url} - {response.status_code} - {response.headers.get('Server', 'Unknown')}",
                        log_type="web",
                        description=f"Web server information for {url}"
                    )
                    
                # Check for common web vulnerabilities
                self._check_web_vulnerabilities(url, response, evidence_collector)
                
            except requests.exceptions.SSLError:
                # Try HTTP
                try:
                    http_url = url.replace('https://', 'http://')
                    response = requests.get(http_url, timeout=self.timeout)
                    
                    self._log(f"  HTTP Status: {response.status_code}")
                    self._log(f"  HTTP Server: {response.headers.get('Server', 'Unknown')}")
                    
                    self.add_finding(
                        finding_id=f"web-server-http-{target}",
                        title=f"Web Server (HTTP): {http_url}",
                        description=f"Web server at {http_url} returned status {response.status_code}. Server: {response.headers.get('Server', 'Unknown')}",
                        severity=FindingSeverity.INFO,
                        evidence={
                            'url': http_url,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server'),
                            'content_type': response.headers.get('Content-Type'),
                            'protocol': 'http'
                        }
                    )
                    
                except Exception as e:
                    self._log(f"  Error probing HTTP: {e}")
                    
            except Exception as e:
                self._log(f"  Error probing web target {url}: {e}")
    
    def _execute_network_recon(
        self, 
        targets: List[str], 
        params: Dict[str, Any], 
        evidence_collector: Any = None
    ):
        """Execute network reconnaissance"""
        self._log("Starting network reconnaissance")
        
        # This would include network topology mapping, traceroute, etc.
        # For now, we'll just log that it's not implemented
        self._log("Network reconnaissance not fully implemented")
    
    def _check_port(self, target: str, port: int) -> bool:
        """Check if a port is open on a target"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if a target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _get_port_severity(self, port: int) -> FindingSeverity:
        """Get severity level for a port based on common services"""
        # High risk ports
        high_risk_ports = [22, 23, 3389, 5900, 1521, 1433, 3306]
        if port in high_risk_ports:
            return FindingSeverity.HIGH
        
        # Medium risk ports
        medium_risk_ports = [21, 25, 110, 135, 139, 445, 465, 587, 993, 995]
        if port in medium_risk_ports:
            return FindingSeverity.MEDIUM
        
        # Web ports
        if port in [80, 443, 8080, 8443]:
            return FindingSeverity.MEDIUM
        
        return FindingSeverity.INFO
    
    def _check_web_vulnerabilities(
        self, 
        url: str, 
        response: requests.Response, 
        evidence_collector: Any = None
    ):
        """Check for common web vulnerabilities"""
        # Check for default pages
        default_pages = ['index.html', 'default.aspx', 'login.php', 'admin.php']
        
        # Check for common headers that might indicate vulnerabilities
        headers = response.headers
        
        # Check for server version disclosure
        server = headers.get('Server', '')
        if server:
            # Check for outdated servers
            outdated_servers = ['Apache/2.2', 'IIS/6.0', 'IIS/7.0', 'nginx/1.']
            for outdated in outdated_servers:
                if outdated in server:
                    self.add_finding(
                        finding_id=f"web-vuln-server-{url}",
                        title=f"Outdated Web Server: {server}",
                        description=f"Web server {server} may be outdated and vulnerable",
                        severity=FindingSeverity.MEDIUM,
                        evidence={'url': url, 'server': server},
                        remediation="Upgrade to the latest version of the web server"
                    )
                    break
        
        # Check for X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            outdated_tech = ['PHP/5.', 'ASP.NET']
            for tech in outdated_tech:
                if tech in powered_by:
                    self.add_finding(
                        finding_id=f"web-vuln-tech-{url}",
                        title=f"Outdated Technology: {powered_by}",
                        description=f"Technology {powered_by} may be outdated and vulnerable",
                        severity=FindingSeverity.LOW,
                        evidence={'url': url, 'technology': powered_by},
                        remediation="Upgrade to the latest version of the technology"
                    )
                    break
