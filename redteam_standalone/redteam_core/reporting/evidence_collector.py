from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Evidence Collector

Forensic evidence collection and preservation for AI-RedTeaming operations.
"""

import os
import json
import hashlib
import shutil
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvidenceItem:
    """A single piece of forensic evidence"""
    evidence_id: str
    attack_id: str
    timestamp: datetime
    evidence_type: str
    description: str
    file_path: str
    file_hash: str
    metadata: Dict[str, Any]


class EvidenceCollector:
    """
    Forensic evidence collector for AI-RedTeaming operations.
    
    This module provides:
    - Secure collection of forensic evidence
    - Cryptographic hash verification
    - Chain of custody tracking
    - Evidence preservation and integrity
    - Integration with attack ledger
    - Support for multiple evidence types
    
    Evidence types supported:
    - Screenshots
    - Log files
    - Network captures
    - Memory dumps
    - File system artifacts
    - Command output
    - Configuration files
    - Database records
    """
    
    def __init__(self, evidence_dir: str = "evidence"):
        """
        Initialize the Evidence Collector.
        
        Args:
            evidence_dir: Directory to store evidence
        """
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Track collected evidence
        self._evidence_index: Dict[str, EvidenceItem] = {}
        
        # Chain of custody
        self._chain_of_custody: List[Dict[str, Any]] = []
    
    def collect_evidence(
        self, 
        attack_id: str, 
        evidence_type: str, 
        data: Any, 
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect a piece of evidence.
        
        Args:
            attack_id: ID of the attack/operation
            evidence_type: Type of evidence (e.g., 'screenshot', 'log', 'pcap')
            data: The evidence data (can be bytes, string, or file path)
            description: Human-readable description of the evidence
            metadata: Additional metadata about the evidence
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        # Generate unique evidence ID
        evidence_id = f"{attack_id}-evidence-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc)
        
        # Create evidence directory for this attack
        attack_evidence_dir = self.evidence_dir / attack_id
        attack_evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine file path and save the data
        file_extension = self._get_file_extension(evidence_type)
        file_name = f"{evidence_id}{file_extension}"
        file_path = attack_evidence_dir / file_name
        
        # Save the data
        if isinstance(data, bytes):
            with open(file_path, 'wb') as f:
                f.write(data)
        elif isinstance(data, str):
            # If it's a file path, copy the file
            if os.path.exists(data):
                shutil.copy2(data, file_path)
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(data)
        else:
            # For other types, convert to JSON
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        # Create evidence item
        evidence_item = EvidenceItem(
            evidence_id=evidence_id,
            attack_id=attack_id,
            timestamp=timestamp,
            evidence_type=evidence_type,
            description=description,
            file_path=str(file_path),
            file_hash=file_hash,
            metadata=metadata or {}
        )
        
        # Store in index
        self._evidence_index[evidence_id] = evidence_item
        
        # Add to chain of custody
        self._add_to_chain_of_custody(
            evidence_id=evidence_id,
            attack_id=attack_id,
            action="COLLECTED",
            timestamp=timestamp,
            details={
                'evidence_type': evidence_type,
                'description': description,
                'file_path': str(file_path),
                'file_hash': file_hash
            }
        )
        
        print(f"[Evidence Collector] Collected evidence: {evidence_id}")
        print(f"[Evidence Collector] Type: {evidence_type}")
        print(f"[Evidence Collector] Path: {file_path}")
        print(f"[Evidence Collector] Hash: {file_hash}")
        
        return evidence_item
    
    def collect_screenshot(
        self, 
        attack_id: str, 
        image_data: bytes, 
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect a screenshot as evidence.
        
        Args:
            attack_id: ID of the attack/operation
            image_data: Screenshot image data (bytes)
            description: Description of the screenshot
            metadata: Additional metadata
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        return self.collect_evidence(
            attack_id=attack_id,
            evidence_type="screenshot",
            data=image_data,
            description=description,
            metadata=metadata
        )
    
    def collect_log(
        self, 
        attack_id: str, 
        log_data: str, 
        log_type: str = "general",
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect log data as evidence.
        
        Args:
            attack_id: ID of the attack/operation
            log_data: Log data (string)
            log_type: Type of log (e.g., 'system', 'application', 'security')
            description: Description of the log
            metadata: Additional metadata
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        metadata = metadata or {}
        metadata['log_type'] = log_type
        
        return self.collect_evidence(
            attack_id=attack_id,
            evidence_type="log",
            data=log_data,
            description=description,
            metadata=metadata
        )
    
    def collect_network_capture(
        self, 
        attack_id: str, 
        pcap_data: bytes, 
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect network capture data as evidence.
        
        Args:
            attack_id: ID of the attack/operation
            pcap_data: Network capture data (bytes)
            description: Description of the capture
            metadata: Additional metadata
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        return self.collect_evidence(
            attack_id=attack_id,
            evidence_type="pcap",
            data=pcap_data,
            description=description,
            metadata=metadata
        )
    
    def collect_file(
        self, 
        attack_id: str, 
        file_path: str, 
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect a file as evidence.
        
        Args:
            attack_id: ID of the attack/operation
            file_path: Path to the file to collect
            description: Description of the file
            metadata: Additional metadata
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        return self.collect_evidence(
            attack_id=attack_id,
            evidence_type="file",
            data=file_path,
            description=description,
            metadata=metadata
        )
    
    def collect_command_output(
        self, 
        attack_id: str, 
        command: str, 
        output: str, 
        description: str = "",
        metadata: Dict[str, Any] = None
    ) -> EvidenceItem:
        """
        Collect command output as evidence.
        
        Args:
            attack_id: ID of the attack/operation
            command: The command that was executed
            output: The output from the command
            description: Description of the command output
            metadata: Additional metadata
            
        Returns:
            EvidenceItem: The collected evidence item
        """
        metadata = metadata or {}
        metadata['command'] = command
        metadata['exit_code'] = metadata.get('exit_code', 0)
        
        return self.collect_evidence(
            attack_id=attack_id,
            evidence_type="command_output",
            data=output,
            description=description,
            metadata=metadata
        )
    
    def get_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        """
        Retrieve a specific evidence item.
        
        Args:
            evidence_id: ID of the evidence to retrieve
            
        Returns:
            EvidenceItem: The evidence item, or None if not found
        """
        return self._evidence_index.get(evidence_id)
    
    def get_evidence_by_attack(self, attack_id: str) -> List[EvidenceItem]:
        """
        Get all evidence for a specific attack.
        
        Args:
            attack_id: ID of the attack
            
        Returns:
            List[EvidenceItem]: All evidence items for the attack
        """
        return [evidence for evidence in self._evidence_index.values() 
                if evidence.attack_id == attack_id]
    
    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """
        Verify the integrity of a specific evidence item.
        
        Args:
            evidence_id: ID of the evidence to verify
            
        Returns:
            bool: True if evidence is intact
        """
        evidence = self._evidence_index.get(evidence_id)
        if not evidence:
            return False
        
        # Recalculate hash and compare
        current_hash = self._calculate_file_hash(evidence.file_path)
        return current_hash == evidence.file_hash
    
    def verify_all_evidence_integrity(self, attack_id: str) -> Dict[str, bool]:
        """
        Verify the integrity of all evidence for a specific attack.
        
        Args:
            attack_id: ID of the attack
            
        Returns:
            Dict: Mapping of evidence_id to integrity status
        """
        results = {}
        evidence_items = self.get_evidence_by_attack(attack_id)
        
        for evidence in evidence_items:
            results[evidence.evidence_id] = self.verify_evidence_integrity(evidence.evidence_id)
        
        return results
    
    def get_chain_of_custody(self, attack_id: str = None) -> List[Dict[str, Any]]:
        """
        Get the chain of custody for all evidence or for a specific attack.
        
        Args:
            attack_id: Optional ID of the attack to filter by
            
        Returns:
            List[Dict]: Chain of custody records
        """
        if attack_id:
            return [record for record in self._chain_of_custody 
                    if record.get('attack_id') == attack_id]
        
        return self._chain_of_custody.copy()
    
    def export_evidence_package(
        self, 
        attack_id: str, 
        output_dir: str = None, 
        include_metadata: bool = True
    ) -> str:
        """
        Export all evidence for an attack as a package.
        
        Args:
            attack_id: ID of the attack
            output_dir: Directory to export to (default: temp directory)
            include_metadata: Whether to include metadata files
            
        Returns:
            str: Path to the exported package
        """
        # Create output directory
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix=f"evidence-{attack_id}-")
        else:
            output_dir = Path(output_dir) / attack_id
            output_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = Path(output_dir)
        
        # Copy all evidence files
        evidence_items = self.get_evidence_by_attack(attack_id)
        
        for evidence in evidence_items:
            src_path = Path(evidence.file_path)
            dst_path = output_path / src_path.name
            shutil.copy2(src_path, dst_path)
        
        # Create metadata file
        if include_metadata:
            metadata = {
                'attack_id': attack_id,
                'export_time': datetime.now(timezone.utc).isoformat(),
                'evidence_count': len(evidence_items),
                'evidence_items': [
                    {
                        'evidence_id': e.evidence_id,
                        'timestamp': e.timestamp.isoformat(),
                        'evidence_type': e.evidence_type,
                        'description': e.description,
                        'file_name': Path(e.file_path).name,
                        'file_hash': e.file_hash,
                        'metadata': e.metadata
                    }
                    for e in evidence_items
                ],
                'chain_of_custody': self.get_chain_of_custody(attack_id)
            }
            
            metadata_path = output_path / "metadata.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
        
        # Create a tar.gz archive
        archive_path = output_path.parent / f"{attack_id}-evidence.tar.gz"
        shutil.make_archive(str(archive_path.with_suffix('')), 'gztar', output_path)
        
        # Clean up temporary directory if we created it
        if output_dir is None:
            shutil.rmtree(output_path)
        
        print(f"[Evidence Collector] Evidence package exported: {archive_path}")
        
        return str(archive_path)
    
    def _get_file_extension(self, evidence_type: str) -> str:
        """Get file extension for evidence type"""
        extensions = {
            'screenshot': '.png',
            'log': '.log',
            'pcap': '.pcap',
            'file': '.dat',
            'command_output': '.txt',
            'memory_dump': '.dump',
            'configuration': '.conf',
            'database': '.db'
        }
        return extensions.get(evidence_type, '.dat')
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _add_to_chain_of_custody(
        self, 
        evidence_id: str, 
        attack_id: str, 
        action: str, 
        timestamp: datetime, 
        details: Dict[str, Any]
    ):
        """Add an entry to the chain of custody"""
        entry = {
            'evidence_id': evidence_id,
            'attack_id': attack_id,
            'action': action,
            'timestamp': timestamp.isoformat(),
            'details': details
        }
        self._chain_of_custody.append(entry)
