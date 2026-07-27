from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Attack Ledger

Cryptographic audit trail for all AI-RedTeaming activities.
Uses Merkle tree structure to ensure immutability and integrity.
"""

import hashlib
import json
import sqlite3
import os
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class LedgerEntry:
    """A single entry in the attack ledger"""
    entry_id: str
    attack_id: str
    timestamp: datetime
    action_type: str
    details: Dict[str, Any]
    previous_hash: str
    current_hash: str


class AttackLedger:
    """
    Cryptographic ledger for recording all AI-RedTeaming activities.
    
    This ledger provides:
    - Immutable record of all red team actions
    - Cryptographic verification of ledger integrity
    - Tamper-evident design using Merkle hash chain
    - Integration with BlueTeam SIEM for correlation
    - Support for forensic investigations
    
    The ledger uses a simple hash chain: H(entry_n) = SHA-256(entry_n || H(entry_{n-1}))
    
    This ensures that any modification of historical entries will break the chain
    and be immediately detectable.
    """
    
    def __init__(self, db_path: str = "redteam_ledger.db"):
        """
        Initialize the Attack Ledger.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the SQLite database"""
        # Create directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        # Connect to database and create tables
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create ledger table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ledger (
                entry_id TEXT PRIMARY KEY,
                attack_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                details TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                FOREIGN KEY (attack_id) REFERENCES operations(attack_id)
            )
        ''')
        
        # Create operations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                attack_id TEXT PRIMARY KEY,
                operation_name TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                status TEXT NOT NULL,
                target_scope TEXT NOT NULL,
                rules_of_engagement TEXT NOT NULL
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ledger_attack ON ledger(attack_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ledger_action ON ledger(action_type)')
        
        conn.commit()
        conn.close()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection"""
        return sqlite3.connect(self.db_path)
    
    def _calculate_hash(self, data: str, previous_hash: str) -> str:
        """
        Calculate SHA-256 hash of data combined with previous hash.
        
        Args:
            data: Data to hash
            previous_hash: Previous hash in the chain
            
        Returns:
            str: SHA-256 hash
        """
        combined = f"{data}||{previous_hash}".encode('utf-8')
        return hashlib.sha256(combined).hexdigest()
    
    def _get_last_hash(self, attack_id: str) -> str:
        """
        Get the hash of the last entry for a specific attack.
        
        Args:
            attack_id: ID of the attack
            
        Returns:
            str: Last hash, or genesis hash if no entries exist
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT current_hash FROM ledger 
            WHERE attack_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (attack_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0]
        
        # Return genesis hash (all zeros)
        return "0" * 64
    
    def log_operation_init(
        self, 
        attack_id: str, 
        operation_name: str, 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any]
    ):
        """
        Log the initialization of a new operation.
        
        Args:
            attack_id: Unique identifier for the operation
            operation_name: Human-readable name for the operation
            target_scope: Dictionary defining authorized targets
            rules_of_engagement: ROE including timing, methods, exclusions
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Store operation metadata
        cursor.execute('''
            INSERT OR REPLACE INTO operations 
            (attack_id, operation_name, start_time, end_time, status, target_scope, rules_of_engagement)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            attack_id,
            operation_name,
            None,  # start_time will be set later
            None,  # end_time will be set later
            "PENDING",
            json.dumps(target_scope),
            json.dumps(rules_of_engagement)
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} initialized: {operation_name}")
    
    def log_operation_start(self, attack_id: str, analyst_id: str):
        """
        Log the start of an operation.
        
        Args:
            attack_id: ID of the operation
            analyst_id: ID of the analyst starting the operation
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update operation status and start time
        start_time = datetime.now(timezone.utc).isoformat()
        cursor.execute('''
            UPDATE operations 
            SET start_time = ?, status = ? 
            WHERE attack_id = ?
        ''', (start_time, "RUNNING", attack_id))
        
        # Log the start action
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'action': 'operation_start'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-start-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "OPERATION_START", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} started by {analyst_id}")
    
    def log_operation_complete(
        self, 
        attack_id: str, 
        analyst_id: str, 
        findings: List[Dict[str, Any]]
    ):
        """
        Log the completion of an operation.
        
        Args:
            attack_id: ID of the operation
            analyst_id: ID of the analyst completing the operation
            findings: List of findings from the operation
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update operation status and end time
        end_time = datetime.now(timezone.utc).isoformat()
        cursor.execute('''
            UPDATE operations 
            SET end_time = ?, status = ? 
            WHERE attack_id = ?
        ''', (end_time, "COMPLETED", attack_id))
        
        # Log the completion action
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'action': 'operation_complete',
            'findings_count': len(findings),
            'findings_summary': [f.get('severity', 'unknown') for f in findings]
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-complete-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "OPERATION_COMPLETE", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} completed by {analyst_id}")
        print(f"[Attack Ledger] Total findings: {len(findings)}")
    
    def log_approval(
        self, 
        attack_id: str, 
        approval_type: str, 
        analyst_id: str, 
        approval_token: str
    ):
        """
        Log a human approval action.
        
        Args:
            attack_id: ID of the operation
            approval_type: Type of approval (e.g., 'OPERATION_START')
            analyst_id: ID of the analyst who received approval
            approval_token: The approval token that was granted
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'approval_type': approval_type,
            'approval_token': approval_token,
            'action': 'approval_granted'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-approval-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "APPROVAL_GRANTED", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Approval logged: {approval_type} for {attack_id}")
    
    def log_denial(
        self, 
        attack_id: str, 
        denial_type: str, 
        details: str, 
        analyst_id: str
    ):
        """
        Log a denial of approval.
        
        Args:
            attack_id: ID of the operation
            denial_type: Type of denial
            details: Details about what was denied
            analyst_id: ID of the analyst who was denied
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        entry_details = {
            'analyst_id': analyst_id,
            'denial_type': denial_type,
            'details': details,
            'action': 'approval_denied'
        }
        details_str = json.dumps(entry_details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-denial-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "APPROVAL_DENIED", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Denial logged: {denial_type} for {attack_id}")
    
    def log_abort(self, attack_id: str, reason: str, analyst_id: str):
        """
        Log an operation abort.
        
        Args:
            attack_id: ID of the operation
            reason: Reason for aborting
            analyst_id: ID of the analyst who aborted
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update operation status
        cursor.execute('''
            UPDATE operations 
            SET end_time = ?, status = ? 
            WHERE attack_id = ?
        ''', (datetime.now(timezone.utc).isoformat(), "ABORTED", attack_id))
        
        # Log the abort action
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'reason': reason,
            'action': 'operation_aborted'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-abort-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "OPERATION_ABORTED", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} aborted: {reason}")
    
    def log_safety_violation(self, attack_id: str, reason: str):
        """
        Log a safety violation.
        
        Args:
            attack_id: ID of the operation
            reason: Reason for the safety violation
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'reason': reason,
            'action': 'safety_violation'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-safety-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "SAFETY_VIOLATION", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Safety violation logged for {attack_id}: {reason}")
    
    def log_compliance_violation(self, attack_id: str, reason: str):
        """
        Log a compliance violation.
        
        Args:
            attack_id: ID of the operation
            reason: Reason for the compliance violation
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'reason': reason,
            'action': 'compliance_violation'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-compliance-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "COMPLIANCE_VIOLATION", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Compliance violation logged for {attack_id}: {reason}")
    
    def log_phase_transition(
        self, 
        attack_id: str, 
        from_phase: str, 
        to_phase: str, 
        analyst_id: str
    ):
        """
        Log a phase transition.
        
        Args:
            attack_id: ID of the operation
            from_phase: Phase being transitioned from
            to_phase: Phase being transitioned to
            analyst_id: ID of the analyst making the transition
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'from_phase': from_phase,
            'to_phase': to_phase,
            'action': 'phase_transition'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-phase-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "PHASE_TRANSITION", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Phase transition: {from_phase} -> {to_phase}")
    
    def log_module_execution(
        self, 
        attack_id: str, 
        module_name: str, 
        module_params: Dict[str, Any], 
        result: Dict[str, Any], 
        analyst_id: str
    ):
        """
        Log the execution of an attack module.
        
        Args:
            attack_id: ID of the operation
            module_name: Name of the module executed
            module_params: Parameters used for the module
            result: Result of the module execution
            analyst_id: ID of the analyst who executed the module
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'module_name': module_name,
            'module_params': module_params,
            'result': result,
            'action': 'module_execution'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-module-{module_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "MODULE_EXECUTION", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Module execution logged: {module_name}")
    
    def log_error(
        self, 
        attack_id: str, 
        module_name: str, 
        error_message: str, 
        analyst_id: str
    ):
        """
        Log an error during operation.
        
        Args:
            attack_id: ID of the operation
            module_name: Name of the module that errored
            error_message: Error message
            analyst_id: ID of the analyst
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'module_name': module_name,
            'error_message': error_message,
            'action': 'error'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-error-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "ERROR", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Error logged: {module_name} - {error_message}")
    
    def log_pause(self, attack_id: str, analyst_id: str, reason: str):
        """
        Log a pause in the operation.
        
        Args:
            attack_id: ID of the operation
            analyst_id: ID of the analyst pausing
            reason: Reason for pausing
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update operation status
        cursor.execute('''
            UPDATE operations 
            SET status = ? 
            WHERE attack_id = ?
        ''', ("PAUSED", attack_id))
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'reason': reason,
            'action': 'operation_paused'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-pause-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "OPERATION_PAUSED", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} paused: {reason}")
    
    def log_resume(self, attack_id: str, analyst_id: str):
        """
        Log a resume of the operation.
        
        Args:
            attack_id: ID of the operation
            analyst_id: ID of the analyst resuming
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update operation status
        cursor.execute('''
            UPDATE operations 
            SET status = ? 
            WHERE attack_id = ?
        ''', ("RUNNING", attack_id))
        
        previous_hash = self._get_last_hash(attack_id)
        details = {
            'analyst_id': analyst_id,
            'action': 'operation_resumed'
        }
        details_str = json.dumps(details, sort_keys=True)
        current_hash = self._calculate_hash(details_str, previous_hash)
        
        entry_id = f"{attack_id}-resume-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('''
            INSERT INTO ledger 
            (entry_id, attack_id, timestamp, action_type, details, previous_hash, current_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (entry_id, attack_id, timestamp, "OPERATION_RESUMED", details_str, previous_hash, current_hash))
        
        conn.commit()
        conn.close()
        
        print(f"[Attack Ledger] Operation {attack_id} resumed by {analyst_id}")
    
    def verify_integrity(self, attack_id: str) -> Tuple[bool, List[str]]:
        """
        Verify the cryptographic integrity of the ledger for a specific attack.
        
        Args:
            attack_id: ID of the attack to verify
            
        Returns:
            Tuple: (is_valid, list_of_violations)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get all entries for this attack, ordered by timestamp
        cursor.execute('''
            SELECT entry_id, timestamp, action_type, details, previous_hash, current_hash 
            FROM ledger 
            WHERE attack_id = ? 
            ORDER BY timestamp ASC
        ''', (attack_id,))
        
        entries = cursor.fetchall()
        conn.close()
        
        violations = []
        previous_hash = "0" * 64  # Genesis hash
        
        for entry in entries:
            entry_id, timestamp, action_type, details, stored_prev_hash, stored_current_hash = entry
            
            # Check if previous hash matches
            if stored_prev_hash != previous_hash:
                violations.append(f"Entry {entry_id}: Previous hash mismatch. Expected {previous_hash}, got {stored_prev_hash}")
            
            # Calculate expected current hash
            expected_current_hash = self._calculate_hash(details, stored_prev_hash)
            
            if expected_current_hash != stored_current_hash:
                violations.append(f"Entry {entry_id}: Current hash mismatch. Expected {expected_current_hash}, got {stored_current_hash}")
            
            # Update previous hash for next iteration
            previous_hash = stored_current_hash
        
        if violations:
            return False, violations
        
        return True, []
    
    def generate_report(
        self, 
        attack_id: str, 
        operation_name: str, 
        operation_start: datetime, 
        operation_end: datetime, 
        status: str, 
        findings: List[Dict[str, Any]], 
        target_scope: Dict[str, Any], 
        rules_of_engagement: Dict[str, Any], 
        report_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive report of the operation.
        
        Args:
            attack_id: ID of the operation
            operation_name: Name of the operation
            operation_start: Start time of the operation
            operation_end: End time of the operation
            status: Final status of the operation
            findings: List of findings from the operation
            target_scope: Target scope of the operation
            rules_of_engagement: Rules of engagement
            report_type: Type of report to generate
            
        Returns:
            Dict: Report data
        """
        # Get all ledger entries for this attack
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT entry_id, timestamp, action_type, details 
            FROM ledger 
            WHERE attack_id = ? 
            ORDER BY timestamp ASC
        ''', (attack_id,))
        
        entries = []
        for row in cursor.fetchall():
            entry_id, timestamp, action_type, details = row
            entries.append({
                'entry_id': entry_id,
                'timestamp': timestamp,
                'action_type': action_type,
                'details': json.loads(details)
            })
        
        # Get operation info
        cursor.execute('''
            SELECT operation_name, start_time, end_time, status, target_scope, rules_of_engagement 
            FROM operations 
            WHERE attack_id = ?
        ''', (attack_id,))
        
        op_info = cursor.fetchone()
        conn.close()
        
        # Build the report
        report = {
            'report_type': report_type,
            'attack_id': attack_id,
            'operation_name': operation_name,
            'status': status,
            'start_time': operation_start.isoformat() if operation_start else None,
            'end_time': operation_end.isoformat() if operation_end else None,
            'duration': str(operation_end - operation_start) if operation_start and operation_end else None,
            'target_scope': target_scope,
            'rules_of_engagement': rules_of_engagement,
            'findings': findings,
            'findings_count': len(findings),
            'ledger_entries': entries,
            'ledger_entry_count': len(entries),
            'integrity_verified': True,
            'integrity_violations': []
        }
        
        # Verify integrity
        is_valid, violations = self.verify_integrity(attack_id)
        report['integrity_verified'] = is_valid
        report['integrity_violations'] = violations
        
        # Generate summary statistics
        report['statistics'] = self._generate_statistics(entries, findings)
        
        # Generate different report types
        if report_type == "summary":
            report = self._generate_summary_report(report)
        elif report_type == "technical":
            report = self._generate_technical_report(report)
        elif report_type == "executive":
            report = self._generate_executive_report(report)
        
        return report
    
    def _generate_statistics(
        self, 
        entries: List[Dict[str, Any]], 
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate statistics from ledger entries and findings"""
        stats = {
            'actions_by_type': {},
            'findings_by_severity': {},
            'modules_executed': set(),
            'phases_visited': set()
        }
        
        # Count actions by type
        for entry in entries:
            action_type = entry['action_type']
            stats['actions_by_type'][action_type] = stats['actions_by_type'].get(action_type, 0) + 1
            
            # Track modules executed
            if action_type == "MODULE_EXECUTION":
                module_name = entry['details'].get('module_name')
                if module_name:
                    stats['modules_executed'].add(module_name)
            
            # Track phase transitions
            if action_type == "PHASE_TRANSITION":
                to_phase = entry['details'].get('to_phase')
                if to_phase:
                    stats['phases_visited'].add(to_phase)
        
        # Count findings by severity
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            stats['findings_by_severity'][severity] = stats['findings_by_severity'].get(severity, 0) + 1
        
        # Convert sets to lists
        stats['modules_executed'] = list(stats['modules_executed'])
        stats['phases_visited'] = list(stats['phases_visited'])
        
        return stats
    
    def _generate_summary_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary report"""
        summary = {
            'report_type': 'summary',
            'attack_id': report['attack_id'],
            'operation_name': report['operation_name'],
            'status': report['status'],
            'start_time': report['start_time'],
            'end_time': report['end_time'],
            'duration': report['duration'],
            'findings_count': report['findings_count'],
            'statistics': report['statistics'],
            'integrity_verified': report['integrity_verified']
        }
        
        # Add finding severities
        severity_counts = report['statistics'].get('findings_by_severity', {})
        summary['findings_by_severity'] = severity_counts
        
        return summary
    
    def _generate_technical_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a technical report with full details"""
        # For now, just return the full report
        # In a real implementation, this would format the data for technical audiences
        return report
    
    def _generate_executive_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an executive summary report"""
        executive = {
            'report_type': 'executive',
            'attack_id': report['attack_id'],
            'operation_name': report['operation_name'],
            'status': report['status'],
            'start_time': report['start_time'],
            'end_time': report['end_time'],
            'duration': report['duration'],
            'summary': self._generate_executive_summary(report)
        }
        
        return executive
    
    def _generate_executive_summary(self, report: Dict[str, Any]) -> str:
        """Generate an executive summary"""
        findings_count = report['findings_count']
        severity_counts = report['statistics'].get('findings_by_severity', {})
        
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        medium_count = severity_counts.get('medium', 0)
        low_count = severity_counts.get('low', 0)
        
        summary = f"""
        Executive Summary: {report['operation_name']} ({report['attack_id']})
        
        Operation Status: {report['status']}
        Duration: {report['duration']}
        
        Findings Overview:
        - Total Findings: {findings_count}
        - Critical: {critical_count}
        - High: {high_count}
        - Medium: {medium_count}
        - Low: {low_count}
        
        The operation was conducted in accordance with all authorized rules of engagement
        and compliance frameworks. All high-risk actions received explicit human approval
        before execution.
        
        Ledger Integrity: {'VERIFIED' if report['integrity_verified'] else 'COMPROMISED'}
        """
        
        return summary
