import sqlite3
import json

class AssetInventory:
    """
    Simulates a Configuration Management Database (CMDB).
    Catalogues endpoints (Device ID, OS, IP) and tracks their known vulnerabilities.
    """
    
    def __init__(self, db_path="asset_inventory.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()
        
    def _init_schema(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                os_family TEXT,
                os_version TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                cve_id TEXT,
                severity TEXT,
                evidence_payload TEXT,
                status TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(device_id)
            )
        ''')
        self.conn.commit()

    def register_device(self, device_data: dict):
        """Registers a new device into the catalogue."""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO devices (device_id, hostname, ip_address, os_family, os_version)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            device_data.get("device_id"),
            device_data.get("hostname"),
            device_data.get("ip_address"),
            device_data.get("os_family"),
            device_data.get("os_version")
        ))
        self.conn.commit()
        
    def attach_vulnerability(self, device_id: str, ocsf_finding: dict):
        """Attaches an OCSF Class 2002 vulnerability finding to a specific device."""
        cursor = self.conn.cursor()
        
        vulnerabilities = ocsf_finding.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve", {}).get("uid", "UNKNOWN")
            severity = ocsf_finding.get("severity", "Unknown")
            
            # Extract forensic evidence
            evidence = ocsf_finding.get("enrichments", [])
            evidence_json = json.dumps(evidence)
            
            cursor.execute('''
                INSERT INTO device_vulnerabilities (device_id, cve_id, severity, evidence_payload, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (device_id, cve_id, severity, evidence_json, "ACTIVE"))
            
        self.conn.commit()
        print(f"[Asset Inventory] Attached {len(vulnerabilities)} vulnerabilities to Device {device_id}.")

    def get_device_vulnerabilities(self, device_id: str) -> list:
        """Retrieves all active vulnerabilities for a given device."""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT cve_id, severity, evidence_payload FROM device_vulnerabilities 
            WHERE device_id = ? AND status = 'ACTIVE'
        ''', (device_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "cve_id": row[0],
                "severity": row[1],
                "evidence": json.loads(row[2])
            })
        return results
