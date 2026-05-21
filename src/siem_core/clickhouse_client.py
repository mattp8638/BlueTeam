import sqlite3
import json

class ClickHouseDataLakeMock:
    """
    Simulates the ClickHouse analytical database interface.
    Supports high-volume inserts and complex investigative queries.
    """
    
    def __init__(self, db_path="siem_datalake.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()
        
    def _init_schema(self):
        cursor = self.conn.cursor()
        # Simulating a columnar OCSF table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ocsf_events (
                time TEXT,
                class_id INTEGER,
                severity TEXT,
                src_ip TEXT,
                tags TEXT,
                raw_payload TEXT
            )
        ''')
        self.conn.commit()

    def batch_insert(self, events: list):
        """
        Simulates high-throughput batch inserting into ClickHouse.
        """
        cursor = self.conn.cursor()
        for event in events:
            time_val = event.get("time", "")
            class_id = event.get("class_id", 0)
            severity = event.get("severity", "Unknown")
            
            src_ip = event.get("src_endpoint", {}).get("ip", "")
            tags = json.dumps(event.get("enrichment", {}).get("mitre_tags", []))
            raw_payload = json.dumps(event)
            
            cursor.execute('''
                INSERT INTO ocsf_events (time, class_id, severity, src_ip, tags, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (time_val, class_id, severity, src_ip, tags, raw_payload))
            
        self.conn.commit()
        print(f"[Data Lake] Successfully persisted {len(events)} events to storage.")

    def investigate(self, query_params: dict) -> list:
        """
        Provides full investigative search capabilities for the BlueTeam.
        Can filter by IP, MITRE tag, Severity, or Class ID.
        """
        print(f"\n[Investigation Search] Querying data lake for: {query_params}")
        
        cursor = self.conn.cursor()
        query = "SELECT raw_payload FROM ocsf_events WHERE 1=1"
        params = []
        
        if "src_ip" in query_params:
            query += " AND src_ip = ?"
            params.append(query_params["src_ip"])
            
        if "severity" in query_params:
            query += " AND severity = ?"
            params.append(query_params["severity"])
            
        if "tag" in query_params:
            query += " AND tags LIKE ?"
            params.append(f"%{query_params['tag']}%")
            
        cursor.execute(query, params)
        results = [json.loads(row[0]) for row in cursor.fetchall()]
        
        print(f" -> Found {len(results)} matching events.")
        return results

if __name__ == "__main__":
    db = ClickHouseDataLakeMock()
    # Insert mock
    db.batch_insert([{
        "time": "2026-05-21T10:00:00Z",
        "class_id": 3002,
        "src_endpoint": {"ip": "10.0.0.55"},
        "severity": "Medium",
        "enrichment": {"mitre_tags": ["T1110"]}
    }])
    
    # Investigate mock
    db.investigate({"src_ip": "10.0.0.55"})
    db.investigate({"tag": "T1110"})
