import uuid
from datetime import datetime, timezone
from src.ir_core.database import IRDatabase
from src.ir_core.merkle_ledger import MerkleLedger

class TokenClusteringEngine:
    """
    Groups discrete SIEM alerts matching identical target signatures into a single root record.
    Prevents alert fatigue during high-volume spikes.
    """
    
    @classmethod
    def ingest_alert(cls, alert: dict) -> str:
        """
        Ingests an OCSF alert. Uses token matching (e.g. target IP + class_id) 
        to find an existing open ticket, or creates a new one.
        Returns the ticket_id.
        """
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        target_ip = alert.get("src_endpoint_ip") or alert.get("event", {}).get("src_endpoint_ip")
        class_id = alert.get("class_id")
        
        # Simple clustering logic: Are there any OPEN tickets containing this IP in the payload?
        if target_ip:
            cursor.execute("SELECT ticket_id FROM tickets WHERE status = 'OPEN'")
            open_tickets = cursor.fetchall()
            
            for (ticket_id,) in open_tickets:
                # Check ledger for this ticket to see if the IP is already tracked
                cursor.execute("SELECT payload FROM ledger WHERE ticket_id = ?", (ticket_id,))
                for (payload_str,) in cursor.fetchall():
                    if target_ip in payload_str:
                        print(f"[Clustering] Matched alert to existing ticket: {ticket_id}")
                        # Append sub-alert
                        MerkleLedger.append_transaction(ticket_id, "ALERT_APPEND", alert)
                        return ticket_id
                        
        # If no cluster found, create a new root ticket
        return cls._create_root_ticket(alert)

    @classmethod
    def _create_root_ticket(cls, alert: dict) -> str:
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        ticket_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        title = f"Root Incident: OCSF Class {alert.get('class_id')}"
        severity = alert.get("severity", "Medium")
        
        cursor.execute(
            "INSERT INTO tickets (ticket_id, title, status, severity, created_at) VALUES (?, ?, ?, ?, ?)",
            (ticket_id, title, "OPEN", severity, now)
        )
        conn.commit()
        
        print(f"[Clustering] Generated NEW root ticket: {ticket_id}")
        MerkleLedger.append_transaction(ticket_id, "TICKET_CREATE", alert)
        return ticket_id
