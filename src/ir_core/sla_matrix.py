import time
import threading
from datetime import datetime, timezone, timedelta
from src.ir_core.database import IRDatabase
from src.ir_core.merkle_ledger import MerkleLedger

class SLAMatrixDaemon:
    """
    Background daemon that embeds real-time countdown clocks tied to ticket variables.
    Triggers internal backend alerts when SLA deadlines approach or breach.
    """
    
    # SLA Configurations (in hours)
    SLA_CONFIG = {
        "CHINA_MAJOR": 1,
        "EU_GDPR": 72,
        "SEC_8K": 96  # 4 days
    }

    def __init__(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._monitor_loop)
        
    def start(self):
        self.worker_thread.start()
        
    def stop(self):
        self.running = False
        self.worker_thread.join()

    def attach_sla(self, ticket_id: str, sla_type: str):
        """Attaches an SLA deadline to a ticket based on its type."""
        hours = self.SLA_CONFIG.get(sla_type)
        if not hours:
            return
            
        deadline = datetime.now(timezone.utc) + timedelta(hours=hours)
        deadline_str = deadline.isoformat()
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET sla_deadline = ? WHERE ticket_id = ?", (deadline_str, ticket_id))
        conn.commit()
        
        print(f"[SLA Matrix] Attached {sla_type} SLA to {ticket_id}. Deadline: {deadline_str}")
        MerkleLedger.append_transaction(ticket_id, "SLA_ATTACHED", {"type": sla_type, "deadline": deadline_str})

    def _monitor_loop(self):
        """Continuously checks open tickets against their SLA deadlines."""
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        while self.running:
            cursor.execute("SELECT ticket_id, sla_deadline FROM tickets WHERE status = 'OPEN' AND sla_deadline IS NOT NULL")
            for ticket_id, deadline_str in cursor.fetchall():
                try:
                    deadline = datetime.fromisoformat(deadline_str)
                    now = datetime.now(timezone.utc)
                    
                    time_left = deadline - now
                    
                    # If breached
                    if time_left.total_seconds() <= 0:
                        self._trigger_breach(ticket_id, deadline_str)
                        # Clear it so it doesn't trigger repeatedly in this mock
                        cursor.execute("UPDATE tickets SET sla_deadline = NULL WHERE ticket_id = ?", (ticket_id,))
                        conn.commit()
                        
                except Exception as e:
                    print(f"[SLA Matrix] Error parsing deadline: {e}")
            
            time.sleep(2) # Mock interval, production would be ~60s
            
    def _trigger_breach(self, ticket_id: str, deadline: str):
        print(f"\n[!!!] SLA BREACH DETECTED [!!!]")
        print(f" -> Ticket: {ticket_id}")
        print(f" -> Deadline Expired At: {deadline}")
        
        # Log to ledger
        MerkleLedger.append_transaction(ticket_id, "SLA_BREACH", {"deadline": deadline})

if __name__ == "__main__":
    # Test the SLA daemon
    from src.ir_core.ingestion_clustering import TokenClusteringEngine
    
    daemon = SLAMatrixDaemon()
    daemon.start()
    
    # Create a mock ticket
    mock_alert = {"class_id": 6001, "severity": "Critical"}
    ticket_id = TokenClusteringEngine._create_root_ticket(mock_alert)
    
    # Attach a fake SLA that will breach in 3 seconds for testing purposes
    # Modifying the standard SLA just for the test
    daemon.SLA_CONFIG["TEST_SLA"] = 0.00083 # ~3 seconds
    daemon.attach_sla(ticket_id, "TEST_SLA")
    
    print("Waiting for SLA breach...")
    time.sleep(5)
    
    daemon.stop()
