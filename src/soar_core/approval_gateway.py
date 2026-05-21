import uuid
import time
from typing import Dict, Any

class ApprovalGateway:
    """
    Human-in-the-Loop Interceptor for the SOAR engine.
    High-risk actions must generate a cryptographic Auth-Token and pause execution
    until a human analyst approves via the IR Ticketing Engine.
    """
    
    # In production, this state lives in the database. For mock, it's in-memory.
    _pending_approvals: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def request_approval(cls, step_id: str, command: str, ticket_id: str) -> str:
        """
        Pauses the DAG execution thread and generates a cryptographic Auth-Token.
        """
        auth_token = f"AUTH_REQ_{uuid.uuid4().hex[:12].upper()}"
        
        cls._pending_approvals[auth_token] = {
            "status": "PENDING",
            "step_id": step_id,
            "command": command,
            "ticket_id": ticket_id
        }
        
        print(f"\n[Approval Gateway] 🛑 EXECUTION PAUSED 🛑")
        print(f" -> High-Risk Action Detected: {command}")
        print(f" -> Generated Auth-Token: {auth_token}")
        print(f" -> Awaiting BlueTeam signature on Ticket {ticket_id}...")
        
        # Simulate blocking wait (Micro-Runner thread blocks here)
        timeout = 30 # 30 seconds for test purposes
        while timeout > 0:
            if cls._pending_approvals[auth_token]["status"] == "APPROVED":
                print(f"[Approval Gateway] ✅ Auth-Token {auth_token} signed! Resuming execution.")
                return True
            time.sleep(1)
            timeout -= 1
            
        print(f"[Approval Gateway] ❌ Auth-Token {auth_token} timed out. Execution aborted.")
        return False

    @classmethod
    def sign_token(cls, auth_token: str, analyst_id: str):
        """
        Simulates the IR Ticketing Engine receiving the analyst's approval signature.
        """
        if auth_token in cls._pending_approvals:
            cls._pending_approvals[auth_token]["status"] = "APPROVED"
            cls._pending_approvals[auth_token]["signed_by"] = analyst_id
            print(f"\n[Ticketing Engine] Analyst {analyst_id} signed token {auth_token}.")
        else:
            print(f"[Ticketing Engine] Invalid Auth-Token: {auth_token}")
