import os
import sys
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

# Ensure parent directory is in path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# Import SIEM Data Lake
try:
    from src.siem_core.clickhouse_client import ClickHouseDataLakeMock
    db = ClickHouseDataLakeMock(db_path="siem_datalake.db")
except ImportError:
    db = None
    print("WARNING: Could not load ClickHouseDataLakeMock")

app = FastAPI(title="BlueTeam Nerve Center API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory fleet tracker
fleet_agents = {
    "agent-001": {"id": "agent-001", "hostname": "WIN-DESKTOP-01", "status": "online", "last_seen": datetime.utcnow().isoformat() + "Z", "av_hits": 2, "vulns": 5},
    "agent-002": {"id": "agent-002", "hostname": "SRV-EXCHANGE-01", "status": "online", "last_seen": datetime.utcnow().isoformat() + "Z", "av_hits": 0, "vulns": 12},
}

# --- AGENT INGESTION ENDPOINTS ---

@app.post("/api/v1/heartbeat")
async def receive_heartbeat(request: Request):
    payload = await request.json()
    agent_id = payload.get("agent_id", "UNKNOWN")
    if agent_id not in fleet_agents:
        fleet_agents[agent_id] = {
            "id": agent_id,
            "hostname": payload.get("hostname", agent_id),
            "av_hits": 0,
            "vulns": 0
        }
    
    fleet_agents[agent_id]["status"] = "online"
    fleet_agents[agent_id]["last_seen"] = datetime.utcnow().isoformat() + "Z"
    fleet_agents[agent_id]["vitals"] = payload.get("vitals", {})
    return {"status": "ok"}

@app.post("/api/v1/telemetry")
async def receive_telemetry(request: Request):
    payload = await request.json()
    # Save to SIEM Data Lake
    if db:
        db.batch_insert([payload])
    return {"status": "ok"}

# --- DASHBOARD ENDPOINTS ---

@app.get("/")
def read_root():
    return {"status": "online", "message": "Nerve Center API is running."}

@app.get("/api/fleet")
def get_fleet_status():
    """Returns a list of all connected endpoint agents and their status."""
    return list(fleet_agents.values())

@app.get("/api/siem/alerts")
def get_siem_alerts():
    """Returns the latest security alerts from the SIEM."""
    if db:
        # Fetch real alerts from the Data Lake
        # For simplicity, returning all payloads mapped to the UI format
        raw_events = db.investigate({"severity": "High"}) + db.investigate({"severity": "Critical"})
        alerts = []
        for idx, event in enumerate(raw_events):
            alerts.append({
                "id": 2000 + idx,
                "timestamp": event.get("time", ""),
                "source": event.get("src_endpoint", {}).get("ip", "Unknown"),
                "severity": event.get("severity", "High"),
                "rule": str(event.get("enrichment", {}).get("mitre_tags", ["Unknown Rule"]))
            })
        if alerts:
            return alerts
    
    # Fallback dummy data if DB empty
    return [
        {"id": 1001, "timestamp": "2026-05-21T19:45:00Z", "source": "WIN-DESKTOP-01", "severity": "Critical", "rule": "YARA: Ransomware_WannaCry_Strings"},
        {"id": 1002, "timestamp": "2026-05-21T19:48:00Z", "source": "SRV-EXCHANGE-01", "severity": "High", "rule": "Suspicious PowerShell Execution"},
    ]

@app.get("/api/soar/playbooks")
def get_playbooks():
    """Returns SOAR playbook status."""
    return [
        {"name": "Isolate Host", "status": "active", "success_rate": "98%"},
        {"name": "Quarantine File", "status": "active", "success_rate": "100%"},
        {"name": "Disable User Account", "status": "inactive", "success_rate": "N/A"},
    ]

@app.get("/api/ir/incidents")
def get_incidents():
    """Returns open IR incidents."""
    return [
        {"id": "INC-001", "title": "Suspected Ransomware on WIN-DESKTOP-01", "status": "Open", "assignee": "Unassigned", "severity": "Critical"},
        {"id": "INC-002", "title": "Anomalous Login to Exchange Server", "status": "Investigating", "assignee": "Alice", "severity": "High"},
    ]

# --- ACTION ENDPOINTS for UI Buttons ---

@app.post("/api/soar/execute/{playbook_name}")
def execute_playbook(playbook_name: str):
    return {"status": "success", "message": f"Playbook '{playbook_name}' executed successfully.", "execution_id": "EXEC-999"}

@app.post("/api/siem/triage/{alert_id}")
def triage_alert(alert_id: int):
    return {"status": "success", "message": f"Alert #{alert_id} has been escalated to an IR case.", "case_id": f"INC-10{alert_id}"}

@app.post("/api/fleet/investigate/{agent_id}")
def investigate_agent(agent_id: str):
    return {"status": "success", "message": f"Forensic package requested from {agent_id}."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
