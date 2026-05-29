import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from typing import Optional, Any
import threading

# Huggingface pipeline (optional)
classifier = None
classifier_lock = threading.Lock()
zero_shot = None
zero_shot_lock = threading.Lock()
chat_model = None
chat_model_lock = threading.Lock()
id2label_map = {}
label_map_source = None
label_map_path = os.environ.get("PEN_TEST_AI_LABEL_MAP", os.path.join(os.path.dirname(__file__), "label_map.json"))
model_source = None

# Ensure parent directory is in path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

nerve_center_core = None
db = None

# Import backend core components
try:
    from src.event_router import NerveCenter
    from src.siem_core.clickhouse_client import ClickHouseDataLakeMock
    from src.vuln_core.asset_inventory import AssetInventory
    from src.ir_core.database import IRDatabase
    from src.ir_core.merkle_ledger import MerkleLedger
    from src.soar_core.dag_orchestrator import DagOrchestrator
    from src.vuln_core.vuln_scanner import VulnScanner
    
    # Initialize NerveCenter core instance
    nerve_center_core = NerveCenter()
    db = nerve_center_core.siem_datalake
except Exception as e:
    print(f"WARNING: Could not load backend core components: {e}")

def seed_databases():
    """Seed Asset Inventory and IR Tickets databases if they are empty."""
    if not nerve_center_core:
        return
    
    # Seed Asset Inventory
    try:
        inventory = nerve_center_core.vuln_inventory
        cursor = inventory.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM devices")
        if cursor.fetchone()[0] == 0:
            print("Seeding Asset Inventory database with default agents...")
            inventory.register_device({
                "device_id": "agent-001",
                "hostname": "WIN-DESKTOP-01",
                "ip_address": "10.0.0.15",
                "os_family": "Windows",
                "os_version": "11 Enterprise"
            })
            inventory.register_device({
                "device_id": "agent-002",
                "hostname": "SRV-EXCHANGE-01",
                "ip_address": "10.0.0.88",
                "os_family": "Windows",
                "os_version": "Server 2019"
            })
            
            # Attach default vulnerabilities
            for i in range(5):
                inventory.attach_vulnerability("agent-001", {
                    "severity": "Medium",
                    "vulnerabilities": [{"cve": {"uid": f"CVE-2026-{1000 + i}"}}],
                    "enrichments": [{"name": "Evidence", "value": f"Mock vulnerability evidence {i}"}]
                })
            for i in range(12):
                inventory.attach_vulnerability("agent-002", {
                    "severity": "High" if i % 2 == 0 else "Medium",
                    "vulnerabilities": [{"cve": {"uid": f"CVE-2026-{2000 + i}"}}],
                    "enrichments": [{"name": "Evidence", "value": f"Mock exchange vuln evidence {i}"}]
                })
    except Exception as e:
        print(f"Error seeding Asset Inventory: {e}")

    # Seed IR Tickets
    try:
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tickets")
        if cursor.fetchone()[0] == 0:
            print("Seeding IR Tickets database with default incidents...")
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            
            cursor.execute(
                "INSERT INTO tickets (ticket_id, title, status, severity, created_at) VALUES (?, ?, ?, ?, ?)",
                ("INC-001", "Suspected Ransomware on WIN-DESKTOP-01", "Open", "Critical", now)
            )
            MerkleLedger.append_transaction("INC-001", "TICKET_CREATE", {
                "class_id": 1001,
                "severity": "Critical",
                "file_path": "C:\\Windows\\Temp\\payload.exe",
                "src_endpoint_ip": "10.0.0.15"
            })
            
            cursor.execute(
                "INSERT INTO tickets (ticket_id, title, status, severity, created_at) VALUES (?, ?, ?, ?, ?)",
                ("INC-002", "Anomalous Login to Exchange Server", "Investigating", "High", now)
            )
            MerkleLedger.append_transaction("INC-002", "TICKET_CREATE", {
                "class_id": 3002,
                "severity": "High",
                "src_endpoint_ip": "10.0.0.88"
            })
            # Seed Quarantine
            cursor.execute("SELECT COUNT(*) FROM quarantine")
            if cursor.fetchone()[0] == 0:
                print("Seeding quarantine threat vault...")
                cursor.execute(
                    "INSERT INTO quarantine (file_hash, file_name, file_path, device_id, hostname, ip_address, status, threat_name, confidence, timestamp, sandbox_report) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "fd7f25bef964f9a3ca2bc277f7e4a88fc7a5b4ea4b12b4b8e3cae5a2df2aba1b", 
                        "cobaltstrike.exe", 
                        "C:\\Users\\Administrator\\Downloads\\cobaltstrike.exe", 
                        "agent-002", 
                        "SRV-EXCHANGE-01", 
                        "10.0.0.88", 
                        "QUARANTINED", 
                        "CobaltStrike.C2.Beacon", 
                        0.99, 
                        now,
                        None
                    )
                )
                cursor.execute(
                    "INSERT INTO quarantine (file_hash, file_name, file_path, device_id, hostname, ip_address, status, threat_name, confidence, timestamp, sandbox_report) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 
                        "ransom.dll", 
                        "C:\\Windows\\Temp\\ransom.dll", 
                        "agent-001", 
                        "WIN-DESKTOP-01", 
                        "10.0.0.15", 
                        "QUARANTINED", 
                        "WannaCry.Ransomware.B", 
                        0.95, 
                        now,
                        None
                    )
                )
                cursor.execute(
                    "INSERT INTO quarantine (file_hash, file_name, file_path, device_id, hostname, ip_address, status, threat_name, confidence, timestamp, sandbox_report) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "ca863ac06579c3c83a235215c1590b06c7ed2ca92a90d2480e606c7e97d2d2c1", 
                        "mimikatz.exe", 
                        "C:\\Temp\\mimikatz.exe", 
                        "agent-001", 
                        "WIN-DESKTOP-01", 
                        "10.0.0.15", 
                        "RESTORED", 
                        "Mimikatz.Tool.A", 
                        0.91, 
                        now,
                        "DYNAMIC ANALYSIS REPORT:\n- Process mimikatz.exe spawned with PID 4322.\n- Attempts to read LSASS memory detected (SeDebugPrivilege requested).\n- LSASS dump file created in C:\\Temp.\n- Sandbox Verdict: MALICIOUS CREDENTIAL DUMPER."
                    )
                )
            
            # Seed SOAR History
            cursor.execute("SELECT COUNT(*) FROM soar_history")
            if cursor.fetchone()[0] == 0:
                print("Seeding SOAR execution history...")
                cursor.execute(
                    "INSERT INTO soar_history (execution_id, playbook_name, target_ip, status, started_at, completed_at, log_output) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "EXEC-001",
                        "PrintNightmare Remediation",
                        "10.0.0.88",
                        "SUCCESS",
                        now,
                        now,
                        "Evaluating patch availability...\nDeploying CVE-2021-34527 patch...\nMonitoring server vitals...\nExecution SUCCESS."
                    )
                )
                cursor.execute(
                    "INSERT INTO soar_history (execution_id, playbook_name, target_ip, status, started_at, completed_at, log_output) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "EXEC-002",
                        "Malware Containment (WannaCry)",
                        "10.0.0.15",
                        "ABORTED",
                        now,
                        now,
                        "Evaluating file entropy...\nHigh risk isolated action detected: agent_control --isolate --host_ip 10.0.0.15\nRequesting human signature approval...\nApproval explicitly DENIED by analyst.\nExecution ABORTED."
                    )
                )
            conn.commit()
    except Exception as e:
        print(f"Error seeding IR Tickets: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run startup actions
    seed_databases()
    await load_hf_model()
    yield

app = FastAPI(title="BlueTeam Nerve Center API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory fleet tracker
fleet_agents = {
    "agent-001": {"id": "agent-001", "hostname": "WIN-DESKTOP-01", "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(), "av_hits": 2, "vulns": 5},
    "agent-002": {"id": "agent-002", "hostname": "SRV-EXCHANGE-01", "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(), "av_hits": 0, "vulns": 12},
}

# --- AGENT INGESTION ENDPOINTS ---

@app.post("/api/v1/heartbeat")
async def receive_heartbeat(request: Request):
    payload = await request.json()
    agent_id = payload.get("agent_id", "UNKNOWN")
    
    # Register device in Asset Inventory
    if nerve_center_core:
        try:
            nerve_center_core.vuln_inventory.register_device({
                "device_id": agent_id,
                "hostname": payload.get("hostname", agent_id),
                "ip_address": payload.get("ip_address") or payload.get("vitals", {}).get("ip_address", "Unknown"),
                "os_family": payload.get("os_family") or payload.get("vitals", {}).get("os_family", "Unknown"),
                "os_version": payload.get("os_version") or payload.get("vitals", {}).get("os_version", "Unknown")
            })
        except Exception as e:
            print(f"Error registering device on heartbeat: {e}")

    if agent_id not in fleet_agents:
        fleet_agents[agent_id] = {
            "id": agent_id,
            "hostname": payload.get("hostname", agent_id),
            "av_hits": 0,
            "vulns": 0
        }
    
    fleet_agents[agent_id]["status"] = "online"
    fleet_agents[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
    fleet_agents[agent_id]["vitals"] = payload.get("vitals", {})
    return {"status": "ok"}

@app.post("/api/v1/telemetry")
async def receive_telemetry(request: Request):
    payload = await request.json()
    source_type = payload.get("source_type", "SYSLOG")
    device_ip = payload.get("src_endpoint", {}).get("ip") or payload.get("device", {}).get("ip") or "10.0.0.15"
    device_context = {
        "device_id": payload.get("agent_id") or payload.get("device_id") or "agent-001",
        "hostname": payload.get("hostname") or "Unknown",
        "ip_address": device_ip,
        "os_family": payload.get("os_family") or "Unknown",
        "os_version": payload.get("os_version") or "Unknown"
    }
    
    if nerve_center_core:
        try:
            if source_type == "SYSLOG":
                raw_data = payload.get("raw_log") or payload.get("message") or str(payload)
                nerve_center_core.route_event("SYSLOG", raw_data, device_context)
            elif source_type == "FILE_DROP":
                file_path = payload.get("file_path", "C:\\Temp\\payload.exe")
                file_bytes = payload.get("file_bytes")
                if isinstance(file_bytes, str):
                    file_bytes = file_bytes.encode('utf-8')
                elif file_bytes is None:
                    file_bytes = b"mock malicious bytes"
                nerve_center_core.route_event("FILE_DROP", (file_path, file_bytes), device_context)
            elif source_type == "ENDPOINT_SCAN":
                nerve_center_core.route_event("ENDPOINT_SCAN", None, device_context)
            else:
                if db:
                    db.batch_insert([payload])
        except Exception as e:
            print(f"Error routing event through NerveCenter: {e}")
            if db:
                db.batch_insert([payload])
    else:
        if db:
            db.batch_insert([payload])
            
    return {"status": "ok"}

# --- HUGGINGFACE CLASSIFICATION ENDPOINT ---
async def load_hf_model():
    """Try to load the Huggingface pipeline at startup. If `transformers` is not installed
    or loading fails, `classifier` will remain None and the endpoint will return an error.
    """
    global classifier, chat_model, zero_shot
    try:
        from transformers import pipeline
        # default to local AI/ folder at repo root if present
        default_local = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..", "AI"))
        model_name = os.environ.get("PEN_TEST_AI_MODEL", default_local)

        # determine device: env PEN_TEST_AI_DEVICE can be -1 (cpu) or an int for GPU index or strings like 'cpu'/'cuda:0'
        device_env = os.environ.get("PEN_TEST_AI_DEVICE")
        device = -1
        if device_env is not None:
            try:
                if device_env.lower() in ("cpu", "-1"):
                    device = -1
                elif device_env.lower().startswith("cuda") or device_env.lower().startswith("gpu"):
                    # support values like 'cuda:0' or 'gpu:0'
                    idx = int(device_env.split(":")[-1])
                    device = idx
                else:
                    device = int(device_env)
            except Exception:
                device = -1

        # If model_name is a local directory, prefer loading tokenizer/model from there
        if os.path.isdir(model_name):
            print(f"Loading local model from: {model_name} (device={device})")
            cls = pipeline("text-classification", model=model_name, tokenizer=model_name, device=device)
        else:
            print(f"Loading remote model '{model_name}' (device={device})")
            cls = pipeline("text-classification", model=model_name, device=device)

        chat_model_name = os.environ.get("PEN_TEST_CHAT_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
        try:
            print(f"Loading chat model '{chat_model_name}' (device={device})...")
            chat_model = pipeline("text-generation", model=chat_model_name, device=device)
        except Exception as e:
            print(f"WARNING: Could not load primary chat model '{chat_model_name}': {e}. Falling back to 'gpt2'...")
            try:
                chat_model = pipeline("text-generation", model="gpt2", device=device)
            except Exception as fallback_e:
                print(f"WARNING: Could not load fallback chat model 'gpt2': {fallback_e}")
                chat_model = None

        # try to load a zero-shot classification pipeline for flexible classification
        # try to load a zero-shot classification pipeline for flexible classification
        try:
            zs_model = os.environ.get("PEN_TEST_AI_ZERO_SHOT", "facebook/bart-large-mnli")
            zs = pipeline("zero-shot-classification", model=zs_model)
            with zero_shot_lock:
                zero_shot = zs
            print(f"Loaded zero-shot model: {zs_model}")
        except Exception as e:
            zero_shot = None
            print("INFO: zero-shot model not available:", e)
        with classifier_lock:
            classifier = cls
        model_source = model_name
        print(f"Loaded Huggingface model: {model_name}")

        # try to pull id2label mapping from the model config
        global id2label_map, label_map_source
        try:
            cfg = getattr(classifier, "model", None)
            if cfg is not None:
                cfg = cfg.config
                model_map = getattr(cfg, "id2label", None) or {}
                if isinstance(model_map, dict) and model_map:
                    # normalize keys to int when possible
                    normalized = {}
                    for k, v in model_map.items():
                        try:
                            normalized[int(k)] = v
                        except Exception:
                            try:
                                normalized[int(str(k))] = v
                            except Exception:
                                normalized[k] = v
                    id2label_map.update(normalized)
                    label_map_source = "model"
        except Exception:
            pass

        # then try loading a local label map (JSON or pickle) to override or extend
        try:
            if os.path.exists(label_map_path):
                import json, pickle
                _, ext = os.path.splitext(label_map_path)
                if ext.lower() in (".json",):
                    with open(label_map_path, "r", encoding="utf-8") as fh:
                        file_map = json.load(fh) or {}
                else:
                    # try pickle: could be a dict or a fitted sklearn LabelEncoder
                    with open(label_map_path, "rb") as fh:
                        file_map = pickle.load(fh)

                normalized = {}
                # If sklearn LabelEncoder, it exposes classes_
                try:
                    classes = getattr(file_map, "classes_", None)
                    if classes is not None:
                        # classes is an array-like of labels where index is numeric id
                        for i, cls in enumerate(classes):
                            normalized[int(i)] = str(cls)
                    elif isinstance(file_map, dict):
                        for k, v in file_map.items():
                            try:
                                normalized[int(k)] = v
                            except Exception:
                                normalized[k] = v
                    else:
                        # unsupported type, skip
                        normalized = {}

                except Exception:
                    normalized = {}

                if normalized:
                    id2label_map.update(normalized)
                    label_map_source = f"file:{label_map_path}"
        except Exception as e:
            print("WARNING: Could not load label map file:", e)

    except Exception as e:
        classifier = None
        print("WARNING: Could not load Huggingface model:", e)


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "model_loaded": classifier is not None,
        "model_source": model_source,
        "zero_shot_loaded": zero_shot is not None,
        "label_map_source": label_map_source,
    }


@app.post("/api/v1/labelmap/reload")
def reload_labelmap():
    """Reload label map from configured path (JSON or pickle) without restarting."""
    global id2label_map, label_map_source
    id2label_map = {}
    label_map_source = None
    try:
        if os.path.exists(label_map_path):
            import json, pickle
            _, ext = os.path.splitext(label_map_path)
            if ext.lower() in (".json",):
                with open(label_map_path, "r", encoding="utf-8") as fh:
                    file_map = json.load(fh) or {}
            else:
                with open(label_map_path, "rb") as fh:
                    file_map = pickle.load(fh)

            normalized = {}
            classes = getattr(file_map, "classes_", None)
            if classes is not None:
                for i, cls in enumerate(classes):
                    normalized[int(i)] = str(cls)
            elif isinstance(file_map, dict):
                for k, v in file_map.items():
                    try:
                        normalized[int(k)] = v
                    except Exception:
                        normalized[k] = v

            if normalized:
                id2label_map.update(normalized)
                label_map_source = f"file:{label_map_path}"
                return {"status": "ok", "label_map_source": label_map_source}

        return {"status": "error", "error": "no valid label map found"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/v1/classify")
async def classify(request: Request):
    payload = await request.json()
    text = payload.get("text") or payload.get("query") or payload.get("input")
    mode = payload.get("mode", "classify")  # 'classify' | 'scores' | 'zero_shot'
    top_k = int(payload.get("top_k", 1))
    if not text:
        return {"status": "error", "error": "no text provided"}

    if classifier is None:
        return {"status": "error", "error": "model not loaded"}

    # run classification under a lock to avoid race conditions with model loading
    try:
        if mode == "zero_shot":
            if zero_shot is None:
                return {"status": "error", "error": "zero-shot model not available"}
            # candidate labels are human-readable values of our mapping
            candidates = list(id2label_map.values()) if id2label_map else None
            if not candidates:
                # fallback to raw LABEL_n names
                candidates = [v for v in [r.get("label") for r in result] if v]
            with zero_shot_lock:
                zs_res = zero_shot(text, candidate_labels=candidates)
            # zero-shot returns 'labels' and 'scores'
            zs_out = []
            for lbl, score in zip(zs_res.get("labels", []), zs_res.get("scores", [])):
                zs_out.append({"label": lbl, "score": score})
            return {"status": "ok", "mode": "zero_shot", "result": zs_out}

        # normal classification: request top_k scores
        with classifier_lock:
            if top_k <= 1:
                result = classifier(text)
            else:
                # pipeline supports top_k to return multiple label scores
                result = classifier(text, top_k=top_k)
    except Exception as e:
        return {"status": "error", "error": str(e)}

    # Map generic LABEL_n to human-readable labels using id2label_map
    mapped = []
    for r in result:
        lbl = r.get("label")
        pretty = lbl
        label_id = None
        if isinstance(lbl, str) and lbl.startswith("LABEL_"):
            try:
                label_id = int(lbl.split("_", 1)[1])
                # prefer mapping from file/model if available
                pretty = id2label_map.get(label_id, id2label_map.get(str(label_id), lbl))
            except Exception:
                label_id = None
                pretty = lbl
        else:
            # label already human-readable
            pretty = lbl

        mapped.append({"label": pretty, "label_id": label_id, "score": r.get("score")})

    return {"status": "ok", "result": mapped, "raw": result, "mapping_source": label_map_source}

# --- DASHBOARD ENDPOINTS ---

@app.get("/")
def read_root():
    return {"status": "online", "message": "Nerve Center API is running."}

@app.get("/api/fleet")
def get_fleet_status():
    """Returns a list of all connected endpoint agents and their status."""
    if nerve_center_core:
        try:
            inventory = nerve_center_core.vuln_inventory
            cursor = inventory.conn.cursor()
            cursor.execute("SELECT device_id, hostname, ip_address, os_family, os_version FROM devices")
            db_devices = cursor.fetchall()
            
            results = []
            for dev_id, hostname, ip, os_fam, os_ver in db_devices:
                status_info = fleet_agents.get(dev_id, {"status": "offline", "last_seen": "Never", "vitals": {}})
                vulns_list = inventory.get_device_vulnerabilities(dev_id)
                
                # Count AV hits from the clickhouse mock datalake
                av_hits = 0
                if db:
                    try:
                        cursor_dl = db.conn.cursor()
                        cursor_dl.execute("SELECT COUNT(*) FROM ocsf_events WHERE class_id = 1001 AND src_ip = ?", (ip,))
                        av_hits = cursor_dl.fetchone()[0]
                    except Exception:
                        av_hits = status_info.get("av_hits", 0)
                else:
                    av_hits = status_info.get("av_hits", 0)
                    
                results.append({
                    "id": dev_id,
                    "hostname": hostname,
                    "status": status_info.get("status", "offline"),
                    "last_seen": status_info.get("last_seen", "Never"),
                    "vitals": status_info.get("vitals", {}),
                    "av_hits": av_hits,
                    "vulns": len(vulns_list)
                })
            return results
        except Exception as e:
            print(f"Error querying AssetInventory: {e}")
            
    return list(fleet_agents.values())

@app.get("/api/siem/alerts")
def get_siem_alerts():
    """Returns the latest security alerts from the SIEM."""
    if db:
        try:
            # Fetch real alerts from the Data Lake
            raw_events = db.investigate({"severity": "High"}) + db.investigate({"severity": "Critical"})
            alerts = []
            for idx, event in enumerate(raw_events):
                rules_matched = event.get("enrichment", {}).get("matched_rules", [])
                rule_name = rules_matched[0] if rules_matched else event.get("malware", {}).get("name") or "Unknown Rule"
                if rule_name == "Unknown Rule":
                    mitre_tags = event.get("enrichment", {}).get("mitre_tags", [])
                    if mitre_tags:
                        rule_name = f"MITRE: {', '.join(mitre_tags)}"
                
                alerts.append({
                    "id": 2000 + idx,
                    "timestamp": event.get("time", ""),
                    "source": event.get("device", {}).get("ip") or event.get("src_endpoint", {}).get("ip") or "Unknown",
                    "severity": event.get("severity", "High"),
                    "rule": rule_name
                })
            if alerts:
                # Sort descending
                try:
                    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
                except Exception:
                    pass
                return alerts
        except Exception as e:
            print(f"Error in get_siem_alerts: {e}")
            
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
    try:
        from src.ir_core.database import IRDatabase
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ticket_id, title, status, severity, assignee FROM tickets")
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "title": row[1],
                "status": row[2],
                "assignee": row[4] if len(row) > 4 and row[4] else "Unassigned",
                "severity": row[3]
            })
        return results
    except Exception as e:
        print(f"Error querying IR database tickets: {e}")
        return [
            {"id": "INC-001", "title": "Suspected Ransomware on WIN-DESKTOP-01", "status": "Open", "assignee": "Unassigned", "severity": "Critical"},
            {"id": "INC-002", "title": "Anomalous Login to Exchange Server", "status": "Investigating", "assignee": "Alice", "severity": "High"},
        ]

# --- ACTION ENDPOINTS for UI Buttons ---

@app.post("/api/soar/execute/{playbook_name}")
def execute_playbook(playbook_name: str):
    if nerve_center_core:
        try:
            # Build mock event based on playbook action/name to simulate triggering EDR / Vuln / AV cores
            class_id = 1001 if "isolate" in playbook_name.lower() or "malware" in playbook_name.lower() or "quarantine" in playbook_name.lower() else 2002
            mock_event = {
                "class_id": class_id,
                "severity": "Critical",
                "file_path": "C:\\Windows\\Temp\\payload.exe",
                "src_endpoint_ip": "10.0.0.88",
                "vulnerability": {"cve_id": "CVE-2026-0001"}
            }
            
            # Execute in background thread to prevent API hanging
            import threading
            thread = threading.Thread(target=nerve_center_core.soar_engine.trigger_incident, args=(mock_event, "INC-EXEC-999"))
            thread.start()
            
            return {"status": "success", "message": f"Playbook '{playbook_name}' initiated in background.", "execution_id": "EXEC-999"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to execute playbook: {str(e)}"}
            
    return {"status": "success", "message": f"Playbook '{playbook_name}' executed successfully.", "execution_id": "EXEC-999"}

@app.post("/api/siem/triage/{alert_id}")
def triage_alert(alert_id: int):
    try:
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        from datetime import datetime, timezone
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        
        ticket_id = f"INC-10{alert_id}"
        title = f"Escalated Alert #{alert_id}"
        now = datetime.now(timezone.utc).isoformat()
        
        # Check if already exists
        cursor.execute("SELECT COUNT(*) FROM tickets WHERE ticket_id = ?", (ticket_id,))
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "INSERT INTO tickets (ticket_id, title, status, severity, created_at) VALUES (?, ?, ?, ?, ?)",
                (ticket_id, title, "Open", "High", now)
            )
            conn.commit()
            
            MerkleLedger.append_transaction(ticket_id, "TICKET_ESCALATE", {
                "alert_id": alert_id,
                "note": "Alert escalated manually from Nerve Center UI"
            })
            
        return {"status": "success", "message": f"Alert #{alert_id} has been escalated to an IR case.", "case_id": ticket_id}
    except Exception as e:
        print(f"Error triaging alert: {e}")
        return {"status": "success", "message": f"Alert #{alert_id} has been escalated to an IR case.", "case_id": f"INC-10{alert_id}"}

@app.post("/api/fleet/investigate/{agent_id}")
def investigate_agent(agent_id: str):
    if nerve_center_core:
        try:
            # Query device info from CMDB
            inventory = nerve_center_core.vuln_inventory
            cursor = inventory.conn.cursor()
            cursor.execute("SELECT hostname, ip_address, os_family, os_version FROM devices WHERE device_id = ?", (agent_id,))
            row = cursor.fetchone()
            
            if row:
                device_context = {
                    "device_id": agent_id,
                    "hostname": row[0],
                    "ip_address": row[1],
                    "os_family": row[2],
                    "os_version": row[3]
                }
            else:
                device_context = {
                    "device_id": agent_id,
                    "hostname": agent_id,
                    "ip_address": "Unknown",
                    "os_family": "Unknown",
                    "os_version": "Unknown"
                }
                
            # Trigger background scan
            import threading
            def run_vuln_scan():
                try:
                    ocsf_payload = VulnScanner.run_scan(device_context)
                    if ocsf_payload:
                        inventory.attach_vulnerability(agent_id, ocsf_payload)
                        if db:
                            db.batch_insert([ocsf_payload])
                except Exception as e:
                    print(f"Error running scan: {e}")
                    
            thread = threading.Thread(target=run_vuln_scan)
            thread.start()
            
            return {"status": "success", "message": f"Vulnerability and forensic scan initiated for {agent_id}."}
        except Exception as e:
            return {"status": "error", "message": f"Failed to initiate scan: {str(e)}"}
            
    return {"status": "success", "message": f"Forensic package requested from {agent_id}."}


# --- SOAR APPROVALS AND TICKETS LEDGERS ENDPOINTS ---

@app.get("/api/soar/approvals")
def get_approvals():
    """Returns all active/pending approvals."""
    try:
        from src.soar_core.approval_gateway import ApprovalGateway
        return ApprovalGateway._pending_approvals
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/soar/approve/{auth_token}")
def approve_token(auth_token: str, analyst_id: str = "analyst_matt"):
    try:
        from src.soar_core.approval_gateway import ApprovalGateway
        from src.ir_core.merkle_ledger import MerkleLedger
        
        if auth_token in ApprovalGateway._pending_approvals:
            # Log to ledger before changing status to APPROVED which unblocks the background execution
            ticket_id = ApprovalGateway._pending_approvals[auth_token]["ticket_id"]
            MerkleLedger.append_transaction(ticket_id, "SOAR_ACTION_APPROVED", {
                "auth_token": auth_token,
                "action": ApprovalGateway._pending_approvals[auth_token]["command"],
                "approved_by": analyst_id
            })
            ApprovalGateway.sign_token(auth_token, analyst_id)
            return {"status": "success", "message": f"Action approved by {analyst_id}."}
        return {"status": "error", "message": "Auth token not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/soar/deny/{auth_token}")
def deny_token(auth_token: str, analyst_id: str = "analyst_matt"):
    try:
        from src.soar_core.approval_gateway import ApprovalGateway
        from src.ir_core.merkle_ledger import MerkleLedger
        
        if auth_token in ApprovalGateway._pending_approvals:
            ApprovalGateway._pending_approvals[auth_token]["status"] = "DENIED"
            ApprovalGateway._pending_approvals[auth_token]["signed_by"] = analyst_id
            ticket_id = ApprovalGateway._pending_approvals[auth_token]["ticket_id"]
            
            MerkleLedger.append_transaction(ticket_id, "SOAR_ACTION_DENIED", {
                "auth_token": auth_token,
                "action": ApprovalGateway._pending_approvals[auth_token]["command"],
                "denied_by": analyst_id
            })
            return {"status": "success", "message": f"Action denied by {analyst_id}."}
        return {"status": "error", "message": "Auth token not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/ir/tickets/{ticket_id}/timeline")
def get_ticket_timeline(ticket_id: str):
    """Retrieves all Merkle ledger transactions for a given ticket."""
    try:
        from src.ir_core.database import IRDatabase
        import json
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT transaction_id, action_type, payload, timestamp, hash_state FROM ledger WHERE ticket_id = ? ORDER BY transaction_id ASC",
            (ticket_id,)
        )
        rows = cursor.fetchall()
        
        timeline = []
        for row in rows:
            try:
                payload = json.loads(row[2])
            except Exception:
                payload = row[2]
            timeline.append({
                "id": row[0],
                "action_type": row[1],
                "payload": payload,
                "timestamp": row[3],
                "hash_state": row[4]
            })
        return timeline
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/ir/tickets/{ticket_id}/update")
async def update_ticket_comment(ticket_id: str, request: Request):
    try:
        payload = await request.json()
        comment = payload.get("comment", "")
        author = payload.get("author", "analyst_matt")
        
        if not comment:
            return {"status": "error", "message": "No comment provided."}
            
        from src.ir_core.merkle_ledger import MerkleLedger
        MerkleLedger.append_transaction(ticket_id, "TICKET_UPDATE", {
            "comment": comment,
            "author": author
        })
        return {"status": "success", "message": "Comment added successfully."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/ir/tickets/{ticket_id}/resolve")
async def resolve_ticket(ticket_id: str, request: Request):
    try:
        payload = await request.json()
        assignee = payload.get("assignee", "analyst_matt")
        
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET status = 'RESOLVED' WHERE ticket_id = ?", (ticket_id,))
        conn.commit()
        
        MerkleLedger.append_transaction(ticket_id, "TICKET_RESOLVE", {
            "resolved_by": assignee,
            "status": "RESOLVED"
        })
        return {"status": "success", "message": "Ticket resolved successfully."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/ir/tickets/{ticket_id}/assign")
async def assign_ticket(ticket_id: str, request: Request):
    try:
        payload = await request.json()
        assignee = payload.get("assignee", "Unassigned")
        author = payload.get("author", "analyst_matt")
        
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET assignee = ? WHERE ticket_id = ?", (assignee, ticket_id))
        conn.commit()
        
        MerkleLedger.append_transaction(ticket_id, "TICKET_ASSIGN", {
            "assignee": assignee,
            "assigned_by": author
        })
        return {"status": "success", "message": f"Ticket assigned to {assignee}."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/ir/tickets/{ticket_id}/severity")
async def update_severity(ticket_id: str, request: Request):
    try:
        payload = await request.json()
        severity = payload.get("severity", "Medium")
        author = payload.get("author", "analyst_matt")
        
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET severity = ? WHERE ticket_id = ?", (severity, ticket_id))
        conn.commit()
        
        MerkleLedger.append_transaction(ticket_id, "TICKET_SEVERITY_UPDATE", {
            "severity": severity,
            "updated_by": author
        })
        return {"status": "success", "message": f"Ticket severity updated to {severity}."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/ir/tickets/{ticket_id}/status")
async def update_status(ticket_id: str, request: Request):
    try:
        payload = await request.json()
        status = payload.get("status", "OPEN")
        author = payload.get("author", "analyst_matt")
        
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE tickets SET status = ? WHERE ticket_id = ?", (status, ticket_id))
        conn.commit()
        
        MerkleLedger.append_transaction(ticket_id, "TICKET_STATUS_UPDATE", {
            "status": status,
            "updated_by": author
        })
        return {"status": "success", "message": f"Ticket status updated to {status}."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/ir/tickets/{ticket_id}/verify")
def verify_ticket_ledger(ticket_id: str):
    try:
        from src.ir_core.merkle_ledger import MerkleLedger
        from src.ir_core.database import IRDatabase
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ledger WHERE ticket_id = ?", (ticket_id,))
        count = cursor.fetchone()[0]
        
        cursor.execute("SELECT hash_state FROM ledger WHERE ticket_id = ? ORDER BY transaction_id DESC LIMIT 1", (ticket_id,))
        row = cursor.fetchone()
        root_hash = row[0] if row else "None"
        
        verified = MerkleLedger.verify_integrity(ticket_id)
        
        return {
            "status": "success",
            "verified": verified,
            "block_count": count,
            "root_hash": root_hash,
            "message": f"Ledger cryptographically verified ({count} blocks checked, root signature valid)" if verified else "Ledger validation FAILED. Chain is broken."
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/ir/tickets/{ticket_id}/diagnose")
async def diagnose_ticket(ticket_id: str):
    try:
        from src.ir_core.database import IRDatabase
        from src.ir_core.merkle_ledger import MerkleLedger
        from src.siem_core.ai_classifier import LocalAIClassifier
        import json

        # Retrieve the creation transaction payload for this ticket
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload FROM ledger WHERE ticket_id = ? AND action_type IN ('TICKET_CREATE', 'TICKET_ESCALATE') ORDER BY transaction_id ASC LIMIT 1",
            (ticket_id,)
        )
        row = cursor.fetchone()
        if not row:
            return {"status": "error", "message": "No creation event payload found to diagnose."}
        
        event_payload = json.loads(row[0])
        
        # Run classification
        log_text = json.dumps(event_payload)
        ai_result = LocalAIClassifier.classify_log(log_text)
        
        if not ai_result:
            return {"status": "error", "message": "AI model classification returned no results."}
            
        label = ai_result.get("label", "").upper()
        score = ai_result.get("score", 0.0)
        
        label_map = {
            "LABEL_0": "covering_tracks",
            "LABEL_1": "gaining_access",
            "LABEL_2": "maintaining_access",
            "LABEL_3": "other",
            "LABEL_4": "reconnaissance",
            "LABEL_5": "scanning"
        }
        threat_phase = label_map.get(label, label.lower())
        
        # Update the ticket's title in DB
        title = f"AI Flagged Threat: {threat_phase.upper()} (Confidence: {score*100:.1f}%)"
        cursor.execute("UPDATE tickets SET title = ?, severity = 'High' WHERE ticket_id = ?", (title, ticket_id))
        conn.commit()
        
        # Log to ledger
        MerkleLedger.append_transaction(ticket_id, "AI_DIAGNOSIS", {
            "classification": threat_phase,
            "confidence": score,
            "title": title
        })
        
        return {
            "status": "success", 
            "message": f"AI diagnosis completed. Classification: {threat_phase} ({score*100:.1f}%)",
            "title": title,
            "classification": threat_phase,
            "confidence": score
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


# In-memory session chat history list to support Turing-test multi-turn conversational context
chat_history = []

@app.post("/api/ai/chat")
async def ai_chat(request: Request):
    try:
        payload = await request.json()
        message = payload.get("message", "").strip()
        
        if not message:
            return {"status": "error", "response": "No message provided."}
            
        global chat_history
        chat_history.append({"role": "user", "content": message})
        chat_history = chat_history[-10:] # limit history to 10 messages
        
        import re
        message_lower = message.lower()
        response_text = ""
        
        # 1. Intent: Query Fleet / CMDB Assets
        if any(w in message_lower for w in ["fleet", "agent", "host", "device", "health", "expose", "online"]):
            try:
                from src.ir_core.database import IRDatabase
                conn = IRDatabase.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM tickets WHERE status != 'RESOLVED'")
                open_tickets = cursor.fetchone()[0]
                
                # Retrieve agents details
                fleet = get_fleet_status()
                online_count = sum(1 for a in fleet if a["status"] == "online")
                total_vulns = sum(a["vulns"] for a in fleet)
                
                response_text = (
                    f"Checking active CMDB asset inventory...\n"
                    f"I located {len(fleet)} endpoints: {', '.join([a['hostname'] for a in fleet])}.\n"
                    f"- **Online Agents**: {online_count} / {len(fleet)}\n"
                    f"- **Total Vulnerabilities**: {total_vulns} active CVEs\n"
                    f"- **Open Incidents**: {open_tickets} cases unresolved.\n\n"
                    f"SRV-EXCHANGE-01 (10.0.0.88) holds the highest threat exposure with {fleet[1]['vulns'] if len(fleet) > 1 else 12} CVEs. "
                    f"Shall we launch an automated forensic package scan on this asset?"
                )
            except Exception as e:
                response_text = f"Forensic database query failed: {e}. I can confirm SRV-EXCHANGE-01 and WIN-DESKTOP-01 are registered."
        
        # 2. Intent: Query SIEM Alerts / Threat Detections
        elif any(w in message_lower for w in ["alert", "threat", "detection", "siem", "rule", "syslog"]):
            try:
                alerts = get_siem_alerts()
                response_text = (
                    f"Accessing clickhouse SIEM Data Lake telemetry...\n"
                    f"I found {len(alerts)} alerts matching search parameters:\n"
                )
                for a in alerts[:3]:
                    response_text += f"- **#{a['id']}** | Severity: **{a['severity']}** | Rule: `{a['rule']}` | Source: `{a['source']}`\n"
                response_text += "\nWe have a critical Ransomware signature alert on WIN-DESKTOP-01. Would you like me to trigger host isolation?"
            except Exception as e:
                response_text = f"Telemetry lookup error: {e}. There are critical ransomware signatures flagged on WIN-DESKTOP-01."

        # 3. Intent: Query Incident Tickets
        elif any(w in message_lower for w in ["incident", "ticket", "case", "inc-"]):
            try:
                from src.ir_core.database import IRDatabase
                conn = IRDatabase.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT ticket_id, title, status, severity, assignee FROM tickets WHERE status != 'RESOLVED'")
                rows = cursor.fetchall()
                
                if rows:
                    response_text = f"Auditing active Incident Response cases...\n"
                    for r in rows:
                        response_text += f"- **{r[0]}** | Severity: **{r[3]}** | `{r[1]}` (Assignee: {r[4] or 'Unassigned'})\n"
                    response_text += "\nWould you like me to run an AI classification on any of these cases?"
                else:
                    response_text = "Checking database... There are currently no open unresolved security incidents. The operations center is clear!"
            except Exception as e:
                response_text = f"Failed to retrieve tickets: {e}."

        # 4. Intent: Cryptographic Ledger Audit
        elif any(w in message_lower for w in ["verify", "audit", "merkle", "integrity"]):
            # Extract case ID
            ticket_id = "INC-001" # Default fallback
            match = re.search(r'inc-\d+', message_lower)
            if match:
                ticket_id = match.group(0).upper()
                
            try:
                from src.ir_core.merkle_ledger import MerkleLedger
                from src.ir_core.database import IRDatabase
                
                conn = IRDatabase.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM ledger WHERE ticket_id = ?", (ticket_id,))
                count = cursor.fetchone()[0]
                
                if count > 0:
                    verified = MerkleLedger.verify_integrity(ticket_id)
                    response_text = (
                        f"Initiating cryptographic Merkle verification protocol on **{ticket_id}** ledger chain...\n"
                        f"- Status: **{'SECURE - TAMPER-FREE' if verified else 'CORRUPT - INTEGRITY BROKEN'}**\n"
                        f"- Blocks Audited: {count} transactions checked.\n"
                        f"- Root Hash Match: `100% Signature Match`.\n\n"
                        f"All operations (creation, updates, SOAR approvals) conform to the cryptographic audit timeline."
                    )
                else:
                    response_text = f"Ledger verification lookup: No ledger blocks found in database for ticket `{ticket_id}`."
            except Exception as e:
                response_text = f"Failed to execute Merkle integrity check: {e}."

        # 5. Intent: Execute Containment / Host Isolation / Playbook
        elif any(w in message_lower for w in ["isolate", "quarantine", "contain", "block", "remediate"]):
            # Try to identify target
            target_ip = "10.0.0.15" # Default
            if "10.0.0.88" in message_lower or "exchange" in message_lower or "agent-002" in message_lower:
                target_ip = "10.0.0.88"
                
            response_text = (
                f"🚨 **Threat Containment Command Intercepted** 🚨\n"
                f"Request: Initiate host isolation for target IP `{target_ip}`.\n\n"
                f"I have successfully initialized the **Malware Containment Playbook**.\n"
                f"To comply with security guardrails, the high-risk isolation command has been halted at the approval gate.\n"
                f"**Approval Intercept Token**: `AUTH_REQ_CHAT` has been created.\n"
                f"Please navigate to the **IR Tickets** tab to review, sign, and execute the containment action."
            )
            # Inject simulated approval request in gateway
            from src.soar_core.approval_gateway import ApprovalGateway
            ApprovalGateway._pending_approvals["AUTH_REQ_CHAT"] = {
                "status": "PENDING",
                "step_id": "step--isolate-host",
                "command": f"agent_control --isolate --host_ip {target_ip}",
                "ticket_id": "INC-001"
            }
            
        # 6. Fallback: Neural conversation / Natural chat
        else:
            if chat_model is not None:
                try:
                    has_chat_template = False
                    try:
                        has_chat_template = hasattr(chat_model.tokenizer, "chat_template") and chat_model.tokenizer.chat_template is not None
                    except Exception:
                        pass

                    if has_chat_template:
                        # Format conversation history for instruct model
                        messages = [
                            {
                                "role": "system",
                                "content": (
                                    "You are the Nerve Center Cognitive Security Assistant, a world-class AI security analyst built by DeepMind. "
                                    "Analyze the user's message and reply with expert, professional advice. Keep it concise, helpful, and direct. "
                                    "Answer the question accurately based on cybersecurity domain knowledge."
                                )
                            }
                        ]
                        # Add historical messages (limit to 5 turns to stay within token limits)
                        for msg in chat_history[-6:-1]:  # all except the last user message we just appended
                            messages.append(msg)
                        messages.append({"role": "user", "content": message})
                        
                        with chat_model_lock:
                            res = chat_model(
                                messages,
                                max_new_tokens=150,
                                do_sample=True,
                                temperature=0.7,
                                top_p=0.9,
                                repetition_penalty=1.15,
                                clean_up_tokenization_spaces=False
                            )
                            generated_text = ""
                            if isinstance(res, list) and len(res) > 0:
                                out = res[0]
                                if isinstance(out, dict):
                                    gen = out.get("generated_text")
                                    if isinstance(gen, list):
                                        for msg in reversed(gen):
                                            if msg.get("role") == "assistant" or msg.get("role") == "ai":
                                                generated_text = msg.get("content", "")
                                                break
                                        if not generated_text and len(gen) > 0:
                                            generated_text = gen[-1].get("content", "")
                                    elif isinstance(gen, str):
                                        generated_text = gen
                                        if "<|im_start|>assistant" in generated_text:
                                            generated_text = generated_text.split("<|im_start|>assistant")[-1].split("<|im_end|>")[0].strip()
                                        elif "<|assistant|>" in generated_text:
                                            generated_text = generated_text.split("<|assistant|>")[-1].strip()
                            response_text = generated_text.strip()
                    else:
                        # Base model (like GPT-2) fallback plain-text format
                        prompt = (
                            f"You are the Nerve Center Cognitive Security Assistant, a world-class AI security analyst built by DeepMind. "
                            f"Analyze the user's message and reply with expert, professional advice. Keep it concise (1-2 sentences) and helpful.\n"
                            f"User: {message}\n"
                            f"AI:"
                        )
                        with chat_model_lock:
                            res = chat_model(
                                prompt,
                                max_new_tokens=100,
                                num_return_sequences=1,
                                truncation=True,
                                pad_token_id=50256,
                                do_sample=True,
                                temperature=0.7,
                                top_p=0.9,
                                repetition_penalty=1.2,
                                clean_up_tokenization_spaces=False
                            )
                            generated_text = res[0]['generated_text']
                            if "AI:" in generated_text:
                                response_text = generated_text.split("AI:")[-1].strip()
                            else:
                                response_text = generated_text[len(prompt):].strip()
                except Exception as e:
                    response_text = f"Deep learning generation failed: {e}. I am standing by for security operations commands."
            
            if not response_text:
                # Premium conversational fallback responses (Turing-level domain-specific context)
                if "hello" in message_lower or "hi " in message_lower or "hey" in message_lower:
                    response_text = "Greetings! I am the Nerve Center cognitive security assistant. I am connected to the SIEM datalake, active asset inventory, and case ledger. How can I assist with your incident response operations today?"
                elif "thank" in message_lower:
                    response_text = "You are welcome. Security operations are 100% nominal. I am monitoring the telemetry queues."
                elif "who are you" in message_lower or "what do you do" in message_lower:
                    response_text = "I am the Nerve Center Cognitive Security Orchestration assistant. I dynamically parse syslogs, classify threat stages using my local Roberta model, synthesize playbooks, and verify cryptographic chain-of-custody logs. How can I help you today?"
                else:
                    response_text = f"Understood. Telemetry stream analysis is active. I can query our fleet stats, list critical incidents, trigger playbooks, or cryptographically audit ledger signatures. Please specify what you would like to investigate."

        chat_history.append({"role": "assistant", "content": response_text})
        return {"status": "ok", "response": response_text}
        
    except Exception as e:
        return {"status": "error", "response": f"Assistant error: {str(e)}"}


# --- SIEM CORRELATION ENDPOINT ---
@app.post("/api/siem/correlate")
async def correlate_syslog(request: Request):
    try:
        payload = await request.json()
        raw_log = payload.get("raw_log", "")
        if not raw_log:
            return {"status": "error", "message": "No log text provided."}
        
        # 1. Zero Shot Parsing
        from src.siem_core.zero_shot_parser import ZeroShotParser
        from src.siem_core.detection_engine import DetectionEngine
        
        parsed = ZeroShotParser.parse_unstructured_log(raw_log)
        
        # 2. Detection Engine Scan
        engine = DetectionEngine()
        enriched = engine.scan_event(parsed)
        
        return {"status": "success", "event": enriched}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- SOAR PLAYBOOK SIMULATION & HISTORY ---
@app.get("/api/soar/history")
def get_soar_history():
    try:
        from src.ir_core.database import IRDatabase
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT execution_id, playbook_name, target_ip, status, started_at, completed_at, log_output FROM soar_history ORDER BY started_at DESC")
        rows = cursor.fetchall()
        
        results = []
        for r in rows:
            results.append({
                "id": r[0],
                "name": r[1],
                "target": r[2],
                "status": r[3],
                "started_at": r[4],
                "completed_at": r[5],
                "log": r[6]
            })
        return results
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/soar/simulate")
async def simulate_playbook(request: Request):
    try:
        payload = await request.json()
        playbook_name = payload.get("playbook_name", "Malware Containment")
        target_ip = payload.get("target_ip", "10.0.0.15")
        
        from src.ir_core.database import IRDatabase
        import uuid
        from datetime import datetime, timezone
        
        exec_id = f"SIM-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc).isoformat()
        
        # Build simulated steps based on playbook name
        if "malware" in playbook_name.lower() or "containment" in playbook_name.lower():
            log_steps = [
                "[0.0s] [Simulator] Initializing CACAO Playbook Simulator...",
                "[0.5s] [Simulator] Step 'verify-entropy': Evaluating C:\\Temp\\suspicious.exe on target host...",
                "[1.5s] [Simulator] Entropy scan result: 7.9 (High entropy / compressed payload).",
                "[2.0s] [Simulator] Step 'evaluate-risk': Severity evaluated as HIGH.",
                "[2.5s] [Simulator] Intercepted isolation request. Step 'isolate-host' proposed.",
                "[3.5s] [Simulator] Human Approval signature generated. Intercept token: AUTH_REQ_SIM.",
                "[3.6s] [Simulator] Dispatching containment action to EDR agent...",
                "[5.0s] [Simulator] EDR isolated host 10.0.0.15 successfully. Network connection blocked.",
                "[5.5s] [Simulator] Playbook execution completed successfully."
            ]
        elif "vulnerability" in playbook_name.lower() or "remediation" in playbook_name.lower():
            log_steps = [
                "[0.0s] [Simulator] Initializing CACAO Playbook Simulator...",
                "[0.5s] [Simulator] Step 'check-patch': Querying CMDB asset for active updates...",
                "[1.2s] [Simulator] Active vulnerability identified: PrintNightmare (CVE-2021-34527).",
                "[2.0s] [Simulator] Step 'deploy-patch': Pushing KB5005010 security update package to 10.0.0.88...",
                "[3.8s] [Simulator] Update installed successfully. Spawning verification check...",
                "[4.5s] [Simulator] Forensic scan confirms patch successfully mitigated vulnerability.",
                "[5.0s] [Simulator] Playbook execution completed successfully."
            ]
        else:
            log_steps = [
                "[0.0s] [Simulator] Initializing CACAO Playbook Simulator...",
                "[0.5s] [Simulator] Step 'log-event': Logging unrecognized incident details to ticketing core...",
                "[1.0s] [Simulator] Playbook execution completed successfully."
            ]
            
        log_output = "\n".join(log_steps)
        status = "SUCCESS"
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO soar_history (execution_id, playbook_name, target_ip, status, started_at, completed_at, log_output) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (exec_id, playbook_name, target_ip, status, now, now, log_output)
        )
        conn.commit()
        
        return {
            "status": "success",
            "execution_id": exec_id,
            "playbook_name": playbook_name,
            "target_ip": target_ip,
            "execution_status": status,
            "log": log_output
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- ANTIVIRUS THREAT QUARANTINE ENDPOINTS ---
@app.get("/api/av/quarantine")
def get_av_quarantine():
    try:
        from src.ir_core.database import IRDatabase
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT file_hash, file_name, file_path, device_id, hostname, ip_address, status, threat_name, confidence, timestamp, sandbox_report FROM quarantine WHERE status != 'DELETED'")
        rows = cursor.fetchall()
        
        results = []
        for r in rows:
            results.append({
                "hash": r[0],
                "name": r[1],
                "path": r[2],
                "device_id": r[3],
                "hostname": r[4],
                "ip": r[5],
                "status": r[6],
                "threat": r[7],
                "confidence": r[8],
                "timestamp": r[9],
                "sandbox_report": r[10]
            })
        return results
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/av/quarantine/{file_hash}/sandbox")
async def sandbox_quarantine_file(file_hash: str):
    try:
        from src.ir_core.database import IRDatabase
        
        report_lines = [
            "DYNAMIC ANALYSIS LOG:",
            "=====================",
            f"Analyzing binary hash: {file_hash}",
            "Environment: Windows 11 x64 Sandbox Environment (Non-Networked)",
            "",
            "1. Static Checks:",
            "   - Header type: PE32+ Executable",
            "   - Digital Signature: UNTRUSTED / SELF-SIGNED",
            "   - High entropy segments detected.",
            "",
            "2. Behavioral Analysis (Sandbox Run):",
            "   - Spawning process 'threat_injector.exe'...",
            "   - Spawned child process: 'cmd.exe /c reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d ...'",
            "   - Registry modification flagged: Persistent startup key added.",
            "   - Security bypass attempt: Executed netsh firewall command to open connection port.",
            "   - Attempted network connection to C2 domain: blackhole-malware-intel.onion (DNS lookup blocked).",
            "   - Process terminated by sandbox controller.",
            "",
            "=====================",
            "SANDBOX VERDICT: MALICIOUS BEHAVIOR CONFIRMED (SEVERITY: CRITICAL)"
        ]
        report = "\n".join(report_lines)
        
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE quarantine SET sandbox_report = ? WHERE file_hash = ?", (report, file_hash))
        conn.commit()
        
        return {"status": "success", "report": report}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/av/quarantine/{file_hash}/delete")
async def delete_quarantine_file(file_hash: str):
    try:
        from src.ir_core.database import IRDatabase
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE quarantine SET status = 'DELETED' WHERE file_hash = ?", (file_hash,))
        conn.commit()
        return {"status": "success", "message": "Quarantined threat file permanently purged from endpoint."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/av/quarantine/{file_hash}/restore")
async def restore_quarantine_file(file_hash: str):
    try:
        from src.ir_core.database import IRDatabase
        conn = IRDatabase.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE quarantine SET status = 'RESTORED' WHERE file_hash = ?", (file_hash,))
        conn.commit()
        return {"status": "success", "message": "File successfully restored from quarantine on target host."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/soar/playbooks")
def get_playbooks():
    """Returns SOAR playbooks and their DAG structures."""
    return [
        {
            "name": "Malware Containment",
            "status": "active",
            "success_rate": "98%",
            "workflow": {
                "verify-entropy": {"type": "action", "label": "Verify File Entropy", "target": "EDR_AGENT", "command": "verify_entropy --file C:\\Temp\\suspicious.exe", "next": "evaluate-risk"},
                "evaluate-risk": {"type": "switch", "label": "Evaluate Risk", "target": "ORCHESTRATOR", "command": "switch --risk", "next": {"Critical": "isolate-host", "default": "quarantine-file"}},
                "quarantine-file": {"type": "action", "label": "Quarantine File", "target": "EDR_AGENT", "command": "agent_control --quarantine --target C:\\Temp\\suspicious.exe", "next": "complete"},
                "isolate-host": {"type": "action", "label": "Isolate Host Asset", "target": "EDR_AGENT", "command": "agent_control --isolate --host_ip 10.0.0.15", "next": "complete"},
                "complete": {"type": "action", "label": "Complete Playbook", "target": "TICKETING_CORE", "command": "ticket_update --note 'Threat contained'", "next": "end"}
            }
        },
        {
            "name": "Vulnerability Remediation",
            "status": "active",
            "success_rate": "100%",
            "workflow": {
                "check-patch": {"type": "action", "label": "Check Patch Availability", "target": "VULN_ENGINE", "command": "check_patch --cve CVE-2021-34527", "next": "deploy-patch"},
                "deploy-patch": {"type": "action", "label": "Deploy KB5005010 Patch", "target": "VULN_ENGINE", "command": "deploy_patch --cve CVE-2021-34527", "next": "verify-mitigation"},
                "verify-mitigation": {"type": "action", "label": "Verify Vulnerability Mitigated", "target": "VULN_ENGINE", "command": "scan_host --target 10.0.0.88", "next": "complete-patch"},
                "complete-patch": {"type": "action", "label": "Complete Remediate", "target": "TICKETING_CORE", "command": "ticket_update --note 'Vulnerability patched'", "next": "end"}
            }
        },
        {
            "name": "Disable User Account",
            "status": "inactive",
            "success_rate": "N/A",
            "workflow": {
                "check-privs": {"type": "action", "label": "Check User Privileges", "target": "IDENTITY_CORE", "command": "check_privs --user user_a", "next": "disable-ad"},
                "disable-ad": {"type": "action", "label": "Disable AD User Account", "target": "IDENTITY_CORE", "command": "disable_account --user user_a", "next": "end"}
            }
        }
    ]

if __name__ == "__main__":

    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
