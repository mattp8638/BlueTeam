import os
import sys
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
id2label_map = {}
label_map_source = None
label_map_path = os.environ.get("PEN_TEST_AI_LABEL_MAP", os.path.join(os.path.dirname(__file__), "label_map.json"))
model_source = None

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
    "agent-001": {"id": "agent-001", "hostname": "WIN-DESKTOP-01", "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(), "av_hits": 2, "vulns": 5},
    "agent-002": {"id": "agent-002", "hostname": "SRV-EXCHANGE-01", "status": "online", "last_seen": datetime.now(timezone.utc).isoformat(), "av_hits": 0, "vulns": 12},
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
    fleet_agents[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
    fleet_agents[agent_id]["vitals"] = payload.get("vitals", {})
    return {"status": "ok"}

@app.post("/api/v1/telemetry")
async def receive_telemetry(request: Request):
    payload = await request.json()
    # Save to SIEM Data Lake
    if db:
        db.batch_insert([payload])
    return {"status": "ok"}


# --- HUGGINGFACE CLASSIFICATION ENDPOINT ---
@app.on_event("startup")
async def load_hf_model():
    """Try to load the Huggingface pipeline at startup. If `transformers` is not installed
    or loading fails, `classifier` will remain None and the endpoint will return an error.
    """
    global classifier
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
