# In a real environment, this would run via: uvicorn ingestion_api:app
from fastapi import FastAPI, HTTPException, Request
import json
from src.siem_core.zero_shot_parser import ZeroShotParser
from src.siem_core.detection_engine import DetectionEngine
from src.siem_core.clickhouse_client import ClickHouseDataLakeMock
from src.siem_core.pipeline_monitor import PipelineMonitor

app = FastAPI(title="Unified SIEM Ingestion API")

# Initialize Pipeline Components
parser = ZeroShotParser()
detector = DetectionEngine()
datalake = ClickHouseDataLakeMock()
monitor = PipelineMonitor()

@app.post("/ingest")
async def ingest_telemetry(request: Request):
    """
    Unified API Gateway. Receives telemetry from external sensors intuitively.
    Validates OCSF, parses unstructured data, tags MITRE TTPs, and persists.
    """
    start_time = monitor.start_timer()
    success = True
    
    try:
        # 1. Read Payload
        content_type = request.headers.get("Content-Type", "")
        payload = await request.body()
        payload_str = payload.decode('utf-8')
        
        event_dict = {}
        
        # 2. OCSF Validation & AI Parsing
        if "application/json" in content_type:
            try:
                event_dict = json.loads(payload_str)
                # Ensure it loosely matches OCSF base structure
                if "class_id" not in event_dict:
                    raise ValueError("Missing OCSF class_id")
            except Exception:
                # If JSON is broken or missing OCSF format, route to SLM Parser
                event_dict = parser.parse_unstructured_log(payload_str)
        else:
            # Unstructured plain text (e.g. legacy syslog). Route to SLM Parser.
            event_dict = parser.parse_unstructured_log(payload_str)
            
        # 3. Real-Time Detection & Filtering
        enriched_event = detector.scan_event(event_dict)
        
        # 4. Data Lake Storage
        datalake.batch_insert([enriched_event])
        
    except Exception as e:
        print(f"[Ingestion API] Error processing event: {e}")
        success = False
        raise HTTPException(status_code=500, detail="Internal Pipeline Error")
        
    finally:
        # 5. Record SLA Metrics
        monitor.record_metrics(start_time, success)
        
    return {"status": "Success", "message": "Telemetry Ingested"}

# --- Mock Fast API execution wrapper for the integration test ---
class MockFastAPIClient:
    """A mock client to simulate HTTP POST requests to the FastAPI app locally."""
    def post(self, headers, body_str):
        print(f"\n[HTTP POST /ingest] Receiving {len(body_str)} bytes...")
        
        # Simulate async framework dispatching to our route handler
        class MockRequest:
            def __init__(self, headers, body):
                self.headers = headers
                self._body = body
            async def body(self):
                return self._body.encode('utf-8')
                
        import asyncio
        req = MockRequest(headers, body_str)
        try:
            res = asyncio.run(ingest_telemetry(req))
            return res
        except HTTPException as e:
            return {"status": "Error", "code": e.status_code}
