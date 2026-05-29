# What's Next: Future Scaling & Roadmap

We have successfully built and integrated the core architecture, including real network telemetry, offline buffering, WebSocket streaming, and in-memory Hugging Face AI integrations.

As the platform moves towards production deployment capable of handling thousands of endpoints, the following architectural upgrades are required.

## Action Items for Next Session

### 1. Replace ClickHouse Mock with Real Database
- **Context:** The SIEM backend is currently using `ClickHouseDataLakeMock` backed by SQLite. Under heavy concurrent load, SQLite will suffer from `database is locked` errors.
- **Action:** Install the official `clickhouse-driver` or `clickhouse-connect` library. Stand up a real ClickHouse instance (via Docker) and rewire `src/siem_core/clickhouse_client.py` to point to the remote cluster.

### 2. Implement a Message Broker (Kafka)
- **Context:** Currently, endpoint agents push telemetry directly to the FastAPI Nerve Center. This synchronous HTTP coupling will crash the web server during a volumetric spike (e.g., a massive malware outbreak generating millions of logs).
- **Action:** Deploy Apache Kafka.
  - Agents will push `syslog` events to a `raw_telemetry` Kafka topic.
  - The SIEM will consume from this topic, run the AI detection, and push alerts to a `siem_alerts` topic.
  - The Nerve Center will read from `siem_alerts` to broadcast via WebSockets.

### 3. SOAR Playbook Execution API Wiring
- **Context:** The UI SOAR dashboard currently simulates executing playbooks via the API. The core DAG runner logic exists in `src/soar_core`, but it isn't wired to the web button.
- **Action:** Wire the `POST /api/soar/execute` FastAPI endpoint to the `DagOrchestrator` in `src/soar_core` so that clicking the "Isolate Host" button in the React UI actually executes physical Python isolation scripts on the endpoint via reverse-shell or polling commands.

### 4. Enhance the AI Reporting Generator
- **Context:** The AI Anomaly Detection is fully integrated, but the `AIReportingEngine` is currently using a fallback generation model (defaulting to `HuggingFaceTB/SmolLM2-1.7B-Instruct`, with fallback to `HuggingFaceTB/SmolLM2-360M-Instruct`).
- **Action:** Once your custom text-generation model is fully trained for Root Cause Analysis, update the pipeline declaration in `src/ir_core/ai_reporting_engine.py` or the `PEN_TEST_CHAT_MODEL` environment variable to point to your new model tag, completing the full end-to-end AI automation flow.
