# BlueTeam Platform - User Guide

Welcome to the BlueTeam Cybersecurity Operations Platform. This guide will walk you through the setup, configuration, and daily operation of the system.

## 1. System Requirements

*   **Operating System**: Windows 10/11 or Windows Server (for the Endpoint Agent), Linux/macOS/Windows (for Nerve Center and Backend Core).
*   **Python**: 3.12+
*   **Node.js**: v18+ (for compiling the React Nerve Center).
*   **Dependencies**:
    *   `pip install -r requirements.txt` (including `fastapi`, `uvicorn`, `requests`, `transformers`, `torch`)
    *   `npm install` (in `src/nerve_center/frontend`)

## 2. Starting the Platform

The platform is composed of several microservices that must be started in the correct sequence.

### Step 2.1: Start the Nerve Center API
The Nerve Center FastAPI backend acts as the central router for all incoming agent telemetry, SIEM routing, and WebSocket broadcasting.

```bash
# From the repository root:
export PYTHONPATH=.
python3 src/nerve_center/api/main.py &
```
*The API will bind to `http://127.0.0.1:8000`.*

### Step 2.2: Start the React Dashboard
The frontend provides the "Single Pane of Glass" visualization.

```bash
cd src/nerve_center/frontend
npm run dev &
```
*Open your browser to `http://localhost:3000`.*

### Step 2.3: Start the Endpoint Agent (Simulation)
To test the agent locally without compiling a full `.msi` Windows installer, you can run the agent integration suite or the daemon directly.

```bash
# From the repository root:
export PYTHONPATH=.
python3 src/endpoint_agent/agent_daemon.py
```
*The agent will immediately begin scanning local files, monitoring processes, and sending a heartbeat (via HTTP POST) to the Nerve Center.*

## 3. Core Capabilities

### 3.1 Offline Buffering
If the Endpoint Agent loses connection to the Nerve Center (e.g., a network outage), it will automatically buffer all telemetry and heartbeats into a local, encrypted SQLite database (`agent_buffer.db`). When the connection is restored, the agent will bulk-flush the queued telemetry to the SIEM to ensure no forensic data is lost.

### 3.2 Real-Time WebSocket Streaming
You do not need to refresh the Nerve Center dashboard. The React frontend maintains a persistent `/ws/fleet` WebSocket connection to the backend. As soon as an agent drops offline, detects malware, or sends telemetry, the UI graphs and status tables will instantly flash and update.

### 3.3 AI Model Integration
The platform comes pre-wired for local, in-memory Hugging Face Inference.
By default, the SIEM `DetectionEngine` lazily loads the `MattP30098638/PenTest-AI` text-classification model via the `transformers` library.

**How it works:**
Every incoming log is passed to both the static Sigma rules and the local HuggingFace AI pipeline. If the AI model classifies the log as a threat with a confidence score `> 0.85`, it will automatically inject an `AI_Generated` tag into the OCSF payload, elevate the severity to `Critical`, and trigger the SOAR isolation playbooks.

*Note: If the `transformers` library is not installed on the host machine, the AI subsystem will gracefully disable itself and fall back entirely to static rule processing.*

## 4. Troubleshooting

*   **ImportError: No module named 'src'**: Ensure you are running Python commands from the absolute root of the repository and that `PYTHONPATH=.` is set in your terminal environment.
*   **Database Locked Errors**: The SIEM currently uses a mock SQLite implementation (`siem_datalake.db`) for ClickHouse. Under extreme, multi-threaded telemetry loads, SQLite may lock. For production environments, refer to the "Future Roadmap" to swap this out for the true `clickhouse-driver`.
