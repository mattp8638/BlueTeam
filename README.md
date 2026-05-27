# BlueTeam Unified Cybersecurity Operations Platform

An enterprise-grade, end-to-end Cybersecurity Operations Platform encompassing an Endpoint Detection & Response (EDR) agent, Security Information & Event Management (SIEM), Security Orchestration, Automation, and Response (SOAR), and an Incident Response (IR) Ticketing system, all unified beneath a React-powered "Single Pane of Glass" Nerve Center.

## 🚀 Architecture Overview

The platform is divided into five distinct domains:

1. **Endpoint Agent (`src/endpoint_agent`)**
   - A physical, deployable Windows agent built in Python.
   - **Capabilities**: Real-time File Monitoring, concurrent YARA/Heuristics AV Engine, Process & Network Monitoring, Registry Watcher, and Self-Protection.
   - **Networking**: Utilizes HTTP(S) POST requests to transmit telemetry, backed by an **Offline SQLite Buffer** that queues events if the central server goes down.
   - **System Tray GUI**: A user-facing dashboard for the endpoint agent built with `pystray` and `tkinter`.
   - **Compiler**: Bundled into a native Windows `.msi` installer using `cx_Freeze`.

2. **SIEM Core (`src/siem_core`)**
   - Centralized data ingestion pipeline.
   - Normalizes logs using the OCSF (Open Cybersecurity Schema Framework) standard.
   - Cross-references incoming telemetry against MITRE ATT&CK rules.
   - **AI Integration**: Uses an in-memory HuggingFace `transformers` pipeline to lazily load `MattP30098638/PenTest-AI`. The AI dynamically scores logs and escalates threats alongside standard static rules.

3. **SOAR Engine (`src/soar_core`)**
   - Automated playbook execution engine utilizing Directed Acyclic Graphs (DAGs).
   - Executes defensive actions automatically (e.g., isolating a host, quarantining a file) when specific SIEM alert thresholds are crossed.

4. **IR Tickets (`src/ir_core`)**
   - Case management system that escalates severe SIEM alerts into human-assignable Incident Response cases.
   - **Cryptographic Ledger**: Utilizes a Merkle Hash Chain (`SHA-256(payload || prev_hash)`) to ensure all forensic logs and actions are mathematically immutable.
   - **AI Reporting**: Employs local Language Models to automatically generate Root Cause Analyses (RCA) and compliance drafts.

5. **Nerve Center (`src/nerve_center`)**
   - The Central Command Dashboard.
   - **Backend**: High-performance FastAPI server bridging the Python core logic to the web.
   - **Frontend**: A state-of-the-art React (Vite) Single Page Application featuring interactive data visualization.
   - **Real-Time Streaming**: Connected via WebSockets (`/ws/fleet`), eliminating the need for UI polling and delivering instant visual updates when threats are detected.

---

## 🛠️ Technology Stack

- **Core Backend**: Python 3.12+
- **AI/ML**: HuggingFace `transformers`, `torch`
- **Agent GUI**: Custom `tkinter` and `pystray`
- **Agent Compiler**: `cx_Freeze` (for MSI generation)
- **Database Simulation**: SQLite (ClickHouse / Data Lake mocking)
- **Web API**: FastAPI, Uvicorn, Pydantic, WebSockets
- **Web Frontend**: React, Vite, Recharts, Lucide-React, Vanilla CSS (Custom Design System)

---

## ⚙️ Documentation

For detailed instructions on how to start the platform and compile the agent, please refer to the [USER_GUIDE.md](USER_GUIDE.md).

For information on security boundaries, guardrails, and production deployment best practices, please refer to the [SECURITY.md](SECURITY.md).

---

## 🔍 Fault Finding & Troubleshooting

### MSI Build Fails with "Access is Denied" (WinError 5)
- **Cause**: Windows Defender actively scans and locks the `.exe` files the millisecond `cx_Freeze` generates them because they contain YARA engines and security tools.
- **Fix**: Open an elevated PowerShell and add a Defender exclusion for your build directory:
  `Add-MpPreference -ExclusionPath "C:\path\to\BlueTeam"`
  Then, delete the dirty `build/` and `dist/` folders and try again.

### MSI Build Fails with "ModuleNotFoundError: No module named 'servicemanager'"
- **Cause**: The `pywin32` C-extensions cannot be resolved as standard directories by the packager.
- **Fix**: Ensure `pywin32` is installed in your active virtual environment. Check `setup.py` and ensure `win32serviceutil` is listed in the `"includes"` array, not `"packages"`.

### Agents Not Showing up in the React Dashboard
- **Cause**: The Agent is trying to push data to the wrong API URL.
- **Fix**: 
  1. Open the BlueTeam System Tray icon on the endpoint.
  2. Navigate to **Settings**.
  3. Ensure the **Nerve Center API URL** is exactly `http://127.0.0.1:8000/api/v1`.
  4. Ensure the React UI is running and checking the WebSocket endpoint.
