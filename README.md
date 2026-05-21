# BlueTeam Unified Cybersecurity Operations Platform

An enterprise-grade, end-to-end Cybersecurity Operations Platform encompassing an Endpoint Detection & Response (EDR) agent, Security Information & Event Management (SIEM), Security Orchestration, Automation, and Response (SOAR), and an Incident Response (IR) Ticketing system, all unified beneath a React-powered "Single Pane of Glass" Nerve Center.

## 🚀 Architecture Overview

The platform is divided into five distinct domains:

1. **Endpoint Agent (`src/endpoint_agent`)**
   - A physical, deployable Windows agent built in Python.
   - **Capabilities**: Real-time File Monitoring, YARA-based AV Engine, Process & Network Monitoring, Registry Watcher, and Self-Protection.
   - **System Tray GUI**: A user-facing dashboard for the endpoint agent built with `pystray` and `tkinter`.
   - **Compiler**: Bundled into a native Windows `.msi` installer using `cx_Freeze`.

2. **SIEM Core (`src/siem_core`)**
   - Centralized data ingestion pipeline simulating a high-throughput ClickHouse Data Lake.
   - Normalizes logs using the OCSF (Open Cybersecurity Schema Framework) standard.
   - Cross-references incoming telemetry against MITRE ATT&CK rules.

3. **SOAR Engine (`src/soar_core`)**
   - Automated playbook execution engine utilizing Directed Acyclic Graphs (DAGs).
   - Executes defensive actions automatically (e.g., isolating a host, quarantining a file) when specific SIEM alert thresholds are crossed.

4. **IR Tickets (`src/ir_core`)**
   - Case management system that escalates severe SIEM alerts into human-assignable Incident Response cases.

5. **Nerve Center (`src/nerve_center`)**
   - The Central Command Dashboard.
   - **Backend**: High-performance FastAPI server bridging the Python core logic to the web.
   - **Frontend**: A state-of-the-art React (Vite) Single Page Application featuring interactive data visualization (`recharts`), live telemetry streams, and glassmorphism UI/UX.

---

## 🛠️ Technology Stack

- **Core Backend**: Python 3.14+
- **Agent GUI**: Custom `tkinter` and `pystray`
- **Agent Compiler**: `cx_Freeze` (for MSI generation)
- **Database Simulation**: SQLite (ClickHouse / Data Lake mocking)
- **Web API**: FastAPI, Uvicorn, Pydantic
- **Web Frontend**: React, Vite, Recharts, Lucide-React, Vanilla CSS (Custom Design System)

---

## ⚙️ How to Run the Platform

### 1. Building the Endpoint Agent (MSI)
To compile the endpoint agent into a distributable `.msi` Windows installer:
```powershell
# Ensure you are in the project root
cd C:\Users\matt_admin\Documents\GitHub\BlueTeam\

# Install dependencies (ensure pywin32 is installed)
pip install -r requirements.txt
pip install pywin32 cx_Freeze

# Run the build
python setup.py bdist_msi
```
The compiled installer will be located in the `dist/` directory. 

### 2. Starting the Nerve Center API
The FastAPI backend acts as the bridge receiving agent telemetry and serving the React frontend.
```powershell
cd C:\Users\matt_admin\Documents\GitHub\BlueTeam\src\nerve_center\api
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### 3. Starting the React Dashboard
The premium web dashboard connects to the FastAPI backend.
```powershell
cd C:\Users\matt_admin\Documents\GitHub\BlueTeam\src\nerve_center\frontend
npm install
npm run dev
```
Open your browser to `http://localhost:3000`.

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
  4. Ensure the React UI is running and checking `http://127.0.0.1:8000/api/fleet`.

### Agent Configuration Changes Not Saving
- **Cause**: The agent was installed to `C:\Program Files\BlueTeamAgent\`. Standard users cannot modify files here due to Windows UAC.
- **Fix**: The system is designed to look for an override config in `C:\ProgramData\BlueTeam\agent_config.yaml`. Edit the file located in `ProgramData` instead, as it is globally writable and supersedes the `Program Files` defaults.
