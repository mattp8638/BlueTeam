# Standalone RedTeam Platform

A complete GUI-first autonomous red team platform for offensive security operations planning, execution, and reporting. Deployable as an independent application separate from the BlueTeam infrastructure.

## Features

- **Operation Lifecycle Management** - Create, plan, approve, and execute coordinated offensive operations
- **Task Planning Engine** - Automated task generation for reconnaissance, exploitation, and evidence collection
- **Real-Time Dashboard** - Web-based mission control center with live operation status and findings tracking
- **Findings & Evidence Tracking** - Capture, categorize, and report security findings with severity levels
- **Phase Transitions** - Plan phases through reconnaissance, exploitation, and reporting with approval gates
- **Report Generation** - Export comprehensive JSON reports of all operation details and findings
- **Fully Self-Contained** - No external dependencies on BlueTeam codebase

## Quick Start

### Install Dependencies

```bash
pip install -e .
```

### Launch Dashboard

```bash
python -m redteam_app
```

The dashboard will be available at `http://localhost:5000`

## Usage

### Via Dashboard (Recommended)

1. **Create Operation** - Navigate to "Create Operation" tab, enter operation details and click "Create Operation"
2. **Build Task Plan** - Click "Build Default Task Plan" to generate reconnaissance and exploitation tasks
3. **Execute Tasks** - Click "Execute" on each task to run it and generate findings
4. **Track Findings** - Add manual findings via the "Findings & Evidence" section
5. **Control Operation** - Change phase and status via the "Operation Control" section
6. **Generate Report** - Click "Generate Report" to export findings as JSON

### API Endpoints

- `GET /` - Dashboard UI
- `GET /api/operations` - List operations
- `POST /api/operations` - Create new operation
- `POST /api/operations/<op_id>/plan` - Build task plan
- `GET /api/operations/<op_id>/tasks` - List tasks
- `POST /api/operations/<op_id>/tasks/<task_id>/run` - Execute task
- `GET /api/operations/<op_id>/findings` - List findings
- `POST /api/operations/<op_id>/findings` - Add finding
- `POST /api/operations/<op_id>/phase` - Change phase
- `POST /api/operations/<op_id>/status` - Change status
- `GET /api/operations/<op_id>/report` - Generate report
- `GET /api/dashboard` - Dashboard data payload

## Project Structure

```
redteam_standalone/
├── redteam_app/
│   ├── app.py - Flask application with API endpoints
│   ├── orchestrator.py - Operation and task execution engine
│   ├── templates/
│   │   └── dashboard.html - GUI dashboard
│   └── static/ - CSS/JS assets
├── tests/
│   └── test_standalone.py - Regression tests
├── pyproject.toml - Dependencies and project config
└── README.md - This file
```

## Development

Run tests:
```bash
pytest tests -v
```

The app supports debug mode with hot reload:
```bash
python -m redteam_app --debug
```

## Architecture

The platform is built around an event-driven orchestrator model:

1. **Operation** - A coordinated engagement with targets, rules of engagement, and approval gates
2. **Tasks** - Individual recon, exploitation, or evidence collection activities
3. **Findings** - Security issues discovered during task execution
4. **Reports** - Comprehensive documentation of operation results

All state is maintained in the `RedTeamOrchestrator` singleton for the current session.
