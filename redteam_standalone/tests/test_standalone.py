import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam_app.app import create_app
from redteam_app.orchestrator import OperationStatus, RedTeamOrchestrator


def test_initialize_and_generate_report():
    orchestrator = RedTeamOrchestrator()
    operation_id = orchestrator.initialize_operation(
        operation_name="Standalone Demo",
        target_scope={"targets": ["10.0.0.10"]},
        rules_of_engagement={"allowed_methods": ["reconnaissance"]},
    )

    assert operation_id.startswith("redteam-op-")
    assert orchestrator.status == OperationStatus.PENDING

    report = orchestrator.generate_report()
    assert report["operation_id"] == operation_id
    assert report["operation_name"] == "Standalone Demo"


def test_full_assessment_plan_and_dashboard_payload():
    orchestrator = RedTeamOrchestrator()
    operation_id = orchestrator.create_operation(
        operation_name="Full Assessment",
        target_scope={"targets": ["192.168.1.10"], "scope": ["external", "web"]},
        rules_of_engagement={"allowed_methods": ["reconnaissance", "scanning", "exploitation"], "authorized_for_destructive": False},
    )

    task_ids = orchestrator.build_default_task_plan()
    assert len(task_ids) >= 4

    first_task = orchestrator.run_task(task_ids[0])
    dashboard_payload = orchestrator.get_dashboard_payload()

    assert first_task["status"] in {"completed", "queued"}
    assert dashboard_payload["summary"]["task_count"] >= 1
    assert dashboard_payload["summary"]["finding_count"] >= 1
    assert dashboard_payload["operations"][0]["operation_id"] == operation_id


def test_flask_app_routes():
    app = create_app()
    client = app.test_client()

    # Test dashboard route
    response = client.get("/")
    assert response.status_code == 200
    assert b"RedTeam Dashboard" in response.data

    # Test API endpoints
    response = client.get("/api/operations")
    assert response.status_code == 200
    data = response.get_json()
    assert "operations" in data

    # Test create operation
    response = client.post(
        "/api/operations",
        json={
            "operation_name": "Test Op",
            "target_scope": {"targets": ["10.0.0.1"]},
            "rules_of_engagement": {"allowed_methods": ["reconnaissance"]},
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["operation_id"].startswith("redteam-op-")

