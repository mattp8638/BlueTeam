from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class OperationStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"
    BLOCKED = "blocked"


class OperationPhase(Enum):
    PLANNING = "planning"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class RedTeamOrchestrator:
    """A standalone red-team orchestrator with planning, task execution, evidence, and dashboard support."""

    def __init__(self) -> None:
        self.attack_id: Optional[str] = None
        self.operation_name = "Standalone RedTeam Operation"
        self.current_phase: Optional[OperationPhase] = None
        self.status = OperationStatus.PENDING
        self.target_scope: Dict[str, Any] = {}
        self.rules_of_engagement: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.tasks: List[Dict[str, Any]] = []
        self.operation_start: Optional[datetime] = None
        self.operation_end: Optional[datetime] = None
        self.operations_history: List[Dict[str, Any]] = []

    def initialize_operation(
        self,
        operation_name: str,
        target_scope: Dict[str, Any],
        rules_of_engagement: Dict[str, Any],
    ) -> str:
        self.attack_id = f"redteam-op-{uuid.uuid4().hex[:12].upper()}"
        self.operation_name = operation_name
        self.target_scope = target_scope
        self.rules_of_engagement = rules_of_engagement
        self.status = OperationStatus.PENDING
        self.current_phase = OperationPhase.PLANNING
        self.findings = []
        self.tasks = []
        self.operation_start = datetime.now(timezone.utc)
        self.operation_end = None
        return self.attack_id

    def create_operation(
        self,
        operation_name: str,
        target_scope: Dict[str, Any],
        rules_of_engagement: Dict[str, Any],
    ) -> str:
        operation_id = self.initialize_operation(operation_name, target_scope, rules_of_engagement)
        self.operations_history.append(
            {
                "operation_id": operation_id,
                "operation_name": operation_name,
                "status": self.status.value,
                "phase": self.current_phase.value if self.current_phase else None,
            }
        )
        return operation_id

    def build_default_task_plan(self) -> List[str]:
        task_plan = [
            {
                "task_id": f"task-{len(self.tasks) + 1}",
                "name": "Target enumeration",
                "category": "recon",
                "status": "queued",
                "summary": "Enumerate reachable hosts and exposed services",
            },
            {
                "task_id": f"task-{len(self.tasks) + 2}",
                "name": "Service probing",
                "category": "recon",
                "status": "queued",
                "summary": "Probe discovered services for version and weak points",
            },
            {
                "task_id": f"task-{len(self.tasks) + 3}",
                "name": "Credential testing",
                "category": "credential",
                "status": "queued",
                "summary": "Attempt credential spraying or password policy review",
            },
            {
                "task_id": f"task-{len(self.tasks) + 4}",
                "name": "Evidence collection",
                "category": "evidence",
                "status": "queued",
                "summary": "Capture findings, logs, and artifacts for reporting",
            },
        ]
        self.tasks.extend(task_plan)
        self.current_phase = OperationPhase.RECON
        self.status = OperationStatus.APPROVED
        return [task["task_id"] for task in task_plan]

    def run_task(self, task_id: str) -> Dict[str, Any]:
        task = next((item for item in self.tasks if item.get("task_id") == task_id), None)
        if not task:
            raise KeyError(f"Unknown task: {task_id}")

        task["status"] = "completed"
        task["result"] = f"Executed {task['name']}"
        self.add_finding(
            title=f"{task['name']} completed",
            severity="medium",
            evidence=f"Observed result for {task['name']}",
        )

        if self.status != OperationStatus.RUNNING:
            self.status = OperationStatus.RUNNING
        return task

    def add_finding(self, title: str, severity: str, evidence: str) -> Dict[str, Any]:
        finding = {
            "finding_id": f"finding-{len(self.findings) + 1}",
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.findings.append(finding)
        return finding

    def get_dashboard_payload(self) -> Dict[str, Any]:
        return {
            "summary": {
                "operation_id": self.attack_id,
                "operation_name": self.operation_name,
                "status": self.status.value,
                "phase": self.current_phase.value if self.current_phase else None,
                "target_count": len(self.target_scope.get("targets", [])),
                "task_count": len(self.tasks),
                "finding_count": len(self.findings),
            },
            "operations": self.operations_history + [
                {
                    "operation_id": self.attack_id,
                    "operation_name": self.operation_name,
                    "status": self.status.value,
                    "phase": self.current_phase.value if self.current_phase else None,
                }
            ],
            "tasks": self.tasks,
            "findings": self.findings,
        }

    def generate_report(self) -> Dict[str, Any]:
        return {
            "operation_id": self.attack_id,
            "operation_name": self.operation_name,
            "status": self.status.value,
            "phase": self.current_phase.value if self.current_phase else None,
            "target_scope": self.target_scope,
            "rules_of_engagement": self.rules_of_engagement,
            "findings": self.findings,
            "tasks": self.tasks,
            "started_at": self.operation_start.isoformat() if self.operation_start else None,
        }
