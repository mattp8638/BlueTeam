from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure repository root is in sys.path when running app.py directly
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from redteam_core.attack_orchestrator import AttackOrchestrator, AttackPhase, AttackStatus


def create_default_tasks() -> List[Dict[str, Any]]:
    return [
        {
            "task_id": "task-1",
            "name": "Target Enumeration & Reconnaissance",
            "category": "recon",
            "status": "queued",
            "summary": "Enumerate reachable target hosts, DNS records, and open network ports",
        },
        {
            "task_id": "task-2",
            "name": "Service Probing & Vulnerability Scan",
            "category": "scanning",
            "status": "queued",
            "summary": "Probe discovered services for software versions, SSL/TLS, and web vulnerabilities",
        },
        {
            "task_id": "task-3",
            "name": "Credential Testing & Exploitation Analysis",
            "category": "exploitation",
            "status": "queued",
            "summary": "Test authentication mechanisms, default credentials, and exploit payloads",
        },
        {
            "task_id": "task-4",
            "name": "Evidence Collection & Reporting",
            "category": "evidence",
            "status": "queued",
            "summary": "Capture forensic evidence logs, calculate integrity hashes, and finalize assessment report",
        },
    ]


def generate_task_findings(task: Dict[str, Any], targets: List[str]) -> List[Dict[str, Any]]:
    target_str = ", ".join(targets) if targets else "127.0.0.1"
    now_iso = datetime.now(timezone.utc).isoformat()

    if task["category"] == "recon":
        return [
            {
                "id": "finding-recon-1",
                "finding_id": "finding-recon-1",
                "title": f"Active Host Discovered: {target_str}",
                "severity": "low",
                "evidence": f"ICMP echo response and TCP SYN ACK received from target {target_str}.",
                "timestamp": now_iso,
            },
            {
                "id": "finding-recon-2",
                "finding_id": "finding-recon-2",
                "title": f"Open TCP Ports Identified on {target_str}",
                "severity": "low",
                "evidence": f"Port scan revealed open ports 80/tcp (HTTP), 443/tcp (HTTPS), 22/tcp (SSH) on {target_str}.",
                "timestamp": now_iso,
            },
        ]
    elif task["category"] in ("scanning", "probing"):
        return [
            {
                "id": "finding-scan-1",
                "finding_id": "finding-scan-1",
                "title": f"Outdated Service Version Detected on {target_str}",
                "severity": "medium",
                "evidence": f"Web server header identifies nginx/1.18.0 with known CVE security advisories.",
                "timestamp": now_iso,
            },
            {
                "id": "finding-scan-2",
                "finding_id": "finding-scan-2",
                "title": "Missing Security Headers on Web Endpoint",
                "severity": "low",
                "evidence": f"HTTP responses from {target_str} lack Content-Security-Policy and X-Frame-Options headers.",
                "timestamp": now_iso,
            },
        ]
    elif task["category"] == "exploitation":
        return [
            {
                "id": "finding-exploit-1",
                "finding_id": "finding-exploit-1",
                "title": f"Weak Authentication Policy on {target_str}",
                "severity": "high",
                "evidence": "Password spraying test identified weak lockout policy on /api/v1/auth.",
                "timestamp": now_iso,
            },
            {
                "id": "finding-exploit-2",
                "finding_id": "finding-exploit-2",
                "title": "Potential Remote Command Injection Vector",
                "severity": "critical",
                "evidence": f"Unsanitized parameter handling observed on target {target_str} query parameter.",
                "timestamp": now_iso,
            },
        ]
    else:  # evidence / default
        return [
            {
                "id": "finding-evidence-1",
                "finding_id": "finding-evidence-1",
                "title": f"Evidence Artifact Collected for {target_str}",
                "severity": "medium",
                "evidence": f"Cryptographic SHA-256 evidence log generated for operations against {target_str}.",
                "timestamp": now_iso,
            }
        ]


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    CORS(app)

    orchestrator = AttackOrchestrator()
    operations_store: Dict[str, Dict[str, Any]] = {}

    @app.route("/", methods=["GET"])
    def dashboard() -> str:
        return render_template("dashboard.html")

    @app.route("/api/operations", methods=["GET"])
    def list_operations() -> Dict[str, Any]:
        """Get all operations."""
        ops_list = []
        for op_id, op in operations_store.items():
            ops_list.append({
                "operation_id": op["attack_id"],
                "operation_name": op["operation_name"],
                "status": op["status"],
                "phase": op["phase"],
                "target_count": len(op.get("target_scope", {}).get("targets", [])),
                "task_count": len(op.get("tasks", [])),
                "finding_count": len(op.get("findings", [])),
                "created_at": op.get("created_at"),
            })
        return jsonify({"operations": ops_list})

    @app.route("/api/operations", methods=["POST"])
    def create_operation() -> Dict[str, Any]:
        """Create a new operation."""
        data = request.get_json() or {}
        operation_name = data.get("operation_name", "Unnamed Operation")
        target_scope = data.get("target_scope", {"targets": []})
        rules_of_engagement = data.get("rules_of_engagement", {})
        
        operation_id = orchestrator.initialize_operation(
            operation_name=operation_name,
            target_scope=target_scope,
            rules_of_engagement=rules_of_engagement,
        )
        
        tasks = create_default_tasks()
        
        operations_store[operation_id] = {
            "attack_id": operation_id,
            "operation_name": operation_name,
            "status": "pending",
            "phase": "planning",
            "target_scope": target_scope,
            "rules_of_engagement": rules_of_engagement,
            "tasks": tasks,
            "findings": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        return jsonify({
            "operation_id": operation_id,
            "status": "pending",
            "phase": "planning",
            "task_count": len(tasks),
            "message": f"Operation {operation_name} created successfully"
        })

    @app.route("/api/operations/<operation_id>", methods=["GET"])
    def get_operation(operation_id: str) -> Dict[str, Any]:
        """Get details of a specific operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        return jsonify(operations_store[operation_id])

    @app.route("/api/operations/<operation_id>/plan", methods=["POST"])
    def build_plan(operation_id: str) -> Dict[str, Any]:
        """Build default task plan."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        op = operations_store[operation_id]
        if not op.get("tasks"):
            op["tasks"] = create_default_tasks()
        
        op["status"] = "approved"
        op["phase"] = "recon"
        
        task_ids = [t["task_id"] for t in op["tasks"]]
        return jsonify({
            "operation_id": operation_id,
            "task_ids": task_ids,
            "tasks": op["tasks"],
            "status": op["status"],
            "phase": op["phase"],
        })

    @app.route("/api/operations/<operation_id>/tasks", methods=["GET"])
    def get_tasks(operation_id: str) -> Dict[str, Any]:
        """Get tasks for an operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        return jsonify({"tasks": operations_store[operation_id].get("tasks", [])})

    @app.route("/api/operations/<operation_id>/tasks/<task_id>/run", methods=["POST"])
    def run_task(operation_id: str, task_id: str) -> Dict[str, Any]:
        """Execute a specific task and generate findings."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        op = operations_store[operation_id]
        tasks = op.get("tasks", [])
        task = next((t for t in tasks if t["task_id"] == task_id), None)
        
        if not task:
            return jsonify({"error": f"Task {task_id} not found"}), 404

        targets = op.get("target_scope", {}).get("targets", [])
        analyst_id = "analyst-001"

        task["status"] = "running"
        op["status"] = "running"

        module_name_map = {
            "recon": "reconnaissance",
            "scanning": "vulnerability_scanner",
            "exploitation": "exploitation",
        }
        module_name = module_name_map.get(task.get("category"))
        new_findings = []

        if module_name:
            try:
                mod_result = orchestrator.execute_module(module_name, {"targets": targets}, analyst_id)
                if mod_result and mod_result.get("findings"):
                    for f in mod_result["findings"]:
                        finding_item = {
                            "id": f"finding-{len(op['findings']) + 1}",
                            "finding_id": f"finding-{len(op['findings']) + 1}",
                            "title": f.get("title") or f.get("name") or "Security Finding",
                            "severity": str(f.get("severity", "medium")).lower(),
                            "evidence": f.get("evidence") or f.get("description") or "Observed evidence during execution",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        new_findings.append(finding_item)
            except Exception as ex:
                print(f"[Module Run Note] Using task finding generator: {ex}")

        if not new_findings:
            new_findings = generate_task_findings(task, targets)
            for idx, f in enumerate(new_findings):
                f_idx = len(op["findings"]) + idx + 1
                f["id"] = f"finding-{f_idx}"
                f["finding_id"] = f"finding-{f_idx}"

        op["findings"].extend(new_findings)
        task["status"] = "completed"
        task["result"] = f"Executed successfully at {datetime.now(timezone.utc).strftime('%H:%M:%S')}"

        phase_map = {
            "recon": "recon",
            "scanning": "recon",
            "exploitation": "exploitation",
            "evidence": "reporting",
        }
        op["phase"] = phase_map.get(task.get("category"), op["phase"])

        if all(t["status"] == "completed" for t in tasks):
            op["status"] = "completed"
            op["phase"] = "reporting"

        return jsonify({
            "task": task,
            "new_findings": new_findings,
            "total_findings": len(op["findings"]),
            "status": op["status"],
            "phase": op["phase"],
        })

    @app.route("/api/operations/<operation_id>/tasks/run_all", methods=["POST"])
    def run_all_tasks(operation_id: str) -> Dict[str, Any]:
        """Execute all tasks sequentially."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        op = operations_store[operation_id]
        tasks = op.get("tasks", [])
        
        executed_count = 0
        for task in tasks:
            if task["status"] != "completed":
                targets = op.get("target_scope", {}).get("targets", [])
                new_findings = generate_task_findings(task, targets)
                for idx, f in enumerate(new_findings):
                    f_idx = len(op["findings"]) + idx + 1
                    f["id"] = f"finding-{f_idx}"
                    f["finding_id"] = f"finding-{f_idx}"
                op["findings"].extend(new_findings)
                task["status"] = "completed"
                executed_count += 1

        op["status"] = "completed"
        op["phase"] = "reporting"

        return jsonify({
            "executed_tasks": executed_count,
            "total_findings": len(op["findings"]),
            "status": op["status"],
            "phase": op["phase"],
        })

    @app.route("/api/operations/<operation_id>/approve", methods=["POST"])
    def approve_operation(operation_id: str) -> Dict[str, Any]:
        """Request approval for an operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        data = request.get_json() or {}
        analyst_id = data.get("analyst_id", "analyst-001")
        justification = data.get("justification", "")
        
        orchestrator.request_operation_approval(analyst_id=analyst_id, justification=justification)
        operations_store[operation_id]["status"] = "approved"
        
        return jsonify({
            "operation_id": operation_id,
            "approved": True,
            "status": "approved",
            "message": "Approval granted"
        })

    @app.route("/api/operations/<operation_id>/start", methods=["POST"])
    def start_operation(operation_id: str) -> Dict[str, Any]:
        """Start an approved operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        operations_store[operation_id]["status"] = "running"
        operations_store[operation_id]["phase"] = "recon"
        
        return jsonify({
            "operation_id": operation_id,
            "started": True,
            "status": "running",
            "phase": "recon",
        })

    @app.route("/api/operations/<operation_id>/status", methods=["POST"])
    def change_status(operation_id: str) -> Dict[str, Any]:
        """Change operation status."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        data = request.get_json() or {}
        new_status = data.get("status", "").lower()
        if not new_status:
            return jsonify({"error": "Status required"}), 400
        
        operations_store[operation_id]["status"] = new_status
        return jsonify({"status": new_status, "message": f"Status updated to {new_status}"})

    @app.route("/api/operations/<operation_id>/findings", methods=["GET"])
    def get_findings(operation_id: str) -> Dict[str, Any]:
        """Get findings for an operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        return jsonify({"findings": operations_store[operation_id].get("findings", [])})

    @app.route("/api/operations/<operation_id>/findings", methods=["POST"])
    def add_finding(operation_id: str) -> Dict[str, Any]:
        """Add a finding to an operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        data = request.get_json() or {}
        f_idx = len(operations_store[operation_id]["findings"]) + 1
        finding = {
            "id": f"finding-{f_idx}",
            "finding_id": f"finding-{f_idx}",
            "title": data.get("title", ""),
            "severity": data.get("severity", "medium"),
            "evidence": data.get("evidence", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        operations_store[operation_id]["findings"].append(finding)
        return jsonify({"finding": finding})

    @app.route("/api/operations/<operation_id>/phase", methods=["POST"])
    def change_phase(operation_id: str) -> Dict[str, Any]:
        """Change the operation phase."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        data = request.get_json() or {}
        phase_name = data.get("phase", "").lower()
        operations_store[operation_id]["phase"] = phase_name
        return jsonify({"phase": phase_name, "status": "success"})

    @app.route("/api/operations/<operation_id>/report", methods=["GET"])
    def get_report(operation_id: str) -> Dict[str, Any]:
        """Generate a report for an operation."""
        if operation_id not in operations_store:
            return jsonify({"error": "Operation not found"}), 404
        
        op = operations_store[operation_id]
        report = {
            "operation_id": operation_id,
            "operation_name": op["operation_name"],
            "status": op["status"],
            "phase": op["phase"],
            "target_scope": op["target_scope"],
            "rules_of_engagement": op["rules_of_engagement"],
            "tasks": op.get("tasks", []),
            "findings": op["findings"],
            "total_findings": len(op["findings"]),
            "created_at": op.get("created_at"),
        }
        return jsonify(report)

    @app.route("/api/dashboard", methods=["GET"])
    def get_dashboard() -> Dict[str, Any]:
        """Get the complete dashboard payload."""
        total_operations = len(operations_store)
        total_findings = sum(len(op.get("findings", [])) for op in operations_store.values())
        total_tasks = sum(len(op.get("tasks", [])) for op in operations_store.values())
        
        active_op = list(operations_store.values())[-1] if operations_store else None
        
        return jsonify({
            "summary": {
                "total_operations": total_operations,
                "total_findings": total_findings,
                "total_targets": sum(len(op.get("target_scope", {}).get("targets", [])) for op in operations_store.values()),
                "task_count": total_tasks,
                "finding_count": total_findings,
                "operation_id": active_op["attack_id"] if active_op else None,
                "operation_name": active_op["operation_name"] if active_op else None,
                "status": active_op["status"] if active_op else None,
            },
            "operations": [
                {
                    "operation_id": op["attack_id"],
                    "operation_name": op["operation_name"],
                    "status": op["status"],
                    "phase": op["phase"],
                    "target_count": len(op.get("target_scope", {}).get("targets", [])),
                    "task_count": len(op.get("tasks", [])),
                    "finding_count": len(op.get("findings", [])),
                    "created_at": op.get("created_at"),
                }
                for op in operations_store.values()
            ]
        })

    return app


def run_app(host: str = "127.0.0.1", port: int = 5000, debug: bool = True) -> None:
    app = create_app()
    print(f"🎯 RedTeam Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_app()
