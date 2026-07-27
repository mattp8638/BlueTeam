import argparse
import json
import sys
from pathlib import Path

from .dashboard import serve_dashboard, write_dashboard
from .orchestrator import RedTeamOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone redteam application")
    subparsers = parser.add_subparsers(dest="command")

    start_parser = subparsers.add_parser("start", help="Create a new operation")
    start_parser.add_argument("--name", default="Standalone Demo")
    start_parser.add_argument("--target", default="10.0.0.10")

    plan_parser = subparsers.add_parser("plan", help="Build the default task plan")
    plan_parser.add_argument("--name", default="Standalone Demo")
    plan_parser.add_argument("--target", default="10.0.0.10")

    run_parser = subparsers.add_parser("run-task", help="Execute a task")
    run_parser.add_argument("--task-id", required=True)

    dashboard_parser = subparsers.add_parser("dashboard", help="Render or serve the dashboard")
    dashboard_parser.add_argument("--output", default=None)
    dashboard_parser.add_argument("--serve", action="store_true")
    dashboard_parser.add_argument("--port", type=int, default=8000)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    orchestrator = RedTeamOrchestrator()
    if not args.command or args.command == "start":
        operation_id = orchestrator.create_operation(
            operation_name=args.name,
            target_scope={"targets": [args.target]},
            rules_of_engagement={"allowed_methods": ["reconnaissance", "scanning", "exploitation"]},
        )
        report = orchestrator.generate_report()
        print(json.dumps({"operation_id": operation_id, "report": report}, indent=2))
        return

    if args.command == "plan":
        orchestrator.create_operation(
            operation_name=args.name,
            target_scope={"targets": [args.target]},
            rules_of_engagement={"allowed_methods": ["reconnaissance", "scanning", "exploitation"]},
        )
        task_ids = orchestrator.build_default_task_plan()
        print(json.dumps({"task_ids": task_ids}, indent=2))
        return

    if args.command == "run-task":
        if not orchestrator.tasks:
            orchestrator.create_operation(operation_name="Queued Operation", target_scope={"targets": ["10.0.0.10"]}, rules_of_engagement={"allowed_methods": ["reconnaissance"]})
            orchestrator.build_default_task_plan()
        task = orchestrator.run_task(args.task_id)
        print(json.dumps(task, indent=2))
        return

    if args.command == "dashboard":
        payload = orchestrator.get_dashboard_payload()
        if args.serve:
            serve_dashboard(payload, port=args.port)
            return
        output = write_dashboard(args.output or "redteam_dashboard.html", payload)
        print(json.dumps({"dashboard_path": str(output)}, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
