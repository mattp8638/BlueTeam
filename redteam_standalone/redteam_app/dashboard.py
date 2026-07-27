from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional


def build_dashboard_html(payload: Dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    tasks = payload.get("tasks", [])
    findings = payload.get("findings", [])
    operations = payload.get("operations", [])

    task_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(task.get('task_id', '')))}</td>
          <td>{html.escape(str(task.get('name', '')))}</td>
          <td>{html.escape(str(task.get('category', '')))}</td>
          <td>{html.escape(str(task.get('status', '')))}</td>
          <td>{html.escape(str(task.get('summary', '')))}</td>
        </tr>
        """
        for task in tasks
    )

    finding_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(finding.get('finding_id', '')))}</td>
          <td>{html.escape(str(finding.get('title', '')))}</td>
          <td>{html.escape(str(finding.get('severity', '')))}</td>
          <td>{html.escape(str(finding.get('evidence', '')))}</td>
        </tr>
        """
        for finding in findings
    )

    operation_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(op.get('operation_id', '')))}</td>
          <td>{html.escape(str(op.get('operation_name', '')))}</td>
          <td>{html.escape(str(op.get('status', '')))}</td>
          <td>{html.escape(str(op.get('phase', '')))}</td>
        </tr>
        """
        for op in operations
    )

    return f"""<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Standalone RedTeam Dashboard</title>
    <style>
      :root {{ color-scheme: dark; }}
      body {{ font-family: Arial, sans-serif; margin: 0; background: #07111f; color: #f3f6ff; }}
      .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
      .hero {{ background: linear-gradient(135deg, #0f2f5a, #1a5fb4); padding: 20px; border-radius: 16px; margin-bottom: 20px; }}
      .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }}
      .card {{ background: #11253d; padding: 16px; border-radius: 14px; border: 1px solid #23496e; }}
      .card h3 {{ margin: 0 0 8px; font-size: 0.95rem; color: #8fc6ff; }}
      .card .value {{ font-size: 1.5rem; font-weight: bold; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
      th, td {{ padding: 10px; border-bottom: 1px solid #23496e; text-align: left; }}
      th {{ background: #18314b; }}
      section {{ background: #10233a; padding: 16px; border-radius: 16px; margin-bottom: 20px; }}
      .status {{ display: inline-block; padding: 4px 8px; border-radius: 999px; background: #265f3f; }}
      code {{ background: #0c1726; padding: 2px 4px; border-radius: 4px; }}
    </style>
  </head>
  <body>
    <div class=\"wrap\">
      <div class=\"hero\">
        <h1>Standalone RedTeam Dashboard</h1>
        <p>Mission control for operations planning, task execution, findings tracking, and reporting.</p>
        <p><strong>Operation:</strong> {html.escape(str(summary.get('operation_name', '')))} <span class=\"status\">{html.escape(str(summary.get('status', '')))}</span></p>
      </div>

      <div class=\"cards\">
        <div class=\"card\"><h3>Operation ID</h3><div class=\"value\">{html.escape(str(summary.get('operation_id', '')))}</div></div>
        <div class=\"card\"><h3>Target Count</h3><div class=\"value\">{summary.get('target_count', 0)}</div></div>
        <div class=\"card\"><h3>Tasks</h3><div class=\"value\">{summary.get('task_count', 0)}</div></div>
        <div class=\"card\"><h3>Findings</h3><div class=\"value\">{summary.get('finding_count', 0)}</div></div>
      </div>

      <section>
        <h2>Operations</h2>
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Phase</th></tr></thead>
          <tbody>{operation_rows}</tbody>
        </table>
      </section>

      <section>
        <h2>Task Plan</h2>
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Status</th><th>Summary</th></tr></thead>
          <tbody>{task_rows}</tbody>
        </table>
      </section>

      <section>
        <h2>Findings</h2>
        <table>
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Evidence</th></tr></thead>
          <tbody>{finding_rows}</tbody>
        </table>
      </section>
    </div>
  </body>
</html>"""


def write_dashboard(output_path: str | Path, payload: Dict[str, Any]) -> Path:
    output = Path(output_path)
    output.write_text(build_dashboard_html(payload), encoding="utf-8")
    return output


def serve_dashboard(payload: Dict[str, Any], host: str = "127.0.0.1", port: int = 8000) -> None:
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = build_dashboard_html(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard available at http://{host}:{port}")
    server.serve_forever()
