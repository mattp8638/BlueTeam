import os
import yaml
import threading
import webbrowser
import pystray
from PIL import Image, ImageDraw
from flask import Flask, render_template, request, jsonify

# Add parent directory to path so we can import agent modules
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.endpoint_agent.agent_config import AgentConfig
from src.endpoint_agent.hash_cache import HashCache
from src.endpoint_agent.quarantine_vault import QuarantineVault
from src.endpoint_agent.yara_rule_loader import YaraRuleLoader
from src.endpoint_agent.local_av_engine import LocalAVEngine
from src.endpoint_agent.scheduled_scanner import ScheduledScanner

import sys

if getattr(sys, 'frozen', False):
    # If running as compiled executable
    base_dir = os.path.dirname(sys.executable)
else:
    # If running from python source
    base_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__,
            template_folder=os.path.join(base_dir, 'templates'),
            static_folder=os.path.join(base_dir, 'static'))
config_manager = AgentConfig.load()
hash_cache = HashCache()
vault = QuarantineVault()
yara_loader = YaraRuleLoader()
# Load YARA rules into memory
yara_loader.load_rules()

local_av = LocalAVEngine()
scanner = ScheduledScanner(local_av)

@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Return local agent status."""
    # Check if the service is actually running in the background.
    # For now, we simulate "Online" if the config loads.
    stats = hash_cache.get_stats()
    return jsonify({
        "status": "Online",
        "agent_id": config_manager.get("agent_id"),
        "hashes_scanned": sum(stats.values()),
        "malicious_found": stats.get("MALICIOUS", 0)
    })

@app.route('/api/config', methods=['GET'])
def get_config():
    """Return current configuration."""
    return jsonify({
        "nerve_center_url": config_manager.get("nerve_center_url"),
        "agent_id": config_manager.get("agent_id")
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration and save to YAML."""
    data = request.json
    
    # Read existing
    yaml_path = r"C:\ProgramData\BlueTeam\agent_config.yaml"
    # Fallback to local repo path for dev
    if not os.path.exists(yaml_path):
        yaml_path = os.path.join(os.path.dirname(__file__), "..", "agent_config.yaml")
        
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            current_config = yaml.safe_load(f) or {}
    except Exception:
        current_config = {}
        
    # Update fields
    if "nerve_center_url" in data:
        current_config["nerve_center_url"] = data["nerve_center_url"]
    if "agent_id" in data:
        current_config["agent_id"] = data["agent_id"]
        
    # Write back
    try:
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(current_config, f, default_flow_style=False)
        # Hot reload in memory
        AgentConfig.reload()
        return jsonify({"success": True, "message": "Configuration saved successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/quarantine', methods=['GET'])
def get_quarantine():
    """List quarantined files."""
    files = vault.list_quarantined()
    return jsonify({"files": files})

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Trigger an offline local scan."""
    data = request.json
    scan_type = data.get("type", "quick")
    
    # Run the scan in a background thread so it doesn't block the Flask request
    if scan_type == "quick":
        threading.Thread(target=scanner.quick_scan, daemon=True).start()
    elif scan_type == "full":
        threading.Thread(target=scanner.full_scan, daemon=True).start()
        
    return jsonify({
        "success": True, 
        "message": f"Offline {scan_type.capitalize()} Scan initiated locally in the background."
    })

def create_tray_image():
    """Generates a dynamic shield icon for the system tray."""
    image = Image.new('RGB', (64, 64), color=(40, 44, 52))
    dc = ImageDraw.Draw(image)
    # Draw a simple blue shield
    dc.polygon([(32, 10), (10, 20), (10, 50), (32, 60), (54, 50), (54, 20)], fill=(0, 120, 215))
    return image

def on_open_dashboard(icon, item):
    """Opens the dashboard in the default web browser."""
    webbrowser.open("http://127.0.0.1:5000")

def on_quick_scan(icon, item):
    """Triggers a quick scan in the background."""
    threading.Thread(target=scanner.quick_scan, daemon=True).start()

def on_full_scan(icon, item):
    """Triggers a full scan in the background."""
    threading.Thread(target=scanner.full_scan, daemon=True).start()

def on_exit(icon, item):
    """Shuts down the tray icon and the Flask server."""
    icon.stop()
    os._exit(0)

if __name__ == '__main__':
    # Start the Flask web server in a background daemon thread
    flask_thread = threading.Thread(
        target=lambda: app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False),
        daemon=True
    )
    flask_thread.start()
    
    # Configure and start the System Tray Icon on the main thread
    menu = pystray.Menu(
        pystray.MenuItem("Open Dashboard", on_open_dashboard, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Run Quick Scan", on_quick_scan),
        pystray.MenuItem("Run Full Scan", on_full_scan),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", on_exit)
    )
    
    icon = pystray.Icon("BlueTeamAgent", create_tray_image(), "BlueTeam Endpoint Agent", menu)
    print("Starting BlueTeam System Tray Icon...")
    icon.run()
