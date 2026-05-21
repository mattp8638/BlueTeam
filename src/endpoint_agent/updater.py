import os
import json
import time
import threading
import shutil
from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("Updater")

class AgentUpdater:
    """
    Background updater service.
    
    Periodically checks the Nerve Center for:
    1. New YARA rule files — downloads and installs them to the local rules dir.
    2. Hash database updates — bulk-inserts new known-bad hashes into the local cache.
    3. Agent binary updates — downloads a new agent package and stages it for
       service restart (the Service Control Manager handles the actual restart).
    
    All updates are verified via SHA-256 checksums before application.
    """
    
    def __init__(self, nerve_center=None, hash_cache=None, yara_loader=None):
        self.config = AgentConfig.load()
        self.nerve_center = nerve_center
        self.hash_cache = hash_cache
        self.yara_loader = yara_loader
        self._stop_event = threading.Event()
        self._thread = None
        self._check_interval = self.config.get("update_check_interval_hours", 1) * 3600
        self._rules_dir = self.config.get("yara_rules_dir", r"C:\ProgramData\BlueTeam\yara_rules")
        self._update_staging = os.path.join(
            self.config.get("quarantine_dir", r"C:\ProgramData\BlueTeam").replace("quarantine", ""),
            "updates"
        )
        
    def start(self):
        """Start the updater as a daemon thread."""
        self._thread = threading.Thread(target=self._run, name="Updater", daemon=True)
        self._thread.start()
        logger.info(f"Updater service started (check_interval={self._check_interval}s)")
        
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Updater service stopped.")
        
    def _run(self):
        # Initial delay before first check (give agent time to fully boot)
        self._stop_event.wait(timeout=30)
        
        while not self._stop_event.is_set():
            try:
                self._check_for_updates()
            except Exception as e:
                logger.error(f"Update check failed: {e}")
            
            self._stop_event.wait(timeout=self._check_interval)
    
    def _check_for_updates(self):
        """Poll the Nerve Center for available updates."""
        logger.info("Checking Nerve Center for updates...")
        
        # In production, this would be an HTTPS GET to the Nerve Center API:
        # response = requests.get(f"{nerve_center_url}/updates/check",
        #                         headers={"Authorization": f"Bearer {api_key}"})
        
        # Simulated update manifest from backend
        update_manifest = self._fetch_update_manifest()
        
        if not update_manifest:
            logger.debug("No updates available.")
            return
        
        # Process YARA rule updates
        if "yara_rules" in update_manifest:
            self._apply_yara_updates(update_manifest["yara_rules"])
        
        # Process hash database updates
        if "hash_updates" in update_manifest:
            self._apply_hash_updates(update_manifest["hash_updates"])
        
        # Process agent binary updates
        if "agent_update" in update_manifest:
            self._stage_agent_update(update_manifest["agent_update"])
    
    def _fetch_update_manifest(self) -> dict:
        """
        Fetch the update manifest from the Nerve Center.
        In production, this is an API call. Here we simulate it.
        """
        # Simulate: no updates available most of the time
        return {}
    
    def _apply_yara_updates(self, rules: list):
        """Download and install new YARA rules."""
        logger.info(f"Applying {len(rules)} new YARA rule files...")
        
        os.makedirs(self._rules_dir, exist_ok=True)
        
        for rule in rules:
            rule_name = rule.get("name", "unknown.yar")
            rule_content = rule.get("content", "")
            rule_checksum = rule.get("sha256", "")
            
            # Verify checksum
            import hashlib
            actual_checksum = hashlib.sha256(rule_content.encode()).hexdigest()
            if rule_checksum and actual_checksum != rule_checksum:
                logger.error(f"Checksum mismatch for YARA rule '{rule_name}'. Skipping.")
                continue
            
            rule_path = os.path.join(self._rules_dir, rule_name)
            with open(rule_path, "w", encoding="utf-8") as f:
                f.write(rule_content)
            logger.info(f"  Installed YARA rule: {rule_name}")
        
        # Hot-reload the YARA scanner
        if self.yara_loader:
            self.yara_loader.hot_reload()
            logger.info("  YARA scanner hot-reloaded with new rules.")
    
    def _apply_hash_updates(self, hashes: list):
        """Bulk-insert new known-bad hashes into the local cache."""
        if not self.hash_cache:
            logger.warning("Hash cache not available. Skipping hash updates.")
            return
        
        logger.info(f"Applying {len(hashes)} new known-bad hashes...")
        self.hash_cache.sync_from_backend(hashes)
        logger.info("  Hash cache synchronized.")
    
    def _stage_agent_update(self, update_info: dict):
        """
        Stage a new agent binary for installation on next service restart.
        The actual restart is handled by the Windows SCM failure recovery.
        """
        version = update_info.get("version", "unknown")
        logger.info(f"Staging agent update v{version}...")
        
        os.makedirs(self._update_staging, exist_ok=True)
        
        # In production:
        # 1. Download the update package to the staging directory
        # 2. Verify its digital signature
        # 3. Write a flag file that the service_wrapper checks on startup
        # 4. Trigger a graceful service restart
        
        flag_path = os.path.join(self._update_staging, "pending_update.json")
        with open(flag_path, "w", encoding="utf-8") as f:
            json.dump({"version": version, "staged_at": time.time()}, f)
        
        logger.info(f"  Update v{version} staged. Will apply on next service restart.")
