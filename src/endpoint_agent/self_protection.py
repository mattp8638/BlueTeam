import os
import sys
import threading
import time
from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("SelfProtection")

class SelfProtectionWatchdog:
    """
    Anti-Tamper Self-Protection Module.
    
    Monitors the agent's own critical components and ensures they cannot be
    trivially disabled by malware or unauthorized users.
    
    Protections:
    1. Thread Watchdog — monitors all agent daemon threads and respawns any
       that are killed or crash unexpectedly.
    2. File Integrity — periodically hashes the agent's own binaries on disk
       and alerts if they have been tampered with.
    3. Process Guard — monitors the agent's own PID. If the main process is
       killed externally, the Windows Service wrapper (service_wrapper.py)
       handles automatic restart via SCM. This module handles the internal
       thread-level resilience.
    """
    
    def __init__(self):
        self.config = AgentConfig.load()
        self._stop_event = threading.Event()
        self._monitored_threads = {}  # name -> (thread, factory_fn)
        self._watchdog_thread = None
        self._check_interval = self.config.get("watchdog_check_interval", 5)
        self._file_hashes = {}  # path -> sha256
        self._agent_dir = os.path.dirname(os.path.abspath(__file__))
        
    def register_thread(self, name: str, thread: threading.Thread, factory_fn):
        """
        Register a thread for monitoring.
        
        Args:
            name: Human-readable name for the thread (e.g., "FileWatcher").
            thread: The running Thread object.
            factory_fn: A callable that returns a NEW started Thread if respawn is needed.
                        This is critical — you cannot restart a dead Thread object in Python,
                        so the factory must create a fresh one.
        """
        self._monitored_threads[name] = (thread, factory_fn)
        logger.info(f"Registered thread '{name}' for self-protection monitoring.")
        
    def start(self):
        """Start the watchdog as a daemon thread."""
        # Take initial file integrity snapshot
        self._snapshot_file_integrity()
        
        self._watchdog_thread = threading.Thread(
            target=self._run, name="SelfProtection-Watchdog", daemon=True
        )
        self._watchdog_thread.start()
        logger.info(f"Self-Protection Watchdog started (check_interval={self._check_interval}s)")
        
    def stop(self):
        self._stop_event.set()
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=5)
        logger.info("Self-Protection Watchdog stopped.")
        
    def _run(self):
        cycle = 0
        while not self._stop_event.is_set():
            cycle += 1
            
            # Every cycle: check thread health
            self._check_thread_health()
            
            # Every 12th cycle (~60s at 5s interval): verify file integrity
            if cycle % 12 == 0:
                self._verify_file_integrity()
            
            self._stop_event.wait(timeout=self._check_interval)
            
    def _check_thread_health(self):
        """Iterate all registered threads. If any have died, respawn them."""
        for name, (thread, factory_fn) in list(self._monitored_threads.items()):
            if not thread.is_alive():
                logger.warning(f"THREAD DIED: '{name}' is no longer alive! Attempting respawn...")
                
                try:
                    new_thread = factory_fn()
                    self._monitored_threads[name] = (new_thread, factory_fn)
                    logger.info(f"RESPAWNED: Thread '{name}' successfully restarted.")
                except Exception as e:
                    logger.error(f"RESPAWN FAILED for '{name}': {e}")
                    
    def _snapshot_file_integrity(self):
        """Take SHA-256 hashes of all .py files in the agent directory."""
        import hashlib
        
        self._file_hashes.clear()
        for filename in os.listdir(self._agent_dir):
            if filename.endswith(".py"):
                filepath = os.path.join(self._agent_dir, filename)
                try:
                    with open(filepath, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    self._file_hashes[filepath] = file_hash
                except OSError as e:
                    logger.warning(f"Could not hash {filepath}: {e}")
                    
        logger.info(f"File integrity snapshot taken: {len(self._file_hashes)} agent files baselined.")
        
    def _verify_file_integrity(self):
        """Re-hash agent files and compare against baseline. Alert on tampering."""
        import hashlib
        
        tampered = []
        for filepath, expected_hash in self._file_hashes.items():
            try:
                with open(filepath, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != expected_hash:
                    tampered.append(filepath)
            except FileNotFoundError:
                tampered.append(filepath)
                logger.critical(f"AGENT FILE DELETED: {filepath}")
            except OSError:
                pass
                
        if tampered:
            logger.critical(f"FILE INTEGRITY VIOLATION: {len(tampered)} agent files tampered with: {tampered}")
            # In production, this would immediately alert the Nerve Center
            # and potentially trigger a self-healing re-download from the backend.
        else:
            logger.debug("File integrity check passed — all agent files intact.")
