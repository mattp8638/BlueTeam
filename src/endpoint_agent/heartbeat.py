import threading
import time
import json
from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("Heartbeat")

class HeartbeatService:
    """
    Periodic health beacon.
    Sends a JSON heartbeat payload to the Nerve Center every N seconds,
    proving the agent is alive and reporting system vitals.
    """
    
    def __init__(self, nerve_center=None):
        self.config = AgentConfig.load()
        self.nerve_center = nerve_center
        self.interval = self.config.get("heartbeat_interval", 60)
        self._stop_event = threading.Event()
        self._thread = None
        self._beat_count = 0
        
    def start(self):
        """Start the heartbeat as a daemon thread."""
        self._thread = threading.Thread(target=self._run, name="Heartbeat", daemon=True)
        self._thread.start()
        logger.info(f"Heartbeat service started (interval={self.interval}s)")
        
    def stop(self):
        """Gracefully stop the heartbeat."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Heartbeat service stopped.")
        
    def _run(self):
        while not self._stop_event.is_set():
            self._send_beat()
            self._stop_event.wait(timeout=self.interval)
            
    def _send_beat(self):
        self._beat_count += 1
        
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("C:\\")
        except ImportError:
            cpu, mem, disk = 0, None, None
        
        payload = {
            "agent_id": self.config.get("agent_id"),
            "beat_number": self._beat_count,
            "timestamp": time.time(),
            "vitals": {
                "cpu_percent": cpu,
                "ram_used_gb": round(mem.used / (1024**3), 2) if mem else 0,
                "ram_total_gb": round(mem.total / (1024**3), 2) if mem else 0,
                "disk_free_gb": round(disk.free / (1024**3), 2) if disk else 0,
            }
        }
        
        logger.debug(f"Heartbeat #{self._beat_count}: CPU={payload['vitals']['cpu_percent']}% | "
                      f"RAM={payload['vitals']['ram_used_gb']}/{payload['vitals']['ram_total_gb']}GB")
        
        # In production, this would POST to the Nerve Center REST API.
        # For now, if a local Nerve Center reference exists, call it.
        if self.nerve_center and hasattr(self.nerve_center, "receive_heartbeat"):
            self.nerve_center.receive_heartbeat(payload)
