import sys
import os
import time
import threading
from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("ServiceWrapper")

# Try to import pywin32 — only available on Windows with the package installed.
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False
    logger.warning("pywin32 not installed. Windows Service mode unavailable. Running in console mode.")


class BlueTeamService:
    """
    Windows Service wrapper for the BlueTeam Endpoint Agent.
    
    When registered as a service via the installer, this class:
    - Starts automatically on system boot (SERVICE_AUTO_START).
    - Runs under LOCAL_SYSTEM with full privileges.
    - Integrates with the Windows Service Control Manager (SCM).
    - Automatically restarts on crash (configured via sc.exe failure actions).
    
    If pywin32 is not installed or the OS is not Windows, falls back to a
    simple console-mode daemon loop for development/testing.
    """
    
    _svc_name_ = "BlueTeamAgent"
    _svc_display_name_ = "BlueTeam Endpoint Security Agent"
    _svc_description_ = ("Comprehensive endpoint security agent providing real-time "
                         "antivirus, telemetry collection, vulnerability assessment, "
                         "and SOAR-driven automated remediation.")
    
    def __init__(self):
        self._stop_event = threading.Event()
        self._agent_daemon = None
    
    def _start_agent_daemon(self):
        """Import and boot the full agent daemon with all subsystems."""
        from src.endpoint_agent.agent_daemon import EndpointAgentDaemon
        
        config = AgentConfig.load()
        device_context = {
            "device_id": config.get("agent_id", "UNKNOWN"),
            "hostname": os.environ.get("COMPUTERNAME", "UNKNOWN"),
            "ip_address": "0.0.0.0",  # Resolved dynamically below
            "os_family": "Windows",
            "os_version": f"{sys.getwindowsversion().major}.{sys.getwindowsversion().minor}" if hasattr(sys, "getwindowsversion") else "Unknown",
        }
        
        # Attempt to resolve local IP
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            device_context["ip_address"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        
        logger.info(f"Starting agent daemon on {device_context['hostname']} ({device_context['ip_address']})")
        self._agent_daemon = EndpointAgentDaemon(nerve_center=None, device_context=device_context)
        self._agent_daemon.start_all_services()
        
    def _stop_agent_daemon(self):
        if self._agent_daemon:
            self._agent_daemon.stop_all_services()
        
    def run_console(self):
        """Run as a foreground console process (for development/testing)."""
        logger.info("BlueTeam Agent starting in CONSOLE mode (Ctrl+C to stop)...")
        self._start_agent_daemon()
        
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1)
        except KeyboardInterrupt:
            logger.info("Ctrl+C received. Shutting down...")
        finally:
            self._stop_agent_daemon()
            logger.info("BlueTeam Agent stopped.")


if HAS_PYWIN32:
    class BlueTeamWinService(win32serviceutil.ServiceFramework):
        """
        Actual Windows Service class — only defined if pywin32 is available.
        """
        _svc_name_ = BlueTeamService._svc_name_
        _svc_display_name_ = BlueTeamService._svc_display_name_
        _svc_description_ = BlueTeamService._svc_description_
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._service = BlueTeamService()
            
        def SvcStop(self):
            """Called by the SCM when the service is being stopped."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logger.info("SCM issued stop command.")
            self._service._stop_event.set()
            self._service._stop_agent_daemon()
            win32event.SetEvent(self.hWaitStop)
            
        def SvcDoRun(self):
            """Called by the SCM when the service is being started."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            logger.info("BlueTeam Agent starting via Windows Service Control Manager...")
            self._service._start_agent_daemon()
            
            # Block until stop signal
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            logger.info("BlueTeam Agent service stopped.")


def main():
    """
    Entry point. If running with pywin32 service arguments, handle them.
    Otherwise, fall back to console mode.
    """
    if HAS_PYWIN32 and len(sys.argv) > 1 and sys.argv[1] in ("install", "start", "stop", "remove", "debug"):
        win32serviceutil.HandleCommandLine(BlueTeamWinService)
    else:
        service = BlueTeamService()
        service.run_console()


if __name__ == "__main__":
    main()
