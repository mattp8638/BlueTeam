from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig
from src.endpoint_agent.heartbeat import HeartbeatService
from src.endpoint_agent.self_protection import SelfProtectionWatchdog
from src.endpoint_agent.realtime_file_watcher import RealtimeFileWatcher
from src.endpoint_agent.process_monitor import ProcessMonitor
from src.endpoint_agent.registry_monitor import RegistryMonitor
from src.endpoint_agent.network_monitor import NetworkMonitor
from src.endpoint_agent.event_log_collector import EventLogCollector
from src.endpoint_agent.local_av_engine import LocalAVEngine
from src.endpoint_agent.yara_rule_loader import YaraRuleLoader
from src.endpoint_agent.hash_cache import HashCache
from src.endpoint_agent.quarantine_vault import QuarantineVault
from src.endpoint_agent.scheduled_scanner import ScheduledScanner
from src.endpoint_agent.action_executor import ActionExecutor
from src.endpoint_agent.vuln_assessor import VulnAssessor
from src.endpoint_agent.updater import AgentUpdater

logger = AgentLogger.get_logger("AgentDaemon")

class EndpointAgentDaemon:
    """
    The Master Agent Service.
    Initializes and wires together all 22 sub-modules.
    """
    
    def __init__(self, nerve_center=None, device_context: dict=None):
        self.config = AgentConfig.load()
        self.nerve_center = nerve_center
        self.device_context = device_context or {}
        self.services = []
        
        logger.info(f"Initializing BlueTeam Agent Daemon v2.0...")
        
        # Layer 1: Infrastructure
        self.heartbeat = HeartbeatService(self.nerve_center)
        self.watchdog = SelfProtectionWatchdog()
        self.updater = AgentUpdater(self.nerve_center)
        
        # Layer 3: Local AV Engine
        self.hash_cache = HashCache()
        self.yara_loader = YaraRuleLoader()
        self.quarantine_vault = QuarantineVault()
        self.local_av = LocalAVEngine(
            hash_cache=self.hash_cache, 
            yara_scanner=self.yara_loader, 
            quarantine_vault=self.quarantine_vault,
            nerve_center=self.nerve_center
        )
        self.scheduled_scanner = ScheduledScanner(self.local_av)
        
        # Layer 2: Sensors
        self.file_watcher = RealtimeFileWatcher(av_callback=self.local_av.scan_file)
        self.process_monitor = ProcessMonitor(nerve_center=self.nerve_center)
        self.registry_monitor = RegistryMonitor(nerve_center=self.nerve_center)
        self.network_monitor = NetworkMonitor(nerve_center=self.nerve_center)
        self.event_log_collector = EventLogCollector(nerve_center=self.nerve_center)
        
        # Layer 4: SOAR
        self.action_executor = ActionExecutor(self.nerve_center)
        self.vuln_assessor = VulnAssessor(self.nerve_center)
        
        # Register for self-protection
        self.watchdog.register_thread("Heartbeat", None, lambda: self.heartbeat.start())
        self.watchdog.register_thread("FileWatcher", None, lambda: self.file_watcher.start())
        self.watchdog.register_thread("ProcessMonitor", None, lambda: self.process_monitor.start())
        self.watchdog.register_thread("RegistryMonitor", None, lambda: self.registry_monitor.start())
        self.watchdog.register_thread("NetworkMonitor", None, lambda: self.network_monitor.start())
        self.watchdog.register_thread("EventLogCollector", None, lambda: self.event_log_collector.start())
        self.watchdog.register_thread("ScheduledScanner", None, lambda: self.scheduled_scanner.start())
        self.watchdog.register_thread("Updater", None, lambda: self.updater.start())
        
    def start_all_services(self):
        logger.info("Starting all agent services...")
        self.yara_loader.load_rules()
        self.heartbeat.start()
        self.file_watcher.start()
        self.process_monitor.start()
        self.registry_monitor.start()
        self.network_monitor.start()
        self.event_log_collector.start()
        self.scheduled_scanner.start()
        self.updater.start()
        
        if self.config.get("self_protection_enabled"):
            self.watchdog.start()
            
        logger.info("Agent initialization complete.")
        
    def stop_all_services(self):
        logger.info("Stopping all agent services...")
        self.watchdog.stop()
        self.heartbeat.stop()
        self.file_watcher.stop()
        self.process_monitor.stop()
        self.registry_monitor.stop()
        self.network_monitor.stop()
        self.event_log_collector.stop()
        self.scheduled_scanner.stop()
        self.updater.stop()
        logger.info("Agent shutdown complete.")
