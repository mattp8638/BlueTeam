import os
import yaml
import threading

class AgentConfig:
    """
    Central configuration manager for the BlueTeam Endpoint Agent.
    Reads agent_config.yaml and provides thread-safe access to all settings.
    Supports hot-reloading without restarting the service.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    # Default paths
    INSTALL_DIR = r"C:\ProgramData\BlueTeam"
    CONFIG_SEARCH_PATHS = [
        r"C:\ProgramData\BlueTeam\agent_config.yaml",
        os.path.join(os.path.dirname(__file__), "agent_config.yaml"),
    ]
    
    DEFAULTS = {
        "agent_id": "AGENT-UNREGISTERED",
        "nerve_center_url": "https://localhost:8443/api/v1",
        "nerve_center_api_key": "",
        
        # Heartbeat
        "heartbeat_interval": 60,
        
        # Logging
        "log_dir": r"C:\ProgramData\BlueTeam\logs",
        "log_max_bytes": 10_485_760,  # 10 MB per log file
        "log_backup_count": 5,
        
        # Real-Time File Watcher
        "watched_directories": [
            r"C:\Users",
            r"C:\Windows\Temp",
            r"C:\ProgramData",
        ],
        "watched_extensions": [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".msi"],
        "watcher_exclusions": [
            r"C:\ProgramData\BlueTeam",  # Don't watch ourselves
        ],
        
        # AV Engine
        "yara_rules_dir": r"C:\ProgramData\BlueTeam\yara_rules",
        "quarantine_dir": r"C:\ProgramData\BlueTeam\quarantine",
        "hash_db_path": r"C:\ProgramData\BlueTeam\hash_cache.db",
        "entropy_threshold": 7.5,
        "max_scan_file_size_mb": 100,
        
        # Scheduled Scans
        "quick_scan_paths": [r"C:\Users", r"C:\Windows\Temp"],
        "full_scan_paths": [r"C:\"],
        "quick_scan_interval_hours": 4,
        "full_scan_interval_hours": 168,  # Weekly
        
        # Process Monitor
        "suspicious_process_names": [
            "mimikatz", "psexec", "procdump", "lazagne",
            "bloodhound", "sharphound", "rubeus",
        ],
        "suspicious_cmdline_patterns": [
            "-enc ", "-encodedcommand", "Invoke-WebRequest",
            "downloadstring", "bypass", "hidden",
            "certutil -urlcache", "bitsadmin /transfer",
        ],
        
        # Network Monitor
        "known_bad_ports": [4444, 5555, 6666, 8888, 1337, 31337],
        "c2_check_interval": 30,
        
        # Registry Monitor
        "watched_registry_keys": [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ],
        
        # Self-Protection
        "self_protection_enabled": True,
        "watchdog_check_interval": 5,
        
        # SOAR
        "adhoc_script_require_signature": True,
        "adhoc_script_timeout": 300,  # 5 minutes max
        
        # Updater
        "update_check_interval_hours": 1,
    }
    
    def __init__(self):
        self._config = dict(self.DEFAULTS)
        self._load_from_file()
        
    @classmethod
    def load(cls):
        """Thread-safe singleton loader."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    @classmethod
    def reload(cls):
        """Force a hot-reload of the config from disk."""
        with cls._lock:
            cls._instance = cls()
        return cls._instance
        
    def _load_from_file(self):
        """Search for and load the YAML config file."""
        for path in self.CONFIG_SEARCH_PATHS:
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        file_config = yaml.safe_load(f) or {}
                    # Merge file config over defaults (file wins)
                    self._config.update(file_config)
                    self._config["_config_loaded_from"] = path
                    return
                except Exception as e:
                    print(f"[AgentConfig] WARNING: Failed to parse {path}: {e}")
        
        self._config["_config_loaded_from"] = "DEFAULTS_ONLY"
        
    def get(self, key, default=None):
        return self._config.get(key, default)
    
    def __getitem__(self, key):
        return self._config[key]
    
    def __contains__(self, key):
        return key in self._config
    
    def all(self):
        """Return a copy of the full configuration dict."""
        return dict(self._config)
