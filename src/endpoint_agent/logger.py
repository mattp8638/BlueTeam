import os
import logging
from logging.handlers import RotatingFileHandler
import threading

class AgentLogger:
    """
    Structured logging for every agent module.
    Writes to both console (stdout) and a rotating file at C:\\ProgramData\\BlueTeam\\logs\\agent.log.
    Thread-safe singleton — all modules share the same underlying handlers.
    """
    
    _initialized = False
    _lock = threading.Lock()
    _log_dir = r"C:\ProgramData\BlueTeam\logs"
    _log_file = "agent.log"
    _max_bytes = 10_485_760   # 10 MB
    _backup_count = 5
    
    @classmethod
    def _ensure_initialized(cls):
        """Lazily initialize the root logging handlers once."""
        if cls._initialized:
            return
            
        with cls._lock:
            if cls._initialized:
                return
                
            # Attempt to create the log directory. If we lack permissions
            # (e.g., running tests outside of ProgramData), fall back gracefully.
            try:
                os.makedirs(cls._log_dir, exist_ok=True)
            except OSError:
                cls._log_dir = os.path.join(os.path.dirname(__file__), "logs")
                os.makedirs(cls._log_dir, exist_ok=True)
            
            log_path = os.path.join(cls._log_dir, cls._log_file)
            
            # Formatter: timestamp | level | module | message
            fmt = logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] [%(name)-24s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            
            # File handler (rotating)
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=cls._max_bytes,
                backupCount=cls._backup_count,
                encoding="utf-8"
            )
            file_handler.setFormatter(fmt)
            file_handler.setLevel(logging.DEBUG)
            
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(fmt)
            console_handler.setLevel(logging.INFO)
            
            # Attach to root logger
            root = logging.getLogger("BlueTeamAgent")
            root.setLevel(logging.DEBUG)
            root.addHandler(file_handler)
            root.addHandler(console_handler)
            
            cls._initialized = True
    
    @classmethod
    def get_logger(cls, module_name: str) -> logging.Logger:
        """
        Returns a named child logger for the given module.
        Usage: logger = AgentLogger.get_logger("FileWatcher")
        """
        cls._ensure_initialized()
        return logging.getLogger(f"BlueTeamAgent.{module_name}")
