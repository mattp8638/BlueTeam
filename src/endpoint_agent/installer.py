import os
import sys
import shutil
import subprocess
from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("Installer")

class AgentInstaller:
    """
    One-click installer for the BlueTeam Endpoint Agent.
    
    This script must be run with Administrator privileges. It performs:
    1. Creates the C:\\ProgramData\\BlueTeam\\ directory tree.
    2. Copies the agent source files to the install directory.
    3. Creates default YARA rules and hash DB directories.
    4. Registers the agent as a Windows Service (auto-start).
    5. Configures the service to auto-restart on failure.
    6. Optionally adds Windows Defender exclusions for the agent directory.
    7. Starts the service.
    """
    
    INSTALL_ROOT = r"C:\ProgramData\BlueTeam"
    SERVICE_NAME = "BlueTeamAgent"
    
    SUBDIRECTORIES = [
        "logs",
        "quarantine",
        "yara_rules",
        "updates",
        "scripts",
    ]
    
    @classmethod
    def install(cls, add_defender_exclusion: bool = True):
        """Run the full installation sequence."""
        logger.info("=" * 60)
        logger.info("BlueTeam Endpoint Agent — Installation")
        logger.info("=" * 60)
        
        if not cls._check_admin():
            logger.error("FATAL: This installer must be run as Administrator.")
            sys.exit(1)
        
        cls._create_directory_tree()
        cls._copy_agent_files()
        cls._create_default_yara_rules()
        cls._register_windows_service()
        cls._configure_failure_recovery()
        
        if add_defender_exclusion:
            cls._add_defender_exclusion()
        
        cls._start_service()
        
        logger.info("=" * 60)
        logger.info("Installation complete. BlueTeam Agent is now running.")
        logger.info("=" * 60)
    
    @classmethod
    def uninstall(cls):
        """Remove the service and clean up."""
        logger.info("Uninstalling BlueTeam Agent...")
        
        cls._stop_service()
        cls._remove_windows_service()
        cls._remove_defender_exclusion()
        
        # Optionally remove the install directory
        # shutil.rmtree(cls.INSTALL_ROOT, ignore_errors=True)
        logger.info("Uninstallation complete. Data preserved at: " + cls.INSTALL_ROOT)
    
    @classmethod
    def _check_admin(cls) -> bool:
        """Verify we are running with elevated privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            # Non-Windows or ctypes unavailable — assume OK for dev
            logger.warning("Cannot verify admin status (non-Windows?). Proceeding anyway.")
            return True
    
    @classmethod
    def _create_directory_tree(cls):
        """Create the ProgramData directory structure."""
        logger.info(f"Creating directory tree at {cls.INSTALL_ROOT}...")
        
        for subdir in cls.SUBDIRECTORIES:
            path = os.path.join(cls.INSTALL_ROOT, subdir)
            os.makedirs(path, exist_ok=True)
            logger.info(f"  Created: {path}")
    
    @classmethod
    def _copy_agent_files(cls):
        """Copy agent source to the install directory."""
        source_dir = os.path.dirname(os.path.abspath(__file__))
        dest_dir = os.path.join(cls.INSTALL_ROOT, "agent")
        
        logger.info(f"Copying agent files from {source_dir} to {dest_dir}...")
        
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(source_dir, dest_dir)
        
        logger.info(f"  Copied {len(os.listdir(dest_dir))} files.")
    
    @classmethod
    def _create_default_yara_rules(cls):
        """Write a starter YARA rule file to the rules directory."""
        rules_dir = os.path.join(cls.INSTALL_ROOT, "yara_rules")
        starter_rule_path = os.path.join(rules_dir, "default_signatures.yar")
        
        if os.path.exists(starter_rule_path):
            logger.info("Default YARA rules already exist. Skipping.")
            return
        
        starter_rule = """
rule Ransomware_WannaCry_Strings {
    meta:
        description = "Detects WannaCry ransomware based on known strings"
        severity = "critical"
    strings:
        $s1 = "WannaDecryptor" ascii
        $s2 = "tasksche.exe" ascii
        $s3 = ".wnry" ascii
    condition:
        any of them
}

rule Suspicious_PowerShell_Downloader {
    meta:
        description = "Detects obfuscated PowerShell download cradles"
        severity = "high"
    strings:
        $s1 = "Invoke-WebRequest" ascii nocase
        $s2 = "DownloadString" ascii nocase
        $s3 = "-enc" ascii nocase
        $s4 = "bypass" ascii nocase
    condition:
        2 of them
}

rule Suspicious_API_Imports {
    meta:
        description = "Detects PE files importing process injection APIs"
        severity = "high"
    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "CreateRemoteThread" ascii
        $api3 = "WriteProcessMemory" ascii
        $api4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}
"""
        with open(starter_rule_path, "w", encoding="utf-8") as f:
            f.write(starter_rule)
        logger.info(f"  Created default YARA rules at {starter_rule_path}")
    
    @classmethod
    def _register_windows_service(cls):
        """Register the agent as a Windows Service using sc.exe."""
        python_exe = sys.executable
        service_script = os.path.join(cls.INSTALL_ROOT, "agent", "service_wrapper.py")
        
        binpath = f'"{python_exe}" "{service_script}" --service'
        
        logger.info(f"Registering Windows Service '{cls.SERVICE_NAME}'...")
        
        try:
            subprocess.run(
                ["sc", "create", cls.SERVICE_NAME,
                 f"binPath={binpath}",
                 "start=auto",
                 f"DisplayName=BlueTeam Endpoint Security Agent"],
                check=True, capture_output=True, text=True
            )
            logger.info(f"  Service '{cls.SERVICE_NAME}' registered successfully.")
        except subprocess.CalledProcessError as e:
            if "already exists" in (e.stderr or ""):
                logger.warning(f"  Service '{cls.SERVICE_NAME}' already registered. Skipping.")
            else:
                logger.error(f"  Failed to register service: {e.stderr}")
    
    @classmethod
    def _configure_failure_recovery(cls):
        """Configure the service to auto-restart on crash (up to 3 times)."""
        logger.info("Configuring failure recovery (auto-restart on crash)...")
        try:
            subprocess.run(
                ["sc", "failure", cls.SERVICE_NAME,
                 "reset=86400",        # Reset failure count after 24 hours
                 "actions=restart/5000/restart/10000/restart/30000"],  # Restart after 5s, 10s, 30s
                check=True, capture_output=True, text=True
            )
            logger.info("  Failure recovery configured: restart after 5s / 10s / 30s")
        except subprocess.CalledProcessError as e:
            logger.error(f"  Failed to configure recovery: {e.stderr}")
    
    @classmethod
    def _add_defender_exclusion(cls):
        """Add our install directory to Windows Defender exclusions."""
        logger.info(f"Adding Windows Defender exclusion for {cls.INSTALL_ROOT}...")
        try:
            subprocess.run(
                ["powershell", "-Command",
                 f"Add-MpPreference -ExclusionPath '{cls.INSTALL_ROOT}'"],
                check=True, capture_output=True, text=True
            )
            logger.info("  Defender exclusion added.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"  Could not add Defender exclusion: {e}")
    
    @classmethod
    def _remove_defender_exclusion(cls):
        try:
            subprocess.run(
                ["powershell", "-Command",
                 f"Remove-MpPreference -ExclusionPath '{cls.INSTALL_ROOT}'"],
                capture_output=True, text=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    @classmethod
    def _start_service(cls):
        logger.info(f"Starting service '{cls.SERVICE_NAME}'...")
        try:
            subprocess.run(["sc", "start", cls.SERVICE_NAME],
                           check=True, capture_output=True, text=True)
            logger.info("  Service started.")
        except subprocess.CalledProcessError as e:
            logger.warning(f"  Could not start service (may already be running): {e.stderr}")
    
    @classmethod
    def _stop_service(cls):
        try:
            subprocess.run(["sc", "stop", cls.SERVICE_NAME],
                           capture_output=True, text=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    @classmethod
    def _remove_windows_service(cls):
        try:
            subprocess.run(["sc", "delete", cls.SERVICE_NAME],
                           capture_output=True, text=True)
            logger.info(f"  Service '{cls.SERVICE_NAME}' removed.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        AgentInstaller.uninstall()
    else:
        AgentInstaller.install()
