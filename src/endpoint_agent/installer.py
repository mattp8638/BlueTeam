import os
import sys
import shutil
import subprocess
import ctypes
import winreg

class AgentDeployment:
    """
    Production Deployment Installer for the compiled BlueTeam Agent.
    
    This script is intended to be run AFTER build_release.py has generated the .exe files.
    It takes the compiled binaries and deploys them to C:\\Program Files\\, locks them down,
    and registers the uninstaller in the Windows Registry.
    """
    
    SERVICE_NAME = "BlueTeamAgent"
    PROGRAM_FILES_DIR = r"C:\Program Files\BlueTeam"
    PROGRAM_DATA_DIR = r"C:\ProgramData\BlueTeam"
    REGISTRY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BlueTeamAgent"
    
    DATA_SUBDIRS = ["logs", "quarantine", "yara_rules", "updates", "scripts"]
    
    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @classmethod
    def install(cls):
        print("=" * 60)
        print("BlueTeam Endpoint Agent — Production Installer")
        print("=" * 60)
        
        if not cls.is_admin():
            print("FATAL: This installer must be run as Administrator.")
            sys.exit(1)
            
        # Ensure we are running from a location where the compiled binaries exist
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        release_dir = os.path.join(repo_root, "dist", "BlueTeam_Release")
        
        if not os.path.exists(os.path.join(release_dir, "BlueTeamAgent.exe")):
            print(f"FATAL: Compiled binaries not found in {release_dir}.")
            print("Please run build_release.py first.")
            sys.exit(1)
            
        cls._create_directories()
        cls._copy_binaries(release_dir)
        cls._lockdown_program_files()
        cls._create_registry_uninstaller()
        cls._add_defender_exclusions()
        cls._register_and_start_service()
        
        print("\n" + "=" * 60)
        print("Installation complete! BlueTeam Agent is now running securely.")
        print("=" * 60)

    @classmethod
    def _create_directories(cls):
        print(f"\n[1/6] Creating deployment directories...")
        os.makedirs(cls.PROGRAM_FILES_DIR, exist_ok=True)
        print(f"  -> Created {cls.PROGRAM_FILES_DIR}")
        
        for subdir in cls.DATA_SUBDIRS:
            path = os.path.join(cls.PROGRAM_DATA_DIR, subdir)
            os.makedirs(path, exist_ok=True)
        print(f"  -> Created {cls.PROGRAM_DATA_DIR} tree")

    @classmethod
    def _copy_binaries(cls, release_dir):
        print(f"\n[2/6] Copying compiled binaries to Program Files...")
        for file_name in ["BlueTeamAgent.exe", "BlueTeamDashboard.exe", "BlueTeamUninstall.exe"]:
            src = os.path.join(release_dir, file_name)
            dst = os.path.join(cls.PROGRAM_FILES_DIR, file_name)
            if os.path.exists(src):
                shutil.copy2(src, dst)
                print(f"  -> Copied {file_name}")

    @classmethod
    def _lockdown_program_files(cls):
        print(f"\n[3/6] Locking down {cls.PROGRAM_FILES_DIR} (ACL Enforcement)...")
        # Grant SYSTEM Full Control, Administrators Full Control, and Users Read/Execute ONLY.
        # This prevents malware running as a standard user from deleting the agent .exe files.
        try:
            # First reset to inherited
            subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/reset", "/t", "/c", "/q"], capture_output=True)
            # Remove inheritance and copy ACEs
            subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/inheritance:d", "/q"], capture_output=True)
            # Remove Users modify rights, grant only RX (Read & Execute)
            subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/grant:r", "SYSTEM:(OI)(CI)F", "/q"], capture_output=True)
            subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/grant:r", "Administrators:(OI)(CI)F", "/q"], capture_output=True)
            subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/grant:r", "Users:(OI)(CI)RX", "/q"], capture_output=True)
            print("  -> ACLs successfully tightened.")
        except Exception as e:
            print(f"  -> Warning: Failed to apply ACLs: {e}")

    @classmethod
    def _create_registry_uninstaller(cls):
        print(f"\n[4/6] Registering Application in Windows Control Panel...")
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, cls.REGISTRY_KEY)
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "BlueTeam Endpoint Security Agent")
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "2.0.0")
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "BlueTeam Cyber")
            # Point uninstall string to our compiled uninstaller
            uninstall_string = f'"{os.path.join(cls.PROGRAM_FILES_DIR, "BlueTeamUninstall.exe")}"'
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall_string)
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, os.path.join(cls.PROGRAM_FILES_DIR, "BlueTeamAgent.exe"))
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            print("  -> Registry keys injected successfully.")
        except Exception as e:
            print(f"  -> Warning: Failed to write to Registry: {e}")

    @classmethod
    def _add_defender_exclusions(cls):
        print(f"\n[5/6] Configuring Windows Defender Exclusions...")
        try:
            subprocess.run([
                "powershell", "-Command",
                f"Add-MpPreference -ExclusionPath '{cls.PROGRAM_FILES_DIR}'; Add-MpPreference -ExclusionPath '{cls.PROGRAM_DATA_DIR}'"
            ], capture_output=True)
            print("  -> Exclusions applied.")
        except Exception as e:
            print(f"  -> Warning: Failed to add exclusions: {e}")

    @classmethod
    def _register_and_start_service(cls):
        print(f"\n[6/6] Registering and Starting Windows Service...")
        
        # Stop and delete if it already exists
        subprocess.run(["sc", "stop", cls.SERVICE_NAME], capture_output=True)
        subprocess.run(["sc", "delete", cls.SERVICE_NAME], capture_output=True)
        
        agent_exe = os.path.join(cls.PROGRAM_FILES_DIR, "BlueTeamAgent.exe")
        binpath = f'"{agent_exe}" --service'
        
        try:
            subprocess.run(
                ["sc", "create", cls.SERVICE_NAME, f"binPath={binpath}", "start=auto", "DisplayName=BlueTeam Endpoint Security Agent"],
                check=True, capture_output=True
            )
            # Configure auto-restart
            subprocess.run(
                ["sc", "failure", cls.SERVICE_NAME, "reset=86400", "actions=restart/5000/restart/10000/restart/30000"],
                check=True, capture_output=True
            )
            # Start it!
            subprocess.run(["sc", "start", cls.SERVICE_NAME], check=True, capture_output=True)
            print(f"  -> Service '{cls.SERVICE_NAME}' is now running.")
        except subprocess.CalledProcessError as e:
            print(f"  -> Error registering service: {e}")

if __name__ == "__main__":
    AgentDeployment.install()
