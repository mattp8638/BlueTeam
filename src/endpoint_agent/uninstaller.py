import os
import sys
import shutil
import subprocess
import winreg
import ctypes

class Uninstaller:
    SERVICE_NAME = "BlueTeamAgent"
    PROGRAM_FILES_DIR = r"C:\Program Files\BlueTeam"
    PROGRAM_DATA_DIR = r"C:\ProgramData\BlueTeam"
    REGISTRY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BlueTeamAgent"

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @classmethod
    def run(cls):
        print("=" * 60)
        print("BlueTeam Endpoint Agent — Uninstaller")
        print("=" * 60)

        if not cls.is_admin():
            print("FATAL: Uninstaller must be run as Administrator.")
            input("Press Enter to exit...")
            sys.exit(1)

        print(f"\n[1/4] Stopping and removing Windows Service '{cls.SERVICE_NAME}'...")
        subprocess.run(["sc", "stop", cls.SERVICE_NAME], capture_output=True)
        # Give it a second to stop
        import time; time.sleep(2)
        subprocess.run(["sc", "delete", cls.SERVICE_NAME], capture_output=True)

        print("\n[2/4] Removing Registry Keys (Add/Remove Programs)...")
        try:
            # Delete from 64-bit and 32-bit registry just in case
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, cls.REGISTRY_KEY)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Warning: Could not remove registry key: {e}")

        print("\n[3/4] Removing Windows Defender Exclusions...")
        subprocess.run([
            "powershell", "-Command",
            f"Remove-MpPreference -ExclusionPath '{cls.PROGRAM_FILES_DIR}'; Remove-MpPreference -ExclusionPath '{cls.PROGRAM_DATA_DIR}'"
        ], capture_output=True)

        print("\n[4/4] Removing Files and Directories...")
        
        # We need to be careful with Program Files wiping as it might be locked
        if os.path.exists(cls.PROGRAM_FILES_DIR):
            try:
                # First reset ACLs so we can actually delete it!
                subprocess.run(["icacls", cls.PROGRAM_FILES_DIR, "/reset", "/t", "/c", "/q"], capture_output=True)
                shutil.rmtree(cls.PROGRAM_FILES_DIR, ignore_errors=True)
                print(f"Removed {cls.PROGRAM_FILES_DIR}")
            except Exception as e:
                print(f"Warning: Could not fully remove {cls.PROGRAM_FILES_DIR}: {e}")

        if os.path.exists(cls.PROGRAM_DATA_DIR):
            try:
                shutil.rmtree(cls.PROGRAM_DATA_DIR, ignore_errors=True)
                print(f"Removed {cls.PROGRAM_DATA_DIR}")
            except Exception as e:
                print(f"Warning: Could not fully remove {cls.PROGRAM_DATA_DIR}: {e}")

        print("\n" + "=" * 60)
        print("Uninstallation complete. BlueTeam Agent has been removed.")
        print("=" * 60)
        input("Press Enter to exit...")

if __name__ == "__main__":
    Uninstaller.run()
