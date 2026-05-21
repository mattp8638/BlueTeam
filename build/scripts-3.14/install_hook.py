import os
import sys
import subprocess

def run_post_install():
    """
    Executed by the MSI installer automatically after files are extracted to C:\\Program Files\\BlueTeamAgent.
    """
    program_files_dir = r"C:\Program Files\BlueTeamAgent"
    program_data_dir = r"C:\ProgramData\BlueTeam"
    service_name = "BlueTeamAgent"
    
    # 1. Create Data Directories
    for subdir in ["logs", "quarantine", "yara_rules", "updates", "scripts"]:
        os.makedirs(os.path.join(program_data_dir, subdir), exist_ok=True)
        
    # 2. Register Windows Service
    agent_exe = os.path.join(program_files_dir, "BlueTeamAgent.exe")
    binpath = f'"{agent_exe}" --service'
    
    # Stop/Delete if upgrading
    subprocess.run(["sc", "stop", service_name], capture_output=True)
    subprocess.run(["sc", "delete", service_name], capture_output=True)
    
    # Create Service
    subprocess.run(
        ["sc", "create", service_name, f"binPath={binpath}", "start=auto", "DisplayName=BlueTeam Endpoint Security Agent"],
        capture_output=True
    )
    subprocess.run(
        ["sc", "failure", service_name, "reset=86400", "actions=restart/5000/restart/10000/restart/30000"],
        capture_output=True
    )
    
    # 3. Lockdown Program Files via ACLs
    subprocess.run(["icacls", program_files_dir, "/inheritance:d", "/q"], capture_output=True)
    subprocess.run(["icacls", program_files_dir, "/grant:r", "SYSTEM:(OI)(CI)F", "/q"], capture_output=True)
    subprocess.run(["icacls", program_files_dir, "/grant:r", "Administrators:(OI)(CI)F", "/q"], capture_output=True)
    subprocess.run(["icacls", program_files_dir, "/grant:r", "Users:(OI)(CI)RX", "/q"], capture_output=True)
    
    # 4. Defender Exclusions
    subprocess.run([
        "powershell", "-Command",
        f"Add-MpPreference -ExclusionPath '{program_files_dir}'; Add-MpPreference -ExclusionPath '{program_data_dir}'"
    ], capture_output=True)
    
    # 5. Start Service
    subprocess.run(["sc", "start", service_name], capture_output=True)
    
    # Create a marker file to prove it ran
    with open(os.path.join(program_data_dir, "install_success.log"), "w") as f:
        f.write("Post-install hook executed successfully.\n")

if __name__ == "__main__":
    run_post_install()
