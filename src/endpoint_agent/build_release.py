import os
import sys
import shutil
import subprocess

def run_build():
    """Compiles the Python source into standalone executables using PyInstaller."""
    print("=" * 60)
    print("BlueTeam Endpoint Agent — Build Release Pipeline")
    print("=" * 60)
    
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dist_dir = os.path.join(repo_root, "dist")
    build_dir = os.path.join(repo_root, "build")
    
    # Clean previous builds
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir, ignore_errors=True)
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir, ignore_errors=True)
        
    # We need to ensure we include the gui templates and static files for the Dashboard
    gui_dir = os.path.join(os.path.dirname(__file__), "gui")
    
    print("\n[1/4] Compiling BlueTeamAgent.exe (Windows Service)...")
    service_entry = os.path.join(os.path.dirname(__file__), "service_wrapper.py")
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--name", "BlueTeamAgent",
        "--hidden-import", "win32timezone",
        "--hidden-import", "src.endpoint_agent.agent_daemon",
        service_entry
    ], check=True)
    
    print("\n[2/4] Compiling BlueTeamDashboard.exe (GUI)...")
    dashboard_entry = os.path.join(os.path.dirname(__file__), "gui", "app.py")
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed", # No console window for the GUI
        "--name", "BlueTeamDashboard",
        "--add-data", f"{os.path.join(gui_dir, 'templates')};templates",
        "--add-data", f"{os.path.join(gui_dir, 'static')};static",
        dashboard_entry
    ], check=True)
    
    print("\n[3/4] Compiling BlueTeamUninstall.exe...")
    uninstaller_entry = os.path.join(os.path.dirname(__file__), "uninstaller.py")
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--console", # Need console to show uninstallation progress
        "--require-administrator", # Force UAC prompt
        "--name", "BlueTeamUninstall",
        uninstaller_entry
    ], check=True)
    
    print("\n[4/4] Assembling Release Package...")
    release_dir = os.path.join(dist_dir, "BlueTeam_Release")
    os.makedirs(release_dir, exist_ok=True)
    
    # Move executables to release folder
    shutil.copy(os.path.join(dist_dir, "BlueTeamAgent.exe"), release_dir)
    shutil.copy(os.path.join(dist_dir, "BlueTeamDashboard.exe"), release_dir)
    shutil.copy(os.path.join(dist_dir, "BlueTeamUninstall.exe"), release_dir)
    
    # The installer script itself shouldn't be compiled, it is meant to be run by the deployment system 
    # (or we could compile it, but for now we leave it as a script to bundle everything).
    
    print("=" * 60)
    print(f"Build complete! Release package available at: {release_dir}")
    print("=" * 60)

if __name__ == "__main__":
    run_build()
