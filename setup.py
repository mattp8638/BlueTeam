import os
import sys
from cx_Freeze import setup, Executable

# Increase recursion depth for complex dependencies
sys.setrecursionlimit(5000)

build_exe_options = {
    "packages": ["os", "sys", "json", "threading", "time", "subprocess", "hashlib", "yaml", "flask", "psutil", "pystray", "PIL", "watchdog", "email"],
    "includes": ["win32serviceutil", "win32service", "win32event", "servicemanager"],
    "excludes": ["tkinter", "unittest"],
    "include_msvcr": True,
    "include_files": [
        ("src/endpoint_agent/gui/templates", "templates"),
        ("src/endpoint_agent/gui/static", "static"),
        ("src/endpoint_agent/agent_config.yaml", "agent_config.yaml")
    ],
    "build_exe": "build/cx_exe"
}

# bdist_msi options
bdist_msi_options = {
    "upgrade_code": "{A1B2C3D4-E5F6-1234-5678-90ABCDEF1234}",
    "add_to_path": False,
    "initial_target_dir": r"[ProgramFiles64Folder]\BlueTeamAgent",
    "all_users": True, # Enforces per-machine install (Forces UAC Admin Prompt)
    "summary_data": {
        "author": "BlueTeam Cyber",
        "comments": "Enterprise Endpoint Security Agent",
        "keywords": "Security, AV, Agent",
    },
    # The install_script runs AFTER the MSI drops the files, using the bundled Python.
    # It will register the Windows Service and lock down the directory.
    "install_script": "install_hook.py"
}

# The executables to compile
executables = [
    Executable(
        script="src/endpoint_agent/service_wrapper.py",
        target_name="BlueTeamAgent.exe",
        base="Console",  # Needs console to receive service arguments
        icon=None
    ),
    Executable(
        script="src/endpoint_agent/gui/app.py",
        target_name="BlueTeamDashboard.exe",
        base="Console", # Or "Win32GUI" if we don't want a console window popping up
        icon=None
    ),
    Executable(
        script="src/endpoint_agent/uninstaller.py",
        target_name="BlueTeamUninstall.exe",
        base="Console", 
        icon=None
    )
]

setup(
    name="BlueTeamAgent",
    version="2.0.0",
    description="BlueTeam Endpoint Security Agent",
    author="BlueTeam Cyber",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=executables,
    scripts=["src/endpoint_agent/install_hook.py"]
)
