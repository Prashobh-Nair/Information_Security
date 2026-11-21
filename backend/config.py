"""
NetSecure Configuration Module
Handles application paths, environment variables, TShark discovery, and lab defaults.
Automatically detects active local IP and MAC addresses.
"""

import os
import shutil
import socket
import subprocess
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BASE_DIR / "data"
CERTS_DIR = DATA_DIR / "certs"
PCAP_DIR = BASE_DIR / "captures"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLE_DIR = BASE_DIR / "sample_data"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
CERTS_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "netsecure.db"

# TShark Detection
KNOWN_TSHARK_PATHS = [
    os.getenv("TSHARK_PATH", ""),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    shutil.which("tshark") or "",
    r"/usr/bin/tshark",
    r"/usr/local/bin/tshark",
    r"/opt/homebrew/bin/tshark",
]

def find_tshark_path() -> str | None:
    for path in KNOWN_TSHARK_PATHS:
        if path and Path(path).is_file() and os.access(path, os.X_OK):
            return str(Path(path).resolve())
    which_path = shutil.which("tshark")
    if which_path:
        return which_path
    return None

TSHARK_BINARY = find_tshark_path()

# Automatic Local IP and MAC Detection for Machine A
def detect_local_network_identity():
    """Detects active primary IPv4 address, default gateway, and hardware MAC address."""
    primary_ip = "127.0.0.1"
    primary_mac = "00:00:00:00:00:00"
    gateway_ip = "192.168.1.1"
    interface_name = "Wi-Fi"

    try:
        # Connect to a public DNS IP to determine the outbound socket route
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Fetch MAC and gateway via Windows PowerShell
    try:
        ps_cmd = (
            "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | "
            "Select-Object InterfaceAlias, @{N='MAC'; E={$_.NetAdapter.MacAddress}}, @{N='Gateway'; E={$_.IPv4DefaultGateway.NextHop}} | "
            "ConvertTo-Json -Compress"
        )
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            import json
            cfg = json.loads(res.stdout)
            if isinstance(cfg, list):
                cfg = cfg[0]
            if cfg.get("MAC"):
                primary_mac = cfg["MAC"].replace("-", ":").lower()
            if cfg.get("Gateway"):
                gateway_ip = cfg["Gateway"]
            if cfg.get("InterfaceAlias"):
                interface_name = cfg["InterfaceAlias"]
    except Exception:
        pass

    return primary_ip, primary_mac, gateway_ip, interface_name

LOCAL_IP, LOCAL_MAC, GATEWAY_IP, PRIMARY_INTERFACE = detect_local_network_identity()

DEFAULT_MACHINE_A_IP = LOCAL_IP
DEFAULT_MACHINE_A_MAC = LOCAL_MAC
DEFAULT_MACHINE_B_IP = GATEWAY_IP # Default target to gateway / peer

# Academic Team Information (Lab Project Group of 4)
DEFAULT_TEAM_INFO = {
    "project_name": "NetSecure – Network Traffic Monitoring and Security Analysis System",
    "course": "Information Security (Semester 5)",
    "lab_exercise": "Lab Exercise 12: Wireshark LAN Traffic & Credential Sniffing Analysis",
    "team_members": [
        {"name": "Student Lead (Machine A Operator)", "role": "Traffic Capture & Protocol Analysis"},
        {"name": "Team Member 2 (Machine B Operator)", "role": "Host Administration & Ping Verification"},
        {"name": "Team Member 3", "role": "HTTP/HTTPS Security Sniffing Demonstration"},
        {"name": "Team Member 4", "role": "Network Packet Dissection & Audit Reporting"},
    ]
}
