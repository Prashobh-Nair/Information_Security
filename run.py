"""
NetSecure - One-Click Launcher & Server Runner
Detects local IP, frees busy ports, opens the browser, and runs Uvicorn.
"""

import socket
import webbrowser
import threading
import time
import subprocess
import sys
import os

def kill_port_5000():
    """Frees port 5000 if an old frozen process is holding it on Windows."""
    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["cmd", "/c", "netstat -ano | findstr :5000"],
                capture_output=True, text=True, timeout=2
            )
            for line in res.stdout.splitlines():
                if "LISTENING" in line:
                    parts = line.strip().split()
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        except Exception:
            pass

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://localhost:5000")

if __name__ == "__main__":
    kill_port_5000()
    local_ip = get_local_ip()

    print("=" * 70)
    print("  NetSecure: Real Hardware Telemetry & Wireshark Sniffer Lab")
    print("=" * 70)
    print()
    print("  [Status] NetSecure Server is starting...")
    print(f"  - On this Laptop:      http://localhost:5000")
    print(f"  - On Phone / Laptop B:  http://{local_ip}:5000")
    print()
    print("=" * 70)
    print()

    # Launch browser in background
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn Server
    import uvicorn
    uvicorn.run("backend.app:app", host="0.0.0.0", port=5000)
