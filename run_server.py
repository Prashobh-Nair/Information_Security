"""
NetSecure Unified Application Launcher
Starts the FastAPI server with production frontend serving and real-time WebSocket backend.
"""

import sys
import os
import webbrowser
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

def main():
    print("=" * 70)
    print("  NETSECURE: NETWORK TRAFFIC MONITORING & SECURITY ANALYSIS SYSTEM")
    print("  University Academic Project • Semester 5 Information Security")
    print("=" * 70)
    print("\n[+] Initializing database and pre-loading sample lab traffic...")
    
    from backend.database import init_db
    init_db()

    print("[+] Launching Web Server on http://127.0.0.1:8000 ...")
    print("    - REST API:     http://127.0.0.1:8000/api")
    print("    - Web UI:       http://127.0.0.1:8000/")
    print("    - WebSocket:    ws://127.0.0.1:8000/ws/packets")
    print("    - Documentation: ./documentation/README.md")
    print("\n[!] Press Ctrl+C to stop the NetSecure service.\n")

    # Optionally auto-open browser
    try:
        webbrowser.open("http://127.0.0.1:8000")
    except Exception:
        pass

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    main()
