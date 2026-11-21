"""
NetSecure - Network Traffic Monitoring and Security Analysis System
Main FastAPI Application Server
Provides REST APIs and WebSocket real-time packet streaming for all modules.
"""

import os
import shutil
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.config import (
    BASE_DIR, TSHARK_BINARY, SAMPLE_DIR, PCAP_DIR, REPORTS_DIR,
    DEFAULT_MACHINE_A_IP, DEFAULT_MACHINE_B_IP, DEFAULT_TEAM_INFO
)
from backend.database import (
    init_db, get_packets, get_packet_by_id, get_all_sessions, get_latest_session,
    get_ping_logs, get_security_alerts, get_lab_settings, update_lab_setting,
    create_session
)
from backend.capture.interface_manager import get_network_interfaces, get_lab_hosts_info
from backend.capture.capture_engine import capture_engine
from backend.capture.pcap_handler import validate_pcap_header, parse_pcap_file, export_session_to_pcap
from backend.capture.ping_runner import execute_ping
from backend.analyzer.statistics_engine import compute_session_statistics
from backend.protocols import (
    get_icmp_analysis, get_arp_analysis, get_dns_analysis,
    get_http_analysis, get_https_analysis, get_ftp_analysis
)
from backend.security_demo.dummy_server import security_demo_engine
from backend.reports.pdf_generator import generate_pdf_report
from backend.reports.csv_exporter import export_packets_to_csv

# Request Models
class PingRequest(BaseModel):
    target_ip: str
    count: int = 4
    timeout_sec: int = 2

class CaptureStartRequest(BaseModel):
    interface: str
    filter_expr: Optional[str] = ""
    mode: Optional[str] = "auto"
    confirm_authorized: bool = Field(..., description="User explicit authorization to capture LAN traffic")

class LabSettingsUpdate(BaseModel):
    machine_a_ip: Optional[str] = None
    machine_a_mac: Optional[str] = None
    machine_b_ip: Optional[str] = None
    machine_b_mac: Optional[str] = None
    tshark_custom_path: Optional[str] = None

class DummyLoginRequest(BaseModel):
    username: str
    password: str
    protocol: str = "HTTP" # "HTTP" or "HTTPS"
    source_ip: Optional[str] = "192.168.1.10"
    target_ip: Optional[str] = "192.168.1.20"

# Application Lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and seed sample if DB empty
    init_db()
    sessions = get_all_sessions()
    if not sessions:
        # Load sample lab pcap on first run so the dashboard is immediately populated!
        sample_pcap = SAMPLE_DIR / "sample_lan_capture.pcap"
        if sample_pcap.exists():
            s_id = create_session("Initial Lab Exercise 12 Capture", "Ethernet0", source_type="sample_pcap", pcap_file=str(sample_pcap))
            parse_pcap_file(str(sample_pcap), s_id)
            print(f"[NetSecure] Auto-loaded sample capture session #{s_id} on startup.")
    yield
    # Shutdown
    if capture_engine.is_running:
        capture_engine.stop_capture()

app = FastAPI(
    title="NetSecure API",
    description="Backend service for NetSecure Network Traffic Monitoring & Security Analysis System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (Enable React frontend access)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# SYSTEM & LAB STATUS ENDPOINTS
# ==========================================

@app.get("/api/system/status")
def get_system_status():
    tshark_avail = TSHARK_BINARY is not None and Path(TSHARK_BINARY).exists()
    return {
        "status": "online",
        "tshark_installed": tshark_avail,
        "tshark_path": TSHARK_BINARY or "Not detected (Dual Engine Active)",
        "capture_active": capture_engine.is_running,
        "active_interface": capture_engine.interface if capture_engine.is_running else None,
        "engine_mode": capture_engine.capture_mode if capture_engine.is_running else "ready",
        "team_info": DEFAULT_TEAM_INFO
    }

@app.get("/api/system/interfaces")
def get_interfaces():
    return {
        "interfaces": get_network_interfaces(),
        "tshark_installed": TSHARK_BINARY is not None
    }

@app.get("/api/system/lab-hosts")
def get_hosts():
    return get_lab_hosts_info()

@app.post("/api/system/lab-settings")
def save_lab_settings(data: LabSettingsUpdate):
    if data.machine_a_ip: update_lab_setting("machine_a_ip", data.machine_a_ip)
    if data.machine_a_mac: update_lab_setting("machine_a_mac", data.machine_a_mac)
    if data.machine_b_ip: update_lab_setting("machine_b_ip", data.machine_b_ip)
    if data.machine_b_mac: update_lab_setting("machine_b_mac", data.machine_b_mac)
    if data.tshark_custom_path: update_lab_setting("tshark_custom_path", data.tshark_custom_path)
    return {"status": "success", "message": "Lab settings updated successfully."}

# ==========================================
# NETWORK MONITORING & PING MODULE
# ==========================================

@app.post("/api/ping")
def ping_target(req: PingRequest):
    result = execute_ping(req.target_ip, count=req.count, timeout_sec=req.timeout_sec)
    return result

@app.get("/api/ping/logs")
def get_recent_ping_logs(limit: int = 15):
    return {"logs": get_ping_logs(limit=limit)}

# ==========================================
# LIVE CAPTURE & PCAP MANAGEMENT
# ==========================================

@app.post("/api/capture/start")
def start_capture_session(req: CaptureStartRequest):
    if not req.confirm_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User authorization is required to start live packet capture on local network interfaces."
        )
    res = capture_engine.start_capture(
        interface=req.interface,
        filter_expr=req.filter_expr or "",
        mode=req.mode or "auto"
    )
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res

@app.post("/api/capture/stop")
def stop_capture_session():
    res = capture_engine.stop_capture()
    return res

@app.get("/api/capture/status")
def get_capture_status():
    return {
        "is_running": capture_engine.is_running,
        "interface": capture_engine.interface,
        "session_id": capture_engine.active_session_id,
        "packet_counter": capture_engine.packet_counter,
        "engine": capture_engine.capture_mode
    }

@app.get("/api/capture/packets")
def list_captured_packets(
    session_id: Optional[int] = None,
    protocol: Optional[str] = "ALL",
    search: Optional[str] = None,
    limit: int = 250,
    offset: int = 0
):
    # If no session specified, query across all or latest session
    packets = get_packets(session_id=session_id, protocol=protocol, search=search, limit=limit, offset=offset)
    return {
        "count": len(packets),
        "protocol_filter": protocol,
        "packets": packets
    }

@app.get("/api/capture/packets/{packet_id}")
def inspect_single_packet(packet_id: int):
    pkt = get_packet_by_id(packet_id)
    if not pkt:
        raise HTTPException(status_code=404, detail=f"Packet #{packet_id} not found.")
    return pkt

@app.post("/api/capture/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Validate file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in [".pcap", ".pcapng", ".cap"]:
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are supported.")

    content = await file.read()
    is_valid, reason = validate_pcap_header(content)
    if not is_valid:
        raise HTTPException(status_code=400, detail=reason)

    dest_path = PCAP_DIR / f"upload_{int(asyncio.get_event_loop().time())}_{file.filename}"
    with open(dest_path, "wb") as f:
        f.write(content)

    session_id = create_session(
        name=f"Uploaded PCAP: {file.filename}",
        interface="Offline PCAP",
        source_type="upload",
        pcap_file=str(dest_path)
    )

    count, _ = parse_pcap_file(str(dest_path), session_id)
    return {
        "status": "success",
        "session_id": session_id,
        "filename": file.filename,
        "packet_count": count,
        "message": f"Successfully parsed and loaded {count} packets from {file.filename}"
    }

@app.post("/api/capture/load-sample")
def load_sample_pcap():
    sample_file = SAMPLE_DIR / "sample_lan_capture.pcap"
    if not sample_file.exists():
        from sample_data.generate_sample_pcap import generate_sample_pcap
        generate_sample_pcap()

    session_id = create_session(
        name="Lab Exercise 12 Authentic Capture Sample",
        interface="Ethernet0 (Virtual Lab LAN)",
        source_type="sample_pcap",
        pcap_file=str(sample_file)
    )

    count, _ = parse_pcap_file(str(sample_file), session_id)
    return {
        "status": "success",
        "session_id": session_id,
        "packet_count": count,
        "message": f"Loaded {count} authentic lab packets (ICMP, ARP, DNS, HTTP, HTTPS, FTP)."
    }

@app.get("/api/capture/export-pcap")
def download_session_pcap(session_id: Optional[int] = None):
    if not session_id:
        latest = get_latest_session()
        if not latest:
            raise HTTPException(status_code=404, detail="No capture sessions available to export.")
        session_id = latest["id"]
        
    pcap_path = export_session_to_pcap(session_id)
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=Path(pcap_path).name
    )

# ==========================================
# DASHBOARD STATS & PROTOCOL ANALYSES
# ==========================================

@app.get("/api/stats")
def get_dashboard_stats(session_id: Optional[int] = None):
    packets = get_packets(session_id=session_id, limit=2000)
    stats = compute_session_statistics(packets)
    return stats

@app.get("/api/protocols/icmp")
def api_icmp_analysis(session_id: Optional[int] = None):
    return get_icmp_analysis(session_id=session_id)

@app.get("/api/protocols/arp")
def api_arp_analysis(session_id: Optional[int] = None):
    return get_arp_analysis(session_id=session_id)

@app.get("/api/protocols/dns")
def api_dns_analysis(session_id: Optional[int] = None):
    return get_dns_analysis(session_id=session_id)

@app.get("/api/protocols/http")
def api_http_analysis(session_id: Optional[int] = None):
    return get_http_analysis(session_id=session_id)

@app.get("/api/protocols/https")
def api_https_analysis(session_id: Optional[int] = None):
    return get_https_analysis(session_id=session_id)

@app.get("/api/protocols/ftp")
def api_ftp_analysis(session_id: Optional[int] = None):
    return get_ftp_analysis(session_id=session_id)

@app.get("/api/alerts")
def api_security_alerts():
    return {"alerts": get_security_alerts()}

# ==========================================
# HTTP vs HTTPS PASSWORD SNIFFING DEMO
# ==========================================

@app.post("/api/dummy/target-login")
def dummy_target_login_endpoint():
    return {"status": "authenticated", "message": "Dummy form submitted over unencrypted HTTP (Port 8000)"}

@app.post("/api/dummy/login")
def submit_dummy_login(req: DummyLoginRequest):
    result = security_demo_engine.process_dummy_login(
        username=req.username,
        password=req.password,
        protocol=req.protocol,
        source_ip=req.source_ip or DEFAULT_MACHINE_A_IP,
        target_ip=req.target_ip or DEFAULT_MACHINE_B_IP
    )
    return result

@app.get("/api/dummy/history")
def get_dummy_history():
    return {"history": security_demo_engine.get_history()}

# ==========================================
# REPORT GENERATION (PDF & CSV)
# ==========================================

@app.get("/api/reports/pdf")
def export_pdf(session_id: Optional[int] = None):
    pdf_path = generate_pdf_report(session_id=session_id)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=Path(pdf_path).name
    )

@app.get("/api/reports/csv")
def export_csv(session_id: Optional[int] = None):
    csv_path = export_packets_to_csv(session_id=session_id)
    return FileResponse(
        csv_path,
        media_type="text/csv",
        filename=Path(csv_path).name
    )

# ==========================================
# WEBSOCKET REAL-TIME PACKET STREAM
# ==========================================

@app.websocket("/ws/packets")
async def websocket_packet_stream(websocket: WebSocket):
    await websocket.accept()
    # Attach current event loop for thread-safe cross-thread dispatch
    websocket.app_loop = asyncio.get_running_loop()
    capture_engine.register_ws(websocket)
    try:
        while True:
            # Keep connection open; client can send ping or filter changes
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        capture_engine.unregister_ws(websocket)
    except Exception:
        capture_engine.unregister_ws(websocket)

# ==========================================
# STATIC FRONTEND SERVING & SPA FALLBACK
# ==========================================
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("ws"):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        file_path = FRONTEND_DIST / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIST / "index.html")

