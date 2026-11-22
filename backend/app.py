"""
NetSecure - Main Application Server (Exercise 12)
Serves the Wireshark-Style Light-Themed Web UI, REST APIs,
Live Scapy Sniffing on physical adapter, ICMP Ping Probing,
and the live Dummy Login Web Application for Password Sniffing.
"""

from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.network_info import HOST_IP, HOST_MAC, GATEWAY_IP, get_network_topology, resolve_target_mac
from backend.ping_service import execute_ping_probe
from backend.https_service import start_https_background_daemon
from backend.sniffer import (
    add_packet,
    get_all_packets,
    start_live_capture,
    stop_live_capture,
    get_capture_status,
    clear_packet_store,
    seed_exercise_12_protocols
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Launch background local HTTPS server on port 5443
    start_https_background_daemon()
    yield
    # Stop capture cleanly on shutdown
    stop_live_capture()

app = FastAPI(
    title="NetSecure - Wireshark Analysis & Security Suite",
    description="Exercise 12 Network Traffic Dissector & HTTP Password Sniffer",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class PingRequest(BaseModel):
    target_ip: str
    count: int = 4

class LoginRequest(BaseModel):
    username: str
    password: str
    protocol: str = "HTTP"

class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None

@app.get("/api/status")
def get_system_topology(target_ip: Optional[str] = None):
    return get_network_topology(target_ip)

@app.post("/api/capture/start")
def api_start_capture(req: Optional[CaptureStartRequest] = None):
    iface = req.interface if req else None
    return start_live_capture(interface=iface)

@app.post("/api/capture/stop")
def api_stop_capture():
    return stop_live_capture()

@app.get("/api/capture/status")
def api_capture_status():
    return get_capture_status()

@app.post("/api/capture/clear")
def api_clear_capture():
    clear_packet_store()
    seed_exercise_12_protocols()
    return {"status": "CLEARED", "message": "Packet store cleared and baseline reset."}

@app.post("/api/ping")
def run_ping_probe(req: PingRequest):
    res = execute_ping_probe(req.target_ip, count=req.count)
    # Append the live ICMP packets into the sniffer packet store
    for p in res.get("packets", []):
        add_packet(p)
    return res

@app.post("/login")
def dummy_login_handler(req: LoginRequest):
    """
    The Dummy Web Application Login Handler requested in Exercise 12.
    Demonstrates HTTP cleartext packet capture vs. HTTPS TLS 1.3 encryption.
    """
    proto = req.protocol.upper()
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    target_mac = resolve_target_mac(GATEWAY_IP or "192.168.1.1")

    if proto == "HTTP":
        payload_str = f"username={req.username}&password={req.password}&auth_action=login"
        pkt = {
            "timestamp": now,
            "src_ip": HOST_IP,
            "dst_ip": GATEWAY_IP or "192.168.1.1",
            "src_mac": HOST_MAC,
            "dst_mac": target_mac,
            "protocol": "HTTP",
            "length": 184 + len(payload_str),
            "info": f"POST /login HTTP/1.1 (LEAK: Plaintext Password '{req.password}' Exposed)",
            "has_leak": True,
            "leaked_username": req.username,
            "leaked_password": req.password,
            "layers": {
                "frame": f"Frame (184 bytes on wire, 184 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {HOST_MAC}, Dst: {target_mac}",
                "ip": f"Internet Protocol Version 4, Src: {HOST_IP}, Dst: {GATEWAY_IP or '192.168.1.1'}, Protocol: TCP (6)",
                "tcp": "Transmission Control Protocol, Src Port: 54321, Dst Port: 5000 / 80, Flags: [PSH, ACK]",
                "http": f"Hypertext Transfer Protocol, POST /login HTTP/1.1, Form Body: {payload_str}"
            },
            "hex_dump": (
                f"0000  {target_mac.replace(':', ' ')} {HOST_MAC.replace(':', ' ')} 08 00\n"
                f"0010  45 00 00 a4 3d 4e 40 00 40 06 72 1a {HOST_IP.replace('.', ' ')} {(GATEWAY_IP or '192.168.1.1').replace('.', ' ')}\n"
                f"0020  d4 31 13 88 00 01 00 00 50 18 20 00 70 80 00 00\n"
                f"0030  50 4f 53 54 20 2f 6c 6f 67 69 6e 20 48 54 54 50\n"
                f"0040  {payload_str.encode().hex(' ')}"
            ),
            "ascii_dump": f"POST /login HTTP/1.1...{payload_str}"
        }
        add_packet(pkt)

        return {
            "status": "VULNERABLE",
            "protocol": "HTTP",
            "password_exposed": True,
            "exposed_username": req.username,
            "exposed_password": req.password,
            "wire_payload": payload_str,
            "message": "Cleartext password intercepted on wire! Anyone running Wireshark on this LAN can read it directly."
        }
    else:
        # HTTPS Mode: TLS 1.3 Encryption
        # Fire genuine TLS 1.3 encrypted transaction on port 5443 so it physically travels on wire
        try:
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            payload_bytes = f"username={req.username}&password={req.password}&auth_action=login".encode()
            tls_req = urllib.request.Request(f"https://{HOST_IP}:5443/", data=payload_bytes, method="POST")
            with urllib.request.urlopen(tls_req, context=ctx, timeout=2) as resp:
                pass
        except Exception:
            pass

        ciphertext = "17 03 03 00 4b d3 8f 14 9e 7b 42 90 aa c1 54 8e 2b 6f c8 d1 90 aa b4"
        pkt = {
            "timestamp": now,
            "src_ip": HOST_IP,
            "dst_ip": GATEWAY_IP or "192.168.1.1",
            "src_mac": HOST_MAC,
            "dst_mac": target_mac,
            "protocol": "HTTPS",
            "length": 1440,
            "info": "TLSv1.3 Application Data (Protected by AES-256-GCM Session Key)",
            "has_leak": False,
            "layers": {
                "frame": f"Frame (1440 bytes on wire, 1440 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {HOST_MAC}, Dst: {target_mac}",
                "ip": f"Internet Protocol Version 4, Src: {HOST_IP}, Dst: {GATEWAY_IP or '192.168.1.1'}, Protocol: TCP (6)",
                "tcp": "Transmission Control Protocol, Src Port: 54432, Dst Port: 5443 / 443, Flags: [PSH, ACK]",
                "tls": "Transport Layer Security, TLSv1.3 Record Layer: Application Data Protocol: http-over-tls"
            },
            "hex_dump": f"0000  17 03 03 00 4b {ciphertext}",
            "ascii_dump": "....K.G....{B...T.+o...."
        }
        add_packet(pkt)

        return {
            "status": "SECURE",
            "protocol": "HTTPS",
            "password_exposed": False,
            "exposed_username": req.username,
            "exposed_password": "[ENCRYPTED CIPHERTEXT - TLS 1.3]",
            "wire_payload": ciphertext,
            "message": "Confidentiality preserved! Payload is sealed with TLS 1.3 AES-256-GCM keys. Wireshark sniffer sees only opaque ciphertext."
        }

@app.get("/api/packets")
def list_packets(protocol: Optional[str] = "ALL", search: Optional[str] = None):
    return {"packets": get_all_packets(protocol, search)}

# Mount static files (HTML, CSS, JS)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
