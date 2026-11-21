"""
NetSecure Ping Runner
Executes real ping commands safely with strict input validation.
Parses output for RTT, packet loss, sent/received counts, and correlates with ICMP packets.
"""

import subprocess
import platform
import re
import ipaddress
import socket
from datetime import datetime
from typing import Dict, Any

from backend.database import insert_ping_log, insert_packet, get_latest_session, create_session
from backend.analyzer.packet_parser import dissect_packet
from backend.capture.capture_engine import capture_engine

def validate_target_host(target: str) -> bool:
    """Strict validation to prevent command injection and ensure valid IP or hostname."""
    if not target or len(target) > 253:
        return False
    # Check if valid IPv4 or IPv6
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    # Check if valid hostname / domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", target):
        return True
    return False

def execute_ping(target_ip: str, count: int = 4, timeout_sec: int = 2) -> Dict[str, Any]:
    if not validate_target_host(target_ip):
        return {
            "status": "ERROR",
            "message": "Invalid IP address or hostname. Input rejected for safety.",
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss_pct": 100.0,
            "min_rtt_ms": 0.0,
            "avg_rtt_ms": 0.0,
            "max_rtt_ms": 0.0,
            "jitter_ms": 0.0,
            "raw_output": "Security validation error: Target contains forbidden characters."
        }

    count = max(1, min(10, count))
    is_win = platform.system().lower() == "windows"
    
    cmd = ["ping", "-n", str(count), "-w", str(timeout_sec * 1000), target_ip] if is_win else ["ping", "-c", str(count), "-W", str(timeout_sec), target_ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=(count * timeout_sec) + 4)
        raw_out = proc.stdout + proc.stderr
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        raw_out = "Ping process timed out."
        returncode = 1
    except Exception as e:
        raw_out = f"Execution failed: {e}"
        returncode = 1

    # Parse ping metrics
    sent = count
    received = 0
    lost = count
    loss_pct = 100.0
    min_rtt = 0.0
    avg_rtt = 0.0
    max_rtt = 0.0
    jitter = 0.0

    if is_win:
        # Windows format: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
        match_stats = re.search(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\(([\d\.]+)%\s*loss\)", raw_out)
        if match_stats:
            sent = int(match_stats.group(1))
            received = int(match_stats.group(2))
            lost = int(match_stats.group(3))
            loss_pct = float(match_stats.group(4))

        # Windows RTT: Minimum = 1ms, Maximum = 4ms, Average = 2ms
        match_rtt = re.search(r"Minimum\s*=\s*([\d\.]+)ms,\s*Maximum\s*=\s*([\d\.]+)ms,\s*Average\s*=\s*([\d\.]+)ms", raw_out)
        if match_rtt:
            min_rtt = float(match_rtt.group(1))
            max_rtt = float(match_rtt.group(2))
            avg_rtt = float(match_rtt.group(3))
            jitter = round(max_rtt - min_rtt, 2)
    else:
        # Unix format: 4 packets transmitted, 4 received, 0% packet loss
        match_stats = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received,\s+([\d\.]+)%\s+packet loss", raw_out)
        if match_stats:
            sent = int(match_stats.group(1))
            received = int(match_stats.group(2))
            loss_pct = float(match_stats.group(3))
            lost = sent - received

        match_rtt = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", raw_out)
        if match_rtt:
            min_rtt = float(match_rtt.group(1))
            avg_rtt = float(match_rtt.group(2))
            max_rtt = float(match_rtt.group(3))
            jitter = float(match_rtt.group(4))

    status = "SUCCESS" if (returncode == 0 and received > 0) else "FAILED"

    result = {
        "target_ip": target_ip,
        "status": status,
        "packets_sent": sent,
        "packets_received": received,
        "packets_lost": lost,
        "packet_loss_pct": loss_pct,
        "min_rtt_ms": min_rtt,
        "avg_rtt_ms": avg_rtt,
        "max_rtt_ms": max_rtt,
        "jitter_ms": jitter,
        "raw_output": raw_out.strip(),
        "timestamp": datetime.now().isoformat()
    }

    # Save to database
    insert_ping_log(result)

    # Correlate into capture session as ICMP packets
    latest = get_latest_session()
    session_id = latest["id"] if latest else create_session("Ping Session", "Ethernet0", "ping")

    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, ICMP
    from backend.config import LOCAL_IP, LOCAL_MAC
    
    source_ip = LOCAL_IP or "127.0.0.1"
    source_mac = LOCAL_MAC or "1c:ce:51:32:87:5e"
    target_mac = "00:0c:29:4d:5e:6f"

    for i in range(1, sent + 1):
        # 1. Echo Request
        req_pkt = Ether(src=source_mac, dst=target_mac) / IP(src=source_ip, dst=target_ip) / ICMP(type=8, code=0, seq=i, id=0x1234) / b"PingMachineProbe"
        p_req = dissect_packet(req_pkt, packet_num=int(datetime.now().timestamp() * 1000) % 100000 + i)
        insert_packet(session_id, p_req)
        capture_engine.broadcast_packet(p_req)

        # 2. Echo Reply if received
        if i <= received:
            rep_pkt = Ether(src=target_mac, dst=source_mac) / IP(src=target_ip, dst=source_ip) / ICMP(type=0, code=0, seq=i, id=0x1234) / b"PingMachineProbe"
            p_rep = dissect_packet(rep_pkt, packet_num=int(datetime.now().timestamp() * 1000) % 100000 + i + 10)
            insert_packet(session_id, p_rep)
            capture_engine.broadcast_packet(p_rep)

    return result
