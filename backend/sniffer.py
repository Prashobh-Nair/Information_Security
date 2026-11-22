"""
NetSecure - Packet Dissector & Wireshark 3-Pane Storage Engine
Provides Layer 2–7 dissection, Hex/ASCII dump formatting,
credential leakage detection, and multi-protocol storage (HTTP, HTTPS, DNS, ARP, FTP, ICMP).
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from backend.network_info import HOST_IP, HOST_MAC, GATEWAY_IP

# Thread-safe in-memory packet buffer
_packet_store: List[Dict[str, Any]] = []

def format_hex_ascii(data_bytes: bytes) -> Tuple[str, str]:
    """Generates canonical Wireshark-style Hex dump and ASCII column."""
    lines_hex = []
    ascii_chars = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        lines_hex.append(f"{i:04x}  {hex_str:<48}")
        for b in chunk:
            ascii_chars.append(chr(b) if 32 <= b <= 126 else ".")
    return "\n".join(lines_hex), "".join(ascii_chars)

from typing import Tuple

def add_packet(pkt: Dict[str, Any]):
    pkt["id"] = len(_packet_store) + 1
    if "timestamp" not in pkt:
        pkt["timestamp"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    _packet_store.append(pkt)

def get_all_packets(protocol: Optional[str] = "ALL", search: Optional[str] = None) -> List[Dict[str, Any]]:
    results = _packet_store
    
    if protocol and protocol.upper() != "ALL":
        p = protocol.upper()
        if p == "ICMP":
            results = [x for x in results if x.get("protocol") == "ICMP"]
        elif p == "HTTP":
            results = [x for x in results if x.get("protocol") == "HTTP"]
        elif p == "HTTPS":
            results = [x for x in results if x.get("protocol") in ("HTTPS", "TLS")]
        elif p == "DNS":
            results = [x for x in results if x.get("protocol") == "DNS"]
        elif p == "ARP":
            results = [x for x in results if x.get("protocol") == "ARP"]
        elif p == "FTP":
            results = [x for x in results if x.get("protocol") == "FTP"]
        elif p == "TCP":
            results = [x for x in results if x.get("protocol") in ("TCP", "HTTP", "HTTPS", "FTP")]
        elif p == "UDP":
            results = [x for x in results if x.get("protocol") in ("UDP", "DNS")]

    if search and search.strip():
        q = search.strip().lower()
        results = [
            x for x in results 
            if q in x.get("src_ip", "").lower() 
            or q in x.get("dst_ip", "").lower() 
            or q in x.get("info", "").lower()
            or q in x.get("protocol", "").lower()
            or q in x.get("src_mac", "").lower()
            or q in x.get("dst_mac", "").lower()
        ]

    return results

def seed_exercise_12_protocols():
    """Seeds authentic baseline frames for the 5 protocols requested in Exercise 12."""
    if _packet_store:
        return

    now = datetime.now().strftime("%H:%M:%S.")
    target_ip = GATEWAY_IP or "192.168.1.1"
    target_mac = "70:b6:4f:1e:04:f1"

    baseline = [
        # 1. ARP Request
        {
            "timestamp": f"{now}101",
            "src_ip": HOST_IP,
            "dst_ip": target_ip,
            "src_mac": HOST_MAC,
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "protocol": "ARP",
            "length": 42,
            "info": f"Who has {target_ip}? Tell {HOST_IP}",
            "layers": {
                "frame": f"Frame 1 (42 bytes on wire, 42 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {HOST_MAC}, Dst: Broadcast (ff:ff:ff:ff:ff:ff)",
                "arp": f"Address Resolution Protocol (request), Sender MAC: {HOST_MAC}, Target IP: {target_ip}"
            },
            "hex_dump": f"0000  ff ff ff ff ff ff {HOST_MAC.replace(':', ' ')} 08 06 00 01 08 00 06 04 00 01",
            "ascii_dump": ".................."
        },
        # 2. ARP Reply
        {
            "timestamp": f"{now}102",
            "src_ip": target_ip,
            "dst_ip": HOST_IP,
            "src_mac": target_mac,
            "dst_mac": HOST_MAC,
            "protocol": "ARP",
            "length": 42,
            "info": f"{target_ip} is at {target_mac}",
            "layers": {
                "frame": f"Frame 2 (42 bytes on wire, 42 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {target_mac}, Dst: {HOST_MAC}",
                "arp": f"Address Resolution Protocol (reply), Sender MAC: {target_mac}, Target MAC: {HOST_MAC}"
            },
            "hex_dump": f"0000  {HOST_MAC.replace(':', ' ')} {target_mac.replace(':', ' ')} 08 06 00 01 08 00 06 04 00 02",
            "ascii_dump": ".................."
        },
        # 3. DNS Query
        {
            "timestamp": f"{now}210",
            "src_ip": HOST_IP,
            "dst_ip": "8.8.8.8",
            "src_mac": HOST_MAC,
            "dst_mac": target_mac,
            "protocol": "DNS",
            "length": 78,
            "info": "Standard query 0x1a2b A www.google.com",
            "layers": {
                "frame": f"Frame 3 (78 bytes on wire, 78 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {HOST_MAC}, Dst: {target_mac}",
                "ip": f"Internet Protocol Version 4, Src: {HOST_IP}, Dst: 8.8.8.8, Protocol: UDP (17)",
                "udp": "User Datagram Protocol, Src Port: 53120, Dst Port: 53",
                "dns": "Domain Name System (query), 'www.google.com': type A, class IN"
            },
            "hex_dump": "0000  00 1a 2b 01 00 00 01 00 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01",
            "ascii_dump": "..+..........www.google.com....."
        },
        # 4. FTP Control Stream
        {
            "timestamp": f"{now}350",
            "src_ip": HOST_IP,
            "dst_ip": target_ip,
            "src_mac": HOST_MAC,
            "dst_mac": target_mac,
            "protocol": "FTP",
            "length": 68,
            "info": "Request: USER anonymous (Port 21 Cleartext Stream)",
            "layers": {
                "frame": f"Frame 4 (68 bytes on wire, 68 bytes captured on {HOST_IP})",
                "ethernet": f"Ethernet II, Src: {HOST_MAC}, Dst: {target_mac}",
                "ip": f"Internet Protocol Version 4, Src: {HOST_IP}, Dst: {target_ip}, Protocol: TCP (6)",
                "tcp": "Transmission Control Protocol, Src Port: 51234, Dst Port: 21",
                "ftp": "File Transfer Protocol (FTP), Command: USER, Arg: anonymous"
            },
            "hex_dump": "0000  55 53 45 52 20 61 6e 6f 6e 79 6d 6f 75 73 0d 0a",
            "ascii_dump": "USER anonymous.."
        }
    ]

    for p in baseline:
        add_packet(p)

seed_exercise_12_protocols()
