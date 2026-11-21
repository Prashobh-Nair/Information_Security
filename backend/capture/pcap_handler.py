"""
NetSecure PCAP Handler
Validates, imports, parses, and exports PCAP/PCAPNG packet capture files.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Tuple
import scapy.all as scapy
from scapy.utils import PcapReader, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

from backend.config import PCAP_DIR
from backend.analyzer.packet_parser import dissect_packet
from backend.database import insert_packets_bulk, insert_security_alert

PCAP_MAGIC_NUMBERS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (microsecond)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (swapped byte order)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (swapped)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG block header
]

def validate_pcap_header(file_bytes: bytes) -> Tuple[bool, str]:
    if len(file_bytes) < 4:
        return False, "File is too small to be a valid PCAP/PCAPNG capture."
    header = file_bytes[:4]
    if any(header == magic for magic in PCAP_MAGIC_NUMBERS):
        return True, "Valid PCAP/PCAPNG capture header."
    return False, "Invalid file format: Missing PCAP magic header (expected Wireshark .pcap or .pcapng)."

def parse_pcap_file(file_path: str | Path, session_id: int, max_packets: int = 5000) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Parses a PCAP file using Scapy PcapReader, runs dissection, and saves to DB.
    """
    path_obj = Path(file_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    parsed_packets = []
    pkt_num = 1
    
    try:
        reader = PcapReader(str(path_obj))
        batch = []
        
        for raw_pkt in reader:
            try:
                pkt_data = dissect_packet(raw_pkt, packet_num=pkt_num)
                batch.append(pkt_data)
                parsed_packets.append(pkt_data)
                pkt_num += 1
                
                # Check for security alert
                sec = pkt_data.get("details", {}).get("security", {})
                if sec.get("has_credentials"):
                    insert_security_alert({
                        "session_id": session_id,
                        "alert_type": "PLAINTEXT_CREDENTIALS_EXPOSED",
                        "severity": sec.get("risk_level", "HIGH"),
                        "title": f"Unencrypted {sec.get('auth_type', 'Credentials')} Intercepted",
                        "description": (
                            f"Packet #{pkt_num - 1} contained plaintext credentials. "
                            f"Username: '{sec.get('username')}', Password: '{sec.get('password')}'"
                        ),
                        "protocol": pkt_data.get("protocol", "HTTP"),
                        "evidence": sec.get("evidence", ""),
                        "remediation": "Enforce HTTPS with TLS 1.3 and HSTS header. Do not transmit credentials over unencrypted HTTP."
                    })
                
                if len(batch) >= 100:
                    insert_packets_bulk(session_id, batch)
                    batch = []
                    
                if pkt_num > max_packets:
                    break
            except Exception:
                continue

        if batch:
            insert_packets_bulk(session_id, batch)

        reader.close()
    except Exception as e:
        # Fallback if PcapReader encounters format quirk
        scapy_pkts = scapy.rdpcap(str(path_obj))
        batch = []
        for raw_pkt in scapy_pkts[:max_packets]:
            pkt_data = dissect_packet(raw_pkt, packet_num=pkt_num)
            batch.append(pkt_data)
            parsed_packets.append(pkt_data)
            pkt_num += 1
        insert_packets_bulk(session_id, batch)

    return len(parsed_packets), parsed_packets

def export_session_to_pcap(session_id: int, file_name: str = "") -> str:
    """
    Exports packets belonging to session_id from DB into a valid .pcap file.
    """
    from backend.database import get_packets
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    import ipaddress

    def safe_ip(ip_str: str, fallback: str = "127.0.0.1") -> str:
        try:
            ipaddress.IPv4Address(ip_str)
            return ip_str
        except Exception:
            return fallback

    packets_meta = get_packets(session_id=session_id, limit=5000)
    if not file_name:
        file_name = f"session_{session_id}_capture.pcap"
        
    out_path = PCAP_DIR / file_name
    
    scapy_pkt_list = []
    for p in packets_meta:
        src_mac = p.get("src_mac") or "00:0c:29:1a:2b:3c"
        dst_mac = p.get("dst_mac") or "00:0c:29:4d:5e:6f"
        src_ip = safe_ip(p.get("src_ip"), "192.168.1.10")
        dst_ip = safe_ip(p.get("dst_ip"), "192.168.1.20")
        proto = p.get("protocol", "TCP").upper()
        
        # Build synthetic Scapy packet matching captured metadata
        eth = Ether(src=src_mac, dst=dst_mac)
        
        if proto == "ARP":
            pkt = eth / ARP(
                hwsrc=src_mac,
                psrc=src_ip,
                hwdst=dst_mac if dst_mac != "N/A" else "ff:ff:ff:ff:ff:ff",
                pdst=dst_ip,
                op=1 if "Who has" in p.get("info", "") else 2
            )
        elif proto == "ICMP":
            icmp_type = p.get("icmp_type", 8)
            icmp_code = p.get("icmp_code", 0)
            pkt = eth / IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, code=icmp_code) / b"NetSecureLabMachinePingData12345"
        elif proto == "UDP" or proto == "DNS":
            from scapy.layers.dns import DNS, DNSQR
            sport = p.get("src_port") or 53535
            dport = p.get("dst_port") or 53
            pkt = eth / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / b"DNS_LAB_PAYLOAD"
        else: # TCP / HTTP / HTTPS / FTP
            sport = p.get("src_port") or 49152
            dport = p.get("dst_port") or 80
            payload = p.get("payload_ascii", "").encode("latin1", errors="ignore")[:200]
            if not payload:
                payload = b"NetSecure Academic Capture Payload"
            pkt = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / payload

        scapy_pkt_list.append(pkt)

    if scapy_pkt_list:
        wrpcap(str(out_path), scapy_pkt_list)
        
    return str(out_path)
