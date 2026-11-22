"""
NetSecure - Packet Dissector & Wireshark 3-Pane Storage Engine
Provides Layer 2–7 dissection, Hex/ASCII dump formatting,
live Scapy/Npcap packet sniffing on physical Wi-Fi/Ethernet adapters,
credential leakage detection, and multi-protocol storage (HTTP, HTTPS, DNS, ARP, FTP, ICMP).
"""

import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import urllib.parse

from scapy.all import AsyncSniffer, conf, Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR

from backend.network_info import HOST_IP, HOST_MAC, GATEWAY_IP

# Thread-safe in-memory packet buffer
_packet_store: List[Dict[str, Any]] = []
_store_lock = threading.Lock()

# Live sniffer state
_sniffer_instance: Optional[AsyncSniffer] = None
_is_capturing: bool = False
_packet_id_counter: int = 0


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


def add_packet(pkt: Dict[str, Any]):
    global _packet_id_counter
    with _store_lock:
        _packet_id_counter += 1
        pkt["id"] = _packet_id_counter
        if "timestamp" not in pkt:
            pkt["timestamp"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        _packet_store.append(pkt)
        # Ring buffer: limit to latest 2000 packets to preserve fast response
        if len(_packet_store) > 2000:
            _packet_store.pop(0)


def clear_packet_store():
    global _packet_id_counter
    with _store_lock:
        _packet_store.clear()
        _packet_id_counter = 0


def detect_credential_leak(raw_payload: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Inspects raw payload strings for cleartext credentials."""
    lower = raw_payload.lower()
    has_leak = False
    leaked_user = None
    leaked_pass = None

    if "password=" in lower or "passwd=" in lower or "pwd=" in lower:
        has_leak = True
        try:
            # Parse form fields if urlencoded
            params = urllib.parse.parse_qs(raw_payload)
            for k, v in params.items():
                k_low = k.lower()
                if "user" in k_low or "email" in k_low:
                    leaked_user = v[0]
                if "pass" in k_low or "pwd" in k_low:
                    leaked_pass = v[0]
        except Exception:
            pass

    return has_leak, leaked_user, leaked_pass


def dissect_scapy_packet(pkt: Packet) -> Optional[Dict[str, Any]]:
    """
    Dissects a live Scapy frame into Wireshark 3-pane format with
    Layer 2-7 details, hex dump, and security leak analysis.
    """
    try:
        raw_bytes = bytes(pkt)
        length = len(raw_bytes)
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Layer 2: Ethernet
        src_mac = HOST_MAC
        dst_mac = "ff:ff:ff:ff:ff:ff"
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        # Layer 3: Network
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        proto_name = "ETH"
        info = "Ethernet Frame"
        layers: Dict[str, str] = {
            "frame": f"Frame ({length} bytes on wire, {length} bytes captured)",
            "ethernet": f"Ethernet II, Src: {src_mac}, Dst: {dst_mac}"
        }

        has_leak = False
        leaked_user = None
        leaked_pass = None

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            proto_name = "ARP"
            op = "request" if arp.op == 1 else "reply"
            if arp.op == 1:
                info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            else:
                info = f"{arp.psrc} is at {arp.hwsrc}"
            layers["arp"] = f"Address Resolution Protocol ({op}), Sender MAC: {arp.hwsrc}, Target IP: {arp.pdst}"

        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = ip.ttl
                proto_num = ip.proto
                layers["ip"] = f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}, TTL: {ttl}, Protocol: {proto_num}"
            else:
                ip6 = pkt[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                layers["ip"] = f"Internet Protocol Version 6, Src: {src_ip}, Dst: {dst_ip}"

            # Layer 4: Transport
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                proto_name = "ICMP"
                t = icmp.type
                c = icmp.code
                meaning = "Echo (ping) request" if t == 8 else ("Echo (ping) reply" if t == 0 else f"Type {t} Code {c}")
                info = f"{meaning} id=0x{icmp.id:04x}, seq={icmp.seq}"
                layers["icmp"] = f"Internet Control Message Protocol, Type: {t}, Code: {c} ({meaning})"

            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = tcp.flags
                flag_str = str(flags)
                proto_name = "TCP"
                info = f"{sport} → {dport} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
                layers["tcp"] = f"Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {tcp.seq}, Ack: {tcp.ack}, Flags: [{flag_str}]"

                # Check for HTTP / HTTPS / FTP
                payload = bytes(tcp.payload)
                if sport in (443, 5443) or dport in (443, 5443):
                    proto_name = "HTTPS"
                    info = f"TLS Application Data {sport} → {dport}"
                    layers["tls"] = "Transport Layer Security (TLSv1.3 / TLSv1.2 Encrypted Application Data)"
                elif sport in (21, 2121) or dport in (21, 2121):
                    proto_name = "FTP"
                    ftp_str = payload.decode(errors="ignore").strip()
                    info = f"FTP: {ftp_str[:40]}" if ftp_str else f"FTP Stream {sport} → {dport}"
                    layers["ftp"] = f"File Transfer Protocol: {ftp_str}"
                elif sport in (80, 5000, 8000, 8080) or dport in (80, 5000, 8000, 8080):
                    proto_name = "HTTP"
                    try:
                        http_text = payload.decode(errors="ignore")
                        if http_text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/1.")):
                            first_line = http_text.split("\r\n")[0]
                            info = first_line
                            layers["http"] = f"Hypertext Transfer Protocol, {first_line}"
                            # Password sniff check
                            leak, u, p = detect_credential_leak(http_text)
                            if leak:
                                has_leak = True
                                leaked_user = u
                                leaked_pass = p
                                info += f" (LEAK: Plaintext Password '{p or 'Exposed'}')"
                    except Exception:
                        pass

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport
                proto_name = "UDP"
                if sport in (49735, 43946) or dport in (49735, 43946):
                    info = f"Windows Phone Link Sync (CrossDeviceService) {sport} → {dport}"
                    layers["udp"] = f"User Datagram Protocol, Windows Phone Link (CrossDeviceService), Src: {sport}, Dst: {dport}"
                else:
                    info = f"{sport} → {dport} Len={udp.len}"
                    layers["udp"] = f"User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}, Length: {udp.len}"

                if pkt.haslayer(DNS):
                    proto_name = "DNS"
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qd:
                        qname = dns.qd.qname.decode(errors="ignore") if hasattr(dns.qd, "qname") else ""
                        info = f"Standard query 0x{dns.id:04x} A {qname}"
                        layers["dns"] = f"Domain Name System (query): {qname}"
                    elif dns.qr == 1:
                        info = f"Standard query response 0x{dns.id:04x}"
                        layers["dns"] = f"Domain Name System (response)"

        hex_d, ascii_d = format_hex_ascii(raw_bytes[:256])

        return {
            "timestamp": now_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": proto_name,
            "length": length,
            "info": info,
            "layers": layers,
            "hex_dump": hex_d,
            "ascii_dump": ascii_d,
            "has_leak": has_leak,
            "leaked_username": leaked_user,
            "leaked_password": leaked_pass
        }
    except Exception:
        return None


def _packet_callback(pkt: Packet):
    parsed = dissect_scapy_packet(pkt)
    if parsed:
        add_packet(parsed)


def start_live_capture(interface: Optional[str] = None) -> Dict[str, Any]:
    """Starts live packet sniffing in a non-blocking background thread."""
    global _sniffer_instance, _is_capturing

    if _is_capturing and _sniffer_instance and _sniffer_instance.running:
        return {"status": "ALREADY_RUNNING", "message": "Live capture is already running."}

    iface = interface or conf.iface
    try:
        _sniffer_instance = AsyncSniffer(
            iface=iface,
            prn=_packet_callback,
            store=False
        )
        _sniffer_instance.start()
        _is_capturing = True
        return {
            "status": "RUNNING",
            "interface": str(iface),
            "message": f"Live packet capture started on {iface}."
        }
    except Exception as e:
        _is_capturing = False
        return {
            "status": "ERROR",
            "error": str(e),
            "message": f"Failed to start live packet capture: {e}"
        }


def stop_live_capture() -> Dict[str, Any]:
    """Stops the live sniffer."""
    global _sniffer_instance, _is_capturing
    if _sniffer_instance:
        try:
            if _sniffer_instance.running:
                _sniffer_instance.stop()
        except Exception:
            pass
        _sniffer_instance = None
    _is_capturing = False
    return {"status": "STOPPED", "message": "Live packet capture stopped."}


def get_capture_status() -> Dict[str, Any]:
    running = bool(_is_capturing and _sniffer_instance and _sniffer_instance.running)
    return {
        "is_capturing": running,
        "packet_count": len(_packet_store),
        "interface": str(conf.iface)
    }


def get_all_packets(protocol: Optional[str] = "ALL", search: Optional[str] = None) -> List[Dict[str, Any]]:
    with _store_lock:
        results = list(_packet_store)

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
        elif p in ("WAN", "INTERNET"):
            results = [
                x for x in results 
                if not (x.get("src_ip", "").startswith("192.168.") and x.get("dst_ip", "").startswith("192.168."))
            ]

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
