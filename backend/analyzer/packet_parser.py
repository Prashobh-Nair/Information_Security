"""
NetSecure Packet Parser
Performs deep multi-layer dissection of network frames (Ethernet, ARP, IP, ICMP, TCP, UDP, DNS, HTTP, HTTPS, FTP).
Formats packet information precisely according to university lab specifications.
"""

from datetime import datetime
from typing import Dict, Any, Optional
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from backend.analyzer.icmp_analyzer import analyze_icmp
from backend.analyzer.payload_inspector import format_hex_ascii_dump, scan_for_credentials

def dissect_packet(raw_pkt: Any, packet_num: int = 1) -> Dict[str, Any]:
    """
    Takes a Scapy packet object and extracts structured layers:
    Ethernet -> IP/ARP -> TCP/UDP/ICMP -> Application (HTTP, DNS, TLS, FTP)
    """
    timestamp = getattr(raw_pkt, "time", None)
    if timestamp:
        try:
            ts_str = datetime.fromtimestamp(float(timestamp)).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            ts_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    else:
        ts_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    raw_bytes = bytes(raw_pkt)
    pkt_len = len(raw_bytes)
    
    # Re-parse through Ether so all fields (ihl, checksums, lengths) are strictly calculated
    try:
        raw_pkt = Ether(raw_bytes)
    except Exception:
        pass
    
    # Defaults
    src_mac = "00:00:00:00:00:00"
    dst_mac = "00:00:00:00:00:00"
    ether_type = "Unknown"
    
    src_ip = "N/A"
    dst_ip = "N/A"
    l3_proto = "OTHER"
    
    l4_proto = "N/A"
    src_port = None
    dst_port = None
    
    detected_proto = "OTHER"
    info = ""
    
    icmp_type = None
    icmp_code = None
    icmp_meaning = ""
    
    details = {
        "ethernet": {},
        "network": {},
        "transport": {},
        "application": {},
        "security": {}
    }

    # ==========================
    # 1. LAYER 2: ETHERNET
    # ==========================
    if raw_pkt.haslayer(Ether):
        eth = raw_pkt[Ether]
        src_mac = eth.src.lower()
        dst_mac = eth.dst.lower()
        ether_type_val = eth.type
        ether_type_name = hex(ether_type_val)
        if ether_type_val == 0x0800:
            ether_type_name = "IPv4 (0x0800)"
        elif ether_type_val == 0x0806:
            ether_type_name = "ARP (0x0806)"
        elif ether_type_val == 0x86dd:
            ether_type_name = "IPv6 (0x86dd)"
            
        details["ethernet"] = {
            "source_mac": src_mac,
            "destination_mac": dst_mac,
            "ether_type": ether_type_name,
            "raw_type": ether_type_val
        }

    # ==========================
    # 2. LAYER 3: ARP or IP
    # ==========================
    if raw_pkt.haslayer(ARP):
        arp = raw_pkt[ARP]
        detected_proto = "ARP"
        l3_proto = "ARP"
        src_ip = arp.psrc
        dst_ip = arp.pdst
        src_mac = arp.hwsrc.lower()
        dst_mac = arp.hwdst.lower() if arp.hwdst else "ff:ff:ff:ff:ff:ff"
        
        op_name = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else f"Opcode {arp.op}")
        if arp.op == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            info = f"ARP {op_name}"
            
        details["network"] = {
            "protocol": "ARP",
            "hardware_type": arp.hwtype,
            "protocol_type": hex(arp.ptype),
            "hardware_size": arp.hwlen,
            "protocol_size": arp.plen,
            "opcode": arp.op,
            "operation": op_name,
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
            "academic_note": (
                "Address Resolution Protocol maps Layer 3 IPv4 addresses to Layer 2 physical MAC addresses. "
                f"{op_name} packet on the broadcast/unicast LAN domain."
            )
        }

    elif raw_pkt.haslayer(IP):
        ip = raw_pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        l3_proto = "IPv4"
        
        flags_list = []
        try:
            if ip.flags.DF:
                flags_list.append("DF (Don't Fragment)")
            if ip.flags.MF:
                flags_list.append("MF (More Fragments)")
        except Exception:
            pass

        ihl_val = getattr(ip, "ihl", 5) or 5
        total_len_val = getattr(ip, "len", pkt_len) or pkt_len
        id_val = getattr(ip, "id", 0) or 0
        chksum_val = getattr(ip, "chksum", 0) or 0
            
        details["network"] = {
            "protocol": "IPv4",
            "version": getattr(ip, "version", 4) or 4,
            "header_length": ihl_val * 4,
            "type_of_service": getattr(ip, "tos", 0) or 0,
            "total_length": total_len_val,
            "identification": hex(id_val),
            "flags": ", ".join(flags_list) if flags_list else "None",
            "fragment_offset": getattr(ip, "frag", 0) or 0,
            "ttl": getattr(ip, "ttl", 64) or 64,
            "l4_protocol_number": getattr(ip, "proto", 6) or 6,
            "checksum": hex(chksum_val),
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

    # ==========================
    # 3. LAYER 4 & 7: ICMP
    # ==========================
    if raw_pkt.haslayer(ICMP):
        icmp = raw_pkt[ICMP]
        detected_proto = "ICMP"
        l4_proto = "ICMP"
        icmp_type = icmp.type
        icmp_code = icmp.code
        
        analysis = analyze_icmp(icmp_type, icmp_code)
        icmp_meaning = analysis["meaning"]
        
        seq_num = getattr(icmp, "seq", 0)
        ident = getattr(icmp, "id", 0)
        
        if icmp_type == 8:
            info = f"Echo (ping) request  id=0x{ident:04x}, seq={seq_num}, ttl={getattr(raw_pkt.getlayer(IP), 'ttl', 64)}"
        elif icmp_type == 0:
            info = f"Echo (ping) reply    id=0x{ident:04x}, seq={seq_num}"
        else:
            info = f"ICMP {analysis['type_name']} ({analysis['meaning']})"
            
        details["transport"] = {
            "protocol": "ICMP",
            "type": icmp_type,
            "code": icmp_code,
            "checksum": hex(getattr(icmp, "chksum", 0) or 0),
            "identifier": ident,
            "sequence_number": seq_num,
            "meaning": icmp_meaning,
            "description": analysis["description"],
            "academic_explanation": analysis["academic_explanation"]
        }

    # ==========================
    # 4. TRANSPORT & APP: TCP
    # ==========================
    elif raw_pkt.haslayer(TCP):
        tcp = raw_pkt[TCP]
        l4_proto = "TCP"
        detected_proto = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport
        
        flags = []
        if tcp.flags.S: flags.append("SYN")
        if tcp.flags.A: flags.append("ACK")
        if tcp.flags.F: flags.append("FIN")
        if tcp.flags.R: flags.append("RST")
        if tcp.flags.P: flags.append("PSH")
        if tcp.flags.U: flags.append("URG")
        flags_str = "[" + ", ".join(flags) + "]"
        
        info = f"{src_port} → {dst_port} {flags_str} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(tcp.payload)}"
        
        details["transport"] = {
            "protocol": "TCP",
            "source_port": src_port,
            "destination_port": dst_port,
            "sequence_number": getattr(tcp, "seq", 0) or 0,
            "acknowledgment_number": getattr(tcp, "ack", 0) or 0,
            "data_offset": (getattr(tcp, "dataofs", 5) or 5) * 4,
            "flags": flags_str,
            "raw_flags": hex(int(tcp.flags)),
            "window_size": getattr(tcp, "window", 65535) or 65535,
            "checksum": hex(getattr(tcp, "chksum", 0) or 0),
            "urgent_pointer": getattr(tcp, "urgptr", 0) or 0
        }

        # Inspect Application Layer for TCP
        payload_bytes = bytes(tcp.payload)
        
        # HTTP Detection (ports 80, 8080, 5000, 8000 or HTTP verbs)
        if (
            src_port in (80, 8080, 5000, 8000) or
            dst_port in (80, 8080, 5000, 8000) or
            payload_bytes.startswith((b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"HEAD ", b"DELETE "))
        ):
            detected_proto = "HTTP"
            try:
                http_text = payload_bytes.decode("latin1", errors="ignore")
                first_line = http_text.split("\r\n")[0] if "\r\n" in http_text else http_text[:60]
                info = f"HTTP {first_line}"
                
                # Parse HTTP Request / Response headers & body
                headers = {}
                body = ""
                if "\r\n\r\n" in http_text:
                    header_part, body_part = http_text.split("\r\n\r\n", 1)
                    body = body_part
                    for h_line in header_part.split("\r\n")[1:]:
                        if ": " in h_line:
                            k, v = h_line.split(": ", 1)
                            headers[k] = v
                else:
                    body = http_text

                details["application"] = {
                    "protocol": "HTTP",
                    "summary": first_line,
                    "is_request": payload_bytes.startswith((b"GET", b"POST", b"PUT", b"DELETE", b"HEAD")),
                    "method": first_line.split(" ")[0] if " " in first_line else "UNKNOWN",
                    "uri": first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "/",
                    "headers": headers,
                    "body": body,
                    "body_length": len(body),
                    "is_encrypted": False,
                    "academic_note": "HTTP transmits all data in plaintext over cleartext TCP connections."
                }
                
                # Check for plaintext credentials
                cred_audit = scan_for_credentials(http_text)
                if cred_audit["has_credentials"]:
                    details["security"] = cred_audit
                    info += f" [VULNERABILITY: Plaintext Credentials Exposed ({cred_audit['username']})]"

            except Exception:
                info = f"HTTP {src_port} → {dst_port}"

        # HTTPS / TLS Detection (port 443 or TLS record markers 0x16, 0x17)
        elif (
            src_port == 443 or dst_port == 443 or
            (len(payload_bytes) > 5 and payload_bytes[0] in (0x14, 0x15, 0x16, 0x17) and payload_bytes[1] == 0x03)
        ):
            detected_proto = "HTTPS"
            rec_type = payload_bytes[0] if len(payload_bytes) > 0 else 0
            rec_map = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}
            rec_name = rec_map.get(rec_type, f"Record 0x{rec_type:02x}")
            
            tls_ver = "TLS"
            if len(payload_bytes) >= 3:
                major = payload_bytes[1]
                minor = payload_bytes[2]
                if major == 3 and minor == 1: tls_ver = "TLS 1.0"
                elif major == 3 and minor == 2: tls_ver = "TLS 1.1"
                elif major == 3 and minor == 3: tls_ver = "TLS 1.2 / 1.3"

            sni = "N/A"
            # Try extracting SNI from Client Hello
            try:
                if rec_type == 0x16 and len(payload_bytes) > 40:
                    text_sub = payload_bytes.decode("latin1", errors="ignore")
                    import re
                    sni_match = re.search(r"([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}", text_sub)
                    if sni_match:
                        sni = sni_match.group(0)
            except Exception:
                pass

            info = f"{tls_ver} {rec_name}"
            if sni != "N/A":
                info += f" (SNI: {sni})"
                
            details["application"] = {
                "protocol": "HTTPS / TLS",
                "tls_version": tls_ver,
                "record_type": rec_name,
                "server_name_indication": sni,
                "payload_bytes_count": len(payload_bytes),
                "is_encrypted": True,
                "encryption_algorithm": "AES-GCM / ChaCha20-Poly1305 (Confidential)",
                "academic_note": (
                    "HTTPS encrypts the entire transport payload using asymmetric key exchange (ECDHE/RSA) "
                    "followed by symmetric cipher suites. Passive sniffers (Wireshark) can only see encrypted ciphertext "
                    "in Application Data packets."
                )
            }

        # FTP Detection (port 21 or FTP command keywords)
        elif (
            src_port == 21 or dst_port == 21 or
            payload_bytes.startswith((b"USER ", b"PASS ", b"PORT ", b"PASV ", b"LIST", b"RETR ", b"220 ", b"331 ", b"230 "))
        ):
            detected_proto = "FTP"
            ftp_str = payload_bytes.decode("latin1", errors="ignore").strip()
            info = f"FTP {ftp_str[:50]}"
            
            cred_audit = scan_for_credentials(ftp_str)
            details["application"] = {
                "protocol": "FTP",
                "command_or_response": ftp_str,
                "is_encrypted": False,
                "academic_note": "FTP RFC 959 sends USER and PASS commands without encryption across the network."
            }
            if cred_audit["has_credentials"]:
                details["security"] = cred_audit
                info += f" [VULNERABILITY: Plaintext Auth ({cred_audit['evidence']})]"

    # ==========================
    # 5. TRANSPORT & APP: UDP
    # ==========================
    elif raw_pkt.haslayer(UDP):
        udp = raw_pkt[UDP]
        l4_proto = "UDP"
        detected_proto = "UDP"
        src_port = udp.sport
        dst_port = udp.dport
        
        info = f"{src_port} → {dst_port} Len={udp.len}"
        details["transport"] = {
            "protocol": "UDP",
            "source_port": src_port,
            "destination_port": dst_port,
            "length": udp.len,
            "checksum": hex(udp.chksum)
        }

        # DNS Detection (port 53 or DNS layer)
        if raw_pkt.haslayer(DNS) or src_port == 53 or dst_port == 53:
            detected_proto = "DNS"
            try:
                dns = raw_pkt[DNS] if raw_pkt.haslayer(DNS) else DNS(bytes(udp.payload))
                is_response = (dns.qr == 1)
                trans_id = hex(dns.id)
                
                # Extract Query Name
                qname = "N/A"
                qtype = "A"
                if dns.qdcount > 0 and dns.qd:
                    q = dns.qd
                    qname = q.qname.decode("utf-8", errors="ignore").rstrip(".") if hasattr(q, "qname") else str(q)
                    qtype_map = {1: "A", 28: "AAAA", 15: "MX", 5: "CNAME", 12: "PTR", 2: "NS"}
                    qtype = qtype_map.get(getattr(q, "qtype", 1), str(getattr(q, "qtype", 1)))
                
                # Extract Answers
                answers = []
                if dns.ancount > 0 and dns.an:
                    curr = dns.an
                    while curr:
                        ans_data = getattr(curr, "rdata", "")
                        if isinstance(ans_data, bytes):
                            ans_data = ans_data.decode("latin1", errors="ignore")
                        answers.append(str(ans_data))
                        curr = curr.payload if hasattr(curr, "payload") and len(bytes(curr.payload)) > 0 else None

                if is_response:
                    ans_str = ", ".join(answers[:3]) if answers else "No address"
                    info = f"Standard query response 0x{dns.id:04x} {qtype} {qname} {ans_str}"
                else:
                    info = f"Standard query 0x{dns.id:04x} {qtype} {qname}"

                details["application"] = {
                    "protocol": "DNS",
                    "transaction_id": trans_id,
                    "is_response": is_response,
                    "opcode": dns.opcode,
                    "query_name": qname,
                    "query_type": qtype,
                    "answers": answers,
                    "rcode": dns.rcode,
                    "academic_note": (
                        "Domain Name System translates human-friendly domain names (e.g. machine-b.lab) "
                        "into IP addresses via UDP port 53."
                    )
                }
            except Exception:
                info = f"DNS {src_port} → {dst_port}"

    # Generate Hex / ASCII Representation
    payload_hex = format_hex_ascii_dump(raw_bytes)
    payload_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw_bytes])

    return {
        "packet_num": packet_num,
        "timestamp": ts_str,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "protocol": detected_proto,
        "length": pkt_len,
        "info": info,
        "l4_proto": l4_proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "icmp_meaning": icmp_meaning,
        "payload_hex": payload_hex,
        "payload_ascii": payload_ascii,
        "details": details
    }
