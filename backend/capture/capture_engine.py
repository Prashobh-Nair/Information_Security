"""
NetSecure Capture Engine
Directly integrates Wireshark TShark for real-time live packet capture on Windows/Linux.
Includes fallback Scapy capture and lab PCAP simulation modes.
Streams packets over WebSockets and records to SQLite.
"""

import threading
import asyncio
import time
import subprocess
import json
import os
from datetime import datetime
from typing import Optional, Any, Dict, List
from pathlib import Path

from backend.config import TSHARK_BINARY, PCAP_DIR
from backend.analyzer.packet_parser import dissect_packet
from backend.analyzer.icmp_analyzer import analyze_icmp
from backend.analyzer.payload_inspector import scan_for_credentials, format_hex_ascii_dump
from backend.database import create_session, stop_session, insert_packet, insert_security_alert

class CaptureEngine:
    def __init__(self):
        self.is_running = False
        self.active_session_id: Optional[int] = None
        self.interface: str = "4" # Default to Wi-Fi index or device
        self.interface_display: str = "Wi-Fi"
        self.filter_expr: str = ""
        self.capture_mode: str = "tshark" if TSHARK_BINARY else "scapy"
        self.thread: Optional[threading.Thread] = None
        self.tshark_proc: Optional[subprocess.Popen] = None
        self.ws_subscribers: List[Any] = []
        self.packet_counter = 0
        self.lock = threading.Lock()

    def register_ws(self, websocket: Any):
        if websocket not in self.ws_subscribers:
            self.ws_subscribers.append(websocket)

    def unregister_ws(self, websocket: Any):
        if websocket in self.ws_subscribers:
            self.ws_subscribers.remove(websocket)

    def broadcast_packet(self, pkt_data: Dict[str, Any]):
        dead = []
        msg = json.dumps({"type": "packet", "data": pkt_data})
        for ws in self.ws_subscribers:
            try:
                loop = getattr(ws, "app_loop", None)
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
            except Exception:
                dead.append(ws)
        for d in dead:
            if d in self.ws_subscribers:
                self.ws_subscribers.remove(d)

    def start_capture(self, interface: str, filter_expr: str = "", mode: str = "auto") -> Dict[str, Any]:
        with self.lock:
            if self.is_running:
                return {"status": "error", "message": "Capture session is already running."}

            self.interface = interface
            self.interface_display = interface
            self.filter_expr = filter_expr.strip()
            self.is_running = True
            self.packet_counter = 0

            # Determine mode
            if mode == "auto":
                self.capture_mode = "tshark" if TSHARK_BINARY else "scapy"
            else:
                self.capture_mode = mode

            session_name = f"Live Capture [{self.capture_mode.upper()}] - {datetime.now().strftime('%b %d, %H:%M:%S')}"
            self.active_session_id = create_session(
                name=session_name,
                interface=self.interface_display,
                source_type=self.capture_mode
            )

            # Start background capture thread
            self.thread = threading.Thread(target=self._run_capture_loop, daemon=True)
            self.thread.start()

            return {
                "status": "success",
                "session_id": self.active_session_id,
                "interface": self.interface_display,
                "engine": self.capture_mode,
                "tshark_path": TSHARK_BINARY
            }

    def stop_capture(self) -> Dict[str, Any]:
        with self.lock:
            if not self.is_running:
                return {"status": "warning", "message": "Capture is not currently running."}

            self.is_running = False

            if self.tshark_proc:
                try:
                    self.tshark_proc.terminate()
                    self.tshark_proc.wait(timeout=2)
                except Exception:
                    try:
                        self.tshark_proc.kill()
                    except Exception:
                        pass
                self.tshark_proc = None

            if self.active_session_id:
                stop_session(self.active_session_id)
                s_id = self.active_session_id
                self.active_session_id = None
                return {"status": "success", "session_id": s_id, "packets_captured": self.packet_counter}

            return {"status": "success", "packets_captured": self.packet_counter}

    def _run_capture_loop(self):
        if self.capture_mode == "tshark" and TSHARK_BINARY:
            self._run_tshark_capture()
        elif self.capture_mode == "scapy":
            self._run_scapy_capture()
        else:
            self._run_synthetic_lab_capture()

    def _run_tshark_capture(self):
        """
        Executes real Wireshark TShark in streaming JSON (-T ek -l) mode.
        Captures real network packets on the selected interface.
        """
        # Determine interface flag
        iface_arg = self.interface
        # If human name or description, find device or index
        if "\\" not in iface_arg and not iface_arg.isdigit():
            from backend.capture.interface_manager import get_network_interfaces
            all_ifaces = get_network_interfaces()
            for item in all_ifaces:
                if item["name"].lower() == iface_arg.lower() or item["description"].lower() in iface_arg.lower():
                    iface_arg = item.get("device_name") or item.get("tshark_index") or iface_arg
                    break

        cmd = [
            TSHARK_BINARY,
            "-i", str(iface_arg),
            "-l",              # line buffered stdout
            "-T", "ek",        # Elasticsearch line-by-line JSON format
        ]
        if self.filter_expr:
            cmd.extend(["-f", self.filter_expr])

        print(f"[NetSecure] Starting TShark CLI: {' '.join(cmd)}")

        try:
            self.tshark_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            for line in iter(self.tshark_proc.stdout.readline, ""):
                if not self.is_running:
                    break
                line = line.strip()
                if not line or line.startswith('{"index"'):
                    continue

                try:
                    raw_json = json.loads(line)
                    layers = raw_json.get("layers", {})
                    self.packet_counter += 1

                    parsed_pkt = self._convert_tshark_json(layers, self.packet_counter)
                    parsed_pkt["source_type"] = "live_tshark"

                    insert_packet(self.active_session_id, parsed_pkt)
                    self.broadcast_packet(parsed_pkt)

                    # Security audit
                    sec = parsed_pkt.get("details", {}).get("security", {})
                    if sec.get("has_credentials"):
                        insert_security_alert({
                            "session_id": self.active_session_id,
                            "alert_type": "PLAINTEXT_CREDENTIALS_EXPOSED",
                            "severity": "CRITICAL",
                            "title": f"Live Sniff: Unencrypted {sec.get('auth_type', 'Credentials')} Intercepted",
                            "description": f"Packet #{self.packet_counter} on interface '{self.interface_display}' contained plaintext credentials: '{sec.get('username')}'",
                            "protocol": parsed_pkt.get("protocol", "HTTP"),
                            "evidence": sec.get("evidence", ""),
                            "remediation": "Enforce HTTPS with TLS 1.3 and HSTS header. Do not transmit credentials over unencrypted HTTP."
                        })

                except Exception as ex:
                    continue

        except Exception as e:
            print(f"[NetSecure] TShark execution encountered: {e}. Falling back to Scapy native.")
            self._run_scapy_capture()

    def _convert_tshark_json(self, layers: Dict[str, Any], pkt_num: int) -> Dict[str, Any]:
        """Maps TShark layer hierarchy to NetSecure standard multi-layer dissection schema."""
        frame = layers.get("frame", {})
        eth = layers.get("eth", {})
        ip = layers.get("ip", {})
        ipv6 = layers.get("ipv6", {})
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        icmp = layers.get("icmp", {})
        http = layers.get("http", {})
        dns = layers.get("dns", {})
        arp = layers.get("arp", {})
        tls = layers.get("tls", {})
        data = layers.get("data", {})

        # 1. Layer 2: Ethernet
        src_mac = eth.get("eth_eth_src") or "00:00:00:00:00:00"
        dst_mac = eth.get("eth_eth_dst") or "00:00:00:00:00:00"
        if isinstance(src_mac, list): src_mac = src_mac[0]
        if isinstance(dst_mac, list): dst_mac = dst_mac[0]

        # 2. Layer 3: Network
        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.1"
        l3_proto = "IPv4"

        if ip:
            src_ip = ip.get("ip_ip_src", "127.0.0.1")
            dst_ip = ip.get("ip_ip_dst", "127.0.0.1")
            l3_proto = "IPv4"
        elif ipv6:
            src_ip = ipv6.get("ipv6_ipv6_src", "::1")
            dst_ip = ipv6.get("ipv6_ipv6_dst", "::1")
            l3_proto = "IPv6"
        elif arp:
            src_ip = arp.get("arp_arp_src_proto_ipv4", "N/A")
            dst_ip = arp.get("arp_arp_dst_proto_ipv4", "N/A")
            src_mac = arp.get("arp_arp_src_hw_mac", src_mac)
            dst_mac = arp.get("arp_arp_dst_hw_mac", dst_mac)
            l3_proto = "ARP"

        if isinstance(src_ip, list): src_ip = src_ip[0]
        if isinstance(dst_ip, list): dst_ip = dst_ip[0]

        # 3. Layer 4: Transport
        l4_proto = "N/A"
        src_port = None
        dst_port = None
        detected_proto = l3_proto
        info = f"{l3_proto} Frame #{pkt_num}"

        icmp_type = None
        icmp_code = None
        icmp_meaning = ""

        trans_details = {}
        app_details = {}
        sec_details = {}

        if icmp:
            detected_proto = "ICMP"
            l4_proto = "ICMP"
            itype = int(icmp.get("icmp_icmp_type", 8))
            icode = int(icmp.get("icmp_icmp_code", 0))
            icmp_type = itype
            icmp_code = icode
            analysis = analyze_icmp(itype, icode)
            icmp_meaning = analysis["meaning"]
            info = f"ICMP {analysis['meaning']}"
            trans_details = {
                "protocol": "ICMP",
                "type": itype,
                "code": icode,
                "meaning": icmp_meaning,
                "description": analysis["description"],
                "academic_explanation": analysis["academic_explanation"]
            }

        elif tcp:
            l4_proto = "TCP"
            detected_proto = "TCP"
            sp = tcp.get("tcp_tcp_srcport")
            dp = tcp.get("tcp_tcp_dstport")
            src_port = int(sp[0] if isinstance(sp, list) else sp) if sp else None
            dst_port = int(dp[0] if isinstance(dp, list) else dp) if dp else None

            flags_str = tcp.get("tcp_tcp_flags_str", "[TCP]")
            seq_val = tcp.get("tcp_tcp_seq", "0")
            ack_val = tcp.get("tcp_tcp_ack", "0")
            info = f"{src_port} → {dst_port} {flags_str} Seq={seq_val} Ack={ack_val}"

            trans_details = {
                "protocol": "TCP",
                "source_port": src_port,
                "destination_port": dst_port,
                "flags": flags_str,
                "sequence_number": seq_val,
                "acknowledgment_number": ack_val,
                "window_size": tcp.get("tcp_tcp_window_size", "65535")
            }

            # Check HTTP
            if http or src_port in (80, 8080, 5000, 8000) or dst_port in (80, 8080, 5000, 8000):
                detected_proto = "HTTP"
                meth = http.get("http_http_request_method", "REQ")
                uri = http.get("http_http_request_uri", "/")
                info = f"HTTP {meth} {uri}"
                app_details = {
                    "protocol": "HTTP",
                    "method": meth,
                    "uri": uri,
                    "is_encrypted": False,
                    "academic_note": "HTTP transmits form parameters in cleartext over TCP."
                }
                # Payload credential audit
                raw_payload = tcp.get("tcp_tcp_payload", "")
                if raw_payload:
                    try:
                        text_payload = bytes.fromhex(raw_payload.replace(":", "")).decode("latin1", errors="ignore")
                        sec_details = scan_for_credentials(text_payload)
                        if sec_details.get("has_credentials"):
                            info += f" [VULNERABILITY: Plaintext Password Exposed ({sec_details.get('username')})]"
                    except Exception:
                        pass

            # Check HTTPS / TLS
            elif tls or src_port == 443 or dst_port == 443 or src_port == 8443 or dst_port == 8443:
                detected_proto = "HTTPS"
                rec_type = "Application Data"
                sni = "localhost"
                info = f"TLS 1.3 {rec_type} (Encrypted Session)"
                app_details = {
                    "protocol": "HTTPS / TLS",
                    "record_type": rec_type,
                    "server_name_indication": sni,
                    "is_encrypted": True,
                    "academic_note": "Payload encrypted with AES-256-GCM / TLS 1.3. Passive sniffers cannot read passwords."
                }

            # Check FTP
            elif src_port == 21 or dst_port == 21:
                detected_proto = "FTP"
                info = "FTP Control Stream (Port 21)"
                app_details = {"protocol": "FTP", "is_encrypted": False}

        elif udp:
            l4_proto = "UDP"
            detected_proto = "UDP"
            sp = udp.get("udp_udp_srcport")
            dp = udp.get("udp_udp_dstport")
            src_port = int(sp[0] if isinstance(sp, list) else sp) if sp else None
            dst_port = int(dp[0] if isinstance(dp, list) else dp) if dp else None
            info = f"{src_port} → {dst_port} (UDP)"

            trans_details = {
                "protocol": "UDP",
                "source_port": src_port,
                "destination_port": dst_port,
                "length": udp.get("udp_udp_length", "N/A")
            }

            if dns or src_port == 53 or dst_port == 53:
                detected_proto = "DNS"
                qname = dns.get("dns_dns_qry_name", "query.lan") if dns else "dns.query"
                info = f"DNS Query {qname}"
                app_details = {
                    "protocol": "DNS",
                    "query_name": qname,
                    "is_encrypted": False
                }

        elif arp:
            detected_proto = "ARP"
            op = arp.get("arp_arp_opcode", "1")
            op_name = "Request" if str(op) == "1" else "Reply"
            info = f"ARP {op_name}: Who has {dst_ip}? Tell {src_ip}"
            app_details = {"protocol": "ARP", "operation": op_name}

        # Build Hex & ASCII display from TShark raw payload or frame
        raw_hex_data = tcp.get("tcp_tcp_payload") or data.get("data_data_data") or ""
        payload_bytes = b""
        if raw_hex_data:
            try:
                clean_hex = raw_hex_data.replace(":", "").replace(" ", "")
                payload_bytes = bytes.fromhex(clean_hex)
            except Exception:
                pass

        payload_hex = format_hex_ascii_dump(payload_bytes) if payload_bytes else "No extra payload bytes"
        payload_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in payload_bytes])

        frame_len = int(frame.get("frame_frame_len") or len(payload_bytes) or 64)
        ts_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        return {
            "packet_num": pkt_num,
            "timestamp": ts_now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": detected_proto,
            "length": frame_len,
            "info": info,
            "l4_proto": l4_proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_meaning": icmp_meaning,
            "payload_hex": payload_hex,
            "payload_ascii": payload_ascii,
            "details": {
                "ethernet": {"source_mac": src_mac, "destination_mac": dst_mac},
                "network": {"source_ip": src_ip, "destination_ip": dst_ip, "protocol": l3_proto},
                "transport": trans_details,
                "application": app_details,
                "security": sec_details
            }
        }

    def _run_scapy_capture(self):
        """Scapy native sniffer fallback."""
        import scapy.all as scapy
        try:
            def pkt_callback(raw_pkt):
                if not self.is_running:
                    return True
                self.packet_counter += 1
                pkt_data = dissect_packet(raw_pkt, packet_num=self.packet_counter)
                pkt_data["source_type"] = "live_scapy"
                insert_packet(self.active_session_id, pkt_data)
                self.broadcast_packet(pkt_data)
                return False

            scapy.sniff(
                prn=pkt_callback,
                filter=self.filter_expr if self.filter_expr else None,
                stop_filter=lambda x: not self.is_running,
                store=False,
                timeout=None
            )
        except Exception as e:
            print(f"[NetSecure] Scapy sniff error: {e}. Switching to synthetic lab generator.")
            self._run_synthetic_lab_capture()

    def _run_synthetic_lab_capture(self):
        """Generates realistic academic lab packet sequence."""
        from sample_data.generate_sample_pcap import build_sample_packet_sequence
        sample_packets = build_sample_packet_sequence()
        idx = 0
        while self.is_running:
            raw_pkt = sample_packets[idx % len(sample_packets)]
            idx += 1
            self.packet_counter += 1
            pkt_data = dissect_packet(raw_pkt, packet_num=self.packet_counter)
            pkt_data["source_type"] = "sample_pcap"
            insert_packet(self.active_session_id, pkt_data)
            self.broadcast_packet(pkt_data)
            time.sleep(1.2)

# Global singleton
capture_engine = CaptureEngine()
