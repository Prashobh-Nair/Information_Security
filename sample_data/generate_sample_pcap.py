"""
NetSecure Realistic Lab PCAP Generator
Creates an authentic network capture file implementing the exact scenario for Lab Exercise 12:
- Machine A (192.168.1.10, MAC 00:0c:29:1a:2b:3c)
- Machine B (192.168.1.20, MAC 00:0c:29:4d:5e:6f)
- ARP resolution
- ICMP Echo Request / Reply (Ping from Machine A to Machine B)
- DNS lookup
- HTTP cleartext dummy web application login (Password Sniffing demo)
- HTTPS TLS 1.3 handshake and encrypted application data
- Plaintext FTP login session
"""

import os
from pathlib import Path
from scapy.all import wrpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

MAC_A = "00:0c:29:1a:2b:3c"
MAC_B = "00:0c:29:4d:5e:6f"
MAC_GATEWAY = "00:50:56:c0:00:08"

IP_A = "192.168.1.10"
IP_B = "192.168.1.20"
IP_DNS = "192.168.1.1"

def build_sample_packet_sequence():
    packets = []
    
    # 1. ARP: Machine A asks "Who has 192.168.1.20? Tell 192.168.1.10"
    arp_req = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwsrc=MAC_A, psrc=IP_A,
        hwdst="00:00:00:00:00:00", pdst=IP_B,
        op=1
    )
    packets.append(arp_req)

    # 2. ARP: Machine B answers "192.168.1.20 is at 00:0c:29:4d:5e:6f"
    arp_rep = Ether(src=MAC_B, dst=MAC_A) / ARP(
        hwsrc=MAC_B, psrc=IP_B,
        hwdst=MAC_A, pdst=IP_A,
        op=2
    )
    packets.append(arp_rep)

    # 3. ICMP Ping Sequence: Machine A pings Machine B (4 requests & 4 replies)
    for seq in range(1, 5):
        # Echo Request (Type 8, Code 0)
        icmp_req = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B, ttl=128) / ICMP(
            type=8, code=0, id=0x0001, seq=seq
        ) / b"abcdefghijklmnopqrstuvwabcdefghi"
        packets.append(icmp_req)

        # Echo Reply (Type 0, Code 0)
        icmp_rep = Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A, ttl=64) / ICMP(
            type=0, code=0, id=0x0001, seq=seq
        ) / b"abcdefghijklmnopqrstuvwabcdefghi"
        packets.append(icmp_rep)

    # 4. DNS: Machine A queries for 'portal.lab.lan'
    dns_query = Ether(src=MAC_A, dst=MAC_GATEWAY) / IP(src=IP_A, dst=IP_DNS) / UDP(sport=53120, dport=53) / DNS(
        id=0x1a2b, qr=0, opcode=0, rd=1,
        qd=DNSQR(qname="portal.lab.lan", qtype="A")
    )
    packets.append(dns_query)

    dns_reply = Ether(src=MAC_GATEWAY, dst=MAC_A) / IP(src=IP_DNS, dst=IP_A) / UDP(sport=53, dport=53120) / DNS(
        id=0x1a2b, qr=1, opcode=0, aa=1, rd=1, ra=1,
        qd=DNSQR(qname="portal.lab.lan", qtype="A"),
        an=DNSRR(rrname="portal.lab.lan", type="A", rclass="IN", ttl=300, rdata=IP_B)
    )
    packets.append(dns_reply)

    # 5. HTTP: TCP 3-way handshake to Machine B port 80
    syn = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54321, dport=80, flags="S", seq=1000)
    syn_ack = Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001)
    ack = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001)
    packets.extend([syn, syn_ack, ack])

    # 6. HTTP GET request for login page
    http_get = (
        "GET /login HTTP/1.1\r\n"
        "Host: portal.lab.lan\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetSecure/1.0\r\n"
        "Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    http_get_pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=2001) / http_get.encode()
    packets.append(http_get_pkt)

    # 7. HTTP 200 OK Response
    http_res = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Server: Apache/2.4.52 (Ubuntu)\r\n"
        "Content-Length: 132\r\n\r\n"
        "<html><body><h2>University Student Portal Login</h2><form method='POST'><input name='username'/><input name='password' type='password'/></form></body></html>"
    )
    http_res_pkt = Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=54321, flags="PA", seq=2001, ack=1001 + len(http_get)) / http_res.encode()
    packets.append(http_res_pkt)

    # 8. HTTP POST: UNENCRYPTED CREDENTIAL SUBMISSION (VULNERABILITY DEMO)
    post_payload = "username=student_alex&password=SuperSecretLabPassword2026!&auth_token=lab_token_99182"
    http_post = (
        "POST /api/dummy/login HTTP/1.1\r\n"
        "Host: portal.lab.lan\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetSecure/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_payload)}\r\n\r\n"
        f"{post_payload}"
    )
    http_post_pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54321, dport=80, flags="PA", seq=1001 + len(http_get), ack=2001 + len(http_res)) / http_post.encode()
    packets.append(http_post_pkt)

    # 9. HTTPS: TLS 1.3 Handshake (Machine A to Machine B port 443)
    # Simulated Client Hello (Record 0x16, TLS 1.2/1.3 0x0303)
    tls_client_hello = (
        b"\x16\x03\x01\x00\x8a\x01\x00\x00\x86\x03\x03\x4f\x8d\x7e\x12"
        b"\x00\x00\x1c\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x14\x00\x9c\x00\x9d"
        b"\x00\x00\x3b\x00\x00\x0f\x00\x01\x00\x00\x0b\x73\x65\x63\x75"
        b"\x72\x65\x2e\x6c\x61\x62\x2e\x6c\x61\x6e" # SNI: secure.lab.lan
    )
    https_ch_pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54322, dport=443, flags="PA", seq=5000, ack=7000) / tls_client_hello
    packets.append(https_ch_pkt)

    # Simulated Server Hello
    tls_server_hello = (
        b"\x16\x03\x03\x00\x5a\x02\x00\x00\x56\x03\x03\x88\x12\x34\x56"
        b"\x00\x13\x01\x00\x00\x2e\x00\x33\x00\x24\x00\x1d\x00\x20\xaa"
    )
    https_sh_pkt = Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=443, dport=54322, flags="PA", seq=7000, ack=5000 + len(tls_client_hello)) / tls_server_hello
    packets.append(https_sh_pkt)

    # HTTPS Application Data (Encrypted Ciphertext - 0x17 0x03 0x03)
    tls_app_data = (
        b"\x17\x03\x03\x00\x45" # Content Type 23 (Application Data), Version TLS 1.2/1.3, Length 69
        b"\xa8\x72\x19\xdf\x3b\x89\xfa\x20\x11\x54\x90\xbc\xde\xef\x01\x23"
        b"\x45\x67\x89\xab\xcd\xef\x10\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
        b"\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa"
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x17"
    )
    https_data_pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=54322, dport=443, flags="PA", seq=5200, ack=7100) / tls_app_data
    packets.append(https_data_pkt)

    # 10. FTP Session with unencrypted USER and PASS
    ftp_banner = b"220 (vsFTPd 3.0.5) Lab FTP Server Ready\r\n"
    packets.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=21, dport=55100, flags="PA", seq=3000, ack=4000) / ftp_banner)

    ftp_user = b"USER lab_admin\r\n"
    packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=55100, dport=21, flags="PA", seq=4000, ack=3000 + len(ftp_banner)) / ftp_user)

    ftp_user_ok = b"331 Please specify the password.\r\n"
    packets.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=21, dport=55100, flags="PA", seq=3050, ack=4000 + len(ftp_user)) / ftp_user_ok)

    ftp_pass = b"PASS CleartextFtpPassword_XYZ123!\r\n"
    packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=55100, dport=21, flags="PA", seq=4020, ack=3050 + len(ftp_user_ok)) / ftp_pass)

    ftp_pass_ok = b"230 Login successful.\r\n"
    packets.append(Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=21, dport=55100, flags="PA", seq=3090, ack=4020 + len(ftp_pass)) / ftp_pass_ok)

    return packets

def generate_sample_pcap(destination_path: str = None) -> str:
    if not destination_path:
        base_dir = Path(__file__).resolve().parent
        destination_path = str(base_dir / "sample_lan_capture.pcap")
        
    pkts = build_sample_packet_sequence()
    wrpcap(destination_path, pkts)
    print(f"[NetSecure] Successfully generated {len(pkts)} packets in {destination_path}")
    return destination_path

if __name__ == "__main__":
    generate_sample_pcap()
